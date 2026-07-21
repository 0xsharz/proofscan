#!/usr/bin/env python3
# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
"""EasyScan report engine.

Deterministic half of the hybrid pipeline: reads a harness results dir, renders
terminal-screenshot PNG proofs, maps CVE/CWE/severity, and assembles a
self-contained HTML report + machine-readable summary.json. The human prose
(exec summary / walkthrough / remediation) comes from an optional report-writer
agent (host-side `claude -p`), with a deterministic template fallback so a
report ALWAYS renders even offline / under throttling.

Reads BOTH result.json schemas: new (finding/finding_type/finding_evidence/
finding_confirmed) and old (crash/crash_type/crash_output/crash_found), and
BOTH layouts (top-level result.json, or run_*/result.json for multi-run).
"""
from __future__ import annotations

import argparse
import base64
import glob
import html
import io
import json
import os
import re
import subprocess
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont


# ── terminal-screenshot renderer ──────────────────────────────────────────────

_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    "/Library/Fonts/DejaVuSansMono.ttf",
]
_BG = (13, 17, 23)
_FG = (201, 209, 217)
_BAR = (33, 38, 45)
_TITLE = (139, 148, 158)
_GREEN = (63, 185, 80)
_RED = (248, 81, 73)
_AMBER = (210, 153, 34)


def _load_font(size):
    for p in _FONT_CANDIDATES:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def termshot(title: str, body: str, cols: int = 100) -> bytes:
    """Render captured terminal output as a dark-terminal PNG. Returns PNG bytes."""
    fsize = 15
    pad = 16
    bar_h = 34
    font = _load_font(fsize)
    ch_w = max(1, font.getbbox("M")[2])
    line_h = fsize + 6

    lines = []
    for raw in (body.replace("\t", "    ").splitlines() or [""]):
        if raw == "":
            lines.append("")
        while len(raw) > cols:
            lines.append(raw[:cols])
            raw = raw[cols:]
        if raw:
            lines.append(raw)
    if not lines:
        lines = [""]

    w = pad * 2 + ch_w * cols
    h = bar_h + pad * 2 + line_h * len(lines)
    img = Image.new("RGB", (w, h), _BG)
    d = ImageDraw.Draw(img)

    # title bar + traffic-light dots
    d.rectangle([0, 0, w, bar_h], fill=_BAR)
    for i, c in enumerate([_RED, _AMBER, _GREEN]):
        d.ellipse([pad + i * 20, 11, pad + i * 20 + 12, 23], fill=c)
    d.text((pad + 74, 9), title, fill=_TITLE, font=_load_font(13))

    y = bar_h + pad
    for ln in lines:
        color = _FG
        low = ln.lower()
        if "error" in low or "failed" in low or "vulnerability confirmed" in low:
            color = _RED
        elif ln.strip().startswith("exit=0") or "benign" in low or "no injected" in low:
            color = _GREEN
        elif ln.strip().startswith("exit=") or "exited" in low:
            color = _AMBER
        d.text((pad, y), ln, fill=color, font=font)
        y += line_h

    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _hexdump(b: bytes, width: int = 16, max_bytes: int = 512) -> str:
    b = b[:max_bytes]
    out = []
    for off in range(0, len(b), width):
        chunk = b[off:off + width]
        hexs = " ".join(f"{c:02x}" for c in chunk).ljust(width * 3 - 1)
        ascii_ = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append(f"{off:08x}  {hexs}  |{ascii_}|")
    tail = "\n[...truncated]" if len(b) == max_bytes else ""
    return ("\n".join(out) or "(empty)") + tail


# ── CVE / CWE / severity mapping ──────────────────────────────────────────────

_CWE_BY_SINK = [
    (("compile", "exec", "yaml", "pickle", "deserial"),
     ("CWE-502", "Deserialization of Untrusted Data")),
    (("os.system", "subprocess", "-injection", "command"),
     ("CWE-78", "OS Command Injection")),
    (("ssrf", "redirect", "socket.connect", "getaddrinfo"),
     ("CWE-918", "Server-Side Request Forgery")),
    (("path-traversal", "zip", "open:", "traversal"),
     ("CWE-22", "Path Traversal")),
    (("heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow", "write"),
     ("CWE-787", "Out-of-bounds Write")),
    (("heap-buffer-overflow-read", "read"),
     ("CWE-125", "Out-of-bounds Read")),
    (("use-after-free", "double-free"),
     ("CWE-416", "Use After Free")),
]


def derive_labels(config_text: str, finding_type: str, severity: str) -> dict:
    m = re.search(r"CVE-\d{4}-\d{4,7}", config_text or "")
    ft = (finding_type or "").lower()
    cwe, cwe_name = ("CWE-693", "Protection Mechanism Failure")
    for keys, (c, n) in _CWE_BY_SINK:
        if any(k in ft for k in keys):
            cwe, cwe_name = c, n
            break
    return {
        "cve": m.group(0) if m else None,
        "cwe": cwe,
        "cwe_name": cwe_name,
        "severity": severity or "UNKNOWN",
    }


# ── results reader (schema + layout tolerant) ─────────────────────────────────

_CONFIRMED = {"finding_confirmed", "crash_found"}


def _find_result_json(results_dir: str) -> str | None:
    top = os.path.join(results_dir, "result.json")
    if os.path.exists(top):
        return top
    runs = sorted(glob.glob(os.path.join(results_dir, "run_*", "result.json")))
    for r in runs:
        try:
            if json.load(open(r)).get("status") in _CONFIRMED:
                return r
        except Exception:
            pass
    return runs[0] if runs else None


def _find_config(results_dir: str, target: str) -> str:
    cands = [os.path.join(os.getcwd(), "targets", target, "config.yaml")]
    d = os.path.abspath(results_dir)
    for _ in range(7):
        cands.append(os.path.join(d, "targets", target, "config.yaml"))
        d = os.path.dirname(d)
    for c in cands:
        if os.path.exists(c):
            try:
                return open(c).read()
            except Exception:
                pass
    return ""


def load_run(results_dir: str) -> dict:
    rjp = _find_result_json(results_dir)
    if not rjp:
        raise FileNotFoundError(f"no result.json under {results_dir}")
    rj = json.load(open(rjp))
    finding = rj.get("finding") or rj.get("crash") or {}
    ft = finding.get("finding_type") or finding.get("crash_type") or "unknown"
    ev = finding.get("finding_evidence") or finding.get("crash_output") or ""
    try:
        poc = base64.b64decode(finding.get("poc_bytes", "")) if finding else b""
    except Exception:
        poc = b""

    severity, analysis = "UNKNOWN", ""
    reps = sorted(glob.glob(os.path.join(results_dir, "reports", "bug_*", "report.json")))
    if reps:
        try:
            rep = json.load(open(reps[0]))
            severity = (rep.get("verdict") or {}).get("severity_rating") or "UNKNOWN"
            analysis = rep.get("report") or ""
        except Exception:
            pass

    target = rj.get("target", "?")
    return {
        "target": target,
        "status": rj.get("status", "?"),
        "confirmed": rj.get("status") in _CONFIRMED,
        "finding_type": ft,
        "finding_evidence": ev,
        "poc_bytes": poc,
        "reproduction_command": finding.get("reproduction_command", ""),
        "exit_code": finding.get("exit_code", -1),
        "severity": severity,
        "analysis_text": analysis,
        "config_text": _find_config(results_dir, target),
    }


# ── report-writer agent + deterministic fallback ──────────────────────────────

def _prose_template(run: dict, labels: dict) -> dict:
    cve = labels.get("cve") or "no assigned CVE"
    tgt = run["target"]
    cls = labels["cwe_name"].lower()
    return {
        "exec_summary": (
            f"An automated security scan of {tgt} confirmed a "
            f"{labels['severity']} vulnerability ({cve}, {labels['cwe']} "
            f"{labels['cwe_name']}). The finding was proven by executing a "
            f"proof-of-concept against the target and observing the dangerous "
            f"behavior actually occur — it was not merely inferred from "
            f"reading source."),
        "walkthrough": [
            f"The scanner fed a crafted input to {tgt} through its normal entry "
            f"point (`{run['reproduction_command'] or 'the target API'}`).",
            f"The input reached the vulnerable code path and triggered the "
            f"{cls} condition.",
            "A detection oracle observed the dangerous primitive actually fire "
            "and recorded a confirmed finding — see the proof screenshots "
            "below for the exact captured evidence."],
        "impact_plain": (
            f"An attacker who can supply input to this component can exploit a "
            f"{cls} issue in {tgt}. Because the scan confirmed it by execution, "
            f"the risk is real and not theoretical. Confirmed severity: "
            f"{labels['severity']}."),
        "recommendations": [
            f"Upgrade {tgt} to a patched release (see the {cve} advisory for the "
            f"fixed version).",
            "Treat all externally-sourced input to this component as untrusted; "
            "validate or sandbox it before it reaches the vulnerable call.",
            "Add a regression test built from the proof-of-concept in this "
            "report so the fix is verified and stays fixed."],
    }


_PROSE_PROMPT = textwrap.dedent("""\
    You are writing the human-facing section of a security report for a
    CONFIRMED, proof-of-concept-verified vulnerability. Audience is mixed
    (executives and developers). Be accurate, plain-spoken, and concrete. Do
    NOT invent facts beyond the technical analysis provided.

    Target: {target}
    Labels: severity={severity}, {cve}, {cwe} ({cwe_name})
    Reproduction command: {repro}
    Technical analysis (from the pipeline's report agent):
    ---
    {analysis}
    ---
    Output ONLY a single JSON object (no prose, no code fence) with EXACTLY
    these keys:
    {{"exec_summary": "at most 4 sentences",
      "walkthrough": ["step 1", "step 2", "..."],
      "impact_plain": "one short paragraph, no jargon",
      "recommendations": ["fix 1", "fix 2", "..."]}}
    """)


def write_prose(run: dict, labels: dict, model: str | None = None) -> dict:
    """Try the report-writer agent (host-side claude -p). Any failure -> template."""
    prompt = _PROSE_PROMPT.format(
        target=run["target"], severity=labels["severity"],
        cve=labels.get("cve") or "no CVE", cwe=labels["cwe"],
        cwe_name=labels["cwe_name"], repro=run["reproduction_command"],
        analysis=(run["analysis_text"] or "(none)")[:6000])
    try:
        env = dict(os.environ)
        tok = "/root/.vp_token"
        if "CLAUDE_CODE_OAUTH_TOKEN" not in env and os.path.exists(tok):
            env["CLAUDE_CODE_OAUTH_TOKEN"] = open(tok).read().strip()
        cmd = ["claude", "-p", prompt]
        if model:
            cmd += ["--model", model]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env)
        out = res.stdout or ""
        data = json.loads(out[out.index("{"):out.rindex("}") + 1])
        need = {"exec_summary", "walkthrough", "impact_plain", "recommendations"}
        if need <= set(data) and isinstance(data["walkthrough"], list) \
                and isinstance(data["recommendations"], list):
            return {k: data[k] for k in need}
    except Exception:
        pass
    return _prose_template(run, labels)


# ── HTML assembler ────────────────────────────────────────────────────────────

_SEV_COLOR = {"CRITICAL": "#cf222e", "HIGH": "#bc4c00", "MEDIUM": "#9a6700",
              "LOW": "#0969da", "UNKNOWN": "#57606a", "NOT-A-BUG": "#57606a"}

_ANALYSIS_SECTIONS = ["primitive", "reachability", "heap_layout",
                      "escalation_path", "constraints", "escalation_attempt"]


def _parse_analysis(text: str) -> list:
    out = []
    for tag in _ANALYSIS_SECTIONS:
        m = re.search(rf"<{tag}>(.*?)</{tag}>", text or "", re.DOTALL)
        if m and m.group(1).strip():
            out.append((tag.replace("_", " ").title(), m.group(1).strip()))
    return out


def _e(s):
    return html.escape(str(s))


def build_html(run: dict, labels: dict, prose: dict, proofs: list) -> str:
    sev = labels["severity"].upper()
    sev_color = _SEV_COLOR.get(sev, "#57606a")
    cve = labels["cve"] or "—"

    facts = [
        ("Target", run["target"]),
        ("Severity", sev),
        ("CVE", cve),
        ("Weakness", f"{labels['cwe']} — {labels['cwe_name']}"),
        ("Finding type", run["finding_type"]),
        ("Status", run["status"]),
        ("PoC size", f"{len(run['poc_bytes'])} bytes"),
        ("Oracle exit code", str(run["exit_code"])),
    ]
    facts_rows = "\n".join(
        f'<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>' for k, v in facts)

    walk = "\n".join(f"<li>{_e(s)}</li>" for s in prose["walkthrough"])
    recs = "\n".join(f"<li>{_e(s)}</li>" for s in prose["recommendations"])

    analysis_sections = _parse_analysis(run["analysis_text"])
    if analysis_sections:
        analysis_html = "\n".join(
            f'<h3>{_e(t)}</h3><div class="analysis">{_e(b)}</div>'
            for t, b in analysis_sections)
    else:
        analysis_html = f'<div class="analysis">{_e(run["analysis_text"] or "(no technical analysis on file)")}</div>'

    proof_html = ""
    for cap, png in proofs:
        b64 = base64.b64encode(png).decode()
        proof_html += (
            f'<figure><img alt="{_e(cap)}" '
            f'src="data:image/png;base64,{b64}"/>'
            f'<figcaption>{_e(cap)}</figcaption></figure>\n')

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Report — {_e(run['target'])} ({_e(sev)})</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ font: 15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         color: #1f2328; background: #f6f8fa; margin: 0; padding: 0 0 4rem; }}
  .wrap {{ max-width: 900px; margin: 0 auto; padding: 0 1.25rem; }}
  header {{ background: #0d1117; color: #e6edf3; padding: 2rem 0; margin-bottom: 2rem; }}
  header .wrap {{ display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }}
  header h1 {{ margin: 0; font-size: 1.5rem; font-weight: 650; }}
  header .sub {{ color: #8b949e; font-size: .85rem; margin-top: .25rem; }}
  .badge {{ display: inline-block; padding: .35rem .9rem; border-radius: 999px;
            color: #fff; font-weight: 700; letter-spacing: .04em; background: {sev_color}; }}
  section {{ background: #fff; border: 1px solid #d0d7de; border-radius: 10px;
             padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }}
  h2 {{ font-size: 1.15rem; margin: 0 0 .75rem; padding-bottom: .4rem; border-bottom: 2px solid #eaeef2; }}
  h3 {{ font-size: .95rem; margin: 1rem 0 .3rem; color: #57606a; text-transform: uppercase; letter-spacing: .03em; }}
  table.facts {{ border-collapse: collapse; width: 100%; }}
  table.facts th {{ text-align: left; color: #57606a; font-weight: 600; width: 180px; padding: .35rem .5rem .35rem 0; vertical-align: top; }}
  table.facts td {{ padding: .35rem 0; font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
  .analysis {{ white-space: pre-wrap; font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
               font-size: .85rem; background: #f6f8fa; border: 1px solid #eaeef2; border-radius: 8px; padding: .75rem 1rem; }}
  figure {{ margin: 0 0 1.25rem; }}
  figure img {{ width: 100%; border-radius: 8px; border: 1px solid #30363d; display: block; }}
  figcaption {{ color: #57606a; font-size: .85rem; margin-top: .4rem; }}
  ol, ul {{ margin: .25rem 0; padding-left: 1.4rem; }}
  li {{ margin: .3rem 0; }}
  .lead {{ font-size: 1.05rem; }}
  footer {{ color: #8b949e; font-size: .8rem; text-align: center; margin-top: 2rem; }}
</style></head>
<body>
<header><div class="wrap">
  <div><h1>Security Assessment: {_e(run['target'])}</h1>
    <div class="sub">EasyScan — execution-verified vulnerability report</div></div>
  <div class="badge">{_e(sev)}</div>
</div></header>
<div class="wrap">

<section><h2>Executive summary</h2>
  <p class="lead">{_e(prose['exec_summary'])}</p></section>

<section><h2>Finding at a glance</h2>
  <table class="facts">{facts_rows}</table></section>

<section><h2>How it works — step by step</h2>
  <ol>{walk}</ol>
  <p>{_e(prose['impact_plain'])}</p></section>

<section><h2>Proof</h2>
  {proof_html}</section>

<section><h2>Technical analysis</h2>
  {analysis_html}</section>

<section><h2>Recommendations</h2>
  <ul>{recs}</ul></section>

<footer>Generated by EasyScan. Findings are execution-verified proof-of-concept results;
review before acting. For authorized security research only.</footer>
</div></body></html>"""


# ── summary.json + CLI ────────────────────────────────────────────────────────

def write_summary(results_dir: str, run: dict, labels: dict) -> dict:
    summary = {
        "target": run["target"],
        "status": run["status"],
        "confirmed": bool(run["confirmed"]),
        "severity": labels["severity"],
        "cve": labels["cve"],
        "cwe": labels["cwe"],
        "finding_type": run["finding_type"],
        "report_path": os.path.abspath(os.path.join(results_dir, "report.html")),
    }
    with open(os.path.join(results_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    return summary


def main(argv):
    ap = argparse.ArgumentParser(prog="report.py",
                                 description="EasyScan report engine")
    ap.add_argument("results_dir", help="a harness results dir (…/results/<target>/<ts>/)")
    ap.add_argument("--model", default=None, help="model for the report-writer agent")
    ap.add_argument("--no-agent", action="store_true",
                    help="skip the report-writer agent; use the deterministic template")
    args = ap.parse_args(argv)

    run = load_run(args.results_dir)
    labels = derive_labels(run["config_text"], run["finding_type"], run["severity"])
    prose = _prose_template(run, labels) if args.no_agent \
        else write_prose(run, labels, args.model)

    proofs_src = [
        ("Detection oracle — the vulnerability firing",
         (run["finding_evidence"] or "(no evidence captured)")
         + f"\n\n[process exited {run['exit_code']}]"),
        ("Proof-of-concept input (hexdump)", _hexdump(run["poc_bytes"])),
        ("Reproduction command", run["reproduction_command"] or "(n/a)"),
    ]
    proofs = [(cap, termshot(cap, body)) for cap, body in proofs_src]

    out_html = os.path.join(args.results_dir, "report.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(build_html(run, labels, prose, proofs))
    write_summary(args.results_dir, run, labels)

    print(f"[easyscan] report:  {os.path.abspath(out_html)}")
    print(f"[easyscan] summary: {os.path.abspath(os.path.join(args.results_dir, 'summary.json'))}")
    print(f"[easyscan] result:  {run['status']}  severity={labels['severity']}"
          f"  {labels['cve'] or ''}")
    return 2 if run["confirmed"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
