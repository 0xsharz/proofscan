#!/usr/bin/env python3
# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
"""EasyScan report engine.

Deterministic half of the hybrid pipeline: reads a harness results dir, renders
terminal-screenshot PNG proofs, maps CVE/CWE/severity, and assembles a
self-contained, professional HTML report + machine-readable summary.json.

The human narrative (summary / description / walkthrough / root cause /
remediation) comes from ONE report-writer agent (host-side `claude -p`) that
consumes the finding + the pipeline's raw analysis as *input* and writes the
entire report in GENERIC, class-agnostic sections — so a deserialization, sandbox
escape, command-injection, SSRF, or memory finding all render the same
professional way, with no memory-safety jargon leaking through. A deterministic
template fallback (also generic) guarantees a report even offline / under
throttling.

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
import time

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
        "fixed_version": None,
        "cvss": None,
        "advisory_url": None,
    }


# ── deserializer identification (so CWE-502 fixes match the real sink) ─────────
# Tokens are ordered so the most specific loader wins; frame filenames in the
# oracle evidence (e.g. `_dill.py`) and the `x.loads(...)` calls in the analysis
# both feed the match. Only `yaml` has a safe loader; the pickle family does not.
_DESER_LIBS = [
    ("dill",        ("_dill.py", "dill.load", "dill.loads")),
    ("cloudpickle", ("cloudpickle",)),
    ("joblib",      ("joblib.load", "joblib.loads")),
    ("jsonpickle",  ("jsonpickle",)),
    ("marshal",     ("marshal.load", "marshal.loads")),
    ("yaml",        ("yaml.load", "fullloader", "unsafeloader", "constructor.py")),
    ("pickle",      ("pickle.load", "pickle.loads", "_pickle", "unpickl", "__reduce__")),
]


def _deserializer_lib(run: dict) -> str:
    """Best-effort name of the deserializer behind a CWE-502 finding, from the
    evidence + analysis. Defaults to pickle (safe generic: pickle-family advice
    is correct for any code-executing deserializer, unlike the yaml-only fix)."""
    hay = " ".join([run.get("finding_type", ""), run.get("finding_evidence", ""),
                    run.get("analysis_text", "")]).lower()
    for lib, toks in _DESER_LIBS:
        if any(t in hay for t in toks):
            return lib
    return "pickle"


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


def _injected_from_evidence(ev: str) -> str:
    """The concrete dangerous operation the oracle captured (its `detail:` line)."""
    m = re.search(r"^detail:\s*(.+)$", ev or "", re.M)
    return m.group(1).strip() if m else ""


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

    exec_proof = ""
    ep = os.path.join(results_dir, "exec_proof.txt")
    if os.path.exists(ep):
        try:
            exec_proof = open(ep, encoding="utf-8", errors="replace").read()
        except Exception:
            pass

    target = rj.get("target", "?")
    return {
        "target": target,
        "exec_proof": exec_proof,
        "status": rj.get("status", "?"),
        "confirmed": rj.get("status") in _CONFIRMED,
        "finding_type": ft,
        "finding_evidence": ev,
        "injected_command": _injected_from_evidence(ev),
        "poc_bytes": poc,
        "reproduction_command": finding.get("reproduction_command", ""),
        "exit_code": finding.get("exit_code", -1),
        "severity": severity,
        "analysis_text": analysis,
        "config_text": _find_config(results_dir, target),
    }


# ── analysis parsing (used only as SOURCE material, never displayed raw) ───────

_ANALYSIS_SECTIONS = ["primitive", "reachability", "heap_layout",
                      "escalation_path", "constraints", "escalation_attempt"]


def _parse_analysis(text: str) -> list:
    out = []
    for tag in _ANALYSIS_SECTIONS:
        m = re.search(rf"<{tag}>(.*?)</{tag}>", text or "", re.DOTALL)
        if m and m.group(1).strip():
            out.append((tag.replace("_", " ").title(), m.group(1).strip()))
    return out


# ── remediation templates (generic fallback, class-specific) ──────────────────

_REMEDIATION_BY_CWE = {
    "CWE-78": [
        {"title": "Remove the shell — pass arguments as a list",
         "location": "the subprocess call that uses shell=True",
         "fix_code": ("# Vulnerable: one shell string with the value interpolated in\n"
                      "#   subprocess.Popen('antiword \"%s\"' % filename, shell=True)\n"
                      "# Fixed: an argument vector, no shell\n"
                      "subprocess.Popen(['antiword', filename], shell=False,\n"
                      "                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)"),
         "detail": ("With shell=False and an argument list the OS passes each element to "
                    "the program verbatim; the shell never re-parses it, so $(...), "
                    "backticks, ;, |, & in attacker-controlled values become inert. Apply "
                    "this to EVERY shell-backed parser, not only the one in the PoC.")},
        {"title": "Upgrade to the fixed release",
         "location": None, "fix_code": None,
         "detail": ("Consult the {cve} advisory for the first fixed version and pin to it "
                    "(or later); this resolves all shell-backed parsers at once.")},
        {"title": "Constrain the input as defense in depth",
         "location": None, "fix_code": None,
         "detail": ("Reject or normalise filenames containing shell metacharacters or path "
                    "separators before they reach the extractor; treat all externally "
                    "supplied names as untrusted.")},
    ],
    "CWE-918": [
        {"title": "Validate the final destination, not just the first URL",
         "location": "the outbound request / URL fetcher",
         "fix_code": ("# Disable transparent redirects so a redirect cannot bounce past your\n"
                      "# check, then re-validate every hop against an allow-list.\n"
                      "resp = requests.get(url, allow_redirects=False, timeout=5)\n"
                      "# re-check resp.headers.get('Location') AND the resolved IP before "
                      "following"),
         "detail": ("SSRF guards that inspect only the initial URL are bypassed by an open "
                    "redirect. Turn off automatic redirect following and re-apply the "
                    "allow-list and IP checks (blocking link-local/private ranges) to each "
                    "hop and to the resolved address.")},
        {"title": "Upgrade the library",
         "location": None, "fix_code": None,
         "detail": "Pin to the release that fixes {cve}."},
        {"title": "Egress-restrict the service",
         "location": None, "fix_code": None,
         "detail": ("Limit the component's outbound network to the destinations it "
                    "legitimately needs, so a bypass has nowhere to reach.")},
    ],
    "CWE-22": [
        {"title": "Canonicalise and confine the path",
         "location": "the file-path construction",
         "fix_code": ("import os\n"
                      "base = os.path.realpath(BASE_DIR)\n"
                      "target = os.path.realpath(os.path.join(base, user_path))\n"
                      "if not (target == base or target.startswith(base + os.sep)):\n"
                      "    raise ValueError('path escapes base directory')"),
         "detail": ("Resolve symlinks and '..' with realpath, then verify the result is "
                    "still inside the intended base directory before opening it.")},
        {"title": "Upgrade the library",
         "location": None, "fix_code": None,
         "detail": "Pin to the release that fixes {cve}."},
    ],
}

_REMEDIATION_GENERIC = [
    {"title": "Treat the input as untrusted and validate it",
     "location": None, "fix_code": None,
     "detail": ("Constrain or sanitise the attacker-controlled value before it reaches the "
                "vulnerable operation.")},
    {"title": "Upgrade to a patched release",
     "location": None, "fix_code": None,
     "detail": ("Consult the {cve} advisory for the first fixed version and pin to it or "
                "later.")},
]

_REMEDIATION_TEST = {
    "title": "Add a regression test built from the proof-of-concept",
    "location": None, "fix_code": None,
    "detail": ("Turn the PoC in this report into an automated test so the fix is verified "
               "now and cannot silently regress later.")}


def _remediation_deser(lib: str, cve: str, fixed_version) -> list:
    """CWE-502 remediation matched to the ACTUAL deserializer. `yaml` has a safe
    loader; the pickle family (pickle/dill/joblib/cloudpickle/marshal/jsonpickle)
    does not — so their fix is 'don't deserialize untrusted data', an allow-listed
    unpickler, authorize-before-deserialize, and a trust boundary on the source."""
    upgrade_detail = (
        "Upgrade to the vendor-patched release"
        + (f" (**{fixed_version}** or later)" if fixed_version
           else f" — consult the {cve} advisory for the first fixed version")
        + " and pin to it. Note a library upgrade fixes only the *specific* call path "
          "the vendor patched; verify every other sink that deserializes the same "
          "untrusted data is covered too, or apply the code-level fixes below to each.")

    if lib == "yaml":
        return [
            {"title": "Deserialize with a safe loader only",
             "location": "the yaml.load call",
             "fix_code": ("# Vulnerable: yaml.load(data)  or  yaml.load(data, Loader=FullLoader)\n"
                          "import yaml\n"
                          "obj = yaml.safe_load(data)   # constructs only plain data types"),
             "detail": ("yaml.safe_load refuses to instantiate arbitrary Python objects — the "
                        "exact behaviour that turns YAML deserialization into code execution. "
                        "Never call the full/unsafe loader on untrusted input.")},
            {"title": "Upgrade the library", "location": None, "fix_code": None,
             "detail": upgrade_detail},
            {"title": "Isolate any required rich deserialization", "location": None, "fix_code": None,
             "detail": ("If complex objects are unavoidable, define an explicit allow-list of "
                        "safe types or run deserialization in a sandboxed, least-privilege process.")},
        ]

    return [
        {"title": f"Do not deserialize untrusted data with {lib}",
         "location": f"the {lib}.loads / {lib}.load call on attacker-influenceable bytes",
         "fix_code": None,
         "detail": (f"`{lib}` reconstructs objects by executing embedded constructor / "
                    f"`__reduce__` code, so `{lib}.loads()` on data that crosses a trust "
                    f"boundary is remote code execution by design — `{lib}` has no 'safe "
                    "mode' or restricted loader that refuses to execute embedded code. Where "
                    "the payload is your own data, replace the serialization format with a "
                    "data-only one (JSON, or Protobuf / FlatBuffers carrying plain fields) so "
                    "no code can ride along.")},
        {"title": "Run authorization BEFORE deserialization",
         "location": "every request handler that deserializes network / registry input",
         "fix_code": ("# Vulnerable order — bytes are deserialized before the authz check,\n"
                      "# so the attacker's code has already run by the time it is consulted:\n"
                      "#   obj = FeatureView.from_proto(request.spec)   # <-- dill.loads() here\n"
                      "#   assert_permissions_to_update(obj)            # too late\n"
                      "# Fixed — authorize first, deserialize only after:\n"
                      "assert_permissions_to_update(request)\n"
                      "obj = FeatureView.from_proto(request.spec)"),
         "detail": ("If any authentication / authorization runs *after* the deserialization "
                    "call, it cannot mitigate the flaw — reconstruction already executed the "
                    "payload. Reorder every handler so permission checks complete before "
                    "untrusted bytes are deserialized.")},
        {"title": "If rich deserialization is unavoidable, restrict it with an allow-listed unpickler",
         "location": "wherever trusted objects must still be loaded",
         "fix_code": ("import io, pickle\n"
                      "_ALLOWED = {(\"mymodule\", \"SafeClass\")}   # (module, qualname) allow-list\n"
                      "class RestrictedUnpickler(pickle.Unpickler):\n"
                      "    def find_class(self, module, name):\n"
                      "        if (module, name) not in _ALLOWED:\n"
                      "            raise pickle.UnpicklingError(f\"blocked {module}.{name}\")\n"
                      "        return super().find_class(module, name)\n"
                      "obj = RestrictedUnpickler(io.BytesIO(data)).load()"),
         "detail": ("A find_class allow-list caps which classes / callables the stream may "
                    "reconstruct, blocking os.system / subprocess / builtins gadgets. This is "
                    "a stdlib-pickle feature; dill does not expose it cleanly, so migrate the "
                    "trusted-load path to pickle with this subclass — or drop rich objects.")},
        {"title": "Treat the serialized-object source as a trust boundary",
         "location": None, "fix_code": None,
         "detail": ("Whoever can write the bytes controls code execution. Restrict write "
                    "access to the store the objects come from — registry file / database, "
                    "S3 / GCS blob, or a remote server response — and authenticate and pin "
                    "that source so a rogue or MITM'd origin cannot supply a payload.")},
        {"title": "Upgrade to the patched release", "location": None, "fix_code": None,
         "detail": upgrade_detail},
    ]


def _remediation_template(labels: dict, lib: str | None = None) -> list:
    cve = labels.get("cve") or "the upstream"
    if labels["cwe"] == "CWE-502":
        items = _remediation_deser(lib or "pickle", cve, labels.get("fixed_version"))
    else:
        items = list(_REMEDIATION_BY_CWE.get(labels["cwe"], _REMEDIATION_GENERIC))
    items = items + [_REMEDIATION_TEST]
    return [{k: (v.replace("{cve}", cve) if isinstance(v, str) else v)
             for k, v in it.items()} for it in items]


def _references(labels: dict) -> list:
    refs = []
    if labels.get("cve"):
        refs.append(labels["cve"])
    refs.append(f"{labels['cwe']}: {labels['cwe_name']}")
    if labels.get("advisory_url"):
        refs.append(labels["advisory_url"])
    return refs


# ── report-time enrichment (NEVER touches the blind find / config.yaml) ────────
# The scan runs blind: config.yaml carries no hints, so the find agent cannot be
# biased. Facts a blind, egress-locked scan cannot know — the assigned CVE, the
# upstream fixed version, a CVSS score, and human-verified exploitability/exposure
# notes — are supplied here, AFTER the finding is confirmed, and are consumed only
# by the report. Source: <results_dir>/enrichment.json, overlaid by CLI flags.
_ENRICH_KEYS = ("cve", "cvss", "fixed_version", "advisory_url", "context", "poc_scope")


def load_enrichment(results_dir: str, cli: dict | None = None) -> dict:
    enr = {}
    p = os.path.join(results_dir, "enrichment.json")
    if os.path.exists(p):
        try:
            enr = json.load(open(p, encoding="utf-8")) or {}
        except Exception:
            enr = {}
    for k, v in (cli or {}).items():
        if v:                       # CLI overrides file, but only when actually set
            enr[k] = v
    return {k: enr[k] for k in _ENRICH_KEYS if enr.get(k)}


# ── report narrative: template fallback + single report-writer agent ──────────

def _prose_template(run: dict, labels: dict) -> dict:
    """Deterministic, GENERIC narrative — no memory jargon, no second agent. Root
    cause reuses the substantive parts of the pipeline analysis (which carry the
    real file:line + code), under generic labels; the memory-only buckets are
    dropped."""
    cve = labels.get("cve")
    cve_txt = cve or "no assigned CVE"
    tgt = run["target"]
    cls = labels["cwe_name"]
    cls_l = cls.lower()
    lib = _deserializer_lib(run) if labels["cwe"] == "CWE-502" else None
    exit_code = run.get("exit_code", "?")

    parsed = _parse_analysis(run.get("analysis_text", ""))
    rc_parts = [body for title, body in parsed
                if title.lower() in ("primitive", "reachability")]
    root_summary = "\n\n".join(rc_parts) or (
        f"The finding is a {cls_l} ({labels['cwe']}). See the captured evidence and "
        f"proof-of-concept above for the concrete trigger.")
    esc = [body for title, body in parsed if title.lower() == "escalation path"]

    impact_txt = (
        f"An attacker able to supply input to this component can exploit a {cls_l} "
        f"issue in {tgt}. Because the scan confirmed it by executing the vulnerable "
        f"code path — not by source review alone — the risk is demonstrated rather "
        f"than theoretical. Confirmed severity: {labels['severity']}.")
    if esc:
        impact_txt += "\n\n" + esc[0]

    return {
        "exec_summary": (
            f"An automated security scan of **{tgt}** confirmed a {labels['severity']} "
            f"**{cls}** vulnerability ({cve_txt}, {labels['cwe']}). The scanner executed a "
            f"proof-of-concept through the vulnerable code path and its detection oracle "
            f"observed the dangerous operation actually occur (process aborted, exit "
            f"{exit_code}) — so the weakness is demonstrated by execution, not inferred "
            f"from source review. See the proof section for exactly what the "
            f"proof-of-concept did and did not exercise."),
        "description": (
            f"{tgt} contains a {cls_l} weakness ({labels['cwe']}). An attacker who can "
            f"control the input shown in the proof-of-concept can drive the component "
            f"into unsafe behaviour; the scan reproduced this deterministically."),
        "walkthrough": [
            f"The scanner supplied a crafted input to {tgt} through its entry "
            f"point (`{run.get('reproduction_command') or 'the target API'}`).",
            f"The input reached the vulnerable code path and triggered the {cls_l} "
            f"condition.",
            "The detection oracle observed the dangerous operation actually occur and "
            "recorded a confirmed finding — see the proof section for the captured "
            "evidence."],
        "impact": impact_txt,
        "root_cause": {"summary": root_summary, "locations": []},
        "remediation": _remediation_template(labels, lib),
        "references": _references(labels),
    }


_PROSE_PROMPT = textwrap.dedent("""\
    You are a senior application-security engineer writing the FINAL, client-ready
    narrative of a professional vulnerability report for a CONFIRMED,
    execution-verified finding. Audience: mixed (executives + engineers).

    Write clear, professional, class-appropriate prose. This is NOT a memory-safety
    bug unless the weakness class below says so — do NOT use memory jargon (heap
    layout, out-of-bounds, etc.) unless it genuinely applies.

    INPUTS
    ------
    Target: {target}
    Severity: {severity}
    Identifiers: {cve}, {cwe} ({cwe_name})
    Fixed version (if known; else "unknown — do not invent one"): {fixed}
    Reproduction command: {repro}
    Oracle evidence (what proved it):
    {evidence}
    Proof-of-concept input (decoded): {poc}
    Dangerous operation observed: {injected}
    Live execution-witness output (if any):
    {exec_proof}
    Human-verified exploitability / exposure context (AUTHORITATIVE — confirmed
    against the upstream advisory; weave these facts into the narrative, do not
    contradict them):
    ---
    {context}
    ---
    Pipeline technical analysis — SOURCE MATERIAL. It contains the REAL file paths,
    line numbers, and code. Extract exact locations/snippets from here, but rewrite
    all prose generically and professionally:
    ---
    {analysis}
    ---

    OUTPUT — output ONLY one JSON object (no code fence, no commentary) with EXACTLY
    these keys:
    {{
      "exec_summary": "3-4 sentences for leadership: what, how bad, proven by execution",
      "description": "one short paragraph: what the vulnerability is, plainly then precisely",
      "walkthrough": ["ordered attack steps, one string each"],
      "impact": "one paragraph: concrete consequences if exploited",
      "root_cause": {{
         "summary": "one short paragraph naming the exact flawed operation and why it is unsafe",
         "locations": [
            {{"file": "exact/path.ext", "lines": "80-83",
              "snippet": "the exact vulnerable code, copied verbatim from the analysis",
              "explanation": "why THIS code is the flaw"}}
         ]
      }},
      "remediation": [
         {{"title": "short imperative fix",
           "location": "file.ext:NN (or empty)",
           "fix_code": "the corrected code, ready to paste (or empty)",
           "detail": "precise specification: what to change, why it works, edge cases, version notes"}}
      ],
      "references": ["{cve}", "{cwe}", "an advisory URL only if you are certain of it"]
    }}

    Rules:
    - root_cause.locations MUST include the real file path(s), line number(s), and the
      verbatim vulnerable code snippet(s) taken from the analysis. Do not invent or alter them.
      If the analysis lists MULTIPLE sinks, include ALL of them as separate locations.
    - remediation MUST match the ACTUAL vulnerable primitive. For pickle-family
      deserializers (pickle / dill / joblib / cloudpickle / marshal) there is NO safe loader:
      do NOT suggest `yaml.safe_load`. Instead: stop deserializing untrusted data, authorize
      BEFORE deserializing, restrict with an allow-listed unpickler (find_class), treat the
      byte source as a trust boundary, and upgrade to the fixed version if known.
    - If the finding is reachable over a network / registry boundary, state explicitly whether
      any authentication / authorization runs BEFORE or AFTER the vulnerable operation in the
      call order, and therefore whether enabling auth actually mitigates it.
    - State the component's default exposure (default auth mode, listening port) if the context
      or analysis reveals it.
    - If multiple sinks exist, scope the fix: say which sink(s) an upgrade covers and which may
      remain — do not imply an upgrade closes all of them.
    - Be honest about what the PoC proved: distinguish "the sink was confirmed dangerous in an
      isolated harness" from "the full end-to-end network attack was replayed against a live
      server". Do not claim the latter unless the evidence shows it.
    - Cite the Fixed version above in remediation if known; otherwise say to consult the
      advisory. Never invent a version, CVE, CVSS, or URL.
    - remediation is specific and paste-ready, ordered primary-fix -> hardening; make the LAST
      item a regression-test recommendation built from the PoC.
    - Output valid JSON only.
    """)


def _merge_prose(base: dict, data: dict) -> dict:
    """Overlay validated agent output on the template defaults, so partial or
    malformed agent output still yields a complete report."""
    out = dict(base)
    for k in ("exec_summary", "description", "impact"):
        if isinstance(data.get(k), str) and data[k].strip():
            out[k] = data[k]
    if isinstance(data.get("walkthrough"), list) and data["walkthrough"]:
        out["walkthrough"] = [str(x) for x in data["walkthrough"]]
    rc = data.get("root_cause")
    if isinstance(rc, dict):
        merged = dict(out["root_cause"])
        if isinstance(rc.get("summary"), str) and rc["summary"].strip():
            merged["summary"] = rc["summary"]
        if isinstance(rc.get("locations"), list):
            locs = [{k: str(loc.get(k, "")) for k in ("file", "lines", "snippet", "explanation")}
                    for loc in rc["locations"] if isinstance(loc, dict)]
            if locs:
                merged["locations"] = locs
        out["root_cause"] = merged
    if isinstance(data.get("remediation"), list) and data["remediation"]:
        rem = []
        for r in data["remediation"]:
            if isinstance(r, dict):
                rem.append({k: str(r.get(k, "")) for k in ("title", "location", "fix_code", "detail")})
            elif isinstance(r, str):
                rem.append({"title": r, "location": "", "fix_code": "", "detail": ""})
        if rem:
            out["remediation"] = rem
    if isinstance(data.get("references"), list) and data["references"]:
        out["references"] = [str(x) for x in data["references"]]
    return out


def _load_token_env() -> dict:
    env = dict(os.environ)
    tok = "/root/.vp_token"
    if "CLAUDE_CODE_OAUTH_TOKEN" not in env and os.path.exists(tok):
        try:
            env["CLAUDE_CODE_OAUTH_TOKEN"] = open(tok).read().strip()
        except Exception:
            pass
    return env


def _poc_for_prompt(poc: bytes) -> str:
    """Represent the PoC for the agent prompt. A binary PoC (e.g. a pickle/dill
    stream) is rendered as hex — decoding it to text would smuggle NUL bytes into
    the string, and a NUL cannot appear in a subprocess argv (raises ValueError:
    embedded null byte). Text PoCs (YAML, shell) pass through readably."""
    if not poc:
        return "(no PoC bytes)"
    head = poc[:500]
    if all(c in (9, 10, 13) or 32 <= c < 127 for c in head):
        return head.decode("utf-8", "replace")
    return f"(binary, {len(poc)} bytes; hex head) {poc[:96].hex()}"


def _build_prompt(run: dict, labels: dict) -> str:
    """Assemble the report-writer prompt and strip any NUL bytes — argv is NUL-free."""
    prompt = _PROSE_PROMPT.format(
        target=run["target"], severity=labels["severity"],
        cve=labels.get("cve") or "no CVE", cwe=labels["cwe"], cwe_name=labels["cwe_name"],
        fixed=labels.get("fixed_version") or "unknown",
        repro=run.get("reproduction_command") or "(n/a)",
        evidence=(run.get("finding_evidence") or "(none)")[:2000],
        poc=_poc_for_prompt(run.get("poc_bytes") or b""),
        injected=run.get("injected_command") or "(n/a)",
        exec_proof=(run.get("exec_proof") or "(none)")[:1500],
        context=(run.get("context_note") or "(none provided)")[:3000],
        analysis=(run.get("analysis_text") or "(none)")[:7000])
    return prompt.replace("\x00", "�")


def _agent_prose(run: dict, labels: dict, model: str | None, timeout: int = 240) -> dict:
    """One report-writer agent call (host-side claude -p). Returns parsed JSON or raises."""
    cmd = ["claude", "-p", _build_prompt(run, labels)]
    if model:
        cmd += ["--model", model]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                         env=_load_token_env())
    out = res.stdout or ""
    if "{" not in out:
        raise RuntimeError((res.stderr or "empty agent output")[:200])
    return json.loads(out[out.index("{"):out.rindex("}") + 1])


def write_prose(run: dict, labels: dict, model: str | None = None,
                retries: int = 2) -> tuple:
    """Run the report-writer agent, retrying on failure (this environment throttles
    the API mid-run). Returns (prose, source): source is 'agent' on success, or
    'template' if every attempt failed — the caller flags that loudly rather than
    passing a generic template off as the real report."""
    base = _prose_template(run, labels)
    last = ""
    for attempt in range(max(1, retries + 1)):
        try:
            return _merge_prose(base, _agent_prose(run, labels, model)), "agent"
        except Exception as e:  # noqa: BLE001 — any failure is retried, then flagged
            last = str(e)
            if attempt < retries:
                time.sleep(3 * (attempt + 1))
    sys.stderr.write(f"[easyscan] WARNING: report-writer agent failed after "
                     f"{retries + 1} attempt(s): {last}\n")
    return base, "template"


# ── minimal, SAFE Markdown → HTML (escape-first) ───────────────────────────────
# All narrative is Markdown. We escape ALL HTML first, then re-introduce only a
# fixed, safe set of tags — so nothing in the source can inject markup and
# `<script>` etc. always render as text.

_URL_OK = re.compile(r"^(https?://|mailto:)", re.I)


def _md_inline(text) -> str:
    """Escape HTML, then apply INLINE Markdown: `code`, **bold**, *italic*, links."""
    s = html.escape(str(text), quote=False)
    spans: list[str] = []

    def _stash(m):
        spans.append(m.group(1))
        return "\x00C%d\x00" % (len(spans) - 1)

    s = re.sub(r"``\s?(.+?)\s?``", _stash, s)   # double-backtick code spans
    s = re.sub(r"`([^`]+)`", _stash, s)         # single-backtick code spans

    def _link(m):
        label, url = m.group(1), m.group(2)
        if _URL_OK.match(url):
            return '<a href="%s" rel="noopener noreferrer">%s</a>' % (
                html.escape(url, quote=True), label)
        return label

    s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", _link, s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<em>\1</em>", s)
    s = re.sub(r"(?<![\w_])_([^_\n]+)_(?![\w_])", r"<em>\1</em>", s)

    def _restore(m):
        return "<code>%s</code>" % spans[int(m.group(1))]

    return re.sub("\x00C(\\d+)\x00", _restore, s)


def _md_to_html(text) -> str:
    """Render a block of Markdown to safe HTML: fenced code blocks, headings,
    bullet/numbered lists, and paragraphs; inline formatting via _md_inline."""
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return ""
    blocks: list[str] = []

    def _fence(m):
        blocks.append('<pre class="md-code"><code>%s</code></pre>'
                      % html.escape(m.group(1), quote=False))
        return "\n\x00B%d\x00\n" % (len(blocks) - 1)

    text = re.sub(r"```[^\n]*\n(.*?)\n?```", _fence, text, flags=re.DOTALL)

    out: list[str] = []
    para: list[str] = []

    def _flush():
        if para:
            out.append("<p>" + "<br>".join(_md_inline(x) for x in para) + "</p>")
            para.clear()

    lines = text.split("\n")
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        mb = re.fullmatch("\x00B(\\d+)\x00", stripped)
        if mb:
            _flush()
            out.append(blocks[int(mb.group(1))])
            i += 1
            continue
        if not stripped:
            _flush()
            i += 1
            continue
        mh = re.match(r"(#{1,6})\s+(.*)$", stripped)
        if mh:
            _flush()
            lvl = min(len(mh.group(1)) + 3, 6)   # '#' -> <h4>
            out.append("<h%d>%s</h%d>" % (lvl, _md_inline(mh.group(2)), lvl))
            i += 1
            continue
        if re.match(r"[-*+]\s+", stripped):
            _flush()
            items = []
            while i < len(lines) and re.match(r"\s*[-*+]\s+", lines[i]):
                items.append(re.sub(r"^\s*[-*+]\s+", "", lines[i]))
                i += 1
            out.append("<ul>%s</ul>"
                       % "".join("<li>%s</li>" % _md_inline(x) for x in items))
            continue
        if re.match(r"\d+\.\s+", stripped):
            _flush()
            items = []
            while i < len(lines) and re.match(r"\s*\d+\.\s+", lines[i]):
                items.append(re.sub(r"^\s*\d+\.\s+", "", lines[i]))
                i += 1
            out.append("<ol>%s</ol>"
                       % "".join("<li>%s</li>" % _md_inline(x) for x in items))
            continue
        para.append(stripped)
        i += 1
    _flush()
    return "\n".join(out)


def _render_reference(ref) -> str:
    ref = str(ref)
    m = re.match(r"(CVE-\d{4}-\d{4,7})", ref)
    if m:
        return '<a href="https://nvd.nist.gov/vuln/detail/%s" rel="noopener noreferrer">%s</a>' % (
            m.group(1), _e(ref))
    m = re.match(r"CWE-(\d+)", ref)
    if m:
        return '<a href="https://cwe.mitre.org/data/definitions/%s.html" rel="noopener noreferrer">%s</a>' % (
            m.group(1), _e(ref))
    if _URL_OK.match(ref):
        return '<a href="%s" rel="noopener noreferrer">%s</a>' % (html.escape(ref, quote=True), _e(ref))
    return _md_inline(ref)


# ── proof screenshots ─────────────────────────────────────────────────────────

_SEV_COLOR = {"CRITICAL": "#cf222e", "HIGH": "#bc4c00", "MEDIUM": "#9a6700",
              "LOW": "#0969da", "UNKNOWN": "#57606a", "NOT-A-BUG": "#57606a"}

# One plain-language sentence per weakness class, appended to the PoC explanation.
_CLASS_NOTE = {
    "CWE-78": "Here the bytes are treated as a **filename**, and the shell "
              "metacharacters inside them are what turn an ordinary call into "
              "command injection.",
    "CWE-502": "Here the bytes are a serialized object; **deserializing** them "
               "is what executes attacker-chosen code.",
    "CWE-918": "Here the bytes steer the server into contacting an "
               "attacker-chosen destination it should have refused.",
    "CWE-22": "Here the path components in the bytes **escape** the directory "
              "the target intended to stay inside.",
}


def _e(s):
    return html.escape(str(s))


def _build_proofs(run: dict, labels: dict) -> list:
    """Construct the (caption, explanation, screenshot) proof triples, each with a
    plain-language explanation so no screenshot is left unexplained."""
    injected = run.get("injected_command") or _injected_from_evidence(run["finding_evidence"])
    run["injected_command"] = injected

    poc = run["poc_bytes"]
    poc_lines = []
    if poc and all(b in (9, 10, 13) or 32 <= b < 127 for b in poc):
        poc_lines += ["attacker-supplied input (as text):", ""]
        poc_lines += ["    " + t for t in (poc.decode("utf-8", "replace").splitlines() or [""])]
        poc_lines += [""]
    poc_lines += ["raw bytes (hexdump):",
                  _hexdump(poc) if poc else "(no PoC bytes were recorded)"]
    poc_body = "\n".join(poc_lines)

    oracle_body = ((run["finding_evidence"] or "(no evidence captured)")
                   + f"\n\n[process exited {run['exit_code']}]")

    oracle_explain = (
        "This is the target's built-in **detection oracle** firing. Instead of "
        "guessing from the source, the scanner ran the input and the oracle watched "
        "the program actually perform the dangerous operation. The moment it did, "
        "the oracle aborted the process — that is the "
        f"`exit {run['exit_code']}` you see, and the banner names the exact primitive "
        "that fired"
        + (f", including the concrete command that was built: `{injected}`" if injected else "")
        + ". A harmless input leaves the oracle silent and the process exits 0.")

    poc_explain = (
        "This is the exact input the scanner supplied to trigger the finding — the "
        "complete proof-of-concept, nothing hidden. Feeding these same bytes to the "
        "target reproduces the result every time."
        + (" " + _CLASS_NOTE[labels["cwe"]] if labels["cwe"] in _CLASS_NOTE else ""))

    src = [
        ("Proof 1 — the detection oracle catching the exploit", oracle_explain, oracle_body),
        ("Proof 2 — the proof-of-concept input", poc_explain, poc_body),
    ]
    if run.get("exec_proof", "").strip():
        exec_explain = (
            "The detection oracle above aborts the process the instant it spots the "
            "injection — **before** the attacker's command can do harm; that is the "
            "safe design. To show the danger is real, this witness runs a **harmless** "
            "command (`id`) through the very same injection point in the sandbox. The "
            "`uid=…(root)` line is genuine output from that command actually executing "
            "— proof the attacker controls code execution, not merely the ability to "
            "trip a detector.")
        src.append(("Proof 3 — the injected command actually runs (live output)",
                    exec_explain, run["exec_proof"].strip()))
    return [(cap, explain, termshot(cap, tbody)) for cap, explain, tbody in src]


def _poc_caveat(run: dict, labels: dict, lib: str | None) -> str:
    """Honest, scope-accurate statement of what the PoC did and did NOT prove, so
    the report never implies the full network chain was replayed against a live
    server when only the sink was exercised in an isolated harness."""
    if run.get("poc_scope", "").strip():
        return run["poc_scope"]
    repro = run.get("reproduction_command") or "the entry point"
    tgt = run.get("target", "the target")
    code = run.get("exit_code", "?")
    if labels["cwe"] == "CWE-502":
        return (f"**Scope of this proof.** The PoC feeds bytes to `{repro}`, which invokes "
                f"`{lib or 'the deserializer'}.loads()` in an isolated harness that mirrors "
                f"{tgt}'s real deserialization call. It proves the primitive executes "
                f"attacker-chosen code (exit {code}) and that the callable and its arguments "
                f"are fully attacker-controlled; it was **not** run against a live {tgt} "
                f"service over the network, so the end-to-end attack chain is established "
                f"from the reachable call paths documented under Root cause, not replayed "
                f"here.")
    if run.get("exec_proof", "").strip():
        return (f"**Scope of this proof.** The oracle aborts at the moment of the dangerous "
                f"operation; a separate witness then runs a harmless command through the same "
                f"sink to show real execution. Together they prove the primitive is "
                f"exploitable in the built target — the full end-to-end attack against a "
                f"production deployment is inferred from the reachability analysis, not "
                f"replayed here.")
    return (f"**Scope of this proof.** The PoC was executed against the built target through "
            f"`{repro}` and the oracle confirmed the dangerous operation (exit {code}); it "
            f"demonstrates the vulnerable primitive rather than a full end-to-end attack "
            f"against a production deployment.")


# ── HTML assembler ────────────────────────────────────────────────────────────

_CSS = """<style>
  :root {
    color-scheme: light;   /* fixed light theme — do not follow the OS dark mode */
    --bg:#f6f8fa; --card:#ffffff; --text:#1f2328; --muted:#57606a; --border:#d0d7de;
    --line:#eaeef2; --code-bg:#eff2f5; --pre-bg:#0d1117; --pre-fg:#e6edf3; --accent:#0969da;
  }
  * { box-sizing: border-box; }
  body { font: 15px/1.65 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         color: var(--text); background: var(--bg); margin: 0; padding: 0 0 4rem;
         counter-reset: sec; }
  .wrap { max-width: 900px; margin: 0 auto; padding: 0 1.25rem; }
  header { background: #0d1117; color: #e6edf3; padding: 2rem 0; margin-bottom: 2rem;
           border-bottom: 3px solid var(--accent); }
  header .wrap { display: flex; align-items: center; justify-content: space-between;
                 gap: 1rem; flex-wrap: wrap; }
  header h1 { margin: 0; font-size: 1.5rem; font-weight: 650; }
  header .sub { color: #8b949e; font-size: .85rem; margin-top: .25rem; }
  .badge { display: inline-block; padding: .4rem 1rem; border-radius: 999px;
           color: #fff; font-weight: 700; letter-spacing: .04em; }
  section { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
            padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }
  section > h2 { font-size: 1.15rem; margin: 0 0 .75rem; padding-bottom: .4rem;
                 border-bottom: 2px solid var(--line); }
  section > h2::before { counter-increment: sec; content: counter(sec) ". ";
                         color: var(--muted); font-weight: 650; }
  h3 { font-size: .8rem; margin: 1.25rem 0 .4rem; color: var(--muted);
       text-transform: uppercase; letter-spacing: .05em; }
  .prose h4, .prose h5, .prose h6 { margin: .9rem 0 .3rem; font-size: .95rem; }
  p { margin: .55rem 0; }
  table.facts { border-collapse: collapse; width: 100%; }
  table.facts th { text-align: left; color: var(--muted); font-weight: 600; width: 170px;
                   padding: .4rem .6rem .4rem 0; vertical-align: top; }
  table.facts td { padding: .4rem 0; word-break: break-word;
                   font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  code { font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size: .88em;
         background: var(--code-bg); padding: .12em .35em; border-radius: 5px; }
  pre.md-code { background: var(--pre-bg); color: var(--pre-fg); border-radius: 8px;
                padding: .8rem 1rem; overflow-x: auto; border: 1px solid var(--border); }
  pre.md-code code { background: none; padding: 0; color: inherit;
                     font-size: .84rem; line-height: 1.5; }
  .prose { font-size: .92rem; }
  .prose ul, .prose ol { padding-left: 1.4rem; }
  .rc-loc { border-left: 3px solid var(--accent); padding: .1rem 0 .1rem 1rem; margin: 1rem 0; }
  .rc-hdr { font-size: .9rem; margin-bottom: .4rem; }
  ol.rem { padding-left: 1.5rem; }
  ol.rem > li { margin: 0 0 1.25rem; }
  .rem-title { font-weight: 650; font-size: 1rem; }
  .rem-loc { color: var(--muted); font-size: .85rem; margin: .2rem 0 .3rem; }
  figure.proof { margin: 0 0 1.75rem; }
  figure.proof .cap { font-weight: 650; color: var(--text); font-size: .98rem; margin-bottom: .3rem; }
  figure.proof .explain { color: var(--text); font-size: .9rem; margin-bottom: .6rem; }
  figure.proof img { width: 100%; border-radius: 8px; border: 1px solid var(--border); display: block; }
  ol, ul { margin: .3rem 0; padding-left: 1.4rem; }
  li { margin: .35rem 0; }
  .lead { font-size: 1.08rem; }
  .intro { color: var(--muted); margin-bottom: 1rem; }
  .caveat { border-left: 3px solid #9a6700; background: #fff8e6; padding: .6rem .9rem;
            border-radius: 6px; margin: 1.25rem 0 .5rem; font-size: .9rem; }
  .caveat p { margin: .3rem 0; }
  .degraded { border: 1px solid #d1242f; background: #fff0f0; color: #86181d;
              padding: .7rem 1rem; border-radius: 8px; margin-bottom: 1.25rem; font-size: .9rem; }
  footer { color: var(--muted); font-size: .8rem; text-align: center; margin-top: 2rem; }
</style>"""


def build_html(run: dict, labels: dict, prose: dict, proofs: list, degraded: str = "") -> str:
    sev = labels["severity"].upper()
    sev_color = _SEV_COLOR.get(sev, "#57606a")
    cve = labels["cve"] or "—"
    lib = _deserializer_lib(run) if labels["cwe"] == "CWE-502" else None

    facts = [("Target", run["target"]), ("Severity", sev), ("CVE", cve)]
    if labels.get("cvss"):
        facts.append(("CVSS", str(labels["cvss"])))
    facts += [("Weakness", f"{labels['cwe']} — {labels['cwe_name']}"),
              ("Finding type", run["finding_type"])]
    if labels.get("fixed_version"):
        facts.append(("Fixed version", str(labels["fixed_version"])))
    facts += [("Status", run["status"]),
              ("PoC size", f"{len(run['poc_bytes'])} bytes"),
              ("Oracle exit code", str(run["exit_code"]))]
    facts_rows = "\n".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in facts)
    inj_row = (f"<tr><th>Injected command</th><td>{_e(run.get('injected_command'))}</td></tr>"
               if run.get("injected_command") else "")

    description = _md_to_html(prose.get("description", "")) or "<p>—</p>"
    walk = "\n".join(f"<li>{_md_inline(s)}</li>" for s in prose["walkthrough"])
    impact = _md_to_html(prose.get("impact", "")) or "<p>—</p>"

    rc = prose.get("root_cause") or {}
    rc_summary = _md_to_html(rc.get("summary", "")) or "<p>—</p>"
    rc_locs = ""
    for loc in rc.get("locations", []):
        hdr = _e(loc.get("file", ""))
        if loc.get("lines"):
            hdr += ":" + _e(loc["lines"])
        snip = loc.get("snippet", "") or ""
        snip_html = (f'<pre class="md-code"><code>{_e(snip)}</code></pre>'
                     if snip.strip() else "")
        rc_locs += (f'<div class="rc-loc"><div class="rc-hdr"><code>{hdr}</code></div>'
                    f'{snip_html}{_md_to_html(loc.get("explanation", ""))}</div>')

    rem = ""
    for r in prose.get("remediation", []):
        if isinstance(r, str):
            r = {"title": r}
        loc = (r.get("location") or "").strip()
        fix = (r.get("fix_code") or "").strip()
        loc_html = f'<div class="rem-loc">Location: <code>{_e(loc)}</code></div>' if loc else ""
        fix_html = f'<pre class="md-code"><code>{_e(fix)}</code></pre>' if fix else ""
        rem += (f'<li><div class="rem-title">{_md_inline(r.get("title", ""))}</div>'
                f'{loc_html}{_md_to_html(r.get("detail", ""))}{fix_html}</li>')

    refs = "\n".join(f"<li>{_render_reference(x)}</li>" for x in prose.get("references", []))

    repro_block = (
        "<h3>Reproduce it yourself</h3>"
        "<p>Run this one command against the built target — it aborts with "
        f"<code>exit {_e(run['exit_code'])}</code> again, deterministically:</p>"
        f'<pre class="md-code"><code>{_e(run["reproduction_command"] or "(not recorded)")}</code></pre>')

    proof_html = ""
    for cap, explain, png in proofs:
        b64 = base64.b64encode(png).decode()
        proof_html += (
            '<figure class="proof">'
            f'<div class="cap">{_e(cap)}</div>'
            f'<div class="explain">{_md_to_html(explain)}</div>'
            f'<img alt="{_e(cap)}" src="data:image/png;base64,{b64}"/>'
            "</figure>\n")

    caveat_html = _md_to_html(_poc_caveat(run, labels, lib))
    context_section = ""
    if run.get("context_note", "").strip():
        context_section = ('\n<section><h2>Exploitability &amp; exposure</h2>'
                           f'<div class="prose">{_md_to_html(run["context_note"])}</div></section>')
    degraded_html = (f'<div class="degraded">{_md_to_html(degraded)}</div>'
                     if degraded.strip() else "")

    body = f"""<body>
<header><div class="wrap">
  <div><h1>Security Assessment: {_e(run['target'])}</h1>
    <div class="sub">EasyScan — execution-verified vulnerability report</div></div>
  <span class="badge" style="background:{sev_color}">{_e(sev)}</span>
</div></header>
<div class="wrap">
{degraded_html}
<section><h2>Executive summary</h2>
  <p class="lead">{_md_inline(prose['exec_summary'])}</p></section>

<section><h2>Finding overview</h2>
  <table class="facts">{facts_rows}{inj_row}</table></section>

<section><h2>Description</h2>
  <div class="prose">{description}</div></section>

<section><h2>Attack walkthrough</h2>
  <ol>{walk}</ol></section>

<section><h2>Proof of concept</h2>
  <p class="intro">The scanner did not just read the source; it executed a
  proof-of-concept through the vulnerable code path and captured what happened.
  Each screenshot below is real captured output — here is what it shows and why
  it matters.</p>
  {proof_html}
  <div class="caveat">{caveat_html}</div>
  {repro_block}</section>

<section><h2>Root cause</h2>
  <div class="prose">{rc_summary}</div>
  {rc_locs}</section>
{context_section}
<section><h2>Impact</h2>
  <div class="prose">{impact}</div></section>

<section><h2>Remediation</h2>
  <ol class="rem">{rem}</ol></section>

<section><h2>References</h2>
  <ul>{refs}</ul></section>

<footer>Generated by EasyScan · findings demonstrated by executing a proof-of-concept
through the vulnerable sink (see the Proof of concept section for scope) · review
before acting · for authorized security research only.</footer>
</div></body></html>"""

    return ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<title>Security Report — {_e(run["target"])} ({_e(sev)})</title>\n'
            + _CSS + "</head>\n" + body)


# ── summary.json + CLI ────────────────────────────────────────────────────────

def write_summary(results_dir: str, run: dict, labels: dict) -> dict:
    summary = {
        "target": run["target"],
        "status": run["status"],
        "confirmed": bool(run["confirmed"]),
        "severity": labels["severity"],
        "cve": labels["cve"],
        "cvss": labels.get("cvss"),
        "cwe": labels["cwe"],
        "finding_type": run["finding_type"],
        "fixed_version": labels.get("fixed_version"),
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
                    help="skip the agent; use the deterministic template (flagged in the report)")
    ap.add_argument("--require-agent", action="store_true",
                    help="exit 3 instead of writing a template report if the agent is unavailable")
    ap.add_argument("--prose-file", default=None,
                    help="render from a human-authored/verified prose JSON (no agent, no template)")
    ap.add_argument("--cve", default=None, help="report-time enrichment: assigned CVE id")
    ap.add_argument("--cvss", default=None, help="report-time enrichment: CVSS score")
    ap.add_argument("--fixed-version", default=None, help="report-time enrichment: fixed version")
    ap.add_argument("--advisory", default=None, help="report-time enrichment: advisory URL")
    args = ap.parse_args(argv)

    run = load_run(args.results_dir)
    labels = derive_labels(run["config_text"], run["finding_type"], run["severity"])

    enr = load_enrichment(args.results_dir, {
        "cve": args.cve, "cvss": args.cvss,
        "fixed_version": args.fixed_version, "advisory_url": args.advisory})
    if enr.get("cve"):
        labels["cve"] = enr["cve"]
    labels["fixed_version"] = enr.get("fixed_version")
    labels["cvss"] = enr.get("cvss")
    labels["advisory_url"] = enr.get("advisory_url")
    run["context_note"] = enr.get("context", "")
    run["poc_scope"] = enr.get("poc_scope", "")

    degraded = ""
    if args.prose_file:
        with open(args.prose_file, encoding="utf-8") as f:
            prose = _merge_prose(_prose_template(run, labels), json.load(f))
        source = "authored"
    elif args.no_agent:
        prose, source = _prose_template(run, labels), "template"
    else:
        prose, source = write_prose(run, labels, args.model)
        if source == "template":
            if args.require_agent:
                sys.stderr.write("[easyscan] ERROR: --require-agent set but the report-writer "
                                 "agent was unavailable; refusing to ship a template report.\n")
                return 3
            degraded = ("This report was produced by the deterministic **fallback template** "
                        "because the report-writer agent was unavailable (e.g. API throttling). "
                        "The prose is generic — re-run `report.py` (optionally `--require-agent`) "
                        "to get the full agent-written narrative.")

    proofs = _build_proofs(run, labels)

    out_html = os.path.join(args.results_dir, "report.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(build_html(run, labels, prose, proofs, degraded=degraded))
    write_summary(args.results_dir, run, labels)

    print(f"[easyscan] report:  {os.path.abspath(out_html)}")
    print(f"[easyscan] summary: {os.path.abspath(os.path.join(args.results_dir, 'summary.json'))}")
    print(f"[easyscan] prose:   {source}")
    print(f"[easyscan] result:  {run['status']}  severity={labels['severity']}"
          f"  {labels['cve'] or ''}")
    return 2 if run["confirmed"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
