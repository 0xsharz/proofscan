# EasyScan Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A one-command install + one-command trigger wrapper around the
defending-code-reference harness that emits a professional self-contained HTML
report (with rendered terminal-screenshot proofs, plain-language walkthrough,
remediation) plus a machine-readable `summary.json` and CI exit codes.

**Architecture:** Hybrid — deterministic Python (`report.py`) renders the
proof PNGs, maps CVE/CWE, and assembles the HTML + summary.json; an optional
LLM "report-writer" pass (host-side `claude -p`) writes the human prose, with
a deterministic template fallback so a report always renders. Two thin shell
scripts (`install.sh`, `scan.sh`) do setup and orchestration.

**Tech Stack:** Python 3.11 (stdlib + Pillow), the `claude` CLI (already in
WSL), bash, Docker/gVisor harness underneath.

## Global Constraints

- Runs in the WSL harness env; source lives in `easyscan/` in the repo.
- Core harness is NOT modified — EasyScan is a pure wrapper layer.
- Only new Python dep: `pillow`. Font: DejaVu Sans Mono (apt `fonts-dejavu-core`).
- Report HTML must be **self-contained** — every image base64-inlined, CSS inline.
- `report.py` must read BOTH result.json schemas: new (`finding`/`finding_type`/
  `finding_evidence`/`finding_confirmed`) and old (`crash`/`crash_type`/
  `crash_output`/`crash_found`).
- Exit-code contract: `0` = no confirmed finding, `2` = confirmed finding,
  `1` = setup/usage error.
- The report-writer agent is OPTIONAL: any failure → deterministic template.

---

### Task 1: `termshot()` — terminal-screenshot PNG renderer

**Files:**
- Create: `easyscan/report.py`
- Test: `easyscan/tests/test_report.py`

**Interfaces:**
- Produces: `termshot(title: str, body: str, cols: int = 100) -> bytes`
  returns PNG bytes of a dark-terminal image with a title bar + monospace body.

- [ ] **Step 1: Write the failing test**

```python
# easyscan/tests/test_report.py
import importlib.util, os
spec = importlib.util.spec_from_file_location(
    "report", os.path.join(os.path.dirname(__file__), "..", "report.py"))
report = importlib.util.module_from_spec(spec); spec.loader.exec_module(report)

def test_termshot_returns_png():
    png = report.termshot("oracle output", "line one\nline two\nexit=134")
    assert isinstance(png, bytes) and len(png) > 200
    assert png[:8] == b"\x89PNG\r\n\x1a\n"   # PNG magic
```

- [ ] **Step 2: Run test to verify it fails** — `pytest easyscan/tests/test_report.py::test_termshot_returns_png -v` → FAIL (no module / attr).

- [ ] **Step 3: Implement `termshot`**

```python
# easyscan/report.py
import io, os
from PIL import Image, ImageDraw, ImageFont

_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
]
_BG = (13, 17, 23); _FG = (201, 209, 217); _BAR = (33, 38, 45)
_TITLE = (139, 148, 158); _GREEN = (63, 185, 80); _RED = (248, 81, 73)

def _load_font(size):
    for p in _FONT_CANDIDATES:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()

def termshot(title, body, cols=100):
    fsize = 15; pad = 16; bar_h = 34
    font = _load_font(fsize)
    ch_w = font.getbbox("M")[2]; line_h = fsize + 6
    lines = []
    for raw in body.replace("\t", "    ").splitlines() or [""]:
        while len(raw) > cols:
            lines.append(raw[:cols]); raw = raw[cols:]
        lines.append(raw)
    w = pad * 2 + ch_w * cols
    h = bar_h + pad * 2 + line_h * max(1, len(lines))
    img = Image.new("RGB", (w, h), _BG); d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, bar_h], fill=_BAR)
    for i, c in enumerate([_RED, (210, 153, 34), _GREEN]):
        d.ellipse([pad + i * 20, 11, pad + i * 20 + 12, 23], fill=c)
    d.text((pad + 74, 9), title, fill=_TITLE, font=_load_font(13))
    y = bar_h + pad
    for ln in lines:
        color = _FG
        if "ERROR" in ln or "failed" in ln or "vulnerability confirmed" in ln:
            color = _RED
        elif ln.strip().startswith("exit=0") or "benign" in ln:
            color = _GREEN
        d.text((pad, y), ln, fill=color, font=font); y += line_h
    buf = io.BytesIO(); img.save(buf, "PNG"); return buf.getvalue()
```

- [ ] **Step 4: Run test to verify it passes** — same command → PASS.
- [ ] **Step 5: Commit** — `git add easyscan/report.py easyscan/tests/test_report.py && git commit -m "feat(easyscan): termshot terminal-screenshot renderer"`

---

### Task 2: `derive_labels()` — CVE/CWE/severity mapping

**Files:** Modify `easyscan/report.py`; Test `easyscan/tests/test_report.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `derive_labels(config_text: str, finding_type: str, severity: str) -> dict`
  returns `{"cve": str|None, "cwe": str, "cwe_name": str, "severity": str}`.

- [ ] **Step 1: Write the failing test**

```python
def test_derive_labels_maps_class_and_extracts_cve():
    cfg = "attack_surface: |\n  ... CVE-2020-14343 ... yaml.load"
    labels = report.derive_labels(cfg, "compile", "CRITICAL")
    assert labels["cve"] == "CVE-2020-14343"
    assert labels["cwe"] == "CWE-502"
    assert "Deserialization" in labels["cwe_name"]
    assert labels["severity"] == "CRITICAL"

def test_derive_labels_command_injection_and_no_cve():
    labels = report.derive_labels("no cve here", "subprocess.Popen-injection", "HIGH")
    assert labels["cve"] is None
    assert labels["cwe"] == "CWE-78"
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement**

```python
import re
_CWE_BY_SINK = [
    (("compile", "exec", "yaml", "pickle", "deserial"), ("CWE-502", "Deserialization of Untrusted Data")),
    (("os.system", "subprocess", "-injection", "command"), ("CWE-78", "OS Command Injection")),
    (("ssrf", "redirect", "socket.connect"), ("CWE-918", "Server-Side Request Forgery")),
    (("path-traversal", "zip", "open:", "traversal"), ("CWE-22", "Path Traversal")),
    (("heap-buffer-overflow", "stack-buffer-overflow", "WRITE"), ("CWE-787", "Out-of-bounds Write")),
    (("use-after-free", "double-free"), ("CWE-416", "Use After Free")),
]
def derive_labels(config_text, finding_type, severity):
    m = re.search(r"CVE-\d{4}-\d{4,7}", config_text or "")
    ft = (finding_type or "").lower()
    cwe, cwe_name = ("CWE-693", "Protection Mechanism Failure")
    for keys, (c, n) in _CWE_BY_SINK:
        if any(k in ft for k in keys):
            cwe, cwe_name = c, n; break
    return {"cve": m.group(0) if m else None, "cwe": cwe,
            "cwe_name": cwe_name, "severity": severity or "UNKNOWN"}
```

- [ ] **Step 4: Run → PASS.**  **Step 5: Commit** `feat(easyscan): derive_labels CVE/CWE/severity mapping`

---

### Task 3: `load_run()` — schema-tolerant results reader

**Files:** Modify `easyscan/report.py`; Test `easyscan/tests/test_report.py` + fixture `easyscan/tests/fixtures/`

**Interfaces:**
- Produces: `load_run(results_dir: str) -> dict` with keys:
  `{target, status, confirmed(bool), finding_type, finding_evidence,
    poc_bytes(bytes), reproduction_command, exit_code, severity,
    analysis_text, config_text}`. Reads new schema, falls back to old.

- [ ] **Step 1: Write the failing test** (two fixtures — old + new schema)

```python
import base64, json
def _mk_results(tmp_path, schema):
    d = tmp_path / "run"; (d / "reports" / "bug_00").mkdir(parents=True)
    fk = "finding" if schema == "new" else "crash"
    tk = "finding_type" if schema == "new" else "crash_type"
    ek = "finding_evidence" if schema == "new" else "crash_output"
    ok = "finding_confirmed" if schema == "new" else "crash_found"
    (d / "result.json").write_text(json.dumps({
        "target": "pyyaml", "status": ok,
        fk: {"poc_path": "/tmp/p", "poc_bytes": base64.b64encode(b"AAAA").decode(),
             "reproduction_command": "/work/entry /tmp/p", tk: "compile",
             ek: "SUMMARY: SecurityOracle: compile x:1", "exit_code": 134}}))
    (d / "reports" / "bug_00" / "report.json").write_text(json.dumps({
        "verdict": {"severity_rating": "CRITICAL"}, "report": "<primitive>RCE.</primitive>"}))
    return str(d)

def test_load_run_new_schema(tmp_path):
    r = report.load_run(_mk_results(tmp_path, "new"))
    assert r["confirmed"] and r["finding_type"] == "compile"
    assert r["poc_bytes"] == b"AAAA" and r["severity"] == "CRITICAL"

def test_load_run_old_schema(tmp_path):
    r = report.load_run(_mk_results(tmp_path, "old"))
    assert r["confirmed"] and r["finding_type"] == "compile"
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement**

```python
import base64, glob, json
_CONFIRMED = {"finding_confirmed", "crash_found"}
def load_run(results_dir):
    rj = json.load(open(os.path.join(results_dir, "result.json")))
    finding = rj.get("finding") or rj.get("crash") or {}
    ft = finding.get("finding_type") or finding.get("crash_type") or "unknown"
    ev = finding.get("finding_evidence") or finding.get("crash_output") or ""
    poc = base64.b64decode(finding.get("poc_bytes", "")) if finding else b""
    sev, analysis = "UNKNOWN", ""
    reps = glob.glob(os.path.join(results_dir, "reports", "bug_*", "report.json"))
    if reps:
        rep = json.load(open(sorted(reps)[0]))
        sev = (rep.get("verdict") or {}).get("severity_rating") or "UNKNOWN"
        analysis = rep.get("report") or ""
    cfg = ""
    for name in (rj.get("target", ""),):
        for cand in glob.glob(os.path.join(os.getcwd(), "targets", name, "config.yaml")):
            cfg = open(cand).read()
    return {"target": rj.get("target", "?"), "status": rj.get("status", "?"),
            "confirmed": rj.get("status") in _CONFIRMED,
            "finding_type": ft, "finding_evidence": ev, "poc_bytes": poc,
            "reproduction_command": finding.get("reproduction_command", ""),
            "exit_code": finding.get("exit_code", -1), "severity": sev,
            "analysis_text": analysis, "config_text": cfg}
```

- [ ] **Step 4: Run → PASS.**  **Step 5: Commit** `feat(easyscan): schema-tolerant load_run`

---

### Task 4: `write_prose()` — report-writer agent + template fallback

**Files:** Modify `easyscan/report.py`; Test `easyscan/tests/test_report.py`

**Interfaces:**
- Produces: `write_prose(run: dict, labels: dict, model: str|None) -> dict`
  returns `{"exec_summary": str, "walkthrough": [str], "impact_plain": str,
  "recommendations": [str]}`. Tries `claude -p`; on ANY failure uses template.
- `_prose_template(run, labels) -> dict` (the fallback, always deterministic).

- [ ] **Step 1: Failing test (fallback path — no claude needed)**

```python
def test_prose_template_fallback_shape():
    run = {"target": "pyyaml", "finding_type": "compile",
           "reproduction_command": "/work/entry /tmp/p", "analysis_text": "x"}
    labels = {"cve": "CVE-2020-14343", "cwe": "CWE-502",
              "cwe_name": "Deserialization of Untrusted Data", "severity": "CRITICAL"}
    p = report._prose_template(run, labels)
    assert set(p) == {"exec_summary", "walkthrough", "impact_plain", "recommendations"}
    assert isinstance(p["walkthrough"], list) and p["walkthrough"]
    assert isinstance(p["recommendations"], list) and p["recommendations"]
    assert "CVE-2020-14343" in p["exec_summary"]
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement** (template + agent wrapper)

```python
import subprocess, textwrap
def _prose_template(run, labels):
    cve = labels.get("cve") or "no assigned CVE"
    return {
        "exec_summary": (f"An automated security scan of {run['target']} confirmed a "
            f"{labels['severity']} vulnerability ({cve}, {labels['cwe']} "
            f"{labels['cwe_name']}). The finding was proven by executing a "
            f"proof-of-concept against the target, not merely inferred."),
        "walkthrough": [
            f"The scanner fed a crafted input to {run['target']} through its "
            f"normal entry point (`{run['reproduction_command']}`).",
            "The input reached the vulnerable code path and triggered the "
            f"{labels['cwe_name'].lower()} condition.",
            "A detection oracle observed the dangerous behavior actually occur "
            "and recorded it as a confirmed finding (see the proof screenshots)."],
        "impact_plain": (f"An attacker who can supply input to this component can "
            f"exploit a {labels['cwe_name'].lower()} issue. Confirmed severity: "
            f"{labels['severity']}."),
        "recommendations": [
            f"Upgrade {run['target']} to a fixed release (see the CVE advisory).",
            "Treat all externally-sourced input to this component as untrusted.",
            "Add a regression test using the proof-of-concept from this report."],
    }

_PROSE_PROMPT = textwrap.dedent("""\
    You are writing the human-facing section of a security report for a
    CONFIRMED, proof-of-concept-verified vulnerability. Audience: mixed
    (executives + developers). Be accurate, plain, and concrete. Do not
    invent facts beyond the technical analysis provided.

    Target: {target}
    Labels: severity={severity}, {cve}, {cwe} ({cwe_name})
    Reproduction: {repro}
    Technical analysis (from the pipeline's report agent):
    ---
    {analysis}
    ---
    Output ONLY a JSON object, no prose around it, with EXACTLY these keys:
    {{"exec_summary": "<=4 sentences",
      "walkthrough": ["step 1", "step 2", "..."],
      "impact_plain": "1 short paragraph, no jargon",
      "recommendations": ["fix 1", "fix 2", "..."]}}
    """)

def write_prose(run, labels, model=None):
    prompt = _PROSE_PROMPT.format(
        target=run["target"], severity=labels["severity"],
        cve=labels.get("cve") or "no CVE", cwe=labels["cwe"],
        cwe_name=labels["cwe_name"], repro=run["reproduction_command"],
        analysis=(run["analysis_text"] or "")[:6000])
    try:
        env = dict(os.environ)
        tok = "/root/.vp_token"
        if os.path.exists(tok):
            env["CLAUDE_CODE_OAUTH_TOKEN"] = open(tok).read().strip()
        cmd = ["claude", "-p", prompt]
        if model:
            cmd += ["--model", model]
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=180, env=env).stdout
        start = out.index("{"); end = out.rindex("}") + 1
        data = json.loads(out[start:end])
        if {"exec_summary", "walkthrough", "impact_plain", "recommendations"} <= set(data):
            return data
    except Exception:
        pass
    return _prose_template(run, labels)
```

- [ ] **Step 4: Run → PASS** (fallback path only; agent path exercised in demo).
- [ ] **Step 5: Commit** `feat(easyscan): report-writer agent + template fallback`

---

### Task 5: `build_html()` — self-contained report assembler

**Files:** Modify `easyscan/report.py`; Test `easyscan/tests/test_report.py`

**Interfaces:**
- Consumes: `run`, `labels`, `prose`, and proof PNGs from `termshot`.
- Produces: `build_html(run, labels, prose, proofs: list[tuple[str, bytes]]) -> str`
  — full HTML string, images base64-inlined.

- [ ] **Step 1: Failing test**

```python
def test_build_html_is_self_contained():
    run = {"target": "pyyaml", "finding_type": "compile", "poc_bytes": b"AAAA",
           "reproduction_command": "/work/entry /tmp/p", "exit_code": 134,
           "analysis_text": "<primitive>RCE.</primitive>", "confirmed": True,
           "status": "finding_confirmed", "finding_evidence": "SUMMARY: x"}
    labels = {"cve": "CVE-2020-14343", "cwe": "CWE-502",
              "cwe_name": "Deserialization of Untrusted Data", "severity": "CRITICAL"}
    prose = report._prose_template(run, labels)
    html = report.build_html(run, labels, prose, [("oracle", report.termshot("t", "x"))])
    assert html.lstrip().startswith("<!doctype html>")
    assert "CVE-2020-14343" in html and "CWE-502" in html and "CRITICAL" in html
    assert "data:image/png;base64," in html   # proof embedded
    assert "http://" not in html.split("</head>")[0].replace("http://www.w3", "")  # no remote deps
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement** `build_html` — inline CSS, severity badge colored by
  level, sections: header/badge → exec summary → facts table (target, CVE, CWE,
  status, PoC size, exit code) → walkthrough (ordered list) → exploitability
  analysis (the `analysis_text`, `<`-escaped, in a styled block) → proof
  screenshots (each `<img src="data:image/png;base64,…">` with caption) →
  recommendations (list). Base64 via `base64.b64encode(png).decode()`. Escape
  all dynamic text with `html.escape`.

- [ ] **Step 4: Run → PASS.**  **Step 5: Commit** `feat(easyscan): self-contained HTML assembler`

---

### Task 6: `write_summary()` + CLI entrypoint

**Files:** Modify `easyscan/report.py`; Test `easyscan/tests/test_report.py`

**Interfaces:**
- Produces: `write_summary(results_dir, run, labels) -> dict` writes
  `results_dir/summary.json` and returns the dict; and `main(argv)` /
  `if __name__` CLI: `report.py <results_dir> [--model M]` → writes
  `report.html` + `summary.json`, prints report path, returns 2 if confirmed
  else 0.

- [ ] **Step 1: Failing test**

```python
def test_write_summary_schema(tmp_path):
    run = {"target": "pyyaml", "status": "finding_confirmed", "confirmed": True,
           "finding_type": "compile"}
    labels = {"cve": "CVE-2020-14343", "cwe": "CWE-502",
              "cwe_name": "x", "severity": "CRITICAL"}
    s = report.write_summary(str(tmp_path), run, labels)
    on_disk = json.load(open(tmp_path / "summary.json"))
    assert on_disk == s
    assert s["confirmed"] is True and s["cve"] == "CVE-2020-14343"
    assert set(s) >= {"target","status","confirmed","severity","cve","cwe","finding_type"}
```

- [ ] **Step 2: Run → FAIL.**  **Step 3: Implement** `write_summary` (json.dump) +
  `main(argv)` that wires `load_run → derive_labels → write_prose → termshot ×3
  → build_html → write files`; the three termshots are: oracle evidence
  (`finding_evidence` + `exit=<code>`), PoC hexdump
  (`_hexdump(poc_bytes)`), reproduction (`reproduction_command`). Add small
  `_hexdump(b: bytes) -> str`. Return `2 if run["confirmed"] else 0`.

- [ ] **Step 4: Run → PASS.**  **Step 5: Commit** `feat(easyscan): summary.json + CLI entrypoint`

---

### Task 7: DEMO — render the real PyYAML run, validate output

**Files:** none new (verification task).

- [ ] **Step 1:** `cd /root/defending-code-reference-harness && python3 /path/easyscan/report.py results/pyyaml/20260721T123318Z --model claude-opus-4-8`
- [ ] **Step 2:** Assert `results/pyyaml/20260721T123318Z/report.html` and
  `summary.json` exist; `summary.json.confirmed == true`, severity `CRITICAL`.
- [ ] **Step 3:** Render one proof PNG to disk and `Read` it (visual check the
  terminal screenshot looks right). Open the HTML's `<title>`/badges via grep.
- [ ] **Step 4:** If the agent prose path failed (throttling), confirm the
  template fallback produced a coherent report. Fix any rendering issues.
- [ ] **Step 5: Commit** the sample report as
  `easyscan/sample/pyyaml_report.html` — `docs(easyscan): sample report`

---

### Task 8: `install.sh`

**Files:** Create `easyscan/install.sh`

- [ ] **Step 1:** Write `install.sh`: `set -euo pipefail`; check `docker info`
  works, `/root/.vp_token` non-empty, `docker info | grep -q runsc` (else point
  to `scripts/setup_sandbox.sh`); `apt-get install -y fonts-dejavu-core` if the
  DejaVu mono TTF is absent; `pip install --quiet pillow`; run a one-line
  `python3 -c "import report; report.termshot('ok','ok')"` smoke test; print a
  green "EasyScan ready" or a clear list of what's missing.
- [ ] **Step 2:** Run it; confirm "ready".  **Step 3: Commit** `feat(easyscan): install.sh`

---

### Task 9: `scan.sh` — trigger + exit-code contract

**Files:** Create `easyscan/scan.sh`

- [ ] **Step 1:** Write `scan.sh <target> [--model M] [--runs N] [--report-only DIR]`:
  resolve harness dir; if `--report-only DIR` set, `RESULTS=DIR`; else
  `export CLAUDE_CODE_OAUTH_TOKEN=$(cat /root/.vp_token)` and run
  `bin/vp-sandboxed run "$target" --model "$model" --runs "$runs" --stream`,
  then `RESULTS=$(ls -td results/$target/*/ | head -1)`. Then
  `python3 easyscan/report.py "$RESULTS" --model "$model"`; capture its exit
  code; print `report.html` absolute path + the `summary.json` one-line status;
  `exit` with the report's code (0/2). On any pre-run error `exit 1`.
- [ ] **Step 2:** Dry-run `scan.sh pyyaml --report-only results/pyyaml/20260721T123318Z`
  → confirm it prints the report path and exits 2.
- [ ] **Step 3: Commit** `feat(easyscan): scan.sh trigger + exit codes`

---

### Task 10: README + wire into repo docs

**Files:** Create `easyscan/README.md`; Modify top-level `README.md`

- [ ] **Step 1:** `easyscan/README.md`: what it is, `install.sh`, `scan.sh <target>`,
  the exit-code contract table, where the report + summary.json land, the
  `--report-only` demo command, and the "agent writes prose / code draws proofs"
  note. Add one row to the top-level README contents table.
- [ ] **Step 2: Commit** `docs(easyscan): README + repo index`

---

## Self-review

- **Spec coverage:** install.sh (T8), scan.sh+exit codes (T9), report.py
  termshot/labels/load/prose/html/summary (T1-6), demo on PyYAML (T7),
  summary.json (T6), README+sample (T7,T10), both-schema read (T3),
  agent+fallback (T4). All spec sections covered.
- **Placeholders:** none — code shown for every code step; T5/T6/T8/T9 prose
  steps describe exact fields/commands.
- **Type consistency:** `run` dict keys defined in T3 (`load_run`) are the same
  ones consumed in T4/T5/T6; `labels` keys from T2 used consistently;
  `termshot(title, body)` signature stable across T1/T5/T6.
