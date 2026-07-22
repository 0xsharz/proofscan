# EasyScan — one-command pipeline + professional reporting

A thin wrapper on top of the `defending-code-reference` harness: **onboard any
Python package** with one command, trigger a scan, and get a **professional,
self-contained HTML security report** — rendered terminal-screenshot proofs, a
plain-language walkthrough, severity/CVE/CWE, root cause with file:line + code,
and remediation — plus a machine-readable `summary.json` and a CI-friendly exit
code.

## The hybrid principle

> One agent writes the whole story; the code draws the pictures and builds the page.

- A **single LLM report-writer** (`claude -p`) writes the entire narrative in
  **generic, class-agnostic sections** — executive summary, description, attack
  walkthrough, root cause (with real file:line + verbatim code), impact, and
  detailed line-wise remediation. It works the same for every class
  (deserialization, sandbox escape, command injection, SSRF, memory) — no
  memory-safety jargon leaks in.
- The pipeline's own `report.json` (produced in-sandbox, with source access) is
  used as **input** to that agent, never shown raw — that's how the report gets
  exact line numbers and verbatim code.
- **Deterministic Python** renders the terminal-screenshot PNG proofs, maps
  CVE/CWE/severity, and assembles the self-contained, **light-theme** HTML +
  `summary.json`.
- If the agent is unavailable or throttled, a deterministic (also generic)
  template takes over, so **a report always renders** (add `--no-agent` to force it).

## Install (once)

```bash
easyscan/install.sh
```
Verifies docker / token / gVisor are ready, installs the report deps
(`pillow` + a mono font), and smoke-tests the engine. Idempotent.

## Onboard any Python package (one command)

Point at a folder, a PyPI name, or a GitHub URL — it **discovers the vulnerable
sink itself**, scaffolds a target, builds it, and self-tests it, then stops with
the scan command. Blind by design: you never tell it the bug.

```bash
easyscan/onboard.sh ./downloaded-code
easyscan/onboard.sh some-pypi-package==1.2.3
easyscan/onboard.sh https://github.com/org/repo
```

Flow: discover (grep all classes) → analyze (an agent picks the entry point +
writes example inputs) → scaffold → build → **self-test gate** (exploit → exit
134, benign → exit 0). Validated blind on **pyod 3.5.2** — it found `joblib.load`
in `persistence.py` (CVE-2026-15529) on its own. Full step-by-step:
**`ONBOARD_GUIDE.md`**.

## Trigger a scan (one command)

```bash
easyscan/scan.sh <target>                 # full AI run -> witness -> report
easyscan/scan.sh textract --auto-focus    # blind run: recon discovers focus areas first
easyscan/scan.sh pyyaml --model claude-opus-4-8 --runs 3
easyscan/scan.sh pyyaml --report-only results/pyyaml/<ts>/   # re-report only, no AI run
```

After the run, if the target ships a `targets/<target>/witness.sh`, scan.sh runs
a **harmless command through the same sink** in the sandbox and captures the real
output as `exec_proof.txt` — rendered in the report as a live execution proof.

Outputs land next to the run:
- `results/<target>/<ts>/report.html` — the professional report (open in a browser).
- `results/<target>/<ts>/summary.json` — machine-readable.

## CI/CD gating

`scan.sh` exits with a documented contract, so a CI step is a one-liner:

| Exit code | Meaning |
|---|---|
| `0` | Ran clean — **no confirmed finding** |
| `2` | **Confirmed finding** present (see `report.html`) |
| `1` | Setup/usage error before the run |

```yaml
# GitHub Actions example
- run: easyscan/scan.sh pyyaml
  # job fails on exit 2 → a confirmed vulnerability blocks the pipeline
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: security-report, path: "**/report.html" }
```

`summary.json` schema:
```json
{"target","status","confirmed","severity","cve","cwe","finding_type","report_path"}
```

## What's in the report

A professional, **light-theme**, numbered layout — the same shape for every
vulnerability class:

1. **Executive summary**
2. **Finding overview** — severity badge, CVE, CWE, component
3. **Description**
4. **Attack walkthrough** — step by step
5. **Proof of concept** — real captured screenshots: the detection oracle firing,
   the exact PoC input (readable + hexdump), and (for command injection) a **live
   execution witness** running a harmless `id` through the injection point
6. **Root cause** — the exact file(s), line number(s), and verbatim vulnerable code
7. **Impact**
8. **Remediation** — specific, line-wise fixes with corrected, paste-ready code
9. **References** — CVE / CWE, linked

A sample is committed at `easyscan/sample/pyyaml_report.html`.

## Tests

```bash
.venv/bin/python -m pytest easyscan/tests/ -q
```
The deterministic engines (`report.py` + `onboard.py`) are unit-tested (32 tests)
— PNG rendering, CVE/CWE mapping, both result.json schemas (old `crash*` and new
`finding*`), the safe Markdown→HTML renderer, the generic prose template +
agent-output merge, the proof builder (incl. the execution witness), HTML
self-containment + escaping, the summary schema, and onboard's sink discovery,
input-type routing, and scaffolding.

## Files

- `install.sh` — one-command setup.
- `onboard.sh` / `onboard.py` — the auto-onboarder: point at any Python code, it
  discovers the sink, scaffolds a target, builds it, and self-tests it.
- `ONBOARD_GUIDE.md` — plain-language step-by-step for the onboard → scan → report flow.
- `scan.sh` — one-command trigger + exit-code contract.
- `report.py` — the report engine: proof screenshots, safe Markdown→HTML, the
  self-contained light-theme page, `summary.json`, and the single report-writer
  agent (generic sections) with a generic template fallback.
- `tests/test_report.py` + `tests/test_onboard.py` — unit tests (32).
- `sample/pyyaml_report.html` — a real generated report, for reference.

The optional per-target execution witness lives with each target as
`targets/<target>/witness.sh` (not here) — scan.sh runs it automatically.
