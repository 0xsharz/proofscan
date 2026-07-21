# EasyScan — one-command pipeline + professional reporting

A thin wrapper on top of the `defending-code-reference` harness: install it
once, trigger a scan with one command, and get a **professional, self-contained
HTML security report** — with rendered terminal-screenshot proofs, a
plain-language step-by-step walkthrough, severity/CVE/CWE, and remediation —
plus a machine-readable `summary.json` and a CI-friendly exit code.

## The hybrid principle

> The agent writes the story; the code draws the pictures and builds the page.

- An **LLM report-writer** (`claude -p`) produces the human prose — executive
  summary, plain-language walkthrough, tailored remediation.
- **Deterministic Python** renders the terminal-screenshot PNG proofs, maps
  CVE/CWE, and assembles the self-contained HTML + `summary.json`.
- If the agent is unavailable or throttled, a deterministic template takes
  over, so **a report always renders** (add `--no-agent` to force it).

## Install (once)

```bash
easyscan/install.sh
```
Verifies docker / token / gVisor are ready, installs the report deps
(`pillow` + a mono font), and smoke-tests the engine. Idempotent.

## Trigger a scan (one command)

```bash
easyscan/scan.sh <target>                 # full AI run, then report
easyscan/scan.sh pyyaml --model claude-opus-4-8 --runs 3
easyscan/scan.sh pyyaml --report-only results/pyyaml/<ts>/   # re-report only
```

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

Executive summary → finding-at-a-glance (severity badge, CVE, CWE) →
step-by-step "how it works" → **proof screenshots** (the detection oracle
firing, the PoC hexdump, the reproduction command — real captured output
rendered as dark-terminal images) → the pipeline's technical analysis →
recommendations. A sample is committed at `easyscan/sample/pyyaml_report.html`.

## Tests

```bash
.venv/bin/python -m pytest easyscan/tests/ -q
```
The deterministic engine (`report.py`) is fully unit-tested — PNG rendering,
CVE/CWE mapping, both result.json schemas (old `crash*` and new `finding*`),
HTML self-containment + escaping, and the summary schema.

## Files

- `install.sh` — one-command setup.
- `scan.sh` — one-command trigger + exit-code contract.
- `report.py` — the deterministic report engine (screenshots, HTML, summary) +
  the report-writer agent call with template fallback.
- `tests/test_report.py` — unit tests.
- `sample/pyyaml_report.html` — a real generated report, for reference.
