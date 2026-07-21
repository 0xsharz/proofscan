# EasyScan — one-command pipeline + professional reporting

**Status:** approved design (2026-07-22)
**Repo home:** `easyscan/` in `pyyaml-vuln-target`
**Runs in:** the WSL harness environment, on top of the unmodified
`defending-code-reference` harness.

## Goal

Make the existing vuln-discovery harness trivial to install, trigger with one
command, and produce a professional, self-contained HTML security report with
rendered terminal "screenshot" proofs, a plain-language walkthrough, and
remediation — plus machine-readable output for CI/CD.

## Non-goals (explicitly cut — YAGNI)

- **SARIF output** — dropped per decision; `summary.json` + exit codes cover
  the CI need.
- **Slack/webhook, ticketing integrations** — not in this iteration.
- **DOCX/PDF export** — HTML is the deliverable; can be added later.
- **Modifying the core harness** — EasyScan is a pure wrapper layer.

## The hybrid principle

> The agent writes the story; the code draws the pictures and builds the page.

- An **LLM report-writer agent** produces the human-facing prose (executive
  summary, plain-language step-by-step walkthrough, tailored remediation) as
  structured JSON. This is where an agent genuinely beats a fixed template,
  and matches the "explain it plainly" preference.
- **Deterministic Python** renders the terminal-screenshot PNGs, maps
  CVE/CWE, assembles the self-contained HTML, and emits `summary.json`. These
  must be code: reproducible, free, identical every run, and an agent cannot
  render a PNG.

Note: the harness's existing `report` stage is *already* an agent that writes
the technical exploitability analysis (`reports/bug_NN/report.json`). The
report-writer agent here is a distinct, lighter **presentation** pass that
consumes that technical analysis and re-voices it for a mixed audience.

## Components (each one job, testable in isolation)

### 1. `install.sh`
One-command, idempotent setup. Verifies prerequisites (docker running, token
present, gVisor `runsc` registered — re-points to `scripts/setup_sandbox.sh`
if missing), installs report deps (`pip install pillow`), locates a monospace
TTF (DejaVu Sans Mono, already present via system fonts / pip fallback), and
self-checks that `report.py` can render a test PNG. Prints a clear ready/not-ready
summary.

### 2. `scan.sh <target> [--model M] [--runs N] [--report-only DIR]`
The one-command trigger. Default: runs the real agent pipeline
(`bin/vp-sandboxed run <target> --model … --stream`), locates the newest
`results/<target>/<ts>/`, calls the report engine on it, then reads the
engine's `summary.json` to set the **process exit code**. Prints the absolute
path to `report.html` at the end. `--report-only DIR` skips the agent run and
just (re)builds the report from an existing results dir (used for the demo and
for re-rendering without spending tokens).

### 3. `report_writer` (the agent pass) — inside `report.py`
Given the technical `report.json` + `result.json`, calls one sandboxed agent
(reusing `harness.agent.run_agent` / the same auth + container infra) with a
prompt that asks for a fixed JSON schema:
`{ "exec_summary": str, "walkthrough": [str, …], "impact_plain": str,
   "recommendations": [str, …] }`.
Parsed with the harness's existing `parse_xml_tag`/JSON conventions. On agent
failure or throttling, falls back to a deterministic template built from the
technical analysis (so a report is ALWAYS produced — the agent enriches, it is
not a hard dependency).

### 4. `report.py` (the deterministic engine)
- **`termshot(title, text) -> PNG bytes`** — renders captured output as a
  dark-terminal image (Pillow + mono font). Used for: the oracle-firing banner
  + exit code, the PoC hexdump, and the reproduction-command output.
- **`derive_labels(config, finding) -> {cve, cwe, severity}`** — CVE from the
  target `config.yaml` `attack_surface`/commit context; CWE from the finding
  type via a small built-in map (deserialization→CWE-502, command-injection→
  CWE-78, SSRF→CWE-918, path-traversal→CWE-22, memory→CWE-787/125); severity
  from the harness verdict's `severity_rating`.
- **`build_html(...) -> str`** — self-contained HTML (all PNGs base64-inlined,
  CSS inline), sections in order: title + severity badge → executive summary →
  finding facts (CVE/CWE/target/PoC size) → plain-language walkthrough →
  exploitability analysis (from the technical report) → **proof screenshots**
  → remediation. Theme: clean, printable, professional.
- **`write_summary(...) -> summary.json`** — `{target, status, severity,
  cve, cwe, finding_type, confirmed: bool, report_path, timestamp}`.
- **optional per-target override:** if `targets/<name>/remediation.md` exists,
  its content is used verbatim for the remediation section instead of the
  auto-derived text.

## Data flow

```
scan.sh <target>
  → bin/vp-sandboxed run <target>            (harness: find→grade→report)
  → results/<target>/<ts>/{result.json, reports/bug_00/report.json}
  → report.py:
       report_writer agent  → narrative JSON (or template fallback)
       termshot            → proof PNGs
       derive_labels       → CVE/CWE/severity
       build_html          → results/<ts>/report.html
       write_summary       → results/<ts>/summary.json
  → scan.sh reads summary.json.confirmed → exit 0 (clean) or 2 (finding)
```

## Exit-code contract (for CI gating)

- `0` — ran to completion, **no confirmed finding**.
- `2` — ran to completion, **confirmed finding** present.
- `1` — setup/usage error before the run (bad target, no auth, build failed).

Matches the harness's own subcommand convention, so a CI step is just:
`easyscan/scan.sh <target> || echo "finding! see report.html"`.

## Testing

- `report.py` is pure/deterministic → unit tests: feed a fixtured results dir,
  assert `report.html` is produced, is valid self-contained HTML (parses,
  contains the severity/CVE/CWE, embeds ≥1 `data:image/png;base64` proof), and
  `summary.json` has the right schema + `confirmed` flag. `termshot` test:
  asserts non-empty PNG with the PNG magic header. `derive_labels` test: the
  CWE map covers all current finding classes.
- The `report_writer` agent path is exercised live during the demo; its
  template fallback is unit-tested (agent stubbed) so a report always renders
  offline.
- `install.sh` / `scan.sh` are thin orchestration → verified by running them.

## Demo (first, before wiring live scan)

Run `report.py --report-only` against the completed PyYAML run
(`results/pyyaml/20260721T123318Z/`, real CRITICAL agent report) to produce a
full `report.html` with real screenshots — no token cost — so the look and
content are validated before `scan.sh` ever triggers a paid run.

## Deliverables

`easyscan/{install.sh, scan.sh, report.py}`, a `README.md`, a `tests/` dir,
and one sample `report.html` committed as a reference artifact.
