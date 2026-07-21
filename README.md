# Non-memory-safety vulnerability targets for the defending-code-reference harness

Extends Anthropic's `defending-code-reference` autonomous vulnerability-discovery
harness (originally built for **C memory bugs** found via AddressSanitizer) to
**Python vulnerability classes that don't crash on their own** — unsafe
deserialization, sandbox-escape RCE, and (via `toolkit/`) command injection,
SSRF, path traversal, and more. Each target supplies its own purpose-built
detection oracle instead of relying on ASAN.

## Repository contents

| Path | What it is |
|---|---|
| `target/` | The **PyYAML** target — unsafe deserialization RCE (CVE-2020-14343). |
| `reportlab-target/` | The **ReportLab** target — `rl_safe_eval` sandbox-escape RCE (CVE-2023-33733). |
| `toolkit/` | Reusable oracle + one-command generator + cookbook for adding new targets. |
| `harness-patches/` | Fixes to the harness's own code (not target-specific) — see below. |
| `demo/`, `scripts/`, `docs/`, `artifacts/` | PyYAML-specific demo, run scripts, write-ups, evidence. |

## Two harness-level fixes shipped here (`harness-patches/`)

1. **Agent-image packaging** (`agent_image.py`) — the container that runs
   find/grade/report agents only kept `/work` from the target image, silently
   dropping any pip-installed dependency, a different Python version, or a
   compiled C extension. Fixed by building the agent image **FROM the target
   image** so its whole runtime survives. This is what let the ReportLab
   target grade correctly instead of hitting `ModuleNotFoundError`.
2. **Crash-output vocabulary** (`asan.py`) — see below.

## Result (21 Jul 2026)

An autonomous `claude-opus-4-8` agent independently discovered, and the pipeline
confirmed and graded, a **CRITICAL** arbitrary-code-execution finding:

- 99-byte YAML proof-of-concept, `exit 134` on the oracle, reproduced **3/3**.
- Grade **0.9**, rubric **9/10**, verdict **REACHABLE**, severity **CRITICAL**.
- Re-found by a second agent and correctly de-duplicated.
- Benign YAML → clean exit 0 (negative control passes → no false positives).

See `docs/PyYAML_Target_Security_Assessment.docx` for the full write-up.

## The key idea — a honest, tool-agnostic vulnerability oracle

Unsafe `yaml.load` runs attacker code *without crashing*, so there is no ASAN to
fire. `target/entry.py` builds the ASAN-equivalent using Python audit hooks
(PEP 578, `toolkit/harness_oracle.py`): it terminates the process
(`os._exit(134)`) the instant deserialization reaches a code-exec /
dangerous-import / outbound-socket / sensitive-file primitive.

**Naming note (fixed 2026-07-21):** the oracle used to print a banner claiming
to be `AddressSanitizer` — misleading for a bug class that has nothing to do
with memory safety. It now prints an honest `SECURITY-ORACLE` banner naming the
real primitive reached (e.g. `os.system`, `compile`) and the **real Python call
stack** at the moment it fired (not a placeholder). `harness-patches/asan.py`
adds a small, additive parser rule so the harness's own dedup/report tooling
recognizes this honest format (`SUMMARY: SecurityOracle: <sink> ...`) exactly
as well as it recognizes native ASAN output — nothing pretends to be a memory
tool, and nothing is lost in translation. See `toolkit/harness_oracle.py`'s
module docstring for the full explanation.

## Layout

```
target/     the harness target: Dockerfile + entry.py (oracle) + config.yaml + docs
scripts/    helper scripts you run from PowerShell (check/build/test/run/status/...)
artifacts/  evidence from the confirmed run (PoC, oracle record, report, grader verdict)
docs/       runbook plan, step-by-step how-to (plain language), and the formal report
```

## Quick start

Full instructions: `docs/PyYAML_HowToRun_StepByStep.md`. In short (from PowerShell):

1. Copy `target/` into the harness at `targets/pyyaml/` (or use the pre-staged copy
   in WSL at `/root/defending-code-reference-harness/targets/pyyaml/`).
2. `docker build -t vuln-pipeline-pyyaml:latest targets/pyyaml`
3. Self-test the oracle (free): malicious gadget → exit 134; benign → exit 0.
4. `bin/vp-sandboxed run pyyaml --model claude-opus-4-8 --runs 3 --stream`

## Difficulty knob

In `target/entry.py`, the `Loader=` in the `yaml.load(...)` call:
`FullLoader` = the real CVE-2020-14343 (default) · `UnsafeLoader` = trivial/reliable
· `SafeLoader` = negative control (must never fire).

## Provenance

- Target: PyYAML pinned to tag **5.3.1** (commit `20a120055ce2d702d8977c76b48033160b7b7c92`).
- Harness: Anthropic defending-code-reference (`vuln-pipeline`), run under gVisor + egress allowlist.
- Remediation for the underlying bug: use `yaml.safe_load`, or upgrade to PyYAML ≥ 5.4.

> Security note: this repository deliberately contains a working RCE exploit and a
> pinned-vulnerable dependency **for authorized security research only**. Do not
> deploy the target; run it only inside the sandboxed harness.
