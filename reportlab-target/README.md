# ReportLab target — rl_safe_eval sandbox escape RCE (CVE-2023-33733)

Third use case for the harness (after PyYAML deserialization). ReportLab
evaluates expressions embedded in paragraph markup — e.g. a
`<font color="[ ... ]">` attribute — through `rl_safe_eval`, a home-grown
"safe" evaluator. **CVE-2023-33733**: the sandbox can be escaped (via
`type()`/`__globals__`/`__builtins__` tricks) to reach `os.system` /
`subprocess` — arbitrary code execution from a single crafted string. Fixed in
3.6.13; this target pins the vulnerable **3.6.12**.

## Result

An autonomous `claude-opus-4-8` agent independently found the real escape
gadget. Confirmed: `status: crash_found`, `passed: true`, `score: 0.9`,
`severity: CRITICAL`, `reachability: REACHABLE`. See `artifacts/`.

## Two real bugs this target surfaced and fixed (not just a demo)

1. **Harness packaging bug** (general, not ReportLab-specific) — see
   `../harness-patches/README.md`. ReportLab is pip-installed and depends on
   Pillow's compiled C extension; the harness's old agent-image build dropped
   everything outside `/work`, so the automated grader hit
   `ModuleNotFoundError` and **rejected a genuine finding** (`crash_rejected`,
   score 0.0) on the first run. Fixed at the harness level for every target.

2. **Oracle precision bug** (specific to "safe eval"-style targets) — the
   audit-hook oracle originally watched the `compile`/`exec` events. But
   `rl_safe_eval` legitimately calls `compile()`/`eval()` on **every** color
   expression it evaluates, benign or not (e.g. a plain `[0,0,0,0]` CMYK
   value) — so watching those events flagged ordinary input as an escape.
   Fixed by excluding `compile`/`exec` for this target and watching only the
   concrete dangerous primitive the escape must reach
   (`os.system`/`subprocess`/dangerous import):
   ```python
   with AuditHookOracle(exclude_events={"compile", "exec"}, watch_imports=True, watch_open=False):
   ```
   Verified: the real exploit still fires (`exploit-primitive: os.system`,
   `detail: (b'id',)`), and the benign CMYK color no longer false-positives.
   See `toolkit/harness_oracle.py`'s `exclude_events` parameter — this is now
   a reusable, documented tuning knob for any future "safe eval" style target
   (SSTI engines, expression sandboxes, etc.).

## Files

- `Dockerfile`, `entry.py`, `config.yaml`, `harness_oracle.py` — the target.
- `artifacts/poc.rml` — the exploit markup the agent wrote.
- `artifacts/result.json` — full run result (crash, grader verdict, timings).
- `artifacts/report_bug_00.json` — the full written report.

## Plain-English verdict

A single string, if rendered by an app using ReportLab 3.6.12 to lay out
attacker-influenced text (e.g. a user's display name in a generated PDF),
lets the attacker run OS commands on the server generating the PDF — no
authentication or network access needed beyond however the text reaches
ReportLab. Fix: upgrade to ReportLab ≥ 3.6.13.
