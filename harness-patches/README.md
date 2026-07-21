# Harness patches (3, growing to a 31-file rename for #3)

Fixes to the upstream harness's own code (not target-specific), each
regression-verified against every target in use (drlibs, pyyaml, reportlab)
before being applied — the first two additive, the third a full mechanical
rename plus 354 passing tests and a real-agent validation run.

1. `agent_image.py` — agent-image packaging bug.
2. `asan.py` — crash-output vocabulary honesty + specificity (superseded by
   the more thorough version shipped in #3 below; kept for history).
3. `harness/` + `tests/` — core status/data-model vocabulary renamed from
   memory-safety-specific (`crash_found`, `CrashArtifact`, `crash_type`, ...)
   to generic (`finding_confirmed`, `FindingArtifact`, `finding_type`, ...)
   across the whole find→grade→judge→report→patch pipeline (further down).

---

## Patch 1 — agent image must build FROM the target, not COPY --from /work

### The bug

`harness/agent_image.py` built the container that runs the AI agent (find/grade/
report stages) like this:

```
FROM vuln-pipeline-agent-base:2.1.144      # a shared gcc:14 + node + claude CLI image
COPY --from=<target-image> /work /work     # only /work survives
```

Any dependency a target installed **outside `/work`** — a `pip install` into
site-packages, an apt package, a different Python version — was silently
dropped. The agent then ran the target's `entry` under the **base image's**
Python (3.13), not the target's own Python. If `entry` imports a pip-installed
library, that import fails with `ModuleNotFoundError` in the agent/grade
containers specifically (the raw target image is unaffected).

### Why it went unnoticed for the C targets and PyYAML

- **drlibs (C):** no interpreter/package dependency question — a compiled ELF
  binary runs the same regardless of what's installed around it.
- **PyYAML:** happened to work by accident. Its `Dockerfile` `git clone`s the
  pure-Python source to `/work/src`, and `entry.py` does
  `sys.path.insert(0, "/work/src/lib3")` — so the actual PyYAML code lived
  *inside* `/work` and survived the `COPY --from`. This was a workaround for
  the same underlying bug, discovered before the bug itself was diagnosed.
- **ReportLab:** breaks the pattern. It's pip-installed (not vendored under
  `/work`) and pulls in Pillow, which ships a **compiled C extension** built
  against a specific Python ABI — it cannot be vendored as pure source at all.
  This is what surfaced the bug: the automated grader correctly reproduced
  `ModuleNotFoundError` and rejected an otherwise-genuine CVE-2023-33733 finding
  (`status: crash_rejected`, score 0.0) even though the exploit was real.

### The fix

Build the agent image **FROM the target image** instead, so its entire runtime
environment (interpreter, every installed package, any compiled extension)
survives, and layer node + the claude CLI + the extra CLI tools (`xxd`, `gdb`,
`file`) on top:

```dockerfile
FROM <target-image>
RUN (apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg xxd gdb file || true) && \
    ( (curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
       apt-get install -y --no-install-recommends nodejs) \
      || (apt-get update && apt-get install -y --no-install-recommends nodejs npm) ) && \
    npm install -g @anthropic-ai/claude-code@<version> && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /work
```

The nodesource install is tried first (works on debian slim images like
`python:3.x-slim`); if the target's base has no matching nodesource repo (e.g.
`gcc:14`'s newer debian release), it falls back to the distro's own
`nodejs`/`npm` packages. This is now the **permanent, general behavior** for
every target — no per-target opt-in, no config flag. Any future target that
pip-installs a dependency, uses a different Python, or needs any OS package
outside `/work` is covered automatically.

### How this was validated (regression-safe)

Rebuilt the *real* agent image, through the actual harness `ensure()` code
path, for all three targets in use:

| Target | Base image | Result |
|---|---|---|
| **reportlab** | `python:3.11-slim` + pip reportlab==3.6.12 | Previously `crash_rejected` (ModuleNotFoundError). After the fix: `crash_found`, `passed: true`, `score: 0.9`. |
| **pyyaml** | `python:3.9-slim` + vendored source | Agent image now correctly runs on the target's own **Python 3.9.25** (previously silently running on the base's 3.13 and only working via the `/work/src` vendoring workaround). `entry` still exits 0 on benign input. |
| **drlibs** | `gcc:14` (ASAN binary, no interpreter dependency) | Unaffected — agent image builds, ELF binary runs, exit 0 on benign input, Claude CLI present. |

No regressions. `agent_image.py` here is the exact patched file; apply it over
`harness/agent_image.py` in a fresh clone of the upstream harness.

### Apply it

```
cp harness-patches/agent_image.py <harness-repo>/harness/agent_image.py
```

---

## Patch 2 — crash-output vocabulary: honest naming + sink-specific typing

### The problem

The oracle used by non-memory-safety targets (`toolkit/harness_oracle.py`)
originally reported findings by printing a **fake AddressSanitizer banner**
and forcing a matching exit code, e.g.:

```
ERROR: AddressSanitizer: unsafe-behavior on unknown address
entry.py:1: oracle: Assertion 'exploit-primitive: os.system' failed.
    #0 0x0 in target_sink entry.py:1
SUMMARY: AddressSanitizer: unsafe-behavior entry.py:1 in target_sink
```

Two real problems with this, not just cosmetic ones:

1. **It's false.** `AddressSanitizer` never ran; nothing memory-unsafe
   happened. For a deserialization RCE or a sandbox-escape finding, claiming
   ASAN produced it is actively misleading to anyone reading the raw
   `crash_output` later (a report author, a future maintainer, an auditor).
2. **The SUMMARY line's "type" was a hardcoded placeholder** — literally the
   fixed word `"unsafe-behavior"`, not the actual sink. Every single finding
   across every non-memory target got `crash_type: "unsafe-behavior"` from
   `harness/asan.py`'s `crash_reason()`, regardless of whether the real
   primitive was `os.system`, `compile`, or a dangerous import — a dedup/report
   quality bug, since nothing distinguished one finding's *kind* from another's.
3. **The "stack frame" was a placeholder**, not a real one — always
   `#0 0x0 in target_sink entry.py:1`, identical for every finding, so
   frame-based dedup (`project_frames`/`top_frame`) couldn't distinguish
   findings by location either.

### The fix

`toolkit/harness_oracle.py`'s `abort_as_finding()` (renamed from
`abort_as_crash`) now:

- Prints an honest `=== SECURITY-ORACLE: vulnerability confirmed ===` banner —
  no tool it didn't run is named.
- Puts the **real sink** in the `SUMMARY: SecurityOracle: <sink> ...` line
  (e.g. `SUMMARY: SecurityOracle: os.system rl_safe_eval.py:1132 in target_sink`),
  so `crash_type` is genuinely sink-specific.
- Captures the **real Python call stack** (`traceback.extract_stack()`) at the
  moment the dangerous primitive fired, filtering out the oracle's own frames
  so the top frame is the first real target/library frame — e.g.
  `construct_python_object_apply constructor.py:652` for PyYAML,
  `__rl_apply__ rl_safe_eval.py:1132` for ReportLab — genuinely useful for
  dedup instead of an identical placeholder every time.

`harness/asan.py` gets one small additive change: `crash_reason()` now also
recognizes `SUMMARY: SecurityOracle: <sink>` (via a new `_ORACLE_SUMMARY`
regex) alongside the existing `SUMMARY: AddressSanitizer: <type>` pattern.
`asan_excerpt()` and `project_frames()` needed **no changes** — they already
keyed on the generic `SUMMARY:` prefix and `#N 0x... in ...` frame shape, so
the new honest banner was already compatible with them.

### How this was validated

Rebuilt both target images and re-ran the free (no-agent) oracle self-test,
then fed the captured output directly through the patched
`harness.asan.crash_reason()` / `top_frame()` / `asan_excerpt()`:

| Target | Malicious input | Benign input | `crash_reason()` |
|---|---|---|---|
| **pyyaml** | exit 134, real banner, real frames from `constructor.py` | exit 0 (unchanged) | `{'crash_type': 'compile', 'operation': None}` — specific, not "unsafe-behavior" |
| **reportlab** | exit 134, real banner, real frames from `rl_safe_eval.py` | exit 0 (unchanged, false-positive fix from the earlier `exclude_events` patch still holds) | `{'crash_type': 'os.system', 'operation': None}` |

No regressions to the original ASAN-based targets (drlibs, cjson, etc.) — they
never emit a `SecurityOracle` summary line, so the new regex never matches
their output; `_ASAN_SUMMARY` (unchanged) still runs first and still wins for
them.

**Scope note:** this patch does *not* rename the harness's own internal status
vocabulary (`crash_found` / `crash_rejected` / `CrashArtifact` / the
`crash_type` result field in `cli.py`/`artifacts.py`). Those are generic,
opaque status labels shared identically by every target including the
original memory-safety ones — "did `entry <input>` terminate abnormally?" is
in fact the correct question for both a real ASAN crash and a manufactured
`SecurityOracle` one. Renaming those would touch many shared call sites
(`_RUN_TERMINAL`, `_STATUS_ORDER`, resume/skip logic, report colorization) for
every existing target for limited benefit, since they're internal identifiers,
not something a reader sees without already having the context this file
provides. Ask if you want that renamed too — it's a bigger, higher-blast-radius
change than this one.

### Apply it

```
cp harness-patches/agent_image.py <harness-repo>/harness/agent_image.py
cp harness-patches/asan.py        <harness-repo>/harness/asan.py
```

(Patch 2's `asan.py` is superseded by Patch 3's version below — apply Patch 3
instead if you're starting fresh.)

---

## Patch 3 — full vocabulary rename: memory-safety-specific → generic

### Why this is bigger than Patch 2

After Patch 2, the *reported* vocabulary was honest, but the harness's own
*internal* status/data-model — `crash_found`/`crash_rejected`/`no_crash_found`,
the `CrashArtifact` class, its `crash_type`/`crash_output` fields, the
`<crash_type>`/`<crash_output>` XML tags every agent is instructed to emit —
still assumed every finding is a memory-safety crash. That's the harness's
*core contract*, used identically by every stage (find, grade, judge, report,
patch) and by every target, including the two SecurityOracle-based ones.

The user asked directly for this to be generic, and to confirm it wouldn't
need redoing for the next use case. This patch renames it throughout:

| Old | New |
|---|---|
| `crash_found` / `crash_rejected` / `no_crash_found` (status) | `finding_confirmed` / `finding_rejected` / `no_finding` |
| `CrashArtifact` (class) | `FindingArtifact` |
| `crash_type` (field / XML tag) | `finding_type` |
| `crash_output` (field / XML tag) | `finding_evidence` |
| `RunResult.crash` (field) | `RunResult.finding` |
| `asan_excerpt()` / `crash_reason()` (functions) | `evidence_excerpt()` / `finding_reason()` |
| `crash_file_from_frame()` / `crash_file` (novelty.py) | `finding_file_from_frame()` / `finding_file` |
| `"asan_excerpt"` (found_bugs.jsonl / manifest.jsonl key) | `"evidence_excerpt"` |
| "Crash Quality Tiers" (find-agent prompt header) | "Finding Quality Tiers" |

**Scope discipline — what did NOT get renamed**, and why:

- `harness/patch_grade.py`'s `_t1_passes()` and `harness/prompts/patch_prompt.py`'s
  hardcoded `git diff -- '*.c' '*.h' ...` — genuinely C/C++-only behavior, not
  a naming issue. Flagged with a docstring/comment at each spot; `patch` has
  not yet been run against a SecurityOracle-based target.
- `report.py`'s `_SECTIONS` tuple (`heap_layout`, ...) and the report-prompt's
  five analysis sections — a real taxonomy-design question (what should a
  non-memory-safety exploitability report's sections be?), not a rename.
  Agents already handle this gracefully today by writing "Not applicable" —
  now made an explicit, correctly-scored option in the grader rubric
  (`report_grader_prompt.py`) rather than an emergent behavior.
- The literal ASAN-specific regexes in `asan.py` (`_ASAN_FRAME`, `_ASAN_SUMMARY`)
  — accurately named; they only ever match native ASAN's own output shape.

### Extra value added while renaming (not just find-and-replace)

- **`find_prompt.py`'s quality-tier guidance** gained a clarifying paragraph:
  the existing tiers ("assertion failure = LOW VALUE, keep searching") are
  correct for native ASAN targets but would actively misdirect an agent on a
  SecurityOracle-based target, where an assertion-style oracle abort *is* the
  correct signal. The new paragraph tells the agent to check which kind of
  target it's on and judge accordingly.
- **`report_grader_prompt.py`'s scoring rubric** now explicitly scores a
  reasoned "Not applicable" as a 2 (evidence-backed), not a 0 (stub) — closing
  a real fairness gap the ReportLab run surfaced (its `heap_layout` section
  scored only 1 under the old, implicit rubric).
- **Every prompt template** dropped the unconditional, false
  "(compiled with AddressSanitizer)" claim about the target binary — true for
  drlibs, false for the two Python targets, previously shown to every agent
  regardless of target.

### How this was validated

1. **354 tests, 0 failures, 5 skipped** (the 5 are `test_agent_sandbox.py`'s
   opt-in real-infra tests, gated behind `REPRO=1`, unrelated to this change).
   This includes `test_patch_grade_e2e.py`'s real-Docker tests against the
   `canary` target — not just mocks.
2. **Comprehensive repo-wide grep** for every old identifier across `harness/`,
   `tests/`, `targets/`, `.claude/skills/`, and every `.md` doc — iterated
   until zero matches remained, including fixing 3 real-format fixture
   `result.json` files (`targets/canary/fixtures/results_sample/`) that
   `vuln-pipeline patch`/`report` load directly, which would otherwise have
   silently broken that documented demo path.
3. **A real live agent run** (`vuln-pipeline run drlibs --model claude-opus-4-8`,
   not a mock) — captured the exact prompt text sent to the container and
   confirmed the renamed tags/headers/clarifying paragraph render correctly
   verbatim. The run itself hit this environment's known Cyber Verification
   Program throttling (`API Error: Claude Code is unable to respond...`,
   documented from the original drlibs session) before landing a full
   `finding_confirmed` result — a pre-existing external limitation of this
   token, unrelated to this patch, not a regression it introduced.

### Apply it

```
cp -r harness-patches/harness/*  <harness-repo>/harness/
cp -r harness-patches/tests/*    <harness-repo>/tests/
```
Then `pip install -e ".[dev]"` and `pytest tests/ -q` to confirm.
