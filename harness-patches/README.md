# Harness patch — agent image must build FROM the target, not COPY --from /work

## The bug

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

## Why it went unnoticed for the C targets and PyYAML

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

## The fix

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

## How this was validated (regression-safe)

Rebuilt the *real* agent image, through the actual harness `ensure()` code
path, for all three targets in use:

| Target | Base image | Result |
|---|---|---|
| **reportlab** | `python:3.11-slim` + pip reportlab==3.6.12 | Previously `crash_rejected` (ModuleNotFoundError). After the fix: `crash_found`, `passed: true`, `score: 0.9`. |
| **pyyaml** | `python:3.9-slim` + vendored source | Agent image now correctly runs on the target's own **Python 3.9.25** (previously silently running on the base's 3.13 and only working via the `/work/src` vendoring workaround). `entry` still exits 0 on benign input. |
| **drlibs** | `gcc:14` (ASAN binary, no interpreter dependency) | Unaffected — agent image builds, ELF binary runs, exit 0 on benign input, Claude CLI present. |

No regressions. `agent_image.py` here is the exact patched file; apply it over
`harness/agent_image.py` in a fresh clone of the upstream harness.

## Apply it

```
cp harness-patches/agent_image.py <harness-repo>/harness/agent_image.py
```
