# How to run the PyYAML target — step by step, in plain language

This guide teaches you to run the PyYAML deserialization test yourself, from a
cold start. Every step says **what you type**, **what it does**, and **what you
should see**. No prior context needed.

> Golden rule for this project: always drive `wsl` from a **PowerShell** window
> (not Git Bash). Git Bash mangles Linux paths like `/root/...`.

---

## The big picture (read this once)

Think of it like a crash test for software:

1. We take a **famous library with a known bug** (PyYAML 5.3.1, which has a
   remote-code-execution flaw called CVE-2020-14343).
2. We wrap it in a tiny program (`entry.py`) that feeds it a file and **rings an
   alarm if the library gets tricked into running attacker code**. That alarm is
   our "crash detector" — the equivalent of the memory-crash detector (ASAN) we
   used for the C library before.
3. We let an **AI agent** poke at it: it reads the code, writes a malicious YAML
   file, and tries to set off the alarm.
4. The system then **double-checks** the agent's exploit really works, **grades**
   it, and **writes a report**.

If the alarm rings on a malicious file but stays silent on a normal file, the
system is working.

---

## Step 0 — Open the right terminal

- Open **Windows PowerShell** (search "PowerShell" in the Start menu).
- Everything below is typed there. You do **not** need to be "inside" Linux —
  each command starts with `wsl -d Ubuntu -- bash ...`, which reaches into the
  Linux environment for you.

## Step 1 — Check the engine is on

**Type:**
```
wsl -d Ubuntu -- bash /root/pyyaml_check.sh
```
**What it does:** confirms three things are ready — Docker (the sandbox engine),
your API login token, and the gVisor secure runtime.

**You should see:** `DOCKER_OK`, `TOKEN_OK`, `RUNSC_OK`.

*If `RUNSC_MISSING`:* the secure runtime needs re-registering after a reboot —
run:
```
wsl -d Ubuntu -- bash -lc "cd /root/defending-code-reference-harness && export CLAUDE_CODE_OAUTH_TOKEN=$(cat /root/.vp_token) && ./scripts/setup_sandbox.sh"
```

## Step 2 — Build the target

**Type:**
```
wsl -d Ubuntu -- bash /root/pyyaml_build.sh
```
**What it does:** packages the vulnerable PyYAML 5.3.1 and our alarm wrapper into
a Docker image the AI can attack. (Uses cache, so it's fast after the first time.)

**You should see:** `PyYAML 5.3.1` and a listing of `/work/entry`.

## Step 3 — Test the alarm yourself (free, no AI, no cost)

**This is the most important test.** It proves the detector works before spending
anything on the AI.

**Type:**
```
wsl -d Ubuntu -- bash /root/pyyaml_oracle_test.sh
```
**What it does:** runs three files through the wrapper:
- **A** — a malicious YAML exploit → the alarm **should** ring (a "crash").
- **B** — a simpler attack that this loader blocks → **no** alarm (proves we
  don't cry wolf).
- **C** — an ordinary config file → **no** alarm, parses fine.

**You should see:**
- Case A: a banner `DESERIALIZATION-SANITIZER: arbitrary code execution` and
  `exit=134`.
- Case B: `exit=0`.
- Case C: `parsed OK` and `exit=0`.

If you see that, **the system is working.** You can stop here, or continue to let
the AI find the bug on its own.

## Step 4 — Let the AI agent find the bug (this uses your API tokens)

**Type:**
```
wsl -d Ubuntu -- bash -lc "setsid bash /root/pyyaml_run.sh </dev/null >/root/pyyaml_run.log 2>&1 & disown; echo started"
```
**What it does:** launches the full pipeline in the background — the AI reads the
target, writes an exploit, then the system checks, grades, and reports it. It
runs 3 attempts, one at a time (sequential, so it won't run your machine out of
memory).

**Important:** run this **once**. Running it twice starts two jobs that collide.

## Step 5 — Watch progress

**Type (repeat whenever you want an update):**
```
wsl -d Ubuntu -- bash /root/pyyaml_status.sh
```
**What it does:** shows the running processes, the active AI container, the latest
log lines, and whether a finding has landed.

**What the log words mean:**
- `[find:0]` — the AI is hunting for the bug.
- `[grade:0] passed=True` — the system re-ran the exploit and confirmed it's real.
- `[judge:0] NEW` — it's a genuinely new finding, not a duplicate.
- `[report:0→bug_00] sev=CRITICAL` — the written report is done; severity CRITICAL.

## Step 6 — See the finding

**Type:**
```
wsl -d Ubuntu -- bash /root/pyyaml_show.sh
```
**What it does:** prints the confirmed finding, the exact malicious YAML the AI
wrote, and the report summary.

The exploit will look like this (a class whose `extend` method is secretly
`exec`, so YAML ends up running code):
```yaml
!!python/object/new:type
args:
- x
- !!python/tuple []
- extend: !!python/name:exec
listitems: "0"
```

## Step 7 — Stop early if you want

You already have a confirmed result after the first run. To stop the remaining
runs and free resources:
```
wsl -d Ubuntu -- bash /root/pyyaml_finalize.sh
```

---

## Tuning the difficulty (optional)

Open `targets/pyyaml/entry.py` and find the line:
```python
obj = yaml.load(data, Loader=yaml.FullLoader)
```
- `FullLoader` — the **real CVE-2020-14343** (hardest, most realistic). Default.
- `UnsafeLoader` — a trivial version, if you want a guaranteed-fast first success.
- `SafeLoader` — the **safe** setting; the alarm should **never** ring (this is
  how a fixed application behaves).

After any change, **rebuild** (Step 2) before running again.

## Common problems

| You see | Meaning | Fix |
|---|---|---|
| `rc=137` in the log | An AI container ran out of memory | Runs are already sequential; if it persists, set `memory_limit: 2g` in `targets/pyyaml/config.yaml`, or give WSL more RAM via `%UserProfile%\.wslconfig`. |
| `container ... is not running` + backoffs | A container died and it's retrying | Usually resource pressure; stop with `pyyaml_finalize.sh` and rerun a single run. |
| Two runs at once | You launched Step 4 twice | Run `pyyaml_cleanup.sh`, then launch once. |
| `RUNSC_MISSING` | Secure runtime not registered after reboot | Re-run `setup_sandbox.sh` (see Step 1). |

## Where everything lives

- Target files (edit these): `/root/defending-code-reference-harness/targets/pyyaml/`
- Helper scripts (the ones you run): `/root/pyyaml_*.sh`
- Results of a run: `/root/defending-code-reference-harness/results/pyyaml/<timestamp>/`
- Exported evidence on Windows: `D:\Ai task\artifacts_pyyaml\`
- The formal report: `D:\Ai task\PyYAML_Target_Security_Assessment.docx`
