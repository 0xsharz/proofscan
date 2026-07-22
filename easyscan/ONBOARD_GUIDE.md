# Onboard any Python package → scan → report (step by step)

This is the **fully automatic** path. You point at a Python codebase — a folder,
a PyPI name, or a GitHub URL — and the tool:

1. **discovers** the dangerous code itself (no hints from you),
2. **builds** a test target around it,
3. **self-tests** that the target actually detects the bug, then **stops** and
   hands you the scan command.

You run the scan when you're ready. Blind by design: you never tell it what the
bug is or where it lives.

---

## Before you start (one-time — already set up)

- The **Ubuntu (WSL)** terminal with the harness. Open it: type `wsl -d Ubuntu`
  in Windows Terminal / PowerShell, or launch the **Ubuntu** app. Type everything
  below **inside that Ubuntu terminal**.
- Your Claude token is at `/root/.vp_token` — the tool reads it automatically.
- The sandbox is already set up (redo only on an "egress" error — see
  **If something goes wrong**).

> Keep the **double quotes** around the `/mnt/d/...` paths below — there's a space
> in "Ai task", and without the quotes the command breaks.

---

## Step 1 — Onboard your package (one command)

Pick the form that matches what you have:

```bash
# A published PyPI package (name, optionally pinned to a version):
bash "/mnt/d/Ai task/pyyaml-vuln-target/easyscan/onboard.sh" somepackage==1.2.3

# A GitHub repo:
bash "/mnt/d/Ai task/pyyaml-vuln-target/easyscan/onboard.sh" https://github.com/org/repo

# A folder you've already downloaded:
bash "/mnt/d/Ai task/pyyaml-vuln-target/easyscan/onboard.sh" /root/some-downloaded-code
```

**What you'll see, in order:**

```
[1/4] discover — fetching source and grepping for sinks ...
  found 2 candidate sink(s); top:
    [deserialization] joblib.load   somepackage/utils/persistence.py:215
[2/4] analyze — picking the entry point + example inputs ...
  class: deserialization
  sink:  somepackage/utils/persistence.py:215
[3/4] scaffold — writing targets/somepackage/ ...
[4/4] build + self-test (this may take a few minutes for heavy deps) ...
  SELF-TEST: exploit input -> exit 134 (want 134)   benign -> exit 0 (want 0)
  RESULT: PASS ✅  — the target detects the vulnerability.
  Ready to scan (blind). Run:
    bash ".../scan.sh" somepackage --auto-focus
```

It takes a few minutes (longer if the package has heavy dependencies to install).
When it finishes it prints the **exact scan command** for you.

**Two outcomes:**
- **PASS ✅** → a verified target is ready. Go to Step 2.
- **FAIL ❌** → the safety gate caught a problem *before* you spent a scan.
  Don't scan yet — see **If something goes wrong**.

---

## Step 2 — Run the scan (when you're ready)

Copy the command onboard printed (or fill in the name it chose):

```bash
bash "/mnt/d/Ai task/pyyaml-vuln-target/easyscan/scan.sh" <name> --auto-focus
```

This runs the full **blind** pipeline — it re-discovers the attack surface on its
own, exploits it, runs the execution witness if it applies, and writes the
professional report. `exit=2` means it found and proved the bug. (5–15 minutes.)

---

## Step 3 — Open the report

```bash
R=$(ls -td ~/defending-code-reference-harness/results/<name>/*/ | head -1)
cp "$R/report.html" "/mnt/d/Ai task/<name>_report.html"
```

Double-click **`D:\Ai task\<name>_report.html`**. It's the same professional,
light-theme report: executive summary, attack walkthrough, proof screenshots,
**root cause with file + line + code**, and detailed remediation.

---

## What "it worked" looks like

- **Onboard:** `RESULT: PASS ✅` with a sink location (`file.py:line`).
- **Scan:** `found_bugs.jsonl` shows `finding_confirmed`; the report's Root Cause
  points at that file:line.

---

## Handy options (add to the onboard command)

| Option | What it does |
|---|---|
| `--name myname` | choose the target name (default: derived from the package) |
| `--class deserialization` | look for one class only (deserialization, command-injection, ssti, ssrf, path-traversal) |
| `--no-agent` | skip the analysis agent; use deterministic sink selection (faster, less precise) |

---

## If something goes wrong

| You see… | Meaning | What to do |
|---|---|---|
| `no known dangerous sinks found` | grep found nothing for the chosen class(es) | try `--class <class>`, or the package may have no obvious sink |
| `BUILD FAILED` | the package couldn't be installed into an image (bad/missing deps) | read the printed pip error; the scaffold is left in `targets/<name>/` — fix its `Dockerfile` and rebuild |
| `SELF-TEST: ... RESULT: FAIL ❌` | the guessed sink didn't behave as expected | the gate is protecting you. Inspect `targets/<name>/entry.py` + `onboard.json`; re-run onboard (the agent may pick better), or hand-fix the sink line, then rebuild |
| an **egress** / proxy error | the sandbox proxy isn't up (WSL restarted) | `cd ~/defending-code-reference-harness && export CLAUDE_CODE_OAUTH_TOKEN=$(cat /root/.vp_token) && ./scripts/setup_sandbox.sh` |
| `target already exists` | you onboarded this name before | add `--name othername`, or `rm -rf ~/defending-code-reference-harness/targets/<name>` first |

---

## Honest limits (so nothing surprises you)

- It targets the **single strongest** candidate per run, not every possible bug.
- A package with nasty native dependencies can fail to build — it tells you, it
  doesn't pretend.
- The sink is a best guess; the **self-test is the proof** it's right *before* you
  spend a scan.

---

## Cheat sheet

```bash
# 1) onboard: discover + build + self-test, then stop
bash "/mnt/d/Ai task/pyyaml-vuln-target/easyscan/onboard.sh" <package | folder | github-url>

# 2) if PASS, scan (blind) + report — use the name onboard printed
bash "/mnt/d/Ai task/pyyaml-vuln-target/easyscan/scan.sh" <name> --auto-focus

# 3) copy the report to Windows
cp "$(ls -td ~/defending-code-reference-harness/results/<name>/*/ | head -1)/report.html" "/mnt/d/Ai task/<name>_report.html"
```
