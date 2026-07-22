#!/bin/bash
# EasyScan auto-onboarder trigger.
#
# Point at Python code — a local folder, a PyPI name (pkg==ver), or a GitHub URL —
# and it DISCOVERS the vulnerable sink, scaffolds a vuln-pipeline target, builds
# it, and self-tests that it fires on an exploit input. Then it stops and prints
# the scan command. Blind by design: you never tell it the bug.
#
#   onboard.sh ./downloaded-code
#   onboard.sh some-pypi-package==1.2.3
#   onboard.sh https://github.com/org/repo
#
# Exit: 0 = target created AND self-test passed (ready to scan)
#       1 = build or self-test failed (scaffold left in place to fix)
#       3 = no dangerous sinks found
set -uo pipefail

HARNESS="${HARNESS_DIR:-/root/defending-code-reference-harness}"
VP="$HARNESS/.venv/bin/python"
HERE="$(cd "$(dirname "$0")" && pwd)"
OB="$HERE/onboard.py"

if [ $# -lt 1 ]; then
  echo "usage: onboard.sh <folder | pypi-name[==ver] | github-url> [--name N] [--no-agent] [--class C]"
  exit 1
fi

# Token for the analysis agent (onboard.py also falls back to reading /root/.vp_token).
if [ -s /root/.vp_token ]; then
  export CLAUDE_CODE_OAUTH_TOKEN="$(cat /root/.vp_token)"
fi

cd "$HARNESS" || { echo "[onboard] harness not found at $HARNESS (set HARNESS_DIR)"; exit 1; }
"$VP" "$OB" "$@"
