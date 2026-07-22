#!/bin/bash
# EasyScan trigger — run the full agent pipeline against a target, then generate
# the professional HTML report + summary.json. Exit code is the CI gate:
#   0 = ran clean, no confirmed finding
#   2 = confirmed finding present (see report.html)
#   1 = setup/usage error before the run
set -uo pipefail

HARNESS="${HARNESS_DIR:-/root/defending-code-reference-harness}"
VP="$HARNESS/.venv/bin/python"
HERE="$(cd "$(dirname "$0")" && pwd)"
RP="$HERE/report.py"

usage() {
  echo "usage: scan.sh <target> [--model M] [--runs N] [--auto-focus] [--report-only DIR]"
  echo "  scan.sh pyyaml                         # full AI run + witness + report"
  echo "  scan.sh textract --auto-focus          # blind run: recon discovers focus areas first"
  echo "  scan.sh pyyaml --model claude-opus-4-8 --runs 3"
  echo "  scan.sh pyyaml --report-only results/pyyaml/<ts>/   # re-report only, no AI run"
  exit 1
}

[ $# -ge 1 ] || usage
TARGET="$1"; shift
MODEL="claude-opus-4-8"; RUNS=1; REPORT_ONLY=""; AUTO_FOCUS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --model)       MODEL="$2"; shift 2;;
    --runs)        RUNS="$2"; shift 2;;
    --auto-focus)  AUTO_FOCUS="--auto-focus"; shift;;
    --report-only) REPORT_ONLY="$2"; shift 2;;
    -h|--help)     usage;;
    *) echo "unknown arg: $1"; usage;;
  esac
done

cd "$HARNESS" || { echo "[scan] harness not found at $HARNESS (set HARNESS_DIR)"; exit 1; }

if [ -n "$REPORT_ONLY" ]; then
  RESULTS="$REPORT_ONLY"
  [ -d "$RESULTS" ] || { echo "[scan] --report-only dir not found: $RESULTS"; exit 1; }
else
  if [ ! -s /root/.vp_token ]; then echo "[scan] no auth token; run install.sh"; exit 1; fi
  export CLAUDE_CODE_OAUTH_TOKEN="$(cat /root/.vp_token)"
  echo "[scan] running pipeline: target=$TARGET model=$MODEL runs=$RUNS ${AUTO_FOCUS}"
  bin/vp-sandboxed run "$TARGET" --model "$MODEL" --runs "$RUNS" --stream $AUTO_FOCUS || true
  RESULTS="$(ls -td "results/$TARGET/"*/ 2>/dev/null | head -1)"
  [ -n "$RESULTS" ] || { echo "[scan] no results dir produced by the pipeline"; exit 1; }
fi

# Execution witness (optional, per-target): if this target ships a witness.sh, run
# a harmless command through the same sink and capture the REAL output as
# exec_proof.txt, which report.py renders as "Proof 3". Kept only if it actually
# produced execution output, so a missing image never shows a broken proof.
WITNESS="$HARNESS/targets/$TARGET/witness.sh"
if [ -f "$WITNESS" ]; then
  echo "[scan] generating execution witness for $TARGET ..."
  if bash "$WITNESS" > "$RESULTS/exec_proof.txt" 2>&1 && grep -q "uid=" "$RESULTS/exec_proof.txt"; then
    echo "[scan] execution witness captured"
  else
    echo "[scan] execution witness unavailable; skipping Proof 3"
    rm -f "$RESULTS/exec_proof.txt"
  fi
fi

echo "[scan] generating report from: $RESULTS"
"$VP" "$RP" "$RESULTS" --model "$MODEL"
CODE=$?
echo "[scan] done. exit=$CODE  (0 = clean, 2 = confirmed finding)"
exit "$CODE"
