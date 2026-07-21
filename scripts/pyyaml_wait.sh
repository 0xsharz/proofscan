#!/bin/bash
# Block up to ~9 min, polling the run. Exit early when the pipeline process ends.
deadline=$(( $(date +%s) + 520 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if ! pgrep -f 'vuln-pipeline run pyyaml' >/dev/null 2>&1; then
    echo "### PIPELINE PROCESS ENDED ###"
    break
  fi
  sleep 20
done
echo "===== progress markers ====="
grep -aE 'Run [0-9]/3|find:[0-9]|\[grade|\[judge|\[report|reproduced|Wrote|found_bugs|POC|poc_path|crash|Assertion|Verdict|verdict|error_during|rc=137|SUCCESS|FAIL|no bug|No bug' /root/pyyaml_run.log | tail -40
echo "===== last 8 log lines ====="
tail -8 /root/pyyaml_run.log
echo "===== found_bugs across result dirs ====="
for d in /root/defending-code-reference-harness/results/pyyaml/*/; do
  f="$d/found_bugs.jsonl"
  if [ -s "$f" ]; then echo "-- $f ($(wc -l <"$f") lines) --"; fi
done
