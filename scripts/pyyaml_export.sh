#!/bin/bash
R=/root/defending-code-reference-harness/results/pyyaml/20260721T123318Z
DEST="/mnt/d/Ai task/artifacts_pyyaml"
mkdir -p "$DEST"
cp "$R/found_bugs.jsonl" "$DEST/" 2>/dev/null
cp "$R/focus_areas.json" "$DEST/" 2>/dev/null
cp "$R/run_000/poc.bin" "$DEST/poc.yaml" 2>/dev/null
cp "$R/run_000/result.json" "$DEST/run_000_result.json" 2>/dev/null
cp "$R/reports/bug_00/report.json" "$DEST/report_bug_00.json" 2>/dev/null
cp /root/defending-code-reference-harness/targets/pyyaml/entry.py "$DEST/entry.py" 2>/dev/null
cp /root/defending-code-reference-harness/targets/pyyaml/config.yaml "$DEST/config.yaml" 2>/dev/null
echo "=== exported files ==="
ls -la "$DEST"
echo
echo "=== FULL report text (report.json 'report' field) ==="
python3 -c "import json;print(json.load(open('$R/reports/bug_00/report.json'))['report'])"
