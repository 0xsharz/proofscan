#!/bin/bash
echo "=== stopping run + containers ==="
pkill -f 'vuln-pipeline run pyyaml' 2>/dev/null
pkill -f pyyaml_run.sh 2>/dev/null
sleep 2
docker ps --format '{{.Names}}' | grep -i pyyaml | grep -v egress | xargs -r docker rm -f 2>/dev/null
echo "=== final result dir ==="
R=/root/defending-code-reference-harness/results/pyyaml/20260721T123318Z
echo "$R"
echo "=== result.json summaries ==="
for f in "$R"/run_*/result.json; do
  [ -f "$f" ] || continue
  echo "-- $f --"
  python3 -c "import json;d=json.load(open('$f'));print({k:d.get(k) for k in ('status','run_idx','n_bugs','error') if k in d})" 2>/dev/null
done
echo "=== confirmed findings (found_bugs.jsonl) ==="
cat "$R"/found_bugs.jsonl 2>/dev/null | python3 -c "import sys,json;[print('crash_type:',json.loads(l).get('crash_type'),'| run',json.loads(l).get('run_idx')) for l in sys.stdin]" 2>/dev/null
wc -l "$R"/found_bugs.jsonl 2>/dev/null
echo "=== report verdict ==="
python3 -c "import json;d=json.load(open('$R/reports/bug_00/report.json'));print(d['verdict'])" 2>/dev/null
echo "=== files in result dir (tree, depth 2) ==="
find "$R" -maxdepth 2 -type f | sort
