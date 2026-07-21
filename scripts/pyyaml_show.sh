#!/bin/bash
R=/root/defending-code-reference-harness/results/pyyaml/20260721T123318Z
echo "############### FOUND_BUGS.JSONL (the confirmed finding) ###############"
python3 - "$R/found_bugs.jsonl" <<'PY'
import json,sys
for line in open(sys.argv[1]):
    b=json.loads(line)
    for k,v in b.items():
        s=str(v)
        if len(s)>600: s=s[:600]+" ...[truncated]"
        print(f"{k}: {s}")
    print("-"*60)
PY
echo
echo "############### THE POC FILE (the malicious YAML the agent wrote) ###############"
find "$R" -name 'poc*' -o -name '*.bin' 2>/dev/null | head
for f in $(find "$R" -type f \( -name 'poc*' -o -name '*poc*' \) 2>/dev/null); do echo "--- $f ---"; cat "$f"; echo; done
echo
echo "############### REPORT (bug_00) ###############"
find "$R" -path '*bug_00*' -name '*.json' 2>/dev/null
RPT=$(find "$R" -path '*bug_00*' -name 'report.json' 2>/dev/null | head -1)
if [ -n "$RPT" ]; then
  python3 - "$RPT" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
for k in ("title","severity","cwe","summary","primitive","root_cause","impact"):
    if k in d:
        s=str(d[k]); s=s[:800]+" ...[truncated]" if len(s)>800 else s
        print(f"== {k} ==\n{s}\n")
PY
fi
echo "############### CURRENT PIPELINE STATE ###############"
pgrep -f 'vuln-pipeline run pyyaml' >/dev/null && echo "RUNNING (still doing runs 2-3)" || echo "FINISHED"
tail -4 /root/pyyaml_run.log
