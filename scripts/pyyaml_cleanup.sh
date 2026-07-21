#!/bin/bash
echo "=== killing pipeline processes ==="
pkill -f pyyaml_run.sh 2>/dev/null
pkill -f 'vuln-pipeline run pyyaml' 2>/dev/null
sleep 3
echo "=== removing agent containers ==="
docker rm -f find_pyyaml_0 find_pyyaml_1 find_pyyaml_2 2>/dev/null
docker ps --format '{{.Names}}' | grep -i pyyaml | grep -v egress | xargs -r docker rm -f 2>/dev/null
echo "=== remaining pyyaml procs (should be none) ==="
ps -eo pid,cmd | grep -E 'vuln-pipeline run pyyaml|pyyaml_run.sh' | grep -v grep || echo NONE
echo "=== memory ==="
free -h
echo "=== nproc ==="
nproc
