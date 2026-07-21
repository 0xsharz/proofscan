#!/bin/bash
echo "=== processes ==="
ps -eo pid,etime,cmd | grep -Ei 'vp-sandboxed|vuln-pipeline|pyyaml_run|python.*pipeline' | grep -v grep
echo "=== docker containers ==="
docker ps --format '{{.Names}}\t{{.Status}}\t{{.Image}}' 2>/dev/null
echo "=== log tail ==="
tail -30 /root/pyyaml_run.log 2>/dev/null
echo "=== results dirs ==="
ls -t /root/defending-code-reference-harness/results/pyyaml/ 2>/dev/null | head -3
