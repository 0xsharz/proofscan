#!/bin/bash
set -e
cd /root/defending-code-reference-harness
echo "=== docker build vuln-pipeline-pyyaml:latest ==="
docker build -t vuln-pipeline-pyyaml:latest targets/pyyaml
echo "=== verify PyYAML version + entry present ==="
docker run --rm vuln-pipeline-pyyaml:latest python3 -c "import yaml; print('PyYAML', yaml.__version__)"
docker run --rm vuln-pipeline-pyyaml:latest bash -c 'ls -la /work/entry; head -1 /work/entry'
