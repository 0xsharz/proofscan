#!/bin/bash
# Manual RCE demo for the PyYAML target. Safe: everything runs inside the
# gVisor-sandboxed container and is thrown away (--rm).
IMG=vuln-pipeline-pyyaml:latest
D=/root/pyyaml_demo
MNT="-v $D/demo_load.py:/demo_load.py:ro -v $D/poc_id.yaml:/poc.yaml:ro"

echo "########################################################################"
echo "# 1) VULNERABLE app: yaml.load(FullLoader) actually EXECUTES the attack #"
echo "#    You should see real 'id' / 'whoami' / 'uname' output below.        #"
echo "########################################################################"
docker run --rm -e PYTHONUNBUFFERED=1 $MNT "$IMG" python3 /demo_load.py /poc.yaml vuln
echo

echo "########################################################################"
echo "# 2) PROOF the attacker wrote a file on the target's disk              #"
echo "########################################################################"
docker run --rm -e PYTHONUNBUFFERED=1 $MNT "$IMG" bash -c 'python3 /demo_load.py /poc.yaml vuln >/dev/null 2>&1; echo "--- cat /tmp/pwned_by_yaml.txt ---"; cat /tmp/pwned_by_yaml.txt'
echo

echo "########################################################################"
echo "# 3) FIXED app: yaml.safe_load() -> gadget ignored, NOTHING runs       #"
echo "########################################################################"
docker run --rm -e PYTHONUNBUFFERED=1 $MNT "$IMG" python3 /demo_load.py /poc.yaml safe
echo

echo "########################################################################"
echo "# 4) HOW THE PIPELINE DETECTS IT: the oracle entry aborts (exit 134)   #"
echo "#    (this version stops the attack the instant it is proven)          #"
echo "########################################################################"
docker run --rm -v $D/poc_id.yaml:/poc.yaml:ro "$IMG" /work/entry /poc.yaml
echo "exit=$?"
