#!/bin/bash
# Oracle self-test: no agent, no tokens. Verifies the deserialization sanitizer.
IMG=vuln-pipeline-pyyaml:latest
T=/root/pyyaml_test

run_case () {
  local label="$1" file="$2"
  echo "=================================================================="
  echo "CASE: $label   ($file)"
  echo "------------------------------------------------------------------"
  docker run --rm -v "$file":/poc.yaml:ro "$IMG" /work/entry /poc.yaml
  echo "---> exit=$?"
  echo
}

echo "############ Loader currently active in entry.py: ############"
grep -n "Loader=yaml" /root/defending-code-reference-harness/targets/pyyaml/entry.py | head -1
echo

run_case "A. malicious FullLoader gadget (CVE-2020-14343) -> expect abort/134" "$T/evil_full.yaml"
run_case "B. os.system apply (only fires under UnsafeLoader) -> depends on loader" "$T/evil_unsafe.yaml"
run_case "C. benign data -> expect parsed OK / exit 0" "$T/ok.yaml"
