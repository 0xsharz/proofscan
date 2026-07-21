#!/bin/bash
# Full pipeline run for the pyyaml target: find -> grade -> report.
cd /root/defending-code-reference-harness || exit 1
export CLAUDE_CODE_OAUTH_TOKEN="$(cat /root/.vp_token)"
echo "START $(date -u +%FT%TZ)"
bin/vp-sandboxed run pyyaml \
  --model claude-opus-4-8 \
  --runs 3 --stream \
  2>&1
echo "END $(date -u +%FT%TZ) exit=$?"
