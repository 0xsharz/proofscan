#!/bin/bash
# EasyScan installer — verify prerequisites + set up the report engine deps.
# Idempotent: safe to run repeatedly.
set -uo pipefail

HARNESS="${HARNESS_DIR:-/root/defending-code-reference-harness}"
VP="$HARNESS/.venv/bin"
HERE="$(cd "$(dirname "$0")" && pwd)"
miss=0

check() {  # name  test-cmd  fix-hint
  if eval "$2" >/dev/null 2>&1; then
    echo "  [ok]      $1"
  else
    echo "  [MISSING] $1  ->  $3"
    miss=$((miss + 1))
  fi
}

echo "== EasyScan install =="
echo "-- prerequisites --"
check "docker running"        "docker info"                                              "start it: sudo service docker start"
check "auth token"            "test -s /root/.vp_token"                                   "mint one: claude setup-token > /root/.vp_token"
check "gVisor runsc runtime"  "docker info --format '{{json .Runtimes}}' | grep -q runsc" "run: $HARNESS/scripts/setup_sandbox.sh (with the token in env)"
check "harness venv"          "test -x $VP/python"                                        "install the harness first (pip install -e . in $HARNESS)"

echo "-- report engine deps --"
if [ -x "$VP/pip" ]; then "$VP/pip" install --quiet pillow 2>&1 | tail -1; fi
if [ ! -f /usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf ]; then
  echo "  installing fonts-dejavu-core ..."
  apt-get install -y -qq fonts-dejavu-core >/dev/null 2>&1
fi
check "Pillow"    "$VP/python -c 'import PIL'"                                    "$VP/pip install pillow"
check "mono font" "test -f /usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"  "apt-get install fonts-dejavu-core"

echo "-- smoke test --"
if "$VP/python" - "$HERE/report.py" <<'PY' 2>/dev/null
import importlib.util, sys
s = importlib.util.spec_from_file_location("r", sys.argv[1])
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
assert m.termshot("ok", "ok")[:8] == b"\x89PNG\r\n\x1a\n"
print("  [ok]      report engine renders a PNG")
PY
then :; else echo "  [MISSING] report engine smoke test"; miss=$((miss + 1)); fi

echo
if [ "$miss" -eq 0 ]; then
  echo "EasyScan is READY.  Trigger a scan with:   $HERE/scan.sh <target>"
  echo "                     (e.g.)                 $HERE/scan.sh pyyaml"
else
  echo "$miss item(s) missing above — fix them and re-run this installer."
  exit 1
fi
