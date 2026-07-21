#!/bin/bash
# Scaffold a new Python vuln-pipeline target from the reusable template.
# One command produces targets/<name>/ with Dockerfile + entry.py + config.yaml
# + harness_oracle.py, ready to `docker build` and run. You edit only the sink.
#
# Example (recreates the pyyaml target):
#   ./new_target.sh pyyaml \
#     --pip "PyYAML==5.3.1" --git https://github.com/yaml/pyyaml \
#     --tag 5.3.1 --commit 20a120055ce2d702d8977c76b48033160b7b7c92 \
#     --src-subdir lib3 --import yaml \
#     --sink 'import yaml; result = yaml.load(data, Loader=yaml.FullLoader)' \
#     --attack "Untrusted YAML into yaml.load(FullLoader) on PyYAML 5.3.1 (CVE-2020-14343)." \
#     --focus "FullLoader gadget construction reaching exec/subprocess (CVE-2020-14343)"
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/templates/python-library"

NAME=""; PIP=""; GIT=""; TAG="main"; COMMIT=""; SRC_SUBDIR="."; IMPORT=""; SINK=""
ATTACK="Untrusted input processed by the library under test."
FOCUS="the vulnerable parsing/deserialization path"
TARGETS_DIR="${TARGETS_DIR:-/root/defending-code-reference-harness/targets}"

usage() { sed -n '2,20p' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --pip) PIP="$2"; shift 2;;
    --git) GIT="$2"; shift 2;;
    --tag) TAG="$2"; shift 2;;
    --commit) COMMIT="$2"; shift 2;;
    --src-subdir) SRC_SUBDIR="$2"; shift 2;;
    --import) IMPORT="$2"; shift 2;;
    --sink) SINK="$2"; shift 2;;
    --attack) ATTACK="$2"; shift 2;;
    --focus) FOCUS="$2"; shift 2;;
    --targets-dir) TARGETS_DIR="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    -*) echo "unknown option: $1" >&2; exit 2;;
    *) if [ -z "$NAME" ]; then NAME="$1"; shift; else echo "unexpected arg: $1" >&2; exit 2; fi;;
  esac
done

[ -n "$NAME" ] || { echo "error: target name required" >&2; usage; exit 2; }
[ -n "$IMPORT" ] || IMPORT="$NAME"
[ -n "$COMMIT" ] || COMMIT="$TAG"
DEST="$TARGETS_DIR/$NAME"
[ -e "$DEST" ] && { echo "error: $DEST already exists" >&2; exit 1; }

mkdir -p "$DEST"
cp "$HERE/harness_oracle.py" "$DEST/harness_oracle.py"

subst() {
  NAME="$NAME" PIP="$PIP" GIT="$GIT" TAG="$TAG" COMMIT="$COMMIT" \
  SRC_SUBDIR="$SRC_SUBDIR" IMPORT="$IMPORT" SINK="$SINK" ATTACK="$ATTACK" FOCUS="$FOCUS" \
  python3 - "$1" "$2" <<'PY'
import os, sys
src, dst = sys.argv[1], sys.argv[2]
t = open(src).read()
sink = os.environ["SINK"] or "raise NotImplementedError('TODO: fill in the vulnerable sink line')"
repl = {
    "__NAME__": os.environ["NAME"], "__PIP__": os.environ["PIP"],
    "__GIT_URL__": os.environ["GIT"], "__TAG__": os.environ["TAG"],
    "__COMMIT__": os.environ["COMMIT"], "__SRC_SUBDIR__": os.environ["SRC_SUBDIR"],
    "__IMPORT__": os.environ["IMPORT"], "__SINK__": sink,
    "__ATTACK_SURFACE__": os.environ["ATTACK"], "__FOCUS__": os.environ["FOCUS"],
}
for k, v in repl.items():
    t = t.replace(k, v)
open(dst, "w").write(t)
PY
}

subst "$TEMPLATE/Dockerfile.tmpl"  "$DEST/Dockerfile"
subst "$TEMPLATE/entry.py.tmpl"    "$DEST/entry.py"
subst "$TEMPLATE/config.yaml.tmpl" "$DEST/config.yaml"

echo "created: $DEST"
echo
echo "next steps:"
echo "  1. Review $DEST/entry.py — confirm the SINK line feeds 'data' to the library."
echo "  2. docker build -t vuln-pipeline-$NAME:latest $DEST"
echo "  3. Oracle self-test: run a known exploit input (expect exit 134) and a benign one (expect 0)."
echo "  4. bin/vp-sandboxed run $NAME --model claude-opus-4-8 --runs 3 --stream"
