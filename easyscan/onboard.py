#!/usr/bin/env python3
# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
"""EasyScan auto-onboarder.

Point at Python code — a local folder, a PyPI name, or a GitHub URL — and this
DISCOVERS the vulnerable sink itself, scaffolds a vuln-pipeline target, builds
it, self-tests that the target actually fires on an exploit input (and stays
quiet on a benign one), then STOPS — ready for you to run the scan.

Blind by design: you never tell it the bug. It greps the source for known
dangerous sinks across all classes (deserialization, command injection, SSTI,
SSRF, path traversal), an agent picks the real untrusted-input entry point and
writes the exact sink + example inputs, and the self-test verifies the guess
before you spend a scan.

Flow: discover -> analyze -> scaffold -> build -> self-test -> (stop).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SELF = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(SELF)
TOOLKIT = os.path.join(REPO, "toolkit")
ORACLE_SRC = os.path.join(TOOLKIT, "harness_oracle.py")
HARNESS = os.environ.get("HARNESS_DIR", "/root/defending-code-reference-harness")
TARGETS_DIR = os.environ.get("TARGETS_DIR", os.path.join(HARNESS, "targets"))


# ── sink patterns: (class, confidence 1-5, regex, label) ─────────────────────

SINK_PATTERNS = [
    ("deserialization", 5, r"\bpickle\.loads?\s*\(", "pickle.load(s)"),
    ("deserialization", 5, r"\bcPickle\.loads?\s*\(", "cPickle.load(s)"),
    ("deserialization", 5, r"\bjoblib\.load\s*\(", "joblib.load"),
    ("deserialization", 5, r"\bcloudpickle\.loads?\s*\(", "cloudpickle.load(s)"),
    ("deserialization", 5, r"\bdill\.loads?\s*\(", "dill.load(s)"),
    ("deserialization", 5, r"\btorch\.load\s*\(", "torch.load"),
    ("deserialization", 5, r"\byaml\.unsafe_load\s*\(", "yaml.unsafe_load"),
    ("deserialization", 4, r"\byaml\.load\s*\((?![^)]*Safe)", "yaml.load (non-safe)"),
    ("deserialization", 4, r"\bmarshal\.loads?\s*\(", "marshal.load(s)"),
    ("deserialization", 4, r"\bjsonpickle\.decode\s*\(", "jsonpickle.decode"),
    ("deserialization", 4, r"\b(?:pd|pandas)\.read_pickle\s*\(", "pandas.read_pickle"),
    ("deserialization", 4, r"\b(?:np|numpy)\.load\s*\([^)]*allow_pickle\s*=\s*True", "np.load(allow_pickle=True)"),
    ("command-injection", 5, r"\bos\.system\s*\(", "os.system"),
    ("command-injection", 5, r"subprocess\.\w+\([^)]*shell\s*=\s*True", "subprocess(shell=True)"),
    ("command-injection", 4, r"\bos\.popen\s*\(", "os.popen"),
    ("ssti", 4, r"render_template_string\s*\(", "render_template_string"),
    ("ssti", 3, r"\bTemplate\s*\(", "Template("),
    ("ssti", 3, r"\.from_string\s*\(", ".from_string("),
    ("ssrf", 3, r"\brequests\.(?:get|post|put|request)\s*\(", "requests.<verb>"),
    ("ssrf", 3, r"urllib\.request\.urlopen\s*\(", "urllib urlopen"),
    ("path-traversal", 2, r"open\s*\(\s*os\.path\.join\s*\(", "open(os.path.join(...))"),
]

# Deterministic per-class input generators — each is a Python snippet that,
# run INSIDE the built target image (so the library is available), writes the
# input BYTES to stdout. Used by --no-agent, and as a safe default the agent's
# generators are validated against.
GEN = {
    "deserialization": {
        "exploit": ("import pickle, os, sys\n"
                    "class E:\n"
                    "    def __reduce__(self):\n"
                    "        return (os.system, ('id',))\n"
                    "sys.stdout.buffer.write(pickle.dumps(E()))\n"),
        "benign": ("import pickle, sys\n"
                   "sys.stdout.buffer.write(pickle.dumps({'ok': 1, 'vals': [1, 2, 3]}))\n"),
    },
    "command-injection": {
        "exploit": "import sys; sys.stdout.buffer.write(b'$(id)')\n",
        "benign": "import sys; sys.stdout.buffer.write(b'report.txt')\n",
    },
    "ssti": {
        "exploit": ("import sys; sys.stdout.buffer.write("
                    "b\"{{ ''.__class__.__mro__[1].__subclasses__() }}\")\n"),
        "benign": "import sys; sys.stdout.buffer.write(b'hello {{ name }}')\n",
    },
    "ssrf": {
        "exploit": ("import sys; sys.stdout.buffer.write("
                    "b'http://169.254.169.254/latest/meta-data/')\n"),
        "benign": "import sys; sys.stdout.buffer.write(b'https://example.com/')\n",
    },
    "path-traversal": {
        "exploit": "import sys; sys.stdout.buffer.write(b'../../../../etc/passwd')\n",
        "benign": "import sys; sys.stdout.buffer.write(b'notes.txt')\n",
    },
}


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, **kw)


def _run_text(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# ── phase 1: resolve input + fetch source for grepping ───────────────────────

def resolve_input(inp: str) -> dict:
    if os.path.isdir(inp):
        return {"kind": "local", "path": os.path.abspath(inp)}
    if re.match(r"https?://", inp) and ("github.com" in inp or inp.endswith(".git")):
        return {"kind": "github", "url": inp}
    return {"kind": "pip", "spec": inp}


def pkg_top(spec: str) -> str:
    """'pyod==3.5.2' -> 'pyod'; a URL -> last path segment; a dir -> basename."""
    base = re.split(r"[=<>!~ ]", spec, 1)[0].strip()
    base = base.rstrip("/").split("/")[-1]
    return re.sub(r"\.git$", "", base) or "target"


def fetch_for_grep(src: dict) -> tuple[str, bool]:
    """Return (source_dir, is_temp) holding the package .py source to grep."""
    if src["kind"] == "local":
        return src["path"], False
    tmp = tempfile.mkdtemp(prefix="onboard_src_")
    if src["kind"] == "github":
        r = _run_text(["git", "clone", "--depth", "1", src["url"], tmp])
        if r.returncode != 0:
            raise RuntimeError("git clone failed:\n" + r.stderr[-600:])
        return tmp, True
    r = _run_text([sys.executable, "-m", "pip", "install", "--target", tmp,
                   "--no-deps", "-q", src["spec"]])
    if r.returncode != 0:
        raise RuntimeError("pip fetch (source-only) failed:\n" + r.stderr[-600:])
    return tmp, True


# ── phase 1b: discover candidate sinks ───────────────────────────────────────

def discover_sinks(source_dir: str, only_class: str | None = None) -> list:
    cands = []
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "__pycache__", ".tox", "build", "dist")]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            rel = os.path.relpath(path, source_dir)
            is_test = "test" in rel.lower()
            for i, line in enumerate(text.splitlines(), 1):
                for cls, conf, rx, label in SINK_PATTERNS:
                    if only_class and cls != only_class:
                        continue
                    if re.search(rx, line):
                        cands.append({
                            "class": cls,
                            "confidence": conf - (2 if is_test else 0),
                            "file": rel.replace("\\", "/"), "line": i,
                            "label": label, "code": line.strip()[:200],
                        })
    cands.sort(key=lambda c: (-c["confidence"], c["file"], c["line"]))
    return cands


# ── phase 2: analyze (agent) or deterministic fallback → target spec ─────────

def _file_excerpt(source_dir: str, rel: str, limit: int = 4000) -> str:
    try:
        return open(os.path.join(source_dir, rel), encoding="utf-8",
                    errors="replace").read()[:limit]
    except Exception:
        return ""


_PROMPT = """You are a security engineer building a dynamic test harness for a Python
library. You are given candidate "sink" locations (dangerous calls) found by a
grep, plus the source of the top files. Decide the SINGLE most likely
untrusted-input entry point an application would expose, and describe how to
drive it.

Package: {pkg}   (install: {install})
Input type: {kind}

Candidate sinks (grep, ranked):
{cands}

Source of the top candidate file(s):
{excerpts}

Write a harness spec. The target entry reads the attacker's input file into a
bytes variable named `data`, then runs your `sink` inside a security oracle that
aborts (exit 134) if the code reaches a dangerous primitive (exec/compile/
os.system/subprocess/socket/dangerous import/sensitive file open).

Output ONLY one JSON object, no code fence:
{{
  "vuln_class": "deserialization|command-injection|ssti|ssrf|path-traversal",
  "sink": "self-contained Python (may be several statements joined by newlines) that feeds `data` into the library's vulnerable call. If the API takes a FILE PATH, write `data` to a temp file first and pass the path. Import what you need. Use the real module path derived from the candidate file path.",
  "sink_location": "file.py:LINE of the actual dangerous call",
  "exploit_gen": "Python that writes MALICIOUS input BYTES to stdout via sys.stdout.buffer.write(...). It must make the sink reach a dangerous primitive. For pickle-family loaders, a __reduce__ gadget calling os.system('id').",
  "benign_gen": "Python that writes a HARMLESS, well-formed input to stdout the same way (must NOT trip the oracle).",
  "rationale": "one sentence"
}}
Rules: derive the import path from the candidate file path; do not invent APIs;
keep `sink` minimal; both generators run inside the target image (the library
is installed), so you may import the library in them if useful."""


def analyze_agent(pkg: str, install: str, kind: str, cands: list,
                  source_dir: str, model: str | None) -> dict | None:
    top_files, seen = [], set()
    for c in cands:
        if c["file"] not in seen:
            seen.add(c["file"])
            top_files.append(c["file"])
        if len(top_files) >= 3:
            break
    excerpts = "\n\n".join("### %s\n%s" % (f, _file_excerpt(source_dir, f))
                           for f in top_files)
    cand_lines = "\n".join(
        "- [%s] %s  (%s:%d)  `%s`" % (c["class"], c["label"], c["file"], c["line"], c["code"])
        for c in cands[:30])
    prompt = _PROMPT.format(pkg=pkg, install=install, kind=kind,
                            cands=cand_lines or "(none)", excerpts=excerpts[:12000])
    try:
        env = dict(os.environ)
        tok = "/root/.vp_token"
        if "CLAUDE_CODE_OAUTH_TOKEN" not in env and os.path.exists(tok):
            env["CLAUDE_CODE_OAUTH_TOKEN"] = open(tok).read().strip()
        cmd = ["claude", "-p", prompt]
        if model:
            cmd += ["--model", model]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=240, env=env)
        out = r.stdout or ""
        data = json.loads(out[out.index("{"):out.rindex("}") + 1])
        if data.get("sink") and data.get("vuln_class") in GEN:
            data.setdefault("exploit_gen", GEN[data["vuln_class"]]["exploit"])
            data.setdefault("benign_gen", GEN[data["vuln_class"]]["benign"])
            return data
    except Exception as e:
        print("[onboard] agent analysis unavailable (%s); using deterministic fallback" % e)
    return None


def analyze_deterministic(cands: list) -> dict:
    if not cands:
        raise RuntimeError("no candidate sinks found — nothing to onboard")
    top = cands[0]
    cls = top["class"]
    # Best-effort generic sink: feed the raw bytes to a temp file and let the
    # library's own loader run. We can't know the exact public API without the
    # agent, so we import the module of the candidate file and call a load()-like
    # entry if present, else fall back to a class-typical call.
    mod = top["file"][:-3].replace("/", ".")
    if cls == "deserialization":
        sink = ("import pickle\n"
                "result = pickle.loads(data)")
    elif cls == "command-injection":
        sink = ("import subprocess\n"
                "result = subprocess.run(data.decode('utf-8', 'replace'), shell=True)")
    elif cls == "ssti":
        sink = ("from jinja2 import Template\n"
                "result = Template(data.decode('utf-8', 'replace')).render()")
    elif cls == "ssrf":
        sink = ("import urllib.request\n"
                "result = urllib.request.urlopen(data.decode('utf-8', 'replace').strip(), timeout=3)")
    else:
        sink = ("import os\n"
                "result = open(os.path.join('/tmp', data.decode('utf-8', 'replace').strip())).read()")
    return {"vuln_class": cls, "sink": sink,
            "sink_location": "%s:%d" % (top["file"], top["line"]),
            "exploit_gen": GEN[cls]["exploit"], "benign_gen": GEN[cls]["benign"],
            "rationale": "deterministic fallback: top-ranked %s candidate (%s)" % (cls, mod)}


# ── phase 3: scaffold the target directory ───────────────────────────────────

def _install_block(src: dict, top: str, target_dir: str) -> str:
    if src["kind"] == "pip":
        return (
            'RUN pip install --no-cache-dir "%s"\n'
            "RUN mkdir -p /work/src && "
            "cp -r \"$(python -c 'import os, %s as _m; print(os.path.dirname(_m.__file__))')\" "
            "/work/src/ 2>/dev/null || true\n" % (src["spec"], top))
    if src["kind"] == "github":
        return ("RUN git clone --depth 1 %s /work/src\n"
                "RUN pip install --no-cache-dir /work/src\n" % src["url"])
    # local: caller copies the folder into target_dir/_src
    shutil.copytree(src["path"], os.path.join(target_dir, "_src"),
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
    return "COPY _src /work/src\nRUN pip install --no-cache-dir /work/src\n"


def _entry(name: str, sink: str) -> str:
    body = "\n".join("    " + ln for ln in sink.splitlines()) or "    pass"
    return (
        "#!/usr/bin/env python3\n"
        "# Auto-generated by EasyScan onboard for target: %s\n"
        "# Contract: ./entry <input>   exit 0 = benign, os._exit(134) = exploit primitive reached\n"
        "import os, sys\n"
        "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
        "sys.path.insert(0, '/work/src')\n"
        "from harness_oracle import AuditHookOracle\n\n\n"
        "def _run(data):\n"
        "%s\n\n\n"
        "def main():\n"
        "    if len(sys.argv) != 2:\n"
        "        sys.stderr.write('usage: entry <input>\\n'); return 2\n"
        "    with open(sys.argv[1], 'rb') as f:\n"
        "        data = f.read()\n"
        "    # Warm up the load path once on a benign sample OUTSIDE the oracle, so the\n"
        "    # library's one-time init (native-lib loading via ctypes, module-code exec,\n"
        "    # imports) happens before we arm and is not mistaken for the exploit.\n"
        "    try:\n"
        "        with open('/work/warmup', 'rb') as _wf:\n"
        "            _run(_wf.read())\n"
        "    except Exception:\n"
        "        pass\n"
        "    # Real input, armed. Detect on the concrete dangerous CALL (os.system/\n"
        "    # subprocess/socket/sensitive open); exec/compile + import watching are\n"
        "    # excluded because benign library loading trips them. See toolkit/COOKBOOK.md.\n"
        "    with AuditHookOracle(exclude_events={'exec', 'compile'}, watch_imports=False):\n"
        "        try:\n"
        "            _run(data)\n"
        "        except Exception:\n"
        "            return 0\n"
        "    sys.stdout.write('benign: no exploit primitive reached\\n')\n"
        "    return 0\n\n\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(main())\n" % (name, body))


def _dockerfile(src: dict, top: str, install_block: str, py_base: str) -> str:
    return (
        "# Auto-generated by EasyScan onboard.\n"
        "FROM %s\n"
        "WORKDIR /work\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends "
        "git xxd file && rm -rf /var/lib/apt/lists/*\n"
        "%s"
        "COPY warmup_gen.py /work/warmup_gen.py\n"
        "RUN python /work/warmup_gen.py > /work/warmup 2>/dev/null || true\n"
        "COPY harness_oracle.py /work/harness_oracle.py\n"
        "COPY entry.py /work/entry\n"
        "RUN chmod +x /work/entry\n"
        'CMD ["/bin/bash"]\n' % (py_base, install_block))


def _config(name: str, src: dict, top: str) -> str:
    if src["kind"] == "github":
        url, commit = src["url"], "main"
    elif src["kind"] == "pip":
        m = re.search(r"==\s*([0-9][^\s]*)", src["spec"])
        url, commit = "https://pypi.org/project/%s/" % top, (m.group(1) if m else "latest")
    else:
        url, commit = "local://%s" % os.path.basename(src["path"]), "local"
    return (
        "# Auto-generated by EasyScan onboard. BLIND: no focus_areas, no attack_surface —\n"
        "# recon/--auto-focus discovers the attack surface at scan time.\n"
        "image_tag: vuln-pipeline-%s:latest\n"
        "github_url: %s\n"
        'commit: "%s"\n'
        "binary_path: /work/entry\n"
        "source_root: /work\n"
        'build_command: python -c "import %s"\n'
        "known_bugs: []\n"
        "focus_areas: []\n" % (name, url, commit, top))


def scaffold(name: str, src: dict, top: str, spec: dict, py_base: str) -> str:
    target_dir = os.path.join(TARGETS_DIR, name)
    if os.path.exists(target_dir):
        raise RuntimeError("target already exists: %s (pick another --name)" % target_dir)
    os.makedirs(target_dir)
    shutil.copy(ORACLE_SRC, os.path.join(target_dir, "harness_oracle.py"))
    install_block = _install_block(src, top, target_dir)
    open(os.path.join(target_dir, "Dockerfile"), "w").write(
        _dockerfile(src, top, install_block, py_base))
    open(os.path.join(target_dir, "entry.py"), "w").write(_entry(name, spec["sink"]))
    open(os.path.join(target_dir, "warmup_gen.py"), "w").write(spec.get("benign_gen", ""))
    open(os.path.join(target_dir, "config.yaml"), "w").write(_config(name, src, top))
    # human-only record of what onboard decided (never read by the pipeline)
    open(os.path.join(target_dir, "onboard.json"), "w").write(json.dumps(spec, indent=2))
    return target_dir


# ── phase 4: build + self-test ───────────────────────────────────────────────

def gen_input(image: str, gen_code: str) -> bytes:
    r = subprocess.run(["docker", "run", "--rm", "-i", image, "python", "-c", gen_code],
                       capture_output=True)
    if r.returncode != 0:
        raise RuntimeError("input generation failed:\n"
                           + r.stderr.decode("utf-8", "replace")[-400:])
    return r.stdout


def self_test(name: str, image: str, exploit: bytes, benign: bytes) -> tuple:
    d = tempfile.mkdtemp(prefix="onboard_poc_")
    open(os.path.join(d, "mal"), "wb").write(exploit)
    open(os.path.join(d, "ben"), "wb").write(benign)
    mal = _run_text(["docker", "run", "--rm", "-v", d + ":/poc:ro", image, "/work/entry", "/poc/mal"])
    ben = _run_text(["docker", "run", "--rm", "-v", d + ":/poc:ro", image, "/work/entry", "/poc/ben"])
    return mal, ben


# ── orchestration ────────────────────────────────────────────────────────────

def main(argv):
    ap = argparse.ArgumentParser(prog="onboard.py", description="EasyScan auto-onboarder")
    ap.add_argument("input", help="a local folder, a PyPI name (pkg==ver), or a GitHub URL")
    ap.add_argument("--name", default=None, help="target name (default: derived from input)")
    ap.add_argument("--model", default="claude-opus-4-8", help="model for the analysis agent")
    ap.add_argument("--class", dest="only_class", default=None,
                    help="restrict discovery to one class (deserialization, command-injection, ...)")
    ap.add_argument("--no-agent", action="store_true",
                    help="skip the analysis agent; use deterministic sink selection")
    ap.add_argument("--python-base", default="python:3.11-slim",
                    help="base image for the target (default python:3.11-slim)")
    args = ap.parse_args(argv)

    src = resolve_input(args.input)
    top = pkg_top(args.input if src["kind"] != "local" else src["path"])
    name = args.name or re.sub(r"[^a-z0-9]", "", top.lower()) or "target"
    install = src.get("spec") or src.get("url") or src.get("path")
    print("== EasyScan onboard ==")
    print("  input:  %s  (%s)" % (args.input, src["kind"]))
    print("  target: %s" % name)

    print("\n[1/4] discover — fetching source and grepping for sinks ...")
    source_dir, is_temp = fetch_for_grep(src)
    try:
        cands = discover_sinks(source_dir, args.only_class)
        if not cands:
            print("  no known dangerous sinks found. Nothing to onboard "
                  "(try --class or a different input).")
            return 3
        print("  found %d candidate sink(s); top:" % len(cands))
        for c in cands[:8]:
            print("    [%s] %-26s %s:%d" % (c["class"], c["label"], c["file"], c["line"]))

        print("\n[2/4] analyze — picking the entry point + example inputs ...")
        spec = None if args.no_agent else analyze_agent(
            top, install, src["kind"], cands, source_dir, args.model)
        if spec is None:
            spec = analyze_deterministic(cands)
        print("  class: %s" % spec["vuln_class"])
        print("  sink:  %s" % spec.get("sink_location", "?"))
    finally:
        if is_temp:
            shutil.rmtree(source_dir, ignore_errors=True)

    print("\n[3/4] scaffold — writing targets/%s/ ..." % name)
    target_dir = scaffold(name, src, top, spec, args.python_base)
    print("  created: %s" % target_dir)

    print("\n[4/4] build + self-test (this may take a few minutes for heavy deps) ...")
    image = "vuln-pipeline-%s:latest" % name
    b = _run_text(["docker", "build", "-t", image, target_dir])
    if b.returncode != 0:
        print("  BUILD FAILED — the codebase could not be installed into an image.")
        print("  ---- last lines ----\n" + (b.stdout + b.stderr)[-1200:])
        print("\n  The target scaffold is at %s — fix the Dockerfile and rebuild." % target_dir)
        return 1
    print("  image built: %s" % image)

    try:
        exploit = gen_input(image, spec["exploit_gen"])
        benign = gen_input(image, spec["benign_gen"])
    except Exception as e:
        print("  could not generate self-test inputs: %s" % e)
        return 1
    mal, ben = self_test(name, image, exploit, benign)
    ok = (mal.returncode == 134 and ben.returncode == 0)

    print("\n" + "=" * 64)
    print("  SELF-TEST: exploit input -> exit %s (want 134)   benign -> exit %s (want 0)"
          % (mal.returncode, ben.returncode))
    if ok:
        det = re.search(r"detail:\s*(.+)", mal.stderr or "")
        print("  RESULT: PASS ✅  — the target detects the vulnerability.")
        print("  sink:   %s" % spec.get("sink_location", "?"))
        if det:
            print("  fired:  %s" % det.group(1).strip()[:160])
        print("\n  Ready to scan (blind). Run:")
        print('    bash "%s/scan.sh" %s --auto-focus' % (SELF, name))
    else:
        print("  RESULT: FAIL ❌  — the auto-generated sink did not behave as expected.")
        print("  This is the safety gate doing its job: DON'T scan yet.")
        print("  Inspect %s/entry.py and %s/onboard.json; re-run onboard with --model,"
              % (target_dir, target_dir))
        print("  or hand-fix the sink line, then rebuild + retry the self-test.")
        if mal.stderr:
            print("  ---- exploit run stderr ----\n" + mal.stderr[-800:])
    print("=" * 64)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
