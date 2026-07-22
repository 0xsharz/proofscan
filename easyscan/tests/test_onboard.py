# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the EasyScan auto-onboarder (deterministic parts only —
no Docker, no agent)."""
import importlib.util
import os

spec = importlib.util.spec_from_file_location(
    "onboard", os.path.join(os.path.dirname(__file__), "..", "onboard.py"))
onboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(onboard)


# ── input resolution ──────────────────────────────────────────────────────────

def test_resolve_input_kinds(tmp_path):
    assert onboard.resolve_input(str(tmp_path))["kind"] == "local"
    assert onboard.resolve_input("https://github.com/org/repo")["kind"] == "github"
    assert onboard.resolve_input("https://github.com/org/repo.git")["kind"] == "github"
    assert onboard.resolve_input("pyod==3.5.2")["kind"] == "pip"


def test_pkg_top():
    assert onboard.pkg_top("pyod==3.5.2") == "pyod"
    assert onboard.pkg_top("https://github.com/yzhao062/pyod.git") == "pyod"
    assert onboard.pkg_top("Some-Lib>=1.0") == "Some-Lib"


# ── sink discovery ────────────────────────────────────────────────────────────

def test_discover_finds_classes_and_skips_safe(tmp_path):
    (tmp_path / "m.py").write_text(
        "import pickle, os, subprocess, yaml\n"
        "def load(b):\n    return pickle.loads(b)\n"
        "def run(x):\n    os.system(x)\n"
        "def sh(x):\n    subprocess.run(x, shell=True)\n"
        "def safe(b):\n    return yaml.safe_load(b)\n")
    cands = onboard.discover_sinks(str(tmp_path))
    classes = {c["class"] for c in cands}
    labels = {c["label"] for c in cands}
    assert "deserialization" in classes and "command-injection" in classes
    assert any("pickle" in l for l in labels)
    assert any("os.system" in l for l in labels)
    assert not any("yaml" in l for l in labels)          # yaml.safe_load is NOT a sink


def test_discover_ranks_confident_first(tmp_path):
    (tmp_path / "a.py").write_text("import pickle\npickle.loads(b)\n")
    (tmp_path / "b.py").write_text("import os\nopen(os.path.join(d, x))\n")
    cands = onboard.discover_sinks(str(tmp_path))
    assert cands[0]["class"] == "deserialization"        # conf 5 beats path-traversal conf 2


def test_discover_class_filter(tmp_path):
    (tmp_path / "m.py").write_text("import pickle, os\npickle.loads(b)\nos.system(x)\n")
    cands = onboard.discover_sinks(str(tmp_path), only_class="command-injection")
    assert cands and all(c["class"] == "command-injection" for c in cands)


# ── deterministic analysis ────────────────────────────────────────────────────

def test_analyze_deterministic_shape():
    cands = [{"class": "deserialization", "confidence": 5, "file": "m.py",
              "line": 3, "label": "pickle.load(s)", "code": "pickle.loads(b)"}]
    s = onboard.analyze_deterministic(cands)
    assert s["vuln_class"] == "deserialization"
    assert "data" in s["sink"]
    assert s["exploit_gen"].strip() and s["benign_gen"].strip()
    assert s["sink_location"] == "m.py:3"


# ── scaffold pieces ───────────────────────────────────────────────────────────

def test_entry_indents_sink_and_is_valid_python():
    entry = onboard._entry("demo", "import pickle\nresult = pickle.loads(data)")
    compile(entry, "entry.py", "exec")                   # must be syntactically valid
    assert "AuditHookOracle(" in entry                   # tuned oracle (exclude exec/compile)
    assert "def _run(data):" in entry                    # sink wrapped for warm-up + real run
    assert "/work/warmup" in entry                       # warm-up outside the oracle
    assert "\n    import pickle" in entry                 # sink body indented into _run
    assert "\n    result = pickle.loads(data)" in entry


def test_config_is_blind():
    cfg = onboard._config("demo", {"kind": "pip", "spec": "pyod==3.5.2"}, "pyod")
    assert "focus_areas: []" in cfg
    assert "attack_surface:" not in cfg                  # no such YAML key (blind)
    assert "image_tag: vuln-pipeline-demo:latest" in cfg
    assert 'commit: "3.5.2"' in cfg


def test_dockerfile_pip_installs_and_copies_source():
    df = onboard._dockerfile({"kind": "pip", "spec": "pyod==3.5.2"}, "pyod",
                             onboard._install_block({"kind": "pip", "spec": "pyod==3.5.2"},
                                                    "pyod", "/tmp/x"),
                             "python:3.11-slim")
    assert "FROM python:3.11-slim" in df
    assert 'pip install --no-cache-dir "pyod==3.5.2"' in df
    assert "/work/src" in df
    assert "COPY entry.py /work/entry" in df
