# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the EasyScan deterministic report engine."""
import base64
import importlib.util
import json
import os

spec = importlib.util.spec_from_file_location(
    "report", os.path.join(os.path.dirname(__file__), "..", "report.py"))
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


# ── termshot ──────────────────────────────────────────────────────────────────

def test_termshot_returns_png():
    png = report.termshot("oracle output", "line one\nline two\nexit=134")
    assert isinstance(png, bytes) and len(png) > 200
    assert png[:8] == b"\x89PNG\r\n\x1a\n"


def test_termshot_handles_empty_and_long_lines():
    png = report.termshot("t", "")
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    png2 = report.termshot("t", "x" * 500)  # wider than cols
    assert png2[:8] == b"\x89PNG\r\n\x1a\n"


def test_hexdump_shape():
    hd = report._hexdump(b"AAAA")
    assert hd.startswith("00000000  41 41 41 41")
    assert "|AAAA|" in hd
    assert report._hexdump(b"") == "(empty)"


# ── derive_labels ─────────────────────────────────────────────────────────────

def test_derive_labels_maps_class_and_extracts_cve():
    cfg = "attack_surface: |\n  ... CVE-2020-14343 ... yaml.load"
    labels = report.derive_labels(cfg, "compile", "CRITICAL")
    assert labels["cve"] == "CVE-2020-14343"
    assert labels["cwe"] == "CWE-502"
    assert "Deserialization" in labels["cwe_name"]
    assert labels["severity"] == "CRITICAL"


def test_derive_labels_command_injection_and_no_cve():
    labels = report.derive_labels("no cve here", "subprocess.Popen-injection", "HIGH")
    assert labels["cve"] is None
    assert labels["cwe"] == "CWE-78"


def test_derive_labels_ssrf_and_traversal():
    assert report.derive_labels("", "ssrf-redirect-bypass", "HIGH")["cwe"] == "CWE-918"
    assert report.derive_labels("", "path-traversal", "MEDIUM")["cwe"] == "CWE-22"


# ── load_run (schema + layout tolerant) ───────────────────────────────────────

def _mk_results(tmp_path, schema, layout="top"):
    base = tmp_path / "run"
    d = base / "run_000" if layout == "multi" else base
    (d / "reports" / "bug_00").mkdir(parents=True)
    (base / "reports" / "bug_00").mkdir(parents=True, exist_ok=True)
    fk = "finding" if schema == "new" else "crash"
    tk = "finding_type" if schema == "new" else "crash_type"
    ek = "finding_evidence" if schema == "new" else "crash_output"
    ok = "finding_confirmed" if schema == "new" else "crash_found"
    (d / "result.json").write_text(json.dumps({
        "target": "pyyaml", "status": ok,
        fk: {"poc_path": "/tmp/p",
             "poc_bytes": base64.b64encode(b"AAAA").decode(),
             "reproduction_command": "/work/entry /tmp/p", tk: "compile",
             ek: "SUMMARY: SecurityOracle: compile x:1", "exit_code": 134}}))
    (base / "reports" / "bug_00" / "report.json").write_text(json.dumps({
        "verdict": {"severity_rating": "CRITICAL"},
        "report": "<primitive>RCE via deserialization.</primitive>"}))
    return str(base)


def test_load_run_new_schema(tmp_path):
    r = report.load_run(_mk_results(tmp_path, "new"))
    assert r["confirmed"] and r["finding_type"] == "compile"
    assert r["poc_bytes"] == b"AAAA" and r["severity"] == "CRITICAL"
    assert "RCE" in r["analysis_text"]


def test_load_run_old_schema(tmp_path):
    r = report.load_run(_mk_results(tmp_path, "old"))
    assert r["confirmed"] and r["finding_type"] == "compile"
    assert r["poc_bytes"] == b"AAAA"


def test_load_run_multirun_layout(tmp_path):
    r = report.load_run(_mk_results(tmp_path, "old", layout="multi"))
    assert r["confirmed"] and r["finding_type"] == "compile"


# ── prose (template fallback) ─────────────────────────────────────────────────

def test_prose_template_fallback_shape():
    run = {"target": "pyyaml", "finding_type": "compile",
           "reproduction_command": "/work/entry /tmp/p", "analysis_text": "x"}
    labels = {"cve": "CVE-2020-14343", "cwe": "CWE-502",
              "cwe_name": "Deserialization of Untrusted Data", "severity": "CRITICAL"}
    p = report._prose_template(run, labels)
    assert set(p) == {"exec_summary", "walkthrough", "impact_plain", "recommendations"}
    assert isinstance(p["walkthrough"], list) and p["walkthrough"]
    assert isinstance(p["recommendations"], list) and p["recommendations"]
    assert "CVE-2020-14343" in p["exec_summary"]


# ── build_html ────────────────────────────────────────────────────────────────

def test_build_html_is_self_contained():
    run = {"target": "pyyaml", "finding_type": "compile", "poc_bytes": b"AAAA",
           "reproduction_command": "/work/entry /tmp/p", "exit_code": 134,
           "analysis_text": "<primitive>RCE.</primitive>", "confirmed": True,
           "status": "finding_confirmed", "finding_evidence": "SUMMARY: x"}
    labels = {"cve": "CVE-2020-14343", "cwe": "CWE-502",
              "cwe_name": "Deserialization of Untrusted Data", "severity": "CRITICAL"}
    prose = report._prose_template(run, labels)
    html = report.build_html(run, labels, prose,
                             [("oracle", report.termshot("t", "x"))])
    assert html.lstrip().startswith("<!doctype html>")
    assert "CVE-2020-14343" in html and "CWE-502" in html and "CRITICAL" in html
    assert "data:image/png;base64," in html
    head = html.split("</head>")[0]
    # no remote resource loads in <head> (color-scheme meta etc. are fine)
    assert "http://" not in head and "https://" not in head


def test_build_html_escapes_analysis():
    run = {"target": "t", "finding_type": "x", "poc_bytes": b"", "exit_code": 0,
           "reproduction_command": "", "analysis_text": "<primitive><script>bad</script></primitive>",
           "confirmed": True, "status": "finding_confirmed", "finding_evidence": ""}
    labels = {"cve": None, "cwe": "CWE-693", "cwe_name": "x", "severity": "LOW"}
    html = report.build_html(run, labels, report._prose_template(run, labels), [])
    assert "<script>bad" not in html
    assert "&lt;script&gt;bad" in html


# ── write_summary ─────────────────────────────────────────────────────────────

def test_write_summary_schema(tmp_path):
    run = {"target": "pyyaml", "status": "finding_confirmed", "confirmed": True,
           "finding_type": "compile", "poc_bytes": b""}
    labels = {"cve": "CVE-2020-14343", "cwe": "CWE-502",
              "cwe_name": "x", "severity": "CRITICAL"}
    s = report.write_summary(str(tmp_path), run, labels)
    on_disk = json.load(open(tmp_path / "summary.json"))
    assert on_disk == s
    assert s["confirmed"] is True and s["cve"] == "CVE-2020-14343"
    assert set(s) >= {"target", "status", "confirmed", "severity", "cve",
                      "cwe", "finding_type"}
