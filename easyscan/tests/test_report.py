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
    assert set(p) == {"exec_summary", "description", "walkthrough", "impact",
                      "root_cause", "remediation", "references"}
    assert isinstance(p["walkthrough"], list) and p["walkthrough"]
    assert isinstance(p["remediation"], list) and p["remediation"]
    assert all(isinstance(r, dict) and r.get("title") for r in p["remediation"])
    assert isinstance(p["root_cause"], dict) and "summary" in p["root_cause"]
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
                             [("oracle", "explanation", report.termshot("t", "x"))])
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


# ── markdown → HTML (safe, escape-first) ──────────────────────────────────────

def test_md_inline_formats_and_escapes():
    out = report._md_inline("use `yaml.load`, **danger**, and <b>x</b>")
    assert "<code>yaml.load</code>" in out
    assert "<strong>danger</strong>" in out
    assert "&lt;b&gt;x&lt;/b&gt;" in out and "<b>x</b>" not in out


def test_md_inline_only_allows_safe_links():
    ok = report._md_inline("see [advisory](https://example.com/x)")
    assert '<a href="https://example.com/x"' in ok
    bad = report._md_inline("[click](javascript:alert(1))")
    assert "javascript:" not in bad and "<a " not in bad and "click" in bad


def test_md_to_html_code_block_list_and_escape():
    md = "Intro **bold**.\n\n```python\nx = 1 < 2\n```\n\n- one\n- two"
    out = report._md_to_html(md)
    assert '<pre class="md-code">' in out
    assert "x = 1 &lt; 2" in out            # escaped inside the code block
    assert "<ul>" in out and "<li>one</li>" in out
    assert "<strong>bold</strong>" in out


def test_md_to_html_escapes_raw_html():
    out = report._md_to_html("<script>evil()</script>")
    assert "<script>evil" not in out
    assert "&lt;script&gt;evil" in out


# ── _build_proofs (explanations + execution witness) ──────────────────────────

def test_build_proofs_explains_and_includes_exec_witness():
    run = {"finding_evidence": 'detail: antiword "$.doc"\nSUMMARY: x',
           "poc_bytes": b"$.doc", "exit_code": 134,
           "exec_proof": "uid=0(root) gid=0(root) groups=0(root)"}
    labels = {"cwe": "CWE-78"}
    proofs = report._build_proofs(run, labels)
    assert len(proofs) == 3                       # oracle, poc, execution witness
    caps = [c for c, _, _ in proofs]
    assert any("oracle" in c.lower() for c in caps)
    assert any("actually runs" in c.lower() for c in caps)
    assert run["injected_command"] == 'antiword "$.doc"'   # surfaced for facts table
    for cap, explain, png in proofs:
        assert explain.strip() and png[:8] == b"\x89PNG\r\n\x1a\n"


def test_build_proofs_without_exec_has_two():
    run = {"finding_evidence": "SUMMARY: x", "poc_bytes": b"AAAA", "exit_code": 134}
    labels = {"cwe": "CWE-502"}
    assert len(report._build_proofs(run, labels)) == 2


# ── generic report (no memory jargon) + detailed remediation ──────────────────

def test_report_drops_memory_buckets_for_non_memory_bug():
    run = {"target": "textract", "finding_type": "os-command-injection",
           "poc_bytes": b"$.doc", "reproduction_command": "/work/entry /tmp/p",
           "exit_code": 134, "confirmed": True, "status": "finding_confirmed",
           "finding_evidence": 'detail: antiword "$.doc"',
           "injected_command": 'antiword "$.doc"',
           "analysis_text": ("<primitive>Shell injection at utils.py:80.</primitive>"
                             "<heap_layout>Not applicable to this finding.</heap_layout>")}
    labels = report.derive_labels("", "os-command-injection", "CRITICAL")
    prose = report._prose_template(run, labels)
    html = report.build_html(run, labels, prose, [])
    assert "Heap Layout" not in html and "heap_layout" not in html
    assert "Not applicable to this finding" not in html   # the memory bucket is dropped
    assert ">Remediation<" in html and ">Root cause<" in html
    assert "shell" in html.lower()                        # CWE-78 remediation present


def test_prose_template_remediation_has_fix_code_for_known_class():
    labels = report.derive_labels("", "os-command-injection", "HIGH")
    run = {"target": "t", "finding_type": "os-command-injection",
           "reproduction_command": "", "analysis_text": ""}
    p = report._prose_template(run, labels)
    assert any((r.get("fix_code") or "").strip() for r in p["remediation"])
    assert any("shell" in (r.get("detail", "") + (r.get("fix_code") or "")).lower()
               for r in p["remediation"])


def test_merge_prose_overlays_agent_output_over_template():
    run = {"target": "t", "finding_type": "x", "reproduction_command": "", "analysis_text": ""}
    base = report._prose_template(run, report.derive_labels("", "x", "LOW"))
    data = {"exec_summary": "AGENT SUMMARY",
            "root_cause": {"summary": "rc",
                           "locations": [{"file": "a.py", "lines": "1",
                                          "snippet": "bad()", "explanation": "why"}]},
            "remediation": [{"title": "Fix", "location": "a.py:1",
                             "fix_code": "good()", "detail": "d"}]}
    merged = report._merge_prose(base, data)
    assert merged["exec_summary"] == "AGENT SUMMARY"
    assert merged["root_cause"]["locations"][0]["file"] == "a.py"
    assert merged["remediation"][0]["fix_code"] == "good()"
    assert merged["walkthrough"] == base["walkthrough"]   # untouched keys keep defaults


def test_render_reference_links_cve_and_cwe():
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2016-10320"' in \
        report._render_reference("CVE-2016-10320")
    assert 'href="https://cwe.mitre.org/data/definitions/78.html"' in \
        report._render_reference("CWE-78: OS Command Injection")


# ── CWE-502 remediation is sink-specific (dill/pickle != PyYAML) ──────────────

def test_deserializer_lib_detects_dill_yaml_and_defaults_pickle():
    assert report._deserializer_lib(
        {"finding_evidence": "os.system _dill.py:452", "analysis_text": "dill.loads(b)"}) == "dill"
    assert report._deserializer_lib(
        {"finding_type": "compile",
         "analysis_text": "yaml.load(data, Loader=yaml.FullLoader)"}) == "yaml"
    assert report._deserializer_lib({"analysis_text": ""}) == "pickle"


def test_cwe502_remediation_is_dill_specific_not_pyyaml():
    labels = report.derive_labels("", "deserialization-rce", "CRITICAL")
    assert labels["cwe"] == "CWE-502"
    run = {"target": "feast", "finding_type": "deserialization-rce", "exit_code": 134,
           "finding_evidence": "os.system _dill.py:452", "analysis_text": "dill.loads(body)",
           "reproduction_command": "/work/entry x"}
    blob = json.dumps(report._prose_template(run, labels)["remediation"]).lower()
    assert "yaml.safe_load" not in blob            # the PyYAML fix must NOT appear for dill
    assert "find_class" in blob and "dill" in blob
    assert "authoriz" in blob                       # authorize-before-deserialize step


def test_cwe502_remediation_keeps_safe_load_for_yaml():
    labels = report.derive_labels("", "compile", "CRITICAL")   # -> CWE-502
    run = {"target": "pyyaml", "finding_type": "compile", "exit_code": 134,
           "analysis_text": "yaml.load(data, Loader=yaml.FullLoader)",
           "reproduction_command": "/work/entry x"}
    assert "yaml.safe_load" in json.dumps(report._prose_template(run, labels)["remediation"])


def test_remediation_upgrade_cites_fixed_version_when_known():
    labels = report.derive_labels("", "deserialization-rce", "CRITICAL")
    labels["fixed_version"] = "0.63.0"
    run = {"target": "feast", "finding_type": "deserialization-rce", "exit_code": 134,
           "finding_evidence": "_dill.py", "analysis_text": "dill.loads(x)",
           "reproduction_command": "x"}
    assert "0.63.0" in json.dumps(report._prose_template(run, labels)["remediation"])


# ── honesty: no live-target overclaim; scope caveat present ───────────────────

def test_exec_summary_does_not_overclaim_live_target():
    labels = report.derive_labels("", "deserialization-rce", "CRITICAL")
    run = {"target": "feast", "finding_type": "deserialization-rce", "exit_code": 134,
           "reproduction_command": "/work/entry x", "analysis_text": "", "finding_evidence": "_dill.py"}
    es = report._prose_template(run, labels)["exec_summary"].lower()
    assert "against the live target" not in es and "exit 134" in es


def test_poc_caveat_marks_isolated_harness_for_deser():
    cav = report._poc_caveat(
        {"target": "feast", "reproduction_command": "/work/entry /tmp/poc.bin", "exit_code": 134},
        {"cwe": "CWE-502"}, "dill").lower()
    assert "not" in cav and "over the network" in cav and "dill.loads" in cav


def test_html_is_honest_and_renders_caveat():
    labels = report.derive_labels("", "deserialization-rce", "CRITICAL")
    run = {"target": "feast", "finding_type": "deserialization-rce", "poc_bytes": b"",
           "exit_code": 134, "reproduction_command": "/work/entry x", "analysis_text": "",
           "confirmed": True, "status": "finding_confirmed", "finding_evidence": "_dill.py"}
    html = report.build_html(run, labels, report._prose_template(run, labels), [])
    assert "execution-verified proof-of-concept results" not in html
    assert "Scope of this proof" in html


# ── report-time enrichment (blind find stays clean) ───────────────────────────

def test_load_enrichment_file_and_cli_overlay(tmp_path):
    (tmp_path / "enrichment.json").write_text(json.dumps(
        {"cve": "CVE-2026-56121", "fixed_version": "0.63.0", "context": "note"}))
    enr = report.load_enrichment(str(tmp_path), {"cvss": "9.8", "fixed_version": None})
    assert enr["cve"] == "CVE-2026-56121"
    assert enr["fixed_version"] == "0.63.0"         # CLI None must not clobber the file
    assert enr["cvss"] == "9.8" and enr["context"] == "note"


def test_enrichment_rows_and_context_render_in_html():
    labels = report.derive_labels("", "deserialization-rce", "CRITICAL")
    labels["fixed_version"], labels["cvss"] = "0.63.0", "9.8"
    run = {"target": "feast", "finding_type": "deserialization-rce", "poc_bytes": b"",
           "exit_code": 134, "reproduction_command": "/work/entry x", "analysis_text": "",
           "confirmed": True, "status": "finding_confirmed", "finding_evidence": "_dill.py",
           "context_note": "**Pre-auth.** deserialized before the authz check."}
    html = report.build_html(run, labels, report._prose_template(run, labels), [])
    assert "Fixed version" in html and "0.63.0" in html
    assert "CVSS" in html and "9.8" in html
    assert "Exploitability" in html and "deserialized before the authz check" in html


def test_build_prompt_handles_binary_poc_without_null_bytes():
    # A dill/pickle PoC is binary and contains NUL bytes — the prompt must not,
    # or subprocess raises "embedded null byte" and the agent path fails.
    run = {"target": "feast", "finding_type": "deserialization-rce",
           "poc_bytes": b"\x80\x04\x95\x00\x00\x00abc", "finding_evidence": "os.system _dill.py",
           "analysis_text": "dill.loads(x)", "reproduction_command": "/work/entry x",
           "exit_code": 134}
    labels = report.derive_labels("", "deserialization-rce", "CRITICAL")
    p = report._build_prompt(run, labels)
    assert "\x00" not in p                            # argv-safe
    assert "binary" in p and "800495000000616263" in p   # rendered as hex, not raw


def test_build_prompt_keeps_text_poc_readable():
    run = {"target": "pyyaml", "finding_type": "compile",
           "poc_bytes": b"!!python/object/new:type", "finding_evidence": "compile",
           "analysis_text": "yaml.load", "reproduction_command": "x", "exit_code": 134}
    labels = report.derive_labels("", "compile", "CRITICAL")
    assert "!!python/object/new:type" in report._build_prompt(run, labels)


def test_degraded_banner_renders_when_fallback_used():
    labels = report.derive_labels("", "deserialization-rce", "CRITICAL")
    run = {"target": "feast", "finding_type": "deserialization-rce", "poc_bytes": b"",
           "exit_code": 134, "reproduction_command": "x", "analysis_text": "",
           "confirmed": True, "status": "finding_confirmed", "finding_evidence": "_dill.py"}
    html = report.build_html(run, labels, report._prose_template(run, labels), [],
                             degraded="fallback template was used")
    assert 'class="degraded"' in html and "fallback template was used" in html
