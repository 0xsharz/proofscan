#!/usr/bin/env python3
# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
#
# ReportLab RCE target entry (CVE-2023-33733).
#
# Contract: ./entry <input.rml>
#   exit 0        -> markup rendered safely (no code-exec primitive reached)
#   os._exit(134) -> the markup escaped rl_safe_eval and ran code = the vuln
#
# The vulnerable sink is rendering attacker markup with reportlab Paragraph,
# which evaluates embedded expressions (e.g. a <font color="[...]"> attribute)
# through ReportLab's rl_safe_eval sandbox. CVE-2023-33733 escapes that sandbox.

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness_oracle import AuditHookOracle


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: entry <input.rml>\n")
        return 2

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    from reportlab.platypus import Paragraph
    from reportlab.lib.styles import getSampleStyleSheet
    style = getSampleStyleSheet()["Normal"]
    text = data.decode("utf-8", "replace")

    # Oracle tuning for THIS target: rl_safe_eval legitimately calls
    # compile()/eval() (the "compile"/"exec" audit events) for every color
    # expression it evaluates, benign or not (e.g. plain "[0,0,0,0]" CMYK).
    # Watching those would flag every request as an escape. The real signal is
    # whether the evaluated expression reaches a primitive rl_safe_eval's
    # sandbox should never allow through: os.system/subprocess/exec-family, or
    # an import of os/subprocess/socket obtained via the __builtins__ pivot.
    # reportlab's own normal parsing does its own file/module I/O (fonts,
    # dependent modules) OUTSIDE this `with` block (before we arm), so
    # watch_imports=True / watch_open=False here only observes what happens
    # *during* the Paragraph render — the sandboxed evaluation itself.
    with AuditHookOracle(exclude_events={"compile", "exec"}, watch_imports=True, watch_open=False):
        try:
            para = Paragraph(text, style)  # parses markup; evaluates color expr
            para.wrap(500, 500)            # force layout
        except Exception:
            return 0  # malformed markup is not a finding

    sys.stdout.write("benign: paragraph rendered, no code-exec primitive reached\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
