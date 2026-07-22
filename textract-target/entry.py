#!/usr/bin/python2.7
# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
#
# textract target entry (Python 2.7).
#
# Contract: ./entry <input>
#   The input file's contents are a single line of text: a document FILENAME.
#   The entry creates a file by that name and asks the textract library to
#   extract text from it (textract.process(name)).
#     exit 0        -> extraction proceeded without the target running an
#                      unexpected shell command
#     os._exit(134) -> extracting the file caused the target to run a shell
#                      command that carried attacker-controlled syntax
#
# The oracle wraps subprocess so it observes any command the target is about to
# run through a shell; a normal text-extraction shell-out carries none of the
# shell metacharacters checked below, so their presence means input broke out
# of its argument. (No audit hooks: those are Python 3 only.)

import os
import re
import subprocess
import sys

WORK = "/work/scan"
_SHELL_META = re.compile(r"[$`;|&><\n]")


def abort_as_finding(sink, detail):
    sys.stderr.write(
        "=== SECURITY-ORACLE: vulnerability confirmed ===\n"
        "entry:1: oracle: Assertion 'vulnerable-primitive: %s' failed.\n"
        "    #0 0x0 in target_sink entry:1\n"
        "detail: %s\n"
        "SUMMARY: SecurityOracle: %s entry:1 in target_sink\n"
        % (sink, str(detail)[:200], sink))
    sys.stderr.flush()
    sys.stdout.flush()
    os._exit(134)


_orig_popen = subprocess.Popen


class _WatchedPopen(_orig_popen):
    def __init__(self, args, *a, **kw):
        shell = kw.get("shell", False)
        if shell:
            try:
                cmd = args if isinstance(args, basestring) else " ".join(args)
            except Exception:
                cmd = str(args)
            if _SHELL_META.search(cmd):
                abort_as_finding("os-command-injection", cmd[:200])
        _orig_popen.__init__(self, args, *a, **kw)


subprocess.Popen = _WatchedPopen


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: entry <input>\n")
        return 2

    f = open(sys.argv[1], "rb")
    name = f.read().strip()
    f.close()

    # textract needs an existing file whose basename contains no '/'.
    if not name or "/" in name or "\n" in name:
        return 0

    if not os.path.isdir(WORK):
        os.makedirs(WORK)
    os.chdir(WORK)

    try:
        g = open(name, "wb")
        g.write(b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n")
        g.close()
    except (OSError, IOError):
        return 0

    import textract
    try:
        textract.process(name)
    except Exception:
        pass  # extraction/parse errors are not, by themselves, a finding

    sys.stdout.write("benign: no unexpected shell command\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
