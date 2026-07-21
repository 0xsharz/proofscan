#!/usr/bin/env python3
# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
#
# Deserialization "sanitizer" entry for the PyYAML unsafe-load target.
#
# Contract (same as any vuln-pipeline target):
#   ./entry <input.yaml>
#     -> exit 0            if the YAML is benign data (no finding)
#     -> SIGABRT / crash   if deserialization executed attacker-controlled code
#                          (this IS the vulnerability -- CVE-2020-14343 class)
#
# There is no ASAN for Python: unsafe yaml.load() runs attacker code WITHOUT
# crashing. This wrapper builds the ASAN-equivalent oracle using Python audit
# hooks (PEP 578, sys.addaudithook): it arms a hook immediately before the
# vulnerable load and aborts if the deserializer reaches a code-execution /
# dangerous-import / network / sensitive-file primitive. Raising in the hook
# also prevents the action from completing (containment on top of the sandbox).
#
# The abort banner is printed in glibc-assertion style so the harness's
# existing crash parser (harness/asan.py: crash_reason / asan_excerpt) classifies
# and dedups it with no pipeline changes.

import os
import sys

# Runtime primitives that mean "the deserializer executed code / reached out".
DANGEROUS_EVENTS = {
    "exec",              # exec(), FullLoader gadget via python/name:exec
    "compile",
    "os.system",
    "os.exec",           # covers os.execv/execve/... (event name is "os.exec")
    "os.posix_spawn",
    "os.spawn",
    "os.fork",
    "subprocess.Popen",
    "socket.connect",    # OOB / SSRF-style exfil
    "socket.gethostbyname",
    "socket.getaddrinfo",
    "pty.spawn",
    "ctypes.dlopen",
    "ctypes.dlsym",
}
# Modules a benign YAML data document never needs to import.
DANGEROUS_IMPORTS = {"os", "subprocess", "socket", "pty", "ctypes", "platform", "posix", "nt"}

_armed = False


def _report_and_abort(sink, detail):
    sys.stderr.write(
        "=== DESERIALIZATION-SANITIZER: arbitrary code execution during yaml.load ===\n"
        "ERROR: AddressSanitizer: unsafe-deserialization on unknown address\n"
        "entry.py:1: deserialize: Assertion 'unsafe-exec: %s' failed.\n"
        "    #0 0x0 in yaml_full_load_gadget entry.py:1\n"
        "detail: %s\n"
        "SUMMARY: AddressSanitizer: unsafe-deserialization entry.py:1 in yaml.load\n"
        % (sink, detail)
    )
    sys.stderr.flush()
    sys.stdout.flush()
    # Terminate immediately with a deterministic nonzero code. os._exit() bypasses
    # the fragile mid-compile interpreter state (a plain os.abort() there can
    # segfault and truncate the banner) and guarantees the dangerous operation
    # never completes. 134 = the conventional SIGABRT exit the pipeline reads as
    # a crash.
    os._exit(134)


def _hook(event, args):
    if not _armed:
        return
    if event in DANGEROUS_EVENTS:
        _report_and_abort(event, repr(args)[:200])
    if event == "import":
        name = args[0] if args else ""
        if isinstance(name, str) and name.split(".")[0] in DANGEROUS_IMPORTS:
            _report_and_abort("import:" + name, repr(args)[:200])
    if event == "open":
        path = args[0] if args else ""
        if isinstance(path, str) and (
            path.startswith("/etc") or path == "/flag" or "passwd" in path or "shadow" in path
        ):
            _report_and_abort("open:" + path, repr(args)[:200])


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: entry <input.yaml>\n")
        return 2

    # Read + import BEFORE arming, so the wrapper's own file open / module import
    # do not trip the hook. Only events during the load window count.
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    # Always resolve to the pinned-vulnerable 5.3.1 source shipped in the image,
    # regardless of which python the surrounding layer puts on PATH.
    sys.path.insert(0, "/work/src/lib3")
    import yaml

    sys.addaudithook(_hook)
    global _armed
    _armed = True
    try:
        # ---- VULNERABLE SINK (difficulty knob) ----
        # FullLoader on PyYAML 5.3.1 -> the real CVE-2020-14343 gadget bypass.
        # Swap to yaml.UnsafeLoader for a trivial/reliable oracle smoke test,
        # or yaml.SafeLoader for a negative control (must never abort).
        obj = yaml.load(data, Loader=yaml.FullLoader)
    except yaml.YAMLError:
        # Malformed YAML is not a security finding.
        return 0
    finally:
        _armed = False

    sys.stdout.write("parsed OK: %r\n" % (type(obj),))
    return 0


if __name__ == "__main__":
    sys.exit(main())
