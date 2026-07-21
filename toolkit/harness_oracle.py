# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
#
# Reusable "sanitizer" oracles for Python vuln-pipeline targets.
# (Canonical copy — new_target.sh copies this into each generated target.)
#
# The harness bug-oracle is only "did `entry <input>` crash?". For memory bugs
# ASAN provides that. For higher-level Python bugs there is no crash, so these
# classes MANUFACTURE a deterministic crash (os._exit(134) + an ASAN-style
# banner the pipeline already parses) the moment the target does something only
# an exploit would do.
#
# ONE oracle, MANY classes. AuditHookOracle detects, via Python audit events
# (PEP 578), the runtime primitives behind most Python vulnerabilities:
#   - unsafe deserialization / object injection -> exec / compile / import
#   - template injection (SSTI)                 -> exec / compile
#   - command injection                         -> subprocess.Popen / os.system
#   - SSRF                                       -> socket.connect / getaddrinfo
#   - path traversal / arbitrary file read      -> open of a sensitive path
# To target a new class you usually change only the *sink call* in entry.py,
# not this file. Add event names to `extra_events` if a class needs them.

import os
import sys


def abort_as_crash(sink, detail=""):
    """Print an ASAN/assertion-style banner and terminate as a 'crash' (134)."""
    sys.stderr.write(
        "=== HARNESS-ORACLE: exploit primitive reached ===\n"
        "ERROR: AddressSanitizer: unsafe-behavior on unknown address\n"
        "entry.py:1: oracle: Assertion 'exploit-primitive: %s' failed.\n"
        "    #0 0x0 in target_sink entry.py:1\n"
        "detail: %s\n"
        "SUMMARY: AddressSanitizer: unsafe-behavior entry.py:1 in target_sink\n"
        % (sink, str(detail)[:200])
    )
    sys.stderr.flush()
    sys.stdout.flush()
    os._exit(134)  # deterministic nonzero exit; also stops the dangerous action


# Runtime primitives that mean "an exploit ran".
_DEFAULT_EVENTS = {
    "exec", "compile",
    "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
    "subprocess.Popen",
    "socket.connect", "socket.gethostbyname", "socket.getaddrinfo",
    "pty.spawn", "ctypes.dlopen", "ctypes.dlsym",
}
_DEFAULT_IMPORTS = {"os", "subprocess", "socket", "pty", "ctypes", "platform", "posix", "nt"}
_DEFAULT_SENSITIVE = ("/etc", "/flag", "passwd", "shadow", "/proc/self/environ")


class AuditHookOracle:
    """Fires when deserialization/rendering/etc. reaches a dangerous primitive.

    Usage:
        with AuditHookOracle():
            result = vulnerable_call(untrusted_input)
    Only events inside the `with` block count, so the wrapper's own imports and
    the input-file read (done before the block) do not trip it.
    """

    def __init__(self, extra_events=(), extra_imports=(), sensitive_paths=None,
                 watch_imports=True, watch_open=True):
        self.events = set(_DEFAULT_EVENTS) | set(extra_events)
        self.imports = set(_DEFAULT_IMPORTS) | set(extra_imports)
        self.sensitive = tuple(sensitive_paths) if sensitive_paths is not None else _DEFAULT_SENSITIVE
        self.watch_imports = watch_imports
        self.watch_open = watch_open
        self.armed = False

    def _hook(self, event, args):
        if not self.armed:
            return
        if event in self.events:
            abort_as_crash(event, repr(args))
        if self.watch_imports and event == "import":
            name = args[0] if args else ""
            if isinstance(name, str) and name.split(".")[0] in self.imports:
                abort_as_crash("import:" + name, repr(args))
        if self.watch_open and event == "open":
            path = args[0] if args else ""
            if isinstance(path, str) and any(s in path for s in self.sensitive):
                abort_as_crash("open:" + path, repr(args))

    def arm(self):
        sys.addaudithook(self._hook)  # cannot be removed; we gate with self.armed
        self.armed = True

    def disarm(self):
        self.armed = False

    def __enter__(self):
        self.arm()
        return self

    def __exit__(self, *exc):
        self.disarm()
        return False  # never swallow exceptions


class MarkerFileOracle:
    """Alternative oracle for exploits that write/read a canary on disk.

    Fires if `marker_path` exists after the target ran (e.g. the exploit did
    `touch /work/pwned`). Useful where audit events don't apply.
    """

    def __init__(self, marker_path="/work/pwned"):
        self.marker_path = marker_path
        try:
            os.remove(marker_path)
        except OSError:
            pass

    def check(self):
        if os.path.exists(self.marker_path):
            abort_as_crash("marker-file", self.marker_path)
