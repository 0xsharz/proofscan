# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
#
# Reusable vulnerability-detection oracles for Python vuln-pipeline targets.
#
# The harness's only detection primitive is "did `entry <input>` terminate
# abnormally?" (nonzero exit / signal). A native memory-safety bug gives that
# for free via AddressSanitizer. Higher-level Python vulnerabilities
# (deserialization RCE, command injection, SSRF, path traversal, sandbox
# escapes, ...) don't crash the interpreter on their own -- the exploit just
# succeeds and the process keeps running -- so these oracles MANUFACTURE that
# signal: the instant the target does something only a successful exploit
# would do, terminate deliberately (os._exit(134)) and report it honestly as a
# CONFIRMED VULNERABILITY. Nothing here pretends to be AddressSanitizer or any
# native memory tool -- the banner says exactly what actually happened.
#
# ONE oracle, MANY classes. AuditHookOracle detects, via Python audit events
# (PEP 578), the runtime primitives behind most Python vulnerabilities:
#   - unsafe deserialization / object injection -> exec / compile / import
#   - unsafe "safe eval" / template injection    -> exec / compile (see
#     exclude_events below if the library ALSO uses these for benign input)
#   - command injection                         -> subprocess.Popen / os.system
#   - SSRF                                       -> socket.connect / getaddrinfo
#   - path traversal / arbitrary file read      -> open of a sensitive path
# To target a new class you usually change only the *sink call* in entry.py,
# not this file. Add event names to `extra_events` if a class needs them.

import os
import sys
import traceback

_THIS_FILE = os.path.basename(__file__)


def abort_as_finding(sink, detail=""):
    """Report a confirmed vulnerability and terminate the process (exit 134).

    Prints a plain, tool-agnostic finding banner -- not a simulated
    AddressSanitizer report -- naming the actual primitive reached (`sink`,
    e.g. "os.system", "compile", "import:os") and the real Python call stack
    at the moment it fired. The harness's crash-output parser
    (harness/asan.py) recognizes the "SUMMARY: SecurityOracle: <sink> ..."
    line the same way it recognizes native ASAN summaries, so dedup/report
    tooling gets an accurate, sink-specific signal instead of a generic one.
    """
    frames = traceback.extract_stack()[:-1]  # caller frames; drop this frame
    # Drop our own module's frames too (e.g. the audit-hook callback itself),
    # so the top/deepest frame is the first REAL target/library frame -- the
    # thing that actually differs between findings and that dedup/reports
    # should key on, not "whichever oracle module we happened to use".
    frames = [fr for fr in frames if os.path.basename(fr.filename) != _THIS_FILE]
    frames = frames[-6:] if len(frames) > 6 else frames
    frame_lines = [
        "    #%d 0x0 in %s %s:%d" % (i, fr.name, os.path.basename(fr.filename), fr.lineno)
        for i, fr in enumerate(reversed(frames))
    ]
    top = frames[-1] if frames else None
    top_loc = "%s:%d" % (os.path.basename(top.filename), top.lineno) if top else "target:0"

    sys.stderr.write(
        "=== SECURITY-ORACLE: vulnerability confirmed ===\n"
        "%s: oracle: Assertion 'vulnerable-primitive: %s' failed.\n"
        "%s\n"
        "detail: %s\n"
        "SUMMARY: SecurityOracle: %s %s in target_sink\n"
        % (top_loc, sink, "\n".join(frame_lines) or "    #0 0x0 in <unknown> %s" % top_loc,
           str(detail)[:200], sink, top_loc)
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

    def __init__(self, extra_events=(), exclude_events=(), extra_imports=(), sensitive_paths=None,
                 watch_imports=True, watch_open=True):
        # exclude_events: drop defaults that are too broad for THIS target.
        # E.g. a "safe eval" library that legitimately calls compile()/eval()
        # on every request (benign or not) must exclude "compile"/"exec", or
        # every request looks like an escape. Only the concrete dangerous
        # primitive the escape must additionally reach (os.system, a dangerous
        # import, ...) is a real signal in that case.
        self.events = (set(_DEFAULT_EVENTS) | set(extra_events)) - set(exclude_events)
        self.imports = set(_DEFAULT_IMPORTS) | set(extra_imports)
        self.sensitive = tuple(sensitive_paths) if sensitive_paths is not None else _DEFAULT_SENSITIVE
        self.watch_imports = watch_imports
        self.watch_open = watch_open
        self.armed = False

    def _hook(self, event, args):
        if not self.armed:
            return
        if event in self.events:
            abort_as_finding(event, repr(args))
        if self.watch_imports and event == "import":
            name = args[0] if args else ""
            if isinstance(name, str) and name.split(".")[0] in self.imports:
                abort_as_finding("import:" + name, repr(args))
        if self.watch_open and event == "open":
            path = args[0] if args else ""
            if isinstance(path, str) and any(s in path for s in self.sensitive):
                abort_as_finding("open:" + path, repr(args))

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
            abort_as_finding("marker-file", self.marker_path)
