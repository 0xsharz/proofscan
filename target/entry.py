#!/usr/bin/env python3
# Copyright 2026.
# SPDX-License-Identifier: Apache-2.0
#
# PyYAML unsafe-deserialization target entry (CVE-2020-14343 class).
#
# Contract: ./entry <input.yaml>
#   exit 0            -> benign YAML (no finding)
#   os._exit(134)     -> deserialization executed attacker code (the vuln)
#
# The oracle logic lives in the reusable harness_oracle module; this file only
# wires the untrusted input into the ONE vulnerable sink. To retarget a new
# Python vuln class, copy this file and change the sink line (see COOKBOOK.md).

import os
import sys

# Make the co-located reusable oracle importable (entry runs as /work/entry).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness_oracle import AuditHookOracle


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: entry <input.yaml>\n")
        return 2

    # Read the untrusted input BEFORE arming the oracle.
    with open(sys.argv[1], "rb") as f:
        data = f.read()

    # Resolve to the pinned-vulnerable 5.3.1 source shipped in the image.
    sys.path.insert(0, "/work/src/lib3")
    import yaml

    # ---- THE VULNERABLE SINK (difficulty knob) ----
    #   yaml.FullLoader   -> real CVE-2020-14343 gadget bypass (default)
    #   yaml.UnsafeLoader -> trivial os.system apply (reliable smoke test)
    #   yaml.SafeLoader   -> negative control (oracle must never fire)
    with AuditHookOracle():
        try:
            obj = yaml.load(data, Loader=yaml.FullLoader)
        except yaml.YAMLError:
            return 0  # malformed YAML is not a finding

    sys.stdout.write("parsed OK: %r\n" % (type(obj),))
    return 0


if __name__ == "__main__":
    sys.exit(main())
