# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Post-hoc finding deduplication — summary view only.

  vuln-pipeline dedup results/<target>/<timestamp>/    # one batch
  vuln-pipeline dedup results/<target>/                # all batches

Walks result.json files under the given root and groups findings by
(finding_type, top evidence frame). Includes both finding_confirmed and
finding_rejected results — a rejected finding is still signal.

This is a summary artifact, not a phase gate. In streaming mode the judge
agent decides which findings get reports; this subcommand just answers "these
N findings cluster into M signatures" for the results writeup.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

from .asan import top_frame, finding_reason


NO_FRAME = "<no-frame>"


def _signature(finding: dict) -> tuple[str, str]:
    reason = finding.get("reason") or finding_reason(finding.get("finding_evidence") or "")
    finding_type = reason["finding_type"] or finding.get("finding_type") or "unknown"
    frame = top_frame(finding.get("finding_evidence") or "")
    return (finding_type, frame or NO_FRAME)


def dedup(results_root: Path) -> dict[tuple[str, str], list[tuple[Path, str, dict]]]:
    """Group findings under results_root by signature.

    Returns {(finding_type, top_frame): [(result_json_path, status, reason), ...]}
    where reason is the pipeline-parsed {finding_type, operation}.
    Skips results where finding is null. Silently skips unreadable/malformed
    files — a half-written result.json from a killed run shouldn't abort
    the whole report.
    """
    groups: dict[tuple[str, str], list[tuple[Path, str, dict]]] = defaultdict(list)
    for path in sorted(results_root.rglob("result.json")):
        try:
            result = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        finding = result.get("finding")
        if not finding:
            continue
        reason = finding.get("reason") or finding_reason(finding.get("finding_evidence") or "")
        sig = _signature(finding)
        groups[sig].append((path, result.get("status", "unknown"), reason))
    return dict(groups)


def format_report(groups: dict[tuple[str, str], list[tuple[Path, str, dict]]],
                  root: Path | None = None) -> str:
    if not groups:
        return "No findings found.\n"

    # Sort: largest group first, then alphabetical by signature.
    ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    total = sum(len(v) for v in groups.values())

    lines = [f"{len(groups)} unique signature(s) across {total} finding(s):", ""]
    for (finding_type, frame), entries in ordered:
        where = f" in {frame}" if frame != NO_FRAME else ""
        ops = sorted({op for _, _, r in entries if (op := r.get("operation"))})
        op_note = f" ({'/'.join(ops)})" if ops else ""
        lines.append(f"[{len(entries)}x] {finding_type}{op_note}{where}")
        for path, status, _ in entries:
            shown = path.relative_to(root) if root else path
            lines.append(f"     {shown}  ({status})")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m harness.dedup <results_dir>", file=sys.stderr)
        sys.exit(1)
    root = Path(sys.argv[1])
    print(format_report(dedup(root), root))
