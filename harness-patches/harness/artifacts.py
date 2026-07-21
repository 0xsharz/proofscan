# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Data contracts for the find→grade pipeline.

FindingArtifact is the pivot: find emits it, grade consumes it. Field names are
tool-agnostic — "finding" covers a native ASAN memory-safety crash exactly as
well as a manufactured oracle abort (deserialization RCE, sandbox escape, ...).
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(frozen=True)
class FindingArtifact:
    """A finding the find-agent claims to have produced. Not yet verified."""
    poc_path: str              # path inside the find-container, e.g. /tmp/poc.bin
    poc_bytes: bytes           # PoC file contents — bytes, inputs are often binary
    reproduction_command: str  # exact command, e.g. "/work/entry /tmp/poc.bin"
    finding_type: str          # agent's classification, e.g. "heap-buffer-overflow" or "os.system"
    finding_evidence: str      # oracle trace / stderr, truncated to 10K chars
    exit_code: int             # e.g. 134 (SIGABRT from ASAN, or a manufactured oracle abort)
    dup_check: str | None = None  # agent's reasoning that this isn't a known dup

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["poc_bytes"] = base64.b64encode(self.poc_bytes).decode("ascii")
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FindingArtifact:
        return cls(
            poc_path=d["poc_path"],
            poc_bytes=base64.b64decode(d["poc_bytes"]),
            reproduction_command=d["reproduction_command"],
            finding_type=d["finding_type"],
            finding_evidence=d["finding_evidence"],
            exit_code=d["exit_code"],
            dup_check=d.get("dup_check"),
        )


@dataclass
class GraderVerdict:
    """The grade-agent's judgment of a FindingArtifact."""
    passed: bool
    score: float               # 0.0–1.0
    criteria: dict[str, bool]  # {"criterion_1": True, ..., "criterion_5": True}
    evidence: str              # grader's summary

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GraderVerdict:
        return cls(
            passed=d["passed"],
            score=d["score"],
            criteria=d["criteria"],
            evidence=d["evidence"],
        )


@dataclass
class PatchVerdict:
    """T0-T3 ladder result for a candidate patch. Every gating tier is an
    executable oracle (compiler/ASAN/tests); T3 is advisory-only."""
    t0_builds: bool
    t1_poc_stops: bool
    t2_tests_pass: bool | None     # None = target has no test suite
    re_attack_clean: bool | None   # None = re-attack not run (--no-reattack)
    t3_style_score: float | None   # 0-10, None when style judge not run
    evidence: dict[str, str]       # per-tier stdout/stderr excerpts
    timings: dict[str, float]

    @property
    def passed(self) -> bool:
        return (
            self.t0_builds
            and self.t1_poc_stops
            and self.t2_tests_pass is not False
            and self.re_attack_clean is not False
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["passed"] = self.passed
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PatchVerdict:
        return cls(
            t0_builds=d["t0_builds"],
            t1_poc_stops=d["t1_poc_stops"],
            t2_tests_pass=d["t2_tests_pass"],
            re_attack_clean=d["re_attack_clean"],
            t3_style_score=d.get("t3_style_score"),
            evidence=d.get("evidence", {}),
            timings=d.get("timings", {}),
        )


@dataclass
class JudgeVerdict:
    """The judge-agent's call on whether a new finding warrants a report."""
    judgment: str              # NEW, DUP_BETTER, DUP_SKIP
    bug_id: int | None         # which existing bug it matches (required for DUP_*)
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> JudgeVerdict:
        return cls(
            judgment=d["judgment"],
            bug_id=d.get("bug_id"),
            reasoning=d.get("reasoning", ""),
        )


@dataclass
class ReportVerdict:
    """The report-agent's exploitability analysis of a verified finding."""
    section_scores: dict[str, int]  # primitive, reachability, heap_layout, escalation_path, constraints → 0/1/2
    rubric_score: int               # sum of section scores, 0..10
    escalation_bonus: int           # 0..4 for escalation_attempt depth
    total_score: float              # (rubric + bonus) / 14
    severity_rating: str            # agent's CRITICAL/HIGH/MEDIUM/LOW/NOT-A-BUG/NOT_STATED
    novelty_status: str             # FIXED/UNFIXED/UNKNOWN/NOT_CHECKED
    reachability_verdict: str       # REACHABLE/HARNESS_ONLY/UNCLEAR

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ReportVerdict:
        return cls(
            section_scores=d["section_scores"],
            rubric_score=d["rubric_score"],
            escalation_bonus=d["escalation_bonus"],
            total_score=d["total_score"],
            severity_rating=d["severity_rating"],
            novelty_status=d["novelty_status"],
            reachability_verdict=d["reachability_verdict"],
        )


@dataclass
class RunResult:
    """One end-to-end run's outcome."""
    target: str
    status: str                     # finding_confirmed, no_finding, finding_rejected, agent_failed, build_failed, error
    finding: FindingArtifact | None
    verdict: GraderVerdict | None
    find_transcript: list[dict] = field(default_factory=list)
    grade_transcript: list[dict] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "status": self.status,
            "finding": self.finding.to_dict() if self.finding else None,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "find_transcript": self.find_transcript,
            "grade_transcript": self.grade_transcript,
            "timings": self.timings,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunResult:
        return cls(
            target=d["target"],
            status=d["status"],
            finding=FindingArtifact.from_dict(d["finding"]) if d.get("finding") else None,
            verdict=GraderVerdict.from_dict(d["verdict"]) if d.get("verdict") else None,
            find_transcript=d.get("find_transcript", []),
            grade_transcript=d.get("grade_transcript", []),
            timings=d.get("timings", {}),
            error=d.get("error"),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, s: str) -> RunResult:
        return cls.from_dict(json.loads(s))
