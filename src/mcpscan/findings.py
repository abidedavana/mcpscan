"""Verdicts, severities, grounding tags, and the Finding record.

These mirror the v0.1 catalogue (CHECKS-v0.1.md) exactly:

* ``Verdict`` — PASS / FAIL / INFO / NA. INFO is a heuristic flag that needs
  operator judgement (e.g. a high-entropy string that merely *looks* like a
  secret). NA means the check does not apply to this target's transport or
  declared posture (e.g. an HTTP-only check against a stdio server).
* ``Grounding`` — whether the check's "secure state" comes from a normative
  MUST/SHOULD in the MCP spec (2025-11-25), from best practice with partial
  spec backing, or from pure inference. Findings carry the tag so reports
  never present an inferred check as a spec violation.

A ``Finding`` is one (check, server) verdict with human-readable evidence.
Evidence must never contain a secret value — checks redact before reporting.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Verdict(enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INFO = "INFO"
    NA = "NA"


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Grounding(enum.Enum):
    SPEC = "spec"
    SPEC_INFERRED = "spec+inferred"
    INFERRED = "inferred"


@dataclass(frozen=True)
class Finding:
    """One check's verdict against one configured server."""

    check_id: str
    title: str
    severity: Severity
    grounding: Grounding
    server: str
    verdict: Verdict
    evidence: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "grounding": self.grounding.value,
            "server": self.server,
            "verdict": self.verdict.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
