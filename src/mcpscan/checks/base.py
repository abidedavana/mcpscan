"""Check base class and registry.

A check is one row of CHECKS-v0.1.md turned into code: stable Prowler-style
ID, severity, grounding tag, the transports it applies to, and a ``run()``
that inspects a :class:`~mcpscan.target.ScanTarget` and returns a verdict
with evidence. The runner (not the check) is responsible for emitting NA
when the target's transport is outside ``applies_to``.

Checks must be side-effect free and, in this milestone, purely static:
``run()`` may only read the target's config fields. Handshake / tools-list /
probe inputs arrive in later milestones as additional attributes on the
scan context.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from ..findings import Grounding, Severity, Verdict
from ..target import ScanTarget


@dataclass(frozen=True)
class CheckResult:
    verdict: Verdict
    evidence: str


class Check(abc.ABC):
    """One catalogue check. Subclasses set the class attributes and run()."""

    id: str
    title: str
    severity: Severity
    grounding: Grounding
    applies_to: tuple[str, ...]
    remediation: str

    @abc.abstractmethod
    def run(self, target: ScanTarget) -> CheckResult:
        """Inspect ``target`` and return a verdict with evidence.

        Evidence must be self-explanatory to an operator and must never
        contain a secret value (redact before reporting).
        """


_REGISTRY: list[Check] = []


def register(cls: type[Check]) -> type[Check]:
    """Class decorator: instantiate and add the check to the registry."""
    _REGISTRY.append(cls())
    return cls


def all_checks() -> list[Check]:
    """Every registered check, in catalogue order."""
    return list(_REGISTRY)
