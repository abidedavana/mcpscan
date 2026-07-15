"""Check base class and registry.

A check is one row of CHECKS-v0.1.md turned into code: stable Prowler-style
ID, severity, grounding tag, the transports it applies to, and a ``run()``
that inspects its inputs and returns a verdict with evidence. The runner
(not the check) is responsible for emitting NA when the target's transport
is outside ``applies_to``, and for skipping ``requires_live`` checks when no
live snapshot exists (live scan not requested, failed, or not yet supported
for the transport).

Checks must be side-effect free:

* static checks (``requires_live = False``) read only the target's config
  fields and must ignore ``snapshot``;
* live checks read the :class:`~mcpscan.mcpclient.ServerSnapshot` the
  runner captured — the runner guarantees it is non-None for them. A
  snapshot is observation only (initialize + tools/list); checks never get
  a channel to invoke tools.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from ..findings import Grounding, Severity, Verdict
from ..mcpclient import ServerSnapshot
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
    requires_live: bool = False

    @abc.abstractmethod
    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        """Inspect the inputs and return a verdict with evidence.

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
