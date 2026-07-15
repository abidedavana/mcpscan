"""The scan loop: every target × every applicable check → findings.

The runner owns two behaviors checks must not implement themselves:

* **NA on transport mismatch** — an HTTP-only check against a stdio server
  yields an NA finding (visible with ``--all``), not silence, so operators
  can see coverage, not just failures.
* **Crash containment** — one buggy check must not kill the scan. An
  exception becomes an INFO finding naming the check, and the scan goes on.
"""

from __future__ import annotations

from collections.abc import Iterable

from .checks import Check, all_checks
from .checks.base import CheckResult
from .findings import Finding, Verdict
from .target import ScanTarget


def _finding(check: Check, target: ScanTarget, result: CheckResult) -> Finding:
    return Finding(
        check_id=check.id,
        title=check.title,
        severity=check.severity,
        grounding=check.grounding,
        server=target.name,
        verdict=result.verdict,
        evidence=result.evidence,
        remediation=check.remediation,
    )


def scan(targets: Iterable[ScanTarget], checks: Iterable[Check] | None = None) -> list[Finding]:
    """Run ``checks`` (default: all registered) against every target."""
    check_list = list(checks) if checks is not None else all_checks()
    findings: list[Finding] = []
    for target in targets:
        for check in check_list:
            if target.transport not in check.applies_to:
                result = CheckResult(
                    Verdict.NA,
                    f"applies to {'/'.join(check.applies_to)} transports; {target.name!r} is {target.transport}",
                )
            else:
                try:
                    result = check.run(target)
                except Exception as e:  # crash containment — see module docstring
                    result = CheckResult(Verdict.INFO, f"internal error while running check: {e!r}")
            findings.append(_finding(check, target, result))
    return findings
