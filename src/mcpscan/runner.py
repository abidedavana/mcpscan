"""The scan loop: every target × every applicable check → findings.

The runner owns behaviors checks must not implement themselves:

* **NA on transport mismatch** — an HTTP-only check against a stdio server
  yields an NA finding (visible with ``--all``), not silence, so operators
  can see coverage, not just failures.
* **Live-snapshot capture and gating** — with ``live=True`` the runner takes
  one observation-only snapshot per stdio target (initialize + tools/list,
  never tools/call) and hands it to ``requires_live`` checks. When there is
  no snapshot — live not requested, the launch failed, or an HTTP target
  (probe engine lands in milestone 4) — live checks report NA with the
  reason instead of guessing.
* **Crash containment** — one buggy check must not kill the scan. An
  exception becomes an INFO finding naming the check, and the scan goes on.
"""

from __future__ import annotations

from collections.abc import Iterable

from .checks import Check, all_checks
from .checks.base import CheckResult
from .findings import Finding, Verdict
from .mcpclient import McpClientError, ServerSnapshot, snapshot_stdio
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


def scan(
    targets: Iterable[ScanTarget],
    checks: Iterable[Check] | None = None,
    live: bool = False,
) -> list[Finding]:
    """Run ``checks`` (default: all registered) against every target."""
    check_list = list(checks) if checks is not None else all_checks()
    findings: list[Finding] = []
    for target in targets:
        snapshot: ServerSnapshot | None = None
        no_live_reason = "live check; run with --live to launch the server and take a snapshot"
        if live:
            if target.transport == "stdio":
                try:
                    snapshot = snapshot_stdio(target)
                except McpClientError as e:
                    no_live_reason = f"live snapshot failed: {e}"
            else:
                no_live_reason = "live scan for HTTP transports lands with the probe engine (milestone 4)"

        for check in check_list:
            if target.transport not in check.applies_to:
                result = CheckResult(
                    Verdict.NA,
                    f"applies to {'/'.join(check.applies_to)} transports; {target.name!r} is {target.transport}",
                )
            elif check.requires_live and snapshot is None:
                result = CheckResult(Verdict.NA, no_live_reason)
            else:
                try:
                    result = check.run(target, snapshot)
                except Exception as e:  # crash containment — see module docstring
                    result = CheckResult(Verdict.INFO, f"internal error while running check: {e!r}")
            findings.append(_finding(check, target, result))
    return findings
