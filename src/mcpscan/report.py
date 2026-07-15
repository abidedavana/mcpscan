"""Report rendering: console text and a machine-readable JSON document.

Console rules:

* Findings group by server, in config order.
* PASS / FAIL / INFO always print; NA prints only with ``show_all`` so the
  default view stays readable while coverage stays inspectable.
* Remediation prints only for FAIL and INFO — a passing check needs no fix.
* The grounding tag prints on FAIL/INFO lines so an inferred check is never
  mistaken for a spec violation.
"""

from __future__ import annotations

import json

from . import SPEC_VERSION, __version__
from .findings import Finding, Verdict


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {v.value: 0 for v in Verdict}
    for f in findings:
        counts[f.verdict.value] += 1
    return counts


def render_console(findings: list[Finding], show_all: bool = False) -> str:
    servers: list[str] = []
    for f in findings:
        if f.server not in servers:
            servers.append(f.server)
    n_checks = len({f.check_id for f in findings})

    # ASCII only: console output must survive Windows codepages and log pipelines.
    lines = [f"mcpscan {__version__} - {len(servers)} server(s), {n_checks} check(s), spec {SPEC_VERSION}"]
    for server in servers:
        lines.append(f"\nserver: {server}")
        for f in findings:
            if f.server != server:
                continue
            if f.verdict is Verdict.NA and not show_all:
                continue
            lines.append(f"  [{f.verdict.value:<4}] {f.severity.value:<8} {f.check_id}")
            lines.append(f"          {f.evidence}")
            if f.verdict in (Verdict.FAIL, Verdict.INFO):
                lines.append(f"          grounding: {f.grounding.value}")
                lines.append(f"          fix: {f.remediation}")

    c = summarize(findings)
    lines.append(f"\nsummary: {c['FAIL']} FAIL, {c['INFO']} INFO, {c['PASS']} PASS, {c['NA']} NA")
    return "\n".join(lines)


def to_json(findings: list[Finding]) -> str:
    doc = {
        "mcpscan_version": __version__,
        "spec_version": SPEC_VERSION,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2)
