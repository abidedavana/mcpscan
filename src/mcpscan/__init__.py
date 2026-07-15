"""mcpscan — defensive posture scanner for MCP (Model Context Protocol) servers.

mcpscan inspects operator-supplied MCP server configurations (and, in later
milestones, live handshakes and tool listings) for security misconfigurations,
reports them with PASS / FAIL / INFO / NA verdicts, and tells the operator the
exact fix. It is the same category of tool as Prowler or a linter: detection
and remediation only — no exploitation, no attack generation.

Every check is defined in ``CHECKS-v0.1.md`` and carries a grounding tag:
``spec`` (backed by a normative MUST/SHOULD in the MCP specification,
revision 2025-11-25), ``spec+inferred``, or ``inferred`` (best practice with
no spec-defined secure state). Reports preserve the tag so an inferred check
is never presented as a spec violation.
"""

from __future__ import annotations

__version__ = "0.1.0"

#: MCP specification revision the catalogue's normative claims were verified
#: against (see CHECKS-v0.1.md, "Verification note").
SPEC_VERSION = "2025-11-25"

from .checks import all_checks
from .findings import Finding, Grounding, Severity, Verdict
from .runner import scan
from .target import ScanTarget, load_targets

__all__ = [
    "__version__",
    "SPEC_VERSION",
    "Finding",
    "Grounding",
    "Severity",
    "Verdict",
    "ScanTarget",
    "load_targets",
    "scan",
    "all_checks",
]
