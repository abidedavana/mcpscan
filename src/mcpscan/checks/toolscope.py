"""Category 3 — tool permission scope (live: needs tools/list).

``mcp_tools_capability_annotation_consistency`` flags two conditions on
dangerous-capability tools:

(a) no annotations at all — clients then fall back to the spec defaults
    (destructiveHint:true, openWorldHint:true, readOnlyHint:false,
    idempotentHint:false), so the operator's intent is whatever the default
    happens to be;
(b) an annotation that contradicts the apparent capability — the worst case
    is readOnlyHint:true on a tool that executes/writes/deletes, which lets
    a mutating tool bypass a host's confirmation prompts.

Grounding: inferred. Annotations are OPTIONAL hints and clients MUST treat
them as untrusted from untrusted servers — so this is a posture check for
the operator's OWN (trusted) server, not conformance. It is lexicon-driven
and therefore heuristic: strong matches (exec/delete/...) report FAIL,
weak single-generic-term matches (update/query/...) report INFO for
operator confirmation, per the catalogue.
"""

from __future__ import annotations

from ..findings import Grounding, Severity, Verdict
from ..mcpclient import ServerSnapshot
from ..target import ScanTarget
from .base import TOOLS_UNOBSERVABLE_REASON, Check, CheckResult, register, tools_unobservable
from .schemas import _words

# Tokens that unambiguously signal a dangerous capability...
_STRONG_TOKENS = {
    "exec", "shell", "spawn", "eval", "sudo",
    "delete", "remove", "drop", "truncate", "purge", "wipe", "destroy",
    "upload", "curl", "sql",
}
# ...the subset that signals destruction specifically...
_DESTRUCTIVE_TOKENS = {"delete", "remove", "drop", "truncate", "purge", "wipe", "destroy"}
# ...and generic verbs that only *suggest* mutation (INFO, not FAIL).
_WEAK_TOKENS = {"run", "command", "write", "update", "put", "post", "fetch", "request", "http", "query"}


def _annotation_issues(tool: dict, tokens: set[str]) -> str | None:
    """The catalogue's three trigger conditions, or None if consistent."""
    name = tool.get("name", "?")
    annotations = tool.get("annotations")
    if not isinstance(annotations, dict) or not annotations:
        return (
            f"tool '{name}' looks dangerous ({', '.join(sorted(tokens))}) but declares no "
            "annotations; clients fall back to spec defaults"
        )
    if annotations.get("readOnlyHint") is True:
        return f"tool '{name}' declares readOnlyHint:true but looks mutating ({', '.join(sorted(tokens))})"
    if tokens & _DESTRUCTIVE_TOKENS and annotations.get("destructiveHint") is False:
        return f"tool '{name}' declares destructiveHint:false but looks destructive ({', '.join(sorted(tokens & _DESTRUCTIVE_TOKENS))})"
    return None


@register
class AnnotationConsistency(Check):
    id = "mcp_tools_capability_annotation_consistency"
    title = "Dangerous-capability tools must carry accurate behavior annotations"
    severity = Severity.HIGH
    grounding = Grounding.INFERRED
    applies_to = ("stdio", "http")
    requires_live = True
    remediation = (
        "Add annotations that truthfully describe each tool: readOnlyHint:true only "
        "for tools with no side effects; destructiveHint:true for tools that "
        "delete/overwrite; openWorldHint:true for tools that reach external systems. "
        "The spec defaults for an unannotated tool are destructiveHint:true, "
        "openWorldHint:true, readOnlyHint:false, idempotentHint:false - declare "
        "explicitly rather than relying on them."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        assert snapshot is not None
        if tools_unobservable(snapshot):
            return CheckResult(Verdict.NA, TOOLS_UNOBSERVABLE_REASON)
        failures: list[str] = []
        reviews: list[str] = []
        for tool in snapshot.tools:
            words = _words(tool.get("name"), tool.get("description"))
            strong = words & _STRONG_TOKENS
            weak = words & _WEAK_TOKENS
            if strong:
                issue = _annotation_issues(tool, strong)
                if issue:
                    failures.append(issue)
            elif weak:
                # Weak lexicon match: same conditions, surfaced as INFO for
                # operator confirmation instead of an authoritative FAIL.
                issue = _annotation_issues(tool, weak)
                if issue:
                    reviews.append(issue)
        if failures:
            return CheckResult(Verdict.FAIL, "; ".join(failures + reviews))
        if reviews:
            return CheckResult(Verdict.INFO, "; ".join(reviews) + "; weak lexicon match - confirm and annotate")
        return CheckResult(
            Verdict.PASS,
            f"annotations are consistent with apparent capability across {len(snapshot.tools)} tool(s)",
        )
