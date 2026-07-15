"""Category 4 — injection-prone tool schemas (live: needs tools/list).

* ``mcp_schema_inputschema_valid`` — spec-grounded conformance: every tool
  MUST declare an inputSchema that is a valid JSON Schema object (not null)
  with root ``type: "object"``. Validation here is *structural* (stdlib
  only): presence, object-ness, root type, and the shape of ``properties``
  / ``required``. Full 2020-12 metaschema validation would need the
  ``jsonschema`` package — a candidate optional extra, not a v0.1 dep.

* ``mcp_schema_unconstrained_input_to_sink`` — inferred, INFO-only: a tool
  whose name/description indicates a sensitive sink (command execution, URL
  fetch, file path, SQL) exposing a free-form string parameter with no
  schema constraint. The scanner flags the schema shape for the operator to
  harden; it does not attempt or confirm injection — schema constraints are
  advisory to clients, server-side validation is the real control.
"""

from __future__ import annotations

import re

from ..findings import Grounding, Severity, Verdict
from ..mcpclient import ServerSnapshot
from ..target import ScanTarget
from .base import Check, CheckResult, register


def _schema_problems(schema: object) -> list[str]:
    """Structural problems with one inputSchema, empty list if sound."""
    if schema is None:
        return ["inputSchema is missing or null"]
    if not isinstance(schema, dict):
        return [f"inputSchema is {type(schema).__name__}, not an object"]
    problems = []
    if schema.get("type") != "object":
        problems.append(f"root type is {schema.get('type')!r}, must be 'object'")
    props = schema.get("properties")
    if props is not None:
        if not isinstance(props, dict):
            problems.append("'properties' is not an object")
        else:
            bad = [k for k, v in props.items() if not isinstance(v, dict)]
            if bad:
                problems.append(f"non-object property definition(s): {', '.join(bad)}")
    required = schema.get("required")
    if required is not None and (
        not isinstance(required, list) or not all(isinstance(r, str) for r in required)
    ):
        problems.append("'required' is not a list of strings")
    return problems


@register
class InputSchemaValid(Check):
    id = "mcp_schema_inputschema_valid"
    title = "Every tool must declare a valid object inputSchema"
    severity = Severity.MEDIUM
    grounding = Grounding.SPEC
    applies_to = ("stdio", "http")
    requires_live = True
    remediation = (
        "Give every tool a valid JSON Schema inputSchema with root type:'object'. For "
        "a zero-argument tool use {\"type\":\"object\",\"additionalProperties\":false} "
        "(the spec's recommended form)."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        assert snapshot is not None
        if not snapshot.tools:
            return CheckResult(Verdict.PASS, "server declares no tools")
        bad: list[str] = []
        for tool in snapshot.tools:
            name = tool.get("name", "?")
            # .get(): an absent key and an explicit null are the same defect here.
            problems = _schema_problems(tool.get("inputSchema"))
            if problems:
                bad.append(f"tool '{name}': {'; '.join(problems)}")
        if bad:
            return CheckResult(Verdict.FAIL, "; ".join(bad))
        return CheckResult(
            Verdict.PASS,
            f"all {len(snapshot.tools)} tool(s) declare a structurally valid object inputSchema",
        )


# Sink lexicon from the catalogue: command execution, URL fetch, file path, SQL.
_SINK_TOKENS = {
    "exec", "shell", "command", "run", "spawn", "eval",
    "fetch", "http", "url", "request", "curl",
    "path", "file", "read", "write",
    "sql", "query", "db",
}
_CONSTRAINT_KEYS = ("enum", "pattern", "format", "maxLength", "const")


def _words(*texts: object) -> set[str]:
    """Lowercase word tokens from tool names/descriptions (splits snake/kebab/camelCase)."""
    joined = " ".join(t for t in texts if isinstance(t, str))
    joined = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", joined)  # camelCase boundary
    return set(re.split(r"[^a-zA-Z]+", joined.lower())) - {""}


@register
class UnconstrainedInputToSink(Check):
    id = "mcp_schema_unconstrained_input_to_sink"
    title = "Sink-bound tool parameters should constrain untrusted input"
    severity = Severity.MEDIUM
    grounding = Grounding.INFERRED
    applies_to = ("stdio", "http")
    requires_live = True
    remediation = (
        "Constrain the parameter at the schema boundary: enum for fixed choices, "
        "pattern/format for structured values (uri, hostname), maxLength to bound "
        "size. Then enforce server-side too: parameterize SQL, allowlist hosts/paths, "
        "avoid passing input to a shell. Schema constraints are advisory to clients; "
        "server-side validation is the real control."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        assert snapshot is not None
        flagged: list[str] = []
        sink_tools = 0
        for tool in snapshot.tools:
            name = tool.get("name", "?")
            if not (_words(tool.get("name"), tool.get("description")) & _SINK_TOKENS):
                continue
            sink_tools += 1
            schema = tool.get("inputSchema")
            props = schema.get("properties") if isinstance(schema, dict) else None
            if not isinstance(props, dict):
                continue  # schema defects are mcp_schema_inputschema_valid's finding
            loose = [
                pname
                for pname, pdef in props.items()
                if isinstance(pdef, dict)
                and pdef.get("type") == "string"
                and not any(k in pdef for k in _CONSTRAINT_KEYS)
            ]
            if loose:
                flagged.append(f"tool '{name}': unconstrained string parameter(s) {', '.join(loose)}")
        if flagged:
            return CheckResult(
                Verdict.INFO,
                "; ".join(flagged) + "; free-form input reaches a sensitive sink by schema - harden for review",
            )
        if sink_tools:
            return CheckResult(Verdict.PASS, f"{sink_tools} sink-like tool(s) constrain their string parameters")
        return CheckResult(Verdict.PASS, "no sink-like tools declared")
