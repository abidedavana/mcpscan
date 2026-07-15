"""Category 2 — secrets exposure.

Two checks share one detector:

* ``mcp_secrets_no_hardcoded_in_config`` (static) — literal credentials in
  the config's ``env`` values or ``args``.
* ``mcp_secrets_not_in_tool_surface`` (live) — credentials in what the
  server *advertises to every client*: tool descriptions, schema literals
  (``default`` / ``const`` / ``examples``), the initialize ``instructions``,
  and ``serverInfo`` strings. Distinct from runtime-traffic secret scanners
  (mcp-scan proxy, Docker --block-secrets): this is a static scan of the
  advertised surface, taken from one observation-only snapshot.

The detector has two confidence tiers, mapped to two verdicts:

* **Known signature** (vendor key prefixes, ``Bearer <literal>``,
  private-key blocks) → FAIL. These are unambiguous.
* **Entropy-only** (a secret-*shaped* high-entropy token with no
  recognizable prefix) → INFO, because entropy heuristics have false
  positives and the catalogue reserves INFO for findings that need operator
  judgement.

The catalogue's fail_when/info_when for the config check overlap on argv;
this module resolves it by confidence tier (signature → FAIL, entropy →
INFO) regardless of location, and appends the argv-exposure note whenever a
match sits in ``args`` — argv is readable by other local processes via the
process table, which makes it *worse* than env, never softer.

Reference forms are never flagged: ``${VAR}`` / ``$VAR`` / ``%VAR%``
indirection, secret-manager URIs, and ``<placeholder>`` values.

Evidence is always redacted: the first four characters plus a length, never
the value itself — a scanner report must not become the leak.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator

from ..findings import Grounding, Severity, Verdict
from ..mcpclient import ServerSnapshot
from ..target import ScanTarget
from .base import TOOLS_UNOBSERVABLE_REASON, Check, CheckResult, register, tools_unobservable

# Unambiguous credential shapes. Label, pattern. Order is report order.
_KNOWN_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI/Anthropic-style secret key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("Slack token", re.compile(r"\bxox[bpoars]-[A-Za-z0-9-]{10,}")),
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("literal bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{15,}")),
]

# Values that are references, not literals — these PASS by design.
_REFERENCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}$"),  # ${VAR}, ${VAR:-default}
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),                  # $VAR
    re.compile(r"^%[A-Za-z_][A-Za-z0-9_()]*%$"),                # %VAR% (Windows)
    re.compile(r"^<[^<>]+>$"),                                  # <your-token-here>
]
_SECRET_MANAGER_SCHEMES = ("vault://", "op://", "aws-sm://", "gcp-sm://", "keyring:", "secretref:")

_ENTROPY_MIN_LENGTH = 20
_ENTROPY_MIN_BITS_PER_CHAR = 3.5


def _is_reference(value: str) -> bool:
    v = value.strip()
    return any(p.match(v) for p in _REFERENCE_PATTERNS) or v.lower().startswith(_SECRET_MANAGER_SCHEMES)


def _shannon_bits_per_char(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_high_entropy(value: str) -> bool:
    v = value.strip()
    if len(v) < _ENTROPY_MIN_LENGTH or any(ch.isspace() for ch in v):
        return False
    # URLs and filesystem paths are long and varied but are not credentials
    # per se; URL-embedded tokens are check 3's territory (HTTP), and paths
    # would drown the signal in false positives.
    if "://" in v or "\\" in v or v.startswith(("/", "./", "../")) or re.match(r"^[A-Za-z]:[\\/]", v):
        return False
    # Random tokens virtually always mix digits in; hyphenated identifiers
    # like npm package specs ("@example/files-server") clear the entropy bar
    # without any. Requiring a digit costs ~3% recall on this heuristic tier
    # and removes that whole false-positive class.
    if not any(ch.isdigit() for ch in v):
        return False
    return _shannon_bits_per_char(v) >= _ENTROPY_MIN_BITS_PER_CHAR


def _redact(value: str) -> str:
    # ASCII only: report text must survive Windows consoles and log pipelines.
    v = value.strip()
    return f"{v[:4]}... ({len(v)} chars)"


def find_secret_hits(locations: Iterable[tuple[str, str]]) -> tuple[list[str], list[str], set[str]]:
    """Scan (where, value) pairs. Returns (signature_hits, entropy_hits, hit_wheres)."""
    signature_hits: list[str] = []
    entropy_hits: list[str] = []
    hit_wheres: set[str] = set()
    for where, value in locations:
        if not isinstance(value, str) or _is_reference(value):
            continue
        matched = False
        for label, pattern in _KNOWN_SIGNATURES:
            m = pattern.search(value)
            if m:
                signature_hits.append(f"{label} in {where}: {_redact(m.group(0))}")
                matched = True
                break
        if not matched and _looks_high_entropy(value):
            entropy_hits.append(f"secret-shaped high-entropy value in {where}: {_redact(value)}")
            matched = True
        if matched:
            hit_wheres.add(where)
    return signature_hits, entropy_hits, hit_wheres


def _iter_schema_literals(prefix: str, node: object) -> Iterator[tuple[str, str]]:
    """Yield (where, value) for every string literal a schema embeds.

    Literals are the fields a schema can smuggle a credential in: ``default``,
    ``const``, and ``examples`` entries, at any nesting depth.
    """
    if isinstance(node, dict):
        for key in ("default", "const"):
            v = node.get(key)
            if isinstance(v, str):
                yield f"{prefix}.{key}", v
        ex = node.get("examples")
        if isinstance(ex, list):
            for i, v in enumerate(ex):
                if isinstance(v, str):
                    yield f"{prefix}.examples[{i}]", v
        for k, v in node.items():
            if k != "examples" and isinstance(v, (dict, list)):
                yield from _iter_schema_literals(f"{prefix}.{k}", v)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, (dict, list)):
                yield from _iter_schema_literals(f"{prefix}[{i}]", v)


@register
class SecretsInConfig(Check):
    id = "mcp_secrets_no_hardcoded_in_config"
    title = "No literal credentials hardcoded in server config"
    severity = Severity.CRITICAL
    grounding = Grounding.SPEC_INFERRED
    applies_to = ("stdio", "http")
    remediation = (
        "Replace literal secrets with environment-variable references resolved at "
        "launch, or a secret manager / OS keychain. For stdio servers pass credentials "
        "via env, never as command-line arguments (argv is readable by other local "
        "users via ps / the process table). Rotate any secret that was stored in "
        "plaintext."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        locations: list[tuple[str, str]] = [(f"env[{k}]", v) for k, v in target.env.items()]
        locations += [(f"args[{i}]", a) for i, a in enumerate(target.args)]
        signature_hits, entropy_hits, hit_wheres = find_secret_hits(locations)

        argv_note = (
            "; note: values in argv are visible to any local process via the process table"
            if any(w.startswith("args[") for w in hit_wheres)
            else ""
        )
        if signature_hits:
            return CheckResult(Verdict.FAIL, "; ".join(signature_hits + entropy_hits) + argv_note)
        if entropy_hits:
            return CheckResult(
                Verdict.INFO,
                "; ".join(entropy_hits) + argv_note + "; verify: if it is a credential, move it to a reference and rotate it",
            )
        return CheckResult(Verdict.PASS, "no literal credentials found in env or args")


@register
class SecretsInToolSurface(Check):
    id = "mcp_secrets_not_in_tool_surface"
    title = "No secrets exposed in tool definitions, schemas, or server instructions"
    severity = Severity.MEDIUM
    grounding = Grounding.INFERRED
    applies_to = ("stdio", "http")
    requires_live = True
    remediation = (
        "Strip credentials from tool descriptions, schema literals, and the initialize "
        "instructions; supply secrets to the server at runtime via env / a secret "
        "manager, never inline in metadata the server advertises to every client. "
        "Rotate any exposed secret."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        assert snapshot is not None  # runner guarantees this for requires_live
        locations: list[tuple[str, str]] = []
        if snapshot.instructions:
            locations.append(("initialize.instructions", snapshot.instructions))
        locations += [
            (f"serverInfo.{k}", v) for k, v in snapshot.server_info.items() if isinstance(v, str)
        ]
        for tool in snapshot.tools:
            name = tool.get("name", "?")
            desc = tool.get("description")
            if isinstance(desc, str):
                locations.append((f"tool[{name}].description", desc))
            for schema_key in ("inputSchema", "outputSchema"):
                locations.extend(_iter_schema_literals(f"tool[{name}].{schema_key}", tool.get(schema_key)))

        # Nothing at all was observed (e.g. an auth-gated HTTP endpoint returned
        # no instructions, serverInfo, or tools): NA, not a misleading PASS.
        if not locations and tools_unobservable(snapshot):
            return CheckResult(Verdict.NA, TOOLS_UNOBSERVABLE_REASON)

        signature_hits, entropy_hits, _ = find_secret_hits(locations)
        if signature_hits:
            return CheckResult(Verdict.FAIL, "; ".join(signature_hits + entropy_hits))
        if entropy_hits:
            return CheckResult(
                Verdict.INFO,
                "; ".join(entropy_hits) + "; verify: if it is a credential, remove it from the advertised surface and rotate it",
            )
        return CheckResult(
            Verdict.PASS,
            f"no secret-shaped values in instructions, serverInfo, or {len(snapshot.tools)} tool definition(s)",
        )
