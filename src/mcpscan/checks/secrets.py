"""Category 2 — secrets exposure. Catalogue check: mcp_secrets_no_hardcoded_in_config.

Two confidence tiers, mapped to two verdicts:

* **Known signature** (vendor key prefixes, ``Bearer <literal>``, private-key
  blocks) → FAIL. These are unambiguous.
* **Entropy-only** (a secret-*shaped* high-entropy token with no recognizable
  prefix) → INFO, because entropy heuristics have false positives and the
  catalogue reserves INFO for findings that need operator judgement.

The catalogue's fail_when/info_when for this check overlap on argv; this
module resolves it by confidence tier (signature → FAIL, entropy → INFO)
regardless of location, and appends the argv-exposure note whenever a match
sits in ``args`` — argv is readable by other local processes via the process
table, which makes it *worse* than env, never softer.

Reference forms are never flagged: ``${VAR}`` / ``$VAR`` / ``%VAR%``
indirection, secret-manager URIs, and ``<placeholder>`` values.

Evidence is always redacted: the first four characters plus a length, never
the value itself — a scanner report must not become the leak.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..findings import Grounding, Severity, Verdict
from ..target import ScanTarget
from .base import Check, CheckResult, register

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

    def run(self, target: ScanTarget) -> CheckResult:
        locations: list[tuple[str, str]] = [(f"env[{k}]", v) for k, v in target.env.items()]
        locations += [(f"args[{i}]", a) for i, a in enumerate(target.args)]

        signature_hits: list[str] = []
        entropy_hits: list[str] = []
        argv_hit = False
        for where, value in locations:
            if _is_reference(value):
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
            if matched and where.startswith("args["):
                argv_hit = True

        argv_note = (
            "; note: values in argv are visible to any local process via the process table"
            if argv_hit
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
