"""Category 5 — transport security.

Static (config-only):

* ``mcp_transport_tls_remote_http`` — plaintext ``http://`` to a non-loopback
  host. Grounding: **inferred**. Verified against the live 2025-11-25 spec:
  HTTPS is mandated only for OAuth authorization-server endpoints and
  redirect URIs, never for the MCP data endpoint itself — so this is a
  hardening recommendation, not a conformance failure, and the report must
  say so.

* ``mcp_transport_localhost_binding`` (config half) — a local server bound to
  ``0.0.0.0`` / ``::`` / a routable interface. Grounding: **spec** ("When
  running locally, servers SHOULD bind only to localhost (127.0.0.1) rather
  than all network interfaces (0.0.0.0)", basic/transports Security Warning).
  Evaluates the operator-declared ``x-mcpscan.bind_host``; runtime detection
  lands with the probe engine.

Live (snapshot):

* ``mcp_transport_stdio_stdout_clean`` — non-protocol output on stdout during
  the handshake. Grounding: **spec** ("The server MUST NOT write anything to
  its stdout that is not a valid MCP message"; logging belongs on stderr,
  which the spec permits). The client collects offending lines as
  ``ServerSnapshot.stdout_noise`` while driving initialize + tools/list.

* ``mcp_transport_origin_validation`` — a Streamable HTTP server that
  processes a request bearing a foreign Origin header. Grounding: **spec**
  ("Servers MUST validate the Origin header on all incoming connections";
  "if present and invalid, servers MUST respond with HTTP 403 Forbidden").

* ``mcp_transport_session_id_quality`` — an issued MCP-Session-Id that is
  outside visible ASCII, low-entropy, or sequential across two handshakes.
  Grounding: **spec+inferred** (charset MUST and "secure, non-deterministic
  session IDs" MUST are spec; the entropy threshold and sequential heuristic
  are inferred).
"""

from __future__ import annotations

import math
from collections import Counter
from urllib.parse import urlsplit

from ..findings import Grounding, Severity, Verdict
from ..mcpclient import ServerSnapshot
from ..netutil import is_loopback_host as _is_loopback_host
from ..target import ScanTarget
from .base import Check, CheckResult, register


@register
class TlsRemoteHttp(Check):
    id = "mcp_transport_tls_remote_http"
    title = "Remote HTTP endpoint should use TLS"
    severity = Severity.MEDIUM
    grounding = Grounding.INFERRED
    applies_to = ("http",)
    remediation = (
        "Serve the MCP endpoint over HTTPS with a valid certificate; redirect or "
        "refuse plaintext http on non-loopback hosts. (Hardening recommendation: the "
        "MCP spec mandates HTTPS only for OAuth endpoints, not the MCP endpoint "
        "itself.)"
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        parts = urlsplit(target.url or "")
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        if not scheme or not host:
            return CheckResult(Verdict.INFO, f"endpoint URL {target.url!r} could not be parsed into scheme + host")
        if scheme == "https":
            return CheckResult(Verdict.PASS, f"endpoint uses TLS: https://{host}")
        if scheme == "http" and _is_loopback_host(host):
            return CheckResult(Verdict.PASS, f"plaintext http acceptable: host {host!r} is loopback-only")
        if scheme == "http":
            return CheckResult(
                Verdict.FAIL,
                f"plaintext http to non-loopback host {host!r}: tokens, tool arguments, "
                "and results are exposed to network interception",
            )
        return CheckResult(Verdict.INFO, f"unrecognized URL scheme {scheme!r} on endpoint {target.url!r}")


@register
class LocalhostBinding(Check):
    id = "mcp_transport_localhost_binding"
    title = "Local HTTP server should bind to loopback, not all interfaces"
    severity = Severity.MEDIUM
    grounding = Grounding.SPEC
    applies_to = ("http",)
    remediation = (
        "Bind local servers to 127.0.0.1 (or ::1) so only local processes can reach "
        "them. If the server must be network-reachable, treat it as remote: require "
        "authentication and TLS, and restrict source addresses."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        if target.scope == "remote":
            return CheckResult(
                Verdict.NA,
                "declared remote/hosted (x-mcpscan.scope=remote): a routable bind is intended; ensure auth + TLS front it",
            )
        bind = target.bind_host
        if bind is None:
            return CheckResult(
                Verdict.NA,
                "bind address not declared (x-mcpscan.bind_host); runtime detection lands with the probe engine",
            )
        if _is_loopback_host(bind):
            return CheckResult(Verdict.PASS, f"binds loopback only: {bind}")

        # Non-loopback bind. FAIL needs the server to be local — declared, or
        # inferred from the client connecting to it via a loopback URL.
        host = (urlsplit(target.url or "").hostname or "").lower()
        inferred_local = target.scope == "local" or _is_loopback_host(host)
        if inferred_local:
            return CheckResult(
                Verdict.FAIL,
                f"local server binds {bind!r}, reachable from the network "
                "(the CVE-2025-49596 exposure class when combined with weak or absent auth)",
            )
        return CheckResult(
            Verdict.INFO,
            f"non-loopback bind {bind!r} with undeclared scope - set x-mcpscan.scope to "
            "'local' (then this is a finding) or 'remote' (then front it with auth + TLS)",
        )


@register
class StdioStdoutClean(Check):
    id = "mcp_transport_stdio_stdout_clean"
    title = "stdio server must emit only protocol messages on stdout"
    severity = Severity.LOW
    grounding = Grounding.SPEC
    applies_to = ("stdio",)
    requires_live = True
    remediation = (
        "Route all logging and diagnostics to stderr (which the spec permits for "
        "logging); keep stdout exclusively for newline-delimited MCP messages with no "
        "embedded newlines."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        assert snapshot is not None
        noise = snapshot.stdout_noise
        if not noise:
            return CheckResult(Verdict.PASS, "stdout carried only valid MCP messages during the handshake")
        shown = "; ".join(repr(line[:60]) for line in noise[:3])
        more = f" (+{len(noise) - 3} more line(s))" if len(noise) > 3 else ""
        return CheckResult(
            Verdict.FAIL,
            f"{len(noise)} non-protocol line(s) on stdout during the handshake: {shown}{more}",
        )


@register
class OriginValidation(Check):
    id = "mcp_transport_origin_validation"
    title = "HTTP server must validate the Origin header"
    severity = Severity.HIGH
    grounding = Grounding.SPEC
    applies_to = ("http",)
    requires_live = True
    remediation = (
        "Validate the Origin header on every incoming connection against an allowlist "
        "of expected origins; respond 403 to a present-but-invalid Origin. This is the "
        "primary DNS-rebinding defense for local HTTP servers."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        probe = snapshot.http if snapshot else None
        if probe is None or probe.foreign_origin_status is None:
            return CheckResult(Verdict.INFO, "could not test Origin validation (no response to the foreign-Origin probe)")
        status = probe.foreign_origin_status
        if status == 200:
            return CheckResult(
                Verdict.FAIL,
                "processed a request bearing a foreign Origin header (HTTP 200): the DNS-rebinding "
                "hole behind CVE-2025-49596",
            )
        if status == 403:
            return CheckResult(Verdict.PASS, "rejected a foreign Origin header with HTTP 403")
        return CheckResult(
            Verdict.INFO,
            f"a foreign Origin header got HTTP {status}; could not confirm Origin validation "
            "(possibly auth-gated before the Origin check)",
        )


def _total_entropy_bits(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    per_char = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return per_char * n


def _looks_sequential(a: str, b: str) -> bool:
    """True if two successive session IDs differ only by a small increment."""
    if not a or not b or a == b:
        return False
    if a.isdigit() and b.isdigit():
        return abs(int(a) - int(b)) <= 4
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    tail_a, tail_b = a[i:], b[i:]
    if tail_a.isdigit() and tail_b.isdigit() and len(tail_a) == len(tail_b):
        return abs(int(tail_a) - int(tail_b)) <= 4
    return False


@register
class SessionIdQuality(Check):
    id = "mcp_transport_session_id_quality"
    title = "HTTP session IDs must be well-formed, non-guessable, and not used as auth"
    severity = Severity.MEDIUM
    grounding = Grounding.SPEC_INFERRED
    applies_to = ("http",)
    requires_live = True
    remediation = (
        "Generate session IDs with a CSPRNG (e.g. a securely generated UUIDv4), using "
        "only visible ASCII (0x21-0x7E). Never treat a session ID as authentication - "
        "verify a credential on every request, and bind the session to user identity "
        "derived from the token (e.g. <user_id>:<session_id>)."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        probe = snapshot.http if snapshot else None
        if probe is None:
            return CheckResult(Verdict.INFO, "endpoint could not be probed")
        sid = probe.session_id
        if not sid:
            return CheckResult(Verdict.NA, "server issues no MCP-Session-Id")
        issues = []
        if not all(0x21 <= ord(c) <= 0x7E for c in sid):
            issues.append("contains characters outside visible ASCII 0x21-0x7E (spec violation)")
        bits = _total_entropy_bits(sid)
        if bits < 64:
            issues.append(f"low estimated entropy (~{bits:.0f} bits over {len(sid)} chars)")
        if _looks_sequential(sid, probe.session_id_2 or ""):
            issues.append("successive session IDs look sequential/predictable")
        redacted = f"{sid[:4]}... ({len(sid)} chars)"
        if issues:
            return CheckResult(Verdict.FAIL, f"session ID {redacted}: " + "; ".join(issues))
        return CheckResult(Verdict.PASS, f"session ID {redacted} is visible-ASCII, high-entropy, and non-sequential")
