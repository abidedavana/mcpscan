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

Still to come (probe engine, milestone 4): Origin validation, session-ID
quality.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from ..findings import Grounding, Severity, Verdict
from ..mcpclient import ServerSnapshot
from ..target import ScanTarget
from .base import Check, CheckResult, register


def _is_loopback_host(host: str) -> bool:
    h = host.strip().lower().strip("[]")
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return h == "localhost" or h.endswith(".localhost")


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
