"""Category 1 — authentication.

* ``mcp_auth_token_not_in_url`` (static) — a credential or session identifier
  carried as a URL query parameter. Grounding: **spec+inferred**. "Access
  tokens MUST NOT be included in the URI query string" is a hard MUST NOT for
  tokens (basic/authorization); extending it to session IDs is inferred.

* ``mcp_auth_unauthenticated_invocation`` (probe) — a non-loopback HTTP
  endpoint that serves ``tools/list`` to an anonymous caller. Grounding:
  **inferred** (authorization is OPTIONAL in the spec; this is an operator
  posture check backed by the transports SHOULD and the Knostic exposure
  data). ``x-mcpscan.auth_expected=false`` declares a deliberately public
  server and turns this NA.

* ``mcp_auth_prm_discoverable`` (probe) — an auth-enforcing endpoint (401)
  that exposes no discoverable Protected Resource Metadata. Grounding:
  **spec** ("MCP servers MUST implement OAuth 2.0 Protected Resource
  Metadata"; the document MUST include authorization_servers; discoverable
  via WWW-Authenticate on 401 OR the well-known URI).
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from ..findings import Grounding, Severity, Verdict
from ..mcpclient import ServerSnapshot
from ..target import ScanTarget
from .base import Check, CheckResult, register

# Query-parameter names that should never carry a value in a URL.
_SENSITIVE_PARAMS = {
    "access_token", "token", "apikey", "api_key",
    "auth", "bearer", "session", "sid", "mcp-session-id",
}


@register
class TokenNotInUrl(Check):
    id = "mcp_auth_token_not_in_url"
    title = "Access tokens and session IDs must not travel in the URL"
    severity = Severity.HIGH
    grounding = Grounding.SPEC_INFERRED
    applies_to = ("http",)
    remediation = (
        "Carry access tokens only in the Authorization request header "
        "(Authorization: Bearer <token>). Move session identifiers into the "
        "MCP-Session-Id header, not the URL. Rotate any credential already exposed "
        "in a URL."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        parts = urlsplit(target.url or "")
        if not parts.scheme:
            return CheckResult(Verdict.INFO, f"endpoint URL {target.url!r} could not be parsed")
        hits = sorted({
            k for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k.lower() in _SENSITIVE_PARAMS and v
        })
        if hits:
            # Name the parameters, never echo their values.
            return CheckResult(
                Verdict.FAIL,
                f"credential/session parameter(s) in the endpoint URL query string: {', '.join(hits)}",
            )
        return CheckResult(Verdict.PASS, "no token- or session-bearing query parameters in the endpoint URL")


@register
class UnauthenticatedInvocation(Check):
    id = "mcp_auth_unauthenticated_invocation"
    title = "Networked HTTP server must not serve tool invocation without credentials"
    severity = Severity.CRITICAL
    grounding = Grounding.INFERRED
    applies_to = ("http",)
    requires_live = True
    remediation = (
        "Put an auth layer in front of the endpoint (an OAuth 2.1 resource server per "
        "the MCP authorization spec, or a gateway enforcing bearer tokens) and reject "
        "unauthenticated requests with 401. If the server is deliberately public, set "
        "x-mcpscan.auth_expected=false to acknowledge and silence this check."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        if not target.auth_expected:
            return CheckResult(Verdict.NA, "operator declared the server intentionally public (x-mcpscan.auth_expected=false)")
        probe = snapshot.http if snapshot else None
        if probe is None or not probe.reachable:
            return CheckResult(Verdict.INFO, "endpoint could not be probed for an unauthenticated response")
        if probe.unauth_returned_result:
            if probe.endpoint_loopback:
                return CheckResult(
                    Verdict.INFO,
                    "unauthenticated tools/list returned results, but the endpoint is loopback-only "
                    "(reachable to local processes only)",
                )
            return CheckResult(
                Verdict.FAIL,
                "unauthenticated tools/list returned a result: the endpoint serves its tool surface to any anonymous caller",
            )
        if probe.unauth_status in (401, 403):
            return CheckResult(Verdict.PASS, f"unauthenticated request rejected with HTTP {probe.unauth_status}")
        return CheckResult(
            Verdict.INFO,
            f"unauthenticated request returned HTTP {probe.unauth_status} without a tool result; verify the auth posture",
        )


@register
class PrmDiscoverable(Check):
    id = "mcp_auth_prm_discoverable"
    title = "Auth-enforcing server must expose discoverable Protected Resource Metadata"
    severity = Severity.MEDIUM
    grounding = Grounding.SPEC
    applies_to = ("http",)
    requires_live = True
    remediation = (
        "Serve an RFC 9728 Protected Resource Metadata document at "
        "/.well-known/oauth-protected-resource including at least one "
        "authorization_servers entry, and/or return a WWW-Authenticate header with "
        "resource_metadata on 401 responses."
    )

    def run(self, target: ScanTarget, snapshot: ServerSnapshot | None = None) -> CheckResult:
        probe = snapshot.http if snapshot else None
        if probe is None or not probe.reachable:
            return CheckResult(Verdict.INFO, "endpoint could not be probed")
        if probe.unauth_status != 401:
            return CheckResult(
                Verdict.NA,
                f"no auth challenge to advertise (unauthenticated request returned HTTP {probe.unauth_status}, not 401)",
            )
        if probe.prm_discovered and probe.prm_authorization_servers:
            return CheckResult(
                Verdict.PASS,
                f"Protected Resource Metadata is discoverable with {len(probe.prm_authorization_servers)} authorization server(s)",
            )
        return CheckResult(
            Verdict.FAIL,
            "returns 401 but exposes no discoverable Protected Resource Metadata "
            "(no WWW-Authenticate resource_metadata and no well-known document with authorization_servers)",
        )
