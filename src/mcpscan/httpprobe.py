"""HTTP probe engine for Streamable HTTP MCP endpoints.

``probe_http`` makes a small, bounded, observation-only set of requests to an
operator-supplied endpoint and records what it observes. It never sends a
credential and never issues ``tools/call``. The requests are:

  * an unauthenticated ``initialize`` + ``tools/list`` — does the endpoint
    hand its tool surface to an anonymous caller?
  * a second ``initialize`` — to compare issued session IDs;
  * an ``initialize`` carrying a foreign ``Origin`` header — is Origin
    validated?
  * GETs for RFC 9728 Protected Resource Metadata (from the
    ``WWW-Authenticate`` header, then the well-known URIs).

This mirrors the ethical boundary of published exposure studies: read what
the server volunteers, never trigger an action. Only run it against servers
you operate or are authorized to assess.

Stdlib only (urllib): the static scanner stays dependency-free.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from . import SPEC_VERSION, __version__
from .mcpclient import HttpProbe, McpClientError, ServerSnapshot
from .netutil import is_loopback_host

DEFAULT_TIMEOUT = 8.0
_MAX_BODY = 65536
_FOREIGN_ORIGIN = "http://mcpscan-probe.invalid"
_ACCEPT = "application/json, text/event-stream"


def _init_payload() -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": SPEC_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcpscan", "version": __version__},
        },
    }


def _request(url, *, method="POST", data=None, headers=None, timeout=DEFAULT_TIMEOUT):
    """Return (status, headers, body_bytes). 4xx/5xx come back as values, not exceptions.

    Raises urllib.error.URLError / OSError only on a genuine connection failure.
    """
    body = json.dumps(data).encode("utf-8") if data is not None else None
    hdrs = {"Accept": _ACCEPT, "Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read(_MAX_BODY)
    except urllib.error.HTTPError as e:
        try:
            payload = e.read(_MAX_BODY)
        except Exception:
            payload = b""
        return e.code, e.headers, payload


def _first_result(headers, body: bytes) -> dict | None:
    """The ``result`` object of the first JSON-RPC message in the body, else None.

    Handles both application/json (one object) and text/event-stream (scan
    ``data:`` lines) responses.
    """
    text = body.decode("utf-8", "replace")
    ctype = (headers.get("Content-Type") or "").lower()
    candidates: list[str] = []
    if "text/event-stream" in ctype:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                candidates.append(line[len("data:"):].strip())
    else:
        candidates.append(text)
    for c in candidates:
        try:
            obj = json.loads(c)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
            return obj["result"]
    return None


def _resource_metadata_url(www_authenticate: str | None) -> str | None:
    if not www_authenticate:
        return None
    m = re.search(r'resource_metadata="?([^",\s]+)"?', www_authenticate)
    return m.group(1) if m else None


def _well_known_candidates(url: str) -> list[str]:
    parts = urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}"
    path = parts.path.rstrip("/")
    candidates = []
    if path:
        candidates.append(f"{base}/.well-known/oauth-protected-resource{path}")
    candidates.append(f"{base}/.well-known/oauth-protected-resource")
    return candidates


def _fetch_authorization_servers(url: str, timeout: float) -> list | None:
    """Fetch a PRM document and return its authorization_servers, or None."""
    try:
        status, headers, body = _request(url, method="GET", timeout=timeout)
    except (urllib.error.URLError, OSError):
        return None
    if status != 200:
        return None
    try:
        doc = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, TypeError):
        return None
    if isinstance(doc, dict) and isinstance(doc.get("authorization_servers"), list):
        return doc["authorization_servers"]
    return None


def probe_http(target, timeout: float = DEFAULT_TIMEOUT) -> ServerSnapshot:
    """Take one observation-only HTTP snapshot of ``target``.

    Raises :class:`McpClientError` only if the endpoint cannot be reached at
    all; partial failures leave individual probe fields unset.
    """
    url = target.url
    if not url:
        raise McpClientError(f"target {target.name!r} has no url")
    host = urlsplit(url).hostname or ""
    probe = HttpProbe(endpoint_loopback=is_loopback_host(host))
    tools: list[dict] = []
    instructions = None
    server_info: dict = {}

    # 1. Unauthenticated initialize.
    try:
        status, headers, body = _request(url, data=_init_payload(), timeout=timeout)
    except (urllib.error.URLError, OSError) as e:
        raise McpClientError(f"could not reach {url}: {e}") from None
    probe.reachable = True
    probe.www_authenticate = headers.get("WWW-Authenticate")
    probe.session_id = headers.get("MCP-Session-Id")
    init_status = status
    init_result = _first_result(headers, body)
    if init_result:
        instructions = init_result.get("instructions")
        server_info = init_result.get("serverInfo") or {}

    # 2. Unauthenticated tools/list — only if initialize was accepted.
    if init_status == 200 and init_result is not None:
        sess = {"MCP-Session-Id": probe.session_id} if probe.session_id else {}
        try:
            _request(url, data={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=sess, timeout=timeout)
        except (urllib.error.URLError, OSError):
            pass
        try:
            ts, th, tb = _request(url, data={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, headers=sess, timeout=timeout)
            probe.unauth_status = ts
            result = _first_result(th, tb)
            if result is not None:
                probe.unauth_returned_result = True
                got = result.get("tools")
                if isinstance(got, list):
                    tools = [t for t in got if isinstance(t, dict)]
        except (urllib.error.URLError, OSError):
            probe.unauth_status = init_status
    else:
        probe.unauth_status = init_status

    # 3. Second initialize — for session-ID comparison.
    try:
        _, h2, _ = _request(url, data=_init_payload(), timeout=timeout)
        probe.session_id_2 = h2.get("MCP-Session-Id")
    except (urllib.error.URLError, OSError):
        pass

    # 4. Foreign-Origin initialize.
    try:
        os_status, _, _ = _request(url, data=_init_payload(), headers={"Origin": _FOREIGN_ORIGIN}, timeout=timeout)
        probe.foreign_origin_status = os_status
    except (urllib.error.URLError, OSError):
        pass

    # 5. PRM discovery — only when the endpoint issued a 401 auth challenge.
    if init_status == 401:
        servers = None
        rm = _resource_metadata_url(probe.www_authenticate)
        if rm:
            servers = _fetch_authorization_servers(rm, timeout)
        if not servers:
            for cand in _well_known_candidates(url):
                servers = _fetch_authorization_servers(cand, timeout)
                if servers:
                    break
        if servers:
            probe.prm_discovered = True
            probe.prm_authorization_servers = list(servers)

    return ServerSnapshot(
        instructions=instructions,
        server_info=server_info,
        tools=tools,
        http=probe,
    )
