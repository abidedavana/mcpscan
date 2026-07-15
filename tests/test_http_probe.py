"""End-to-end HTTP probe: spin up configurable in-process servers on loopback.

Exercises httpprobe.probe_http + the runner + the probe checks against three
fixtures: an open server, a secure (auth + Origin + PRM) server, and an
auth-server-with-no-PRM. Servers bind 127.0.0.1:0, so the unauthenticated
check reports INFO (loopback) rather than FAIL; the non-loopback FAIL path is
covered by the synthetic-probe unit tests in test_probe_checks.py.
"""

import json
import threading
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mcpscan.findings import Verdict
from mcpscan.httpprobe import probe_http
from mcpscan.runner import scan
from mcpscan.target import ScanTarget


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep test output quiet
        pass

    @property
    def cfg(self):
        return self.server.cfg

    def _send_json(self, status, obj, extra_headers=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            if self.cfg.get("serve_prm"):
                self._send_json(200, {
                    "resource": "https://mcp.example.com/mcp",
                    "authorization_servers": ["https://auth.example.com"],
                })
            else:
                self._send_json(404, {"error": "not found"})
            return
        self._send_json(405, {"error": "method not allowed"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        try:
            msg = json.loads(raw)
        except ValueError:
            msg = {}

        # Origin is validated on all incoming connections, before auth.
        if self.headers.get("Origin") and self.cfg.get("validate_origin"):
            self._send_json(403, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "bad origin"}})
            return

        if self.cfg.get("require_auth") and not self.headers.get("Authorization"):
            hdrs = {}
            if self.cfg.get("www_authenticate"):
                hdrs["WWW-Authenticate"] = self.cfg["www_authenticate"]
            self._send_json(401, {"jsonrpc": "2.0", "error": {"code": -32001, "message": "unauthorized"}}, hdrs)
            return

        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            hdrs = {}
            sid = self._next_session()
            if sid is not None:
                hdrs["MCP-Session-Id"] = sid
            self._send_json(200, {
                "jsonrpc": "2.0", "id": mid,
                "result": {"protocolVersion": "2025-11-25", "serverInfo": {"name": "http-fixture"}, "capabilities": {}},
            }, hdrs)
        elif method == "tools/list":
            self._send_json(200, {
                "jsonrpc": "2.0", "id": mid,
                "result": {"tools": [{"name": "ping", "description": "health", "inputSchema": {"type": "object"}}]},
            })
        elif method and method.startswith("notifications/"):
            self.send_response(202)
            self.end_headers()
        else:
            self._send_json(200, {"jsonrpc": "2.0", "id": mid, "result": {}})

    def _next_session(self):
        mode = self.cfg.get("session_mode", "uuid")
        if mode == "none":
            return None
        if mode == "sequential":
            self.server.counter += 1
            return str(self.server.counter)
        return uuid.uuid4().hex


@contextmanager
def http_fixture(**cfg):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.cfg = cfg
    srv.counter = 0
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    finally:
        srv.shutdown()
        srv.server_close()


def target_for(url):
    return ScanTarget(name="probe", transport="http", url=url)


def _by_id(findings):
    return {f.check_id: f for f in findings}


# --- probe engine ----------------------------------------------------------

def test_probe_open_server():
    with http_fixture(require_auth=False, validate_origin=False, session_mode="uuid") as url:
        snap = probe_http(target_for(url))
    assert snap.http.reachable
    assert snap.http.endpoint_loopback
    assert snap.http.unauth_returned_result          # anonymous tools/list worked
    assert snap.http.foreign_origin_status == 200     # origin not validated
    assert snap.http.session_id and snap.http.session_id_2
    assert [t["name"] for t in snap.tools] == ["ping"]  # tool list captured for the surface checks


def test_probe_secure_server():
    with http_fixture(require_auth=True, www_authenticate="Bearer", serve_prm=True, validate_origin=True) as url:
        snap = probe_http(target_for(url))
    assert snap.http.unauth_status == 401
    assert not snap.http.unauth_returned_result
    assert snap.http.prm_discovered                   # found via well-known fallback
    assert snap.http.prm_authorization_servers == ["https://auth.example.com"]
    assert snap.http.foreign_origin_status == 403


def test_probe_unreachable_raises():
    from mcpscan.mcpclient import McpClientError
    # Nothing listening on this port.
    with pytest.raises(McpClientError):
        probe_http(target_for("http://127.0.0.1:1/mcp"))


# --- full live scan --------------------------------------------------------

def test_open_server_live_scan_verdicts():
    with http_fixture(require_auth=False, validate_origin=False, session_mode="uuid") as url:
        findings = scan([target_for(url)], live=True)
    by_id = _by_id(findings)
    # Loopback softens unauth to INFO; origin is a hard FAIL.
    assert by_id["mcp_auth_unauthenticated_invocation"].verdict is Verdict.INFO
    assert by_id["mcp_transport_origin_validation"].verdict is Verdict.FAIL
    assert by_id["mcp_auth_prm_discoverable"].verdict is Verdict.NA  # no 401 challenge
    assert by_id["mcp_transport_session_id_quality"].verdict is Verdict.PASS
    # http snapshot also feeds the tool-surface checks
    assert by_id["mcp_schema_inputschema_valid"].verdict is Verdict.PASS


def test_secure_server_live_scan_verdicts():
    with http_fixture(require_auth=True, www_authenticate="Bearer", serve_prm=True, validate_origin=True) as url:
        findings = scan([target_for(url)], live=True)
    by_id = _by_id(findings)
    assert by_id["mcp_auth_unauthenticated_invocation"].verdict is Verdict.PASS
    assert by_id["mcp_auth_prm_discoverable"].verdict is Verdict.PASS
    assert by_id["mcp_transport_origin_validation"].verdict is Verdict.PASS


def test_auth_server_without_prm_fails_prm_check():
    with http_fixture(require_auth=True, www_authenticate="Bearer", serve_prm=False, validate_origin=True) as url:
        findings = scan([target_for(url)], live=True)
    assert _by_id(findings)["mcp_auth_prm_discoverable"].verdict is Verdict.FAIL


def test_sequential_session_ids_flagged_live():
    with http_fixture(require_auth=False, validate_origin=False, session_mode="sequential") as url:
        findings = scan([target_for(url)], live=True)
    assert _by_id(findings)["mcp_transport_session_id_quality"].verdict is Verdict.FAIL
