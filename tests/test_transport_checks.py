"""TLS and localhost-binding checks: every branch of the catalogue logic."""

from mcpscan.checks.transport import LocalhostBinding, TlsRemoteHttp
from mcpscan.findings import Verdict
from mcpscan.target import ScanTarget

TLS = TlsRemoteHttp()
BIND = LocalhostBinding()


def http(url="https://example.com/mcp", scope=None, bind_host=None):
    return ScanTarget(name="t", transport="http", url=url, scope=scope, bind_host=bind_host)


# --- mcp_transport_tls_remote_http -----------------------------------------

def test_tls_https_passes():
    assert TLS.run(http("https://mcp.example.com/mcp")).verdict is Verdict.PASS


def test_tls_plaintext_remote_fails():
    result = TLS.run(http("http://search.internal.example:8080/mcp"))
    assert result.verdict is Verdict.FAIL
    assert "search.internal.example" in result.evidence


def test_tls_plaintext_loopback_passes():
    assert TLS.run(http("http://127.0.0.1:9200/mcp")).verdict is Verdict.PASS
    assert TLS.run(http("http://localhost:9200/mcp")).verdict is Verdict.PASS
    assert TLS.run(http("http://[::1]:9200/mcp")).verdict is Verdict.PASS


def test_tls_unparseable_url_is_info():
    assert TLS.run(http("not a url")).verdict is Verdict.INFO


# --- mcp_transport_localhost_binding ----------------------------------------

def test_bind_loopback_passes():
    assert BIND.run(http(bind_host="127.0.0.1", scope="local")).verdict is Verdict.PASS
    assert BIND.run(http(bind_host="::1", scope="local")).verdict is Verdict.PASS


def test_bind_all_interfaces_local_fails():
    result = BIND.run(http("http://127.0.0.1:9200/mcp", scope="local", bind_host="0.0.0.0"))
    assert result.verdict is Verdict.FAIL
    assert "0.0.0.0" in result.evidence


def test_bind_local_inferred_from_loopback_url():
    # No declared scope, but the client reaches it via localhost → local.
    result = BIND.run(http("http://127.0.0.1:9200/mcp", bind_host="::"))
    assert result.verdict is Verdict.FAIL


def test_bind_declared_remote_is_na():
    assert BIND.run(http(scope="remote", bind_host="0.0.0.0")).verdict is Verdict.NA


def test_bind_undeclared_is_na():
    result = BIND.run(http(scope="local"))
    assert result.verdict is Verdict.NA
    assert "bind_host" in result.evidence


def test_bind_nonloopback_unknown_scope_is_info():
    result = BIND.run(http("https://mcp.example.com/mcp", bind_host="0.0.0.0"))
    assert result.verdict is Verdict.INFO
    assert "scope" in result.evidence
