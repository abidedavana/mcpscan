"""Unit tests for the HTTP probe checks, driven by synthetic HttpProbe objects.

These cover the verdict branches (including the non-loopback FAIL path that a
loopback test server can't produce). End-to-end wiring is in test_http_probe.py.
"""

from mcpscan.checks.auth import PrmDiscoverable, TokenNotInUrl, UnauthenticatedInvocation
from mcpscan.checks.transport import OriginValidation, SessionIdQuality
from mcpscan.findings import Verdict
from mcpscan.mcpclient import HttpProbe, ServerSnapshot
from mcpscan.target import ScanTarget


def http(url="https://mcp.example.com/mcp", auth_expected=True):
    return ScanTarget(name="t", transport="http", url=url, auth_expected=auth_expected)


def snap(**probe_kwargs):
    return ServerSnapshot(http=HttpProbe(reachable=True, **probe_kwargs))


# --- mcp_auth_token_not_in_url (static) -------------------------------------

TOKEN = TokenNotInUrl()


def test_token_in_query_fails():
    r = TOKEN.run(http("https://mcp.example.com/mcp?access_token=sk-secret-value"))
    assert r.verdict is Verdict.FAIL
    assert "access_token" in r.evidence
    assert "sk-secret-value" not in r.evidence  # value not echoed


def test_session_in_query_fails():
    r = TOKEN.run(http("https://mcp.example.com/mcp?session=abc123"))
    assert r.verdict is Verdict.FAIL


def test_clean_url_passes():
    assert TOKEN.run(http("https://mcp.example.com/mcp?verbose=1")).verdict is Verdict.PASS


def test_token_check_is_static():
    assert TokenNotInUrl.requires_live is False


# --- mcp_auth_unauthenticated_invocation ------------------------------------

UNAUTH = UnauthenticatedInvocation()


def test_unauth_result_nonloopback_fails():
    r = UNAUTH.run(http(), snap(unauth_returned_result=True, endpoint_loopback=False))
    assert r.verdict is Verdict.FAIL


def test_unauth_result_loopback_is_info():
    r = UNAUTH.run(http(), snap(unauth_returned_result=True, endpoint_loopback=True))
    assert r.verdict is Verdict.INFO


def test_unauth_rejected_passes():
    assert UNAUTH.run(http(), snap(unauth_status=401)).verdict is Verdict.PASS
    assert UNAUTH.run(http(), snap(unauth_status=403)).verdict is Verdict.PASS


def test_unauth_declared_public_is_na():
    r = UNAUTH.run(http(auth_expected=False), snap(unauth_returned_result=True, endpoint_loopback=False))
    assert r.verdict is Verdict.NA


# --- mcp_auth_prm_discoverable ----------------------------------------------

PRM = PrmDiscoverable()


def test_prm_discovered_passes():
    r = PRM.run(http(), snap(unauth_status=401, prm_discovered=True, prm_authorization_servers=["https://auth.example.com"]))
    assert r.verdict is Verdict.PASS


def test_prm_missing_on_401_fails():
    r = PRM.run(http(), snap(unauth_status=401, prm_discovered=False))
    assert r.verdict is Verdict.FAIL


def test_prm_na_when_no_auth_challenge():
    assert PRM.run(http(), snap(unauth_status=200)).verdict is Verdict.NA


# --- mcp_transport_origin_validation ----------------------------------------

ORIGIN = OriginValidation()


def test_origin_200_fails():
    assert ORIGIN.run(http(), snap(foreign_origin_status=200)).verdict is Verdict.FAIL


def test_origin_403_passes():
    assert ORIGIN.run(http(), snap(foreign_origin_status=403)).verdict is Verdict.PASS


def test_origin_other_status_is_info():
    assert ORIGIN.run(http(), snap(foreign_origin_status=401)).verdict is Verdict.INFO


# --- mcp_transport_session_id_quality ---------------------------------------

SESSION = SessionIdQuality()


def test_good_session_id_passes():
    good = "f47ac10b58cc4372a5670e02b2c3d479"  # 32 hex chars, ~128 bits
    r = SESSION.run(http(), snap(session_id=good, session_id_2="9e107d9d372bb6826bd81d3542a419d6"))
    assert r.verdict is Verdict.PASS


def test_sequential_session_ids_fail():
    r = SESSION.run(http(), snap(session_id="1000", session_id_2="1001"))
    assert r.verdict is Verdict.FAIL
    assert "sequential" in r.evidence or "entropy" in r.evidence


def test_non_ascii_session_id_fails():
    r = SESSION.run(http(), snap(session_id="sess id value here xx"))
    assert r.verdict is Verdict.FAIL
    assert "visible ASCII" in r.evidence


def test_session_id_redacted():
    secret_sid = "f47ac10b58cc4372a5670e02b2c3d479"
    r = SESSION.run(http(), snap(session_id="1", session_id_2="2"))
    assert SESSION.run(http(), snap(session_id=secret_sid)).evidence.count(secret_sid) == 0


def test_no_session_id_is_na():
    assert SESSION.run(http(), snap(session_id=None)).verdict is Verdict.NA
