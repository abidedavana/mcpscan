"""End-to-end live scan: launch the fixture servers through the real client.

Exercises mcpclient (subprocess + handshake + tools/list) → runner (snapshot
capture + live gating) → the live checks, against the two fixture servers.
The command is the current Python interpreter; args point at the fixture.
"""

import sys
from pathlib import Path

import pytest

from mcpscan.findings import Verdict
from mcpscan.mcpclient import McpClientError, snapshot_stdio
from mcpscan.runner import scan
from mcpscan.target import ScanTarget

SERVERS = Path(__file__).parent / "fixtures" / "servers"


def target_for(script: str) -> ScanTarget:
    return ScanTarget(
        name=script.replace("_server.py", ""),
        transport="stdio",
        command=sys.executable,
        args=[str(SERVERS / script)],
    )


# --- the raw client ---------------------------------------------------------

def test_snapshot_reads_tools_and_metadata():
    snap = snapshot_stdio(target_for("clean_server.py"))
    assert snap.protocol_version == "2025-11-25"
    assert snap.server_info.get("name") == "clean-fixture"
    assert {t["name"] for t in snap.tools} == {"get_weather", "list_files", "ping"}
    assert snap.stdout_noise == []


def test_snapshot_collects_stdout_noise_from_messy_server():
    snap = snapshot_stdio(target_for("messy_server.py"))
    assert any("starting up" in line for line in snap.stdout_noise)
    assert len(snap.tools) == 4  # handshake still succeeds despite the banner


def test_snapshot_of_nonexistent_command_raises():
    with pytest.raises(McpClientError):
        snapshot_stdio(ScanTarget(name="x", transport="stdio", command="mcpscan-no-such-binary-xyz"))


# --- full live scan ---------------------------------------------------------

def _by_id(findings, server):
    return {f.check_id: f for f in findings if f.server == server}


def test_clean_server_live_scan_has_no_failures():
    findings = scan([target_for("clean_server.py")], live=True)
    fails = [f for f in findings if f.verdict is Verdict.FAIL]
    assert fails == [], [f"{f.check_id}: {f.evidence}" for f in fails]
    by_id = _by_id(findings, "clean")
    assert by_id["mcp_transport_stdio_stdout_clean"].verdict is Verdict.PASS
    assert by_id["mcp_schema_inputschema_valid"].verdict is Verdict.PASS
    assert by_id["mcp_secrets_not_in_tool_surface"].verdict is Verdict.PASS


def test_messy_server_live_scan_finds_every_live_issue():
    findings = scan([target_for("messy_server.py")], live=True)
    by_id = _by_id(findings, "messy")
    assert by_id["mcp_transport_stdio_stdout_clean"].verdict is Verdict.FAIL
    assert by_id["mcp_secrets_not_in_tool_surface"].verdict is Verdict.FAIL
    assert by_id["mcp_schema_inputschema_valid"].verdict is Verdict.FAIL
    assert by_id["mcp_tools_capability_annotation_consistency"].verdict is Verdict.FAIL
    assert by_id["mcp_schema_unconstrained_input_to_sink"].verdict is Verdict.INFO


def test_all_emitted_text_is_ascii():
    # Report output must survive Windows codepages; no em-dashes / smart quotes
    # in evidence or remediation. The messy server exercises most string paths.
    findings = scan([target_for("messy_server.py")], live=True)
    for f in findings:
        f.evidence.encode("ascii")
        f.remediation.encode("ascii")
        f.title.encode("ascii")


def test_live_checks_are_na_without_live_flag():
    findings = scan([target_for("clean_server.py")], live=False)
    by_id = _by_id(findings, "clean")
    assert by_id["mcp_schema_inputschema_valid"].verdict is Verdict.NA
    assert "--live" in by_id["mcp_schema_inputschema_valid"].evidence
    # static checks still run
    assert by_id["mcp_secrets_no_hardcoded_in_config"].verdict is Verdict.PASS
