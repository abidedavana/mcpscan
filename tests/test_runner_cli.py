"""End-to-end: runner NA handling, crash containment, CLI exit codes, JSON report."""

import json
from pathlib import Path

from mcpscan.checks.base import Check, CheckResult
from mcpscan.cli import main
from mcpscan.findings import Grounding, Severity, Verdict
from mcpscan.runner import scan
from mcpscan.target import ScanTarget, load_targets

FIXTURES = Path(__file__).parent / "fixtures"


def test_runner_emits_na_for_transport_mismatch():
    stdio_target = ScanTarget(name="s", transport="stdio", command="npx")
    findings = scan([stdio_target])
    by_id = {f.check_id: f for f in findings}
    assert by_id["mcp_transport_tls_remote_http"].verdict is Verdict.NA
    assert by_id["mcp_secrets_no_hardcoded_in_config"].verdict is Verdict.PASS


def test_runner_contains_check_crashes():
    class Exploding(Check):
        id = "test_exploding"
        title = "always crashes"
        severity = Severity.LOW
        grounding = Grounding.INFERRED
        applies_to = ("stdio", "http")
        remediation = "n/a"

        def run(self, target, snapshot=None):
            raise RuntimeError("boom")

    (finding,) = scan([ScanTarget(name="s", transport="stdio", command="npx")], checks=[Exploding()])
    assert finding.verdict is Verdict.INFO
    assert "internal error" in finding.evidence


def test_bad_config_scan_finds_expected_failures():
    findings = scan(load_targets(FIXTURES / "bad_config.json"))
    fails = {(f.server, f.check_id) for f in findings if f.verdict is Verdict.FAIL}
    assert ("files", "mcp_secrets_no_hardcoded_in_config") in fails
    assert ("search", "mcp_transport_tls_remote_http") in fails
    assert ("search", "mcp_transport_localhost_binding") in fails


def test_good_config_scan_is_clean():
    findings = scan(load_targets(FIXTURES / "good_config.json"))
    assert not [f for f in findings if f.verdict is Verdict.FAIL]


def test_cli_exit_1_on_fail_and_json_report(capsys):
    code = main(["scan", "--config", str(FIXTURES / "bad_config.json"), "--json"])
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["spec_version"] == "2025-11-25"
    assert doc["summary"]["FAIL"] >= 3
    check_ids = {f["check_id"] for f in doc["findings"]}
    assert "mcp_secrets_no_hardcoded_in_config" in check_ids


def test_cli_exit_0_on_clean_config(capsys):
    code = main(["scan", "--config", str(FIXTURES / "good_config.json")])
    assert code == 0
    out = capsys.readouterr().out
    assert "summary:" in out and "0 FAIL" in out


def test_cli_exit_2_on_missing_config(capsys):
    code = main(["scan", "--config", str(FIXTURES / "does_not_exist.json")])
    assert code == 2
    assert "mcpscan:" in capsys.readouterr().err


def test_cli_exit_2_on_unknown_server_filter(capsys):
    code = main(["scan", "--config", str(FIXTURES / "good_config.json"), "--server", "nope"])
    assert code == 2


def test_cli_server_filter_scopes_scan(capsys):
    # 'files' in bad_config has the secrets FAIL; 'search' has the transport FAILs.
    code = main(["scan", "--config", str(FIXTURES / "bad_config.json"), "--server", "files", "--json"])
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert {f["server"] for f in doc["findings"]} == {"files"}


def test_cli_checks_lists_catalogue(capsys):
    assert main(["checks"]) == 0
    out = capsys.readouterr().out
    assert "mcp_secrets_no_hardcoded_in_config" in out
    assert "grounding" in out
