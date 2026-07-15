"""mcp_secrets_no_hardcoded_in_config: signatures FAIL, entropy INFO, references PASS."""

from mcpscan.checks.secrets import SecretsInConfig
from mcpscan.findings import Verdict
from mcpscan.target import ScanTarget

CHECK = SecretsInConfig()

GH_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def stdio(env=None, args=None):
    return ScanTarget(name="t", transport="stdio", command="npx", env=env or {}, args=args or [])


def test_github_token_in_env_fails():
    result = CHECK.run(stdio(env={"GITHUB_TOKEN": GH_TOKEN}))
    assert result.verdict is Verdict.FAIL
    assert "env[GITHUB_TOKEN]" in result.evidence
    assert "GitHub token" in result.evidence


def test_evidence_is_redacted():
    result = CHECK.run(stdio(env={"GITHUB_TOKEN": GH_TOKEN}))
    assert GH_TOKEN not in result.evidence  # a scan report must never leak the secret


def test_aws_key_fails():
    result = CHECK.run(stdio(env={"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}))
    assert result.verdict is Verdict.FAIL
    assert "AWS access key ID" in result.evidence


def test_bearer_literal_fails():
    result = CHECK.run(stdio(env={"AUTH_HEADER": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}))
    assert result.verdict is Verdict.FAIL


def test_private_key_block_fails():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
    result = CHECK.run(stdio(env={"KEY": pem}))
    assert result.verdict is Verdict.FAIL


def test_secret_inside_arg_fails_with_argv_note():
    result = CHECK.run(stdio(args=["--api-key=sk-live-abcdefghijklmnop1234"]))
    assert result.verdict is Verdict.FAIL
    assert "args[0]" in result.evidence
    assert "process table" in result.evidence


def test_env_reference_forms_pass():
    env = {
        "A": "${GITHUB_TOKEN}",
        "B": "${GITHUB_TOKEN:-fallback}",
        "C": "$GITHUB_TOKEN",
        "D": "%GITHUB_TOKEN%",
        "E": "<your-token-here>",
        "F": "op://vault/item/token",
        "G": "vault://secret/data/mcp#token",
    }
    result = CHECK.run(stdio(env=env))
    assert result.verdict is Verdict.PASS


def test_high_entropy_unprefixed_value_is_info_not_fail():
    result = CHECK.run(stdio(env={"SEARCH_KEY": "q7Zt9rK2mXv4bLp8wNc3hJd6fGy5"}))
    assert result.verdict is Verdict.INFO
    assert "env[SEARCH_KEY]" in result.evidence


def test_npm_package_spec_in_args_passes():
    # Regression: "@example/files-server" clears the entropy bar (~3.55 bits/char)
    # but has no digits; package names must not flag as secrets.
    result = CHECK.run(stdio(args=["-y", "@example/files-server", "--verbose"]))
    assert result.verdict is Verdict.PASS


def test_ordinary_values_pass():
    env = {
        "PORT": "8080",
        "DEBUG": "false",
        "DATA_DIR": "C:\\Users\\abide\\data",
        "ENDPOINT": "https://api.example.com/v2/search?verbose=1",
        "GREETING": "hello world this is fine",
    }
    result = CHECK.run(stdio(env=env))
    assert result.verdict is Verdict.PASS


def test_applies_to_both_transports():
    assert CHECK.applies_to == ("stdio", "http")
    http_target = ScanTarget(name="h", transport="http", url="https://x/mcp", env={"K": GH_TOKEN})
    assert CHECK.run(http_target).verdict is Verdict.FAIL
