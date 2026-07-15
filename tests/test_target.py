"""Config loader: both accepted shapes, transport inference, x-mcpscan keys."""

import json
from pathlib import Path

import pytest

from mcpscan.target import ConfigError, load_targets

FIXTURES = Path(__file__).parent / "fixtures"


def write(tmp_path, data):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_loads_mcpservers_shape():
    targets = {t.name: t for t in load_targets(FIXTURES / "bad_config.json")}
    assert targets["files"].transport == "stdio"
    assert targets["files"].command == "npx"
    assert targets["files"].env["GITHUB_TOKEN"].startswith("ghp_")
    assert targets["search"].transport == "http"
    assert targets["search"].url.startswith("http://")


def test_loads_bare_mapping_shape(tmp_path):
    p = write(tmp_path, {"solo": {"url": "https://example.com/mcp"}})
    (target,) = load_targets(p)
    assert target.name == "solo"
    assert target.transport == "http"


def test_x_mcpscan_keys_parsed():
    targets = {t.name: t for t in load_targets(FIXTURES / "bad_config.json")}
    assert targets["search"].scope == "local"
    assert targets["search"].bind_host == "0.0.0.0"
    assert targets["search"].auth_expected is True  # default


def test_x_mcpscan_defaults():
    targets = {t.name: t for t in load_targets(FIXTURES / "good_config.json")}
    assert targets["files"].scope is None
    assert targets["files"].bind_host is None


def test_entry_with_both_transports_rejected(tmp_path):
    p = write(tmp_path, {"mcpServers": {"x": {"command": "npx", "url": "https://a/mcp"}}})
    with pytest.raises(ConfigError, match="both"):
        load_targets(p)


def test_entry_with_neither_transport_rejected(tmp_path):
    p = write(tmp_path, {"mcpServers": {"x": {"env": {"A": "b"}}}})
    with pytest.raises(ConfigError, match="neither"):
        load_targets(p)


def test_bad_scope_rejected(tmp_path):
    p = write(tmp_path, {"mcpServers": {"x": {"url": "https://a/mcp", "x-mcpscan": {"scope": "lan"}}}})
    with pytest.raises(ConfigError, match="scope"):
        load_targets(p)


def test_invalid_json_rejected(tmp_path):
    p = tmp_path / "config.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_targets(p)


def test_unrecognized_top_level_rejected(tmp_path):
    p = write(tmp_path, {"servers": {"x": {"url": "https://a/mcp"}}})
    with pytest.raises(ConfigError):
        load_targets(p)
