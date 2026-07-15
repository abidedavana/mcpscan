"""Scan targets and the config loader.

mcpscan scans the same JSON config files MCP clients already use — the
de-facto standard ``{"mcpServers": {name: entry}}`` shape found in
``claude_desktop_config.json``, ``.mcp.json``, and most other hosts — so
``mcpscan scan --config claude_desktop_config.json`` works on real files
with no conversion step.

Each entry is either:

* **stdio** — has ``command`` (plus optional ``args`` / ``env``); the client
  launches the server as a subprocess, or
* **http** — has ``url``; the Streamable HTTP transport (SSE-style responses
  included).

Posture facts the standard config shape cannot express (is this server meant
to be local or remote? is unauthenticated access intentional? what interface
does it bind?) go in an ``x-mcpscan`` sub-object on the entry, which MCP
clients ignore:

    {
      "mcpServers": {
        "search": {
          "url": "http://127.0.0.1:9200/mcp",
          "x-mcpscan": {"scope": "local", "bind_host": "127.0.0.1"}
        }
      }
    }

* ``scope`` — ``"local"`` or ``"remote"``. Gates checks whose secure state
  differs for a laptop-local server vs a hosted service.
* ``auth_expected`` — set ``false`` to declare a deliberately public server
  and silence the unauthenticated-invocation check (see catalogue check 1).
* ``bind_host`` — the interface the server binds; used by the config half of
  the localhost-binding check until the runtime probe lands.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(ValueError):
    """Raised when a config file cannot be parsed into scan targets."""


@dataclass
class ScanTarget:
    """One configured MCP server, as mcpscan sees it."""

    name: str
    transport: str  # "stdio" | "http"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    # x-mcpscan posture declarations (all optional):
    scope: str | None = None  # "local" | "remote" | None (undeclared)
    auth_expected: bool = True
    bind_host: str | None = None


def _target_from_entry(name: str, entry: dict) -> ScanTarget:
    if not isinstance(entry, dict):
        raise ConfigError(f"server {name!r}: entry must be an object, got {type(entry).__name__}")

    has_command = bool(entry.get("command"))
    has_url = bool(entry.get("url"))
    if has_command and has_url:
        raise ConfigError(f"server {name!r}: entry declares both 'command' and 'url'; pick one transport")
    if not has_command and not has_url:
        raise ConfigError(f"server {name!r}: entry has neither 'command' (stdio) nor 'url' (http)")

    extra = entry.get("x-mcpscan", {})
    if not isinstance(extra, dict):
        raise ConfigError(f"server {name!r}: 'x-mcpscan' must be an object")
    scope = extra.get("scope")
    if scope not in (None, "local", "remote"):
        raise ConfigError(f"server {name!r}: x-mcpscan.scope must be 'local' or 'remote', got {scope!r}")

    return ScanTarget(
        name=name,
        transport="stdio" if has_command else "http",
        command=entry.get("command"),
        args=[str(a) for a in entry.get("args", [])],
        env={str(k): str(v) for k, v in entry.get("env", {}).items()},
        url=entry.get("url"),
        scope=scope,
        auth_expected=bool(extra.get("auth_expected", True)),
        bind_host=extra.get("bind_host"),
    )


def load_targets(path: str | Path) -> list[ScanTarget]:
    """Parse a client-style JSON config into scan targets.

    Accepts either the standard ``{"mcpServers": {...}}`` wrapper or a bare
    ``{name: entry}`` mapping whose entries look like server definitions.
    """
    # utf-8-sig: transparently strips a UTF-8 BOM if present (Windows editors
    # and PowerShell's Out-File add one) and reads plain UTF-8 unchanged.
    raw = Path(path).read_text(encoding="utf-8-sig")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: not valid JSON ({e})") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a JSON object")

    servers = data.get("mcpServers")
    if servers is None:
        # Bare-mapping form: every value must itself look like a server entry.
        if data and all(isinstance(v, dict) and ("command" in v or "url" in v) for v in data.values()):
            servers = data
        else:
            raise ConfigError(f"{path}: no 'mcpServers' key and top level is not a server mapping")
    if not isinstance(servers, dict) or not servers:
        raise ConfigError(f"{path}: 'mcpServers' must be a non-empty object")

    return [_target_from_entry(name, entry) for name, entry in servers.items()]
