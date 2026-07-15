"""Minimal raw MCP client for live scans (stdio transport).

This is deliberately NOT built on the official ``mcp`` SDK, for two reasons
that matter to a scanner and not to a normal client:

* **We want to see the wire.** Check ``mcp_transport_stdio_stdout_clean``
  exists to catch servers that write banners/logs to stdout. An SDK client
  either crashes on or silently skips non-protocol output; this client
  *collects* it (``ServerSnapshot.stdout_noise``) as evidence.
* **Zero runtime dependencies** stays true: the whole client is subprocess +
  json + threading from the stdlib.

Scope: ``initialize`` → ``notifications/initialized`` → paginated
``tools/list``, then shut down. Nothing else is sent — a posture snapshot
must never invoke a tool. Server-initiated requests are not answered (none
are expected before the first tools/call, and we never issue one).

HTTP snapshots land with the probe engine (milestone 4); until then live
scans cover stdio targets only.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field

from . import SPEC_VERSION, __version__
from .target import ScanTarget

#: Overall budget for one request/response exchange, seconds.
DEFAULT_TIMEOUT = 15.0


class McpClientError(RuntimeError):
    """The server could not be launched, or the handshake failed."""


@dataclass
class ServerSnapshot:
    """Everything one non-invasive live pass observed about a server."""

    protocol_version: str | None = None
    server_info: dict = field(default_factory=dict)
    instructions: str | None = None
    capabilities: dict = field(default_factory=dict)
    tools: list[dict] = field(default_factory=list)
    #: Raw stdout lines that were not valid MCP messages (spec MUST NOT).
    stdout_noise: list[str] = field(default_factory=list)


class _LineReader:
    """Reads a pipe on a daemon thread so timeouts work on Windows pipes."""

    _EOF = object()

    def __init__(self, stream) -> None:
        self._q: queue.Queue = queue.Queue()
        t = threading.Thread(target=self._pump, args=(stream,), daemon=True)
        t.start()

    def _pump(self, stream) -> None:
        for line in stream:
            self._q.put(line)
        self._q.put(self._EOF)

    def readline(self, timeout: float) -> str | None:
        """Next line, or None on EOF. Raises McpClientError on timeout."""
        try:
            item = self._q.get(timeout=timeout)
        except queue.Empty:
            raise McpClientError(f"server produced no output for {timeout:.0f}s") from None
        return None if item is self._EOF else item


def _send(proc: subprocess.Popen, message: dict) -> None:
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()


def _read_response(reader: _LineReader, want_id: int, noise: list[str], deadline: float) -> dict:
    """Read lines until the response with ``want_id``; collect noise en route."""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise McpClientError(f"timed out waiting for response id={want_id}")
        line = reader.readline(timeout=remaining)
        if line is None:
            raise McpClientError(f"server closed stdout before responding to id={want_id}")
        stripped = line.rstrip("\r\n")
        if not stripped:
            continue
        try:
            msg = json.loads(stripped)
        except json.JSONDecodeError:
            noise.append(stripped)  # non-JSON on stdout: evidence, not an error
            continue
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            noise.append(stripped)
            continue
        if msg.get("id") == want_id:
            if "error" in msg:
                err = msg["error"]
                raise McpClientError(f"server returned JSON-RPC error {err.get('code')}: {err.get('message')}")
            return msg.get("result", {})
        # A notification or a message for another id: fine to ignore in a
        # snapshot pass (we only ever have one request in flight).


def snapshot_stdio(target: ScanTarget, timeout: float = DEFAULT_TIMEOUT) -> ServerSnapshot:
    """Launch the configured stdio server and take a posture snapshot."""
    if target.transport != "stdio" or not target.command:
        raise McpClientError(f"target {target.name!r} is not a stdio server")

    try:
        proc = subprocess.Popen(
            [target.command, *target.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # never read → never deadlock on a chatty server
            env={**os.environ, **target.env},
            text=True,
            encoding="utf-8",
        )
    except OSError as e:
        raise McpClientError(f"could not launch {target.command!r}: {e}") from None

    snap = ServerSnapshot()
    reader = _LineReader(proc.stdout)
    try:
        deadline = time.monotonic() + timeout
        _send(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": SPEC_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcpscan", "version": __version__},
            },
        })
        init = _read_response(reader, 1, snap.stdout_noise, deadline)
        snap.protocol_version = init.get("protocolVersion")
        snap.server_info = init.get("serverInfo") or {}
        snap.instructions = init.get("instructions")
        snap.capabilities = init.get("capabilities") or {}

        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        # tools/list, following pagination cursors until exhausted.
        cursor: str | None = None
        next_id = 2
        while True:
            deadline = time.monotonic() + timeout
            params = {"cursor": cursor} if cursor else {}
            _send(proc, {"jsonrpc": "2.0", "id": next_id, "method": "tools/list", "params": params})
            result = _read_response(reader, next_id, snap.stdout_noise, deadline)
            snap.tools.extend(t for t in result.get("tools", []) if isinstance(t, dict))
            cursor = result.get("nextCursor")
            next_id += 1
            if not cursor:
                break
        return snap
    except BrokenPipeError:
        raise McpClientError("server exited during the handshake") from None
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
