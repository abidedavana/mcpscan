"""A well-behaved stdio MCP server fixture — every live check should PASS.

Stdlib only, no SDK: reads newline-delimited JSON-RPC on stdin, answers
initialize + tools/list on stdout, and writes nothing else to stdout. Run as
``python clean_server.py``.
"""

import json
import sys

SERVER_INFO = {"name": "clean-fixture", "version": "1.0.0"}
INSTRUCTIONS = "A demo server. Configure credentials via the API_TOKEN environment variable."
CAPABILITIES = {"tools": {"listChanged": False}}

TOOLS = [
    {
        "name": "get_weather",
        "description": "Get current weather for a location.",
        "inputSchema": {
            "type": "object",
            "properties": {"location": {"type": "string", "maxLength": 100}},
            "required": ["location"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
    },
    {
        "name": "list_files",
        "description": "List files under a project-relative path.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "pattern": "^[A-Za-z0-9_/-]+$"}},
            "required": ["path"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "ping",
        "description": "Health check.",
        "inputSchema": {"type": "object", "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
]


def _respond(mid, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            _respond(mid, {
                "protocolVersion": "2025-11-25",
                "serverInfo": SERVER_INFO,
                "instructions": INSTRUCTIONS,
                "capabilities": CAPABILITIES,
            })
        elif method == "tools/list":
            _respond(mid, {"tools": TOOLS})
        elif method == "notifications/initialized":
            continue  # notification: no response
        elif mid is not None:
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
