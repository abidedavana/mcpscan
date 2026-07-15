"""A deliberately misconfigured stdio MCP server fixture.

Every live check has something to find here. This is a scan TARGET, not an
exploit — it only advertises a bad posture; it never acts on anything.

Findings this server is built to produce:
  * mcp_transport_stdio_stdout_clean          — writes a banner to stdout
  * mcp_secrets_not_in_tool_surface           — a token in the instructions
  * mcp_schema_inputschema_valid              — 'broken_tool' inputSchema is a string
  * mcp_schema_unconstrained_input_to_sink    — 'run_shell'/'fetch_url' free-form params
  * mcp_tools_capability_annotation_consistency — 'run_shell' unannotated,
                                                  'delete_record' destructiveHint:false

Stdlib only. Run as ``python messy_server.py``.
"""

import json
import sys

SERVER_INFO = {"name": "messy-fixture", "version": "0.1.0"}
# Spec MUST-NOT: a live credential baked into the advertised surface.
INSTRUCTIONS = "Internal tools. Auth is preconfigured with token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789."
CAPABILITIES = {"tools": {"listChanged": False}}

TOOLS = [
    {
        "name": "run_shell",
        "description": "Execute an arbitrary shell command on the host.",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},  # unconstrained sink param
            "required": ["command"],
        },
        # No annotations at all: clients fall back to spec defaults.
    },
    {
        "name": "fetch_url",
        "description": "Fetch the contents of a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},  # unconstrained sink param
            "required": ["url"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
    },
    {
        "name": "delete_record",
        "description": "Delete a record from the database by id.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string", "pattern": "^[0-9]+$"}},
            "required": ["id"],
        },
        "annotations": {"destructiveHint": False},  # contradicts a 'delete' tool
    },
    {
        "name": "broken_tool",
        "description": "Tool with a malformed input schema.",
        "inputSchema": "just a string, not a schema",  # spec violation
    },
]


def _respond(mid, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
    sys.stdout.flush()


def main():
    # Spec MUST-NOT: non-protocol output on stdout. A real server would log
    # this to stderr; emitting it on stdout is exactly what the check catches.
    sys.stdout.write("messy-fixture v0.1.0 starting up on stdout...\n")
    sys.stdout.flush()

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
            continue
        elif mid is not None:
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
