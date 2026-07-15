"""Unit tests for the live checks, driven by hand-built ServerSnapshots."""

from mcpscan.checks.schemas import InputSchemaValid, UnconstrainedInputToSink
from mcpscan.checks.secrets import SecretsInToolSurface
from mcpscan.checks.toolscope import AnnotationConsistency
from mcpscan.checks.transport import StdioStdoutClean
from mcpscan.findings import Verdict
from mcpscan.mcpclient import ServerSnapshot
from mcpscan.target import ScanTarget

STDIO = ScanTarget(name="t", transport="stdio", command="x")


def snap(tools=None, instructions=None, server_info=None, stdout_noise=None):
    return ServerSnapshot(
        instructions=instructions,
        server_info=server_info or {},
        tools=tools or [],
        stdout_noise=stdout_noise or [],
    )


# --- mcp_schema_inputschema_valid -------------------------------------------

SCHEMA_CHECK = InputSchemaValid()


def test_string_inputschema_fails():
    r = SCHEMA_CHECK.run(STDIO, snap(tools=[{"name": "bad", "inputSchema": "nope"}]))
    assert r.verdict is Verdict.FAIL
    assert "bad" in r.evidence


def test_missing_inputschema_fails():
    r = SCHEMA_CHECK.run(STDIO, snap(tools=[{"name": "bad"}]))
    assert r.verdict is Verdict.FAIL
    assert "missing or null" in r.evidence


def test_non_object_root_type_fails():
    r = SCHEMA_CHECK.run(STDIO, snap(tools=[{"name": "bad", "inputSchema": {"type": "string"}}]))
    assert r.verdict is Verdict.FAIL


def test_valid_schema_passes():
    tools = [{"name": "ok", "inputSchema": {"type": "object", "properties": {"a": {"type": "string"}}}}]
    assert SCHEMA_CHECK.run(STDIO, snap(tools=tools)).verdict is Verdict.PASS


def test_no_tools_passes():
    assert SCHEMA_CHECK.run(STDIO, snap(tools=[])).verdict is Verdict.PASS


# --- mcp_schema_unconstrained_input_to_sink ---------------------------------

SINK_CHECK = UnconstrainedInputToSink()


def test_unconstrained_shell_param_is_info():
    tools = [{
        "name": "run_shell",
        "description": "Execute a shell command",
        "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}},
    }]
    r = SINK_CHECK.run(STDIO, snap(tools=tools))
    assert r.verdict is Verdict.INFO
    assert "command" in r.evidence


def test_constrained_sink_param_passes():
    tools = [{
        "name": "fetch_url",
        "description": "Fetch a URL",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string", "format": "uri"}}},
    }]
    r = SINK_CHECK.run(STDIO, snap(tools=tools))
    assert r.verdict is Verdict.PASS
    assert "constrain" in r.evidence


def test_non_sink_tool_passes():
    tools = [{"name": "get_weather", "description": "Weather", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}}]
    r = SINK_CHECK.run(STDIO, snap(tools=tools))
    assert r.verdict is Verdict.PASS
    assert "no sink-like tools" in r.evidence


# --- mcp_tools_capability_annotation_consistency ----------------------------

ANNOT_CHECK = AnnotationConsistency()


def test_dangerous_tool_without_annotations_fails():
    tools = [{"name": "run_shell", "description": "Execute a shell command", "inputSchema": {"type": "object"}}]
    r = ANNOT_CHECK.run(STDIO, snap(tools=tools))
    assert r.verdict is Verdict.FAIL
    assert "no annotations" in r.evidence


def test_destructive_tool_marked_nondestructive_fails():
    tools = [{
        "name": "delete_record", "description": "Delete a record",
        "inputSchema": {"type": "object"}, "annotations": {"destructiveHint": False},
    }]
    r = ANNOT_CHECK.run(STDIO, snap(tools=tools))
    assert r.verdict is Verdict.FAIL
    assert "destructiveHint:false" in r.evidence


def test_readonly_on_exec_tool_fails():
    tools = [{
        "name": "exec_task", "description": "Run a task",
        "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True},
    }]
    r = ANNOT_CHECK.run(STDIO, snap(tools=tools))
    assert r.verdict is Verdict.FAIL
    assert "readOnlyHint:true" in r.evidence


def test_weak_token_unannotated_is_info():
    tools = [{"name": "update_profile", "description": "Update a profile", "inputSchema": {"type": "object"}}]
    r = ANNOT_CHECK.run(STDIO, snap(tools=tools))
    assert r.verdict is Verdict.INFO


def test_consistent_annotations_pass():
    tools = [
        {"name": "get_weather", "description": "Weather", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}},
        {"name": "delete_record", "description": "Delete a record", "inputSchema": {"type": "object"}, "annotations": {"destructiveHint": True}},
    ]
    assert ANNOT_CHECK.run(STDIO, snap(tools=tools)).verdict is Verdict.PASS


# --- mcp_secrets_not_in_tool_surface ----------------------------------------

SURFACE_CHECK = SecretsInToolSurface()
GH_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def test_secret_in_instructions_fails():
    r = SURFACE_CHECK.run(STDIO, snap(instructions=f"Auth token is {GH_TOKEN}."))
    assert r.verdict is Verdict.FAIL
    assert "instructions" in r.evidence
    assert GH_TOKEN not in r.evidence  # redacted


def test_secret_in_schema_default_fails():
    tools = [{
        "name": "search", "description": "Search",
        "inputSchema": {"type": "object", "properties": {"key": {"type": "string", "default": GH_TOKEN}}},
    }]
    r = SURFACE_CHECK.run(STDIO, snap(tools=tools))
    assert r.verdict is Verdict.FAIL
    assert "inputSchema" in r.evidence


def test_clean_surface_passes():
    tools = [{"name": "ping", "description": "Health check", "inputSchema": {"type": "object"}}]
    r = SURFACE_CHECK.run(STDIO, snap(tools=tools, instructions="Use the API_TOKEN env var."))
    assert r.verdict is Verdict.PASS


# --- mcp_transport_stdio_stdout_clean ---------------------------------------

STDOUT_CHECK = StdioStdoutClean()


def test_stdout_noise_fails():
    r = STDOUT_CHECK.run(STDIO, snap(stdout_noise=["server starting...", "listening"]))
    assert r.verdict is Verdict.FAIL
    assert "2 non-protocol" in r.evidence


def test_clean_stdout_passes():
    assert STDOUT_CHECK.run(STDIO, snap(stdout_noise=[])).verdict is Verdict.PASS
