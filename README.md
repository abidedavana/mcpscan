# mcpscan

Defensive posture scanner for MCP (Model Context Protocol) servers. Point it at the same
JSON config your MCP client already uses; it inspects each server for security
misconfigurations and reports PASS / FAIL / INFO / NA with the exact fix. Detection and
remediation only — no exploitation, no attack generation.

```
mcpscan scan --config claude_desktop_config.json          # static checks (no server launched)
mcpscan scan --config claude_desktop_config.json --live   # also launch stdio servers for the live checks
mcpscan scan --config .mcp.json --json                    # machine-readable, CI-friendly exit codes
mcpscan checks                                            # list the implemented checks
```

Exit codes: `0` clean, `1` at least one FAIL, `2` usage/config error. INFO findings never
fail the build — they are review flags, not verdicts.

**Static vs `--live`.** Without `--live`, mcpscan only reads the config — it never launches
anything. With `--live`, it launches each stdio server and takes one **observation-only**
snapshot (`initialize` + `tools/list`, never `tools/call`) to run the checks that need the
server's advertised tool surface. A posture scan never invokes a tool.

## Grounding honesty

Every check in the catalogue ([CHECKS-v0.1.md](CHECKS-v0.1.md)) carries a grounding tag,
and reports print it on every finding:

- **spec** — backed by a normative MUST/SHOULD in the MCP specification (revision
  2025-11-25; every claim verified against the live spec).
- **spec+inferred** / **inferred** — best practice grounded in advisories (CVE-2025-49596,
  the Knostic exposure study, Equixly's testing data) where the spec defines no
  conformance requirement. Never presented as a spec violation.

## Status

All 13 v0.1 checks implemented. **Static** checks read only the config. **Live** checks
need `--live`: for stdio, one `initialize` + `tools/list` snapshot; for HTTP, a small set
of observation-only requests (unauthenticated `initialize`/`tools/list`, an `initialize`
with a foreign `Origin` header, and RFC 9728 well-known GETs — never `tools/call`, never a
credential).

| Check | Severity | Grounding | Input |
|---|---|---|---|
| `mcp_auth_token_not_in_url` | high | spec+inferred | static |
| `mcp_secrets_no_hardcoded_in_config` | critical | spec+inferred | static |
| `mcp_transport_tls_remote_http` | medium | inferred | static |
| `mcp_transport_localhost_binding` (config half) | medium | spec | static |
| `mcp_secrets_not_in_tool_surface` | medium | inferred | live |
| `mcp_tools_capability_annotation_consistency` | high | inferred | live |
| `mcp_schema_inputschema_valid` | medium | spec | live |
| `mcp_schema_unconstrained_input_to_sink` | medium | inferred | live |
| `mcp_transport_stdio_stdout_clean` | low | spec | live (stdio) |
| `mcp_auth_unauthenticated_invocation` | critical | inferred | live (http) |
| `mcp_auth_prm_discoverable` | medium | spec | live (http) |
| `mcp_transport_origin_validation` | high | spec | live (http) |
| `mcp_transport_session_id_quality` | medium | spec+inferred | live (http) |

The full design, including checks deliberately excluded and the v0.2 growth path, is in
[CHECKS-v0.1.md](CHECKS-v0.1.md).

Runnable demo servers live under [tests/fixtures/servers/](tests/fixtures/servers/):
`clean_server.py` (passes every stdio live check) and `messy_server.py` (fails each one).
Point mcpscan at either with `--live`. HTTP probe behavior is exercised by in-process
fixtures in [tests/test_http_probe.py](tests/test_http_probe.py).

**HTTP `--live` makes real requests.** Only scan HTTP endpoints you operate or are
authorized to assess. The requests are non-invasive (read what the server volunteers), but
they are real network calls. One honesty note: if an HTTP server requires auth, mcpscan
can't retrieve its tool list without credentials, so the tool-surface / schema / annotation
checks report PASS ("no tools observed") rather than a true assessment for that server.

## Development

```
pip install -e .[dev]
pytest
```

Zero runtime dependencies by design: the static scanner reads JSON configs with the
stdlib only. The MCP client for live checks will land behind an optional extra.

## Declaring posture the config can't express

Standard `mcpServers` entries can't say whether a server is meant to be local or remote,
or whether unauthenticated access is intentional. Add an `x-mcpscan` object (MCP clients
ignore it):

```json
{
  "mcpServers": {
    "search": {
      "url": "http://127.0.0.1:9200/mcp",
      "x-mcpscan": { "scope": "local", "bind_host": "127.0.0.1" }
    }
  }
}
```

`scope` (`"local"`/`"remote"`), `bind_host` (interface the server binds), and
`auth_expected` (`false` declares a deliberately public server) gate the checks whose
secure state depends on intent.
