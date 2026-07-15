# mcpscan

Defensive posture scanner for MCP (Model Context Protocol) servers. Point it at the same
JSON config your MCP client already uses; it inspects each server for security
misconfigurations and reports PASS / FAIL / INFO / NA with the exact fix. Detection and
remediation only — no exploitation, no attack generation.

```
mcpscan scan --config claude_desktop_config.json
mcpscan scan --config .mcp.json --json     # machine-readable, CI-friendly exit codes
mcpscan checks                             # list the implemented checks
```

Exit codes: `0` clean, `1` at least one FAIL, `2` usage/config error. INFO findings never
fail the build — they are review flags, not verdicts.

## Grounding honesty

Every check in the catalogue ([CHECKS-v0.1.md](CHECKS-v0.1.md)) carries a grounding tag,
and reports print it on every finding:

- **spec** — backed by a normative MUST/SHOULD in the MCP specification (revision
  2025-11-25; every claim verified against the live spec).
- **spec+inferred** / **inferred** — best practice grounded in advisories (CVE-2025-49596,
  the Knostic exposure study, Equixly's testing data) where the spec defines no
  conformance requirement. Never presented as a spec violation.

## Status

v0.1 engine with the config-only checks implemented:

| Check | Severity | Grounding |
|---|---|---|
| `mcp_secrets_no_hardcoded_in_config` | critical | spec+inferred |
| `mcp_transport_tls_remote_http` | medium | inferred |
| `mcp_transport_localhost_binding` (config half) | medium | spec |

Next milestones: `tools/list` static checks (schemas, annotations, tool-surface secrets),
then the handshake/probe checks (unauthenticated invocation, Origin validation, session-ID
quality, stdio stdout hygiene). The full design, including checks deliberately excluded
and the v0.2 growth path, is in [CHECKS-v0.1.md](CHECKS-v0.1.md).

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
