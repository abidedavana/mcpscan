# mcpscan — v0.1 Check Catalogue

Defensive posture scanner for operator-run / operator-authorized MCP servers.
Detection and remediation only. No exploitation, no payload generation.

> **Verification note (2026-07-15):** every normative spec claim in this document was
> checked against the live MCP specification, version **2025-11-25** (confirmed current
> at modelcontextprotocol.io/specification/versioning), pages: `basic/authorization`,
> `basic/transports`, `basic/security_best_practices`, `server/tools`, and the
> `schema/2025-11-25/schema.ts` source (annotation defaults, Tool.inputSchema).
> Advisory facts verified: Knostic exposure study (1,862 servers), Equixly stats
> (43% command injection / 30% SSRF / 22% path traversal), CVE-2025-49596
> (MCP Inspector: missing auth + 0.0.0.0 binding + DNS rebinding, CVSS 9.4).
> One correction was applied to v0.2 item 3 (see that item).

## Scan model (what the engine actually inspects)

Each check reaches a verdict from one or more of these inputs, gathered in a single
non-destructive pass:

- **config** — the server config the operator points mcpscan at: transport type, for
  stdio the `command` / `args` / `env`, for HTTP the endpoint `url` and any auth wiring.
- **handshake** — the `initialize` response (incl. `serverInfo`, `instructions`,
  `capabilities`) and, for HTTP, response headers + any `MCP-Session-Id`.
- **tools** — the `tools/list` result: each tool's `name`, `description`, `inputSchema`,
  `outputSchema`, `annotations`, `execution`.
- **probe** — benign observational requests only: one unauthenticated request, one
  request bearing a foreign `Origin` header, and inspection of an issued session ID.
  These are read-and-observe (status-code / header checks), the same class of request a
  conformance linter or Prowler makes — no crafted input, no exploit path.

`applies_to` on each check states whether it runs for `stdio`, `http`, or both. HTTP here
means the Streamable HTTP transport (SSE-style responses included).

## Verdicts

`PASS` / `FAIL` / `INFO` (finding needs operator judgement, e.g. a heuristic flag) /
`NA` (check doesn't apply to this transport or state, e.g. auth checks on an
intentionally public server).

## Grounding honesty

Every check is tagged `spec`, `spec+inferred`, or `inferred`.

- **spec** — backed by a normative MUST / MUST NOT / SHOULD in the 2025-11-25
  specification. Cited inline; all citations verified against the live pages.
- **inferred** — a defensible best-practice / advisory-backed check where the spec
  defines **no** conformance requirement. These are honest inferences, flagged as such so
  you never present them to an operator as spec violations.

Sources:
- Spec (2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization ·
  .../basic/transports · .../basic/security_best_practices · .../server/tools
- Knostic exposure study: https://www.knostic.ai/blog/mapping-mcp-servers-study
- Equixly MCP testing: https://equixly.com/blog/2025/03/29/mcp-server-new-security-nightmare/
- CVE-2025-49596: https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596
- OWASP MCP Top 10 (2025 beta), Trail of Bits MCP series (2025)

---

## Checks

```yaml
# ============================================================================
# CATEGORY 1 — AUTHENTICATION
# ============================================================================

- id: mcp_auth_unauthenticated_invocation
  title: Networked HTTP server must not serve tool invocation without credentials
  severity: critical
  severity_rationale: >
    An internet- or LAN-reachable server that answers tools/call with no credential
    hands every declared capability to any anonymous caller; this is the single most
    common real-world MCP failure (Knostic found ~1,862 servers reachable unauthenticated).
  applies_to: [http]
  detects: >
    A non-loopback HTTP MCP endpoint that processes tools/list or tools/call from a
    request carrying no Authorization header (or other configured credential).
  inputs: [config, probe]
  logic:
    na_when: "config.transport == stdio OR config.auth_expected == false (operator declares server intentionally public)"
    fail_when: "unauthenticated probe of tools/list OR tools/call returns HTTP 200 with a valid JSON-RPC result"
    pass_when: >
      unauthenticated probe returns HTTP 401 or 403. Note: 401 is the spec-aligned code
      for a missing/invalid token (authorization error-handling table); a 403 still
      demonstrates the endpoint is not open, so it passes with a conformance side-note.
    info_when: "endpoint bound to loopback only (127.0.0.1/::1) AND returns 200 — reachable only to local processes; report as reduced-severity INFO"
  remediation: >
    Put an auth layer in front of the endpoint (OAuth 2.1 resource server per the MCP
    authorization spec, or a gateway/reverse-proxy enforcing bearer tokens). Reject
    unauthenticated requests with 401. If the server is deliberately public, set
    auth_expected=false in the mcpscan config to acknowledge and silence this check.
  grounding: inferred
  grounding_note: >
    Authorization is OPTIONAL in the spec ("Authorization is OPTIONAL for MCP
    implementations", .../basic/authorization), so this is NOT a conformance failure.
    It is an operator-posture check backed by the spec's SHOULD ("Servers SHOULD
    implement proper authentication for all connections", .../basic/transports Security
    Warning), OWASP MCP07, and the Knostic exposure data. The auth_expected escape hatch
    keeps it honest.

- id: mcp_auth_prm_discoverable
  title: Auth-enforcing server must expose discoverable Protected Resource Metadata
  severity: medium
  severity_rationale: >
    Without RFC 9728 metadata a compliant client cannot discover the authorization
    server; auth may be enforced but is undiscoverable, breaking the standard client flow
    and pushing operators toward out-of-band token handling.
  applies_to: [http]
  detects: >
    An HTTP server that returns 401 (auth enforced) but exposes neither a WWW-Authenticate
    resource_metadata pointer nor a reachable Protected Resource Metadata document.
  inputs: [probe]
  logic:
    na_when: "unauthenticated probe returned 200 (no auth to advertise) OR transport == stdio"
    pass_when: >
      401 response carries WWW-Authenticate with a resource_metadata parameter,
      OR GET /.well-known/oauth-protected-resource (root or path-scoped) returns a JSON
      document whose authorization_servers array is non-empty
    fail_when: "server returns 401 but neither discovery mechanism yields valid PRM with a non-empty authorization_servers field"
  remediation: >
    Serve an RFC 9728 Protected Resource Metadata document at
    /.well-known/oauth-protected-resource including at least one authorization_servers
    entry, and/or return a WWW-Authenticate header with resource_metadata on 401 responses.
  grounding: spec
  grounding_note: >
    .../basic/authorization (verified): "MCP servers MUST implement OAuth 2.0 Protected
    Resource Metadata (RFC9728)"; the PRM document "MUST include the authorization_servers
    field containing at least one authorization server"; and "MCP servers MUST implement
    one of the following discovery mechanisms" — WWW-Authenticate on 401 OR the well-known
    URI (path-scoped or root). The pass logic reflects the spec's "one of two" allowance
    exactly, including the path-scoped well-known variant.

- id: mcp_auth_token_not_in_url
  title: Access tokens and session IDs must not travel in the URL
  severity: high
  severity_rationale: >
    Tokens in query strings leak into proxy logs, browser history, referrer headers, and
    server access logs; the spec forbids it outright for access tokens.
  applies_to: [http]
  detects: >
    A configured endpoint URL, or a session/redirect URL observed in the handshake, that
    carries an access token or session identifier as a query-string parameter.
  inputs: [config, handshake]
  logic:
    fail_when: >
      config.url OR any handshake-returned URL contains a query parameter matching
      (case-insensitively) {access_token, token, apikey, api_key, auth, bearer, session,
      sid, mcp-session-id} with a non-placeholder value
    pass_when: "no token- or session-bearing query parameters present in any inspected URL"
  remediation: >
    Carry access tokens only in the Authorization request header (Authorization: Bearer
    <token>). Move session identifiers into the MCP-Session-Id header, not the URL. Rotate
    any credential that has already been exposed in a URL.
  grounding: spec+inferred
  grounding_note: >
    "Access tokens MUST NOT be included in the URI query string" (.../basic/authorization,
    Access Token Usage — verified verbatim) is a hard MUST NOT — spec-grounded for tokens.
    Extending the same rule to session IDs is inferred (Equixly flagged session-IDs-in-URLs
    as an anti-pattern); the spec places session IDs in the MCP-Session-Id header but does
    not explicitly forbid the query string.

# ============================================================================
# CATEGORY 2 — SECRETS EXPOSURE
# ============================================================================

- id: mcp_secrets_no_hardcoded_in_config
  title: No literal credentials hardcoded in server config
  severity: critical
  severity_rationale: >
    A plaintext key in a config that is committed, synced, or world-readable is a direct
    credential compromise; Trail of Bits found this endemic across shipped MCP servers.
  applies_to: [stdio, http]
  detects: >
    A literal secret value (not a ${VAR} reference or secret-manager handle) in a config
    env value or command-line argument. Argv placement is called out as worse — argv is
    visible to any local process via the process table.
  inputs: [config]
  logic:
    fail_when: >
      any config.env value OR config.args element matches a secret signature —
      known-prefix patterns (sk-, ghp_, gho_, xoxb-, AKIA, AIza, -----BEGIN * PRIVATE KEY-----),
      Authorization: Bearer <literal>, or a high-entropy string (>= ~3.5 bits/char over
      >= 20 chars) that is not a recognizable ${VAR}/$ENV reference or vault URI
    pass_when: "all credential-shaped fields are references (${VAR}, env indirection, secret-manager URIs) or absent"
    info_when: "a secret-shaped value appears only in config.args (report as high-confidence, note argv exposure)"
  remediation: >
    Replace literal secrets with environment-variable references resolved at launch, or a
    secret manager / OS keychain. For stdio servers pass credentials via env, never as
    command-line arguments (argv is readable by other local users via ps / /proc). Rotate
    any secret that was stored in plaintext.
  grounding: spec+inferred
  grounding_note: >
    The spec makes secure token storage a MUST by reference ("Clients and servers MUST
    implement secure token storage and follow OAuth best practices", .../basic/authorization
    Token Theft — verified) but defines no storage mechanics — so the specific "no plaintext
    in config" rule is inferred (Trail of Bits, OWASP MCP01). The env-over-argv preference
    is spec-informed: "Implementations using an STDIO transport SHOULD NOT follow this
    specification, and instead retrieve credentials from the environment"
    (.../basic/authorization, Protocol Requirements — verified verbatim).

- id: mcp_secrets_not_in_tool_surface
  title: No secrets exposed in tool definitions, schemas, or server instructions
  severity: medium
  severity_rationale: >
    Secrets embedded in tool descriptions, schema defaults, or the server instructions
    field are shipped to every connecting client and into the model context, widening
    exposure well beyond the server host.
  applies_to: [stdio, http]
  detects: >
    A secret-shaped value in any tool description, any inputSchema/outputSchema default or
    example, or the initialize `instructions` / `serverInfo` fields.
  inputs: [handshake, tools]
  logic:
    fail_when: >
      any tool.description, inputSchema.default, schema example, or initialize.instructions
      matches the secret signature set from mcp_secrets_no_hardcoded_in_config
    pass_when: "no secret-shaped values in any tool-facing or handshake-facing string"
  remediation: >
    Strip credentials from tool descriptions and schema defaults; supply secrets to the
    server at runtime via env/secret manager, never inline in metadata the server
    advertises. Rotate any exposed secret.
  grounding: inferred
  grounding_note: >
    No spec requirement; inferred from Trail of Bits credential-storage findings and
    OWASP MCP01. Distinct from runtime-traffic secret scanners (mcp-scan proxy, Docker
    --block-secrets) — this is a static scan of the advertised surface.

# ============================================================================
# CATEGORY 3 — TOOL PERMISSION SCOPE
# ============================================================================

- id: mcp_tools_capability_annotation_consistency
  title: Dangerous-capability tools must carry accurate behavior annotations
  severity: high
  severity_rationale: >
    Hosts gate tool calls off annotations; a shell/write/egress tool that omits them
    inherits the operator's intent by accident, and one mislabeled readOnlyHint:true lets
    a mutating tool bypass a host's confirmation prompts.
  applies_to: [stdio, http]
  detects: >
    Two conditions. (a) A tool whose name/description matches the dangerous-capability
    lexicon but declares no annotations — so clients fall back to spec defaults.
    (b) An annotation that contradicts the apparent capability, e.g. readOnlyHint:true on
    a tool named/described as writing, deleting, executing, or fetching.
  inputs: [tools]
  logic:
    fail_when: >
      tool.name+description matches lexicon {exec, shell, command, run, spawn, eval,
      write, delete, remove, drop, truncate, update, upload, put, post, fetch, request,
      curl, http, sql, query} AND
      ( annotations absent
        OR annotations.readOnlyHint == true
        OR (destructive-verb match AND annotations.destructiveHint == false) )
    pass_when: "dangerous-lexicon tools declare annotations consistent with their apparent capability; non-dangerous tools unaffected"
    info_when: "tool matches lexicon weakly (single generic term like 'update') — surface as INFO for operator confirmation"
  remediation: >
    Add annotations that truthfully describe each tool: readOnlyHint:true only for tools
    with no side effects; destructiveHint:true for tools that delete/overwrite;
    openWorldHint:true for tools that reach external systems. Recall the spec defaults for
    an unannotated tool are destructiveHint:true, openWorldHint:true, readOnlyHint:false,
    idempotentHint:false — declare explicitly rather than relying on them.
  grounding: inferred
  grounding_note: >
    Annotations are OPTIONAL in the spec (schema: annotations?: ToolAnnotations), and
    "clients MUST consider tool annotations to be untrusted unless they come from trusted
    servers" (.../server/tools — verified verbatim) — so this is not a conformance check.
    It is a posture check for the operator's OWN (trusted) server, where accurate
    annotations are what let downstream hosts gate correctly. The mismatch half is
    near-unclaimed prior art (only Cisco's behavior-vs-description detector is comparable).
    Heuristic: emit findings for review, not as authoritative verdicts. Spec defaults
    verified against schema/2025-11-25/schema.ts doc comments: readOnlyHint false,
    destructiveHint true, idempotentHint false, openWorldHint true.

# ============================================================================
# CATEGORY 4 — INJECTION-PRONE TOOL SCHEMAS
# ============================================================================

- id: mcp_schema_inputschema_valid
  title: Every tool must declare a valid object inputSchema
  severity: medium
  severity_rationale: >
    A missing or malformed inputSchema means the client and host have no contract to
    validate arguments against, so every argument reaches the tool unvalidated; it is also
    a straight spec-conformance failure.
  applies_to: [stdio, http]
  detects: >
    A tool whose inputSchema is absent, null, not a JSON object, or whose root is not
    type:"object".
  inputs: [tools]
  logic:
    fail_when: "tool.inputSchema is missing OR null OR not an object OR inputSchema.type != 'object' OR inputSchema fails JSON Schema (2020-12) validation"
    pass_when: "inputSchema present, an object with type:'object', and schema-valid"
  remediation: >
    Give every tool a valid JSON Schema inputSchema with root type:"object". For a
    zero-argument tool use {"type":"object","additionalProperties":false} (the spec's
    recommended form).
  grounding: spec
  grounding_note: >
    .../server/tools (verified): inputSchema "MUST be a valid JSON Schema object (not
    null)", "Defaults to 2020-12 if no $schema field is present", and the no-parameter
    recommendation is quoted from the spec. schema.ts confirms inputSchema is a required
    property of Tool with type: "object" at the root. Fully spec-grounded conformance
    check.

- id: mcp_schema_unconstrained_input_to_sink
  title: Sink-bound tool parameters should constrain untrusted input
  severity: medium
  severity_rationale: >
    Real MCP servers show high rates of command injection (~43%), SSRF (~30%), and path
    traversal (~22%) per Equixly; an unconstrained free-form string flowing to a shell,
    URL, path, or SQL sink is where those land. Flag-for-review, not an exploit test.
  applies_to: [stdio, http]
  detects: >
    A tool whose name/description indicates a sensitive sink (command execution, URL fetch,
    file path, SQL) exposing a string parameter with no constraint — no enum, pattern,
    format, or maxLength — i.e. arbitrary free-form input reaches the sink by schema.
  inputs: [tools]
  logic:
    info_when: >
      tool matches sink lexicon {exec/shell/command/run, fetch/http/url/request,
      path/file/read/write, sql/query/db} AND has >=1 string property lacking all of
      {enum, pattern, format, maxLength, const}
    pass_when: "sink-matched tools constrain their string parameters (enum / pattern / format / bounded length), or no sink-matched tools present"
  remediation: >
    Constrain the parameter at the schema boundary: enum for fixed choices, pattern/format
    for structured values (uri, email, hostname), maxLength to bound size. Then enforce
    server-side too — parameterize SQL, use allowlists for hosts/paths, avoid passing input
    to a shell. Schema constraints are advisory to clients; server-side validation is the
    real control.
  grounding: inferred
  grounding_note: >
    The spec says servers MUST "Validate all tool inputs" (.../server/tools Security
    Considerations — verified) but defines no schema-shape requirement, so the specific
    "constrain sink-bound strings" rule is inferred (Equixly data, OWASP MCP05).
    Intentionally INFO/review severity — the scanner flags a schema shape for the operator
    to harden; it does not attempt or confirm injection.

# ============================================================================
# CATEGORY 5 — TRANSPORT SECURITY
# ============================================================================

- id: mcp_transport_origin_validation
  title: HTTP server must validate the Origin header
  severity: high
  severity_rationale: >
    Missing Origin validation is the DNS-rebinding hole that lets a remote web page drive a
    victim's local MCP server; it is a spec MUST and the class behind CVE-2025-49596.
  applies_to: [http]
  detects: >
    A Streamable HTTP server that processes a request bearing a foreign/bogus Origin header
    instead of rejecting it.
  inputs: [probe]
  logic:
    fail_when: "a request with Origin set to a foreign value (e.g. http://attacker.example) is processed normally (HTTP 200)"
    pass_when: "server rejects the invalid Origin with HTTP 403"
    na_when: "transport == stdio"
  remediation: >
    Validate the Origin header on every incoming connection against an allowlist of
    expected origins; respond 403 to a present-but-invalid Origin. This is the primary
    DNS-rebinding defense for local HTTP servers.
  grounding: spec
  grounding_note: >
    .../basic/transports Security Warning (verified verbatim): "Servers MUST validate the
    Origin header on all incoming connections to prevent DNS rebinding attacks" and "If
    the Origin header is present and invalid, servers MUST respond with HTTP 403
    Forbidden." The probe is a benign header observation, not an exploit.

- id: mcp_transport_localhost_binding
  title: Local HTTP server should bind to loopback, not all interfaces
  severity: medium
  severity_rationale: >
    Binding a local server to 0.0.0.0 exposes it to the whole network; combined with weak
    or absent auth this is exactly the CVE-2025-49596 exposure.
  applies_to: [http]
  detects: >
    A server intended to run locally whose configured bind address is 0.0.0.0, ::, or a
    non-loopback interface.
  inputs: [config]
  logic:
    fail_when: "config bind host in {0.0.0.0, ::, a specific non-loopback IP} AND server is declared/inferred local (config.scope == local OR endpoint host is localhost-family in the client URL)"
    pass_when: "bind host is 127.0.0.1 or ::1"
    na_when: "server is a declared remote/hosted service (config.scope == remote) where a routable bind is intended and fronted by auth + TLS"
  remediation: >
    Bind local servers to 127.0.0.1 (or ::1) so only local processes can reach them. If the
    server must be network-reachable, treat it as remote: require authentication and TLS,
    and restrict source addresses.
  grounding: spec
  grounding_note: >
    .../basic/transports Security Warning (verified verbatim): "When running locally,
    servers SHOULD bind only to localhost (127.0.0.1) rather than all network interfaces
    (0.0.0.0)." SHOULD-level; the scope gate avoids false positives on genuinely remote
    servers.

- id: mcp_transport_tls_remote_http
  title: Remote HTTP endpoint should use TLS
  severity: medium
  severity_rationale: >
    A non-loopback MCP endpoint over plaintext http:// exposes tokens, tool arguments, and
    results to network interception.
  applies_to: [http]
  detects: >
    A configured endpoint whose scheme is http:// and whose host is not loopback.
  inputs: [config]
  logic:
    fail_when: "config.url scheme == http AND host not in {localhost, 127.0.0.0/8, ::1}"
    pass_when: "scheme == https, OR host is loopback (plaintext acceptable for local-only)"
  remediation: >
    Serve the MCP endpoint over HTTPS with a valid certificate; redirect or refuse
    plaintext http on non-loopback hosts.
  grounding: inferred
  grounding_note: >
    IMPORTANT — this is NOT spec-conformance, and this was re-verified against the live
    2025-11-25 pages: the spec mandates HTTPS only for OAuth authorization-server
    endpoints and redirect URIs ("All authorization server endpoints MUST be served over
    HTTPS. All redirect URIs MUST be either localhost or use HTTPS.",
    .../basic/authorization Communication Security). The transports page contains no TLS
    requirement for the MCP endpoint itself (examples merely use https). The nearest spec
    language is client-side: MCP clients "SHOULD require HTTPS for all OAuth-related URLs"
    (.../basic/security_best_practices, SSRF mitigation). Present this check to operators
    as a hardening recommendation, never as a spec MUST.

- id: mcp_transport_stdio_stdout_clean
  title: stdio server must emit only protocol messages on stdout
  severity: low
  severity_rationale: >
    Non-protocol output on stdout corrupts the JSON-RPC stream and can leak diagnostic
    info (paths, tokens, internal state) into the channel; it is a spec MUST NOT.
  applies_to: [stdio]
  detects: >
    A stdio server that writes banners, logs, or other non-MCP content to stdout during the
    handshake.
  inputs: [handshake]
  logic:
    fail_when: "during initialize, any line received on the server's stdout is not a valid newline-delimited JSON-RPC MCP message (or contains an embedded newline within a framed message)"
    pass_when: "stdout carries only valid MCP messages; diagnostic output, if any, appears on stderr"
  remediation: >
    Route all logging and diagnostics to stderr (which the spec permits for logging); keep
    stdout exclusively for newline-delimited MCP messages with no embedded newlines.
  grounding: spec
  grounding_note: >
    .../basic/transports stdio section (verified verbatim): "The server MUST NOT write
    anything to its stdout that is not a valid MCP message"; messages "MUST NOT contain
    embedded newlines"; "The server MAY write UTF-8 strings to its standard error (stderr)
    for any logging purposes". Directly observable while mcpscan drives the handshake.

- id: mcp_transport_session_id_quality
  title: HTTP session IDs must be well-formed, non-guessable, and not used as auth
  severity: medium
  severity_rationale: >
    Predictable or auth-bearing session IDs enable session hijacking; the spec sets a hard
    charset requirement and forbids treating sessions as authentication.
  applies_to: [http]
  detects: >
    An issued MCP-Session-Id that contains characters outside the allowed range, is short
    or low-entropy / sequential, or that the server accepts as sufficient authentication.
  inputs: [handshake, probe]
  logic:
    fail_when: >
      MCP-Session-Id contains any character outside 0x21-0x7E (spec violation),
      OR two successive initialize calls yield sequential / trivially-incrementing IDs,
      OR estimated entropy < ~64 bits over the identifier,
      OR a request bearing only a valid session ID and no credential is accepted as
      authenticated on an otherwise auth-enforcing server
    pass_when: "session ID is visible-ASCII, high-entropy, non-sequential, and not accepted in lieu of authentication"
    na_when: "server issues no MCP-Session-Id"
  remediation: >
    Generate session IDs with a CSPRNG (e.g. a securely generated UUIDv4), using only
    visible ASCII (0x21-0x7E). Never treat a session ID as authentication — verify a
    credential on every request; bind the session to user identity derived from the token
    (e.g. <user_id>:<session_id>), not to client-supplied data.
  grounding: spec+inferred
  grounding_note: >
    Spec-grounded (all verified verbatim): the session ID "MUST only contain visible ASCII
    characters (ranging from 0x21 to 0x7E)" and "SHOULD be globally unique and
    cryptographically secure" (.../basic/transports Session Management); "MCP Servers MUST
    NOT use sessions for authentication", "MCP servers MUST use secure, non-deterministic
    session IDs", generated IDs "SHOULD use secure random number generators", and servers
    "SHOULD bind session IDs to user-specific information" using a key format like
    <user_id>:<session_id> (.../basic/security_best_practices Session Hijacking).
    Inferred: the specific ~64-bit entropy threshold and the sequential-ID heuristic (the
    spec sets no numeric bar). Note the header is spelled MCP-Session-Id in 2025-11-25
    (Mcp-Session-Id in older revisions); match it case-insensitively per HTTP semantics.
```

---

## Coverage & grounding summary

| # | Check ID | Category | Severity | Grounding |
|---|----------|----------|----------|-----------|
| 1 | mcp_auth_unauthenticated_invocation | Authentication | critical | inferred (spec SHOULD + advisory) |
| 2 | mcp_auth_prm_discoverable | Authentication | medium | spec (MUST) |
| 3 | mcp_auth_token_not_in_url | Authentication | high | spec+inferred (MUST NOT for tokens) |
| 4 | mcp_secrets_no_hardcoded_in_config | Secrets | critical | spec+inferred |
| 5 | mcp_secrets_not_in_tool_surface | Secrets | medium | inferred |
| 6 | mcp_tools_capability_annotation_consistency | Tool scope | high | inferred |
| 7 | mcp_schema_inputschema_valid | Injection-prone schemas | medium | spec (MUST) |
| 8 | mcp_schema_unconstrained_input_to_sink | Injection-prone schemas | medium (INFO/review) | inferred |
| 9 | mcp_transport_origin_validation | Transport | high | spec (MUST) |
| 10 | mcp_transport_localhost_binding | Transport | medium | spec (SHOULD) |
| 11 | mcp_transport_tls_remote_http | Transport | medium | inferred (spec silent — flagged) |
| 12 | mcp_transport_stdio_stdout_clean | Transport | low | spec (MUST NOT) |
| 13 | mcp_transport_session_id_quality | Transport | medium | spec+inferred |

Eight checks (2, 3-partial, 4-partial, 7, 9, 10, 12, 13-partial) rest on a normative spec
clause. Five (1, 5, 6, 8, 11) are honest best-practice inferences with no spec-defined
secure state — each carries a note saying so.

## Categories deliberately left without a v0.1 check

Per the "don't invent a check where there's no definable secure state" rule:

- **Rate limiting** — the tools page makes "Rate limit tool invocations" a bare MUST
  (verified: Security Considerations lists "Validate all tool inputs / Implement proper
  access controls / Rate limit tool invocations / Sanitize tool outputs") with zero
  observable parameters — no threshold, algorithm, or externally visible behavior. There
  is nothing a static+handshake scan can assert a PASS/FAIL against. Left out.
- **Prompt-injection / tool-poisoning detection** — deliberately excluded from v0.1. It is
  the most crowded space (mcp-scan, Cisco, eSentire, Trail of Bits all cover it) and the
  spec defines no secure state, only that annotations/descriptions are untrusted. mcpscan
  differentiates on server-side posture instead; revisit only if you want to compete there.
- **Audit/telemetry posture (OWASP MCP08)** — no spec requirement beyond a client SHOULD
  ("Log tool usage for audit purposes" is client guidance), and not observable from the
  handshake. Candidate for a config-declared check later.

---

## v0.2 growth path (design targets, not yet built)

1. **mcp_auth_token_audience_validation** — probe whether the server rejects a token minted
   for a different audience/resource (RFC 8707). Strongly spec-grounded (verified: "MCP
   servers MUST validate that access tokens were issued specifically for them as the
   intended audience"; "MCP servers MUST NOT accept or transit any other tokens"; token
   passthrough is a MUST NOT in security_best_practices), but it needs a token oracle —
   two valid tokens or a mintable test token — which is why it's v0.2, not v0.1. High
   value: this is the confused-deputy / passthrough class.

2. **mcp_tools_definition_pinning** — trust-on-first-use hash of each tool's
   name+description+schema, with drift detection on re-scan ("rug pull" detection). Cheap
   to add and complements the static checks; note it overlaps mcp-scan/mcp-context-protector,
   so position it as continuity for operators already in mcpscan rather than a differentiator.

3. **mcp_transport_protocol_version_enforced** — verify the server returns HTTP 400 for an
   **invalid or unsupported** MCP-Protocol-Version header value. Spec-grounded (verified:
   "If the server receives a request with an invalid or unsupported MCP-Protocol-Version,
   it MUST respond with 400 Bad Request"). CORRECTED from the draft: an **absent** header
   is NOT a 400 — the spec says the server "SHOULD assume protocol version 2025-03-26"
   for backwards compatibility, so only bad values are a conformance failure.

4. **mcp_tools_output_schema_conformance** — when a tool declares outputSchema, drive one
   benign call and validate the structured result against it (verified: "Servers MUST
   provide structured results that conform to this schema"). Requires safe invocation of
   read-only tools, so it lands after the annotation-consistency check can identify which
   tools are safe to call.

5. **mcp_multitenant_isolation** — for multi-tenant HTTP servers, probe whether a resource
   handle issued to identity A is rejected for identity B (cross-tenant / IDOR). This is the
   costliest real incident class (Asana, Supabase service_role) and essentially unclaimed by
   scanners — but it needs two authorized identities and per-tenant resource IDs, so it's a
   deliberate v0.2 with a heavier setup contract.
