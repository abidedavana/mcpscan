# Building mcpscan: a spec-grounded posture scanner for MCP servers

This is a short write-up of why I built mcpscan, how it works, and the engineering
decisions I care about in it. It is a portfolio project: a working v0.1 with 13 checks and
92 tests, not a production-hardened product. I have tried to keep the claims here honest
about what it does and does not do.

## The problem

The Model Context Protocol (MCP) is the connective tissue for AI agents: a server exposes
"tools" (functions the model can call), and any MCP client can connect and use them. That
surface is growing fast, and a lot of it ships insecurely.

The evidence is not hypothetical:

- Knostic scanned the internet and found 1,862 exposed MCP servers. In a manual sample of
  119, every single one served its tool listing to an anonymous caller. No authentication
  at all.
- Equixly tested a set of MCP server implementations and found 43% with command-injection
  flaws, 30% with SSRF, and 22% with path traversal, almost all of it flowing through
  free-form tool parameters.
- CVE-2025-49596 (Anthropic's MCP Inspector, CVSS 9.4) was a classic combination: a local
  server bound to all interfaces, no auth between client and proxy, and no Origin
  validation, which let a malicious web page drive the victim's local server over DNS
  rebinding.

These are misconfigurations, not exotic zero-days. That is exactly the kind of thing a
scanner should catch before an operator ships. mcpscan is that scanner: point it at an MCP
server you run or are authorized to assess, and it tells you what is misconfigured and how
to fix it. Detection and remediation only. No exploitation, no payloads.

## Approach: research first, then ground every check

I did not want to invent a checklist from intuition. The category is well-defined (this is
the same shape as Prowler for AWS or a linter for code), so the checks should come from two
places: what the MCP specification actually requires, and what real advisories show going
wrong.

So the first deliverable was not code, it was a catalogue ([CHECKS-v0.1.md](../CHECKS-v0.1.md)).
For every candidate check I read the relevant section of the MCP spec (revision 2025-11-25)
and decided whether there was a real, definable "secure state" to test against. Then I
tagged each check with its grounding:

- **spec**: backed by a normative MUST/SHOULD in the spec, quoted inline.
- **spec+inferred**: partly spec-backed, partly best practice.
- **inferred**: a defensible best-practice check where the spec defines no conformance
  requirement.

That last distinction is the part I care most about. Authentication, for example, is
explicitly OPTIONAL in the MCP spec. So a check that flags an unauthenticated server is not
a spec violation; it is a posture opinion backed by advisory data. mcpscan says so, in the
report, on every finding. An operator should never be told "you violated the spec" when
they did not. Getting that boundary right is what separates a credible security tool from
one that cries wolf.

A related decision: where a category had no definable secure state, I left it out rather
than inventing a check. Rate limiting is a spec MUST, but the spec gives no observable
threshold or behavior, so there is nothing a scan can assert a PASS or FAIL against. It is
documented as deliberately excluded, not quietly skipped.

## How it works

A scan runs every check against every server in a client-style config (the same
`mcpServers` JSON shape that Claude Desktop and other hosts already use). Each check returns
PASS, FAIL, INFO, or NA with evidence and a remediation.

There are three tiers of inspection, in increasing order of intrusiveness:

1. **Static** (default): read the config only. Never contacts the server. Catches
   hardcoded secrets, plaintext HTTP, tokens in URLs, unsafe bind addresses.
2. **Live snapshot** (`--live`, stdio): launch the server and run one handshake plus
   `tools/list`. This gives the checks the server's advertised tool surface: schema
   validity, dangerous-capability annotations, secrets leaked into tool descriptions,
   stdout hygiene.
3. **Live probe** (`--live`, HTTP): a small, bounded set of observation-only requests to
   the endpoint: an unauthenticated `initialize`/`tools/list`, an `initialize` carrying a
   foreign Origin header, a second `initialize` to compare session IDs, and RFC 9728
   well-known metadata GETs.

The rule that holds across all of it: a posture scan never invokes a tool and never sends a
credential. That mirrors the ethical boundary the Knostic researchers used (read what the
server volunteers, never trigger an action), and it is what makes the tool safe to run
against a server you own.

INFO versus FAIL is a deliberate confidence signal. A vendor-prefixed key like `ghp_...` is
an unambiguous FAIL. A high-entropy string with no recognizable prefix is an INFO: it might
be a secret, it might not, and the operator should look. Heuristic checks (the "does this
tool parameter flow to a shell" one) are INFO by design, because the scanner is flagging a
schema shape to harden, not confirming an injection. INFO findings never fail the build, so
CI does not get trained to ignore the tool.

## Engineering decisions I care about

**Grounding honesty as a first-class feature.** Covered above, but it is the spine of the
project. Every finding carries its grounding tag, and I verified every spec citation
against the live spec pages rather than from memory. When I re-checked the catalogue I found
one real error (I had claimed an absent protocol-version header must return HTTP 400, when
the spec actually says the server should assume an older version) and corrected it. That
kind of thing is why you verify.

**Zero runtime dependencies.** The static scanner and the HTTP probe both use only the
standard library (`json`, `urllib`, `subprocess`). I deliberately did not build on the
official MCP SDK for the client, for two reasons: it keeps the install trivial, and a
normal SDK client hides exactly the things a scanner needs to see. The stdout-hygiene check
depends on collecting non-protocol output that an SDK would either crash on or silently
discard.

**Fixtures that are both tests and demos.** There are two runnable stdio fixture servers, a
clean one that passes every check and a messy one that fails each, plus in-process HTTP
fixtures for the probe. They are the integration tests and the demo target at once, and
because they are self-contained (stdlib, ~60 lines each) anyone can see exactly what
misconfiguration each check is meant to catch.

**Report text that survives real terminals.** A small thing that bit me twice: em-dashes
and smart quotes in evidence strings turn into mojibake on a Windows console. All emitted
text is now ASCII, with a guard test that fails if a non-ASCII character sneaks into a
finding.

## What it does not do (yet)

Being honest about the edges:

- HTTP servers that require auth cannot have their tool list retrieved without credentials,
  which mcpscan deliberately never handles. For those servers the tool-surface checks
  report PASS ("no tools observed") rather than a real assessment. This is documented, not
  hidden.
- The `inputSchema` check does structural validation (presence, object root, well-formed
  `properties`/`required`), not full JSON Schema 2020-12 metaschema validation. That would
  need a third-party library, which I kept out of the zero-dependency core.
- It is not on PyPI and has not been run against a large corpus of real servers. It is a
  design-and-build project, and I would want that field validation before calling it more
  than v0.1.

## What is next (v0.2)

The catalogue already sketches the growth path. The ones I would build next, roughly in
order of value:

1. **Token audience validation**: probe whether a server rejects a token minted for a
   different resource (RFC 8707). This is the confused-deputy / token-passthrough class, and
   it is strongly spec-grounded. It needs a token oracle to test, which is why it is v0.2.
2. **Tool-definition pinning**: hash each tool's definition on first scan and flag drift on
   re-scan ("rug pull" detection).
3. **Protocol-version enforcement**: verify the server returns HTTP 400 for an invalid
   MCP-Protocol-Version header (a clean conformance probe).
4. **Multi-tenant isolation**: for multi-tenant HTTP servers, probe whether a resource
   handle issued to one identity is rejected for another. This is the costliest real
   incident class and essentially unclaimed by existing scanners, but it needs two
   authorized identities to test.

## What I took away from it

The most useful discipline was refusing to write a check until I could name its secure
state and cite where it comes from. It is tempting, in security tooling, to pile on checks
because more findings looks like more value. The opposite is true: a tool that flags things
it cannot justify teaches people to stop reading its output. The grounding tags, the INFO
tier, and the deliberate exclusions are all the same idea, which is that a scanner's
credibility is its whole product.
