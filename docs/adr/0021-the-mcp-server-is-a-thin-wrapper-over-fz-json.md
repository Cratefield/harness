# ADR 0021: The MCP server is a thin wrapper over `fz --json`, living in this workspace

Status: accepted, 2026-09-19. Issue #160. The issue asked for a published
MCP server and assumed the answer came with a new public repository and a
publishing token; this ADR records why neither is part of the answer, and
what the server is allowed to be instead.

## Context

An agent that wanted to drive the venture CLI had to read prose. `fz`
printed paragraphs written for an operator, so anything driving it
programmatically scraped them, and every rewording of the output — usually
a helpful one — broke the scraper. Issue #140 had already done the work
that changes this: six verbs (`fz doctor`, `plan`, `deploy`, `add`,
`init`, `verify`) speak the two disciplines — prose without `--json`,
and with it exactly one JSON object on stdout whose failures each carry a
stable code from an append-only catalogue (`crates/cli/src/codes.rs`).
What was missing was the last mile. An agent's client already speaks the
Model Context Protocol, so #160 asked for a server that turns those verbs
into tools and lets the protocol carry the discipline the rest of the way.

The issue's shape assumed the server would be a product: a new public
repository, a publishing token, a release process. The question this
decision answers is what the server is allowed to *be*, because the
temptation the moment it exists is to give it opinions — about plans,
about digests, about what a drift means — and every opinion it takes is a
second place that can disagree with the CLI.

One constraint was already fixed. `fz` is a per-venture `[[bin]]`, linked
against that venture's compiled-in harness, and the harness-bound verbs —
`fz doctor` most of all — cannot run in a process that lacks it, so
whatever the server is, it spawns the venture's own `fz` as a child in
the venture's directory.

## Decision

**The server is a thin wrapper, and it lives in this workspace.**
`crates/mcp` (crate `cratefield-mcp`, binary `fz-mcp`) speaks
newline-delimited JSON-RPC 2.0 over stdio and does nothing else. Six of
the seven tools spawn the configured `fz` with `--json` and hand back
the one JSON object `fz` printed — as the result's text content byte
for byte, and as `structuredContent` on protocols new enough to have
it; the seventh, `fz_error_codes`, serves the catalogue in-process.
`isError` keys on the envelope's `ok` and on nothing else. A reader
debugging a tool result runs the same `fz` command, diffs the two, and
finds nothing between them.

**The wrapper owns no contract the CLI already owns.** The error-code
catalogue is compiled in from the `cratefield-cli` library —
`cratefield_cli::codes::registry()` is called in the server's own
process, not asked of the spawned `fz` — and never copied, so a code
the CLI appends is served here with no change on this side. The server
adds exactly four codes of its own, prefixed `mcp-` so they cannot
collide with the CLI's kebab-case namespace, and
bound by the same append-only promise. Its input schemas describe the
arguments each verb takes; its one output schema pins the envelope's
first three keys and deliberately nothing beyond them, because the
envelope is grow-only and a closed schema would make every
verb-specific addition look like a tool regression the moment the CLI
exercised its own contract.

**A new agent-safe verb is a table row.** The tool table is data: one
entry per `--json` verb, each carrying its own argv builder, so "which
tools exist" and "what a call runs" cannot drift apart. When the CLI
grows a seventh speaking verb under #140's disciplines, wrapping it is
one row — no new protocol, no new schema version, no change outside this
crate.

## Rejected

**1. A separate repository.** What the issue assumed. It needs a
publishing token and human setup before any of it exists, and then it
drifts by default: the envelope's shape and the catalogue would have to
be copied into it, and a copy is precisely the second place that can
disagree with the original. The failure this issue exists to remove —
two renderings of one truth — would be rebuilt at the very layer meant
to remove it. ADR 0013 already gave the distribution answer for this
workspace's crates: one repository.

**2. A TypeScript/npm server beside `tools/cfjs`.** The installation
story is genuinely better — `npx` is how MCP clients expect to start a
server — but the server would re-declare the catalogue and the envelope
in a second language: two implementations of one contract, in the
artifact most likely to be installed and least able to share a line of
it. The catalogue lives in Rust next to the codes it describes, where a
change to a code fails the crate's own tests; a TS copy could only be
kept in step by hand.

**3. A richer API of its own.** Typed per-tool outputs, its own result
shapes, its own verb set layered above `fz`'s — a server that models the
domain rather than proxying it. Every such addition is a second surface
to keep in step: the day it has opinions about when a plan is stale or
what removing a module costs, it competes with `fz deploy`'s own refusals,
and the two eventually answer differently. The server's one opinion is
routing.

## Consequences

- Publishing `cratefield-mcp` to crates.io is the remaining human step —
  the one every other new crate waits on: a place in the ordered publish
  list and a trusted publisher ([docs/RELEASING.md](../RELEASING.md)).
  Until then the server is built from this repository, which is the
  deviation from the issue made permanent.
- Coverage is exactly the verbs that speak `--json`. `fz modules`,
  `fz migrations`, `fz data`, `fz tables`, `fz build`, `fz build-key` and
  `fz push` print prose and stay unwrapped — wrapping them today would
  mean screen-scraping, the thing this issue removes.
- The wrapper cannot be smarter than the CLI. An agent's question has to
  be answerable as a coded refusal or an envelope key on the CLI side
  first; where it is not, the change belongs in the CLI, and the server
  trails.
- The four `mcp-` codes are append-only like the CLI's catalogue, and
  `fz_error_codes` serves both as one list tagged with a `source`, so an
  agent resolves every code in one call.
- Extending coverage is a CLI change first and a table row second; it can
  never be a server change alone.

## References

Issue #160; harness #140 (the agent-safe verbs, the two disciplines and
the catalogue); ADR 0013 (one repository); `crates/mcp`;
`crates/cli/src/codes.rs`; [docs/MCP.md](../MCP.md).
