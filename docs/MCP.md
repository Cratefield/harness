# MCP

`fz-mcp` is a Model Context Protocol server over `fz --json` (issue
#160), built in [`crates/mcp/`](../crates/mcp/) as the crate
`cratefield-mcp`. It puts the venture CLI in front of an agent without
giving it a second surface that can drift: six of the seven tools spawn
the venture's real `fz` program and hand back the one JSON object `fz
--json` printed, byte for byte. This document is the why;
[`crates/mcp/README.md`](../crates/mcp/README.md) is the five-minute how
— the tools, the arguments, the envelope, a client configuration. The
decision to build it here, as a wrapper and nothing more, is
[ADR 0021](adr/0021-the-mcp-server-is-a-thin-wrapper-over-fz-json.md).

## Why a server at all

An agent driving `fz` used to screen-scrape. The CLI printed paragraphs
written for an operator, so anything driving it programmatically parsed
prose, and every rewording of that prose — usually a helpful one — broke
the agent silently. Issue #140 fixed the source of the problem: six verbs
(`fz doctor`, `plan`, `deploy`, `add`, `init`, `verify`) speak two
disciplines —

- without `--json`, prose for the operator, unchanged;
- with `--json`, exactly one JSON object on stdout — `schema`, `ok`,
  `failures[]`, each failure carrying a stable code from the append-only
  catalogue — and nothing else.

The server exists because that line held. A protocol wrapper over a
disciplined output is small and honest; a protocol wrapper over prose is
a screen-scraper with a socket on it. `fz-mcp` assumes the discipline and
adds none of its own: it turns the verbs the CLI already made agent-safe
into tools the agent's client already knows how to call, and it is the
place the agent finds out *which* code a failure carried — `fz_error_codes`
serves the whole catalogue, no subprocess spent.

## A wrapper, not a second surface

The temptation, once a server exists, is to give it opinions: typed
results of its own, a schema that models plans and digests, codes for
situations the CLI never named. Every opinion is a second place that can
disagree with the CLI, and the disagreement would be discovered by an
agent mid-task. So the wrapper owns no contract the CLI already owns:

- **The envelope is the CLI's.** The text content of a tool result is the
  exact line `fz` printed — byte for byte, not re-serialised. Run the
  same command outside the protocol and diff: there is nothing between
  them. When the CLI's envelope grows a key, the server serves it with no
  change here, which is also why the one output schema pins `schema`,
  `ok` and `failures` and deliberately nothing beyond them — a closed
  schema would make every verb-specific addition look like a tool
  regression the moment the CLI exercised its own contract.
- **The catalogue is read, never copied.** `fz_error_codes` serves the
  catalogue compiled in from the `cratefield-cli` library — a call to
  `cratefield_cli::codes::registry()` in the server's own process, not a
  question put to the spawned `fz` — in registry order, each entry
  tagged `source: "fz"`; the four wrapper-owned codes are appended
  tagged `source: "mcp"`. A code the CLI appends is answerable the
  moment it ships. The four `mcp-` codes are everything the server may
  ever add, and they are prefixed so a collision with the CLI's
  kebab-case namespace is structurally impossible.
- **A new agent-safe verb is one table row.** The tool table is data,
  each entry carrying its own argv builder, so what a call runs cannot
  drift from what the tool listing advertises.

`fz` is a child process, never a library call: in a venture it is a
per-venture `[[bin]]` linked against that venture's compiled-in harness,
and the harness-bound verbs — `fz doctor` most of all — cannot run in a
process that lacks it. So the server is pointed at a venture rather than
linked to one:

```sh
fz-mcp --cwd ./my-venture -- cargo run -q --bin fz --
```

`-q` is not decoration: cargo's own chatter must stay off stdout, because
on this transport stdout belongs to the protocol alone — one JSON-RPC
message per line, serialised compactly, never prettified, or an embedded
newline desynchronises every client at once. The words after `--` are
split on whitespace with no shell interpretation, and the same is true of
`FZ_MCP_COMMAND`: a quoted or globbed value would silently run something
else than the operator typed. The child's stdin is `/dev/null` and both
of its output streams are piped, so an `fz` that tried to prompt could
not eat MCP messages off the server's stdin, and nothing the child prints
can enter the protocol stream.

## A failure is a result, not an error

`isError` is true exactly when the envelope's `ok` is false — never for
any other reason. This mirrors the CLI on purpose and the MCP spec draws
the same line for the same reason: a *tool execution error* is part of
the conversation. The model reads the envelope, sees
`composition-drift` or `stale-plan`, and corrects — re-plans, re-reads
the manifest, calls `fz_plan` again. A *protocol error* belongs to the
client, not the model; it ends the exchange and carries no structured
answer to learn from. A tool that ran and refused is the first thing,
because the refusal is information the model needs; making it the second
would turn every ordinary refusal into a broken server.

So the JSON-RPC error codes are reserved for requests that could not be
understood at all: an unparsable line (`-32700`), a shape the protocol
forbids — the batched arrays 2025-06-18 removed (`-32600`) — an unknown
method (`-32601`), and params that are missing or name a tool this server
does not have (`-32602`). For those there is no envelope to show. For
everything else there always is.

## Why `-` is refused before `fz` runs

The wrapper validates every argument before any process is spawned, and a
failure of validation is an envelope carrying `mcp-argument-invalid`. The
interesting refusal is a value starting with `-`. Arguments travel as
argv — there is no shell to quote through — and clap reads a token
beginning with `-` as a flag, so a call asking for `module: "-h"` would
run `fz add -h`: a usage error on stderr, exit 2, and **no JSON at all**
on stdout. That is precisely the non-JSON stdout the `mcp-fz-no-json`
code exists for, and refusing at the boundary is what keeps the envelope
the only thing an agent ever has to parse.

The other checks are the same idea with less drama. An unknown property
would otherwise be silently ignored while the agent believed its argument
mattered — the tool would run on defaults and report success. A missing
or empty required value would produce clap's prose instead of an envelope.
A wrong JSON type would arrive at `fz` as something other than what the
agent sent. Each refusal names the argument, because an agent that cannot
see which argument failed cannot fix it either.

## What the protocol adds, and what it withholds

The handshake prefers protocol `2025-11-25` and also speaks
`2025-06-18`, `2025-03-26` and `2024-11-05`, echoing the client's
requested version whenever this server speaks it and falling back to the
preference when it does not — a successful handshake either way, because
an agent on an older protocol must still be able to read the answer.
`structuredContent` and `outputSchema` exist only from 2025-06-18, so
they are emitted only then: an older client gets the envelope as text and
no schema keys it could not know. The `initialize` result carries
instructions that say what every result is and name `fz_error_codes` as
the way to resolve any code — the one orientation an agent needs, instead
of per-tool lore.

Two pieces of surface are withheld because surface nobody needs is
surface that can drift: the tool listing pages nothing (seven tools fit
one page; a `cursor` is ignored and no `nextCursor` is emitted), and no
method exists that the tools do not need. Notifications are answered with
nothing at all, not even an error — their sender is not waiting.

## The deliberate gap

Coverage is exactly the six verbs that speak `--json`. The rest —
`modules`, `migrations`, `data`, `tables`, `build`, `build-key`, `push` —
print prose and are deliberately not wrapped, because wrapping them today
would mean screen-scraping, and screen-scraping is what this server
exists to end. A tool that hands back parsed paragraphs would also drift
the moment the prose was reworded, rebuilding the fragility the wrapper
removed, one verb at a time.

Finishing the coverage is therefore a CLI change first: the verb speaks
`--json` under the same two disciplines, its codes join the catalogue,
the acceptance suites pin both — and then wrapping it is one table row
here. The wrapper cannot lead this. It cannot be smarter than the CLI,
and that is its guarantee: an agent's question has to be answerable as a
coded refusal or an envelope key on the CLI side before the server can
carry it anywhere.

## Operating it

Point it at the venture and let the client start it — the invocation and
a client configuration block are in
[`crates/mcp/README.md`](../crates/mcp/README.md). `--cwd` and the `--`
command have environment fallbacks `FZ_MCP_CWD` and `FZ_MCP_COMMAND`,
and the time limit has `FZ_MCP_TIMEOUT_SECS`: 600 seconds by default, `0`
for no limit at all, a non-numeric value refused at startup rather than
silently defaulted. The limit exists because the serve loop answers one
call at a time, so a child that never exits would stop even `ping` from
being answered — and the documented `cargo run -q --bin fz --`
invocation blocks indefinitely whenever another cargo holds the package
lock, so "the child is just slow" is not an answer a session can wait
out forever. The default is generous on purpose — a real `fz deploy`
legitimately takes minutes — because the point is termination, not
speed: a child that outlives the limit is killed, and its call comes
back as `mcp-fz-timeout`, one of the four wrapper codes, instead of
hanging the session. One skew to note: `FZ_MCP_COMMAND` naming an `fz`
built from a different version than the `cratefield-cli` this server
was compiled against means the six spawning tools reflect that binary
while `fz_error_codes` still reports the compiled-in catalogue, and the
two code sets can disagree. Diagnostics are one stderr line at startup;
stdin ending is a clean shutdown. Publishing `cratefield-mcp` to crates.io is
the remaining human step — the same process as every other crate
([docs/RELEASING.md](RELEASING.md)); until then it is built from this
repository, which is where it belongs (ADR
[0021](adr/0021-the-mcp-server-is-a-thin-wrapper-over-fz-json.md)).
