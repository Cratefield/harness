# cratefield-mcp

A Model Context Protocol server over `fz --json` (issue #160). The binary
is `fz-mcp`. It is a thin wrapper: six of its seven tools spawn the
venture's real `fz` program and hand back the one JSON object `fz --json`
printed — the CLI's own envelope, untouched. It has no contract of its
own to drift,
which is the point. The rationale is in
[docs/MCP.md](../../docs/MCP.md); the decision to build it here, as a
wrapper, is
[ADR 0021](../../docs/adr/0021-the-mcp-server-is-a-thin-wrapper-over-fz-json.md).

## Run it

```sh
cargo build -p cratefield-mcp
./target/debug/fz-mcp --cwd ./my-venture -- cargo run -q --bin fz --
```

`--cwd` is the directory the child runs in (env `FZ_MCP_CWD`) — an
empty `FZ_MCP_CWD` counts as unset, while an empty `--cwd ""` is
refused at startup rather than read as the current directory. Everything
after `--` is the `fz` program to run plus leading arguments (env
`FZ_MCP_COMMAND`, split on ASCII whitespace with no shell interpretation);
the default is plain `fz`. In a venture the long form above is the usual
one, because the venture's `fz` is a per-venture `[[bin]]` carrying its
compiled-in harness — and `-q` matters, because cargo's own chatter must
stay off stdout: on this transport stdout belongs to the protocol alone.

The child is on a leash, not a schedule: `FZ_MCP_TIMEOUT_SECS` (default
600 seconds) bounds one `fz` run. The default is generous on purpose — a
real `fz deploy` legitimately takes minutes — because the point is
termination, not speed: the serve loop answers one call at a time, so a
child that never exits would stop even `ping` from being answered, and
the long form above blocks indefinitely whenever another cargo holds the
package lock. A child that outlives the limit is killed and its call
comes back as an `mcp-fz-timeout` envelope. `0` means no limit at all; a
non-numeric value is refused at startup, never silently defaulted.

The transport is newline-delimited JSON-RPC 2.0 over stdin and stdout —
one message per line, no Content-Length framing. Diagnostics are one line
on stderr at startup; stdin ending is a clean shutdown. `--help` prints
usage and exits before the server starts.

## Point a client at it

MCP clients start a stdio server from a `command` and `args` pair:

```json
{
  "mcpServers": {
    "fz": {
      "command": "/path/to/fz-mcp",
      "args": ["--cwd", "./my-venture", "--", "cargo", "run", "-q", "--bin", "fz", "--"]
    }
  }
}
```

## The seven tools

| Tool | Runs | Does | Arguments |
|---|---|---|---|
| `fz_doctor` | `fz doctor --json` | Harness, production rules, migration lockfile and portable-SQL findings | `out`, `allow_no_captcha` |
| `fz_plan` | `fz plan --json --non-interactive` | What a deployment would change, plus the `digest` that approves exactly that plan. Writes nothing | `manifest`, `migrations` |
| `fz_verify` | `fz verify --json --non-interactive` | Whether the recorded deployment still matches the manifest; drift is coded failures | `manifest`, `migrations` |
| `fz_init` | `fz init --json --non-interactive` | Writes a new venture manifest — name and host, no modules | `name` (required), `host` (required), `manifest`, `force` |
| `fz_add` | `fz add --json --non-interactive` | Adds one module to the desired composition — never deploys. Re-adding is a successful no-op | `module` (required), `manifest` |
| `fz_deploy` | `fz deploy --json --non-interactive` | Records the approved plan beside the manifest; the `digest` from `fz_plan` is the approval token it enforces | `plan`, `manifest`, `migrations`, `i_am_deploying_to_production`, `i_am_removing_modules` |
| `fz_error_codes` | nothing — no process | The stable error-code catalogue | none |

Argument types follow the names: `force`, `i_am_deploying_to_production`
and `i_am_removing_modules` are booleans, everything else is a string.
Every argument is optional unless marked required. Strings must not start
with `-` — clap would re-read the value as a flag. `null` counts as
absent. Unknown properties, missing or empty required values and wrong
types are refused before any process is spawned, each as an envelope
carrying `mcp-argument-invalid`.

The four annotations are stated on every tool, because the MCP spec
defaults the surprising ones — `destructiveHint` and `openWorldHint` both
default to *true*, and silence would advertise a read-only tool as a
hazard.

| Tool | `readOnlyHint` | `destructiveHint` | `idempotentHint` | `openWorldHint` |
|---|---|---|---|---|
| `fz_doctor` | true | false | true | false |
| `fz_plan` | true | false | true | false |
| `fz_verify` | true | false | true | false |
| `fz_init` | false | false | false | false |
| `fz_add` | false | false | true | false |
| `fz_deploy` | false | true | false | true |
| `fz_error_codes` | true | false | true | false |

Only `fz_deploy` is destructive — a plan that removes modules takes their
data out of the venture — and only `fz_deploy` is open-world: it is the
step that leads to a Worker standing up in the world.

## One envelope

Every tool result carries the same object — the CLI's own. A success,
which is the exact line `fz add waitlist --json` prints:

```json
{"schema":1,"ok":true,"failures":[],"changed":true,"module":"waitlist","manifest":"venture.json"}
```

A failure is the same shape with `ok` false and the reasons coded:

```json
{"schema":1,"ok":false,"failures":[{"code":"locked-migration-edited","message":"…"}]}
```

The wrapper builds that same shape itself when it must refuse:

```json
{"schema":1,"ok":false,"failures":[{"code":"mcp-argument-invalid","message":"argument `module` must not start with `-`: the fz command line would read \"-h\" as a flag"}]}
```

Three rules pin the result around the envelope:

- **`isError` mirrors `ok`.** True exactly when the envelope's `ok` is
  false. A tool that ran and reported a failure is a tool execution
  error the model can read and self-correct from, never a JSON-RPC
  error; those are reserved for requests that could not be understood at
  all — an unparsable line, a non-object or batched request, an unknown
  method, malformed params or an unknown tool.
- **The text content is the exact line `fz` printed, byte for byte.** Run
  the same command and diff the two: there is nothing between them. The
  results the wrapper builds itself — the `mcp-` refusals and the
  catalogue — carry the same single-line shape.
- **`structuredContent` and `outputSchema` appear only on protocol
  2025-06-18 and later.** An older client gets the envelope as text and
  no schema keys it could not know. The handshake prefers `2025-11-25`
  and also speaks `2025-06-18`, `2025-03-26` and `2024-11-05`, echoing
  the client's requested version whenever this server speaks it.

`schema` is `1` today. Verbs add keys (`digest`, `record`, `changed`) and
never remove one, so the one output schema pins the envelope's first
three keys and deliberately nothing beyond them.

## The four codes of its own

The catalogue is the CLI's, compiled in from the `cratefield-cli`
library — `cratefield_cli::codes::registry()` runs in this server's own
process, never asked of the spawned `fz` and never copied into this
crate — so a code the CLI appends is served here with no change on this
side. `fz_error_codes`
returns it, every entry tagged `source: "fz"`, followed by exactly four
wrapper codes tagged `source: "mcp"` — everything this server may ever
add:

| Code | When |
|---|---|
| `mcp-fz-unavailable` | The `fz` program could not be spawned at all — a missing binary, a configured `--cwd` that does not exist |
| `mcp-fz-no-json` | `fz` ran but stdout was not a single JSON object — most often a clap usage error (exit 2), else a refusal or a crash; the message carries the exit status and a bounded excerpt of stderr, else stdout — a crash's last words can land on stdout |
| `mcp-fz-timeout` | `fz` outlived the configured time limit (`FZ_MCP_TIMEOUT_SECS`) and was killed; the message names the program and the limit |
| `mcp-argument-invalid` | An argument failed validation before `fz` was invoked |

All four carry the catalogue's append-only contract: a code is never
renamed, reworded or removed. A failure *message* may change wording
freely; a *code* may not. New codes append.

## Not wrapped, on purpose

The six verbs above are exactly the ones that speak `--json` today. The
rest — `modules`, `migrations`, `data`, `tables`, `build`, `build-key`,
`push` — print prose for the operator, and wrapping them would mean
screen-scraping, which is what this server exists to end. Finishing the
coverage is a CLI change first — the verb speaks `--json` under the same
two disciplines, its codes join the catalogue — and then one table row
here.
