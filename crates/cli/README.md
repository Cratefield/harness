<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-cli"><img src="https://img.shields.io/crates/v/cratefield-cli.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-cli on crates.io"></a>
  <a href="https://docs.rs/cratefield-cli"><img src="https://img.shields.io/docsrs/cratefield-cli?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-cli documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-cli (`fz`)

The venture CLI: `fz migrations collect`, `fz migrations apply`, `fz
data export` / `fz data import`, `fz doctor`, `fz modules`, `fz push`,
and the agent-safe manifest workflow — `fz plan`, `fz deploy --plan`,
`fz add`, `fz init`, `fz verify` (harness #140).

`fz` links against your venture's compiled-in harness, so it runs as a bin
target **inside the venture repo** — the pattern the venture template
ships:

```toml
# venture Cargo.toml
[[bin]]
name = "fz"
path = "src/fz_main.rs"

[dependencies]
cratefield-cli = "0.1"
```

```rust,ignore
// venture src/fz_main.rs
fn main() { cratefield_cli::main_for(my_venture::harness); }
```

Then:

```sh
cargo run --bin fz -- migrations collect
cargo run --bin fz -- doctor
cargo run --bin fz -- modules
```

## `fz migrations collect [--dialect sqlite] [--out migrations]`

Walks the harness's modules in config order and writes
`migrations/<GGGG>_<module>_<NNNN>_<name>.sql` — the format
`wrangler d1 migrations apply` executes in lexical (apply) order.
`migrations/.harness-lock.json` pins `<module>/<migration-id>` to the
global file name plus a sha256 of its content:

- locked entries are never renamed or renumbered;
- new migrations append with the next `GGGG`;
- exits non-zero when a locked file is missing or was edited after being
  applied (restore the file or add a new migration instead).

`--dialect postgres` for collect is not a thing: collect writes the
wrangler/D1 (sqlite) flow. Postgres migrations apply directly — see
`fz migrations apply` below.

## `fz migrations apply [--dialect postgres] --url <URL>`

Applies the harness's module migrations directly to a Postgres database
(issue #18): per module the `postgres` migration set when shipped, else
the `sqlite` set when it passes the portable-SQL lint, in lock order
(the order `migrations collect` pins), tracked idempotently in
`harness_migrations(id, applied_at)`. The native counterpart of
`wrangler d1 migrations apply`.

Requires building `fz` with the crate's `postgres` feature (so sqlx and
tokio stay out of the default, wasm-safe dependency graph):

```toml
[dependencies]
cratefield-cli = { version = "0.1", features = ["postgres"] }
```

```sh
cargo run --bin fz -- migrations apply --dialect postgres \
  --url postgres://user:pass@host:5432/venture
```

## `fz data export [--plan] --db <PATH> --out <FILE.jsonl>` / `fz data import [--append] [--plan] --url <URL> <FILE.jsonl>`

Moves a venture's D1 data to Postgres (issue #21). Export reads a
venture SQLite database — D1 is SQLite; the Cloudflare-side step is
`wrangler d1 export` loaded into a local file (`docs/DATA-MOVE.md` is
the whole runbook) — and writes one JSON Lines file: a manifest line
(per-table row counts and sha256, tables in lock order), then one
`{"table","row"}` record per row. `--plan` prints the per-table summary
without writing.

Import (built with the crate's `postgres` feature, like `migrations
apply`) loads that file into Postgres in lock order:

- every table's sha256 is verified against the manifest **before
  anything is written** — a tampered or truncated file leaves the
  target untouched;
- a non-empty table is refused without `--append` (naming the table and
  the flag) before any write; `--append` adds to it, and overlapping
  primary keys fail loudly rather than duplicating;
- inserts are batched multi-row statements inside one transaction per
  table; values bind by the target column's Postgres type (typed NULLs
  included), and the portable subset is TEXT/INTEGER/REAL/BOOLEAN —
  anything else fails by name;
- after the writes, row counts are verified against the manifest;
- `--plan` prints the target's state (tables, incoming rows, existing
  rows, refusal warnings) and writes nothing.

The manifest must be exactly this venture's tables — another venture's
export file is refused before anything touches the network.

## `fz doctor [--out migrations] [--json]`

Fails when:

- a module's `harness_api` differs from the `cratefield-core` it linked
  against (the message names the module, its version and the core crate;
  `Harness::build` already refuses this, the doctor re-asserts it —
  issue #17);
- a module with `public_writes()` runs in a `production` venture without
  the Captcha port (section 11);
- any module migration is not collected yet, a locked file is missing or
  edited;
- a migration contains non-portable SQL: `AUTOINCREMENT`, `datetime(`,
  `SERIAL`, `NOW()`, `json_extract`, or backtick quoting.

With `--json` the doctor speaks for agents (harness #140): exactly one
JSON object on stdout and nothing else —

```json
{"schema":1,"ok":false,"failures":[{"code":"locked-migration-edited","message":"…"}]}
```

`schema` is `1` today so consumers can branch; every failure carries a
`code` from the stable catalogue in `cratefield_cli::codes` — kebab-case,
never renamed or removed, while message wording may change. The exit code
still reflects the verdict; prose and operator warnings are unchanged
without the flag.

## `fz plan [--manifest venture.json] [--migrations migrations] [--json]`

The agent-safe workflow (harness #140) starts here. Reads the manifest,
the migration lockfile and the deploy record, and describes what would
change: modules added or removed (with each added module's catalog
tier, required modules, and whether a dependency pulled it in), venture
config deltas, migrations not yet collected, and the migration files a
removal would orphan. It changes nothing on disk.

The JSON carries `"schema": 1` and a **`digest`**: the sha256 over the
normalised destination state (venture identity, env, resolved modules,
per-module config, venture config, seed SQL, migration status). The
same inputs always give the same digest; any input change gives a
different one. The baseline-dependent deltas (added/removed lists) are
presentation, deliberately not hashed — an approval is of the
destination, not the journey.

## `fz deploy --plan <digest> [--manifest venture.json] [--i-am-deploying-to-production] [--json]`

Applies exactly the approved plan: recomputes it from the current
inputs and refuses any other digest — a stale approval cannot deploy
(`stale-plan`), and the refusal names what moved since the recorded
deployment.
Deploying without `--plan` at all is refused (`deploy-plan-required`):
approval is the point.

What "applies" means here is deliberate and bounded: `fz deploy`
records the plan, bound to its digest, in `.harness-deploy.json`
beside the manifest (written atomically, so an interrupted deploy
leaves either the old record or the new one and re-running
reconciles). It never runs wrangler, never compiles, and never
touches a database — the printed next steps (`fz migrations
collect`, `worker-build`, `wrangler deploy`) are needs-human and need
credentials `fz` does not hold. Running the same approved deploy
twice is safe: the second records nothing and reports
`changed: false`.

Two consents, deliberately separate:

- a venture whose manifest config resolves `ENV=production` refuses
  without `--i-am-deploying-to-production`
  (`production-deploy-unauthorized`);
- a plan that removes modules — their data leaves the served venture —
  refuses without the same flag (`destructive-change-unauthorized`).

## `fz add <module> [--manifest venture.json] [--json]`

Adds a module to the manifest's desired composition and nothing else:
it never deploys, never provisions, never touches a database. The slug
must be in the catalog (`module-unknown` otherwise); adding a module
the manifest already lists is a no-op that succeeds with
`changed: false`. `.toml` manifests are rewritten as TOML, others as
JSON; comments and formatting are not preserved.

## `fz init --name <name> --host <host> [--manifest venture.json] [--force] [--json]`

Writes a new venture manifest — name and host, no modules yet. Refuses
to overwrite an existing manifest unless `--force`
(`manifest-exists`).

## `fz verify [--manifest venture.json] [--migrations migrations] [--json]`

Checks the recorded deployment still matches the manifest, reporting
drift as coded failures in exactly the doctor's JSON shape: the
module set (`composition-drift`), the config (`config-drift`), the
resolved environment (`env-drift`), and — when nothing narrower
explains it — the recorded digest no longer matching a recomputed
plan (`manifest-drift`). No deployment recorded at all is
`not-deployed`.

Every workflow command speaks both disciplines `fz doctor --json`
established: under `--json`, exactly one JSON object on stdout,
nothing on stderr, every failure carrying a stable code from the
catalogue; `--non-interactive` is accepted everywhere (the commands
never prompt — anything needing a human is a coded refusal, and the
flag suppresses the human `next:` steps from prose output).

## `fz push` (issue #184)

The operator side of the push transports. It reads the push environment
through `cratefield-push-wiring` — the one `build_push` that `serve()` and
`fz doctor` also call — so what `fz push` reaches is what the deployment
reaches, and no second place in the workspace names a push variable
(`crates/cli-acceptance/tests/push_env_guard.rs` fails the build if one
does). None of it needs a compiled-in harness, so the standalone `fz` (and
the Docker image) serve it too.

### `fz push vapid keygen [--file PATH] [--force] [--print-private]`

Generates the P-256 key pair Web Push identifies this application server by
and prints the **public** key — base64url of the 65-byte uncompressed point,
which is exactly what a browser passes to `pushManager.subscribe()` as
`applicationServerKey`.

- `--file` writes the private key, owner-readable only. Pipe it straight
  into the secret: `wrangler secret put VAPID_PRIVATE_KEY < that file`.
- The private key is **never** printed without `--print-private`.
- An existing `--file` is not overwritten without `--force`, and both the
  refusal and the `--force` run say what a rotation costs: every existing
  browser subscription, none of which a server can recreate — each browser
  has to subscribe again, with the user back on the site.
- Neither `--file` nor `--print-private` is refused: the run would keep no
  private key, and the public half alone is useless.

A venture generates one of these once and keeps it forever.

### `fz push send --transport apns|fcm|web-push --recipient … --title … --body …`

Builds the venture's adapters from its environment and sends **one**
notification — the live-proof tool (issue #186) and the first thing support
runs. The report names the transport, a fingerprint of the recipient (never
the token, the endpoint or the `auth` secret), the transport's wiring
verdict, and then the outcome: `DELIVERED`, `FAILED` with the provider's
reason and what to do about it, or `NOT SENT` with the reason nothing was
routed.

`--recipient` is the bare device/registration token for `apns` and `fcm`,
and the browser's subscription JSON for `web-push` (`{"endpoint":…,
"keys":{"p256dh":…,"auth":…}}`, or the flattened form). Also `--data`,
`--url`, `--ttl`, `--priority` and `--silent`.

`--dry-run` reports which transport would carry the send and why, without
sending — it builds no HTTP client at all, so it cannot reach the network.

The send itself needs the crate's `push-send` feature, which pulls the
native runtime's HTTP client (reqwest behind the outbound policy) and the
tokio runtime it needs — the same shape `fz migrations apply` needs
`postgres`, and for the same reason:

```toml
[dependencies]
cratefield-cli = { version = "0.1", features = ["push-send"] }
```

Without it every other `fz push` command still works, `--dry-run` included,
and `send` says exactly that in one line. That outbound policy refuses
loopback, private and link-local destinations, so a self-hosted push service
on a private network is refused by the client, not by the protocol.

### `fz push inspect-subscription <json>`

Validates a Web Push subscription with the adapter's own rules and prints
the `aud` it will sign for it — the push service's origin, never the
subscription's path, because a path-bearing `aud` is the commonest cause of
a VAPID `401`. Catches an endpoint that is not an absolute http(s) URL, a
`p256dh` that is not a 65-byte uncompressed P-256 point on the curve, and an
`auth` that is not 16 bytes.

## `fz modules`

Prints `name version /v1/<name> emits=[…] tables=[…]` per module.

## Applying migrations (wrangler)

Staging and production run the same commands from the venture repo:

```sh
# staging (first time / new migrations)
wrangler d1 migrations apply <database-name> --remote --env staging

# production
wrangler d1 migrations apply <database-name> --remote --env production
```

Locally: `wrangler d1 migrations apply <database-name> --local`.
