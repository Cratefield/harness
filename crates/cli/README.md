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
data export` / `fz data import`, `fz doctor`, `fz modules`.

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
