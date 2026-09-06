# factory0-adapter-postgres

The [`Database`] port over `sqlx` Postgres 16 for the [Factory Zero
harness](https://github.com/Factory-Zero/harness) native runtime (ADR 0004,
issue #18). **Native only** — the crate fails compilation on any wasm
target with a clear message, and the sqlx dependency is target-gated to
non-wasm builds, so it can never slip into a Worker.

```rust
use factory0_adapter_postgres::Postgres;

let db = Postgres::connect("postgres://user:pass@host:5432/venture").await?;
db.apply_harness_migrations(&harness).await?;   // see below
// … through Arc<dyn Database> as with any adapter
```

- `Postgres::connect(url)` opens a pool (`sqlx` 0.8, `runtime-tokio`,
  `tls-rustls`); `batch` runs all statements in one transaction (atomic).
- Port statements arrive in the portable `?`-placeholder form rendered by
  sea-query's `SqliteQueryBuilder`; the adapter rewrites them to `$n`
  (skipping string literals, quoted identifiers and comments) and binds
  the values positionally. The migration runner's own bookkeeping is
  rendered by sea-query's `PostgresQueryBuilder`.
- `apply_harness_migrations(&Harness)` applies every module's migrations
  in lock order (module config order, then zero-padded migration id —
  the order `fz migrations collect` pins). Per module it applies the
  `postgres` migration set when the module ships one, else the `sqlite`
  set when it passes the portable-SQL lint (`factory0-core`'s
  `lint_portable_sql`, the same predicate `fz doctor` enforces).
- `apply_migrations(module, &[SqlMigration])` is the per-module entry
  point: idempotent, each migration applied in its own transaction and
  tracked under `<module>/<id>` in `harness_migrations(id, applied_at)`.
- CLI: `fz migrations apply --dialect postgres --url …` (the `fz` binary
  must be built with factory0-cli's `postgres` feature).

## The SQLite → Postgres mapping actually used

The portable subset is the intersection of both engines, so the same
migration files run verbatim:

| Portable concept | SQLite | Postgres | Notes |
|---|---|---|---|
| ULID ids | `TEXT PRIMARY KEY` | `TEXT PRIMARY KEY` | no `AUTOINCREMENT`/`SERIAL` |
| timestamps | ISO-8601 `TEXT` | ISO-8601 `TEXT` | computed in Rust, never `NOW()`/`datetime()` |
| counters | `INTEGER` | `INTEGER` (`int4`) | |
| booleans | `INTEGER 0/1` convention | `INTEGER 0/1` convention | no SQL `BOOLEAN` columns; `SeaValue::Bool` binds as `SMALLINT` 0/1 |
| upserts | `INSERT … ON CONFLICT …` | identical syntax | sea-query renders both |
| read-back writes | `INSERT … RETURNING …` | identical syntax | sea-query renders both |

## Tests

Tests that need a server are gated on `FZ_TEST_POSTGRES_URL` and skipped
with a printed reason when it is unset (CI provides a `postgres:16`
service container). Locally:

```sh
docker run --rm -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:16
export FZ_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5433/postgres
cargo test -p factory0-adapter-postgres
```
