# ADR 0004: sea-query for queries, hand-written portable SQL for migrations

Status: accepted, 2026-09-05

## Context
D1 is SQLite. The later target is Postgres. We want one query layer that
renders for either engine, and one migration story both accept, without an
ORM that forks per dialect or drags a runtime into wasm.

## Decision
- Queries are built with `sea-query` (pure Rust, no I/O, wasm-safe) and rendered
  with `SqliteQueryBuilder` or `PostgresQueryBuilder` by the adapter. Module
  code never writes raw SQL strings for queries.
- Migrations are SQL files per module, `migrations/sqlite/NNNN_name.sql`,
  embedded with `include_str!`, with `migrations/postgres/` overrides only
  where the SQL truly differs.
- Portable subset: `TEXT` ULID ids, ISO-8601 `TEXT` timestamps, `INTEGER`
  counters, no `AUTOINCREMENT`, no dialect functions in DDL. `fz doctor` lints it.
- BLOB columns are in the subset too: a module binds and reads
  `sea_query::Value::Bytes`, and every adapter round-trips it as bytes.
- `fz migrations collect` writes wrangler-compatible files into the venture
  repo and pins module -> global mapping in `migrations/.harness-lock.json`.

## Alternatives considered
- `sqlx` everywhere: its runtime and drivers do not compile to wasm32-unknown-unknown; it stays in the native Postgres adapter only.
- `diesel`: synchronous, native drivers, same problem.
- `sea-orm`: pulls sqlx; too heavy for two tables.

## Consequences
- Migrations are reviewed as plain SQL.
- Phase 3 adds the Postgres adapter and a parity suite that runs module tests on both engines.
- The two wasm adapters encode `Bytes` differently on the wire, on purpose:
  D1 binds a native `js_sys::Uint8Array` (its bridge crosses JsValue), while
  adapter-sqlite-wasm crosses a JSON string and uses the tagged
  `{"$bytes": "<base64>"}` form. The difference stays inside each adapter's
  marshalling boundary — module code only ever sees `sea_query::Value`,
  `Bytes` in, `Bytes` out — so it is a property of the bridges, not a bug to
  unify away, and `cratefield_testing::assert_blob_round_trips` is the
  cross-engine guard that pins the round trip.
