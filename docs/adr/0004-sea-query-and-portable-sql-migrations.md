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
- `fz migrations collect` writes wrangler-compatible files into the venture
  repo and pins module -> global mapping in `migrations/.harness-lock.json`.

## Alternatives considered
- `sqlx` everywhere: its runtime and drivers do not compile to wasm32-unknown-unknown; it stays in the native Postgres adapter only.
- `diesel`: synchronous, native drivers, same problem.
- `sea-orm`: pulls sqlx; too heavy for two tables.

## Consequences
- Migrations are reviewed as plain SQL.
- Phase 3 adds the Postgres adapter and a parity suite that runs module tests on both engines.
