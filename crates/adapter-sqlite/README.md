# factory0-adapter-sqlite

The [`Database`] port over `rusqlite` (bundled SQLite) for the Factory
Zero harness. Native only — never compiled to wasm. Used by every module
test and by `factory0-testing`, and viable for a single-node self-hosted
deployment (ADR 0004).

```rust,ignore
use factory0_adapter_sqlite::SqliteDatabase;

let db = SqliteDatabase::in_memory()?;          // or ::open("venture.db")
db.apply_migrations("email-signup", &migrations)?; // tracked in harness_migrations
// ... through Arc<dyn Database> as usual
```

- `batch` runs all statements in one transaction (atomic).
- `apply_migrations(module, &[SqlMigration])` is idempotent: each
  migration is tracked under `<module>/<id>` in a `harness_migrations`
  table and applied in its own transaction.
- The `rusqlite` connection is `!Sync`, so it lives behind a mutex; this
  is connection guarding, not request state (see the workspace
  `clippy.toml` policy).
