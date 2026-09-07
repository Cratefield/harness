<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-sqlite"><img src="https://img.shields.io/crates/v/cratefield-adapter-sqlite.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-sqlite on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-sqlite"><img src="https://img.shields.io/docsrs/cratefield-adapter-sqlite?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-sqlite documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-sqlite

The [`Database`] port over `rusqlite` (bundled SQLite) for the Factory
Zero harness. Native only — never compiled to wasm. Used by every module
test and by `cratefield-testing`, and viable for a single-node self-hosted
deployment (ADR 0004).

```rust,ignore
use cratefield_adapter_sqlite::SqliteDatabase;

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
