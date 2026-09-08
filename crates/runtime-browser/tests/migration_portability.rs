//! Kill-signal 2 (the compose engine's second gate): every built-in module's
//! migrations must apply cleanly against *plain* SQLite, because the browser
//! runtime runs them on sqlite-wasm — not D1. This catches D1-isms (batch
//! semantics, `PRAGMA`s, D1-only SQL) before they reach a browser where they
//! are far harder to diagnose.
//!
//! It runs natively over `cratefield-adapter-sqlite` (rusqlite, the same
//! portable SQLite dialect sqlite-wasm speaks), so it is a real headless test.

#![cfg(not(target_arch = "wasm32"))]

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::Module;

fn modules() -> Vec<Box<dyn Module>> {
    vec![
        Box::new(cratefield_module_waitlist::Waitlist::default()),
        Box::new(cratefield_module_email_signup::EmailSignup::default()),
        Box::new(cratefield_module_cms::Cms::default()),
    ]
}

/// Each module's migrations apply cleanly to a fresh plain-SQLite database,
/// and re-applying is idempotent (the `harness_migrations` ledger short-circuits).
#[test]
fn each_module_migrates_on_plain_sqlite() {
    for module in modules() {
        let db = SqliteDatabase::in_memory().expect("open in-memory sqlite");
        let migrations = module.migrations().sqlite;
        assert!(
            !migrations.is_empty() || module.tables().is_empty(),
            "module `{}` declares tables but ships no migrations",
            module.name()
        );

        db.apply_migrations(module.name(), migrations)
            .unwrap_or_else(|err| {
                panic!(
                    "module `{}` failed to migrate on plain sqlite: {err}",
                    module.name()
                )
            });
        // Idempotent: a second apply is a no-op, not an error.
        db.apply_migrations(module.name(), migrations)
            .unwrap_or_else(|err| {
                panic!(
                    "module `{}` re-apply was not idempotent: {err}",
                    module.name()
                )
            });
    }
}

/// All three modules compose into ONE database (as they do in the browser
/// monolith) without migration-id or table collisions.
#[test]
fn all_modules_compose_into_one_database() {
    let db = SqliteDatabase::in_memory().expect("open in-memory sqlite");
    for module in modules() {
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .unwrap_or_else(|err| panic!("composing module `{}` failed: {err}", module.name()));
    }
}
