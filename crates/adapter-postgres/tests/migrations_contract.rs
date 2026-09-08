//! Contract test (issue #18): every migration shipped in this repo also
//! applies cleanly on Postgres 16, idempotently, through the same runner
//! `fz migrations apply --dialect postgres` uses.
//!
//! Skipped with a printed reason when `FZ_TEST_POSTGRES_URL` is unset; CI
//! provides a `postgres:16` service container.

mod common;

use axum::Router;
use common::{TempDb, base_url, skip_reason};
use cratefield_adapter_postgres::Postgres;
use cratefield_core::{
    Config, ConfigError, Database, DbError, Harness, Migrations, Module, ModuleContext, Port,
    Runtime, SqlMigration, Statement, Venture,
};
use cratefield_module_email_signup::EmailSignup;
use cratefield_module_waitlist::Waitlist;
use std::sync::Arc;

struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

fn repo_harness() -> Harness {
    Harness::builder()
        .venture(
            Venture::new("contract", "contract.example").cors_origins(["https://contract.example"]),
        )
        .module(EmailSignup::new())
        .module(Waitlist::new())
        .runtime(AllPorts)
        .build()
        .expect("contract harness builds")
}

#[tokio::test]
async fn every_shipped_migration_applies_on_postgres_16() {
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(temp) = TempDb::create(&base, "contract").await else {
        panic!("throwaway database creation failed");
    };
    temp.assert_postgres_16().await;

    let harness = repo_harness();
    let db = Postgres::connect(&temp.url)
        .await
        .expect("connect to the throwaway database");

    db.apply_harness_migrations(&harness)
        .await
        .expect("every shipped migration applies on Postgres 16");

    // Re-running is a no-op (lock order + tracking table).
    db.apply_harness_migrations(&harness)
        .await
        .expect("re-apply is idempotent");

    // Inventory of every shipped migration, tracked as <module>/<id> —
    // appending a migration to a module means appending it here too.
    let rows = db
        .query(&Statement::new(
            "SELECT id FROM harness_migrations ORDER BY id",
        ))
        .await
        .expect("tracking rows are readable");
    let ids: Vec<String> = rows
        .rows
        .iter()
        .filter_map(|row| row.get::<String>("id"))
        .collect();
    assert_eq!(
        ids,
        [
            "email-signup/0001",
            "email-signup/0002",
            "waitlist/0001",
            "waitlist/0002",
            "waitlist/0003"
        ]
    );

    // The tables exist with the columns the modules query: the portable
    // DDL really landed (missing columns would error).
    for table in ["subscribers", "waitlist_entries", "waitlist_send_cooldown"] {
        db.query(&Statement::new(format!(
            "SELECT * FROM {table} WHERE 1 = 0"
        )))
        .await
        .unwrap_or_else(|err| panic!("table {table} is queryable: {err}"));
    }

    temp.finish().await;
}

#[tokio::test]
async fn runner_applies_a_module_directly_and_is_idempotent() {
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(temp) = TempDb::create(&base, "runner").await else {
        panic!("throwaway database creation failed");
    };
    temp.assert_postgres_16().await;

    let db = Postgres::connect(&temp.url).await.expect("connect");
    let waitlist = Waitlist::new();
    let set = cratefield_adapter_postgres::select_set(&waitlist.migrations())
        .expect("the waitlist sqlite set passes the portable lint");

    db.apply_migrations(waitlist.name(), set)
        .await
        .expect("applies per-module without a harness");
    db.apply_migrations(waitlist.name(), set)
        .await
        .expect("second run is a no-op");

    let rows = db
        .query(&Statement::new("SELECT id FROM harness_migrations"))
        .await
        .expect("tracking readable");
    assert_eq!(rows.len(), 3, "all shipped waitlist migrations are tracked");

    // Through the port as a trait object, like a venture wires it.
    let port: Arc<dyn Database> = Arc::new(db);
    let rows = port
        .query(&Statement::new(
            "SELECT COUNT(*) AS n FROM waitlist_entries",
        ))
        .await
        .expect("counts through Arc<dyn Database>");
    assert_eq!(rows.first().and_then(|row| row.get::<i64>("n")), Some(0));

    temp.finish().await;
}

#[tokio::test]
async fn non_portable_sqlite_set_is_refused_not_applied() {
    const SERIAL: SqlMigration = SqlMigration {
        id: "0001",
        name: "oops",
        sql: "CREATE TABLE t (id SERIAL PRIMARY KEY);",
    };
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(temp) = TempDb::create(&base, "lint").await else {
        panic!("throwaway database creation failed");
    };
    let db = Postgres::connect(&temp.url).await.expect("connect");

    let err = db
        .apply_harness_migrations(&harness_with(&[SERIAL]))
        .await
        .expect_err("SERIAL sqlite set must be refused for Postgres");
    let DbError::Batch(message) = &err else {
        panic!("expected DbError::Batch, got {err:?}");
    };
    assert!(message.contains("portable-SQL lint"), "message: {message}");
    assert!(message.contains("0001/oops"), "message: {message}");

    temp.finish().await;
}

/// A minimal harness around one migration set (for the refusal case).
fn harness_with(migrations: &'static [SqlMigration]) -> Harness {
    struct OneModule(&'static [SqlMigration]);
    impl Module for OneModule {
        fn name(&self) -> &'static str {
            "one"
        }
        fn version(&self) -> &'static str {
            "0.0.0"
        }
        fn requires(&self) -> &'static [Port] {
            &[]
        }
        fn migrations(&self) -> Migrations {
            Migrations::sqlite(self.0)
        }
        fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
            Ok(())
        }
        fn router(&self, _ctx: ModuleContext) -> Router {
            Router::new()
        }
    }
    Harness::builder()
        .venture(Venture::new("one", "one.example").cors_origins(["https://one.example"]))
        .module(OneModule(migrations))
        .runtime(AllPorts)
        .build()
        .expect("one-module harness builds")
}

/// Forward-only enforced by the database, not by one repository's
/// lockfile: an applied migration whose SQL changed is refused, and a
/// database written before checksums were recorded keeps working
/// (issues #28, #34). The SQLite adapter asserts the same, and the two
/// must not drift.
#[tokio::test]
async fn an_edited_migration_is_refused_and_pre_checksum_rows_are_tolerated() {
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(temp) = TempDb::create(&base, "checksum").await else {
        panic!("throwaway database creation failed");
    };
    let db = Postgres::connect(&temp.url).await.expect("connect");

    let first = [SqlMigration {
        id: "0001",
        name: "init",
        sql: "CREATE TABLE IF NOT EXISTS widgets (id text PRIMARY KEY)",
    }];
    db.apply_migrations("widgets", &first)
        .await
        .expect("applies");
    db.apply_migrations("widgets", &first)
        .await
        .expect("second run is a no-op");

    let edited = [SqlMigration {
        id: "0001",
        name: "init",
        sql: "CREATE TABLE IF NOT EXISTS widgets (id text PRIMARY KEY, colour text)",
    }];
    let err = db
        .apply_migrations("widgets", &edited)
        .await
        .expect_err("an edited migration must be refused");
    let message = err.to_string();
    assert!(message.contains("widgets/0001"), "{message}");
    assert!(message.contains("write a new migration"), "{message}");

    // A row recorded before checksums existed reads as applied and
    // unverifiable, never as a mismatch.
    db.execute(&Statement::new(
        "UPDATE harness_migrations SET checksum = NULL WHERE id = 'widgets/0001'",
    ))
    .await
    .expect("simulate a pre-checksum row");
    db.apply_migrations("widgets", &edited)
        .await
        .expect("an old row is tolerated, not a mismatch");

    temp.finish().await;
}
