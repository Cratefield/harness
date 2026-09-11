//! Local dev server for the control-plane console and dashboard — so the
//! guarded wizard and the account dashboard can be clicked through without
//! Cloudflare or a Google client.
//!
//! ```sh
//! HARNESS_SECRET=dev-secret-0123456789abcdef-0123 CONSOLE_DEV_LOGIN=1 \
//!   cargo run --manifest-path crates/control-plane-dev/Cargo.toml --bin serve
//! # then open http://127.0.0.1:8787/v1/console/dev-login
//! ```
//!
//! `CONSOLE_DEV_LOGIN=1` turns on the console's dev-login shortcut (a session
//! for a fixed local operator; the module forbids it in production). The DB is
//! in-memory SQLite, migrated from the modules' own schemas.
//!
//! The dev operator is seeded with four ventures, one per health verdict, so
//! the distinction the dashboard exists to make — a degraded venture reads as
//! DEGRADED, never as loading — is visible on the first page load. A `Live`
//! venture here reads unreachable, and that is the truthful verdict: nothing
//! is deployed behind `*.cratefield.app` from a laptop.

use std::sync::Arc;

use cratefield_accounts::{Repository, VentureStatus};
use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{Database, Harness, Module, Statement, Venture};
use cratefield_runtime_native::{Native, serve_on};
use tokio::net::TcpListener;

/// The identity the console's dev-login mints a session for.
const DEV_OPERATOR: &str = "dev@cratefield.local";

#[tokio::main]
async fn main() {
    if std::env::var("HARNESS_SECRET").is_err() {
        eprintln!(
            "set HARNESS_SECRET (>= 32 bytes) and CONSOLE_DEV_LOGIN=1, e.g.\n  \
             HARNESS_SECRET=dev-secret-0123456789abcdef-0123 CONSOLE_DEV_LOGIN=1 \
             cargo run --manifest-path crates/control-plane-dev/Cargo.toml --bin serve"
        );
        std::process::exit(1);
    }

    // In-memory SQLite, migrated from each module's own schema set. The two
    // modules share sub-schemas (accounts, provisioning) on purpose — the
    // dashboard reads what the console writes — so the second apply must be
    // a no-op rather than a duplicate-table error.
    let db = SqliteDatabase::in_memory().expect("open sqlite");
    db.apply_migrations("console", cratefield_console::Console.migrations().sqlite)
        .expect("apply console migrations");
    db.apply_migrations(
        "dashboard",
        cratefield_dashboard::Dashboard.migrations().sqlite,
    )
    .expect("apply dashboard migrations");
    let db: Arc<dyn Database> = Arc::new(db);

    seed(&db).await;

    let harness = Arc::new(
        Harness::builder()
            .venture(
                Venture::new("cratefield-control-plane", "localhost")
                    .public_url("http://127.0.0.1:8787")
                    .cors_origins(["http://127.0.0.1:8787"]),
            )
            .module(cratefield_console::Console)
            .module(cratefield_dashboard::Dashboard)
            .runtime(Native::new().db_arc(Arc::clone(&db)))
            .build()
            .expect("the control-plane harness is valid"),
    );
    let runtime = Native::new().db_arc(db);

    let listener = TcpListener::bind("127.0.0.1:8787").await.expect("bind");
    eprintln!("control-plane dev server on http://127.0.0.1:8787");
    eprintln!("  sign in:   http://127.0.0.1:8787/v1/console/dev-login");
    eprintln!("  dashboard: http://127.0.0.1:8787/v1/dashboard");
    eprintln!("  wizard:    http://127.0.0.1:8787/v1/console/new");
    serve_on(harness, runtime, listener).await.expect("serve");
}

/// Four ventures for the dev operator, one per health verdict.
async fn seed(db: &Arc<dyn Database>) {
    let repo = Repository::new(Arc::clone(db));
    let account = repo
        .account_for_login(DEV_OPERATOR, "Dev Operator", "acc_dev", "2026-01-01T00:00:00Z")
        .await
        .expect("seed the dev account");

    // (id, slug, module set, the status to land on)
    let plan = [
        ("v_draft", "draft-app", "cms", VentureStatus::Draft),
        ("v_live", "live-app", "cms+waitlist", VentureStatus::Live),
        (
            "v_broken",
            "broken-app",
            "cms+waitlist+notifications",
            VentureStatus::Degraded,
        ),
        ("v_old", "old-app", "cms", VentureStatus::Archived),
    ];

    for (id, slug, modules, status) in plan {
        repo.create_venture(
            id,
            &account.id,
            slug,
            &format!("{slug}.cratefield.app"),
            modules,
            "ten_dev",
            "2026-01-01T00:00:00Z",
        )
        .await
        .expect("seed a venture");
        if status != VentureStatus::Draft {
            repo.set_venture_status(
                &account.id,
                id,
                VentureStatus::Provisioning,
                "2026-01-01T00:01:00Z",
            )
            .await
            .expect("seed provisioning");
            repo.set_venture_status(&account.id, id, status, "2026-01-01T00:02:00Z")
                .await
                .expect("seed status");
        }
    }

    // The degraded venture's recorded failure. This is the row the dashboard
    // renders instead of a spinner, and the reason issue #11 exists.
    db.execute(&Statement::with_values(
        "INSERT INTO provision_progress (venture_id, last_step, error, updated_at) \
         VALUES (?, ?, ?, ?)",
        vec![
            text("v_broken"),
            text("deploy-worker"),
            text("the Cloudflare API refused the upload: script too large (1.2 MiB over the limit)"),
            text("2026-01-01T00:02:00Z"),
        ],
    ))
    .await
    .expect("seed the recorded failure");
}

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}
