//! Local dev server for the control-plane console — so the guarded wizard and
//! dashboard can be clicked through without Cloudflare or a Google client.
//!
//! ```sh
//! HARNESS_SECRET=dev-secret-0123456789abcdef-0123 CONSOLE_DEV_LOGIN=1 \
//!   cargo run --manifest-path crates/control-plane-dev/Cargo.toml --bin serve
//! # then open http://127.0.0.1:8787/v1/console/dev-login
//! ```
//!
//! `CONSOLE_DEV_LOGIN=1` turns on the console's dev-login shortcut (a session
//! for a fixed local operator; the module forbids it in production). The DB is
//! in-memory SQLite, migrated from the console's own schema.

use std::sync::Arc;

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{Database, Harness, Module, Venture};
use cratefield_runtime_native::{Native, serve_on};
use tokio::net::TcpListener;

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

    // In-memory SQLite, migrated from the console's own schema set.
    let db = SqliteDatabase::in_memory().expect("open sqlite");
    db.apply_migrations("console", cratefield_console::Console.migrations().sqlite)
        .expect("apply console migrations");
    let db: Arc<dyn Database> = Arc::new(db);

    let harness = Arc::new(
        Harness::builder()
            .venture(
                Venture::new("cratefield-control-plane", "localhost")
                    .public_url("http://127.0.0.1:8787")
                    .cors_origins(["http://127.0.0.1:8787"]),
            )
            .module(cratefield_console::Console)
            .runtime(Native::new().db_arc(Arc::clone(&db)))
            .build()
            .expect("the control-plane harness is valid"),
    );
    let runtime = Native::new().db_arc(db);

    let listener = TcpListener::bind("127.0.0.1:8787").await.expect("bind");
    eprintln!("console dev server on http://127.0.0.1:8787");
    eprintln!("  sign in:   http://127.0.0.1:8787/v1/console/dev-login");
    eprintln!("  wizard:    http://127.0.0.1:8787/v1/console/new");
    serve_on(harness, runtime, listener).await.expect("serve");
}
