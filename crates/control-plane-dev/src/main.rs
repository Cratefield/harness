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
//!
//! The secrets manager is wired for real: a `LocalFileKms` under a
//! development key file (`DASHBOARD_DEV_KEK`, or one generated under the
//! working directory on first boot), the durable audit chain, and two
//! obviously-fake seeded secrets so the screen has something truthful to
//! show. `DASHBOARD_DEV_KEK` in a production environment is refused twice —
//! by the dashboard's `validate_config` and by `LocalFileKms` itself.

use std::sync::Arc;

use cratefield_accounts::{Repository, VentureStatus};
use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{Database, Harness, Module, Statement, Venture};
use cratefield_kms::{Kms, LocalFileKms};
use cratefield_secrets::{Actor, SecretBytes, Secrets, chain_sink};
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
    // a no-op rather than a duplicate-table error. The dashboard's set now
    // carries the secrets store's tables too, under its own ids.
    let db = SqliteDatabase::in_memory().expect("open sqlite");
    db.apply_migrations("console", cratefield_console::Console.migrations().sqlite)
        .expect("apply console migrations");
    db.apply_migrations(
        "dashboard",
        cratefield_dashboard::Dashboard::default().migrations().sqlite,
    )
    .expect("apply dashboard migrations");
    let db: Arc<dyn Database> = Arc::new(db);

    let kms = dev_kms().unwrap_or_else(|err| {
        eprintln!("the development key manager could not be wired: {err}");
        std::process::exit(1);
    });

    seed(&db).await;
    seed_secrets(&db, &Secrets::new(kms.clone()).with_audit(chain_sink(Arc::clone(&db)))).await;

    let harness = Arc::new(
        Harness::builder()
            .venture(
                Venture::new("cratefield-control-plane", "localhost")
                    .public_url("http://127.0.0.1:8787")
                    .cors_origins(["http://127.0.0.1:8787"]),
            )
            .module(cratefield_chrome::Chrome)
            .module(cratefield_console::Console)
            .module(cratefield_dashboard::Dashboard::new(Some(kms)))
            .runtime(Native::new().db_arc(Arc::clone(&db)))
            .build()
            .expect("the control-plane harness is valid"),
    );
    let runtime = Native::new().db_arc(db);

    // 8787 by default like wrangler; `PORT` moves it, so two developers
    // (or a wrangler session) can hold their own ports on one machine.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(8787);
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap_or_else(|err| panic!("bind 127.0.0.1:{port}: {err}"));
    eprintln!("control-plane dev server on http://127.0.0.1:{port}");
    eprintln!("  sign in:   http://127.0.0.1:{port}/v1/console/dev-login");
    eprintln!("  dashboard: http://127.0.0.1:{port}/v1/dashboard");
    eprintln!("  secrets:   http://127.0.0.1:{port}/v1/dashboard/secrets");
    eprintln!("  wizard:    http://127.0.0.1:{port}/v1/console/new");
    serve_on(harness, runtime, listener).await.expect("serve");
}

/// Wires the development key manager for the secrets screen.
///
/// `DASHBOARD_DEV_KEK` names a key file to use — which must already
/// exist, because pointing at a path nothing wrote is a configuration
/// mistake to fix, not a reason to invent a key beside it. With the
/// variable unset, a development key is generated under the working
/// directory on first boot and never overwritten: losing a KEK means
/// losing every secret wrapped under it, so the destructive version of
/// this is a human deleting the file on purpose.
fn dev_kms() -> Result<Arc<dyn Kms>, cratefield_kms::KmsError> {
    let env = std::env::var("ENV").unwrap_or_default();
    let generate = std::env::var_os("DASHBOARD_DEV_KEK").is_none();
    let path = if generate {
        std::path::PathBuf::from("control-plane-dev.kek")
    } else {
        std::path::PathBuf::from(std::env::var_os("DASHBOARD_DEV_KEK").expect("just checked"))
    };
    if generate && !path.exists() {
        LocalFileKms::create(&path)?;
        eprintln!(
            "  ⚠  generated a DEVELOPMENT master key at {}. It is a local file: \
               anything that can read it can unwrap every secret this server \
               stores. Never point a production deployment at it — \
               DASHBOARD_DEV_KEK is refused in production.",
            path.display()
        );
    }
    Ok(Arc::new(LocalFileKms::open(&path, &env)?))
}

/// Four ventures for the dev operator, one per health verdict. Each gets
/// its own tenant so the secrets store list shows four real stores, not
/// one store wearing four names.
async fn seed(db: &Arc<dyn Database>) {
    let repo = Repository::new(Arc::clone(db));
    let account = repo
        .account_for_login(DEV_OPERATOR, "Dev Operator", "acc_dev", "2026-01-01T00:00:00Z")
        .await
        .expect("seed the dev account");

    // (id, slug, module set, tenant, the status to land on)
    let plan = [
        ("v_draft", "draft-app", "cms", "ten_draft", VentureStatus::Draft),
        (
            "v_live",
            "live-app",
            "cms+waitlist",
            "ten_live",
            VentureStatus::Live,
        ),
        (
            "v_broken",
            "broken-app",
            "cms+waitlist+notifications",
            "ten_broken",
            VentureStatus::Degraded,
        ),
        ("v_old", "old-app", "cms", "ten_old", VentureStatus::Archived),
    ];

    for (id, slug, modules, tenant, status) in plan {
        repo.create_venture(
            id,
            &account.id,
            slug,
            &format!("{slug}.cratefield.app"),
            modules,
            tenant,
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

/// Two plausible secrets, with obviously fake values: a platform key in
/// the global store and the live venture's Google client secret in its
/// tenant store. Seeding is the composition acting, not an operator, so
/// the actor names the job — and both `put`s land on the audit chains
/// the screen then shows verifying.
async fn seed_secrets(db: &Arc<dyn Database>, secrets: &Secrets) {
    let actor = Actor::new("dev-seed").expect("a job name is never empty");
    secrets
        .control_plane_global(Arc::clone(db))
        .put(
            "platform/demo-signing-key",
            &SecretBytes::from("dev-platform-key-obviously-fake-do-not-use"),
            &actor,
        )
        .await
        .expect("seed the platform key");
    secrets
        .tenant("ten_live", Arc::clone(db))
        .put(
            "venture-google-client-secret",
            &SecretBytes::from("GOCSPX-dev-only-obviously-fake-client-secret"),
            &actor,
        )
        .await
        .expect("seed the venture's client secret");
}

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}
