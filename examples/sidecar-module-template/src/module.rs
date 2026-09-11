//! The module this sidecar serves. This file is the part you edit: it is
//! written for someone who has never read the harness internals, and the
//! whole contract it relies on is one trait, [`Module`].
//!
//! A module never touches Cloudflare, environment variables or a vendor
//! client (ADR 0002). It declares what it needs — here, the `Database`
//! port — and the harness hands those ports to it inside
//! [`ModuleContext`]. The same crate mounted in-process on a host serves
//! byte-identical answers, which is why you can move it between mounts
//! without changing this file (docs/MOUNTING.md).

use axum::extract::State;
use axum::routing::{get, post};
use cratefield_core::{
    Action, Audience, Clock, Config, ConfigError, IdGen, Json, Migrations, Module, ModuleConfig,
    ModuleContext, Outcome, Port, Problem, Scope, SqlMigration, Statement, Surface, SystemClock,
    UlidIdGen, View,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

/// Mounted at `/v1/notes` on whichever Worker serves this harness.
const MODULE_NAME: &str = "notes";

/// The one table, created by the one migration below. The name must match
/// `tables()` — `fz doctor` checks for collisions across every module on
/// the database, and this template's stream and the host's stream share
/// one database (docs/MIGRATION-STREAMS.md).
const TABLE: &str = "sidecar_notes";

/// Days a note is kept before the scheduled purge deletes it. Compile-time
/// default; override per deployment with the `NOTES_RETENTION_DAYS`
/// variable (see `validate_config`).
const RETENTION_DAYS: u32 = 30;

/// The module's only migration, embedded at compile time so the crate
/// ships its own schema. Written in the portable SQL subset (ADR 0004):
/// TEXT ids and ISO-8601 TEXT timestamps, no `AUTOINCREMENT`, no
/// `NOW()`. It is idempotent, because the conformance kit applies the
/// set twice and wrangler can re-apply a stream after a partial run.
const MIGRATION_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
};

/// The notes module: one table, one public write, one public read, and a
/// retention purge on the cron.
///
/// The purge is why this template's Worker declares its own cron trigger.
/// `serve_scheduled` fans a cron out to the modules of the Worker that
/// received it — and the host's Worker never receives this one's cron,
/// because the two Workers have separate trigger configurations. A
/// scheduled hook without a `[triggers]` block in `wrangler.toml` is
/// dead code that still passes every test.
pub struct Notes;

impl Default for Notes {
    fn default() -> Self {
        Self::new()
    }
}

impl Notes {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Module for Notes {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// The ports this module refuses to start without. `Harness::build`
    /// fails if the runtime does not provide one, which turns "the
    /// binding is missing" from a runtime 500 into a build error.
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }

    fn tables(&self) -> &'static [&'static str] {
        &[TABLE]
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    /// Reads `NOTES_RETENTION_DAYS` from the deployment configuration and
    /// rejects a value a retention rule cannot act on. This runs in
    /// `fz doctor` (no config there, so only the compile-time default is
    /// checked) and once per isolate at cold start, where a bad value is
    /// logged loudly instead of silently disabling the purge.
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new(MODULE_NAME, cfg);
        let mut errors = ConfigError::default();
        if let Some(raw) = cfg
            .get(&module.key("RETENTION_DAYS"))
            .map(|raw| raw.parse::<u32>())
            && matches!(raw, Ok(0) | Err(_))
        {
            errors.push(format!(
                "notes: {} must be a positive integer",
                module.key("RETENTION_DAYS")
            ));
        }
        errors.into_result()
    }

    /// The routes. Whatever is mounted here the caller reaches at
    /// `/v1/<module name>/...`, in-process or as a sidecar — a caller
    /// cannot tell which, so nothing here may care where it runs.
    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ctx);
        axum::Router::new()
            .route("/", post(insert_note).with_state(Arc::clone(&state)))
            .route("/latest", get(latest_note).with_state(state))
    }

    /// The UI surface (ADR 0010): the write as a form the host's `/ui`
    /// renders. A mounted sidecar's surface is fetched over `/__surface`
    /// and merged by the host, so this renders like any other module's.
    fn surface(&self) -> Surface {
        Surface::new()
            .action(
                Action::post("insert", "/")
                    .input::<InsertBody>()
                    .accepted("Note stored."),
            )
            .action(
                Action::get("latest", "/latest")
                    .audience(Audience::Public)
                    .outcome(Outcome::Json),
            )
            .view(View::form("insert"))
            .view(View::status("latest"))
    }

    /// The retention purge: deletes rows older than the configured number
    /// of days, whenever the Worker's own cron fires. The cron expression
    /// lives in `wrangler.toml` (`[triggers]`), not here — code cannot
    /// schedule itself on Workers.
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> cratefield_core::BoxFuture<'a, Result<(), cratefield_core::AnyError>> {
        Box::pin(async move {
            let Some(db) = ctx.ports.db.clone() else {
                return Ok(());
            };
            let cfg = ModuleConfig::new(MODULE_NAME, &*ctx.config);
            let days = i64::from(cfg.get_u32("RETENTION_DAYS", RETENTION_DAYS));
            let cutoff = SystemClock
                .now()
                .replace_nanosecond(0)
                .expect("truncation stays in range")
                .saturating_sub(time::Duration::seconds(days.saturating_mul(86_400)))
                .format(&Rfc3339)
                .unwrap_or_default();
            let query = sea_query::Query::delete()
                .from_table(sea_query::Alias::new(TABLE))
                .cond_where(
                    sea_query::Expr::col((
                        sea_query::Alias::new(TABLE),
                        sea_query::Alias::new("created_at"),
                    ))
                    .lt(cutoff),
                )
                .to_owned();
            let deleted = db.execute(&Statement::render(&query)).await.map_err(
                |err| -> cratefield_core::AnyError {
                    Box::new(PurgeError {
                        source: err.to_string(),
                    })
                },
            )?;
            // Log only when something happened, so a quiet cron is not a
            // stream of noise — but do log, because a purge that stopped
            // running must be findable in Workers Logs.
            if deleted > 0 {
                tracing::info!(deleted, cron, "purged expired notes");
            }
            Ok(())
        })
    }
}

/// The scheduled hook's one failure mode, wrapped so a bad database day
/// fails the cron loudly in the logs instead of looking like "nothing to
/// do".
#[derive(Debug)]
struct PurgeError {
    source: String,
}

impl std::fmt::Display for PurgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "notes retention purge failed: {}", self.source)
    }
}

impl std::error::Error for PurgeError {}

#[derive(Deserialize, JsonSchema)]
struct InsertBody {
    #[schemars(extend("x-cf-label" = "Note", "x-cf-widget" = "textarea"))]
    text: String,
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

/// `POST /v1/notes` — store one note. This is the route body the issue's
/// verification says someone replaces: change these lines, deploy, and
/// the host's mounted prefix serves your version without a rebuild of
/// the host.
async fn insert_note(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    Json(body): Json<InsertBody>,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(db) = ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let id = match ctx.ports.id_gen.as_ref() {
        Some(id_gen) => id_gen.ulid(),
        None => UlidIdGen.ulid(),
    };
    let query = sea_query::Query::insert()
        .into_table(sea_query::Alias::new(TABLE))
        .columns([
            sea_query::Alias::new("id"),
            sea_query::Alias::new("text"),
            sea_query::Alias::new("created_at"),
        ])
        .values_panic([
            id.clone().into(),
            body.text.clone().into(),
            SystemClock
                .now()
                .format(&Rfc3339)
                .unwrap_or_default()
                .into(),
        ])
        .to_owned();
    db.execute(&Statement::render(&query))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "notes insert failed");
            internal(&scope)
        })?;
    Ok(Json(json!({ "id": id })))
}

/// `GET /v1/notes/latest` — the most recent note, or `null`.
async fn latest_note(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(db) = ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let query = sea_query::Query::select()
        .columns([
            sea_query::Alias::new("id"),
            sea_query::Alias::new("text"),
            sea_query::Alias::new("created_at"),
        ])
        .from(sea_query::Alias::new(TABLE))
        .order_by(sea_query::Alias::new("created_at"), sea_query::Order::Desc)
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await.map_err(|err| {
        tracing::error!(error = %err, "notes select failed");
        internal(&scope)
    })?;
    match rows.first() {
        Some(row) => Ok(Json(json!({
            "id": row.get::<String>("id"),
            "text": row.get::<String>("text"),
            "created_at": row.get::<String>("created_at"),
        }))),
        None => Ok(Json(json!(null))),
    }
}
