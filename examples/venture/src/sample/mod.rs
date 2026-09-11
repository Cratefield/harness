//! Sample module for the venture example: one table, one write endpoint,
//! one read endpoint — the sea-query/D1 round-trip canary (issue #5).

use axum::extract::State;
use axum::routing::{get, post};
use cratefield::{
    Action, Audience, Clock, Config, ConfigError, DataKind, Disposition, IdGen, Json, Migrations,
    Module, ModuleContext, Outcome, PersonalDataSet, Port, Problem, Scope, SqlMigration, Statement,
    Surface, SystemClock, UlidIdGen, View,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub struct SampleRowModule;

const MIGRATION: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("migrations/sqlite/0001_init.sql"),
    transactional: true,
};

impl Module for SampleRowModule {
    fn name(&self) -> &'static str {
        "sample"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["sample_rows"]
    }

    /// The sample table holds an address, so it says so. A module that owns
    /// a table and declares nothing about it is outside export and erasure
    /// however plainly the schema reads (issue #244).
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[PersonalDataSet {
            table: "sample_rows",
            subject: "email",
            kind: DataKind::Contact,
            disposition: Disposition::Erase,
            description: "The address you typed into the sample form, with the date.",
            redacted: &[],
        }];
        SETS
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ctx);
        axum::Router::new()
            .route("/rows", post(insert_row).with_state(Arc::clone(&state)))
            .route(
                "/rows/latest",
                get(latest_row).with_state(Arc::clone(&state)),
            )
    }

    /// The UI surface (ADR 0010): the insert as a public form, the read as
    /// a JSON action. `GET /__surface` lists both; the CI wrangler smoke
    /// asserts the document on a real Workers request.
    fn surface(&self) -> Surface {
        Surface::new()
            .action(
                Action::post("insert", "/rows")
                    .input::<InsertBody>()
                    .accepted("Row stored."),
            )
            .action(
                Action::get("latest", "/rows/latest")
                    .audience(Audience::Public)
                    .outcome(Outcome::Json),
            )
            .view(View::form("insert"))
            .view(View::status("latest"))
    }
}

#[derive(Deserialize, JsonSchema)]
struct InsertBody {
    #[schemars(extend("x-cf-label" = "Email", "x-cf-widget" = "email"))]
    email: String,
}

fn now_iso() -> String {
    SystemClock
        .now()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

async fn insert_row(
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
        .into_table(sea_query::Alias::new("sample_rows"))
        .columns([
            sea_query::Alias::new("id"),
            sea_query::Alias::new("email"),
            sea_query::Alias::new("created_at"),
        ])
        .values_panic([
            id.clone().into(),
            body.email.clone().into(),
            now_iso().into(),
        ])
        .to_owned();
    db.execute(&Statement::render(&query))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "sample insert failed");
            internal(&scope)
        })?;
    Ok(Json(json!({ "id": id })))
}

async fn latest_row(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(db) = ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let query = sea_query::Query::select()
        .columns([
            sea_query::Alias::new("id"),
            sea_query::Alias::new("email"),
            sea_query::Alias::new("created_at"),
        ])
        .from(sea_query::Alias::new("sample_rows"))
        .order_by(sea_query::Alias::new("created_at"), sea_query::Order::Desc)
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await.map_err(|err| {
        tracing::error!(error = %err, "sample select failed");
        internal(&scope)
    })?;
    match rows.first() {
        Some(row) => Ok(Json(json!({
            "id": row.get::<String>("id"),
            "email": row.get::<String>("email"),
            "created_at": row.get::<String>("created_at"),
        }))),
        None => Ok(Json(json!(null))),
    }
}
