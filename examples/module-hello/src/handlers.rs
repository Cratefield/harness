//! Handlers for `/v1/hello` (built in docs/MODULE-AUTHORING.md): one
//! public write, one public read. The write emits `hello.recorded` on the
//! shared bus.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use factory0_core::{
    Action, Audience, IdGen, Json, ModuleConfig, ModuleContext, Outcome, Problem, Scope, Statement,
    Surface, UlidIdGen, View,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// Event emitted after a name is recorded; payload `{ "name": <str> }`.
pub(crate) const EVENT_RECORDED: &str = "hello.recorded";

/// The builder's compile-time settings, cloned into the router state.
#[derive(Clone)]
pub(crate) struct Settings {
    pub max_name_len: u32,
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
}

pub(crate) fn router(ctx: Arc<ModuleContext>, settings: Settings) -> axum::Router {
    let state = Arc::new(ModuleState { ctx, settings });
    axum::Router::new()
        .route("/", post(record))
        .route("/count", get(count))
        .with_state(state)
}

#[derive(Deserialize, JsonSchema)]
struct RecordBody {
    #[schemars(extend("x-cf-label" = "Your name", "x-cf-placeholder" = "Ada"))]
    name: String,
}

/// The module's UI surface (ADR 0010): the record form and the count as
/// a status view. Derived from `RecordBody`, the type `record` deserializes.
pub(crate) fn surface() -> Surface {
    Surface::new()
        .action(
            Action::post("record", "/")
                .input::<RecordBody>()
                .accepted("Recorded. Hello!"),
        )
        .action(
            Action::get("count", "/count")
                .audience(Audience::Public)
                .outcome(Outcome::Json),
        )
        .view(View::form("record"))
        .view(View::status("count"))
}

/// `POST /v1/hello` `{ "name": str }` -> `202 {"ok":true,"name":..}`;
/// records the visit and emits [`EVENT_RECORDED`] in this request's scope.
async fn record(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Json(body): Json<RecordBody>,
) -> Result<axum::response::Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let cfg = ModuleConfig::new("hello", &*state.ctx.config);
    let max = cfg.get_u32("MAX_NAME_LEN", state.settings.max_name_len) as usize;

    let name = body.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > max {
        return Err(
            Problem::validation_failed(format!("name must be 1..={max} characters"))
                .instance(&scope.request_id),
        );
    }

    let id = state
        .ctx
        .ports
        .id_gen
        .as_ref()
        .map_or_else(|| UlidIdGen.ulid(), |id_gen| id_gen.ulid());
    let query = sea_query::Query::insert()
        .into_table(sea_query::Alias::new("hello_visits"))
        .columns([sea_query::Alias::new("id"), sea_query::Alias::new("name")])
        .values_panic([id.into(), name.clone().into()])
        .to_owned();
    db.execute(&Statement::render(&query))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "hello insert failed");
            internal(&scope)
        })?;

    state
        .ctx
        .events
        .emit_in(&scope, EVENT_RECORDED, json!({ "name": name }));
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "ok": true, "name": name })),
    )
        .into_response())
}

/// `GET /v1/hello/count` -> `200 {"visits": n}`.
async fn count(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
) -> Result<Json<Value>, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let query = sea_query::Query::select()
        .expr_as(
            sea_query::Expr::col(sea_query::Alias::new("id")).count(),
            sea_query::Alias::new("count"),
        )
        .from(sea_query::Alias::new("hello_visits"))
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await.map_err(|err| {
        tracing::error!(error = %err, "hello count failed");
        internal(&scope)
    })?;
    let visits: i64 = rows.first().and_then(|row| row.get("count")).unwrap_or(0);
    Ok(Json(json!({ "visits": visits })))
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}
