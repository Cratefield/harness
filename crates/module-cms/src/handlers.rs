//! Routes, request bodies and the UI surface for the CMS module.
//!
//! Public routes are reads only: a venture's pages fetch published content.
//! Every write is an admin action, gated by the harness `ADMIN_TOKEN` bearer
//! ([`require_admin`]); the module has no public write endpoint, so it needs
//! no captcha.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use cratefield_core::{
    Action, Audience, Clock, Column, IdGen, ModuleContext, Outcome, Problem, Scope, Surface,
    SystemClock, UlidIdGen, View, require_admin,
};
use http::HeaderMap;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::store;
use crate::{Collections, Settings};

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
}

pub(crate) fn router(ctx: Arc<ModuleContext>, settings: Settings) -> axum::Router {
    let state = Arc::new(ModuleState { ctx, settings });
    axum::Router::new()
        // Public reads.
        .route("/{collection}", get(read_collection))
        .route("/{collection}/{slug}", get(read_item))
        // Admin writes and listing.
        .route("/admin/save", post(admin_save))
        .route("/admin/publish", post(admin_publish))
        .route("/admin/unpublish", post(admin_unpublish))
        .route("/admin/delete", post(admin_delete))
        .route("/admin/list", get(admin_list))
        .with_state(state)
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

fn db_of(state: &ModuleState) -> Option<Arc<dyn cratefield_core::Database>> {
    state.ctx.ports.db.clone()
}

/// Rejects a collection the venture did not allow, so a caller cannot invent
/// collections. `Ok` when the venture accepts any collection.
fn check_collection(state: &ModuleState, scope: &Scope, collection: &str) -> Result<(), Problem> {
    match &state.settings.collections {
        Collections::Any => Ok(()),
        Collections::List(allowed) if allowed.iter().any(|c| c == collection) => Ok(()),
        Collections::List(_) => Err(Problem::not_found().instance(&scope.request_id)),
    }
}

fn now_iso() -> String {
    // RFC 3339 from the wall clock, the same source the other modules' `now`
    // helpers use.
    use time::format_description::well_known::Rfc3339;
    SystemClock
        .now()
        .replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Public reads
// ---------------------------------------------------------------------------

/// `GET /v1/cms/{collection}/{slug}` — the published item, or 404.
async fn read_item(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path((collection, slug)): Path<(String, String)>,
) -> Result<Response, Problem> {
    check_collection(&state, &scope, &collection)?;
    let Some(db) = db_of(&state) else {
        return Err(internal(&scope));
    };
    let revision = store::published_revision(&*db, &collection, &slug)
        .await
        .map_err(|_| internal(&scope))?;
    match revision {
        Some(rev) => Ok(Json(revision_json(&rev)).into_response()),
        None => Err(Problem::not_found().instance(&scope.request_id)),
    }
}

/// `GET /v1/cms/{collection}` — the published items of a collection.
async fn read_collection(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(collection): Path<String>,
) -> Result<Response, Problem> {
    check_collection(&state, &scope, &collection)?;
    let Some(db) = db_of(&state) else {
        return Err(internal(&scope));
    };
    let items = store::published_in_collection(&*db, &collection)
        .await
        .map_err(|_| internal(&scope))?;
    let list: Vec<Value> = items.iter().map(revision_json).collect();
    Ok(Json(json!({ "collection": collection, "items": list })).into_response())
}

fn revision_json(rev: &store::Revision) -> Value {
    json!({
        "collection": rev.collection,
        "slug": rev.slug,
        "version": rev.version,
        "title": rev.title,
        "body": rev.body,
        "data": parse_data(&rev.data),
        "publishedAt": rev.created_at,
    })
}

fn item_json(item: &store::Item) -> Value {
    json!({
        "collection": item.collection,
        "slug": item.slug,
        "title": item.title,
        "body": item.body,
        "data": parse_data(&item.data),
        "status": item.status,
        "version": item.version,
        "updatedAt": item.updated_at,
    })
}

/// The stored `data` text as JSON, or an empty object if it does not parse
/// (it is written only through [`admin_save`], which validates it first).
fn parse_data(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| json!({}))
}

// ---------------------------------------------------------------------------
// Admin writes
// ---------------------------------------------------------------------------

/// The body of a save: create or edit an item's draft.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SaveBody {
    /// The collection the item belongs to.
    pub collection: String,
    /// The item's slug, unique within the collection.
    pub slug: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
    /// Structured fields as a JSON object. Defaults to `{}`.
    #[serde(default)]
    pub data: Option<Value>,
}

/// The body of publish/unpublish/delete: which item.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ItemRef {
    pub collection: String,
    pub slug: String,
}

/// The query of the admin list: which collection.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ListQuery {
    pub collection: String,
}

fn admin_gate(state: &ModuleState, headers: &HeaderMap, scope: &Scope) -> Result<(), Problem> {
    require_admin(&*state.ctx.config, headers).map_err(|p| p.instance(&scope.request_id))
}

async fn admin_save(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Json(body): Json<SaveBody>,
) -> Result<Response, Problem> {
    admin_gate(&state, &headers, &scope)?;
    check_collection(&state, &scope, &body.collection)?;
    let slug = body.slug.trim();
    if slug.is_empty() {
        return Err(
            Problem::validation_failed("slug must not be empty").instance(&scope.request_id)
        );
    }
    // `data` must be a JSON object, never a scalar or array, so reads can rely
    // on an object shape.
    let data = match &body.data {
        None => "{}".to_owned(),
        Some(Value::Object(_)) => body
            .data
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        Some(_) => {
            return Err(Problem::validation_failed("data must be a JSON object")
                .instance(&scope.request_id));
        }
    };
    let Some(db) = db_of(&state) else {
        return Err(internal(&scope));
    };
    store::save_item(
        &*db,
        &body.collection,
        slug,
        &body.title,
        &body.body,
        &data,
        &now_iso(),
    )
    .await
    .map_err(|_| internal(&scope))?;
    let item = store::find_item(&*db, &body.collection, slug)
        .await
        .map_err(|_| internal(&scope))?
        .ok_or_else(|| internal(&scope))?;
    Ok(Json(item_json(&item)).into_response())
}

async fn admin_publish(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Json(body): Json<ItemRef>,
) -> Result<Response, Problem> {
    admin_gate(&state, &headers, &scope)?;
    check_collection(&state, &scope, &body.collection)?;
    let Some(db) = db_of(&state) else {
        return Err(internal(&scope));
    };
    let item = store::find_item(&*db, &body.collection, &body.slug)
        .await
        .map_err(|_| internal(&scope))?
        .ok_or_else(|| Problem::not_found().instance(&scope.request_id))?;
    let version = store::publish_item(&*db, &item, &UlidIdGen.ulid(), &now_iso())
        .await
        .map_err(|_| internal(&scope))?;
    Ok(Json(json!({ "ok": true, "version": version })).into_response())
}

async fn admin_unpublish(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Json(body): Json<ItemRef>,
) -> Result<Response, Problem> {
    admin_gate(&state, &headers, &scope)?;
    check_collection(&state, &scope, &body.collection)?;
    let Some(db) = db_of(&state) else {
        return Err(internal(&scope));
    };
    store::unpublish_item(&*db, &body.collection, &body.slug, &now_iso())
        .await
        .map_err(|_| internal(&scope))?;
    Ok(Json(json!({ "ok": true })).into_response())
}

async fn admin_delete(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Json(body): Json<ItemRef>,
) -> Result<Response, Problem> {
    admin_gate(&state, &headers, &scope)?;
    check_collection(&state, &scope, &body.collection)?;
    let Some(db) = db_of(&state) else {
        return Err(internal(&scope));
    };
    store::delete_item(&*db, &body.collection, &body.slug)
        .await
        .map_err(|_| internal(&scope))?;
    Ok(Json(json!({ "ok": true })).into_response())
}

async fn admin_list(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response, Problem> {
    admin_gate(&state, &headers, &scope)?;
    check_collection(&state, &scope, &query.collection)?;
    let Some(db) = db_of(&state) else {
        return Err(internal(&scope));
    };
    let items = store::list_items(&*db, &query.collection)
        .await
        .map_err(|_| internal(&scope))?;
    let list: Vec<Value> = items.iter().map(item_json).collect();
    Ok(Json(json!({ "collection": query.collection, "items": list })).into_response())
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

pub(crate) fn surface(_settings: &Settings) -> Surface {
    Surface::new()
        .action(
            Action::post("save", "/admin/save")
                .audience(Audience::Admin)
                .input::<SaveBody>()
                .accepted("Saved."),
        )
        .action(
            Action::post("publish", "/admin/publish")
                .audience(Audience::Admin)
                .input::<ItemRef>()
                .outcome(Outcome::Json),
        )
        .action(
            Action::post("unpublish", "/admin/unpublish")
                .audience(Audience::Admin)
                .input::<ItemRef>()
                .outcome(Outcome::Json),
        )
        .action(
            Action::post("delete", "/admin/delete")
                .audience(Audience::Admin)
                .input::<ItemRef>()
                .outcome(Outcome::Json),
        )
        .action(
            Action::get("list", "/admin/list")
                .audience(Audience::Admin)
                .input::<ListQuery>()
                .outcome(Outcome::Json),
        )
        .view(View::form("save"))
        .view(View::table(
            "list",
            [
                ("slug", "Slug"),
                ("title", "Title"),
                ("status", "Status"),
                ("version", "Version"),
                ("updated_at", "Updated"),
            ]
            .into_iter()
            .map(|(key, label)| Column::new(key, label))
            .collect(),
        ))
}
