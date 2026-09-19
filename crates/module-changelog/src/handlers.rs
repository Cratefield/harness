//! Routes for the changelog module, and the UI surface declaring them.
//!
//! The reads are the contract: they open the database and nothing else —
//! no `HttpClient` anywhere behind them — so GitHub being down,
//! rate-limited or misconfigured costs a refresh, not the changelog. The
//! one write, `POST /admin/refresh`, is an admin action behind the harness
//! `ADMIN_TOKEN` bearer ([`require_admin`]).

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use cratefield_core::{
    Action, Audience, ModuleContext, Outcome, Problem, Scope, Surface, require_admin,
};
use http::{HeaderMap, header};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Settings;
use crate::cache::ReadCache;
use crate::source;
use crate::store::{self, Release};

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
}

impl ModuleState {
    /// The settings as configured: composed values with the `CHANGELOG_*`
    /// keys applied over them.
    pub(crate) fn resolved(&self) -> Settings {
        source::resolved(&self.ctx, &self.settings)
    }
}

pub(crate) fn router(ctx: Arc<ModuleContext>, settings: Settings) -> axum::Router {
    let state = Arc::new(ModuleState { ctx, settings });
    axum::Router::new()
        // Public reads. Database only.
        .route("/", get(list_releases))
        .route("/{version}", get(read_release))
        // The admin refresh, under `/admin/`: core's surface validation
        // reserves admin-audience actions for `/admin/*` paths (the same
        // rule that puts module-cms's writes at `/admin/save`,
        // `/admin/list`), so that is the one spelling the route has.
        .route("/admin/refresh", post(refresh_now))
        .with_state(state)
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

fn admin_gate(state: &ModuleState, headers: &HeaderMap, scope: &Scope) -> Result<(), Problem> {
    require_admin(&*state.ctx.config, headers).map_err(|p| p.instance(&scope.request_id))
}

/// A JSON response from a body already serialized — the same bytes the read
/// cache holds, so a hit and a miss answer byte for byte identically.
fn json_body(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn source_json(settings: &Settings) -> Value {
    json!({
        "kind": settings.kind(),
        "repo": settings.repo.as_deref().unwrap_or(""),
    })
}

/// The rendering block. With no rewriting configured — always, in this
/// version — the original text is served and the block says so; a later
/// `TextModel` port is what will vary it.
fn rendering_json(settings: &Settings) -> Value {
    json!({
        "style": "original",
        "locale": settings.locale,
        "machine_generated": false,
    })
}

fn release_json(release: &Release, settings: &Settings) -> Value {
    json!({
        "version": release.version,
        "title": release.title,
        "body": release.body,
        "url": release.url,
        "published_at": if release.published_at.is_empty() {
            Value::Null
        } else {
            json!(release.published_at)
        },
        "prerelease": release.prerelease,
        "rendering": rendering_json(settings),
    })
}

// ---------------------------------------------------------------------------
// Public reads
// ---------------------------------------------------------------------------

/// The list query. `locale` and `style` are accepted — a caller can already
/// send what a later rendering feature will consume — and select nothing
/// today: the original is served whatever they say.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub(crate) struct ListQuery {
    /// 1-based; default 1.
    pub page: Option<String>,
    /// 1-100; default 20.
    pub per_page: Option<String>,
    /// Accepted for a later rendering; selects nothing today.
    pub locale: Option<String>,
    /// Accepted for a later rendering; selects nothing today.
    pub style: Option<String>,
}

const DEFAULT_PER_PAGE: u64 = 20;
const MAX_PER_PAGE: u64 = 100;

/// `GET /` — the stored releases, newest first. Before any refresh has run
/// this is a 200 with an empty list, never an error: an unconfigured or
/// unreachable GitHub is not the changelog's outage.
async fn list_releases(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Query(query): Query<ListQuery>,
) -> Result<Response, Problem> {
    let settings = state.resolved();
    let page = parse_count(query.page.as_deref(), "page", 1)?.max(1);
    let per_page = parse_count(query.per_page.as_deref(), "per_page", DEFAULT_PER_PAGE)?
        .clamp(1, MAX_PER_PAGE);
    let offset = (page - 1).saturating_mul(per_page).min(i64::MAX as u64);

    // The fingerprint is everything the answer depends on, path and query
    // alike, so a cache hit is the same answer a miss would have built.
    let fingerprint = format!(
        "list:{page}:{per_page}:{}:{}",
        query.locale.as_deref().unwrap_or(""),
        query.style.as_deref().unwrap_or(""),
    );
    let cache = ReadCache::of(&state.ctx, settings.cache_ttl_secs);
    if let Some(body) = cache.get(&fingerprint).await {
        return Ok(json_body(body));
    }

    let db = state
        .ctx
        .ports
        .db
        .clone()
        .ok_or_else(|| Problem::not_ready("the changelog module needs a database"))?;
    let source_id = settings.source_id();
    let total = store::count_releases(db.as_ref(), &source_id)
        .await
        .map_err(|_| internal(&scope))?;
    let releases = store::list_releases(db.as_ref(), &source_id, per_page, offset)
        .await
        .map_err(|_| internal(&scope))?;
    // A source row that will not load costs the timestamp, not the read:
    // the releases themselves are the answer, `refreshed_at` is metadata.
    let refreshed_at = match store::source_state(db.as_ref(), &source_id).await {
        Ok(Some(source)) if !source.last_refreshed_at.is_empty() => {
            json!(source.last_refreshed_at)
        }
        _ => Value::Null,
    };

    let list: Vec<Value> = releases
        .iter()
        .map(|release| release_json(release, &settings))
        .collect();
    let body = json!({
        "releases": list,
        "page": page,
        "per_page": per_page,
        "total": total,
        "source": source_json(&settings),
        "refreshed_at": refreshed_at,
    })
    .to_string();
    cache.put(&fingerprint, &body).await;
    Ok(json_body(body))
}

/// `GET /{version}` — the one stored release, or 404.
async fn read_release(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(version): Path<String>,
) -> Result<Response, Problem> {
    let settings = state.resolved();
    let fingerprint = format!("release:{version}");
    let cache = ReadCache::of(&state.ctx, settings.cache_ttl_secs);
    if let Some(body) = cache.get(&fingerprint).await {
        return Ok(json_body(body));
    }

    let db = state
        .ctx
        .ports
        .db
        .clone()
        .ok_or_else(|| Problem::not_ready("the changelog module needs a database"))?;
    let Some(release) = store::find_release(db.as_ref(), &settings.source_id(), &version)
        .await
        .map_err(|_| internal(&scope))?
    else {
        return Err(Problem::not_found().instance(&scope.request_id));
    };
    let body = release_json(&release, &settings).to_string();
    cache.put(&fingerprint, &body).await;
    Ok(json_body(body))
}

fn parse_count(raw: Option<&str>, name: &str, default: u64) -> Result<u64, Problem> {
    match raw {
        None | Some("") => Ok(default),
        Some(value) => value.trim().parse::<u64>().map_err(|_| {
            Problem::validation_failed(format!("{name} must be a positive integer, got {value:?}"))
        }),
    }
}

// ---------------------------------------------------------------------------
// Admin refresh
// ---------------------------------------------------------------------------

/// `POST /admin/refresh` — pull from the source now. Upstream failures come
/// back as problems with the status they deserve, and the stored releases
/// stay exactly as they were. `complete` is `false` when the walk hit the
/// page cap: what arrived still applied, but nothing was pruned.
async fn refresh_now(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    admin_gate(&state, &headers, &scope)?;
    let settings = state.resolved();
    let report = source::refresh(&state.ctx, &settings)
        .await
        .map_err(|problem| problem.instance(&scope.request_id))?;
    Ok(Json(json!({
        "ok": true,
        "fetched": report.fetched,
        "inserted": report.inserted,
        "updated": report.updated,
        "unchanged": report.unchanged,
        "skipped": report.skipped,
        "removed": report.removed,
        "not_modified": report.not_modified,
        "complete": report.complete,
    }))
    .into_response())
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

pub(crate) fn surface() -> Surface {
    Surface::new()
        .action(
            Action::get("releases", "/")
                .audience(Audience::Public)
                .input::<ListQuery>()
                .outcome(Outcome::Json),
        )
        .action(
            Action::get("release", "/{version}")
                .audience(Audience::Public)
                .outcome(Outcome::Json),
        )
        .action(
            // The path is the `/admin/` spelling: core's surface validation
            // reserves admin-audience actions for `/admin/*`, and the
            // renderer's button points where the declaration says.
            Action::post("refresh", "/admin/refresh")
                .audience(Audience::Admin)
                .outcome(Outcome::Json),
        )
}

/// The status codes the module itself answers with, checked to stay that
/// way: reads never blame the caller for GitHub.
#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;

    #[test]
    fn counts_default_and_refuse_nonsense() {
        assert_eq!(parse_count(None, "page", 1).unwrap(), 1);
        assert_eq!(parse_count(Some(""), "page", 7).unwrap(), 7);
        assert_eq!(parse_count(Some(" 4 "), "page", 1).unwrap(), 4);
        let problem = parse_count(Some("soon"), "page", 1).unwrap_err();
        assert_eq!(problem.status, StatusCode::BAD_REQUEST);
    }
}
