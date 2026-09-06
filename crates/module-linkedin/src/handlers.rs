//! The router and the plumbing every handler shares (issues #6, #8 to #13).
//!
//! Admin routes live under `/v1/linkedin/admin/*`, which is where
//! `ARCHITECTURE.md` section 11 puts them: they answer `401` while
//! `ADMIN_TOKEN` is unset, so a deployment that forgot the secret is closed
//! rather than open. The OAuth callback is the one public route.

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use factory0_core::{
    Clock, Database, Defer, HttpClient, IdGen, Json, ModuleConfig, ModuleContext, Problem,
    ProblemDef, Scope, Signer, rate_limit_keys, rate_limited, require_admin,
};
use serde_json::json;
use std::sync::Arc;

use crate::token::SealKey;

pub const EVENT_CONNECTED: &str = "linkedin.connected";
pub const EVENT_PAGES_SYNCED: &str = "linkedin.pages_synced";
pub const EVENT_POST_PUBLISHED: &str = "linkedin.post_published";
pub const EVENT_POST_FAILED: &str = "linkedin.post_failed";
pub const EVENT_TOKEN_REFRESHED: &str = "linkedin.token_refreshed";
pub const EVENT_TOKEN_EXPIRING: &str = "linkedin.token_expiring";
pub const EVENT_TOKEN_EXPIRED: &str = "linkedin.token_expired";

/// The state token's purpose (ADR 0006): a connect token can never be
/// replayed as anything else.
pub(crate) const PURPOSE_CONNECT: &str = "linkedin.connect";

// The module's own problem types. Core's registry covers the shared ones;
// these four are LinkedIn-shaped and a caller needs to tell them apart.
pub(crate) const NOT_CONNECTED: ProblemDef = ProblemDef {
    slug: "linkedin-not-connected",
    status: StatusCode::CONFLICT,
    title: "No LinkedIn account connected",
    description: "Connect a page first: POST /v1/linkedin/admin/connect.",
};

pub(crate) const RECONNECT_REQUIRED: ProblemDef = ProblemDef {
    slug: "linkedin-reconnect-required",
    status: StatusCode::CONFLICT,
    title: "LinkedIn connection needs renewing",
    description: "LinkedIn rejected the stored credentials. A page administrator must connect again.",
};

pub(crate) const PAGE_ROLE_MISSING: ProblemDef = ProblemDef {
    slug: "linkedin-page-role-missing",
    status: StatusCode::FORBIDDEN,
    title: "The connected account cannot post to this page",
    description: "The page is unknown, revoked, or held with a role that cannot publish organic posts.",
};

pub(crate) const UPSTREAM: ProblemDef = ProblemDef {
    slug: "linkedin-upstream",
    status: StatusCode::BAD_GATEWAY,
    title: "LinkedIn rejected the request",
    description: "LinkedIn answered with an error. The detail carries its code.",
};

/// The builder's compile-time settings, cloned into the router state.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub api_version: String,
    pub default_visibility: String,
    pub refresh_lead_days: u32,
    pub max_image_bytes: usize,
    pub publish_lease_secs: i64,
    pub asset_poll_secs: i64,
    pub connect_ttl_secs: i64,
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
}

/// Config helpers. These take a `ModuleContext` rather than the router state
/// because scheduled work has no state: the cron passes need the same client
/// credentials, seal key and settings that a request does.
pub(crate) fn cfg(ctx: &ModuleContext) -> ModuleConfig<'_> {
    ModuleConfig::new("linkedin", ctx.config.as_ref())
}

/// Compile-time settings overlaid with configuration. Config wins, so a
/// deployment can move the API version pin without a rebuild.
pub(crate) fn settings_of(ctx: &ModuleContext, base: &Settings) -> Settings {
    let cfg = cfg(ctx);
    let mut settings = base.clone();
    settings.api_version = cfg.get_str("API_VERSION", &settings.api_version);
    settings.default_visibility = cfg.get_str("DEFAULT_VISIBILITY", &settings.default_visibility);
    settings.refresh_lead_days = cfg.get_u32("REFRESH_LEAD_DAYS", settings.refresh_lead_days);
    settings.max_image_bytes = cfg
        .get_opt("MAX_IMAGE_BYTES")
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(settings.max_image_bytes);
    settings.publish_lease_secs = cfg
        .get_opt("PUBLISH_LEASE_SECS")
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(settings.publish_lease_secs);
    settings
}

/// The app's client id and secret. Read per use and never parked on the
/// router state, so nothing long-lived holds the secret.
pub(crate) fn client_credentials(ctx: &ModuleContext) -> Option<(String, String)> {
    let cfg = cfg(ctx);
    Some((cfg.get_opt("CLIENT_ID")?, cfg.get_opt("CLIENT_SECRET")?))
}

/// The registered redirect URI. Defaults to the venture's API host, which is
/// what a single-venture deployment wants; LinkedIn matches it exactly, so a
/// mismatch here is the first thing to check when a connect fails.
pub(crate) fn redirect_uri(ctx: &ModuleContext) -> String {
    cfg(ctx)
        .get_opt("REDIRECT_URI")
        .unwrap_or_else(|| format!("https://api.{}/v1/linkedin/callback", ctx.venture.domain))
}

pub(crate) fn seal_key(ctx: &ModuleContext) -> Option<SealKey> {
    let cfg = cfg(ctx);
    let encoded = cfg.get_opt("TOKEN_KEY")?;
    let id = cfg
        .get_opt("TOKEN_KEY_ID")
        .and_then(|raw| raw.parse::<u8>().ok())
        .unwrap_or(1);
    SealKey::from_config(&encoded, id).ok()
}

impl ModuleState {
    pub(crate) fn settings(&self) -> Settings {
        settings_of(&self.ctx, &self.settings)
    }
}

/// Ports the module declared as required. `Harness::build` refuses to
/// assemble a runtime that is missing one, so reaching these `None` arms
/// means the harness was bypassed; answer `503` rather than panicking inside
/// a Worker.
pub(crate) fn db(ctx: &ModuleContext) -> Result<&dyn Database, Problem> {
    ctx.ports
        .db
        .as_deref()
        .ok_or_else(|| Problem::not_ready("the linkedin module needs a database"))
}

pub(crate) fn http(ctx: &ModuleContext) -> Result<&dyn HttpClient, Problem> {
    ctx.ports
        .http
        .as_deref()
        .ok_or_else(|| Problem::not_ready("the linkedin module needs an http client"))
}

pub(crate) fn clock(ctx: &ModuleContext) -> Result<&dyn Clock, Problem> {
    ctx.ports
        .clock
        .as_deref()
        .ok_or_else(|| Problem::not_ready("the linkedin module needs a clock"))
}

pub(crate) fn signer(ctx: &ModuleContext) -> Result<&dyn Signer, Problem> {
    ctx.ports
        .signer
        .as_deref()
        .ok_or_else(|| Problem::not_ready("the linkedin module needs a signer"))
}

pub(crate) fn id_gen(ctx: &ModuleContext) -> Result<&dyn IdGen, Problem> {
    ctx.ports
        .id_gen
        .as_deref()
        .ok_or_else(|| Problem::not_ready("the linkedin module needs an id generator"))
}

/// The `Defer` port, required so scheduled work can build a [`Scope`] to emit
/// events through.
pub(crate) fn defer(ctx: &ModuleContext) -> Option<Arc<dyn Defer>> {
    ctx.ports.defer.clone()
}

/// A scope for work that has no request: the cron passes. `EventBus::emit_in`
/// takes a `&Scope` and `Module::scheduled` is handed none, so one is built
/// here from the ports the module declared. `request_id` is a real generated
/// id so a scheduled run is traceable in logs like any request.
pub(crate) fn cron_scope(ctx: &ModuleContext, cron: &str) -> Option<Scope> {
    let defer = defer(ctx)?;
    let request_id = ctx
        .ports
        .id_gen
        .as_ref()
        .map(|id_gen| id_gen.ulid())
        .unwrap_or_default();
    Some(Scope {
        request_id,
        defer,
        span: tracing::info_span!("linkedin.cron", cron = %cron),
    })
}

pub(crate) fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

/// Maps a LinkedIn failure onto a problem a caller can act on. A 401 is
/// deliberately a reconnect problem and not a 502: by the time it reaches
/// here the token layer has already tried a refresh.
pub(crate) fn upstream_problem(error: &crate::client::ApiError) -> Problem {
    use crate::client::ApiError;
    match error {
        ApiError::TokenRejected => Problem::new(&RECONNECT_REQUIRED),
        ApiError::Forbidden { code, message } => Problem::new(&PAGE_ROLE_MISSING)
            .with_detail(format!("LinkedIn refused this call ({code}): {message}")),
        ApiError::RateLimited { retry_after_secs } => {
            Problem::new(&factory0_core::SLUGS.rate_limited).with_detail(format!(
                "LinkedIn rate limited this call; retry after {}s",
                retry_after_secs.unwrap_or(60)
            ))
        }
        other => Problem::new(&UPSTREAM).with_detail(other.to_string()),
    }
}

/// Flushes the requests a client spent into today's budget row. Called at the
/// end of every unit of work that talked to LinkedIn: the cap is per app per
/// day, and a Worker isolate cannot count it.
pub(crate) async fn flush_budget(ctx: &ModuleContext, spent: u32) {
    if spent == 0 {
        return;
    }
    let (Ok(db), Ok(clock)) = (db(ctx), clock(ctx)) else {
        return;
    };
    let day = crate::store::day_of(clock);
    if let Err(error) = crate::store::spend_budget(db, &day, spent).await {
        tracing::warn!(error = %error, "could not record linkedin request budget");
    }
}

pub(crate) fn accepted(body: serde_json::Value) -> Response {
    (StatusCode::ACCEPTED, Json(body)).into_response()
}

pub(crate) fn ok(body: serde_json::Value) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

/// The rate limit on the one public route. Fails open with a warning when the
/// limiter itself is unreachable, the way the public modules do: an edge
/// binding outage must not strand a connect a person is in the middle of.
pub(crate) async fn limit_public(state: &ModuleState, headers: &HeaderMap) -> Option<Response> {
    let limiter = state.ctx.ports.rate_limiter.as_deref()?;
    let ip = factory0_core::client_ip(headers);
    for key in rate_limit_keys(ip.as_deref(), None) {
        match limiter.limit(&key).await {
            Ok(decision) if !decision.ok => {
                return Some(rate_limited(decision.retry_after).into_response());
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(error = %error, "linkedin callback rate limiter unavailable");
                return None;
            }
        }
    }
    None
}

pub(crate) fn router(ctx: Arc<ModuleContext>, settings: Settings) -> axum::Router {
    let max_image_bytes = {
        let state = ModuleState {
            ctx: ctx.clone(),
            settings: settings.clone(),
        };
        state.settings().max_image_bytes
    };
    let state = Arc::new(ModuleState { ctx, settings });

    // The image route raises core's 64 KiB /v1/* body cap for itself. axum
    // resolves the innermost DefaultBodyLimit, so this layer wins for this
    // route and this route only. Deliberate deviation, documented in README.
    let images = post(crate::images::upload).layer(DefaultBodyLimit::max(max_image_bytes));

    axum::Router::new()
        .route("/callback", get(crate::oauth::callback))
        .route("/admin/connect", post(crate::oauth::connect))
        .route("/admin/status", get(crate::oauth::status))
        .route("/admin/account", delete(crate::oauth::disconnect))
        .route("/admin/pages", get(crate::pages::list))
        .route("/admin/pages/sync", post(crate::pages::sync_route))
        .route("/admin/pages/{org}/images", images)
        .route("/admin/assets/{id}", get(crate::images::status))
        .route("/admin/pages/{org}/posts", post(crate::posts::create))
        .route("/admin/posts", get(crate::posts::list))
        .route("/admin/posts/{id}", patch(crate::posts::edit))
        .route("/admin/posts/{id}", delete(crate::posts::remove))
        .with_state(state)
}

/// Every admin handler starts here.
pub(crate) fn admin(state: &ModuleState, headers: &HeaderMap) -> Result<(), Problem> {
    require_admin(state.ctx.config.as_ref(), headers)
}

/// `?kind=` and friends, parsed leniently: an unknown value is a validation
/// error rather than a silent full listing.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ListQuery {
    pub kind: Option<String>,
    pub page: Option<String>,
    pub state: Option<String>,
    pub limit: Option<u64>,
}

/// A small helper for the JSON shape of a page row.
pub(crate) fn page_json(row: &crate::store::PageRow) -> serde_json::Value {
    json!({
        "org_id": row.org_id,
        "urn": row.urn,
        "name": row.name,
        "vanity_name": row.vanity_name,
        "kind": row.kind,
        "parent_org_id": row.parent_org_id,
        "role": row.role,
        "can_post_organic": row.can_post_organic,
        "state": row.state,
        "logo_urn": row.logo_urn,
        "synced_at": row.synced_at,
    })
}

/// The JSON shape of a post row, with the permalink a human wants.
pub(crate) fn post_json(row: &crate::store::PostRow) -> serde_json::Value {
    json!({
        "id": row.id,
        "org_id": row.org_id,
        "state": row.state,
        "commentary": row.commentary,
        "visibility": row.visibility,
        "asset_id": row.asset_id,
        "post_urn": row.post_urn,
        "permalink": row
            .post_urn
            .as_ref()
            .map(|urn| format!("https://www.linkedin.com/feed/update/{urn}/")),
        "scheduled_at": row.scheduled_at,
        "not_before": row.not_before,
        "publishing_since": row.publishing_since,
        "attempts": row.attempts,
        "error_code": row.error_code,
        "error_detail": row.error_detail,
        "edited_at": row.edited_at,
        "previous_commentary": row.previous_commentary,
        "created_at": row.created_at,
        "published_at": row.published_at,
        "deleted_at": row.deleted_at,
    })
}
