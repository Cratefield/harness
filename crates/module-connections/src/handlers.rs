//! The module's one route, `GET /v1/connections/callback/{provider}` (issue
//! #624), public because a provider redirect is. The `state` is single-use and
//! bound to a row this module wrote, so the route only spends it, exchanges
//! the code, and redirects to the `return_to` on that row — whose origin is
//! checked against the allowed origins *again*, here, before any `Location` is
//! written. A state that is unknown, spent or expired answers an RFC 9457
//! problem, never a redirect to a URL nobody vouched for. No token — access,
//! refresh, code or secret — reaches a body, header or log line.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use cratefield_core::{
    Config, ConfigError, ModuleConfig, ModuleContext, Problem, ProblemDef, Scope,
};

use crate::service;
use crate::{ConnectionError, Provider};

/// Emitted when a provider is connected and its tokens are stored. Payload:
/// the connection id, the subject and the provider key — never a token.
pub(crate) const EVENT_CONNECTED: &str = "connections.connected";

/// Emitted when an access token is refreshed. Payload: the connection id, the
/// subject and the provider key.
pub(crate) const EVENT_REFRESHED: &str = "connections.refreshed";

/// Emitted when a connection is revoked. Payload: the connection id, the
/// subject and the provider key.
pub(crate) const EVENT_REVOKED: &str = "connections.revoked";

/// Emitted when a provider rejects a refresh token and a human must authorize
/// again. Payload: the connection id, the subject and the provider key.
pub(crate) const EVENT_NEEDS_RECONNECT: &str = "connections.needs_reconnect";

/// The callback named a provider this venture never configured.
pub(crate) const UNKNOWN_PROVIDER: ProblemDef = ProblemDef {
    slug: "connections-unknown-provider",
    status: StatusCode::NOT_FOUND,
    title: "Unknown provider",
    description: "The callback names a provider key the venture has not configured, so there \
                  is no client to exchange the code with.",
};

/// The callback carried a `state` that is unknown, already spent or past its
/// deadline — or the venture cannot vouch for the URL it would redirect to.
pub(crate) const BAD_STATE: ProblemDef = ProblemDef {
    slug: "connections-bad-state",
    status: StatusCode::BAD_REQUEST,
    title: "That connection link is no longer valid",
    description: "The connect state was never issued, has already been used, or has expired. \
                  Start the connection again.",
};

/// The provider refused the authorization and redirected back with an error.
pub(crate) const OAUTH_DENIED: ProblemDef = ProblemDef {
    slug: "connections-oauth-denied",
    status: StatusCode::BAD_REQUEST,
    title: "The provider did not grant access",
    description: "The provider sent the browser back with an error instead of a code, so no \
                  connection was stored.",
};

/// A connection needs a new authorization before its token can be handed out.
pub(crate) const RECONNECT_REQUIRED: ProblemDef = ProblemDef {
    slug: "connections-reconnect-required",
    status: StatusCode::CONFLICT,
    title: "This connection needs to be reconnected",
    description: "The provider rejected the stored refresh token, so the person must authorize \
                  the connection again before an access token can be issued.",
};

/// No connection carries the id the caller asked for.
pub(crate) const NOT_FOUND: ProblemDef = ProblemDef {
    slug: "connections-not-found",
    status: StatusCode::NOT_FOUND,
    title: "No such connection",
    description: "No connection the venture holds has that id.",
};

/// A connection was revoked, so it has no token to hand out.
pub(crate) const REVOKED: ProblemDef = ProblemDef {
    slug: "connections-revoked",
    status: StatusCode::CONFLICT,
    title: "This connection was revoked",
    description: "The connection was revoked and its tokens were cleared, so there is nothing \
                  left to use or refresh.",
};

/// The provider answered a token call with something that is not a token.
pub(crate) const UPSTREAM: ProblemDef = ProblemDef {
    slug: "connections-upstream",
    status: StatusCode::BAD_GATEWAY,
    title: "The provider could not complete the connection",
    description: "Talking to the provider's token endpoint failed, or it answered with a body \
                  that is not a token response.",
};

/// The builder's settings, cloned into the router state and every API handle.
/// Nothing here reads the environment; `validate` does that.
#[derive(Clone, Default)]
pub(crate) struct Settings {
    /// The providers a venture may connect, by key.
    pub providers: Vec<Provider>,
    /// The origins a `return_to` may live on, normalized.
    pub allowed_origins: Vec<String>,
    /// How long before an access token expires the module refreshes it.
    pub refresh_lead_secs: i64,
}

impl Settings {
    /// The provider with this key, if it is configured.
    pub(crate) fn provider(&self, key: &str) -> Option<&Provider> {
        self.providers.iter().find(|provider| provider.key == key)
    }

    /// Whether `return_to` lives on one of the allowed origins.
    pub(crate) fn allows(&self, return_to: &str) -> bool {
        crate::origin_of(return_to).is_some_and(|origin| self.allowed_origins.contains(&origin))
    }
}

/// Maps a lifecycle failure to the problem a route answers with.
pub(crate) fn problem_for(error: &ConnectionError) -> Problem {
    let def = match error {
        ConnectionError::UnknownProvider(_) => &UNKNOWN_PROVIDER,
        ConnectionError::OriginNotAllowed(_) | ConnectionError::BadState => &BAD_STATE,
        ConnectionError::NotFound(_) => &NOT_FOUND,
        ConnectionError::NeedsReconnect(_) => &RECONNECT_REQUIRED,
        ConnectionError::Revoked => &REVOKED,
        ConnectionError::Provider(_) | ConnectionError::Config(_) => &UPSTREAM,
        ConnectionError::Db(_) => return Problem::internal(),
    };
    // A detail only where it adds a fact the title does not — the offending
    // provider, origin or id — using the error's own safe wording, never a
    // provider's.
    match error {
        ConnectionError::UnknownProvider(_)
        | ConnectionError::OriginNotAllowed(_)
        | ConnectionError::NotFound(_)
        | ConnectionError::NeedsReconnect(_) => Problem::new(def).with_detail(error.to_string()),
        _ => Problem::new(def),
    }
}

/// A scope for work no request asked for — the scheduled refresh and purge
/// passes, where `EventBus::emit_in` still wants a `&Scope`. Its `request_id`
/// is a real generated id, so a scheduled run is traceable like a request.
pub(crate) fn event_scope(ctx: &ModuleContext) -> Option<Scope> {
    let defer = ctx.ports.defer.clone()?;
    let request_id = ctx
        .ports
        .id_gen
        .as_ref()
        .map(|id_gen| id_gen.ulid())
        .unwrap_or_default();
    Some(Scope {
        request_id,
        defer,
        span: tracing::info_span!("connections.event"),
    })
}

/// Emits one of this module's four events. Every payload is ids and keys —
/// connection id, subject, provider — and never a token.
pub(crate) fn emit(ctx: &ModuleContext, name: &str, payload: serde_json::Value) {
    if let Some(scope) = event_scope(ctx) {
        ctx.events.emit_in(&scope, name, payload);
    } else {
        tracing::debug!(event = name, "no Defer port is mounted; event not emitted");
    }
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
}

/// The module's one route, mounted at `/v1/connections`.
pub(crate) fn router(ctx: Arc<ModuleContext>, settings: Settings) -> axum::Router {
    let state = Arc::new(ModuleState { ctx, settings });
    axum::Router::new()
        .route("/callback/{provider}", get(callback))
        .with_state(state)
}

/// The query a provider redirects back with (RFC 6749 §4.1.2).
#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQuery {
    /// The authorization code, when the provider granted one.
    code: Option<String>,
    /// The single-use state this module issued.
    state: Option<String>,
    /// The provider's error code, when it refused.
    error: Option<String>,
}

async fn callback(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    if state.settings.provider(&provider).is_none() {
        return problem(
            &UNKNOWN_PROVIDER,
            &scope,
            format!("`{provider}` is not a configured provider"),
        );
    }
    if let Some(error) = query.error.as_deref() {
        // The code is logged sanitized and length-capped, and never rendered
        // or echoed: LinkedIn and others put text an attacker chose in
        // `error_description`, and reflecting it would be a reflected XSS on
        // this venture's own domain.
        tracing::warn!(
            provider = %provider,
            error = crate::safe_token(error),
            "the provider refused the authorization"
        );
        return problem(
            &OAUTH_DENIED,
            &scope,
            "the provider sent the browser back with an error".to_owned(),
        );
    }
    let (Some(code), Some(raw_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return problem(
            &BAD_STATE,
            &scope,
            "the callback carried no code or state".to_owned(),
        );
    };

    let ctx = state.ctx.as_ref();
    // Spending the state first is the whole single-use story: a replayed
    // callback spends nothing, gets `BadState`, and never reaches the
    // exchange, so no code is redeemed twice.
    let row = match service::spend_state(ctx, raw_state).await {
        Ok(row) => row,
        Err(error) => {
            return problem_for(&error)
                .instance(&scope.request_id)
                .into_response();
        }
    };
    // The origin check runs again here, and *before* the code is redeemed.
    // A state row can outlive the configuration it was written under — a
    // venture may narrow its allowed origins between the person starting the
    // flow and the provider sending them back — and a `return_to` the
    // venture no longer vouches for must not become a `Location`. Refusing
    // first also means a redirect that cannot be made never spends the
    // provider's code.
    if !state.settings.allows(&row.return_to) {
        tracing::error!(
            "refusing to redirect to a return_to whose origin is not an allowed origin"
        );
        return problem(
            &BAD_STATE,
            &scope,
            "the return URL is not on an allowed origin".to_owned(),
        );
    }
    let outcome = service::exchange(ctx, &state.settings, &row, code).await;
    let (name, value) = match &outcome {
        Ok(connection) => ("connection", connection.id.clone()),
        Err(error) => ("error", error.slug().to_owned()),
    };
    redirect(&row.return_to, name, &value)
}

/// The 303 back to the `return_to` the state recorded, with the outcome
/// appended. Its origin was checked above, against the same list `start`
/// checked.
fn redirect(return_to: &str, name: &str, value: &str) -> Response {
    let location = crate::append_query(return_to, name, value);
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

/// The RFC 9457 problem for a failure the route answers with directly.
fn problem(def: &ProblemDef, scope: &Scope, detail: String) -> Response {
    Problem::new(def)
        .with_detail(detail)
        .instance(&scope.request_id)
        .into_response()
}

/// The two places the crate's needed config keys are named.
#[must_use]
pub(crate) fn validate(settings: &Settings, cfg: &dyn Config) -> ConfigError {
    let module = ModuleConfig::new("connections", cfg);
    let mut errors = ConfigError::new();

    match cfg.get(&module.key("TOKEN_KEY")) {
        Some(raw) => {
            if crate::seal::SealKey::from_config(&raw, 1).is_err() {
                errors.push(format!(
                    "connections: {} must be {} bytes of base64",
                    module.key("TOKEN_KEY"),
                    crate::seal::KEY_LEN
                ));
            }
        }
        None => errors.push(format!(
            "connections: {} is required ({} random bytes, base64)",
            module.key("TOKEN_KEY"),
            crate::seal::KEY_LEN
        )),
    }

    for provider in &settings.providers {
        for kind in ["CLIENT_ID", "CLIENT_SECRET"] {
            let key = module.key(&format!("{}_{kind}", provider.env_key()));
            match cfg.get(&key) {
                Some(value) if !value.trim().is_empty() => {}
                Some(_) => errors.push(format!("connections: {key} must not be empty")),
                None => errors.push(format!(
                    "connections: {key} is required (a Worker secret, never wrangler.toml)"
                )),
            }
        }
    }

    if let Some(base) = cfg.get(&module.key("API_BASE"))
        && !base.trim().is_empty()
        && !base.starts_with("https://")
        && !base.starts_with("http://localhost")
        && !base.starts_with("http://127.0.0.1")
    {
        errors.push(format!(
            "connections: {} must be https (or a localhost URL for wrangler dev), got {base:?}",
            module.key("API_BASE")
        ));
    }

    errors
}

/// The composition a build must refuse, reported by [`Module::self_check`].
#[must_use]
pub(crate) fn self_check(settings: &Settings) -> Vec<String> {
    let mut problems = Vec::new();
    if settings.providers.is_empty() {
        problems.push(
            "connections: no providers are configured, so no connection can ever be started — \
             add `.provider(..)`"
                .to_owned(),
        );
    }
    if settings.allowed_origins.is_empty() {
        problems.push(
            "connections: no allowed origins are configured, so every `return_to` would be \
             refused and no callback could redirect — add `.allowed_origin(..)`"
                .to_owned(),
        );
    }
    for provider in &settings.providers {
        if provider.key.is_empty()
            || !provider
                .key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            problems.push(format!(
                "connections: provider key {:?} must be a non-empty kebab-case token",
                provider.key
            ));
        }
    }
    problems
}
