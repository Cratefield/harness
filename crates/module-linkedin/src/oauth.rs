//! Connecting a page, and what the connection looks like afterwards
//! (issue #8).
//!
//! Three-legged OAuth, once, by a human who administers the page. The state
//! is a signed token whose subject is a row in `linkedin_oauth_states`, and
//! spending it is a conditional delete: LinkedIn documents no PKCE for this
//! flow, so single-use state is the entire replay defence and it has to come
//! from a statement that reports how many rows it hit.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use factory0_core::{Kid, Payload, Problem, Scope};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::client::{self, Client};
use crate::handlers::{self, EVENT_CONNECTED, ModuleState, PURPOSE_CONNECT};
use crate::store::{self, AccountRow};
use crate::tokens;

/// Starts a connection. Returns the URL rather than redirecting: this route
/// is behind the admin bearer, and a browser following a redirect would not
/// carry that header.
pub(crate) async fn connect(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    handlers::admin(&state, &headers)?;
    let ctx = state.ctx.as_ref();
    let settings = state.settings();
    let db = handlers::db(ctx)?;
    let clock = handlers::clock(ctx)?;
    let signer = handlers::signer(ctx)?;
    let id_gen = handlers::id_gen(ctx)?;

    let (client_id, _) = handlers::client_credentials(ctx).ok_or_else(|| {
        Problem::not_ready("LINKEDIN_CLIENT_ID and LINKEDIN_CLIENT_SECRET are not configured")
    })?;
    if handlers::seal_key(ctx).is_none() {
        return Err(Problem::not_ready(
            "LINKEDIN_TOKEN_KEY is not configured, so tokens could not be stored",
        ));
    }

    let state_id = id_gen.ulid();
    let now = store::now_iso(clock);
    let expires_at = store::iso_in(clock, settings.connect_ttl_secs);
    store::insert_state(db, &state_id, &expires_at, &now)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not record a connect state");
            handlers::internal(&scope)
        })?;

    // No `exp` in the signed payload: `Signer::verify` compares against the
    // wall clock rather than the Clock port, which would make the expiry
    // untestable and would disagree with the row under a test clock. The row
    // carries the deadline and `spend_state` enforces it.
    let token = signer.sign(&Payload {
        purpose: PURPOSE_CONNECT.to_owned(),
        subject: state_id,
        exp: None,
        kid: Kid::Cur,
    });

    Ok(handlers::ok(json!({
        "authorize_url": client::authorize_url(&client_id, &handlers::redirect_uri(ctx), &token),
        "expires_at": expires_at,
        "scopes": crate::SCOPES,
    })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// The one public route. Everything it renders is a fixed string: LinkedIn
/// redirects failures back with attacker-controllable `error` and
/// `error_description` parameters, and echoing either would be a reflected
/// XSS on our own domain. The parameters are logged, never rendered.
pub(crate) async fn callback(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    if let Some(limited) = handlers::limit_public(&state, &headers).await {
        return limited;
    }

    if let Some(error) = query.error.as_deref() {
        tracing::warn!(linkedin_error = %error, "linkedin refused the authorization");
        return page(
            StatusCode::BAD_REQUEST,
            "LinkedIn did not grant access. Nothing was changed. You can close this tab and try again.",
        );
    }

    let (Some(code), Some(signed_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return page(
            StatusCode::BAD_REQUEST,
            "That link is incomplete. Start again from the connect step.",
        );
    };

    match complete(&state, &scope, code, signed_state).await {
        Ok(()) => page(
            StatusCode::OK,
            "LinkedIn is connected. You can close this tab.",
        ),
        Err(CallbackError::BadState) => page(
            StatusCode::BAD_REQUEST,
            "That link is not valid any more. Start again from the connect step.",
        ),
        Err(CallbackError::Upstream) => page(
            StatusCode::BAD_GATEWAY,
            "LinkedIn could not complete the connection. Nothing was stored. Try again.",
        ),
        Err(CallbackError::Internal) => page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong on our side. Nothing was stored.",
        ),
    }
}

enum CallbackError {
    BadState,
    Upstream,
    Internal,
}

async fn complete(
    state: &ModuleState,
    scope: &Scope,
    code: &str,
    signed_state: &str,
) -> Result<(), CallbackError> {
    let ctx = state.ctx.as_ref();
    let settings = state.settings();
    let db = handlers::db(ctx).map_err(|_| CallbackError::Internal)?;
    let clock = handlers::clock(ctx).map_err(|_| CallbackError::Internal)?;
    let signer = handlers::signer(ctx).map_err(|_| CallbackError::Internal)?;
    let id_gen = handlers::id_gen(ctx).map_err(|_| CallbackError::Internal)?;
    let http = handlers::http(ctx).map_err(|_| CallbackError::Internal)?;

    let payload = signer
        .verify(signed_state, PURPOSE_CONNECT)
        .ok_or(CallbackError::BadState)?;

    let now = store::now_iso(clock);
    // One shot. The delete is conditional on the row existing and not having
    // expired, and its affected-row count is the proof: a replayed callback
    // deletes nothing, gets `false`, and never reaches the token exchange.
    let spent = store::spend_state(db, &payload.subject, &now)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not spend a connect state");
            CallbackError::Internal
        })?;
    if !spent {
        tracing::warn!("a linkedin connect state was replayed or had expired");
        return Err(CallbackError::BadState);
    }

    let (client_id, client_secret) =
        handlers::client_credentials(ctx).ok_or(CallbackError::Internal)?;
    let linkedin = Client::anonymous(http);
    let exchanged = linkedin
        .exchange_code(
            code,
            &handlers::redirect_uri(ctx),
            &client_id,
            &client_secret,
        )
        .await;
    handlers::flush_budget(ctx, linkedin.spent()).await;
    let exchanged = exchanged.map_err(|error| {
        tracing::error!(error = %error, "linkedin token exchange failed");
        CallbackError::Upstream
    })?;

    let account_id = id_gen.ulid();
    let sealed = tokens::store_tokens(ctx, &account_id, &exchanged, clock).map_err(|error| {
        tracing::error!(error = ?error, "could not seal the linkedin tokens");
        CallbackError::Internal
    })?;

    store::put_account(
        db,
        &AccountRow {
            id: account_id.clone(),
            person_urn: None,
            access_token: sealed.access,
            access_expires_at: sealed.access_expires_at,
            refresh_token: sealed.refresh,
            refresh_expires_at: sealed.refresh_expires_at,
            scopes: exchanged.scope.clone(),
            status: store::ACCOUNT_CONNECTED.to_owned(),
            expiring_notified_at: None,
        },
        &now,
    )
    .await
    .map_err(|error| {
        tracing::error!(error = %error, "could not store the linkedin account");
        CallbackError::Internal
    })?;

    // The page sync is not called from here. #10 subscribes to this event, so
    // connecting and building the page directory stay independent.
    ctx.events.emit_in(
        scope,
        EVENT_CONNECTED,
        json!({
            "account_id": account_id,
            "scopes": exchanged.scope,
            "has_refresh_token": exchanged.refresh_token.is_some(),
        }),
    );
    let _ = settings;
    Ok(())
}

/// What the connection looks like now: both expiries, the granted scopes and
/// the day's request budget. Never a token, sealed or otherwise.
pub(crate) async fn status(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    handlers::admin(&state, &headers)?;
    let ctx = state.ctx.as_ref();
    let db = handlers::db(ctx)?;
    let clock = handlers::clock(ctx)?;

    let day = store::day_of(clock);
    let spent = store::budget_spent(db, &day).await.map_err(|error| {
        tracing::error!(error = %error, "could not read the request budget");
        handlers::internal(&scope)
    })?;
    let account = store::load_account(db).await.map_err(|error| {
        tracing::error!(error = %error, "could not read the linkedin account");
        handlers::internal(&scope)
    })?;
    let pages = store::list_pages(db, None).await.unwrap_or_default();

    let Some(account) = account else {
        return Ok(handlers::ok(json!({
            "connected": false,
            "budget": { "day": day, "spent": spent },
            "pages": 0,
        })));
    };

    let granted: Vec<&str> = account.scopes.split_whitespace().collect();
    let missing: Vec<&str> = crate::SCOPES
        .iter()
        .copied()
        .filter(|scope| !granted.contains(scope))
        .collect();

    Ok(handlers::ok(json!({
        "connected": account.status == store::ACCOUNT_CONNECTED,
        "status": account.status,
        "person_urn": account.person_urn,
        "scopes": granted,
        "missing_scopes": missing,
        "access_expires_at": account.access_expires_at,
        "access_expires_in_days": days_until(clock, &account.access_expires_at),
        "refresh_expires_at": account.refresh_expires_at,
        "refresh_expires_in_days": account
            .refresh_expires_at
            .as_deref()
            .and_then(|at| days_until(clock, at)),
        "budget": { "day": day, "spent": spent },
        "pages": pages.len(),
    })))
}

/// Forgets our copy of the tokens. It does not revoke them on LinkedIn's
/// side, which is a separate act by a human, and it deliberately keeps the
/// post history: that records what we published, which outlives a connection.
pub(crate) async fn disconnect(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    handlers::admin(&state, &headers)?;
    let ctx = state.ctx.as_ref();
    let db = handlers::db(ctx)?;
    let removed = store::delete_account(db).await.map_err(|error| {
        tracing::error!(error = %error, "could not delete the linkedin account");
        handlers::internal(&scope)
    })?;
    Ok(handlers::ok(json!({
        "ok": true,
        "removed": removed,
        "note": "tokens are forgotten here; revoking them on LinkedIn is a separate step",
    })))
}

fn days_until(clock: &dyn factory0_core::Clock, at: &str) -> Option<i64> {
    store::parse_iso(at).map(|expiry| (expiry - clock.now()).whole_days())
}

/// A fixed page for the human at the end of the redirect. No parameter from
/// the request reaches this string.
fn page(status: StatusCode, message: &'static str) -> Response {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>LinkedIn</title></head>\
<body style=\"font:16px/1.5 system-ui,sans-serif;margin:3rem auto;max-width:32rem;padding:0 1rem\">\
<p>{message}</p></body></html>"
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(body),
    )
        .into_response()
}
