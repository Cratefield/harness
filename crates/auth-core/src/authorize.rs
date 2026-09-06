//! The authorization code flow's browser endpoints (issue #10):
//! `GET /authorize` and `GET /logout`, with the server-rendered login
//! chooser and error pages.
//!
//! The two redirect rules everything here bends to:
//!
//! 1. **An unregistered `redirect_uri` never receives a redirect** —
//!    an unknown client, an unregistered URI and a disabled client
//!    all render the same generic error page, so the response cannot
//!    leak whether a client id exists and an attacker's URI is never
//!    validated by a redirect. Validation failures *after* the client
//!    and URI check (bad `response_type`, missing or non-S256
//!    challenge) redirect back to the registered URI with OAuth
//!    `error` parameters — spec-recommended, and safe because the URI
//!    is by then exact-matched against the registration.
//! 2. **No session, no code** — `/authorize` without a live session
//!    renders the login chooser; each login method's own issue
//!    (issues #13-#22) adds its button and returns here.
//!
//! Authorization codes are 32 random bytes, base64url, stored only as
//! their SHA-256 in a `single_use_tokens` row of kind
//! `authorization_code` carrying the client id, redirect URI, code
//! challenge and session id, expiring in 60 seconds.

use askama::Template;
use axum::extract::{Query, State};
use axum::extract::rejection::QueryRejection;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64ct::{Base64UrlUnpadded, Encoding};
use factory0_core::{Clock, Database, IdGen, Problem, Scope, subject_hash};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ModuleState;
use crate::redirect_uri::matches_any;
use crate::sessions;
use crate::secrets;
use crate::store::{self, TOKEN_AUTHORIZATION_CODE};

/// Authorization-code lifetime: 60 seconds, single-use.
pub const CODE_LIFETIME_SECS: i64 = 60;

/// The generic `/authorize` failure page's one message: same words
/// for unknown client, unregistered URI and disabled client, because
/// the page is the only channel that could leak the difference.
const AUTHORIZE_REFUSED_MESSAGE: &str = "The sign-in request did not match a registered application.";

/// A button on the login chooser. Empty until the login-method issues
/// land; the template carries the empty-state copy.
pub struct LoginMethod {
    pub slug: String,
    pub label: String,
    pub href: String,
}

#[derive(Template)]
#[template(path = "login_chooser.html")]
struct LoginChooserTemplate {
    methods: Vec<LoginMethod>,
}

#[derive(Template)]
#[template(path = "authorize_error.html")]
struct AuthorizeErrorTemplate {
    message: &'static str,
    request_id: String,
}

#[derive(Template)]
#[template(path = "signed_out.html")]
struct SignedOutTemplate;

fn iso(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .expect("rfc3339 formats")
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// The enabled login methods, in display order. Login methods are
/// issues #13-#22; none exists yet, so the chooser renders its
/// empty state until the first one lands and appends its button.
#[must_use]
pub fn enabled_login_methods() -> Vec<LoginMethod> {
    Vec::new()
}

fn error_page(scope: &Scope) -> Response {
    AuthorizeErrorTemplate {
        message: AUTHORIZE_REFUSED_MESSAGE,
        request_id: scope.request_id.clone(),
    }
    .into_response()
}

/// Percent-encodes one query component: unreserved characters pass,
/// everything else becomes `%XX`. The code is base64url already; the
/// client-supplied `state` is arbitrary text and must round-trip.
fn encode_query_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Builds the redirect back to the registered URI, appending to any
/// query the registration itself carries.
fn redirect_with_params(uri: &str, params: &[(&str, String)]) -> String {
    let separator = if uri.contains('?') { '&' } else { '?' };
    let query = params
        .iter()
        .map(|(key, value)| format!("{key}={}", encode_query_component(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{uri}{separator}{query}")
}

/// Redirects to the validated URI with an OAuth error code; used only
/// after the client and URI checks passed.
fn oauth_error_redirect(uri: &str, error: &str, state: Option<&str>) -> Response {
    let mut params = vec![("error", error.to_owned())];
    if let Some(state) = state {
        params.push(("state", state.to_owned()));
    }
    (
        StatusCode::FOUND,
        [(header::LOCATION, redirect_with_params(uri, &params))],
    )
        .into_response()
}

fn is_base64url_43(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
}

/// Validates the client and the exact redirect URI. `Err` renders the
/// generic error page — never a redirect — and never distinguishes an
/// unknown client from an unregistered URI or a disabled client.
async fn validate_client_and_uri(
    db: &dyn Database,
    client_id: &str,
    redirect_uri: &str,
) -> Result<store::ClientRow, ()> {
    let Some(client) = store::client_by_id(db, client_id).await.map_err(|_| ())? else {
        return Err(());
    };
    let registered = store::redirect_uris_for_client(db, client_id)
        .await
        .map_err(|_| ())?
        .into_iter()
        .map(|row| row.uri)
        .collect::<Vec<_>>();
    if !matches_any(&registered, redirect_uri) {
        return Err(());
    }
    if secrets::ensure_client_usable(&client).is_err() {
        return Err(());
    }
    Ok(client)
}

async fn authorize(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    query: Result<Query<AuthorizeQuery>, QueryRejection>,
) -> Result<Response, Problem> {
    let Query(query) = query.map_err(|_| Problem::internal())?;
    let (Some(db), Some(clock), Some(id_gen)) = (
        state.ctx.ports.db.clone(),
        state.ctx.ports.clock.clone(),
        state.ctx.ports.id_gen.clone(),
    ) else {
        return Err(Problem::internal());
    };

    // Client and URI first: any failure here renders the page, never
    // a redirect (the brief's one hard rule).
    if query.client_id.is_empty()
        || query.redirect_uri.is_empty()
        || validate_client_and_uri(&*db, &query.client_id, &query.redirect_uri)
            .await
            .is_err()
    {
        return Ok(error_page(&scope));
    }

    // From here the URI is registered: parameter failures redirect
    // back with OAuth error codes, as RFC 6749 section 4.1.2.1
    // recommends.
    if query.response_type != "code" {
        return Ok(oauth_error_redirect(
            &query.redirect_uri,
            "unsupported_response_type",
            query.state.as_deref(),
        ));
    }
    let challenge_ok = query
        .code_challenge
        .as_deref()
        .is_some_and(is_base64url_43);
    let method_ok = query.code_challenge_method.as_deref() == Some("S256");
    if !challenge_ok || !method_ok {
        // Missing challenge, wrong length, or any method other than
        // S256 — which includes `plain`, refused outright.
        return Ok(oauth_error_redirect(
            &query.redirect_uri,
            "invalid_request",
            query.state.as_deref(),
        ));
    }
    if let Some(state_param) = query.state.as_deref()
        && state_param.len() > 2048
    {
        return Ok(oauth_error_redirect(
            &query.redirect_uri,
            "invalid_request",
            None,
        ));
    }

    // A session is required to mint a code; without one, the login
    // chooser (its buttons arrive with the login-method issues).
    let Some(cookie) = sessions::cookie_value(&headers) else {
        return Ok(LoginChooserTemplate {
            methods: enabled_login_methods(),
        }
        .into_response());
    };
    let session = sessions::validate(&*db, &*clock, &cookie)
        .await
        .map_err(|_| Problem::internal())?;
    let Some(session) = session else {
        return Ok(LoginChooserTemplate {
            methods: enabled_login_methods(),
        }
        .into_response());
    };

    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| {
        tracing::error!(error = %err, "code entropy source failed");
        Problem::internal()
    })?;
    let code = Base64UrlUnpadded::encode_string(&bytes);
    let now = clock.now().replace_nanosecond(0).expect("in range");
    store::insert_single_use_token(
        &*db,
        &store::SingleUseTokenRow {
            id: id_gen.ulid(),
            kind: TOKEN_AUTHORIZATION_CODE.to_owned(),
            token_hash: store::Redacted(sha256(code.as_bytes())),
            user_id: Some(session.user_id.clone()),
            client_id: Some(query.client_id.clone()),
            payload: Some(
                json!({
                    "redirect_uri": query.redirect_uri,
                    "code_challenge": query.code_challenge,
                    "sid": session.id,
                })
                .to_string(),
            ),
            expires_at: iso(now.saturating_add(time::Duration::seconds(CODE_LIFETIME_SECS))),
            consumed_at: None,
        },
    )
    .await?;

    tracing::info!(
        audit = true,
        action = "authorize.grant",
        client_id = %query.client_id,
        subject_hash = %subject_hash(&session.user_id),
        "authorization code issued"
    );
    let mut params = vec![("code", code)];
    if let Some(state_param) = query.state.clone() {
        params.push(("state", state_param));
    }
    Ok((
        StatusCode::FOUND,
        [(header::LOCATION, redirect_with_params(&query.redirect_uri, &params))],
    )
        .into_response())
}

#[derive(Deserialize)]
struct LogoutQuery {
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
}

/// RP-initiated logout: revokes the session and redirects **only** to
/// a registered URI of a registered, active client — an unregistered
/// target renders the error page and never redirects. Without a
/// redirect target it revokes and shows the signed-out page.
async fn logout(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    query: Result<Query<LogoutQuery>, QueryRejection>,
) -> Result<Response, Problem> {
    let Query(query) = query.map_err(|_| Problem::internal())?;
    let (Some(db), Some(clock)) = (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone())
    else {
        return Err(Problem::internal());
    };

    let target = match (query.client_id, query.post_logout_redirect_uri) {
        (Some(client_id), Some(redirect)) => {
            match validate_client_and_uri(&*db, &client_id, &redirect).await {
                Ok(_) => redirect,
                // Unknown client, unregistered URI or disabled client:
                // same page, no redirect, nothing leaked.
                Err(()) => return Ok(error_page(&scope)),
            }
        }
        (_, Some(_)) => return Ok(error_page(&scope)),
        (None, None) => String::new(),
        (Some(_), None) => String::new(),
    };

    if let Some(cookie) = sessions::cookie_value(&headers)
        && let Ok(Some(session)) = sessions::validate(&*db, &*clock, &cookie).await
    {
        store::revoke_session(&*db, &session.id, &iso(clock.now())).await?;
        tracing::info!(
            audit = true,
            action = "logout.rp",
            subject_hash = %subject_hash(&session.user_id),
            "session revoked at logout"
        );
    }

    let clear = [(header::SET_COOKIE, sessions::clear_cookie())];
    if target.is_empty() {
        return Ok((clear, SignedOutTemplate).into_response());
    }
    Ok((StatusCode::FOUND, clear, [(header::LOCATION, target)]).into_response())
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new().route("/authorize", get(authorize)).route(
        "/logout",
        get(logout),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_components_round_trip_through_percent_encoding() {
        assert_eq!(encode_query_component("abcXYZ09-_.~"), "abcXYZ09-_.~");
        assert_eq!(encode_query_component("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(encode_query_component("héllo"), "h%C3%A9llo");
    }

    #[test]
    fn redirects_append_to_the_registered_query_properly() {
        assert_eq!(
            redirect_with_params("https://app.example/cb", &[("code", "c".to_owned())]),
            "https://app.example/cb?code=c"
        );
        assert_eq!(
            redirect_with_params(
                "https://app.example/cb?x=1",
                &[("code", "c".to_owned()), ("state", "s s".to_owned())]
            ),
            "https://app.example/cb?x=1&code=c&state=s%20s"
        );
    }

    #[test]
    fn challenges_must_be_43_base64url_characters() {
        assert!(is_base64url_43(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ));
        assert!(!is_base64url_43("short"));
        assert!(!is_base64url_43(&"x".repeat(44)));
        assert!(!is_base64url_43("d+BjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX"));
    }
}
