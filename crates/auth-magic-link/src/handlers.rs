//! The two routes (issue #21): request and consume.

use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use cratefield_core::{Json, Message, Problem, Scope, SendOutcome};
use factory0_auth_core::{
    Redacted, STATUS_ACTIVE, SingleUseTokenRow, TOKEN_MAGIC_LINK, UserRow,
    consume_single_use_token, cookie_value as session_cookie_value, insert_single_use_token,
    insert_user, set_cookie, single_use_token_by_hash, user_by_id, user_by_primary_email,
};
use http::{HeaderMap, StatusCode, header};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::mail::{self, MagicLinkMail};
use crate::{ModuleState, NOT_READY, REQUEST_REFUSED};

pub(crate) const EVENT_REQUESTED: &str = "auth-magic-link.requested";
pub(crate) const EVENT_LOGGED_IN: &str = "auth-magic-link.logged_in";
pub(crate) const EVENT_EMAIL_VERIFIED: &str = "auth-magic-link.email_verified";

/// RFC 8176: possession of the mailbox, and nothing else. Not `mfa`: one
/// factor, and the factor is an inbox.
const AMR: [&str; 1] = ["email"];

/// 32 random bytes. The token is the whole credential, so it is sized to
/// be unguessable rather than to be typed.
const TOKEN_BYTES: usize = 32;

/// A `return_to` longer than this is not a path anyone meant. Matches the
/// providers' limit so the login chooser's `/authorize` fits.
const MAX_RETURN_TO: usize = 4096;

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/request", post(request))
        .route("/consume", get(consume).post(confirm))
}

#[derive(Debug, Default, Deserialize)]
struct RequestBody {
    #[serde(default)]
    email: String,
    #[serde(default)]
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConsumeQuery {
    token: Option<String>,
}

/// Only a path on this service, for the same reason every other module
/// checks: an absolute URL here is an open redirect.
pub(crate) fn safe_return_to(candidate: Option<&str>) -> Option<String> {
    let value = candidate?.trim();
    if value.len() > MAX_RETURN_TO || !value.starts_with('/') {
        return None;
    }
    if value.starts_with("//") || value.starts_with("/\\") {
        return None;
    }
    if value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_owned())
}

fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn page(status: StatusCode, message: &str, confirm: Option<&str>) -> Response {
    let action = confirm.map_or_else(String::new, |token| {
        format!(
            "<form method=\"post\"><input type=\"hidden\" name=\"token\" value=\"{token}\">\
<button type=\"submit\" style=\"font:inherit;padding:12px 20px;border-radius:6px;\
border:0;background:#1a1a1a;color:#fff;font-weight:600;cursor:pointer\">Sign in</button></form>"
        )
    });
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"robots\" content=\"noindex\">\
<title>Sign in</title></head>\
<body style=\"font:16px/1.5 system-ui,sans-serif;margin:3rem auto;max-width:32rem;padding:0 1rem\">\
<p>{message}</p>{action}</body></html>"
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(body),
    )
        .into_response()
}

async fn limit(state: &ModuleState, headers: &HeaderMap, email: Option<&str>) -> Option<Response> {
    let limiter = state.ctx.ports.rate_limiter.as_deref()?;
    let ip = cratefield_core::client_ip(headers);
    // Keyed on the address as well as the caller: an unlimited request
    // endpoint is a way to send somebody a hundred emails.
    for key in cratefield_core::rate_limit_keys(ip.as_deref(), email) {
        match limiter.limit(&format!("auth-magic-link:{key}")).await {
            Ok(decision) if !decision.ok => {
                return Some(cratefield_core::rate_limited(decision.retry_after).into_response());
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "the auth-magic-link rate limiter is unavailable");
                return None;
            }
        }
    }
    None
}

async fn captcha_ok(state: &ModuleState, token: Option<&str>, headers: &HeaderMap) -> bool {
    let Some(captcha) = state.ctx.ports.captcha.as_deref() else {
        return true;
    };
    let ip = cratefield_core::client_ip(headers);
    match captcha
        .verify(token.unwrap_or_default(), ip.as_deref())
        .await
    {
        Ok(verdict) => verdict.ok,
        Err(err) => {
            // Fail closed: an outage at the captcha provider must not turn
            // this into an open mail relay.
            tracing::warn!(error = %err, "the captcha could not be verified");
            false
        }
    }
}

/// `POST /request`.
///
/// Always `202`, always the same body. A known address gets a mail; an
/// unknown one gets nothing, and the caller cannot tell which.
async fn request(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    raw: bytes::Bytes,
) -> Result<Response, Problem> {
    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    let parsed: RequestBody = serde_json::from_value(body.clone()).unwrap_or_default();
    let email = cratefield_core::normalize_email(&parsed.email);

    if let Some(limited) = limit(&state, &headers, Some(&email)).await {
        return Ok(limited);
    }
    let captcha_token = body
        .get("captchaToken")
        .and_then(Value::as_str)
        .or_else(|| body.get("captcha_token").and_then(Value::as_str));
    if !captcha_ok(&state, captcha_token, &headers).await {
        // Even this is the accepted answer: a caller who can tell a failed
        // captcha from a sent mail learns nothing useful, but a caller who
        // can tell it from an unknown address learns plenty.
        return Ok(accepted());
    }

    let Some(settings) = state.settings.as_ref() else {
        return Err(Problem::new(&NOT_READY));
    };
    let ctx = state.ctx.as_ref();
    let (Some(db), Some(clock), Some(id_gen), Some(mailer)) = (
        ctx.ports.db.as_deref(),
        ctx.ports.clock.as_deref(),
        ctx.ports.id_gen.as_deref(),
        ctx.ports.mailer.as_deref(),
    ) else {
        return Err(Problem::new(&NOT_READY));
    };

    if !email.contains('@') {
        return Ok(accepted());
    }

    let user = match user_by_primary_email(db, &email).await {
        Ok(user) => user,
        Err(err) => {
            tracing::error!(error = %err, "could not look up an address");
            return Err(Problem::internal().instance(&scope.request_id));
        }
    };

    let user_id = match (user, settings.allow_registration) {
        (Some(user), _) => {
            // A disabled account gets no link. Answered like everything
            // else, because "that account is switched off" is not a thing
            // an unauthenticated caller may learn.
            if user.status != STATUS_ACTIVE {
                return Ok(accepted());
            }
            user.id
        }
        (None, true) => match create_account(db, clock, id_gen, &email).await {
            Ok(id) => id,
            Err(err) => {
                tracing::error!(error = %err, "could not create an account for a magic link");
                return Err(Problem::internal().instance(&scope.request_id));
            }
        },
        // No account, and this venture does not register by link.
        (None, false) => return Ok(accepted()),
    };

    if let Err(err) = issue_link(
        db,
        clock,
        id_gen,
        mailer,
        ctx,
        settings,
        &user_id,
        &email,
        parsed.return_to.as_deref(),
    )
    .await
    {
        tracing::error!(error = %err, "could not issue a sign-in link");
        return Err(Problem::internal().instance(&scope.request_id));
    }

    ctx.events
        .emit_in(&scope, EVENT_REQUESTED, json!({ "user_id": user_id }));
    Ok(accepted())
}

/// Mints the token, stores its digest and sends the mail.
///
/// Split out so `request` stays readable. A send that fails is logged and
/// swallowed by the caller: the answer is the same either way, and telling
/// a caller the mail bounced would tell them the address exists.
#[allow(clippy::too_many_arguments)]
async fn issue_link(
    db: &dyn cratefield_core::Database,
    clock: &dyn cratefield_core::Clock,
    id_gen: &dyn cratefield_core::IdGen,
    mailer: &dyn cratefield_core::Mailer,
    ctx: &cratefield_core::ModuleContext,
    settings: &crate::Settings,
    user_id: &str,
    email: &str,
    return_to: Option<&str>,
) -> Result<(), cratefield_core::DbError> {
    let Some(token) = random_token() else {
        return Err(cratefield_core::DbError::Query(
            "the entropy source failed".to_owned(),
        ));
    };
    let expires_at = crate::handlers::iso(
        clock
            .now()
            .saturating_add(time::Duration::seconds(settings.ttl_secs)),
    );
    let row = SingleUseTokenRow {
        id: id_gen.ulid(),
        kind: TOKEN_MAGIC_LINK.to_owned(),
        // Only the digest is stored. A leaked database row is not a way in.
        token_hash: Redacted(hash(&token)),
        user_id: Some(user_id.to_owned()),
        client_id: None,
        payload: safe_return_to(return_to)
            .map(|return_to| json!({ "return_to": return_to }).to_string()),
        expires_at,
        consumed_at: None,
    };
    insert_single_use_token(db, &row).await?;

    let link = format!(
        "{}/v1/auth-magic-link/consume?token={token}",
        settings.public_base
    );
    let rendered = match mail::render(
        &ctx.templates,
        &MagicLinkMail {
            venture: ctx.venture.name.clone(),
            link,
            minutes: settings.ttl_secs / 60,
        },
        "en",
    ) {
        Ok(rendered) => rendered,
        Err(err) => {
            tracing::error!(error = %err, "could not render the sign-in mail");
            return Err(cratefield_core::DbError::Query(err.to_string()));
        }
    };

    match mailer
        .send(
            Message::new(
                email,
                settings.mail_from.clone(),
                rendered.subject,
                rendered.text,
                rendered.html,
            )
            .idempotency_key(row.id.clone())
            .tags(["auth-magic-link"]),
        )
        .await
    {
        Ok(SendOutcome::Sent { .. }) => {}
        Ok(SendOutcome::NotConfigured) => {
            // The adapter has no key. Logged loudly, because every request
            // will silently do nothing until somebody notices.
            tracing::error!("the mailer is not configured; no sign-in link was sent");
        }
        Err(err) => {
            // The address is never logged: a log line naming who asked to
            // sign in is the thing this endpoint refuses to say out loud.
            tracing::error!(error = %err, "could not send a sign-in link");
        }
    }

    Ok(())
}

/// The one answer a request gives.
fn accepted() -> Response {
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "accepted",
            "message": "If that address can sign in, a link is on its way.",
        })),
    )
        .into_response()
}

fn random_token() -> Option<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    Some(Base64UrlUnpadded::encode_string(&bytes))
}

pub(crate) fn iso(at: time::OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

async fn create_account(
    db: &dyn cratefield_core::Database,
    clock: &dyn cratefield_core::Clock,
    id_gen: &dyn cratefield_core::IdGen,
    email: &str,
) -> Result<String, cratefield_core::DbError> {
    let now = iso(clock.now());
    let id = id_gen.ulid();
    insert_user(
        db,
        &UserRow {
            id: id.clone(),
            display_name: None,
            primary_email: Some(email.to_owned()),
            // Unverified until the link is consumed. Creating the row is
            // not proof of anything; opening the mail is.
            primary_email_verified: false,
            status: STATUS_ACTIVE.to_owned(),
            created_at: now.clone(),
            updated_at: now,
        },
    )
    .await?;
    Ok(id)
}

/// Whether this request looks like a person clicking rather than a mail
/// client checking the link.
///
/// **A heuristic, and the limits are the point.** Fetch metadata headers
/// are sent by every current browser on a top-level navigation:
/// `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`. A scanner
/// fetching the URL out of band sends neither, or sends `empty`/`no-cors`.
///
/// What it does **not** catch: a scanner that copies a real browser's
/// headers, or one that renders the message in a real browser engine.
/// What it must not do is refuse a real person — so a request with no
/// fetch metadata at all (an old browser, a stripped proxy) gets the
/// confirm button rather than a refusal, which costs one click and works
/// everywhere.
fn looks_like_a_click(headers: &HeaderMap) -> bool {
    let value = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_ascii_lowercase)
    };
    value("sec-fetch-mode").as_deref() == Some("navigate")
        && value("sec-fetch-dest").as_deref() == Some("document")
}

/// `GET /consume?token=…`, the URL in the mail.
///
/// Does **not** spend the token unless the request looks like a person
/// clicking. Mail clients and corporate scanners prefetch links, and a
/// prefetch that consumed a single-use token would sign nobody in and
/// leave the person with a link that has already been used.
async fn consume(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Query(query): Query<ConsumeQuery>,
) -> Result<Response, Problem> {
    let token = query.token.unwrap_or_default();
    if token.is_empty() {
        return Ok(expired_page());
    }
    if !looks_like_a_click(&headers) {
        // Nothing is read, nothing is spent: the answer is the same page
        // whether or not the token is real, so a scanner cannot use this
        // to test one.
        return Ok(page(
            StatusCode::OK,
            "Confirm that it was you who asked to sign in.",
            Some(&token),
        ));
    }
    spend(&state, &scope, &headers, &token).await
}

/// `POST /consume`, the confirm button.
async fn confirm(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Problem> {
    let token = url::form_urlencoded::parse(body.as_bytes())
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.to_string())
        .unwrap_or_default();
    if token.is_empty() {
        return Ok(expired_page());
    }
    spend(&state, &scope, &headers, &token).await
}

/// Spends the token and signs the person in.
///
/// Single-use is enforced by `consume_single_use_token`, which updates
/// `where consumed_at is null and expires_at > now` and checks the
/// affected row count. Two simultaneous consumes therefore produce one
/// session and one refusal, rather than two sessions or a lost update.
async fn spend(
    state: &ModuleState,
    scope: &Scope,
    headers: &HeaderMap,
    token: &str,
) -> Result<Response, Problem> {
    let Some(settings) = state.settings.as_ref() else {
        return Err(Problem::new(&NOT_READY));
    };
    let ctx = state.ctx.as_ref();
    let (Some(db), Some(clock), Some(id_gen)) = (
        ctx.ports.db.as_deref(),
        ctx.ports.clock.as_deref(),
        ctx.ports.id_gen.as_deref(),
    ) else {
        return Err(Problem::new(&NOT_READY));
    };
    let now = iso(clock.now());

    let Ok(Some(row)) = single_use_token_by_hash(db, &hash(token)).await else {
        return Ok(expired_page());
    };
    // A token of the wrong kind is not this endpoint's business: an
    // authorization code presented here must not become a session.
    if row.kind != TOKEN_MAGIC_LINK {
        tracing::warn!(kind = %row.kind, "a token of another kind was presented to the magic link");
        return Ok(expired_page());
    }

    // The one statement that makes this single-use.
    let Ok(Some(spent)) = consume_single_use_token(db, &row.id, &now).await else {
        // Expired, or somebody else got there first. Both answer the same
        // way: an attacker racing a real person must not learn they lost.
        return Ok(expired_page());
    };

    let Some(user_id) = spent.user_id.clone() else {
        return Ok(expired_page());
    };
    let Ok(Some(user)) = user_by_id(db, &user_id).await else {
        return Ok(expired_page());
    };
    if user.status != STATUS_ACTIVE {
        return Ok(expired_page());
    }

    // Opening a link sent to an address is the proof that the address is
    // theirs, and the only proof this service has. The linking rules only
    // ever auto-link a verified address, so this is what makes one.
    if !user.primary_email_verified {
        if let Err(err) = factory0_auth_core::set_primary_email_verified(db, &user.id, &now).await {
            tracing::warn!(error = %err, "could not record a verified address");
        } else {
            ctx.events
                .emit_in(scope, EVENT_EMAIL_VERIFIED, json!({ "user_id": user.id }));
        }
    }

    let presented = session_cookie_value(headers);
    let session = factory0_auth_core::issue(
        db,
        clock,
        id_gen,
        factory0_auth_core::Login {
            user_id: &user.id,
            ip: cratefield_core::client_ip(headers).as_deref(),
            user_agent: headers
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            presented_cookie: presented.as_deref(),
            // A top-level GET from the mailed link, so the cookie above
            // arrives and names the session itself (auth #36).
            presented_session_id: None,
            amr: &AMR,
        },
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "could not issue a session");
        Problem::new(&REQUEST_REFUSED).instance(&scope.request_id)
    })?;

    ctx.events.emit_in(
        scope,
        EVENT_LOGGED_IN,
        json!({ "user_id": user.id, "session_id": session.session_id }),
    );

    let return_to = spent
        .payload
        .as_deref()
        .and_then(|payload| serde_json::from_str::<Value>(payload).ok())
        .and_then(|payload| {
            payload
                .get("return_to")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .and_then(|candidate| safe_return_to(Some(&candidate)))
        .unwrap_or_else(|| settings.default_return_to.clone());

    let mut response = (StatusCode::FOUND, [(header::LOCATION, return_to)]).into_response();
    if let Ok(value) = header::HeaderValue::from_str(&set_cookie(&session.value)) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    Ok(response)
}

fn expired_page() -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "That sign-in link has expired or was already used. Ask for another.",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_return_to_may_only_be_a_path_on_this_service() {
        assert_eq!(
            safe_return_to(Some("/account")).as_deref(),
            Some("/account")
        );
        for bad in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "javascript:alert(1)",
            "",
            "/ok\nSet-Cookie: x",
        ] {
            assert_eq!(safe_return_to(Some(bad)), None, "{bad} was accepted");
        }
    }

    #[test]
    fn only_a_browser_navigation_counts_as_a_click() {
        let with = |pairs: &[(&str, &str)]| {
            let mut headers = HeaderMap::new();
            for (name, value) in pairs {
                headers.insert(
                    http::HeaderName::from_bytes(name.as_bytes()).expect("name"),
                    value.parse().expect("value"),
                );
            }
            headers
        };

        assert!(looks_like_a_click(&with(&[
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-dest", "document"),
        ])));
        // Case is not significant in the header value.
        assert!(looks_like_a_click(&with(&[
            ("sec-fetch-mode", "Navigate"),
            ("sec-fetch-dest", "Document"),
        ])));

        // What a scanner sends, and what an old browser sends: neither is
        // refused, both get the confirm button.
        for headers in [
            with(&[]),
            with(&[("sec-fetch-mode", "no-cors"), ("sec-fetch-dest", "empty")]),
            with(&[("sec-fetch-mode", "navigate")]),
            with(&[("sec-fetch-dest", "document")]),
            with(&[("sec-fetch-mode", "cors"), ("sec-fetch-dest", "document")]),
        ] {
            assert!(!looks_like_a_click(&headers), "{headers:?}");
        }
    }

    #[test]
    fn a_token_is_stored_only_as_its_digest() {
        let token = random_token().expect("entropy");
        let digest = hash(&token);
        assert_eq!(digest.len(), 32);
        assert_ne!(
            digest,
            token.as_bytes(),
            "the token itself must not be stored"
        );
        // Deterministic, so a lookup by digest finds it.
        assert_eq!(digest, hash(&token));
        assert_ne!(digest, hash(&random_token().expect("entropy")));
    }

    #[test]
    fn tokens_are_unguessable_and_url_safe() {
        let first = random_token().expect("entropy");
        let second = random_token().expect("entropy");
        assert_ne!(first, second);
        // It goes in a URL in an email, which some clients rewrite.
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert!(first.len() >= 43, "32 bytes of entropy: {first}");
    }
}
