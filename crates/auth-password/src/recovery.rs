//! Address verification and password recovery (issues #19, #20).
//!
//! Two single-use bearer credentials sent by mail, and the same rules as
//! `auth-magic-link` for both, because a link in an inbox is a channel
//! this service does not control:
//!
//! - **The link asks; only the button acts.** `GET /verify` and `GET
//!   /reset` never read or spend the token — they render a form whose
//!   same-origin `POST` does the work. Mail scanners and previews fetch
//!   every URL in a message, and a prefetch that spent a single-use token
//!   would leave the person with a link that has already been used.
//! - **Nothing distinguishes the reasons.** Missing, expired, already
//!   used, never issued and the wrong kind are one answer, in status and
//!   body alike.
//! - **The response never says whether an address has an account.**
//!   `/register`, `/verify/resend` and `/reset/request` answer `202` and
//!   the same body either way; only the owner of the address learns by
//!   mail.

use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use cratefield_core::{
    Json, Message, ModuleContext, Problem, Rendered, Scope, SendOutcome, Template,
};
use factory0_auth_core::{
    Redacted, STATUS_ACTIVE, SingleUseTokenRow, TOKEN_EMAIL_VERIFICATION, TOKEN_PASSWORD_RESET,
    TOKEN_REFRESH, UserRow, consume_single_use_token, hash_password, insert_single_use_token,
    password_credential, retire_unconsumed_tokens, revoke_all_sessions, set_password_hash,
    set_primary_email_verified, single_use_token_by_hash, user_by_id, user_by_primary_email,
};
use http::{HeaderMap, StatusCode, Uri, header};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::handlers::{body_of, captcha_ok, html_escape, limit_pause, looks_like_an_address};
use crate::mail::{self, DuplicateMail, ResetMail, VerifyMail};
use crate::{
    ModuleState, NOT_READY, PASSWORD_UNSUITABLE, RESET_TTL_SECS, TOKEN_REFUSED, VERIFY_TTL_SECS,
    password_length_ok,
};

pub(crate) const EVENT_EMAIL_VERIFIED: &str = "auth-password.email_verified";
/// A password was reset. `user_id` and nothing else — the same shape as
/// every other event in the auth stack, and never an address.
pub(crate) const EVENT_RESET: &str = "auth-password.reset";

/// 32 random bytes. The token is the whole credential, so it is sized to
/// be unguessable rather than to be typed.
const TOKEN_BYTES: usize = 32;

/// The tag every message this module sends carries, for an adapter that
/// routes or filters by it.
const MAIL_TAG: &str = "auth-password";

/// The one answer a request endpoint gives, whatever it found. The caller
/// cannot tell a known address from an unknown one, a captcha pass from a
/// captcha failure, or a mail that went out from one that did not.
const ACCEPTED_RESEND: &str = "If that address has an account, a link is on its way.";
const ACCEPTED_RESET: &str = "If that address has an account, a reset link is on its way.";

#[derive(Debug, Deserialize)]
pub(crate) struct TokenQuery {
    token: Option<String>,
}

/// Whether a request is the JSON API or the hosted form. Only the body
/// shape and the answer's content type differ; the decision is one
/// function either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Api,
    Form,
}

fn kind_of(headers: &HeaderMap) -> Kind {
    match headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        Some(value) if value.to_ascii_lowercase().contains("json") => Kind::Api,
        _ => Kind::Form,
    }
}

/// Reads one field from either a JSON object or a form-encoded body,
/// following whichever the request declared.
fn field(raw: &[u8], kind: Kind, name: &str) -> String {
    match kind {
        Kind::Api => body_of(raw)
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        Kind::Form => url::form_urlencoded::parse(raw)
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Token shape

fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn random_token() -> Option<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    Some(Base64UrlUnpadded::encode_string(&bytes))
}

/// Whether a presented value could be one of ours at all: the unpadded
/// base64url length of [`TOKEN_BYTES`], in that alphabet and no other.
/// A value that is not token-shaped never reaches a lookup.
fn looks_like_a_token(value: &str) -> bool {
    let len = (TOKEN_BYTES * 4).div_ceil(3);
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Latitudes, for a locale tag: `en`, `en-GB`, `nb-NO`. Anything else
/// falls back to `en`, the same sanitisation `module-email-signup` uses.
pub(crate) fn sanitize_locale(raw: Option<&str>) -> String {
    fn is_tag(tag: &str) -> bool {
        let mut parts = tag.split('-');
        let language_ok = parts.next().is_some_and(|part| {
            (2..=3).contains(&part.len()) && part.chars().all(|c| c.is_ascii_alphabetic())
        });
        let region_ok = parts.next().is_none_or(|part| {
            (2..=4).contains(&part.len()) && part.chars().all(|c| c.is_ascii_alphabetic())
        });
        language_ok && region_ok && parts.next().is_none()
    }
    raw.filter(|tag| is_tag(tag)).unwrap_or("en").to_owned()
}

// ---------------------------------------------------------------------------
// Pages (the hosted variant)

/// The bits of styling the three hosted forms share, written once.
const LABEL: &str = "style=\"display:block;margin-bottom:.4rem\"";
const FIELD: &str = "style=\"font:inherit;padding:10px;width:100%;box-sizing:border-box;\
border:1px solid #ccc;border-radius:6px\"";
const BUTTON: &str = "style=\"font:inherit;padding:12px 20px;border-radius:6px;border:0;\
background:#1a1a1a;color:#fff;font-weight:600;cursor:pointer\"";

fn page_html(status: StatusCode, title: &str, body: &str) -> Response {
    let document = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"robots\" content=\"noindex\">\
<title>{}</title></head>\
<body style=\"font:16px/1.5 system-ui,sans-serif;margin:3rem auto;max-width:32rem;\
padding:0 1rem\">{body}</body></html>",
        html_escape(title)
    );
    // These pages carry a token in their HTML (the hidden field) or a
    // result only the person who asked should see. The `no-store` and
    // `no-referrer` they must answer with are stamped by the harness's
    // `/v1/*` security layer (a module response cannot dodge it), so only
    // the content type is set here.
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(document),
    )
        .into_response()
}

/// A hidden token field, escaped. The token came off a mail link, so it
/// is caller-supplied and lands in a `value=`.
fn hidden_token(token: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"token\" value=\"{}\">",
        html_escape(token)
    )
}

/// The refusal page. One page for missing, expired, used and never-issued
/// alike — a page cannot be the place the reasons separate.
fn refused_page() -> Response {
    page_html(
        StatusCode::BAD_REQUEST,
        "That link is no longer valid",
        "<p>That link has expired or was already used. Ask for another.</p>",
    )
}

/// `GET /verify` — the confirm button. Never reads the token.
pub(crate) async fn verify_form(Query(query): Query<TokenQuery>) -> Response {
    let token = query.token.unwrap_or_default();
    if !looks_like_a_token(&token) {
        return refused_page();
    }
    let body = format!(
        "<p>Confirm that this address belongs to you.</p>\
<form method=\"post\">{}\
<button type=\"submit\" {BUTTON}>Confirm address</button></form>",
        hidden_token(&token)
    );
    page_html(StatusCode::OK, "Confirm your address", &body)
}

/// `GET /reset?token=…` — the new-password form. Never reads the token.
pub(crate) async fn reset_form(Query(query): Query<TokenQuery>) -> Response {
    let token = query.token.unwrap_or_default();
    if !looks_like_a_token(&token) {
        return refused_page();
    }
    password_page(&token, None)
}

/// `GET /reset/request` — the "forgot your password" form, the page the
/// duplicate-registration mail points at.
pub(crate) async fn request_form() -> Response {
    let body = format!(
        "<form method=\"post\">\
<label for=\"email\" {LABEL}>Email address</label>\
<input id=\"email\" name=\"email\" type=\"email\" autocomplete=\"email\" required \
autofocus {FIELD}>\
<button type=\"submit\" {BUTTON}>Email me a reset link</button></form>"
    );
    page_html(StatusCode::OK, "Reset your password", &body)
}

fn password_page(token: &str, message: Option<&str>) -> Response {
    let note = message.map_or_else(String::new, |text| {
        format!("<p style=\"color:#a33\">{}</p>", html_escape(text))
    });
    let body = format!(
        "{note}<form method=\"post\">{}\
<label for=\"new_password\" {LABEL}>New password</label>\
<input id=\"new_password\" name=\"new_password\" type=\"password\" \
autocomplete=\"new-password\" minlength=\"8\" required autofocus {FIELD}>\
<button type=\"submit\" {BUTTON}>Set a new password</button></form>",
        hidden_token(token)
    );
    page_html(StatusCode::OK, "Choose a new password", &body)
}

// ---------------------------------------------------------------------------
// Issuing and spending

struct Issued {
    /// The row id, used as the message idempotency key.
    id: String,
    /// The token itself, which is only ever mailed, never logged or
    /// stored.
    token: String,
}

/// Mints a token, stores its digest and retires the user's older live
/// tokens of the same kind, so a second request invalidates the first.
async fn issue_token(
    db: &dyn cratefield_core::Database,
    clock: &dyn cratefield_core::Clock,
    id_gen: &dyn cratefield_core::IdGen,
    kind: &str,
    user_id: &str,
    ttl_secs: i64,
) -> Result<Issued, cratefield_core::DbError> {
    let Some(token) = random_token() else {
        return Err(cratefield_core::DbError::Query(
            "the entropy source failed".to_owned(),
        ));
    };
    let issued_at = clock.now();
    let now = crate::lockout::iso(issued_at);
    let expires_at =
        crate::lockout::iso(issued_at.saturating_add(time::Duration::seconds(ttl_secs)));
    let row = SingleUseTokenRow {
        id: id_gen.ulid(),
        kind: kind.to_owned(),
        // Only the digest is stored. A leaked database row is not a way
        // in.
        token_hash: Redacted(hash(&token)),
        user_id: Some(user_id.to_owned()),
        client_id: None,
        payload: None,
        expires_at,
        consumed_at: None,
    };
    retire_unconsumed_tokens(db, kind, user_id, &now).await?;
    insert_single_use_token(db, &row).await?;
    Ok(Issued { id: row.id, token })
}

/// Consumes a token of the expected kind and returns the account it names.
///
/// `Ok(None)` is the one refusal: missing, expired, already used, never
/// issued, or a token of another kind. A `DbError` is reported, never
/// turned into a refusal, so a database outage does not look like a bad
/// link.
async fn spend_token(
    db: &dyn cratefield_core::Database,
    now: &str,
    token: &str,
    kind: &str,
) -> Result<Option<UserRow>, Problem> {
    let row = match single_use_token_by_hash(db, &hash(token)).await {
        Ok(row) => row,
        Err(err) => {
            tracing::error!(error = %err, "could not look up a recovery token");
            return Err(Problem::internal());
        }
    };
    let Some(row) = row else {
        return Ok(None);
    };
    if row.kind != kind {
        tracing::warn!(kind = %row.kind, "a token of another kind was presented");
        return Ok(None);
    }
    // The one statement that makes this single-use: it stamps
    // `consumed_at` only on an unconsumed, unexpired row and checks the
    // affected count, so of two concurrent spends at most one wins.
    let spent = match consume_single_use_token(db, &row.id, now).await {
        Ok(spent) => spent,
        Err(err) => {
            tracing::error!(error = %err, "could not consume a recovery token");
            return Err(Problem::internal());
        }
    };
    let Some(spent) = spent else {
        return Ok(None);
    };
    let Some(user_id) = spent.user_id.clone() else {
        return Ok(None);
    };
    match user_by_id(db, &user_id).await {
        Ok(Some(user)) if user.status == STATUS_ACTIVE => Ok(Some(user)),
        Ok(_) => Ok(None),
        Err(err) => {
            tracing::error!(error = %err, "could not read the account a recovery token names");
            Err(Problem::internal())
        }
    }
}

// ---------------------------------------------------------------------------
// Sending

/// Sends one rendered message. A send failure is logged and swallowed:
/// the caller's answer is the same whether the mail went out, and telling
/// a caller it bounced would tell them the address exists.
async fn deliver(
    mailer: &dyn cratefield_core::Mailer,
    to: &str,
    from: &str,
    idempotency_key: &str,
    rendered: Rendered,
) {
    match mailer
        .send(
            Message::new(to, from, rendered.subject, rendered.text, rendered.html)
                .idempotency_key(idempotency_key.to_owned())
                .tags([MAIL_TAG]),
        )
        .await
    {
        Ok(SendOutcome::Sent { .. }) => {}
        Ok(SendOutcome::NotConfigured) => {
            tracing::error!("the mailer is not configured; no auth-password mail was sent");
        }
        // The address is never logged: a log line naming who asked to
        // verify or reset is the thing this module refuses to say.
        Err(err) => tracing::error!(error = %err, "could not send auth-password mail"),
    }
}

/// Renders through the registry, logging a render failure instead of
/// returning it — a failure here means no mail, not a different answer.
fn render<T: serde::Serialize>(
    ctx: &ModuleContext,
    id: &str,
    default: &dyn Template,
    data: &T,
    locale: &str,
) -> Option<Rendered> {
    match mail::render(&ctx.templates, id, default, data, locale) {
        Ok(rendered) => Some(rendered),
        Err(err) => {
            tracing::error!(error = %err, "could not render auth-password mail");
            None
        }
    }
}

/// Every mail here is returned as work rather than performed, so the
/// caller's answer does not wait on the mailer: `register`,
/// `/verify/resend` and `/reset/request` hand it to
/// `scope.defer.wait_until` (Workers `wait_until`, `tokio::spawn`
/// natively), the same shape `module-email-signup` uses for its welcome
/// mail. A deployment with no mailer, no `PUBLIC_BASE`/`MAIL_FROM`, or a
/// mailer that fails still answers `202`, and the token is simply not
/// issued.
///
/// An address that is not an address is never mailed: [`cratefield_core::is_valid`]
/// refuses control characters and anything else that is not an address, and
/// the caller's answer is the same either way.
fn spawn(
    work: impl std::future::Future<Output = ()> + Send + 'static,
) -> cratefield_core::BoxFuture<'static, ()> {
    Box::pin(work)
}

/// The verification link for an unverified address.
pub(crate) fn send_verify_mail(
    state: Arc<ModuleState>,
    user_id: &str,
    email: &str,
    locale: &str,
) -> cratefield_core::BoxFuture<'static, ()> {
    let (user_id, email, locale) = (user_id.to_owned(), email.to_owned(), locale.to_owned());
    spawn(async move {
        if !cratefield_core::is_valid(&email) {
            tracing::warn!("no verification mail was sent to an invalid address");
            return;
        }
        let ctx = state.ctx.as_ref();
        let Some((public_base, mail_from)) = state.settings.mail_ready() else {
            tracing::warn!("no PUBLIC_BASE/MAIL_FROM configured; no verification mail was sent");
            return;
        };
        let (Some(db), Some(clock), Some(id_gen), Some(mailer)) = (
            ctx.ports.db.as_deref(),
            ctx.ports.clock.as_deref(),
            ctx.ports.id_gen.as_deref(),
            ctx.ports.mailer.as_deref(),
        ) else {
            return;
        };
        let issued = match issue_token(
            db,
            clock,
            id_gen,
            TOKEN_EMAIL_VERIFICATION,
            &user_id,
            VERIFY_TTL_SECS,
        )
        .await
        {
            Ok(issued) => issued,
            Err(err) => {
                tracing::error!(error = %err, "could not issue a verification token");
                return;
            }
        };
        let link = format!(
            "{public_base}/v1/auth-password/verify?token={}",
            issued.token
        );
        let data = VerifyMail {
            venture: ctx.venture.name.clone(),
            link,
            hours: VERIFY_TTL_SECS / 3600,
        };
        if let Some(rendered) = render(
            ctx,
            mail::TEMPLATE_VERIFY,
            &mail::VerifyDefault,
            &data,
            &locale,
        ) {
            deliver(mailer, &email, mail_from, &issued.id, rendered).await;
        }
    })
}

/// The password-reset link for an account that has a password credential.
pub(crate) fn send_reset_mail(
    state: Arc<ModuleState>,
    user_id: &str,
    email: &str,
    locale: &str,
) -> cratefield_core::BoxFuture<'static, ()> {
    let (user_id, email, locale) = (user_id.to_owned(), email.to_owned(), locale.to_owned());
    spawn(async move {
        if !cratefield_core::is_valid(&email) {
            tracing::warn!("no reset mail was sent to an invalid address");
            return;
        }
        let ctx = state.ctx.as_ref();
        let Some((public_base, mail_from)) = state.settings.mail_ready() else {
            tracing::warn!("no PUBLIC_BASE/MAIL_FROM configured; no reset mail was sent");
            return;
        };
        let (Some(db), Some(clock), Some(id_gen), Some(mailer)) = (
            ctx.ports.db.as_deref(),
            ctx.ports.clock.as_deref(),
            ctx.ports.id_gen.as_deref(),
            ctx.ports.mailer.as_deref(),
        ) else {
            return;
        };
        let issued = match issue_token(
            db,
            clock,
            id_gen,
            TOKEN_PASSWORD_RESET,
            &user_id,
            RESET_TTL_SECS,
        )
        .await
        {
            Ok(issued) => issued,
            Err(err) => {
                tracing::error!(error = %err, "could not issue a reset token");
                return;
            }
        };
        let link = format!(
            "{public_base}/v1/auth-password/reset?token={}",
            issued.token
        );
        let data = ResetMail {
            venture: ctx.venture.name.clone(),
            link,
            minutes: RESET_TTL_SECS / 60,
        };
        if let Some(rendered) = render(
            ctx,
            mail::TEMPLATE_RESET,
            &mail::ResetDefault,
            &data,
            &locale,
        ) {
            deliver(mailer, &email, mail_from, &issued.id, rendered).await;
        }
    })
}

/// Tells the owner of an address that somebody tried to register it. Sent
/// to any existing account, including one that has only ever signed in by
/// magic link.
pub(crate) fn send_duplicate_mail(
    state: Arc<ModuleState>,
    user: &UserRow,
    locale: &str,
) -> cratefield_core::BoxFuture<'static, ()> {
    let Some(email) = user.primary_email.clone() else {
        return spawn(async {});
    };
    let id = user.id.clone();
    let locale = locale.to_owned();
    spawn(async move {
        if !cratefield_core::is_valid(&email) {
            tracing::warn!("no duplicate mail was sent to an invalid address");
            return;
        }
        let ctx = state.ctx.as_ref();
        let Some((public_base, mail_from)) = state.settings.mail_ready() else {
            tracing::warn!("no PUBLIC_BASE/MAIL_FROM configured; no duplicate mail was sent");
            return;
        };
        let Some(mailer) = ctx.ports.mailer.as_deref() else {
            return;
        };
        let data = DuplicateMail {
            venture: ctx.venture.name.clone(),
            reset_link: format!("{public_base}/v1/auth-password/reset/request"),
        };
        // Keyed on the user, not a token row: there is no token here, and
        // the key still stops a duplicate mail per account within the
        // adapter's window.
        if let Some(rendered) = render(
            ctx,
            mail::TEMPLATE_DUPLICATE,
            &mail::DuplicateDefault,
            &data,
            &locale,
        ) {
            deliver(mailer, &email, mail_from, &format!("dup-{id}"), rendered).await;
        }
    })
}

// ---------------------------------------------------------------------------
// The token-consuming endpoints

/// `POST /verify` — the confirm button (form) or an API call.
pub(crate) async fn verify(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    uri: Uri,
    raw: bytes::Bytes,
) -> Result<Response, Problem> {
    // Spending a verification token changes account state, so a form on
    // another site must not be able to press this button (issue #439).
    factory0_auth_core::csrf::require_same_origin(&headers, &uri)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let kind = kind_of(&headers);
    let token = field(&raw, kind, "token");
    if !looks_like_a_token(&token) {
        return Ok(refusal(kind));
    }
    if let Some(decision) = limit_pause(&state, &headers, None).await {
        return Ok(limited(kind, &decision));
    }

    let ctx = state.ctx.as_ref();
    let (Some(db), Some(clock)) = (ctx.ports.db.as_deref(), ctx.ports.clock.as_deref()) else {
        return Err(Problem::new(&NOT_READY));
    };
    let now = crate::lockout::iso(clock.now());

    let Some(user) = spend_token(db, &now, &token, TOKEN_EMAIL_VERIFICATION).await? else {
        return Ok(refusal(kind));
    };
    // The event says "this address became verified", not "somebody pressed
    // confirm": an address that is already verified changes nothing, so
    // nothing is announced. (The token is still spent either way — it is
    // single-use.)
    if !user.primary_email_verified {
        if let Err(err) = set_primary_email_verified(db, &user.id, &now).await {
            tracing::error!(error = %err, "could not record a verified address");
            return Err(Problem::internal().instance(&scope.request_id));
        }
        ctx.events
            .emit_in(&scope, EVENT_EMAIL_VERIFIED, json!({ "user_id": user.id }));
    }
    Ok(success(kind, "Your address is confirmed.", "verified"))
}

/// `POST /reset` — choose a new password (form) or an API call.
pub(crate) async fn reset(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    uri: Uri,
    raw: bytes::Bytes,
) -> Result<Response, Problem> {
    factory0_auth_core::csrf::require_same_origin(&headers, &uri)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let kind = kind_of(&headers);
    let token = field(&raw, kind, "token");
    let new_password = field(&raw, kind, "new_password");
    if !looks_like_a_token(&token) {
        return Ok(refusal(kind));
    }
    if let Some(decision) = limit_pause(&state, &headers, None).await {
        return Ok(limited(kind, &decision));
    }

    // The password is the person's own business, and telling them it is
    // too short or breached reveals nothing about anybody else. Checked
    // before the token is spent, so a rejected password does not cost
    // them the link.
    if !password_length_ok(&new_password) {
        if kind == Kind::Form {
            return Ok(password_page(
                &token,
                Some("Choose a password of at least 8 characters."),
            ));
        }
        return Err(Problem::new(&PASSWORD_UNSUITABLE).instance(&scope.request_id));
    }

    let ctx = state.ctx.as_ref();
    let (Some(db), Some(clock)) = (ctx.ports.db.as_deref(), ctx.ports.clock.as_deref()) else {
        return Err(Problem::new(&NOT_READY));
    };
    if state.settings.breach_check
        && let Some(http) = ctx.ports.http.as_ref()
        && crate::breach::is_breached(http, &new_password).await
    {
        if kind == Kind::Form {
            return Ok(password_page(
                &token,
                Some("That password has appeared in a public breach. Choose another."),
            ));
        }
        return Err(Problem::new(&PASSWORD_UNSUITABLE).instance(&scope.request_id));
    }

    let now = crate::lockout::iso(clock.now());
    let Some(user) = spend_token(db, &now, &token, TOKEN_PASSWORD_RESET).await? else {
        return Ok(refusal(kind));
    };
    let Ok(Some(credential)) = password_credential(db, &user.id).await else {
        return Ok(refusal(kind));
    };
    let Ok(fresh) = hash_password(&new_password) else {
        tracing::error!("could not hash a password");
        return Err(Problem::internal().instance(&scope.request_id));
    };
    // Also clears the lockout: a proven reset is proof the person holds
    // the credential.
    if let Err(err) = set_password_hash(db, &credential.id, &fresh).await {
        tracing::error!(error = %err, "could not store a reset password");
        return Err(Problem::internal().instance(&scope.request_id));
    }

    // A reset is what somebody does when they think their password is
    // known to others, so every session and every refresh token goes —
    // and the person is not signed in here, so nothing is re-issued.
    if let Err(err) = revoke_all_sessions(db, &user.id, &now).await {
        tracing::error!(error = %err, "could not revoke sessions after a reset");
        return Err(Problem::internal().instance(&scope.request_id));
    }
    if let Err(err) = retire_unconsumed_tokens(db, TOKEN_REFRESH, &user.id, &now).await {
        tracing::warn!(error = %err, "could not retire refresh tokens after a reset");
    }
    // And any other reset link the account has out is no longer a way in.
    if let Err(err) = retire_unconsumed_tokens(db, TOKEN_PASSWORD_RESET, &user.id, &now).await {
        tracing::warn!(error = %err, "could not retire reset tokens after a reset");
    }

    ctx.events
        .emit_in(&scope, EVENT_RESET, json!({ "user_id": user.id }));
    Ok(success(
        kind,
        "Your password has been changed. Sign in with the new one.",
        "reset",
    ))
}

// ---------------------------------------------------------------------------
// The request endpoints

/// The fields the two request endpoints read, from either body shape.
struct RequestFields {
    email: String,
    locale: String,
    captcha: Option<String>,
}

/// Reads `email`, `locale` and the captcha token following whichever body
/// shape the caller declared — the hosted form posts `form-urlencoded`, an
/// API client posts JSON, and a form that is parsed as JSON (or the
/// reverse) silently sees nothing.
fn request_fields(raw: &[u8], kind: Kind) -> RequestFields {
    let captcha = ["captchaToken", "captcha_token"]
        .iter()
        .map(|name| field(raw, kind, name))
        .find(|value| !value.is_empty());
    RequestFields {
        email: cratefield_core::normalize_email(&field(raw, kind, "email")),
        locale: sanitize_locale(Some(field(raw, kind, "locale").as_str())),
        captcha,
    }
}

/// `POST /verify/resend` — send another verification link.
///
/// Always `202` and the same body (the JSON object, or the page for a form
/// post). A mail goes out only to an existing, unverified, active account,
/// and the caller cannot tell which case they hit.
pub(crate) async fn resend(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    uri: Uri,
    raw: bytes::Bytes,
) -> Result<Response, Problem> {
    factory0_auth_core::csrf::require_same_origin(&headers, &uri)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let kind = kind_of(&headers);
    let RequestFields {
        email,
        locale,
        captcha,
    } = request_fields(&raw, kind);

    if let Some(decision) = limit_pause(&state, &headers, Some(&email)).await {
        return Ok(cratefield_core::rate_limited(&decision).into_response());
    }
    if !captcha_ok(&state, captcha.as_deref(), &headers).await {
        return Ok(accepted(kind, ACCEPTED_RESEND));
    }

    let ctx = state.ctx.as_ref();
    let Some(db) = ctx.ports.db.as_deref() else {
        return Err(Problem::new(&NOT_READY));
    };
    if looks_like_an_address(&email)
        && let Ok(Some(user)) = user_by_primary_email(db, &email).await
        && !user.primary_email_verified
        && user.status == STATUS_ACTIVE
    {
        scope.defer.wait_until(send_verify_mail(
            Arc::clone(&state),
            &user.id,
            &email,
            &locale,
        ));
    }
    Ok(accepted(kind, ACCEPTED_RESEND))
}

/// `POST /reset/request` — send a password-reset link.
///
/// Always `202` and the same body; a mail goes out only when the account
/// exists and has a password credential, so a passkey- or provider-only
/// account is never mailed a way past a password it does not have.
pub(crate) async fn request_reset(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    uri: Uri,
    raw: bytes::Bytes,
) -> Result<Response, Problem> {
    factory0_auth_core::csrf::require_same_origin(&headers, &uri)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let kind = kind_of(&headers);
    let RequestFields {
        email,
        locale,
        captcha,
    } = request_fields(&raw, kind);

    if let Some(decision) = limit_pause(&state, &headers, Some(&email)).await {
        return Ok(cratefield_core::rate_limited(&decision).into_response());
    }
    if !captcha_ok(&state, captcha.as_deref(), &headers).await {
        return Ok(accepted(kind, ACCEPTED_RESET));
    }

    let ctx = state.ctx.as_ref();
    let Some(db) = ctx.ports.db.as_deref() else {
        return Err(Problem::new(&NOT_READY));
    };
    if looks_like_an_address(&email)
        && let Ok(Some(user)) = user_by_primary_email(db, &email).await
        && user.status == STATUS_ACTIVE
        && matches!(password_credential(db, &user.id).await, Ok(Some(_)))
    {
        scope.defer.wait_until(send_reset_mail(
            Arc::clone(&state),
            &user.id,
            &email,
            &locale,
        ));
    }
    Ok(accepted(kind, ACCEPTED_RESET))
}

// ---------------------------------------------------------------------------
// Answers

/// The one answer a request endpoint gives, whatever it found: the JSON
/// object for an API caller, the page for a browser that posted the hosted
/// form.
fn accepted(kind: Kind, message: &str) -> Response {
    match kind {
        Kind::Api => (
            StatusCode::ACCEPTED,
            Json(json!({ "status": "accepted", "message": message })),
        )
            .into_response(),
        Kind::Form => page_html(
            StatusCode::ACCEPTED,
            "Check your inbox",
            &format!("<p>{}</p>", html_escape(message)),
        ),
    }
}

/// The refusal, in the shape the caller asked for. JSON gets the one
/// `Problem`; the form gets the one page.
fn refusal(kind: Kind) -> Response {
    match kind {
        Kind::Api => Problem::new(&TOKEN_REFUSED).into_response(),
        Kind::Form => refused_page(),
    }
}

/// A limit refusal, in the shape the caller asked for.
fn limited(kind: Kind, decision: &cratefield_core::Decision) -> Response {
    match kind {
        Kind::Api => cratefield_core::rate_limited(decision).into_response(),
        Kind::Form => page_html(
            StatusCode::TOO_MANY_REQUESTS,
            "Try again shortly",
            "<p>Too many attempts just now. Try again shortly.</p>",
        ),
    }
}

/// The success, in the shape the caller asked for.
fn success(kind: Kind, message: &str, status: &str) -> Response {
    match kind {
        Kind::Api => (StatusCode::OK, Json(json!({ "status": status }))).into_response(),
        Kind::Form => page_html(
            StatusCode::OK,
            "Done",
            &format!("<p>{}</p>", html_escape(message)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_stored_only_as_its_digest() {
        let token = random_token().expect("entropy");
        let digest = hash(&token);
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, token.as_bytes());
        assert_eq!(digest, hash(&token));
        assert_ne!(digest, hash(&random_token().expect("entropy")));
    }

    #[test]
    fn only_a_token_shaped_value_passes_the_shape_guard() {
        assert_eq!((TOKEN_BYTES * 4).div_ceil(3), 43);
        assert!(looks_like_a_token(&random_token().expect("entropy")));
        assert!(looks_like_a_token(&"-".repeat(43)));
        for bad in [
            String::new(),
            "+".repeat(43),
            "-".repeat(42),
            "-".repeat(44),
        ] {
            assert!(!looks_like_a_token(&bad), "{bad:?}");
        }
    }

    #[test]
    fn a_locale_is_a_bcp_47_tag_or_english() {
        assert_eq!(sanitize_locale(None), "en");
        assert_eq!(sanitize_locale(Some("nl")), "nl");
        assert_eq!(sanitize_locale(Some("en-GB")), "en-GB");
        for bad in ["", "e", "english", "en-GB-extra", "en-", "<script>"] {
            assert_eq!(sanitize_locale(Some(bad)), "en", "{bad:?}");
        }
    }
}
