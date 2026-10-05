//! Changing the address an account is reached at (issue #648).
//!
//! `POST /email/change` (body `{new_email, current_password?}`, signed-in
//! session) mails a link; `POST /email/confirm` (body `{token}`, no
//! session) spends it and moves the address. The rules come from
//! `auth-password`'s recovery flow, because a mailbox is a channel this
//! service does not control:
//!
//! - **Nothing distinguishes the reasons.** Change answers the same 202
//!   whether the address is free or another account's; confirm answers one
//!   refusal for missing, expired, used, never issued, of another kind and
//!   taken-in-the-meantime alike.
//! - **The old address is always told**, whether or not the change can go
//!   ahead: it is the only signal its owner gets.
//! - **The link asks; the POST acts.** `GET /email/confirm` renders a form
//!   and never spends the token, so a scanner prefetching it cannot use it
//!   up (issue #439's rule).
//!
//! A live session is a bearer credential, so a stolen one would otherwise
//! move the account and every later reset with it. A session younger than
//! [`RECENT_SECS`] stands for itself; an older one must re-enter the
//! password, and an account with none has nothing to re-enter. Confirming
//! revokes the account's other sessions, because the address moved and any
//! session signed in against the old one is a way in — except the session
//! that carried the confirm, whose holder is mid-flow.

use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use cratefield_core::{
    Clock, Config, Database, IdGen, Json, Message, ModuleConfig, ModuleContext, Problem,
    ProblemDef, Rendered, Scope, SendOutcome, Template, TemplateError,
};
use http::{HeaderMap, StatusCode, Uri, header};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::store::{self, Redacted, SingleUseTokenRow, UserRow};
use crate::{
    LegacyHashes, ModuleState, STATUS_ACTIVE, TOKEN_EMAIL_CHANGE, consume_single_use_token,
    cookie_value, identity_by_provider_subject, password_credential, retire_unconsumed_tokens,
    revoke_other_sessions, set_password_identity_email, set_primary_email,
    set_primary_email_verified, single_use_token_by_hash, user_by_id, user_by_primary_email,
    validate, verify_password_with,
};

/// What a completed change announces: `user_id` and nothing else, never an
/// address in either sense.
pub const EVENT_EMAIL_CHANGED: &str = "auth-core.email_changed";

/// How long a confirm link lives: long enough to survive a quiet inbox,
/// short enough that one forwarded by mistake stops working.
pub const EMAIL_CHANGE_TTL_SECS: i64 = 60 * 60;

/// How young a session must be to act on its own.
pub const RECENT_SECS: i64 = 10 * 60;

/// The session is too old and the password does not match. One answer on
/// purpose.
pub const REAUTHENTICATION_REQUIRED: ProblemDef = ProblemDef {
    slug: "auth/reauthentication-required",
    status: StatusCode::FORBIDDEN,
    title: "Sign in again to change this",
    description: "The session is too old and the password does not match, not distinguished",
};

/// The one refusal every spent-and-found-wanting token gets; a caller who can
/// tell them apart gets an oracle for which addresses hold accounts.
pub const TOKEN_REFUSED: ProblemDef = ProblemDef {
    slug: "auth/email-token-refused",
    status: StatusCode::BAD_REQUEST,
    title: "That link is no longer valid",
    description: "Missing, expired, already used, never issued, or the address is now taken",
};

/// The registry ids a venture overrides.
pub const TEMPLATE_EMAIL_CHANGE_CONFIRM: &str = "auth-core/email-change-confirm";
pub const TEMPLATE_EMAIL_CHANGE_NOTICE: &str = "auth-core/email-change-notice";

/// 32 random bytes: the token is the whole credential, so it is sized to be
/// unguessable rather than to be typed.
const TOKEN_BYTES: usize = 32;

/// The tag every message this module sends carries.
const MAIL_TAG: &str = "auth-core";

/// The one answer `POST /email/change` gives, whatever it found.
const ACCEPTED: &str = "If the change can go ahead, a link is on its way to the new address.";

// ---------------------------------------------------------------------------
// Settings

/// The two keys the confirm link is built from. Both optional: a deployment
/// with neither sends no mail, a configuration rather than a caller-visible
/// error.
#[derive(Debug, Clone, Default)]
pub(crate) struct MailSettings {
    public_base: String,
    mail_from: String,
}

impl MailSettings {
    pub(crate) fn from_config(cfg: &dyn Config) -> Self {
        let module = ModuleConfig::new("auth-core", cfg);
        let base = module.get_opt("PUBLIC_BASE").unwrap_or_default();
        Self {
            public_base: base.trim().trim_end_matches('/').to_owned(),
            mail_from: module
                .get_opt("MAIL_FROM")
                .unwrap_or_default()
                .trim()
                .to_owned(),
        }
    }

    /// The pair when both are set, `None` when this deployment cannot mail.
    fn mail_ready(&self) -> Option<(&str, &str)> {
        match (self.public_base.is_empty(), self.mail_from.is_empty()) {
            (false, false) => Some((&self.public_base, &self.mail_from)),
            _ => None,
        }
    }
}

/// The `AUTH_CORE_PUBLIC_BASE` problems, for `AuthCore::validate_config`. `http`
/// is allowed only on loopback, where https does not reach a mail client — the
/// rule `auth-password` applies to its own.
pub(crate) fn config_problems(cfg: &dyn Config) -> Vec<String> {
    let module = ModuleConfig::new("auth-core", cfg);
    let base = module.get_opt("PUBLIC_BASE").unwrap_or_default();
    let base = base.trim().trim_end_matches('/');
    let reachable = base.starts_with("https://")
        || base.starts_with("http://localhost")
        || base.starts_with("http://127.0.0.1");
    if base.is_empty() || reachable {
        return Vec::new();
    }
    vec![format!(
        "{} must be https (localhost may be http), got {base:?}",
        module.key("PUBLIC_BASE")
    )]
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
fn looks_like_a_token(value: &str) -> bool {
    value.len() == (TOKEN_BYTES * 4).div_ceil(3)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

fn refused_problem(scope: &Scope) -> Problem {
    Problem::new(&TOKEN_REFUSED).instance(&scope.request_id)
}

fn db_and_clock<'a>(
    state: &'a ModuleState,
    scope: &Scope,
) -> Result<(&'a dyn Database, &'a dyn Clock), Problem> {
    let ports = &state.ctx.ports;
    match (ports.db.as_deref(), ports.clock.as_deref()) {
        (Some(db), Some(clock)) => Ok((db, clock)),
        _ => Err(internal(scope)),
    }
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/email/change", post(change))
        .route("/email/confirm", post(confirm))
        .route("/email/confirm", get(confirm_form))
}

// ---------------------------------------------------------------------------
// POST /email/change

#[derive(Debug, Default, Deserialize)]
struct ChangeBody {
    new_email: String,
    current_password: Option<String>,
}

async fn change(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    session: crate::Session,
    headers: HeaderMap,
    uri: Uri,
    Json(body): Json<ChangeBody>,
) -> Result<Response, Problem> {
    // Moving the address is what every later reset mail points at, so a
    // cross-site request must not be able to start it.
    crate::csrf::require_same_origin(&headers, &uri)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let (db, clock) = db_and_clock(&state, &scope)?;
    // This is the caller's own request, and a value that is not an address is
    // refused in as many words, which says nothing about anybody else's.
    let new_email = cratefield_core::normalize_email(&body.new_email);
    if !cratefield_core::is_valid(&new_email) {
        return Err(
            Problem::validation_failed("new_email is not a valid email address")
                .instance(&scope.request_id),
        );
    }
    if let Some(decision) = limit(&state, &headers, Some(&new_email)).await {
        return Ok(cratefield_core::rate_limited(&decision).into_response());
    }
    let user = match user_by_id(db, &session.user_id).await {
        Ok(Some(user)) if user.status == STATUS_ACTIVE => user,
        Ok(_) => return Err(Problem::new(&crate::SESSION_INVALID).instance(&scope.request_id)),
        Err(err) => {
            tracing::error!(error = %err, "could not read the account asking to change address");
            return Err(internal(&scope));
        }
    };
    prove_recent(
        db,
        clock,
        &state,
        &session.id,
        &user.id,
        body.current_password.as_deref(),
    )
    .await
    .map_err(|problem| problem.instance(&scope.request_id))?;

    // Everything that could distinguish the outcomes happens here, on the
    // deferred task: whether the address is free, whether a token is issued,
    // whether any mail goes out. The answer is the same in all three cases, so
    // it must not take a different amount of time.
    scope.defer.wait_until(send_mail(
        Arc::clone(&state),
        &user,
        &new_email,
        accept_language(&headers),
    ));
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "status": "accepted", "message": ACCEPTED })),
    )
        .into_response())
}

/// Checks that this session is recent enough, or that the caller can re-prove
/// who they are. The window is measured on the row's `created_at`, read back by
/// id — which keeps this honest without widening the public [`crate::Session`]
/// extractor with an age nobody else needs.
async fn prove_recent(
    db: &dyn Database,
    clock: &dyn Clock,
    state: &ModuleState,
    session_id: &str,
    user_id: &str,
    current_password: Option<&str>,
) -> Result<(), Problem> {
    // A timestamp we cannot read is not evidence of recency.
    let recent = match store::session_by_id(db, session_id).await {
        Ok(Some(row)) => OffsetDateTime::parse(&row.created_at, &Rfc3339)
            .is_ok_and(|created| (clock.now() - created).whole_seconds() < RECENT_SECS),
        Ok(None) => false,
        Err(err) => {
            tracing::error!(error = %err, "could not read a session's age");
            return Err(Problem::internal());
        }
    };
    if recent {
        return Ok(());
    }
    // No password to re-enter — a passkey-only or provider-only account — means
    // recency was the whole test, and it was not met.
    let credential = match password_credential(db, user_id).await {
        Ok(Some(credential)) => credential,
        Ok(None) => return Err(Problem::new(&REAUTHENTICATION_REQUIRED)),
        Err(err) => {
            tracing::error!(error = %err, "could not read the password credential");
            return Err(Problem::internal());
        }
    };
    let stored = credential
        .password_hash
        .as_ref()
        .map_or_else(String::new, |h| h.0.clone());
    // The deployment's legacy formats apply here for the reason they apply at
    // login (issue #650): an imported bcrypt account that could not re-prove
    // itself here would be locked out of its own settings.
    let legacy = match LegacyHashes::from_config(&*state.ctx.config) {
        Ok(legacy) => legacy,
        Err(err) => {
            tracing::warn!(error = %err, "auth-core: legacy-hash configuration is invalid");
            LegacyHashes::default()
        }
    };
    let proved = verify_password_with(current_password.unwrap_or_default(), &stored, legacy);
    if !proved {
        return Err(Problem::new(&REAUTHENTICATION_REQUIRED));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /email/confirm

/// The body a caller asked for. The GET page's `<form method="post">` sends
/// form-encoded bytes and an API caller sends JSON, so the route takes raw
/// bytes and reads whichever the `Content-Type` names — the same shape
/// `auth-password`'s reset route uses.
async fn confirm(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    uri: Uri,
    raw: axum::body::Bytes,
) -> Result<Response, Problem> {
    crate::csrf::require_same_origin(&headers, &uri)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let (db, clock) = db_and_clock(&state, &scope)?;
    if let Some(decision) = limit(&state, &headers, None).await {
        return Ok(limited(&headers, &decision));
    }
    let token = token_of(&raw, &headers);
    if !looks_like_a_token(&token) {
        return Ok(refused(&headers, &scope));
    }
    let now = crate::sessions::iso(clock.now());
    let Some((user, row)) = spend_token(db, &now, &token).await? else {
        return Ok(refused(&headers, &scope));
    };
    // The address the token names. It was validated and normalized when the
    // token was issued; a row that does not say so is refused rather than
    // trusted, because this is the one value that becomes an account.
    let Some(new_email) = row
        .payload
        .as_deref()
        .map(cratefield_core::normalize_email)
        .filter(|email| cratefield_core::is_valid(email))
    else {
        return Ok(refused(&headers, &scope));
    };
    // Both uniqueness checks, re-run here rather than only at issue time: an
    // address free an hour ago may have been registered since, and taking
    // somebody else's is how one account swallows another. The identity check
    // matters as much as the users one — the `password` provider's subject is
    // the address, so a subject somebody else holds would make this move fail
    // on the unique constraint below.
    match address_is_free(db, &user.id, &new_email).await {
        Ok(true) => {}
        Ok(false) => return Ok(refused(&headers, &scope)),
        Err(err) => {
            tracing::error!(error = %err, "could not check whether the new address is taken");
            return Err(internal(&scope));
        }
    }

    // The constraint-bearing write goes first, so a failure part-way leaves
    // the account signable at the address it still answers to rather than at
    // neither: the identity subject follows `users.primary_email`, and moving
    // the second before the first would strand the old address as
    // unregistrable. The `Database` port has no transaction across statements,
    // so the order is what protects this.
    match set_password_identity_email(db, &user.id, &new_email).await {
        // Nothing moved. That is ordinary for a passkey-only or provider-only
        // account and worth saying nothing about; for an account that does hold
        // a password credential it means the row was not where the constraint
        // says it should be, and the old address stays unregistrable.
        Ok(0) => {
            if let Ok(Some(_)) = password_credential(db, &user.id).await {
                tracing::warn!(
                    audit = true,
                    user_id = %user.id,
                    "email change left a password credential's identity behind"
                );
            }
        }
        Ok(_) => {}
        Err(err) => {
            tracing::error!(error = %err, "could not move the password identity");
            return Err(internal(&scope));
        }
    }
    if let Err(err) = set_primary_email(db, &user.id, &new_email, &now).await {
        tracing::error!(error = %err, "could not move a user's primary address");
        return Err(internal(&scope));
    }
    if let Err(err) = set_primary_email_verified(db, &user.id, &now).await {
        tracing::error!(error = %err, "could not record the new address as verified");
        return Err(internal(&scope));
    }

    // The session that carried this request, when it is a live session of this
    // same account, survives; everything else the account holds goes. A stale
    // id kept "just in case" would keep a way in.
    let keep = live_session_of(db, clock, &headers, &user.id).await;
    match revoke_other_sessions(db, &user.id, keep.as_deref(), &now).await {
        Ok(revoked) => tracing::info!(
            audit = true,
            action = "email.confirm",
            user_id = %user.id,
            revoked_sessions = revoked,
            "auth-core email change"
        ),
        Err(err) => {
            tracing::error!(error = %err, "could not revoke sessions after an email change");
            return Err(internal(&scope));
        }
    }
    state
        .ctx
        .events
        .emit_in(&scope, EVENT_EMAIL_CHANGED, json!({ "user_id": user.id }));
    Ok(changed(&headers))
}

/// Whether `new_email` is unclaimed for `user_id` in both the tables that
/// make it unique: `users.primary_email`, which is what sign-in looks the
/// account up by, and the `password` identity's subject, which is the same
/// address under a unique constraint of its own.
async fn address_is_free(
    db: &dyn Database,
    user_id: &str,
    new_email: &str,
) -> Result<bool, cratefield_core::DbError> {
    if let Some(other) = user_by_primary_email(db, new_email).await?
        && other.id != user_id
    {
        return Ok(false);
    }
    if let Some(other) =
        identity_by_provider_subject(db, crate::PROVIDER_PASSWORD, new_email).await?
        && other.user_id != user_id
    {
        return Ok(false);
    }
    Ok(true)
}

/// The token out of whichever body the caller declared: a JSON object for an
/// API client, form-encoded pairs for the GET page's button.
fn token_of(raw: &[u8], headers: &HeaderMap) -> String {
    if wants_json(headers) {
        serde_json::from_slice::<Value>(raw)
            .ok()
            .and_then(|body| body.get("token").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_default()
    } else {
        url::form_urlencoded::parse(raw)
            .find(|(key, _)| key == "token")
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default()
    }
}

/// The refusal in the shape the caller asked for: one problem for an API
/// client, one page for a browser, neither naming which check failed.
fn refused(headers: &HeaderMap, scope: &Scope) -> Response {
    if wants_json(headers) {
        return refused_problem(scope).into_response();
    }
    page_html(
        StatusCode::BAD_REQUEST,
        "That link is no longer valid",
        "<p>That link has expired or was already used. Ask for another.</p>",
    )
}

fn limited(headers: &HeaderMap, decision: &cratefield_core::Decision) -> Response {
    if wants_json(headers) {
        return cratefield_core::rate_limited(decision).into_response();
    }
    page_html(
        StatusCode::TOO_MANY_REQUESTS,
        "Try again shortly",
        "<p>Too many attempts just now. Try again shortly.</p>",
    )
}

fn changed(headers: &HeaderMap) -> Response {
    if wants_json(headers) {
        return Json(json!({ "status": "changed" })).into_response();
    }
    page_html(
        StatusCode::OK,
        "Your address is changed",
        "<p>Your account is reached at the new address from now on. \
         Any other session has been signed out.</p>",
    )
}

fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("json"))
}

/// The session the request presented, when it is a live one belonging to
/// `user_id`. `None` otherwise, the common case: confirming needs no cookie.
async fn live_session_of(
    db: &dyn Database,
    clock: &dyn Clock,
    headers: &HeaderMap,
    user_id: &str,
) -> Option<String> {
    let session = validate(db, clock, &cookie_value(headers)?).await.ok()??;
    (session.user_id == user_id).then_some(session.id)
}

/// Consumes a token of the expected kind and returns the account it names with
/// the spent row, whose `payload` is the address being moved to. `Ok(None)` is
/// the one refusal: missing, expired, used, never issued, or another kind. A
/// database error is reported rather than refused, so an outage does not look
/// like a bad link.
async fn spend_token(
    db: &dyn Database,
    now: &str,
    token: &str,
) -> Result<Option<(UserRow, SingleUseTokenRow)>, Problem> {
    let row = match single_use_token_by_hash(db, &hash(token)).await {
        Ok(row) => row,
        Err(err) => {
            tracing::error!(error = %err, "could not look up an email-change token");
            return Err(Problem::internal());
        }
    };
    let Some(row) = row.filter(|row| row.kind == TOKEN_EMAIL_CHANGE) else {
        return Ok(None);
    };
    // The one statement that makes this single-use: it stamps `consumed_at`
    // only on an unconsumed, unexpired row and checks the affected count, so of
    // two concurrent spends at most one wins.
    let spent = match consume_single_use_token(db, &row.id, now).await {
        Ok(spent) => spent,
        Err(err) => {
            tracing::error!(error = %err, "could not consume an email-change token");
            return Err(Problem::internal());
        }
    };
    let Some(user_id) = spent.as_ref().and_then(|spent| spent.user_id.clone()) else {
        return Ok(None);
    };
    match user_by_id(db, &user_id).await {
        Ok(Some(user)) if user.status == STATUS_ACTIVE => Ok(spent.map(|spent| (user, spent))),
        Ok(_) => Ok(None),
        Err(err) => {
            tracing::error!(error = %err, "could not read the account an email-change token names");
            Err(Problem::internal())
        }
    }
}

// ---------------------------------------------------------------------------
// GET /email/confirm — the confirm button

#[derive(Debug, Default, Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

/// The page the mailed link opens. It reads the token only to echo it into a
/// hidden field, and never spends it: mail scanners fetch every URL in a
/// message, and a prefetch that spent a single-use token would leave the person
/// with a link already used.
async fn confirm_form(axum::extract::Query(query): axum::extract::Query<TokenQuery>) -> Response {
    let token = query.token.unwrap_or_default();
    let body = if looks_like_a_token(&token) {
        format!(
            "<p>Move your account to the address you asked to change it to.</p> \
             <form method=\"post\"><input type=\"hidden\" name=\"token\" value=\"{}\"> \
             <button type=\"submit\">Confirm the new address</button></form>",
            html_escape(&token)
        )
    } else {
        "<p>That link has expired or was already used. Ask for another.</p>".to_owned()
    };
    page_html(StatusCode::OK, "Confirm your new address", &body)
}

/// The one page shell every browser-facing answer on this route wears. Pages
/// here carry a token in their HTML, so the `no-store` and `no-referrer` they
/// must answer with are stamped by the harness's `/v1/*` security layer (a module
/// response cannot dodge it) and only the content type is set here.
fn page_html(status: StatusCode, title: &str, body: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"> \
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"> \
             <meta name=\"robots\" content=\"noindex\"> \
             <title>{}</title></head> \
             <body style=\"font:16px/1.5 system-ui,sans-serif;margin:3rem auto; \
             max-width:32rem;padding:0 1rem\">{}</body></html>",
            html_escape(title),
            body
        )),
    )
        .into_response()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ---------------------------------------------------------------------------
// Sending

/// Everything `POST /email/change` promised, run off the request's critical path
/// (`scope.defer.wait_until`; `tokio::spawn` natively), so the answer's timing
/// says nothing about the outcome and a slow or broken mailer costs nothing.
fn send_mail(
    state: Arc<ModuleState>,
    user: &UserRow,
    new_email: &str,
    accept_language: Option<String>,
) -> cratefield_core::BoxFuture<'static, ()> {
    let (user_id, old_email, stored_locale) = (
        user.id.clone(),
        user.primary_email.clone().unwrap_or_default(),
        user.locale.clone(),
    );
    let new_email = new_email.to_owned();
    Box::pin(async move {
        let ctx = state.ctx.as_ref();
        let (Some(db), Some(clock), Some(id_gen), Some(mailer)) = (
            ctx.ports.db.as_deref(),
            ctx.ports.clock.as_deref(),
            ctx.ports.id_gen.as_deref(),
            ctx.ports.mailer.as_deref(),
        ) else {
            return;
        };
        let Some((public_base, mail_from)) = state.mail.mail_ready() else {
            tracing::warn!("no PUBLIC_BASE/MAIL_FROM configured; no email-change mail was sent");
            return;
        };
        let now = crate::sessions::iso(clock.now());
        let brand = crate::Brand::from_config(&*ctx.config, &ctx.venture);
        let locale = crate::locale::resolve(
            &crate::SupportedLocales::from_config(&*ctx.config),
            &crate::Hints {
                stored: stored_locale.as_deref(),
                accept_language: accept_language.as_deref(),
                ..crate::Hints::default()
            },
        );

        // Free, or already this account's own address, is one case: an address
        // the account already answers to needs no proof. Both uniqueness
        // checks, because the confirm step refuses on either and a link that
        // could only be refused is a mail nobody needed.
        let issued = match address_is_free(db, &user_id, &new_email).await {
            Ok(true) => match issue_token(db, clock, id_gen, &user_id, &new_email).await {
                Ok(issued) => Some(issued),
                Err(err) => {
                    tracing::error!(error = %err, "could not issue an email-change token");
                    return;
                }
            },
            Ok(false) => {
                tracing::debug!("the new address belongs to another account; no link was issued");
                None
            }
            Err(err) => {
                tracing::error!(error = %err, "could not check whether an address is taken");
                return;
            }
        };

        // The notice goes first and unconditionally. Whether the change can go
        // ahead is not this mail's business, and the person who owns the old
        // address is the only one who can act on a change somebody else began.
        if cratefield_core::is_valid(&old_email) {
            mail(
                ctx,
                mailer,
                &NOTICE_DEFAULT,
                &NoticeMail {
                    venture: brand.name.clone(),
                    new_email: new_email.clone(),
                    contact: brand.support_email.clone().unwrap_or_default(),
                },
                (&locale, &old_email, mail_from),
                &format!("email-change-notice-{user_id}-{now}"),
            )
            .await;
        }

        let Some(issued) = issued else { return };
        mail(
            ctx,
            mailer,
            &CONFIRM_DEFAULT,
            &ConfirmMail {
                venture: brand.name,
                link: format!(
                    "{public_base}/v1/auth-core/email/confirm?token={}",
                    issued.token
                ),
                minutes: EMAIL_CHANGE_TTL_SECS / 60,
            },
            (&locale, &new_email, mail_from),
            &issued.id,
        )
        .await;
    })
}

/// Renders one message through the venture's registry and sends it, logging
/// rather than propagating every failure — here a failure means no mail, never
/// a different answer to the caller who is already waiting.
async fn mail<T: serde::Serialize>(
    ctx: &ModuleContext,
    mailer: &dyn cratefield_core::Mailer,
    template: &EmailChangeTemplate,
    data: &T,
    (locale, to, from): (&str, &str, &str),
    idempotency_key: &str,
) {
    // The registry resolves `<id>@<locale>` before `<id>`, and a venture that
    // registered neither falls back to the compiled default.
    let Ok(mut value) = serde_json::to_value(data) else {
        return;
    };
    cratefield_mail_templates::attach_theme(&mut value, &ctx.venture, &*ctx.config);
    let rendered = match ctx.templates.render(template.id, &value, locale) {
        Err(TemplateError::UnknownTemplate { .. }) => template.render(&value, locale).ok(),
        other => other.ok(),
    };
    let Some(rendered) = rendered else {
        tracing::error!(
            template = template.id,
            "an auth-core email-change mail would not render"
        );
        return;
    };
    // A send failure is logged and swallowed: the caller's answer is the same
    // whether the mail went out, and telling the caller it bounced would tell
    // them the address exists.
    let sent = mailer
        .send(
            Message::new(to, from, rendered.subject, rendered.text, rendered.html)
                .idempotency_key(idempotency_key.to_owned())
                .tags([MAIL_TAG]),
        )
        .await;
    match sent {
        Ok(SendOutcome::Sent { .. }) => {}
        Ok(SendOutcome::NotConfigured) => {
            tracing::error!(
                "the mailer is not configured; no auth-core email-change mail was sent"
            );
        }
        // The address is never logged: a log line naming who asked to move an
        // account is the thing this module refuses to say.
        Err(err) => tracing::error!(error = %err, "could not send auth-core email-change mail"),
    }
}

struct Issued {
    /// The row id, used as the message's idempotency key.
    id: String,
    /// The token itself, only ever mailed, never logged or stored.
    token: String,
}

/// Mints a token, stores its digest, retires this account's older live tokens so
/// a second request invalidates the first, and carries the address in `payload`.
async fn issue_token(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user_id: &str,
    new_email: &str,
) -> Result<Issued, cratefield_core::DbError> {
    let Some(token) = random_token() else {
        return Err(cratefield_core::DbError::Query(
            "the entropy source failed".to_owned(),
        ));
    };
    let issued_at = clock.now();
    let row = SingleUseTokenRow {
        id: id_gen.ulid(),
        kind: TOKEN_EMAIL_CHANGE.to_owned(),
        // Only the digest is stored: a leaked row is not a way in.
        token_hash: Redacted(hash(&token)),
        user_id: Some(user_id.to_owned()),
        client_id: None,
        payload: Some(new_email.to_owned()),
        expires_at: crate::sessions::iso(
            issued_at.saturating_add(time::Duration::seconds(EMAIL_CHANGE_TTL_SECS)),
        ),
        consumed_at: None,
    };
    let now = crate::sessions::iso(issued_at);
    retire_unconsumed_tokens(db, TOKEN_EMAIL_CHANGE, user_id, &now).await?;
    store::insert_single_use_token(db, &row).await?;
    Ok(Issued { id: row.id, token })
}

fn accept_language(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Consults the limiter for one request, keyed on the caller and — where there
/// is one — the address the request is about.
///
/// Fails open, like every `auth-password` route: the durable backstops behind
/// this are the password credential's own lockout and the token's guarded
/// single-use consume, and taking an account's mail offline because a limiter
/// is unreachable would be the larger harm.
async fn limit(
    state: &ModuleState,
    headers: &HeaderMap,
    email: Option<&str>,
) -> Option<cratefield_core::Decision> {
    let limiter = state.ctx.ports.rate_limiter.as_deref()?;
    let ip = cratefield_core::client_ip(headers);
    for key in cratefield_core::rate_limit_keys(ip.as_deref(), email) {
        match limiter.limit(&format!("auth-core:{key}")).await {
            Ok(decision) if !decision.ok => return Some(decision),
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "the auth-core rate limiter is unavailable");
                return None;
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Mail templates

/// What the confirm template is given. Serialized through the registry, so it is
/// a wire format: adding a field is fine, renaming one breaks overrides. Every
/// mail's data also carries the resolved theme.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConfirmMail {
    pub venture: String,
    /// The full confirm URL, token included.
    pub link: String,
    /// How long the link lives, for the sentence that says so.
    pub minutes: i64,
}

/// What the notice template is given.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NoticeMail {
    pub venture: String,
    /// The address the change would move the account to. Naming it is what lets
    /// the old address's owner recognise the attempt — and the notice goes to
    /// the old address only, after the caller proved a session or a password.
    pub new_email: String,
    /// Where to write, when the deployment configured a support address.
    pub contact: String,
}

/// One of the two default mails. Both are the same shape — a subject, a
/// preheader, a paragraph or two, a note and a "why you got this" — so one
/// renderer with a branch beats two near-identical ones.
pub(crate) struct EmailChangeTemplate {
    id: &'static str,
    notice: bool,
}

pub(crate) const CONFIRM_DEFAULT: EmailChangeTemplate = EmailChangeTemplate {
    id: TEMPLATE_EMAIL_CHANGE_CONFIRM,
    notice: false,
};
pub(crate) const NOTICE_DEFAULT: EmailChangeTemplate = EmailChangeTemplate {
    id: TEMPLATE_EMAIL_CHANGE_NOTICE,
    notice: true,
};

impl Template for EmailChangeTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        use cratefield_mail_templates::{self as mt, Message};
        let theme = mt::theme_for_template(None, data);
        // The theme wins where it has a name; the module's own `venture` field
        // is the fallback for data that predates themes.
        let declared = data
            .get("venture")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let venture = theme.name_or(declared);
        let message = if self.notice {
            let data: NoticeMail = parse(self.id, data)?;
            let way_out = if data.contact.is_empty() {
                format!(
                    "If this was not you, sign in to {venture} and change the address back, or \
                     ask whoever administers this service to help."
                )
            } else {
                format!(
                    "If this was not you, write to {} and we will look into it. You can also \
                     sign in and change the address back yourself.",
                    data.contact
                )
            };
            Message::new(
                format!("Your {venture} email address is being changed"),
                format!("Your {venture} email address is being changed"),
            )
            .preheader(
                "Somebody signed in to your account and asked to move it to another address.",
            )
            .paragraph(format!(
                "Somebody signed in to the {venture} account at this address and asked to \
                     move it to {}. Until they confirm the change at the new address, this \
                     address still receives your sign-in codes and password resets.",
                data.new_email
            ))
            .note(way_out)
            .why(format!(
                "somebody asked to change the email address on a {venture} account"
            ))
        } else {
            let data: ConfirmMail = parse(self.id, data)?;
            Message::new(
                format!("Confirm your new address for {venture}"),
                format!("Confirm your new address for {venture}"),
            )
            .preheader(format!(
                "This link works once and expires in {} minutes. If you did not ask to \
                     change your address, ignore this message.",
                data.minutes
            ))
            .button("Confirm this address", &data.link)
            .fallback_link()
            .link_intro("If the button does not work, copy this address into your browser:")
            .paragraph(format!(
                "Open the link below to move your {venture} account to this address. It \
                     works once and expires in {} minutes.",
                data.minutes
            ))
            .note(
                "If you did not ask to change the address on your account, ignore this \
                     message. Nothing has changed, and the link will expire on its own.",
            )
            .why(format!(
                "someone signed in and asked to change their {venture} address"
            ))
        };
        Ok(message.render(&theme).into())
    }
}

fn parse<T: serde::de::DeserializeOwned>(id: &str, data: &Value) -> Result<T, TemplateError> {
    serde_json::from_value(data.clone()).map_err(|_| TemplateError::RenderFailed {
        id: id.to_owned(),
        reason: "the mail data is not the shape this template takes".to_owned(),
    })
}

/// The module's default templates, for `Harness::builder().templates(..)`, and
/// the same ids a venture registers to reword them.
#[must_use]
pub fn default_templates() -> Vec<(String, Box<dyn Template>)> {
    [CONFIRM_DEFAULT, NOTICE_DEFAULT]
        .into_iter()
        .map(|template| (template.id.to_owned(), Box::new(template) as _))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::{EmptyConfig, Venture};

    fn themed<T: serde::Serialize>(data: &T) -> Value {
        let mut value = serde_json::to_value(data).expect("serializes");
        cratefield_mail_templates::attach_theme(
            &mut value,
            &Venture::new("Acme", "acme.example"),
            &EmptyConfig,
        );
        value
    }

    #[test]
    fn only_a_token_shaped_value_passes_the_shape_guard() {
        assert_eq!((TOKEN_BYTES * 4).div_ceil(3), 43);
        assert!(looks_like_a_token(&random_token().expect("entropy")));
        for bad in [
            String::new(),
            "+".repeat(43),
            "-".repeat(42),
            "-".repeat(44),
        ] {
            assert!(!looks_like_a_token(&bad), "{bad:?}");
        }
    }

    /// Both mails keep what makes them safe to send: the link appears as a
    /// button and as a copyable fallback, and the notice names the address
    /// while offering no link at all.
    #[test]
    fn the_two_mails_carry_what_they_must() {
        let link = "https://auth.example/v1/auth-core/email/confirm?token=abc";
        let confirm = CONFIRM_DEFAULT
            .render(
                &themed(&ConfirmMail {
                    venture: "Acme".into(),
                    link: link.into(),
                    minutes: 60,
                }),
                "en",
            )
            .expect("renders");
        assert!(confirm.text.contains(link), "{}", confirm.text);
        assert!(confirm.text.contains("60 minutes"));
        assert_eq!(confirm.html.matches(&format!("href=\"{link}\"")).count(), 2);

        let notice = NOTICE_DEFAULT
            .render(
                &themed(&NoticeMail {
                    venture: "Acme".into(),
                    new_email: "new@example.test".into(),
                    contact: "help@acme.example".into(),
                }),
                "en",
            )
            .expect("renders");
        assert!(notice.text.contains("new@example.test"), "{}", notice.text);
        assert!(notice.text.contains("help@acme.example"));
        assert!(!notice.html.contains("class=\"cf-btn\""), "{}", notice.html);
    }
}
