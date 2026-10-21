//! Passkey-first sign-up without an address (issue #914): the one-time
//! recovery codes an account can sign back in with, the in-app security
//! notices, the terms an account accepted at sign-up, and the guards every
//! anonymous request to this module passes first (rate limit, captcha).
//!
//! Nothing here requires an email address. An account with none keeps every
//! path open to it that a passkey can open: sign-in, step-up, and account
//! changes made with a passkey ceremony (see the README's sign-up section).

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use cratefield_core::{Clock, Config, Database, IdGen, Json, ModuleConfig, Problem, Scope};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::ModuleState;
use crate::secrets::{hash_password, verify_password};
use crate::store::{self, RecoveryCodeRow, STATUS_ACTIVE};

/// How many recovery codes an account is given at sign-up and each time it
/// regenerates them.
pub const RECOVERY_CODE_COUNT: usize = 10;

/// The alphabet a recovery code is drawn from: no `0`, `O`, `1` or `I`, so a
/// code read off a page is not mistyped. 32 symbols divide 256 evenly, so a
/// byte maps to one of them without bias.
const CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// The config keys the terms an account accepts are read from.
pub(crate) const TERMS_VERSION_KEY: &str = "TERMS_VERSION";
pub(crate) const PRIVACY_VERSION_KEY: &str = "PRIVACY_VERSION";

/// A recovery code or account that does not check out. One answer for both,
/// so the response does not say whether the account exists.
pub const RECOVERY_REFUSED: cratefield_core::ProblemDef = cratefield_core::ProblemDef {
    slug: "auth/recovery-refused",
    status: axum::http::StatusCode::UNAUTHORIZED,
    title: "Recovery refused",
    description: "The account and code did not match a live recovery code",
};

/// The terms and privacy versions this deployment asks sign-up to accept.
/// `None` when either is unset: sign-up is then refused, because nothing can
/// be recorded as accepted.
#[must_use]
pub fn terms_versions(cfg: &dyn Config) -> Option<(String, String)> {
    let module = ModuleConfig::new("auth-core", cfg);
    let terms = module.get_opt(TERMS_VERSION_KEY)?;
    let privacy = module.get_opt(PRIVACY_VERSION_KEY)?;
    let terms = terms.trim().to_owned();
    let privacy = privacy.trim().to_owned();
    (!terms.is_empty() && !privacy.is_empty()).then_some((terms, privacy))
}

/// The limiter's answer for an anonymous request. Callers fail closed on
/// anything but `Allow` (issue #914).
#[derive(Debug)]
pub enum Guard {
    /// The caller is within its limit.
    Allow,
    /// The caller is over its limit.
    Limited(cratefield_core::Decision),
    /// The limiter itself failed, or is not configured.
    Failed,
}

/// Checks the caller's address against the limiter, under `bucket`.
pub async fn guard_anonymous(
    ctx: &cratefield_core::ModuleContext,
    headers: &HeaderMap,
    bucket: &str,
) -> Guard {
    let Some(limiter) = ctx.ports.rate_limiter.as_deref() else {
        return Guard::Failed;
    };
    let ip = cratefield_core::client_ip(headers);
    for key in cratefield_core::rate_limit_keys(ip.as_deref(), None) {
        match limiter.limit(&format!("auth-core:{bucket}:{key}")).await {
            Ok(decision) if !decision.ok => return Guard::Limited(decision),
            Ok(_) => {}
            Err(err) => {
                tracing::error!(error = %err, "the rate limiter failed; refusing an anonymous request");
                return Guard::Failed;
            }
        }
    }
    Guard::Allow
}

/// Whether the captcha accepts this request. A deployment with no captcha
/// port accepts it; one whose captcha cannot be reached refuses it (fail
/// closed), as the magic link's send does.
pub async fn captcha_passes(
    ctx: &cratefield_core::ModuleContext,
    token: Option<&str>,
    headers: &HeaderMap,
) -> bool {
    let Some(captcha) = ctx.ports.captcha.as_deref() else {
        return true;
    };
    let ip = cratefield_core::client_ip(headers);
    match captcha
        .verify(token.unwrap_or_default(), ip.as_deref())
        .await
    {
        Ok(verdict) => verdict.ok,
        Err(err) => {
            tracing::warn!(error = %err, "the captcha could not be verified");
            false
        }
    }
}

/// Sign-up, and recovery, present a code the way a person types it:
/// upper-cased, with the separators and spaces dropped.
fn normalize_code(presented: &str) -> String {
    presented
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Draws `RECOVERY_CODE_COUNT` codes, each 16 symbols in four groups.
fn fresh_codes() -> Result<Vec<String>, Problem> {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|err| {
            tracing::error!(error = %err, "no entropy for recovery codes");
            Problem::internal()
        })?;
        let symbols: String = bytes
            .iter()
            .map(|b| char::from(CODE_ALPHABET[usize::from(*b) % 32]))
            .collect();
        codes.push(format!(
            "{}-{}-{}-{}",
            &symbols[0..4],
            &symbols[4..8],
            &symbols[8..12],
            &symbols[12..16]
        ));
    }
    Ok(codes)
}

/// Replaces the account's recovery codes with a fresh set, and returns the
/// plain codes. They are shown once: only Argon2id hashes are stored, and the
/// old set, spent or not, is gone.
///
/// # Errors
///
/// [`Problem`] when hashing or a write fails.
pub async fn issue_recovery_codes(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user_id: &str,
) -> Result<Vec<String>, Problem> {
    let codes = fresh_codes()?;
    let now = crate::sessions::iso(clock.now());
    store::delete_recovery_codes(db, user_id)
        .await
        .map_err(|_| Problem::internal())?;
    for code in &codes {
        let hash = hash_password(&normalize_code(code)).map_err(|err| {
            tracing::error!(error = %err, "could not hash a recovery code");
            Problem::internal()
        })?;
        store::insert_recovery_code(
            db,
            &RecoveryCodeRow {
                id: id_gen.ulid(),
                user_id: user_id.to_owned(),
                code_hash: hash,
                created_at: now.clone(),
            },
        )
        .await
        .map_err(|_| Problem::internal())?;
    }
    Ok(codes)
}

/// Spends the recovery code that matches `presented`, if the account holds
/// one. Returns whether a code was spent.
///
/// # Errors
///
/// [`Problem`] when a read or the spend fails.
pub(crate) async fn spend_recovery_code(
    db: &dyn Database,
    clock: &dyn Clock,
    user_id: &str,
    presented: &str,
) -> Result<bool, Problem> {
    let normalized = normalize_code(presented);
    if normalized.is_empty() {
        return Ok(false);
    }
    let rows = store::unused_recovery_codes(db, user_id)
        .await
        .map_err(|_| Problem::internal())?;
    for row in rows {
        if verify_password(&normalized, &row.code_hash) {
            let now = crate::sessions::iso(clock.now());
            // Of two requests racing on one code, exactly one spends it.
            let spent = store::spend_recovery_code(db, &row.id, &now)
                .await
                .map_err(|_| Problem::internal())?;
            return Ok(spent == 1);
        }
    }
    Ok(false)
}

/// Records an in-app security notice for the account.
///
/// # Errors
///
/// [`cratefield_core::DbError`] when the write fails.
pub async fn record_notice(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user_id: &str,
    kind: &str,
    detail: &str,
) -> Result<(), cratefield_core::DbError> {
    let now = crate::sessions::iso(clock.now());
    store::insert_security_notice(db, &id_gen.ulid(), user_id, kind, detail, &now).await
}

/// Records the terms and privacy versions an account accepted at sign-up.
///
/// # Errors
///
/// [`cratefield_core::DbError`] when the write fails.
pub async fn record_terms(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user_id: &str,
    terms_version: &str,
    privacy_version: &str,
) -> Result<(), cratefield_core::DbError> {
    let now = crate::sessions::iso(clock.now());
    store::insert_terms_acceptance(
        db,
        &id_gen.ulid(),
        user_id,
        terms_version,
        privacy_version,
        &now,
    )
    .await
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

fn db_clock_ids<'a>(
    state: &'a ModuleState,
    scope: &Scope,
) -> Result<(&'a dyn Database, &'a dyn Clock, &'a dyn IdGen), Problem> {
    let ports = &state.ctx.ports;
    match (
        ports.db.as_deref(),
        ports.clock.as_deref(),
        ports.id_gen.as_deref(),
    ) {
        (Some(db), Some(clock), Some(ids)) => Ok((db, clock, ids)),
        _ => Err(internal(scope)),
    }
}

/// The answer to an anonymous request the limiter refused or could not judge,
/// or `None` when the request may proceed.
fn refused_anonymous(scope: &Scope, guard: Guard) -> Option<Response> {
    match guard {
        Guard::Allow => None,
        Guard::Limited(decision) => Some(cratefield_core::rate_limited(&decision).into_response()),
        Guard::Failed => Some(
            Problem::new(&RECOVERY_REFUSED)
                .instance(&scope.request_id)
                .into_response(),
        ),
    }
}

#[derive(Deserialize)]
struct RedeemBody {
    sub: String,
    recovery_code: String,
    #[serde(default, rename = "captchaToken")]
    captcha_token: Option<String>,
}

/// `POST /recovery/redeem`: sign back in with an account id and one of its
/// recovery codes. The session it earns carries the `recovery` method, which
/// can enrol a passkey and nothing else; it starts the 24-hour quiet period,
/// and the account is told in the app and by mail where it has an address.
async fn redeem(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Json(body): Json<RedeemBody>,
) -> Result<Response, Problem> {
    let (db, clock, id_gen) = db_clock_ids(&state, &scope)?;
    if let Some(response) = refused_anonymous(
        &scope,
        guard_anonymous(&state.ctx, &headers, "recovery").await,
    ) {
        return Ok(response);
    }
    if !captcha_passes(&state.ctx, body.captcha_token.as_deref(), &headers).await {
        return Err(Problem::new(&RECOVERY_REFUSED).instance(&scope.request_id));
    }
    let refused = || Problem::new(&RECOVERY_REFUSED).instance(&scope.request_id);
    let user = store::user_by_id(db, &body.sub)
        .await
        .map_err(|_| internal(&scope))?
        .filter(|user| user.status == STATUS_ACTIVE)
        .ok_or_else(refused)?;
    if !spend_recovery_code(db, clock, &user.id, &body.recovery_code).await? {
        return Err(refused());
    }
    let ip = cratefield_core::client_ip(&headers);
    let issued = crate::sessions::issue(
        db,
        clock,
        id_gen,
        crate::sessions::Login {
            user_id: &user.id,
            ip: ip.as_deref(),
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr: &["recovery"],
        },
    )
    .await
    .map_err(|_| internal(&scope))?;
    crate::authorize::record_security_change(db, clock, &user.id)
        .await
        .map_err(|_| internal(&scope))?;
    crate::email::notify_account(
        &state.ctx,
        &user.id,
        "recovery_used",
        "A recovery code was used to sign in to your account. If that was not you, sign in and change your passkeys now.",
    )
    .await;
    let mut response = Json(json!({ "sub": user.id, "status": "signed_in" })).into_response();
    if let Ok(cookie) = axum::http::HeaderValue::from_str(&issued.cookie) {
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
    }
    Ok(response)
}

/// `POST /recovery/codes`: a new set of recovery codes, shown once. Asks for
/// a fresh passkey or email ceremony, so a stolen session cannot take the
/// account's way back in. The old set stops working.
async fn regenerate(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    session: crate::Session,
) -> Result<Response, Problem> {
    let (db, clock, id_gen) = db_clock_ids(&state, &scope)?;
    crate::authorize::require_recent_ceremony(db, clock, &session.id, &session.user_id)
        .await
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let codes = issue_recovery_codes(db, clock, id_gen, &session.user_id).await?;
    crate::email::notify_account(
        &state.ctx,
        &session.user_id,
        "recovery_codes_replaced",
        "Your recovery codes were replaced. The old ones no longer work.",
    )
    .await;
    Ok(Json(json!({ "recovery_codes": codes, "shown_once": true })).into_response())
}

/// `GET /notices`: the signed-in account's security notices, newest first.
async fn notices(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    session: crate::Session,
) -> Result<Response, Problem> {
    let (db, _, _) = db_clock_ids(&state, &scope)?;
    let rows = store::security_notices_for_user(db, &session.user_id)
        .await
        .map_err(|_| internal(&scope))?;
    let list: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id,
                "kind": row.kind,
                "detail": row.detail,
                "created_at": row.created_at,
                "read_at": row.read_at,
            })
        })
        .collect();
    Ok(Json(Value::Array(list)).into_response())
}

/// `POST /notices/{id}/read`: marks one of the account's notices read. Another
/// account's notice, or an unknown id, is the same empty answer.
async fn mark_read(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    session: crate::Session,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let (db, clock, _) = db_clock_ids(&state, &scope)?;
    let now = crate::sessions::iso(clock.now());
    store::mark_security_notice_read(db, &session.user_id, &id, &now)
        .await
        .map_err(|_| internal(&scope))?;
    Ok(Json(json!({ "status": "ok" })).into_response())
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/recovery/redeem", post(redeem))
        .route("/recovery/codes", post(regenerate))
        .route("/notices", get(notices))
        .route("/notices/{id}/read", post(mark_read))
}
