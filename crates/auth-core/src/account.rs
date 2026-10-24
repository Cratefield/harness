//! Passkey-first sign-up without an address (issue #914): the one-time
//! recovery codes an account can sign back in with, the in-app security
//! notices, the terms an account accepted at sign-up, and the guards every
//! anonymous request to this module passes first (rate limit, captcha).
//!
//! Nothing here requires an email address. An account with none keeps every
//! path a passkey can open (see the README's sign-up section).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use cratefield_core::{
    Clock, Config, Database, DbError, IdGen, Json, ModuleConfig, ModuleContext, Problem, Scope,
    Statement, constant_time_eq,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::ModuleState;
use crate::linking::{self, UnlinkError};
use crate::store::{self, RecoveryCodeRow, STATUS_ACTIVE};

/// How many recovery codes an account is given at sign-up and each time it
/// regenerates them.
pub const RECOVERY_CODE_COUNT: usize = 10;

/// Symbols in a code's public lookup half, and in its secret half.
const LOOKUP_SYMBOLS: usize = 8;
const SECRET_SYMBOLS: usize = 16;

/// The alphabet a code is drawn from: no `0`, `O`, `1` or `I`. 32 symbols
/// divide 256 evenly, so a byte maps to one of them without bias.
const CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// The config keys the terms an account accepts are read from.
pub(crate) const TERMS_VERSION_KEY: &str = "TERMS_VERSION";
pub(crate) const PRIVACY_VERSION_KEY: &str = "PRIVACY_VERSION";

/// The one answer for every recovery refusal: a wrong code, an unknown code, a
/// spent one, an unknown account, a missing captcha. It says nothing about which.
pub const RECOVERY_REFUSED: cratefield_core::ProblemDef = cratefield_core::ProblemDef {
    slug: "auth/recovery-refused",
    status: axum::http::StatusCode::UNAUTHORIZED,
    title: "Recovery refused",
    description: "The recovery code did not match a live code",
};

/// The hash a lookup with no matching row is checked against, so an unknown
/// code does the same work as a wrong one.
fn dummy_hash() -> String {
    sha256_hex(b"no recovery code has this secret")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

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
/// anything but `Allow`.
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
pub async fn guard_anonymous(ctx: &ModuleContext, headers: &HeaderMap, bucket: &str) -> Guard {
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

/// Whether the captcha accepts this request. Sign-up and recovery require a
/// captcha: with no captcha port, or one that cannot be reached, they refuse
/// (fail closed, issue #914).
pub async fn captcha_passes(ctx: &ModuleContext, token: Option<&str>, headers: &HeaderMap) -> bool {
    let Some(captcha) = ctx.ports.captcha.as_deref() else {
        return false;
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

/// Presents a code the way a person types it: upper-cased, with separators and
/// spaces dropped. Returns the lookup half and the secret half, or `None` when
/// the length is wrong. Callers still do the same work either way.
fn split_code(presented: &str) -> (String, String) {
    let normalized: String = presented
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let lookup: String = normalized.chars().take(LOOKUP_SYMBOLS).collect();
    let secret: String = normalized.chars().skip(LOOKUP_SYMBOLS).collect();
    (lookup, secret)
}

/// One freshly drawn code, as shown to the person and as stored.
pub(crate) struct DrawnCode {
    /// What the person is shown: `LOOKUP-LOOKUP-SECRET-SECRET-SECRET-SECRET`.
    pub display: String,
    pub lookup: String,
    /// The secret half, which is never stored: only its hash is.
    secret: String,
}

fn symbols(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| char::from(CODE_ALPHABET[usize::from(*b) % 32]))
        .collect()
}

/// Draws `RECOVERY_CODE_COUNT` codes from the OS entropy source.
///
/// # Errors
///
/// [`DbError::Batch`] when the entropy source fails, so the caller's batch is
/// never started.
fn draw_codes() -> Result<Vec<DrawnCode>, DbError> {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut bytes = [0u8; LOOKUP_SYMBOLS + SECRET_SYMBOLS];
        getrandom::fill(&mut bytes).map_err(|err| DbError::Batch(err.to_string()))?;
        let all = symbols(&bytes);
        let (lookup, secret) = all.split_at(LOOKUP_SYMBOLS);
        let display = format!(
            "{}-{}-{}-{}-{}-{}",
            &lookup[0..4],
            &lookup[4..8],
            &secret[0..4],
            &secret[4..8],
            &secret[8..12],
            &secret[12..16]
        );
        codes.push(DrawnCode {
            display,
            lookup: lookup.to_owned(),
            secret: secret.to_owned(),
        });
    }
    Ok(codes)
}

/// Domain separator for a stored code digest. A digest from any other use of
/// SHA-256 in this service cannot be mistaken for one of these.
const CODE_DIGEST_DOMAIN: &str = "cratefield-recovery-v1";

/// The digest a code's secret is stored as: SHA-256 over a domain separator, the
/// public lookup id and the secret. The lookup id is unique per row, so it acts
/// as a per-row salt: two accounts with the same secret store different digests.
fn code_digest(lookup: &str, secret: &str) -> String {
    sha256_hex(format!("{CODE_DIGEST_DOMAIN}\0{lookup}\0{secret}").as_bytes())
}

/// The stored row for a drawn code.
fn code_row(id: String, user_id: &str, code: &DrawnCode, now: &str) -> RecoveryCodeRow {
    RecoveryCodeRow {
        id,
        lookup_id: code.lookup.clone(),
        user_id: user_id.to_owned(),
        code_hash: code_digest(&code.lookup, &code.secret),
        created_at: now.to_owned(),
        used_at: None,
    }
}

/// How many fresh draws a write makes before it gives up: a lookup id that is
/// already taken, or a batch that loses a race, is redrawn, never a 500.
const DRAW_ATTEMPTS: usize = 3;

/// Writes one batch built from a fresh draw of the codes, redrawing up to
/// `DRAW_ATTEMPTS` times when the batch fails (a lookup id that another row
/// already holds, or a concurrent write). Returns the codes as shown, once.
async fn write_with_fresh_codes(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user_id: &str,
    draw: fn() -> Result<Vec<DrawnCode>, DbError>,
    prefix: Vec<Statement>,
    replace_existing: bool,
) -> Result<Vec<String>, DbError> {
    let now = crate::sessions::iso(clock.now());
    let mut last = None;
    for _ in 0..DRAW_ATTEMPTS {
        let drawn = draw()?;
        let mut statements = prefix.clone();
        if replace_existing {
            statements.push(store::delete_recovery_codes_statement(user_id));
        }
        for code in &drawn {
            statements.push(store::insert_recovery_code_statement(&code_row(
                id_gen.ulid(),
                user_id,
                code,
                &now,
            )));
        }
        match db.batch_atomic(&statements).await {
            Ok(()) => return Ok(drawn.into_iter().map(|code| code.display).collect()),
            Err(err) => {
                tracing::warn!(error = %err, "a recovery-code batch was redrawn");
                last = Some(err);
            }
        }
    }
    Err(last.unwrap_or_else(|| DbError::Batch("no recovery-code draw succeeded".to_owned())))
}

/// Replaces the account's recovery codes with a fresh set, and returns the
/// codes as they are shown, once. The old set, spent or not, stops working.
///
/// # Errors
///
/// [`DbError`] when drawing or writing the codes keeps failing.
pub async fn issue_recovery_codes(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user_id: &str,
) -> Result<Vec<String>, DbError> {
    write_with_fresh_codes(db, clock, id_gen, user_id, draw_codes, Vec::new(), true).await
}

/// Creates a passkey-first account in one atomic batch: the user row, the
/// passkey, the terms accepted, and the recovery codes. A failure anywhere
/// (including the passkey already existing, which a concurrent sign-up with the
/// same authenticator can cause) leaves none of them behind. Returns the codes
/// as they are shown, once.
///
/// # Errors
///
/// [`DbError`] when the batch keeps failing.
pub async fn create_passkey_account(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user: &crate::store::UserRow,
    credential: &crate::store::CredentialRow,
    terms: (&str, &str),
) -> Result<Vec<String>, DbError> {
    let now = crate::sessions::iso(clock.now());
    let terms_id = id_gen.ulid();
    let prefix = vec![
        store::insert_user_statement(user),
        store::insert_credential_statement(credential),
        store::insert_terms_acceptance_statement(&terms_id, &user.id, terms.0, terms.1, &now),
    ];
    write_with_fresh_codes(db, clock, id_gen, &user.id, draw_codes, prefix, false).await
}

/// The stored code a presented string names, if it is well formed and the
/// lookup finds a row. Does no spending, so the caller can check the account
/// first. Always does the same reads and the same hash, whatever the input.
async fn find_code(db: &dyn Database, presented: &str) -> Result<Option<RecoveryCodeRow>, Problem> {
    let (lookup, secret) = split_code(presented);
    let row = store::recovery_code_by_lookup(db, &lookup)
        .await
        .map_err(|_| Problem::internal())?;
    let expected = row
        .as_ref()
        .map_or_else(dummy_hash, |row| row.code_hash.clone());
    let presented_digest = code_digest(&lookup, &secret);
    let matches = constant_time_eq(presented_digest.as_bytes(), expected.as_bytes());
    let Some(row) = row else {
        return Ok(None);
    };
    if !matches || row.used_at.is_some() || secret.len() != SECRET_SYMBOLS {
        return Ok(None);
    }
    Ok(Some(row))
}

/// Spends a code a `find_code` matched. Of two requests racing on one code,
/// exactly one spends it.
async fn spend_found(
    db: &dyn Database,
    clock: &dyn Clock,
    row: &RecoveryCodeRow,
) -> Result<bool, Problem> {
    let now = crate::sessions::iso(clock.now());
    let spent = store::spend_recovery_code(db, &row.id, &now)
        .await
        .map_err(|_| Problem::internal())?;
    Ok(spent == 1)
}

/// Records an in-app security notice for the account.
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub async fn record_notice(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user_id: &str,
    kind: &str,
    detail: &str,
) -> Result<(), DbError> {
    let now = crate::sessions::iso(clock.now());
    store::insert_security_notice(db, &id_gen.ulid(), user_id, kind, detail, &now).await
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
    recovery_code: String,
    #[serde(default, rename = "captchaToken")]
    captcha_token: Option<String>,
    /// Revoke every other session of the account when the code is used.
    /// On by default: a code used after a stolen session is the moment to end it.
    #[serde(default = "default_true")]
    sign_out_other_sessions: bool,
}

fn default_true() -> bool {
    true
}

/// `POST /recovery/redeem`: sign back in with a recovery code, which names its
/// account. The session it earns carries the `recovery` method, which can enrol
/// a passkey and nothing else (the authorization endpoint treats it as signed
/// out). The redeem starts the 24-hour quiet period, signs the account's other
/// sessions out unless the caller asks not to, and tells the account.
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
    let refused = || Problem::new(&RECOVERY_REFUSED).instance(&scope.request_id);
    if !captcha_passes(&state.ctx, body.captcha_token.as_deref(), &headers).await {
        return Err(refused());
    }
    // The account is checked before the code is spent, so a disabled account's
    // code is not burned. Every path does the same reads (issue #914, review).
    let found = find_code(db, &body.recovery_code).await?;
    let owner = match &found {
        Some(row) => row.user_id.clone(),
        None => String::new(),
    };
    let user = store::user_by_id(db, &owner)
        .await
        .map_err(|_| internal(&scope))?
        .filter(|user| user.status == STATUS_ACTIVE);
    let Some((row, user)) = found.zip(user) else {
        return Err(refused());
    };
    if !spend_found(db, clock, &row).await? {
        return Err(refused());
    }
    let now = crate::sessions::iso(clock.now());
    let signed_out = if body.sign_out_other_sessions {
        let sessions = store::revoke_all_sessions(db, &user.id, &now)
            .await
            .map_err(|_| internal(&scope))?;
        store::retire_unconsumed_tokens(db, store::TOKEN_REFRESH, &user.id, &now)
            .await
            .map_err(|_| internal(&scope))?;
        sessions
    } else {
        0
    };
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
    let mut response = Json(json!({
        "sub": user.id,
        "status": "signed_in",
        "sessions_signed_out": signed_out,
    }))
    .into_response();
    if let Ok(cookie) = axum::http::HeaderValue::from_str(&issued.cookie) {
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
    }
    Ok(response)
}

/// `POST /recovery/codes`: a new set of recovery codes, shown once. Asks for a
/// fresh passkey or email ceremony, so a stolen session cannot take the
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
    let codes = issue_recovery_codes(db, clock, id_gen, &session.user_id)
        .await
        .map_err(|_| internal(&scope))?;
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

/// Refused when removing an identity would leave the account with no way in.
pub(crate) const LAST_SIGN_IN_METHOD: cratefield_core::ProblemDef = cratefield_core::ProblemDef {
    slug: "auth/last-sign-in-method",
    status: axum::http::StatusCode::CONFLICT,
    title: "Last way to sign in",
    description: "This is the only way into the account. Add a password, a passkey, or another provider first",
};

/// `GET /identities`: the sign-in identities linked to the caller's account
/// (Google, Apple, Factory Zero, SSO). Only the caller's own rows.
async fn identities(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    session: crate::Session,
) -> Result<Response, Problem> {
    let (db, _clock, _) = db_clock_ids(&state, &scope)?;
    let rows = store::identities_by_user(db, &session.user_id)
        .await
        .map_err(|_| internal(&scope))?;
    let identities: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id,
                "provider": row.provider,
                "email": row.email,
                "created_at": row.created_at,
                "last_login_at": row.last_login_at,
            })
        })
        .collect();
    Ok(Json(json!({ "identities": identities })).into_response())
}

/// `DELETE /identities/{id}`: removes one of the caller's sign-in identities.
///
/// The refusal for the last way in is [`linking::unlink`]'s rule, not a
/// second copy of it here. Another account's identity is the same answer as
/// an unknown one. Same-origin only: a cross-site request must not be able to
/// remove a way in.
async fn remove_identity(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    session: crate::Session,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    crate::csrf::require_same_origin(&headers, &uri)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let (db, _clock, _) = db_clock_ids(&state, &scope)?;
    match linking::unlink(db, &session.user_id, &id)
        .await
        .map_err(|_| internal(&scope))?
    {
        Ok(()) => Ok(Json(json!({ "status": "ok" })).into_response()),
        Err(UnlinkError::NotFound) => Err(Problem::not_found().instance(&scope.request_id)),
        Err(UnlinkError::LastMethod) => {
            Err(Problem::new(&LAST_SIGN_IN_METHOD).instance(&scope.request_id))
        }
    }
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/recovery/redeem", post(redeem))
        .route("/recovery/codes", post(regenerate))
        .route("/notices", get(notices))
        .route("/notices/{id}/read", post(mark_read))
        .route("/identities", get(identities))
        .route("/identities/{id}", axum::routing::delete(remove_identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_testing::{FixedClock, TestHarness};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use time::OffsetDateTime;

    static DRAWS: AtomicUsize = AtomicUsize::new(0);

    /// The first draw collides with a lookup id another row already holds; every
    /// later draw is fresh.
    fn colliding_first_draw() -> Result<Vec<DrawnCode>, DbError> {
        let mut codes = draw_codes()?;
        if DRAWS.fetch_add(1, Ordering::SeqCst) == 0 {
            codes[0].lookup = "ZZZZZZZZ".to_owned();
        }
        Ok(codes)
    }

    fn user(id: &str) -> crate::store::UserRow {
        crate::store::UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: None,
            primary_email_verified: false,
            locale: None,
            status: STATUS_ACTIVE.to_owned(),
            created_at: "2026-10-01T00:00:00Z".to_owned(),
            updated_at: "2026-10-01T00:00:00Z".to_owned(),
        }
    }

    /// Issue #914 (review): a lookup id already taken makes the batch fail; the
    /// write redraws and succeeds, instead of failing the request.
    #[pollster::test]
    async fn a_colliding_lookup_is_redrawn_not_a_failure() {
        let kit = TestHarness::with_ports(vec![Box::new(crate::AuthCore::new())], |_| {});
        let clock = FixedClock(OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("epoch"));
        let db: &dyn Database = &*kit.db;
        crate::store::insert_user(db, &user("ada"))
            .await
            .expect("ada");
        crate::store::insert_user(db, &user("other"))
            .await
            .expect("other");
        // Another account already holds the lookup id the first draw will take.
        db.batch_atomic(&[crate::store::insert_recovery_code_statement(
            &RecoveryCodeRow {
                id: "taken".to_owned(),
                lookup_id: "ZZZZZZZZ".to_owned(),
                user_id: "other".to_owned(),
                code_hash: "x".repeat(64),
                created_at: "2026-10-01T00:00:00Z".to_owned(),
                used_at: None,
            },
        )])
        .await
        .expect("seeded");
        DRAWS.store(0, Ordering::SeqCst);
        let shown = write_with_fresh_codes(
            db,
            &clock,
            &cratefield_core::UlidIdGen,
            "ada",
            colliding_first_draw,
            Vec::new(),
            true,
        )
        .await
        .expect("the write succeeds on a redraw");
        assert_eq!(shown.len(), RECOVERY_CODE_COUNT);
        assert_eq!(DRAWS.load(Ordering::SeqCst), 2, "one collision, one redraw");
        let rows: cratefield_core::Rows = db
            .query(&Statement::new(
                "SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = 'ada'".to_owned(),
            ))
            .await
            .expect("count");
        assert_eq!(rows.rows[0].get::<i64>("n"), Some(10));
    }
}
