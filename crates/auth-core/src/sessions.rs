//! Sessions (issue #8): one session per login, carried by the
//! `__Host-fz_session` cookie. The cookie value is 32 random bytes;
//! only its SHA-256 is stored, so a leaked database cannot log anyone
//! in. Validation is a hash lookup plus revocation and expiry checks,
//! with a sliding 30-day expiry capped at 90 days from creation.
//!
//! Session fixation: [`issue`] always mints a fresh value and revokes
//! whatever session the request presented first — a pre-login cookie
//! never survives a login.
//!
//! Audit lines carry the action and a `subject_hash` of the user id,
//! nothing else.

use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64ct::{Base64UrlUnpadded, Encoding};
use factory0_core::{Clock, Database, DbError, IdGen, Json, Problem, Scope, subject_hash};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ModuleState;
use crate::store::{self, Redacted};

/// The session cookie. `__Host-` prefix rules: `Secure`, `Path=/`, no
/// `Domain` — the attributes built below are exactly those rules.
pub const COOKIE_NAME: &str = "__Host-fz_session";

/// Random bytes in a session cookie value.
pub const SESSION_VALUE_BYTES: usize = 32;

/// `last_seen_at` refreshes at most this often, to keep writes cheap.
pub const SLIDE_AFTER_SECS: i64 = 300;

/// A validated session slides to `last_seen + 30 days`.
pub const SLIDE_WINDOW_DAYS: i64 = 30;

/// …never past `created + 90 days`.
pub const ABSOLUTE_CAP_DAYS: i64 = 90;

/// The single 401 every signed-out caller sees: missing cookie,
/// unknown cookie, revoked session and expired session are
/// indistinguishable.
pub const SESSION_INVALID: factory0_core::ProblemDef = factory0_core::ProblemDef {
    slug: "auth/session-invalid",
    status: StatusCode::UNAUTHORIZED,
    title: "A valid session is required",
    description: "Missing, unknown, revoked or expired session — not distinguished",
};

/// Failure while issuing a session: entropy or database. The cookie
/// value never leaves the failing call.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("entropy source failed: {0}")]
    Entropy(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

/// A validated session: what signed-in handlers need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidSession {
    pub id: String,
    pub user_id: String,
}

fn iso(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .expect("rfc3339 formats")
}

fn plus_days(t: OffsetDateTime, days: i64) -> OffsetDateTime {
    t.saturating_add(time::Duration::days(days))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in &digest {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

fn sha256_raw(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// The `Set-Cookie` value that carries a fresh session: `__Host-`
/// rules verbatim — `Secure`, `Path=/`, `HttpOnly`, `SameSite=Lax`,
/// never a `Domain` attribute.
#[must_use]
pub fn set_cookie(value: &str) -> String {
    format!("{COOKIE_NAME}={value}; Path=/; Secure; HttpOnly; SameSite=Lax")
}

/// The `Set-Cookie` value that clears the session cookie.
#[must_use]
pub fn clear_cookie() -> String {
    format!(
        "{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0; \
         Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    )
}

/// The session cookie value from a `Cookie` header, when present and
/// of the issued shape (43 base64url characters).
#[must_use]
pub fn cookie_value(headers: &HeaderMap) -> Option<String> {
    for header in headers.get_all(header::COOKIE) {
        let Ok(raw) = header.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let Some(value) = pair.trim().strip_prefix(COOKIE_NAME) else {
                continue;
            };
            let Some(value) = value.strip_prefix('=') else {
                continue;
            };
            let value = value.trim();
            if value.len() == 43
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Some(value.to_owned());
            }
        }
    }
    None
}

/// A crude user-agent family for the session listing; `None` when no
/// header was sent. Edge and Opera identify as Chrome and Safari
/// first, so they are sniffed before both.
#[must_use]
pub fn ua_family(user_agent: Option<&str>) -> Option<String> {
    let ua = user_agent?.to_ascii_lowercase();
    let family = if ua.contains("edg/") {
        "edge"
    } else if ua.contains("opr/") || ua.contains("opera") {
        "opera"
    } else if ua.contains("firefox/") || ua.contains("fxios") {
        "firefox"
    } else if ua.contains("chrome/") || ua.contains("crios") {
        "chrome"
    } else if ua.contains("safari") {
        "safari"
    } else {
        "other"
    };
    Some(family.to_owned())
}

/// Everything [`issue`] needs about one login.
pub struct Login<'a> {
    pub user_id: &'a str,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    /// The cookie the login request presented, if any: revoked before
    /// the new session exists (fixation).
    pub presented_cookie: Option<&'a str>,
}

/// A freshly issued session; the caller answers with
/// `Set-Cookie: <cookie>`.
pub struct IssuedSession {
    pub session_id: String,
    /// The cookie value — the only place it exists in the clear.
    pub value: String,
    pub cookie: String,
}

fn audit(action: &str, user_id: &str) {
    tracing::info!(
        audit = true,
        action,
        subject_hash = %subject_hash(user_id),
        "auth-core session"
    );
}

/// Issues a session on a successful login: 32 random bytes in the
/// cookie, only the SHA-256 stored, expiry `now + 30 days`. Any
/// session the request presented is revoked first — a new session is
/// always issued at login, so a fixed pre-login value dies here.
///
/// # Errors
///
/// [`SessionError::Entropy`] when the OS entropy source fails;
/// [`SessionError::Db`] when a write fails.
///
/// # Panics
///
/// Never in practice: the documented panics are the `time` crate's
/// nanosecond truncation and RFC 3339 formatting of a whole-second
/// timestamp, both infallible on this path.
pub async fn issue(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    login: Login<'_>,
) -> Result<IssuedSession, SessionError> {
    if let Some(presented) = login.presented_cookie
        && let Some(old) =
            store::session_by_token_hash(db, &sha256_raw(presented.as_bytes())).await?
    {
        store::revoke_session(db, &old.id, &iso(clock.now())).await?;
        audit("session.revoke", login.user_id);
    }

    let mut bytes = [0u8; SESSION_VALUE_BYTES];
    getrandom::fill(&mut bytes).map_err(|err| SessionError::Entropy(err.to_string()))?;
    let value = Base64UrlUnpadded::encode_string(&bytes);
    let now = clock.now().replace_nanosecond(0).expect("in range");

    let session_id = id_gen.ulid();
    store::insert_session(
        db,
        &store::SessionRow {
            id: session_id.clone(),
            user_id: login.user_id.to_owned(),
            token_hash: Redacted(sha256_raw(value.as_bytes())),
            created_at: iso(now),
            last_seen_at: iso(now),
            expires_at: iso(plus_days(now, SLIDE_WINDOW_DAYS)),
            revoked_at: None,
            ip_hash: login.ip.map(|ip| Redacted(sha256_hex(ip.as_bytes()))),
            ua_family: ua_family(login.user_agent),
        },
    )
    .await?;

    audit("session.issue", login.user_id);
    Ok(IssuedSession {
        session_id,
        cookie: set_cookie(&value),
        value,
    })
}

/// Validates a session cookie by its hash: unknown, revoked and
/// expired all return `Ok(None)` with nothing to tell them apart.
/// `last_seen_at` slides (with the expiry) at most once per
/// [`SLIDE_AFTER_SECS`], never past [`ABSOLUTE_CAP_DAYS`] from
/// creation.
///
/// # Errors
///
/// [`DbError`] when a read or the slide write fails.
///
/// # Panics
///
/// Never in practice: the documented panics are the `time` crate's
/// nanosecond truncation and RFC 3339 formatting of a whole-second
/// timestamp, both infallible on this path.
pub async fn validate(
    db: &dyn Database,
    clock: &dyn Clock,
    cookie_value: &str,
) -> Result<Option<ValidSession>, DbError> {
    let Some(row) = store::session_by_token_hash(db, &sha256_raw(cookie_value.as_bytes())).await?
    else {
        return Ok(None);
    };
    let now = clock.now().replace_nanosecond(0).expect("in range");
    if row.revoked_at.is_some() || row.expires_at <= iso(now) {
        return Ok(None);
    }

    if row.last_seen_at <= iso(now.saturating_sub(time::Duration::seconds(SLIDE_AFTER_SECS))) {
        let created = OffsetDateTime::parse(&row.created_at, &Rfc3339)
            .map_err(|_| DbError::Query("session created_at is malformed".to_owned()))?;
        let expires = std::cmp::min(
            plus_days(now, SLIDE_WINDOW_DAYS),
            plus_days(created, ABSOLUTE_CAP_DAYS),
        );
        let landed = store::slide_session(db, &row.id, &iso(now), &iso(expires), &iso(now)).await?;
        if landed == 0 {
            // Revoked or expired between the read and the write.
            return Ok(None);
        }
    }

    Ok(Some(ValidSession {
        id: row.id,
        user_id: row.user_id,
    }))
}

/// Revokes every live session of a user — the password-change and
/// account-disable path (wired by the password issue).
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub async fn revoke_all(
    db: &dyn Database,
    clock: &dyn Clock,
    user_id: &str,
) -> Result<u64, DbError> {
    let revoked = store::revoke_all_sessions(db, user_id, &iso(clock.now())).await?;
    audit("session.revoke-all", user_id);
    Ok(revoked)
}

/// The extractor for handlers that require a signed-in user: takes the
/// request parts (the `Scope` and the cookie) and the module state
/// (the `Database` and `Clock` ports), yields the session's id and
/// user id, or the one 401 every signed-out caller sees.
pub struct Session {
    pub id: String,
    pub user_id: String,
}

impl FromRequestParts<Arc<ModuleState>> for Session {
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ModuleState>,
    ) -> Result<Self, Self::Rejection> {
        let scope = parts.extensions.get::<Scope>().cloned();
        let denied = || {
            let problem = Problem::new(&SESSION_INVALID);
            match &scope {
                Some(scope) => problem.instance(&scope.request_id),
                None => problem,
            }
        };
        let (Some(db), Some(clock)) = (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone())
        else {
            return Err(Problem::internal());
        };
        let Some(value) = cookie_value(&parts.headers) else {
            return Err(denied());
        };
        match validate(&*db, &*clock, &value).await {
            Ok(Some(session)) => Ok(Session {
                id: session.id,
                user_id: session.user_id,
            }),
            Ok(None) => Err(denied()),
            Err(err) => {
                tracing::error!(error = %err, "session validation failed");
                Err(Problem::internal())
            }
        }
    }
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}", axum::routing::delete(delete_session))
}

async fn logout(
    session: Session,
    State(state): State<Arc<ModuleState>>,
) -> Result<Response, Problem> {
    let (Some(db), Some(clock)) = (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone())
    else {
        return Err(Problem::internal());
    };
    store::revoke_session(&*db, &session.id, &iso(clock.now())).await?;
    audit("session.logout", &session.user_id);
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, clear_cookie())],
        Json(json!({ "ok": true })),
    )
        .into_response())
}

async fn logout_all(
    session: Session,
    State(state): State<Arc<ModuleState>>,
) -> Result<Response, Problem> {
    let (Some(db), Some(clock)) = (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone())
    else {
        return Err(Problem::internal());
    };
    let revoked = revoke_all(&*db, &*clock, &session.user_id).await?;
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, clear_cookie())],
        Json(json!({ "ok": true, "revoked": revoked })),
    )
        .into_response())
}

async fn list_sessions(
    session: Session,
    State(state): State<Arc<ModuleState>>,
) -> Result<Response, Problem> {
    let (Some(db), Some(clock)) = (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone())
    else {
        return Err(Problem::internal());
    };
    let now = iso(clock.now());
    let rows = store::sessions_by_user(&*db, &session.user_id).await?;
    let sessions: Vec<Value> = rows
        .iter()
        .filter(|row| row.revoked_at.is_none() && row.expires_at > now)
        .map(|row| {
            json!({
                "id": row.id,
                "created_at": row.created_at,
                "last_seen_at": row.last_seen_at,
                "expires_at": row.expires_at,
                "ip_hash": row.ip_hash.as_ref().map(|hash| hash.0.clone()),
                "ua_family": row.ua_family,
                "current": row.id == session.id,
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": sessions })).into_response())
}

async fn delete_session(
    session: Session,
    State(state): State<Arc<ModuleState>>,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let (Some(db), Some(clock)) = (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone())
    else {
        return Err(Problem::internal());
    };
    // Only the user's own sessions are addressable; anyone else's id
    // is a plain 404, leaking nothing.
    let owns = store::sessions_by_user(&*db, &session.user_id)
        .await?
        .iter()
        .any(|row| row.id == id);
    if !owns {
        return Err(Problem::not_found());
    }
    let revoked = store::revoke_session(&*db, &id, &iso(clock.now())).await?;
    audit("session.revoke", &session.user_id);
    Ok(Json(json!({ "ok": true, "revoked": revoked })).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_cookie(cookie: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_str(cookie).expect("cookie header builds"),
        );
        headers
    }

    #[test]
    fn set_cookie_carries_the_host_prefix_rules() {
        let cookie = set_cookie("abc");
        assert!(cookie.starts_with("__Host-fz_session=abc;"));
        for attribute in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(cookie.contains(attribute), "{attribute} missing: {cookie}");
        }
        assert!(!cookie.to_lowercase().contains("domain"), "{cookie}");
    }

    #[test]
    fn clear_cookie_expires_the_value_immediately() {
        let cookie = clear_cookie();
        assert!(cookie.starts_with("__Host-fz_session=;"));
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("Expires=Thu, 01 Jan 1970"));
        assert!(!cookie.to_lowercase().contains("domain"));
    }

    #[test]
    fn cookie_value_reads_past_sibling_cookies() {
        let value = "a".repeat(43);
        let headers =
            headers_with_cookie(&format!("theme=dark; __Host-fz_session={value}; other=1"));
        assert_eq!(cookie_value(&headers).as_deref(), Some(value.as_str()));
        assert_eq!(cookie_value(&HeaderMap::new()), None);
        assert!(
            cookie_value(&headers_with_cookie("__Host-fz_session=short")).is_none(),
            "wrong-length values never reach validation"
        );
        assert!(
            cookie_value(&headers_with_cookie("__Host-fz_session=")).is_none(),
            "empty values never reach validation"
        );
    }

    #[test]
    fn ua_family_sniffs_edge_and_opera_before_chrome_and_safari() {
        assert_eq!(
            ua_family(Some(
                "Mozilla/5.0 Windows Chrome/120.0 Safari/537.36 Edg/120.0"
            ))
            .as_deref(),
            Some("edge")
        );
        assert_eq!(
            ua_family(Some(
                "Mozilla/5.0 Macintosh Chrome/119.0 Safari/537.36 OPR/105.0"
            ))
            .as_deref(),
            Some("opera")
        );
        assert_eq!(
            ua_family(Some("Mozilla/5.0 Firefox/121.0")).as_deref(),
            Some("firefox")
        );
        assert_eq!(
            ua_family(Some("Mozilla/5.0 iPhone CriOS/120")).as_deref(),
            Some("chrome")
        );
        assert_eq!(
            ua_family(Some("Mozilla/5.0 Macintosh Safari/605.1.15")).as_deref(),
            Some("safari")
        );
        assert_eq!(ua_family(Some("curl/8.4.0")).as_deref(), Some("other"));
        assert_eq!(ua_family(None), None);
    }

    #[test]
    fn hashes_are_sha256_of_the_value() {
        assert_eq!(sha256_hex(b"abc"), sha256_hex(b"abc"));
        assert_ne!(sha256_hex(b"abc"), sha256_hex(b"abd"));
        assert_eq!(sha256_raw(b"abc").len(), 32);
    }
}
