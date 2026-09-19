//! Request plumbing the two ceremonies share.

use axum::response::{IntoResponse, Response};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use cratefield_core::{Clock, Database, IdGen, Json, Problem, Scope};
use factory0_auth_core::{SESSION_INVALID, ValidSession, cookie_value, validate};
use http::HeaderMap;
use http::StatusCode;

use crate::ModuleState;

/// The ports the module declared. `Harness::build` refuses a runtime that is
/// missing one, so reaching a `None` arm means the harness was bypassed;
/// answer 503 rather than panicking inside a Worker.
pub(crate) fn ports(
    state: &ModuleState,
) -> Result<(&dyn Database, &dyn Clock, &dyn IdGen), Problem> {
    let (Some(db), Some(clock), Some(id_gen)) = (
        state.ctx.ports.db.as_deref(),
        state.ctx.ports.clock.as_deref(),
        state.ctx.ports.id_gen.as_deref(),
    ) else {
        return Err(Problem::not_ready(
            "the passkeys module needs db, clock and idgen",
        ));
    };
    Ok((db, clock, id_gen))
}

/// The signed-in user, or the one 401 every signed-out caller sees.
/// auth-core's own `Session` extractor is bound to its private state, so the
/// same two steps are done here rather than reaching into it.
pub(crate) async fn require_session(
    state: &ModuleState,
    headers: &HeaderMap,
    scope: &Scope,
) -> Result<ValidSession, Problem> {
    let (db, clock, _) = ports(state)?;
    let denied = || Problem::new(&SESSION_INVALID).instance(&scope.request_id);
    let Some(value) = cookie_value(headers) else {
        return Err(denied());
    };
    match validate(db, clock, &value).await {
        Ok(Some(session)) => Ok(session),
        Ok(None) => Err(denied()),
        Err(err) => {
            tracing::error!(error = %err, "session validation failed");
            Err(Problem::internal().instance(&scope.request_id))
        }
    }
}

/// The rate limit on the two endpoints anyone can call. Keyed on the client
/// address **only**: keying on the email as well would let anyone lock a
/// named account out of its own logins, which trades one denial of service
/// for a worse one.
///
/// Fails open with a warning when the limiter itself is unreachable. An edge
/// binding outage must not take logins down, and the ceremony still has to
/// pass a single-use challenge and a signature.
pub(crate) async fn limit_login(state: &ModuleState, headers: &HeaderMap) -> Option<Response> {
    let limiter = state.ctx.ports.rate_limiter.as_deref()?;
    let ip = cratefield_core::client_ip(headers);
    for key in cratefield_core::rate_limit_keys(ip.as_deref(), None) {
        match limiter.limit(&format!("auth-passkeys:{key}")).await {
            Ok(decision) if !decision.ok => {
                return Some(cratefield_core::rate_limited(decision.retry_after).into_response());
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "the passkey rate limiter is unavailable");
                return None;
            }
        }
    }
    None
}

/// The durable budget on `login/options`, next to [`limit_login`]. The
/// limiter above is an optional port, so a composition without one left the
/// endpoint an unlimited enumeration oracle — every call answers with an
/// account's credential ids or an empty list — and a write amplifier,
/// because every call stored a challenge row. The budget is a row in this
/// module's own table (see [`crate::budget`]), so the database enforces the
/// cap whether or not a limiter was wired up; where a limiter exists the two
/// compose, and whichever is tighter refuses first.
///
/// Keyed per client address and per named address, like the limiter. The
/// per-address key has the documented trade: a caller can spend another
/// address's budget and keep its credential list out of reach for a window.
/// That is one login chooser degraded for a minute — a challenge already
/// issued keeps working — against an oracle a composition without a limiter
/// would otherwise run forever.
///
/// The budget is spent before the account lookup, so a refusal is the same
/// 429 whatever address was named: it says something about the caller's
/// request rate and nothing about any account.
pub(crate) async fn limit_challenges(
    state: &ModuleState,
    scope: &Scope,
    headers: &HeaderMap,
    email: Option<&str>,
) -> Result<Option<Response>, Problem> {
    let (db, clock, _) = ports(state)?;
    let ip = cratefield_core::client_ip(headers);
    let now = clock.now();
    let cutoff = now.saturating_sub(time::Duration::seconds(
        crate::budget::CHALLENGE_BUDGET_WINDOW_SECS,
    ));
    let (now, cutoff) = (crate::iso(now), crate::iso(cutoff));
    for (subject, cap) in crate::budget::subjects(ip.as_deref(), email) {
        match crate::budget::acquire(db, &subject, &now, &cutoff, cap).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(subject = %subject, "the login challenge budget is spent");
                return Ok(Some(
                    cratefield_core::rate_limited(Some(std::time::Duration::from_secs(
                        crate::budget::CHALLENGE_BUDGET_WINDOW_SECS as u64,
                    )))
                    .into_response(),
                ));
            }
            Err(err) => {
                tracing::error!(error = %err, "could not read the challenge budget");
                return Err(internal(scope));
            }
        }
    }
    Ok(None)
}

/// The single answer every failed ceremony gets, whatever went wrong.
pub(crate) fn ceremony_failed(scope: &Scope) -> Problem {
    Problem::new(&crate::CEREMONY_FAILED).instance(&scope.request_id)
}

pub(crate) fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

pub(crate) fn b64u(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

pub(crate) fn ok(body: serde_json::Value) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

/// The client address and user agent a session records, as far as the edge
/// tells us.
pub(crate) fn client_hints(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let ip = cratefield_core::client_ip(headers);
    let user_agent = headers
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (ip, user_agent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn base64url_is_unpadded() {
        assert_eq!(b64u(b"any carnal pleas"), "YW55IGNhcm5hbCBwbGVhcw");
    }
}
