//! Rate-limit key helpers (architecture section 11, issues #10/#11/#13):
//! keys are `ip:<ip>` and `email:<normalized>`, shared across modules so
//! one venture has one budget per subject. Both modules call these on
//! every public route, including confirm and status.

use axum::http::HeaderMap;
#[cfg(not(target_arch = "wasm32"))]
use axum::http::HeaderName;

use crate::email;
use crate::ports::{Decision, RateLimiter};
use std::sync::Arc;
use std::time::Duration;

/// The client IP for rate limiting, from the headers.
///
/// On Workers (`cf-connecting-ip`) the edge sets the address and
/// `x-forwarded-for` is client-forgeable, so it is ignored on wasm. A
/// self-hosted runtime sits behind its own proxy, so native builds honor
/// `x-forwarded-for`'s first hop when the Cloudflare header is absent.
#[must_use]
pub fn client_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(ip) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
    {
        return Some(ip.trim().to_owned());
    }
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(first) = headers
        .get(HeaderName::from_static("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .and_then(|list| list.split(',').next())
        .map(str::trim)
        .filter(|first| !first.is_empty())
    {
        return Some(first.to_owned());
    }
    None
}

/// The rate-limit keys for one request: always `ip:<ip>` (or `ip:unknown`
/// when no address is visible), plus `email:<normalized>` when an address
/// is known. The limiter is consulted per key, in order.
#[must_use]
pub fn rate_limit_keys(remote_ip: Option<&str>, email: Option<&str>) -> Vec<String> {
    let mut keys = vec![format!("ip:{}", remote_ip.unwrap_or("unknown"))];
    if let Some(email) = email {
        keys.push(format!("email:{}", email::normalize(email)));
    }
    keys
}

/// What a limiter transport error means for the request (issue #133).
/// Every call site picks one deliberately; it used to be an implicit
/// "allow" buried in each module's copy of the limiter loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitFailure {
    /// Allow the request with a warning: availability first. Sound only
    /// where durable backstops sit behind the limiter — a captcha gate
    /// and a DB-enforced [`SendCooldown`](crate::cooldown::SendCooldown),
    /// as on the waitlist and email-signup joins.
    FailOpen,
    /// Deny the request. Correct when the limiter is the only thing
    /// between the route and an enumeration or brute-force budget.
    FailClosed,
}

/// Outcome of consulting the limiter for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimit {
    Allowed,
    Denied { retry_after: Option<Duration> },
}

/// Shared limiter loop: every key must pass, and a transport error is
/// resolved by `on_failure` at the call site rather than per-module
/// convention. No limiter configured (`None`) allows the request:
/// composition chose to run without one.
pub async fn check_rate_limit(
    limiter: Option<&Arc<dyn RateLimiter>>,
    keys: &[String],
    on_failure: RateLimitFailure,
) -> RateLimit {
    let Some(limiter) = limiter else {
        return RateLimit::Allowed;
    };
    for key in keys {
        match limiter.limit(key).await {
            Ok(Decision { ok: true, .. }) => {}
            Ok(Decision {
                ok: false,
                retry_after,
            }) => {
                return RateLimit::Denied { retry_after };
            }
            Err(err) => {
                if on_failure == RateLimitFailure::FailClosed {
                    tracing::warn!(error = %err, key = %key, "rate limiter unavailable; denying");
                    return RateLimit::Denied { retry_after: None };
                }
                tracing::warn!(error = %err, key = %key, "rate limiter unavailable; allowing");
            }
        }
    }
    RateLimit::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    #[test]
    fn keys_are_ip_then_normalized_email() {
        let keys = rate_limit_keys(Some("203.0.113.7"), Some(" Nick@Example.COM "));
        assert_eq!(keys, ["ip:203.0.113.7", "email:nick@example.com"]);
    }

    #[test]
    fn missing_ip_falls_back_to_unknown() {
        assert_eq!(rate_limit_keys(None, None), ["ip:unknown"]);
    }

    #[test]
    fn prefers_cf_connecting_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cf-connecting-ip",
            header::HeaderValue::from_static("198.51.100.9"),
        );
        headers.insert(
            header::HeaderName::from_static("x-forwarded-for"),
            header::HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
        );
        assert_eq!(client_ip(&headers).as_deref(), Some("198.51.100.9"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_honors_forwarded_for_first_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("x-forwarded-for"),
            header::HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
        );
        assert_eq!(client_ip(&headers).as_deref(), Some("1.2.3.4"));
    }

    struct StubLimiter {
        ok: bool,
        transport_error: bool,
    }

    #[async_trait::async_trait]
    impl RateLimiter for StubLimiter {
        async fn limit(&self, _key: &str) -> Result<Decision, crate::ports::RateLimitError> {
            if self.transport_error {
                return Err(crate::ports::RateLimitError::Transport("down".to_owned()));
            }
            Ok(Decision {
                ok: self.ok,
                retry_after: (!self.ok).then(|| Duration::from_secs(7)),
            })
        }
    }

    fn limiter(ok: bool, transport_error: bool) -> Arc<dyn RateLimiter> {
        Arc::new(StubLimiter {
            ok,
            transport_error,
        })
    }

    fn ip_key() -> Vec<String> {
        vec!["ip:203.0.113.7".to_owned()]
    }

    #[pollster::test]
    async fn all_keys_passing_allows() {
        let keys = vec!["ip:203.0.113.7".to_owned(), "email:a@b.co".to_owned()];
        let result = check_rate_limit(
            Some(&limiter(true, false)),
            &keys,
            RateLimitFailure::FailClosed,
        )
        .await;
        assert!(matches!(result, RateLimit::Allowed), "{result:?}");
    }

    #[pollster::test]
    async fn a_denied_key_carries_its_retry_after() {
        let result = check_rate_limit(
            Some(&limiter(false, false)),
            &ip_key(),
            RateLimitFailure::FailClosed,
        )
        .await;
        assert!(
            matches!(&result, RateLimit::Denied { retry_after } if *retry_after == Some(Duration::from_secs(7))),
            "{result:?}"
        );
    }

    #[pollster::test]
    async fn transport_errors_resolve_at_the_call_site() {
        let open = check_rate_limit(
            Some(&limiter(true, true)),
            &ip_key(),
            RateLimitFailure::FailOpen,
        )
        .await;
        assert!(matches!(open, RateLimit::Allowed), "{open:?}");
        let closed = check_rate_limit(
            Some(&limiter(true, true)),
            &ip_key(),
            RateLimitFailure::FailClosed,
        )
        .await;
        assert!(
            matches!(&closed, RateLimit::Denied { retry_after: None }),
            "{closed:?}"
        );
    }

    #[pollster::test]
    async fn no_limiter_is_a_composition_choice_not_a_failure() {
        let result = check_rate_limit(None, &ip_key(), RateLimitFailure::FailClosed).await;
        assert!(matches!(result, RateLimit::Allowed), "{result:?}");
    }
}
