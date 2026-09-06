//! Rate-limit key helpers (architecture section 11, issues #10/#11/#13):
//! keys are `ip:<ip>` and `email:<normalized>`, shared across modules so
//! one venture has one budget per subject. Both modules call these on
//! every public route, including confirm and status.

use axum::http::{HeaderMap, HeaderName};

use crate::email;

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
}
