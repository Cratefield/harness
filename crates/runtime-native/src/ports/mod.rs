//! Port adapters over native infrastructure (issue #19): the system
//! clock on tokio, `tokio::spawn`, `reqwest` and Redis — plus client-IP
//! resolution, the one place a native deployment must behave
//! differently from Workers.

mod blob;
mod clock;
mod defer;
mod http;
mod kv;
mod rate_limit;
mod realtime;

pub use blob::DirBlob;
pub use clock::TokioClock;
pub use defer::SpawnDefer;
pub use http::{OutboundOptions, ReqwestClient, vet_ip_ok};
pub use kv::{RedisBundle, RedisKv, RedisPortError, redis_from_env};
pub use rate_limit::RedisRateLimiter;
pub use realtime::{Connection, InProcessRealtime};

use axum::http::{HeaderMap, HeaderName};
use std::net::IpAddr;
use std::str::FromStr as _;

use cratefield_core::Config;

/// The header the runtime normalizes the resolved client IP into. Core's
/// `client_ip` reads it first on every target, so modules (which only
/// ever call `cratefield_core::client_ip`) see the same header contract on
/// Workers and native. The server middleware sets it **after** stripping
/// every inbound forwarding header, so its value is always the one this
/// runtime resolved — never what a client sent.
pub const CLIENT_IP_HEADER: &str = "cf-connecting-ip";

/// Forwarding headers stripped from every inbound request before the
/// router sees it. `cratefield_core::client_ip` trusts
/// `x-forwarded-for`'s first hop on native builds, so an unsanitized
/// header would let any client pick its own rate-limit key; stripping
/// here is what makes [`trusted_proxy_headers`] the single trust point.
const STRIPPED: [&str; 4] = [
    "cf-connecting-ip",
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
];

/// The `TRUSTED_HOSTS` list: extra `Host` values this deployment answers
/// to, beyond the venture's own domain (issue #129).
///
/// A native process serves whatever `Host` a caller sends, and `Host` is
/// the key ADR 0008's database-per-tenant resolution will read once phase
/// three lands — so an unvalidated one is both a link-forgery and
/// cache-poisoning vector today and the cross-tenant vector tomorrow.
/// Entries are compared without their port, lowercased. Empty is not
/// permissive: the venture's own domain still answers.
#[must_use]
pub fn trusted_hosts(config: &dyn Config) -> Vec<String> {
    config
        .get("TRUSTED_HOSTS")
        .map(|raw| {
            raw.split(',')
                .map(|entry| entry.trim().to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The hosts a venture answers to by construction: its apex domain, the
/// `api.<domain>` the architecture says the API serves, and the host of
/// its own public URL (issue #129).
#[must_use]
pub fn venture_hosts(venture: &cratefield_core::Venture) -> Vec<String> {
    let domain = venture.domain.trim().to_ascii_lowercase();
    let mut hosts = Vec::new();
    if !domain.is_empty() {
        hosts.push(format!("api.{domain}"));
        hosts.push(domain);
    }
    if let Some(host) = venture
        .public_url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
    {
        let host = host_without_port(&host);
        if !hosts.iter().any(|known| known == &host) {
            hosts.push(host);
        }
    }
    hosts
}

/// The host part of an authority, without its port. IPv6 literals keep
/// their brackets, which is how a `Host` header spells them.
#[must_use]
pub fn host_without_port(authority: &str) -> String {
    let authority = authority.trim().to_ascii_lowercase();
    if let Some(rest) = authority.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((inner, _)) => format!("[{inner}]"),
            None => authority,
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host.to_owned(),
        _ => authority,
    }
}

/// Whether `host` is a loopback name or literal, with or without a port.
/// Local development and every in-process test reach the server this way.
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    let host = host_without_port(host);
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "[::1]"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The `TRUSTED_PROXY_HEADERS` list: the header names this deployment is
/// willing to believe the client IP from (comma-separated, e.g.
/// `TRUSTED_PROXY_HEADERS=x-forwarded-for` behind one nginx, or
/// `cf-connecting-ip` behind Cloudflare). Default: **empty** — an
/// unconfigured deployment must not trust any forwarding header, and the
/// runtime resolves every address from the socket peer instead.
///
/// Trust is a property of the network path, not the header: only list a
/// header when a proxy you control overwrites it on every request.
/// Entries are lowercased; invalid header names are ignored; `forwarded`
/// (RFC 7239) is accepted as a name but its `for=` value format is not
/// parsed — use an `x-forwarded-for`-style list or `cf-connecting-ip`.
#[must_use]
pub fn trusted_proxy_headers(config: &dyn Config) -> Vec<String> {
    config
        .get("TRUSTED_PROXY_HEADERS")
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_ascii_lowercase)
                .filter(|name| HeaderName::from_str(name).is_ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

/// The client IP for one request, in trust order:
///
/// 1. the first [`trusted_proxy_headers`] header present with a value
///    whose first comma-separated entry parses as an IP address;
/// 2. else the TCP peer address the server observed.
///
/// `None` only when both are unavailable (no trusted header matched and
/// the middleware ran without connection info, e.g. a test's `oneshot`).
///
/// This function decides; the server middleware enforces. It resolves
/// the address here, strips every forwarding header, and writes the
/// result into [`CLIENT_IP_HEADER`](crate::CLIENT_IP_HEADER) — so by the time a module calls
/// `cratefield_core::client_ip(headers)`, the only forwarding header left
/// carries exactly this runtime's verdict.
#[must_use]
pub fn client_ip(headers: &HeaderMap, trusted: &[String], peer: Option<IpAddr>) -> Option<IpAddr> {
    for name in trusted {
        let parsed = headers
            .get(name.as_str())
            .and_then(|value| value.to_str().ok())
            .and_then(|list| list.split(',').next())
            .map(str::trim)
            .and_then(|first| first.parse::<IpAddr>().ok());
        if let Some(ip) = parsed {
            return Some(ip);
        }
    }
    peer
}

/// Applies the resolution to a request's headers: strip
/// [`STRIPPED`], then set [`CLIENT_IP_HEADER`] to `resolved`. This is
/// what the server middleware calls; it is `pub(crate)` visible only
/// through tests that assert the sanitized view modules actually see.
pub(crate) fn normalize_headers(headers: &mut HeaderMap, resolved: Option<IpAddr>) {
    for name in STRIPPED {
        headers.remove(HeaderName::from_static(name));
    }
    if let Some(ip) = resolved
        && let Ok(value) = axum::http::HeaderValue::from_str(&ip.to_string())
    {
        headers.insert(HeaderName::from_static(CLIENT_IP_HEADER), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use cratefield_core::MapConfig;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        use std::str::FromStr as _;
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_str(name).expect("test header names are valid"),
                HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        map
    }

    #[test]
    fn trusted_list_defaults_to_empty() {
        assert!(trusted_proxy_headers(&MapConfig::default()).is_empty());
        let cfg = MapConfig::from_pairs([("TRUSTED_PROXY_HEADERS", "  ")]);
        assert!(trusted_proxy_headers(&cfg).is_empty());
    }

    #[test]
    fn trusted_list_parses_lowercased_and_drops_invalid() {
        let cfg = MapConfig::from_pairs([(
            "TRUSTED_PROXY_HEADERS",
            "X-Forwarded-For, x-real-ip, bad name,,cf-connecting-ip",
        )]);
        assert_eq!(
            trusted_proxy_headers(&cfg),
            ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"]
        );
    }

    #[test]
    fn unconfigured_trusts_no_header_only_the_peer() {
        let headers = headers(&[
            ("x-forwarded-for", "6.6.6.6"),
            ("cf-connecting-ip", "7.7.7.7"),
            ("x-real-ip", "8.8.8.8"),
        ]);
        let peer: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(
            client_ip(&headers, &[], Some(peer)),
            Some(peer),
            "with no trusted headers, forwarding headers are decoration"
        );
    }

    #[test]
    fn trusted_header_wins_in_config_order() {
        let headers = headers(&[
            ("x-real-ip", "198.51.100.2"),
            ("x-forwarded-for", "198.51.100.1, 10.0.0.1"),
        ]);
        let trusted = vec!["x-forwarded-for".to_owned(), "x-real-ip".to_owned()];
        let resolved = client_ip(&headers, &trusted, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(
            resolved.map(|ip| ip.to_string()).as_deref(),
            Some("198.51.100.1")
        );
    }

    #[test]
    fn garbage_in_trusted_header_falls_through_to_next_then_peer() {
        let headers = headers(&[("x-real-ip", "not-an-ip")]);
        let peer: IpAddr = "203.0.113.7".parse().unwrap();
        let trusted = vec!["x-real-ip".to_owned()];
        assert_eq!(client_ip(&headers, &trusted, Some(peer)), Some(peer));
    }

    #[test]
    fn normalize_strips_everything_and_sets_the_verdict() {
        let mut headers = headers(&[
            ("x-forwarded-for", "6.6.6.6"),
            ("forwarded", "for=7.7.7.7"),
            ("x-real-ip", "8.8.8.8"),
            ("cf-connecting-ip", "9.9.9.9"),
        ]);
        normalize_headers(&mut headers, Some("203.0.113.7".parse::<IpAddr>().unwrap()));
        // The spoofed values are gone; the verdict is the only survivor.
        assert_eq!(headers.get("x-forwarded-for"), None);
        assert_eq!(headers.get("forwarded"), None);
        assert_eq!(headers.get("x-real-ip"), None);
        assert_eq!(
            headers.get(CLIENT_IP_HEADER).and_then(|v| v.to_str().ok()),
            Some("203.0.113.7")
        );
        // And core — what the modules call — reads exactly that verdict.
        assert_eq!(
            cratefield_core::client_ip(&headers).as_deref(),
            Some("203.0.113.7")
        );
    }
}

#[cfg(test)]
mod host_tests {
    use super::{host_without_port, is_loopback_host, trusted_hosts, venture_hosts};
    use cratefield_core::{MapConfig, Venture};

    #[test]
    fn a_venture_answers_to_its_own_domain_and_api_subdomain() {
        let venture = Venture::new("cratefield-waitlist", "cratefield.com")
            .public_url("https://cratefield.com");
        let hosts = venture_hosts(&venture);
        assert!(hosts.contains(&"cratefield.com".to_owned()), "{hosts:?}");
        assert!(
            hosts.contains(&"api.cratefield.com".to_owned()),
            "{hosts:?}"
        );
        // A public URL on another host is answered to as well.
        let split =
            Venture::new("auth", "factory0.ventures").public_url("https://auth.factory0.ventures/");
        let hosts = venture_hosts(&split);
        assert!(
            hosts.contains(&"auth.factory0.ventures".to_owned()),
            "{hosts:?}"
        );
    }

    #[test]
    fn ports_are_not_part_of_the_comparison_and_ipv6_keeps_its_brackets() {
        assert_eq!(host_without_port("cratefield.com:8443"), "cratefield.com");
        assert_eq!(host_without_port("CrateField.com"), "cratefield.com");
        assert_eq!(host_without_port("[::1]:8080"), "[::1]");
        assert_eq!(host_without_port("[fd00::1]"), "[fd00::1]");
        // Not a port: a bare colon with a non-numeric tail stays put.
        assert_eq!(host_without_port("host:notaport"), "host:notaport");
    }

    #[test]
    fn loopback_is_recognized_in_every_spelling_local_work_uses() {
        for host in [
            "localhost",
            "localhost:8080",
            "127.0.0.1",
            "127.0.0.1:8080",
            "127.9.9.9",
            "[::1]",
            "[::1]:8080",
            "app.localhost",
        ] {
            assert!(is_loopback_host(host), "{host} is loopback");
        }
        for host in ["cratefield.com", "10.0.0.1", "[fd00::1]", "evil.example"] {
            assert!(!is_loopback_host(host), "{host} is not loopback");
        }
    }

    #[test]
    fn the_extra_host_list_is_parsed_like_the_trusted_proxy_list() {
        assert!(trusted_hosts(&MapConfig::default()).is_empty());
        let cfg = MapConfig::from_pairs([("TRUSTED_HOSTS", " Api.Example.com , , other.test ")]);
        assert_eq!(trusted_hosts(&cfg), ["api.example.com", "other.test"]);
    }
}
