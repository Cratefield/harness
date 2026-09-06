//! Redirect URI validation (issue #7): one matching rule used at
//! registration and at `/authorize` (wired there by issue #10).
//!
//! Byte-exact comparison **after parsing** both sides as absolute
//! URIs: scheme, authority (host and port), path and query must be
//! identical strings. No wildcards, no prefix matching, no pattern
//! language — a client that needs several callbacks registers several
//! URIs. Fragments are rejected outright, and because `http::Uri`
//! silently drops them, the fragment check runs on the raw string
//! before any parsing.
//!
//! `http::Uri` cannot parse path-form custom schemes
//! (`com.example.app:/callback`, the issue's native-app shape), so
//! custom schemes are parsed here into the same comparison key. The
//! one normalization `http::Uri` performs — an absent path on an
//! authority-form URI reads as `/` — applies to both sides equally.

use factory0_core::Problem;

use crate::store::CLIENT_PUBLIC;

/// The byte-exact comparison key. Equality of two keys is the whole
/// matching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalUri {
    scheme: String,
    authority: Option<String>,
    path: String,
    query: Option<String>,
}

fn split_query(rest: &str) -> (&str, Option<&str>) {
    match rest.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (rest, None),
    }
}

/// Parses a path-form custom scheme URI (`scheme:/path[?q]`).
fn parse_custom(scheme: &str, rest: &str) -> Option<CanonicalUri> {
    if let Some(authority_part) = rest.strip_prefix("//") {
        let end = authority_part
            .find(['/', '?'])
            .unwrap_or(authority_part.len());
        let (authority, tail) = authority_part.split_at(end);
        let (path, query) = split_query(tail);
        if authority.is_empty() {
            return None;
        }
        return Some(CanonicalUri {
            scheme: scheme.to_owned(),
            authority: Some(authority.to_owned()),
            path: path.to_owned(),
            query: query.map(str::to_owned),
        });
    }
    let (path, query) = split_query(rest);
    if path.is_empty() {
        return None;
    }
    Some(CanonicalUri {
        scheme: scheme.to_owned(),
        authority: None,
        path: path.to_owned(),
        query: query.map(str::to_owned),
    })
}

/// The comparison key of one URI: `None` when it is not an absolute,
/// fragment-free URI (relative references, junk, anything with a `#`).
fn canonical(uri: &str) -> Option<CanonicalUri> {
    if uri.contains('#') || uri.contains('*') {
        return None;
    }
    let (scheme, rest) = uri.split_once(':')?;
    if scheme.is_empty() {
        return None;
    }
    if matches!(scheme, "http" | "https") {
        let parsed = http::Uri::try_from(uri).ok()?;
        let authority = parsed.authority()?.as_str().to_owned();
        if authority.contains('@') {
            return None;
        }
        return Some(CanonicalUri {
            scheme: scheme.to_owned(),
            authority: Some(authority),
            path: parsed.path().to_owned(),
            query: parsed.query().map(str::to_owned),
        });
    }
    if !scheme
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase())
    {
        return None;
    }
    if !scheme
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    parse_custom(scheme, rest)
}

/// Whether `presented` is the same URI as `registered`: byte-exact
/// after parsing. Fragments fail both sides; a wildcard fails both
/// sides; relative references never match.
#[must_use]
pub fn matches(registered: &str, presented: &str) -> bool {
    match (canonical(registered), canonical(presented)) {
        (Some(registered), Some(presented)) => registered == presented,
        _ => false,
    }
}

/// Whether any registered URI matches — the `/authorize` gate
/// (issue #10 renders an error page when this is `false`; it never
/// redirects to an unregistered URI).
#[must_use]
pub fn matches_any(registered: &[String], presented: &str) -> bool {
    registered.iter().any(|uri| matches(uri, presented))
}

fn reject(detail: impl Into<String>) -> Problem {
    Problem::validation_failed(detail)
}

/// Registration-time validation: the URI must be one `matches` could
/// accept, and its scheme must be legal for the client kind.
///
/// - `https` — always allowed.
/// - `http` — only `http://localhost` / `http://127.0.0.1` (any port),
///   and only for public clients.
/// - custom schemes — public clients only, registered in full,
///   lowercase, path non-empty.
///
/// # Errors
///
/// A `validation-failed` problem naming the rule the URI broke.
pub fn validate_registration(uri: &str, client_kind: &str) -> Result<(), Problem> {
    let Some(parsed) = canonical(uri) else {
        return Err(reject(format!(
            "{uri:?}: must be an absolute, fragment-free URI without wildcards"
        )));
    };
    let host = parsed
        .authority
        .as_deref()
        .map(|authority| authority.split(':').next().unwrap_or_default());
    match parsed.scheme.as_str() {
        "https" => Ok(()),
        "http" => {
            if client_kind != CLIENT_PUBLIC {
                return Err(reject(format!("{uri:?}: http is public-client only")));
            }
            match host {
                Some("localhost" | "127.0.0.1") => Ok(()),
                _ => Err(reject(format!(
                    "{uri:?}: plain http is allowed only on localhost / 127.0.0.1"
                ))),
            }
        }
        _ => {
            if client_kind != CLIENT_PUBLIC {
                return Err(reject(format!(
                    "{uri:?}: custom schemes are public-client only"
                )));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CLIENT_CONFIDENTIAL, CLIENT_PUBLIC};

    const REGISTERED: &str = "https://undercoverrockstars.com/auth/callback";

    #[test]
    fn the_issue_table_every_mutation_fails_except_the_exact_match() {
        let table = [
            (REGISTERED, true, "exact match"),
            (
                "https://undercoverrockstars.com/auth/callback/",
                false,
                "trailing slash",
            ),
            (
                "https://UndercoverRockstars.com/auth/callback",
                false,
                "host case",
            ),
            (
                "https://undercoverrockstars.com/auth/callback?x=1",
                false,
                "added query parameter",
            ),
            (
                "https://undercoverrockstars.com/auth/callback#frag",
                false,
                "added fragment",
            ),
            (
                "https://undercoverrockstars.com:8443/auth/callback",
                false,
                "port change",
            ),
            (
                "http://undercoverrockstars.com/auth/callback",
                false,
                "scheme change",
            ),
            (
                "https://undercoverrockstars.com/auth/callback/extra",
                false,
                "prefix extension",
            ),
            (
                "https://*.undercoverrockstars.com/auth/callback",
                false,
                "wildcard attempt",
            ),
            (
                "https://user:pass@undercoverrockstars.com/auth/callback",
                false,
                "userinfo",
            ),
            (
                "https://app.undercoverrockstars.com/auth/callback",
                false,
                "subdomain",
            ),
            ("/auth/callback", false, "relative"),
            ("", false, "empty"),
        ];
        for (presented, expected, why) in table {
            assert_eq!(
                matches(REGISTERED, presented),
                expected,
                "{why}: {presented}"
            );
        }
    }

    #[test]
    fn identical_fragments_fail_too_because_fragments_never_parse() {
        let registered = "https://undercoverrockstars.com/auth/callback";
        assert!(!matches(
            "https://undercoverrockstars.com/auth/callback#same",
            "https://undercoverrockstars.com/auth/callback#same"
        ));
        assert!(matches(REGISTERED, registered));
    }

    #[test]
    fn explicit_default_ports_differ_from_absent_ones() {
        assert!(!matches(
            "https://undercoverrockstars.com:443/auth/callback",
            REGISTERED
        ));
        assert!(matches(
            "https://undercoverrockstars.com:8443/auth/callback",
            "https://undercoverrockstars.com:8443/auth/callback"
        ));
    }

    #[test]
    fn registered_queries_match_exactly() {
        let registered = "https://undercoverrockstars.com/auth/callback?a=1&b=2";
        assert!(matches(
            registered,
            "https://undercoverrockstars.com/auth/callback?a=1&b=2"
        ));
        assert!(!matches(
            registered,
            "https://undercoverrockstars.com/auth/callback?a=1"
        ));
        assert!(!matches(
            registered,
            "https://undercoverrockstars.com/auth/callback?a=1&b=2&c=3"
        ));
        assert!(!matches(
            registered,
            "https://undercoverrockstars.com/auth/callback?b=2&a=1"
        ));
    }

    #[test]
    fn absent_path_and_slash_are_the_same_target() {
        assert!(matches(
            "https://undercoverrockstars.com",
            "https://undercoverrockstars.com/"
        ));
        assert!(matches(
            "https://undercoverrockstars.com/",
            "https://undercoverrockstars.com"
        ));
    }

    #[test]
    fn custom_schemes_match_in_full() {
        assert!(matches(
            "com.example.app:/callback",
            "com.example.app:/callback"
        ));
        assert!(!matches(
            "com.example.app:/callback",
            "com.example.app:/callback2"
        ));
        assert!(!matches(
            "com.example.app:/callback",
            "com.example.app:/callback?x=1"
        ));
        assert!(matches(
            "com.example.app:/callback?x=1",
            "com.example.app:/callback?x=1"
        ));
        assert!(matches("myapp://callback/x", "myapp://callback/x"));
        assert!(!matches("myapp://callback/x", "myapp://callback/y"));
        assert!(!matches("myapp://callback/x", "com.example.app:/callback"));
    }

    #[test]
    fn matches_any_is_the_authorize_gate() {
        let registered = vec![
            "https://undercoverrockstars.com/auth/callback".to_owned(),
            "https://kontinuum.audio/cb".to_owned(),
        ];
        assert!(matches_any(&registered, "https://kontinuum.audio/cb"));
        assert!(!matches_any(&registered, "https://kontinuum.audio/cb/"));
        assert!(!matches_any(&registered, "https://evil.example/cb"));
        assert!(!matches_any(
            &[],
            "https://undercoverrockstars.com/auth/callback"
        ));
    }

    #[test]
    fn registration_accepts_https_for_both_kinds() {
        for kind in [CLIENT_CONFIDENTIAL, CLIENT_PUBLIC] {
            assert!(validate_registration(REGISTERED, kind).is_ok(), "{kind}");
        }
    }

    #[test]
    fn registration_localhost_http_is_public_only() {
        for uri in [
            "http://localhost:3000/cb",
            "http://127.0.0.1/cb",
            "http://127.0.0.1:9/cb",
        ] {
            assert!(validate_registration(uri, CLIENT_PUBLIC).is_ok(), "{uri}");
            assert!(
                validate_registration(uri, CLIENT_CONFIDENTIAL).is_err(),
                "{uri}"
            );
        }
        for uri in ["http://example.com/cb", "http://localhost.evil/cb"] {
            assert!(validate_registration(uri, CLIENT_PUBLIC).is_err(), "{uri}");
        }
    }

    #[test]
    fn registration_custom_schemes_are_public_only() {
        assert!(validate_registration("com.example.app:/callback", CLIENT_PUBLIC).is_ok());
        assert!(validate_registration("myapp://callback/x", CLIENT_PUBLIC).is_ok());
        assert!(
            validate_registration("com.example.app:/callback", CLIENT_CONFIDENTIAL).is_err(),
            "custom schemes are public-client only"
        );
    }

    #[test]
    fn registration_rejects_what_matching_would_never_accept() {
        for uri in [
            "https://undercoverrockstars.com/cb#frag",
            "https://*.example.com/cb",
            "/callback",
            "example.com/cb",
            "https://user:pass@example.com/cb",
            "myapp:",
            "MyApp:/cb",
            "",
        ] {
            assert!(
                validate_registration(uri, CLIENT_PUBLIC).is_err(),
                "{uri:?} must never be registerable"
            );
        }
    }
}
