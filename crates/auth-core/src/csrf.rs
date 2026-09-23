//! Login CSRF (issue #439): the guard that makes "a same-origin POST
//! from our own form" true before a state-changing handler acts on it.
//!
//! `SameSite=Lax` stops a cross-site POST from *carrying* our session
//! cookie, but not from *setting* one. A form on another site that posts
//! to our login endpoint still completes: we mint a session for the
//! attacker's account, the browser stores it over whatever the victim
//! was carrying, and the victim goes on using the venture signed in as
//! someone else. No cookie attribute helps — the request itself has to
//! be refused on arrival.
//!
//! `require_same_origin` reads the two signals a browser sends with
//! every request. `sec-fetch-site` is checked first: `same-origin` and
//! `none` pass, everything else — `same-site` included, because a
//! sibling subdomain can post a `__Host-` cookie onto us from a
//! cross-origin form — is refused. Then `origin`, when present, must be
//! this venture's own origin, judged against the host the request
//! actually reached, with the scheme's default port normalised away;
//! `http` passes only for a loopback host so local development keeps
//! working. A request carrying neither header is accepted: curl and
//! server-to-server callers send neither, and every current browser
//! sends at least one.
//!
//! The `CROSS_SITE_REQUEST` problem names the refusing signal in its
//! `detail`, so an operator reading logs can tell `sec-fetch-site` from
//! `origin`.

use axum::http::{HeaderMap, StatusCode, Uri, header};
use cratefield_core::{Problem, ProblemDef};

/// The one refusal for a request the browser reports as coming from
/// another site. The body does not say which signal refused it — that is
/// what the `detail` is for.
pub const CROSS_SITE_REQUEST: ProblemDef = ProblemDef {
    slug: "auth/cross-site-request",
    status: StatusCode::FORBIDDEN,
    title: "A same-origin request is required",
    description: "Fetch metadata or the origin header reports another site; a request \
                  that can change state is accepted only from this venture's own origin",
};

/// Refuses a request the browser reports as coming from another site.
///
/// Two signals, in the order they can be trusted:
///
/// 1. `sec-fetch-site`, when the browser sent it: `same-origin` and
///    `none` pass, any other value is refused — including `same-site`,
///    which covers sibling subdomains, and a sibling subdomain is
///    exactly who can post a `__Host-` cookie onto us.
/// 2. `origin`, when present: it must be this venture's own origin. The
///    host it is judged against is the `Host` header when present and
///    non-empty, else the URI's authority — the same `Host`-then-
///    authority fallback the native runtime's host layer uses, because
///    on Cloudflare the request URI is absolute and `Host` may not be
///    sent. Neither available means refused: an `Origin` header means a
///    browser is talking to us, and a claim we cannot check is not a
///    claim we accept.
///
/// A request carrying neither header is accepted: non-browser clients
/// (curl, server-to-server) send neither, and every current browser
/// sends at least one. `x-forwarded-host` is deliberately not consulted,
/// per the harness's one header-trust contract.
///
/// # Errors
///
/// [`CROSS_SITE_REQUEST`] — a 403 whose `detail` names the signal that
/// refused the request — whenever either signal reports another site, an
/// `origin` is malformed or `null`, or an `origin` arrives that this
/// request gives no host to check against.
pub fn require_same_origin(headers: &HeaderMap, uri: &Uri) -> Result<(), Problem> {
    // Signal one: fetch metadata. Set by the browser alone — a page
    // script cannot forge it — so it outranks `origin`, which a
    // same-site attacker controls outright. `none` is a request with no
    // initiating site: typed into the address bar, a bookmark, or a
    // plain non-browser client.
    if let Some(site) = headers.get("sec-fetch-site") {
        let site = match site.to_str() {
            Ok(site) => site.to_ascii_lowercase(),
            Err(_) => {
                return Err(refused(
                    "sec-fetch-site was not valid UTF-8; only same-origin or none is accepted",
                ));
            }
        };
        // Case is not significant in the value; anything that is not
        // `same-origin` or `none` after that is refused, `same-site`
        // included.
        match site.as_str() {
            "same-origin" | "none" => {}
            other => {
                return Err(refused(format!(
                    "sec-fetch-site is {other}; only same-origin or none is accepted"
                )));
            }
        }
    }

    // Signal two: the origin. Present on every cross-origin request and
    // on our own non-GET requests; a browser that sends it is claiming a
    // starting point, and the claim is checked, never believed.
    if let Some(origin) = headers.get(header::ORIGIN) {
        let Ok(origin) = origin.to_str() else {
            return Err(refused("origin was not valid UTF-8"));
        };
        // `null` is the spec's "I am not telling you": a sandboxed
        // iframe, a redirect chain the browser declines to attribute. It
        // is never our origin.
        if origin == "null" {
            return Err(refused(
                "origin is null; requests must come from this venture's own origin",
            ));
        }
        let Some((scheme, authority)) = origin.split_once("://") else {
            return Err(refused(format!(
                "origin {origin} carries no scheme; expected an origin like https://…"
            )));
        };
        // `http` is allowed only where https does not reach: loopback
        // names and literals, so `cargo run` against `localhost:8788`
        // still works. Everywhere else the origin must be https.
        let is_loopback = is_loopback_host(authority_host(authority));
        if scheme != "https" && !(scheme == "http" && is_loopback) {
            return Err(refused(format!(
                "origin {origin} is not https (http is accepted only for a loopback host)"
            )));
        }
        let Some(own) = own_host(headers, uri) else {
            return Err(refused(
                "origin was present but the request named no host to check it against",
            ));
        };
        if !same_authority(authority, own, scheme) {
            return Err(refused(format!(
                "origin {origin} does not match the host this request reached ({own})"
            )));
        }
    }

    // Neither header present: a non-browser client (curl, server-to-
    // server) sends neither, and every current browser sends at least
    // one, so accepting is the trade-off that keeps those callers
    // working. Everything a browser does send has been checked above.
    Ok(())
}

/// The `Problem` for a refused request; `detail` names the signal.
fn refused(detail: impl Into<String>) -> Problem {
    Problem::new(&CROSS_SITE_REQUEST).with_detail(detail)
}

/// The host this request reached: the `Host` header when present and
/// non-empty, else the URI's authority — the same fallback the native
/// runtime's host layer uses, because on Cloudflare the request URI is
/// absolute and `Host` may be absent, while on native HTTP/1.1 `Host` is
/// required and HTTP/2 puts the authority in the URI. `None` is a
/// request whose host cannot be established at all.
fn own_host<'a>(headers: &'a HeaderMap, uri: &'a Uri) -> Option<&'a str> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|host| !host.is_empty())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
}

/// The host part of an authority: the authority with any port removed.
/// A bracketed IPv6 host keeps its colons, so the split looks for the
/// closing bracket before it looks for the last colon.
fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return match rest.find(']') {
            Some(close) => &authority[..=close + 1],
            None => authority,
        };
    }
    match authority.rsplit_once(':') {
        Some((host, _port)) => host,
        None => authority,
    }
}

/// The loopback names `http` is accepted on: local development, where
/// https does not reach. Case-insensitive, like any host name.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host.eq_ignore_ascii_case("[::1]")
}

/// The authority with the scheme's default port removed, so
/// `example.com:443` compares equal to `example.com` under https. An
/// authority ending in `]` is a bracketed host with no port.
fn without_default_port<'a>(authority: &'a str, scheme: &str) -> &'a str {
    let default = match scheme {
        "https" => "443",
        "http" => "80",
        _ => return authority,
    };
    if authority.ends_with(']') {
        return authority;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port == default => host,
        _ => authority,
    }
}

/// Whether the origin's authority and the host the request reached name
/// the same thing: default ports normalised away, host case ignored.
fn same_authority(origin_authority: &str, own_host: &str, scheme: &str) -> bool {
    without_default_port(origin_authority, scheme)
        .eq_ignore_ascii_case(without_default_port(own_host, scheme))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).expect("header name builds"),
                header::HeaderValue::from_str(value).expect("header value builds"),
            );
        }
        headers
    }

    fn opaque_header(name: &str, bytes: &[u8]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).expect("header name builds"),
            header::HeaderValue::from_bytes(bytes).expect("opaque value builds"),
        );
        headers
    }

    fn uri_of(uri: &str) -> Uri {
        uri.parse().expect("uri parses")
    }

    #[test]
    fn a_request_carrying_neither_browser_header_is_accepted() {
        // curl, server-to-server: no `sec-fetch-site`, no `origin`.
        assert!(require_same_origin(&headers_with(&[]), &uri_of("/login")).is_ok());
    }

    #[test]
    fn same_origin_and_none_fetch_metadata_are_accepted() {
        for value in ["same-origin", "none"] {
            let headers = headers_with(&[("sec-fetch-site", value)]);
            assert!(
                require_same_origin(&headers, &uri_of("/login")).is_ok(),
                "{value} should pass"
            );
        }
    }

    #[test]
    fn cross_site_fetch_metadata_is_refused_with_the_signal_named() {
        let headers = headers_with(&[("sec-fetch-site", "cross-site")]);
        let problem =
            require_same_origin(&headers, &uri_of("/login")).expect_err("cross-site is refused");
        assert_eq!(problem.slug, "auth/cross-site-request");
        assert_eq!(problem.status, StatusCode::FORBIDDEN);
        let detail = problem.detail.expect("a detail naming the signal");
        assert!(detail.contains("sec-fetch-site"), "{detail}");
    }

    /// The subdomain case: `same-site` covers a sibling subdomain, and a
    /// sibling subdomain can post a `__Host-` cookie onto us from a
    /// cross-origin form — so "same site" is not good enough.
    #[test]
    fn same_site_fetch_metadata_is_refused_too() {
        let headers = headers_with(&[("sec-fetch-site", "same-site")]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_err());
    }

    #[test]
    fn an_unrecognised_fetch_metadata_value_is_refused() {
        // `Same-Site` shows the case normalisation does not turn a
        // refusal into an acceptance.
        for value in ["Same-Site", "garbage", ""] {
            let headers = headers_with(&[("sec-fetch-site", value)]);
            assert!(
                require_same_origin(&headers, &uri_of("/login")).is_err(),
                "{value:?} should be refused"
            );
        }
    }

    #[test]
    fn fetch_metadata_that_is_not_valid_utf8_is_refused() {
        let headers = opaque_header("sec-fetch-site", &[0xFF]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_err());
    }

    #[test]
    fn a_matching_origin_is_accepted() {
        let headers = headers_with(&[("host", "example.com"), ("origin", "https://example.com")]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_ok());
    }

    #[test]
    fn a_matching_origin_with_an_explicit_port_is_accepted() {
        let headers = headers_with(&[
            ("host", "example.com:8443"),
            ("origin", "https://example.com:8443"),
        ]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_ok());
    }

    #[test]
    fn host_letter_case_does_not_matter() {
        let headers = headers_with(&[("host", "EXAMPLE.COM"), ("origin", "https://example.com")]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_ok());
    }

    #[test]
    fn the_default_port_normalises_away_on_both_sides() {
        let host_443 = headers_with(&[
            ("host", "example.com:443"),
            ("origin", "https://example.com"),
        ]);
        assert!(require_same_origin(&host_443, &uri_of("/login")).is_ok());
        let origin_443 = headers_with(&[
            ("host", "example.com"),
            ("origin", "https://example.com:443"),
        ]);
        assert!(require_same_origin(&origin_443, &uri_of("/login")).is_ok());
    }

    #[test]
    fn an_origin_whose_host_differs_is_refused() {
        let headers = headers_with(&[
            ("host", "example.com"),
            ("origin", "https://evil.example.net"),
        ]);
        let problem = require_same_origin(&headers, &uri_of("/login"))
            .expect_err("another site's origin is refused");
        assert_eq!(problem.status, StatusCode::FORBIDDEN);
        let detail = problem.detail.expect("a detail naming the signal");
        assert!(detail.contains("origin"), "{detail}");
    }

    #[test]
    fn a_null_origin_is_refused() {
        // Sandboxed iframe, or a redirect chain the browser declines to
        // attribute.
        let headers = headers_with(&[("host", "example.com"), ("origin", "null")]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_err());
    }

    #[test]
    fn an_origin_without_a_scheme_is_refused() {
        let headers = headers_with(&[("host", "example.com"), ("origin", "example.com")]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_err());
    }

    #[test]
    fn an_origin_that_is_not_valid_utf8_is_refused() {
        let headers = opaque_header("origin", &[0xFF]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_err());
    }

    #[test]
    fn an_origin_is_checked_against_the_uri_authority_when_host_is_absent() {
        // The Cloudflare shape: the request URI is absolute, `Host` may
        // not be sent.
        let headers = headers_with(&[("origin", "https://example.com")]);
        assert!(require_same_origin(&headers, &uri_of("https://example.com/login")).is_ok());
    }

    #[test]
    fn an_origin_with_no_host_at_all_to_check_against_is_refused() {
        // A relative URI and no `Host` header: the claim cannot be
        // checked, so it is not accepted.
        let headers = headers_with(&[("origin", "https://example.com")]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_err());
    }

    #[test]
    fn an_empty_host_header_falls_through_to_the_uri_authority() {
        let headers = headers_with(&[("host", ""), ("origin", "https://example.com")]);
        assert!(require_same_origin(&headers, &uri_of("https://example.com/login")).is_ok());
    }

    #[test]
    fn http_is_accepted_on_a_loopback_host_only() {
        for (host, origin) in [
            ("localhost:8788", "http://localhost:8788"),
            ("127.0.0.1:8788", "http://127.0.0.1:8788"),
            ("[::1]:8788", "http://[::1]:8788"),
        ] {
            let headers = headers_with(&[("host", host), ("origin", origin)]);
            assert!(
                require_same_origin(&headers, &uri_of("/login")).is_ok(),
                "{origin} against {host} should pass"
            );
        }
        // Anywhere https reaches, plain http is not an origin we accept.
        let headers = headers_with(&[("host", "example.com"), ("origin", "http://example.com")]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_err());
    }

    #[test]
    fn passing_fetch_metadata_still_leaves_the_origin_checked() {
        let headers = headers_with(&[
            ("host", "example.com"),
            ("origin", "https://evil.example.net"),
            ("sec-fetch-site", "same-origin"),
        ]);
        assert!(require_same_origin(&headers, &uri_of("/login")).is_err());
    }
}
