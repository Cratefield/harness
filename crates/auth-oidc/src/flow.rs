//! The in-flight authorization, carried in a signed cookie (issue #15).
//!
//! Between `/start` and `/callback` the module has to remember four things:
//! the `state` it will compare, the `nonce` the ID token must echo, the PKCE
//! verifier, and where to send the browser afterwards. They live in a signed
//! cookie rather than a row because they belong to *this browser*: a row
//! keyed by state would be spendable by anyone who saw the state in a
//! redirect chain or a referrer.
//!
//! The expiry is inside the signed payload and checked against the `Clock`
//! port, not through the signer's own `exp`, which reads the wall clock
//! directly and so cannot be driven by a test clock.

use factory0_core::{Clock, Kid, Payload, Signer};
use serde::{Deserialize, Serialize};

/// The signed payload's purpose (ADR 0006), so a flow cookie can never be
/// replayed as any other signed token this service issues.
pub(crate) const PURPOSE: &str = "auth-oidc.flow";

/// `__Host-` so the cookie is origin-locked: no domain, path `/`, secure.
pub(crate) const COOKIE_NAME: &str = "__Host-fz_oidc";

/// How long a person has to finish at the provider. Long enough to create
/// an account or find a second factor, short enough that an abandoned flow
/// does not stay spendable.
pub(crate) const TTL_SECS: i64 = 600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Flow {
    /// Which provider this flow belongs to. Checked at the callback, so a
    /// cookie from one provider cannot complete another's flow.
    pub provider: String,
    pub state: String,
    pub nonce: String,
    /// The PKCE code verifier. It never leaves this cookie and the token
    /// request.
    pub verifier: String,
    /// Where to send the browser afterwards: always a path on this service,
    /// never an absolute URL (see `crate::handlers::safe_return_to`).
    pub return_to: String,
    /// Unix seconds. Checked against the `Clock` port.
    pub expires_at: i64,
}

impl Flow {
    /// Signs the flow into a cookie value.
    pub(crate) fn seal(&self, signer: &dyn Signer) -> String {
        let payload = serde_json::to_string(self).unwrap_or_default();
        signer.sign(&Payload {
            purpose: PURPOSE.to_owned(),
            subject: payload,
            // Deliberately none: `Signer::verify` compares `exp` against the
            // wall clock rather than the Clock port, which would make the
            // expiry untestable and disagree with a test clock. The expiry
            // lives in the payload and is checked below.
            exp: None,
            kid: Kid::Cur,
        })
    }

    /// Recovers a flow from a cookie value, or `None` for anything that is
    /// not a live flow: unsigned, tampered, malformed, expired, or for a
    /// different provider.
    pub(crate) fn open(
        signer: &dyn Signer,
        clock: &dyn Clock,
        provider: &str,
        cookie: &str,
    ) -> Option<Self> {
        let payload = signer.verify(cookie, PURPOSE)?;
        let flow: Flow = serde_json::from_str(&payload.subject).ok()?;
        if flow.provider != provider {
            return None;
        }
        if flow.expires_at <= clock.now().unix_timestamp() {
            return None;
        }
        Some(flow)
    }
}

/// The `Set-Cookie` value that carries a flow.
pub(crate) fn set_cookie(value: &str) -> String {
    // `SameSite=Lax` and not `Strict`: the callback arrives as a top-level
    // navigation from the provider, and `Strict` would withhold the cookie
    // on exactly that request.
    format!("{COOKIE_NAME}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={TTL_SECS}")
}

/// The `Set-Cookie` value that clears it, sent once the flow is spent.
pub(crate) fn clear_cookie() -> String {
    format!(
        "{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0; \
         Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    )
}

/// The flow cookie's value from a `Cookie` header.
pub(crate) fn cookie_value(headers: &http::HeaderMap) -> Option<String> {
    for header in headers.get_all(http::header::COOKIE) {
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
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_core::HmacSigner;

    struct FixedClock(i64);
    impl Clock for FixedClock {
        fn now(&self) -> time::OffsetDateTime {
            time::OffsetDateTime::from_unix_timestamp(self.0).expect("in range")
        }
    }

    fn signer() -> HmacSigner {
        HmacSigner::new("a-test-secret-that-is-long-enough-32", None).expect("a long enough secret")
    }

    fn flow(expires_at: i64) -> Flow {
        Flow {
            provider: "google".to_owned(),
            state: "state-value".to_owned(),
            nonce: "nonce-value".to_owned(),
            verifier: "verifier-value".to_owned(),
            return_to: "/v1/auth-core/authorize?x=1".to_owned(),
            expires_at,
        }
    }

    #[test]
    fn a_flow_round_trips() {
        let signer = signer();
        let sealed = flow(1_000).seal(&signer);
        let opened = Flow::open(&signer, &FixedClock(500), "google", &sealed).expect("opens");
        assert_eq!(opened, flow(1_000));
    }

    #[test]
    fn a_tampered_cookie_is_not_a_flow() {
        let signer = signer();
        let sealed = flow(1_000).seal(&signer);
        let tampered = format!("{}x", &sealed[..sealed.len() - 1]);
        assert_eq!(
            Flow::open(&signer, &FixedClock(500), "google", &tampered),
            None
        );
        assert_eq!(Flow::open(&signer, &FixedClock(500), "google", ""), None);
        assert_eq!(
            Flow::open(&signer, &FixedClock(500), "google", "not.a.token"),
            None
        );
    }

    #[test]
    fn a_flow_expires_against_the_clock_port() {
        let signer = signer();
        let sealed = flow(1_000).seal(&signer);
        assert!(Flow::open(&signer, &FixedClock(999), "google", &sealed).is_some());
        assert_eq!(
            Flow::open(&signer, &FixedClock(1_000), "google", &sealed),
            None
        );
        assert_eq!(
            Flow::open(&signer, &FixedClock(5_000), "google", &sealed),
            None
        );
    }

    #[test]
    fn a_flow_belongs_to_one_provider() {
        let signer = signer();
        let sealed = flow(1_000).seal(&signer);
        assert_eq!(
            Flow::open(&signer, &FixedClock(500), "apple", &sealed),
            None
        );
    }

    #[test]
    fn the_cookie_is_origin_locked_and_survives_the_providers_redirect() {
        let header = set_cookie("value");
        assert!(header.starts_with("__Host-fz_oidc="), "{header}");
        assert!(header.contains("Secure"), "{header}");
        assert!(header.contains("HttpOnly"), "{header}");
        // Lax, not Strict: the callback is a top-level navigation from the
        // provider, and Strict would withhold the cookie on it.
        assert!(header.contains("SameSite=Lax"), "{header}");
        assert!(!header.contains("Domain="), "__Host- forbids a domain");
    }

    #[test]
    fn the_cookie_reads_past_its_neighbours() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "theme=dark; __Host-fz_oidc=abc; other=1"
                .parse()
                .expect("header"),
        );
        assert_eq!(cookie_value(&headers).as_deref(), Some("abc"));
        assert_eq!(cookie_value(&http::HeaderMap::new()), None);
    }
}
