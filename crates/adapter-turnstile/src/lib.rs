//! `cratefield-adapter-turnstile`: the [`Captcha`] port over Cloudflare
//! Turnstile `siteverify` (issue #7). Runs on the runtime's `HttpClient`
//! port; the 5 s timeout is supplied by the runtime's [`Clock`].
//!
//! Fail-closed by default: a transport failure (or timeout) verifies as
//! `{ ok: false, reason: "unavailable" }`. `.fail_open(true)` is for
//! staging only. If the secret is absent, [`Turnstile::from_env`] returns
//! `None` so the port is not provided at all — and `Harness::build` then
//! refuses a production venture with `HumanForm` routes (issue #133).
//!
//! A bound adapter checks what it was bound to: an expected hostname
//! rejects responses from any other site (including a response that omits
//! the hostname), and an expected action rejects a token minted for a
//! different flow. [`Captcha::binding`] reports both, so the harness can
//! tell "port present" from "verification configured".
//!
//! The siteverify form body is fully percent-encoded and the token is
//! shape-checked before anything is sent: a malformed token verifies as
//! `invalid-input-response` locally, with no request at all (issue #436).

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{Captcha, CaptchaBinding, CaptchaError, Clock, HttpClient, Verdict, timeout};
use http::Request;
use std::sync::Arc;
use std::time::Duration;

const SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// `Captcha` over Turnstile siteverify.
pub struct Turnstile {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    secret: String,
    expected_hostname: Option<String>,
    expected_action: Option<String>,
    fail_open: bool,
}

impl Turnstile {
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        secret: impl Into<String>,
    ) -> Self {
        Self {
            http,
            clock,
            secret: secret.into(),
            expected_hostname: None,
            expected_action: None,
            fail_open: false,
        }
    }

    /// `Some(...)` only when `TURNSTILE_SECRET` is set: an absent secret
    /// means the port is not provided at all. `TURNSTILE_HOSTNAME` and
    /// `TURNSTILE_ACTION` bind the checks when present (issue #133: an
    /// unbound adapter cannot support a production `HumanForm` route).
    pub fn from_env(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Option<Self> {
        let secret = std::env::var("TURNSTILE_SECRET").ok()?;
        let mut turnstile = Self::new(http, clock, secret);
        if let Ok(hostname) = std::env::var("TURNSTILE_HOSTNAME") {
            turnstile = turnstile.expected_hostname(hostname);
        }
        if let Ok(action) = std::env::var("TURNSTILE_ACTION") {
            turnstile = turnstile.expected_action(action);
        }
        Some(turnstile)
    }

    /// Verifies the response hostname against this expectation. A mismatch
    /// — or a response that carries no hostname at all — fails the verdict
    /// with `hostname-mismatch` (issue #133: absent is not "passed").
    #[must_use]
    pub fn expected_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.expected_hostname = Some(hostname.into());
        self
    }

    /// Verifies the response `action` against this expectation, so a token
    /// minted for another flow on the same site does not authorize this
    /// one. Mismatch or absence fails the verdict with `action-mismatch`.
    #[must_use]
    pub fn expected_action(mut self, action: impl Into<String>) -> Self {
        self.expected_action = Some(action.into());
        self
    }

    /// Transport failures verify as OK. **Staging only** — production is
    /// fail-closed (architecture section 11).
    #[must_use]
    pub fn fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }

    fn transport_verdict(&self) -> Verdict {
        Verdict {
            ok: self.fail_open,
            reason: if self.fail_open {
                None
            } else {
                Some("unavailable".to_string())
            },
        }
    }
}

/// Turnstile tokens are ASCII `[A-Za-z0-9._-]`, bounded in length; a
/// value outside that shape is not a token this adapter will carry.
const MAX_TOKEN_LEN: usize = 2048;

/// True when `token` matches `[A-Za-z0-9._-]{1,2048}`. The check runs
/// before anything is built or sent, so an attacker-supplied token is
/// never passed on to siteverify at all.
fn is_plausible_token(token: &str) -> bool {
    let len = token.len();
    if len == 0 || len > MAX_TOKEN_LEN {
        return false;
    }
    token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

// Duplicated from the Stripe adapter (`crates/adapter-stripe`) rather than
// shared: a dependency edge between two adapters (or a new public helper
// in `cratefield-core`) costs more than a fifteen-line copy, so issue #436
// chose the local copy.
/// Percent-encodes for `application/x-www-form-urlencoded`: unreserved bytes
/// pass through, everything else (space included, as `%20`) is escaped.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

/// Builds the siteverify form body with every field percent-encoded.
/// `token` arrives from the untrusted request body and `remote_ip` from
/// request headers, so an unencoded `&` or `=` would inject an extra
/// parameter into the verification request (issue #436).
fn encode_form(secret: &str, token: &str, remote_ip: Option<&str>) -> String {
    let mut form = format!(
        "secret={}&response={}",
        percent_encode(secret),
        percent_encode(token)
    );
    if let Some(ip) = remote_ip {
        form.push_str("&remoteip=");
        form.push_str(&percent_encode(ip));
    }
    form
}

#[derive(serde::Deserialize)]
struct SiteverifyResponse {
    #[serde(default)]
    success: bool,
    #[serde(rename = "error-codes", default)]
    error_codes: Vec<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    action: Option<String>,
}

#[async_trait]
impl Captcha for Turnstile {
    async fn verify(&self, token: &str, remote_ip: Option<&str>) -> Result<Verdict, CaptchaError> {
        // A malformed token is refused before anything is built or sent.
        // This refusal is unconditional: `fail_open` exists for transport
        // and availability failures, not for a syntactically invalid
        // token — a fail-open adapter must not wave one through to a
        // provider that could be tricked by it (issue #436).
        if !is_plausible_token(token) {
            tracing::warn!("refusing malformed turnstile token");
            return Ok(Verdict {
                ok: false,
                reason: Some("invalid-input-response".to_string()),
            });
        }
        let form = encode_form(&self.secret, token, remote_ip);
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(SITEVERIFY_URL)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Bytes::from(form))
            .map_err(|err| CaptchaError::Transport(err.to_string()))?;

        let http = Arc::clone(&self.http);
        let Some(response) = timeout(
            self.clock.as_ref(),
            async move { http.send(request).await },
            VERIFY_TIMEOUT,
        )
        .await
        else {
            return Ok(self.transport_verdict());
        };
        // Transport errors surface as the (fail-closed) verdict; the
        // error itself is logged, never propagated to the module.
        let Ok(response) = response else {
            tracing::warn!("siteverify transport failure");
            return Ok(self.transport_verdict());
        };

        let status = response.status();
        let body = String::from_utf8_lossy(response.body()).to_string();
        if !status.is_success() {
            tracing::warn!(status = %status, "siteverify returned non-success");
            return Ok(self.transport_verdict());
        }

        let parsed: SiteverifyResponse =
            serde_json::from_str(&body).map_err(|err| CaptchaError::Transport(err.to_string()))?;

        if !parsed.success {
            return Ok(Verdict {
                ok: false,
                reason: parsed.error_codes.into_iter().next(),
            });
        }

        // A bound check that the provider did not answer is a mismatch:
        // absent hostname/action means the widget was not bound as this
        // deployment requires (issue #133).
        if let Some(expected) = &self.expected_hostname
            && parsed
                .hostname
                .as_deref()
                .is_none_or(|actual| actual != expected)
        {
            return Ok(Verdict {
                ok: false,
                reason: Some("hostname-mismatch".to_string()),
            });
        }

        if let Some(expected) = &self.expected_action
            && parsed
                .action
                .as_deref()
                .is_none_or(|actual| actual != expected)
        {
            return Ok(Verdict {
                ok: false,
                reason: Some("action-mismatch".to_string()),
            });
        }

        Ok(Verdict {
            ok: true,
            reason: None,
        })
    }

    fn binding(&self) -> Option<CaptchaBinding> {
        Some(CaptchaBinding {
            hostname_bound: self.expected_hostname.is_some(),
            action_bound: self.expected_action.is_some(),
            fail_open: self.fail_open,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_passes_unreserved_bytes_and_escapes_the_rest() {
        assert_eq!(percent_encode("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("secret&x=1"), "secret%26x%3D1");
        assert_eq!(percent_encode("café"), "caf%C3%A9");
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn a_hostile_token_and_ip_cannot_add_a_form_key() {
        // The injection the issue describes: `&` and `=` in the token (or
        // the header-supplied IP) must arrive as data, not as structure.
        let body = encode_form(
            "secret-value",
            "abc&sitekey=evil&idempotency_key=x",
            Some("1.2.3.4&foo=bar"),
        );
        let mut keys: Vec<&str> = body
            .split('&')
            .map(|pair| pair.split('=').next().expect("a pair always has a key"))
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["remoteip", "response", "secret"]);
        assert!(body.contains("response=abc%26sitekey%3Devil%26idempotency_key%3Dx"));
        assert!(body.contains("remoteip=1.2.3.4%26foo%3Dbar"));
    }

    #[test]
    fn the_secret_is_encoded_too() {
        assert_eq!(
            encode_form("s&ecret=1", "tok", None),
            "secret=s%26ecret%3D1&response=tok"
        );
        assert_eq!(
            encode_form("secret-value", "tok", None),
            "secret=secret-value&response=tok"
        );
    }

    #[test]
    fn tokens_on_the_plausible_shape_pass_the_check() {
        assert!(is_plausible_token("0.z8xQa_7-bBcCdDeE"));
        let exactly_2048 = "a".repeat(MAX_TOKEN_LEN);
        assert!(is_plausible_token(&exactly_2048));
    }

    #[test]
    fn tokens_off_the_plausible_shape_fail_the_check() {
        assert!(!is_plausible_token(""));
        assert!(!is_plausible_token("bad&token"));
        assert!(!is_plausible_token("bad token"));
        assert!(!is_plausible_token("bad;token"));
        assert!(!is_plausible_token("bad/token"));
        assert!(!is_plausible_token("héllo"));
        let one_past_the_ceiling = "a".repeat(MAX_TOKEN_LEN + 1);
        assert!(!is_plausible_token(&one_past_the_ceiling));
    }
}
