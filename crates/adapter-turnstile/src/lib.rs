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
        let mut form = format!("secret={}&response={}", self.secret, token);
        if let Some(ip) = remote_ip {
            form = format!("{form}&remoteip={ip}");
        }
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
