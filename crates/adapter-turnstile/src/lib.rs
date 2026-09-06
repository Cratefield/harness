//! `factory0-adapter-turnstile`: the [`Captcha`] port over Cloudflare
//! Turnstile `siteverify` (issue #7). Runs on the runtime's `HttpClient`
//! port; the 5 s timeout is supplied by the runtime's [`Clock`].
//!
//! Fail-closed by default: a transport failure (or timeout) verifies as
//! `{ ok: false, reason: "unavailable" }`. `.fail_open(true)` is for
//! staging only. If the secret is absent, [`Turnstile::from_env`] returns
//! `None` so the port is not provided at all — `fz doctor` then refuses a
//! production build without captcha.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use factory0_core::{Captcha, CaptchaError, Clock, HttpClient, Verdict, timeout};
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
            fail_open: false,
        }
    }

    /// `Some(...)` only when `TURNSTILE_SECRET` is set: an absent secret
    /// means the port is not provided at all.
    pub fn from_env(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Option<Self> {
        std::env::var("TURNSTILE_SECRET")
            .ok()
            .map(|secret| Self::new(http, clock, secret))
    }

    /// Verifies the response hostname against this expectation; a mismatch
    /// fails the verdict with `hostname-mismatch`.
    #[must_use]
    pub fn expected_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.expected_hostname = Some(hostname.into());
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

        if let (Some(expected), Some(actual)) = (&self.expected_hostname, &parsed.hostname)
            && expected != actual
        {
            return Ok(Verdict {
                ok: false,
                reason: Some("hostname-mismatch".to_string()),
            });
        }

        Ok(Verdict {
            ok: true,
            reason: None,
        })
    }
}
