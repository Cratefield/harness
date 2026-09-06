//! The `Captcha` port. The Turnstile adapter is the reference
//! implementation (issue #7).

use async_trait::async_trait;
use thiserror::Error;

/// A captcha verification verdict. `ok: false` with a `reason` from the
/// provider's `error-codes`; transport-level unavailability surfaces as
/// `ok: false, reason: "unavailable"` unless the adapter is configured
/// fail-open (staging only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub ok: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Error)]
pub enum CaptchaError {
    #[error("captcha transport error: {0}")]
    Transport(String),
}

#[async_trait]
pub trait Captcha: Send + Sync {
    async fn verify(&self, token: &str, remote_ip: Option<&str>) -> Result<Verdict, CaptchaError>;
}
