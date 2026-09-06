//! `factory0-adapter-resend`: the [`Mailer`] port over the Resend REST API
//! (issue #6). Uses the runtime's [`HttpClient`] port — no `reqwest`, no
//! vendor SDK — so the same adapter runs on Workers and natively.
//!
//! **Degraded mode.** The Resend account has no verified domain yet; until
//! `send.<domain>` is verified, real sends 403. When the API key is absent
//! the adapter reports [`SendOutcome::NotConfigured`] without any network
//! call, so forms keep working.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use factory0_core::{HttpClient, HttpError, MailError, Mailer, Message, SendOutcome};
use http::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use http::{Request, StatusCode};
use std::sync::Arc;
use std::time::Duration;

const RESEND_ENDPOINT: &str = "https://api.resend.com/emails";

/// `Mailer` over `POST https://api.resend.com/emails`.
pub struct Resend {
    http: Arc<dyn HttpClient>,
    api_key: Option<String>,
    from: String,
    reply_to: Option<String>,
}

impl Resend {
    /// `api_key: None` => the adapter is `NotConfigured` (no network).
    pub fn new(
        http: Arc<dyn HttpClient>,
        api_key: Option<String>,
        from: impl Into<String>,
        reply_to: Option<String>,
    ) -> Self {
        Self {
            http,
            api_key,
            from: from.into(),
            reply_to,
        }
    }

    /// Reads `RESEND_API_KEY`, `MAIL_FROM`, `MAIL_REPLY_TO` from the process
    /// environment. On Workers the venture should read the secrets from its
    /// `Env` and use [`Resend::new`] instead (`std::env` has no Workers vars).
    pub fn from_env(http: Arc<dyn HttpClient>) -> Self {
        Self::new(
            http,
            std::env::var("RESEND_API_KEY").ok(),
            std::env::var("MAIL_FROM").unwrap_or_else(|_| String::new()),
            std::env::var("MAIL_REPLY_TO").ok(),
        )
    }
}

#[derive(serde::Serialize)]
struct OutboundEmail<'a> {
    from: &'a str,
    to: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<&'a str>,
    subject: &'a str,
    html: &'a str,
    text: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    tags: &'a [String],
}

#[derive(serde::Deserialize)]
struct SendResponse {
    #[serde(default)]
    id: String,
}

#[derive(serde::Deserialize)]
struct ErrorResponse {
    #[serde(default)]
    message: String,
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    value.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Pulls the sending domain out of a Resend error message like
/// "Domain send.factory0.ventures is not verified" — the first
/// dot-separated token, otherwise the whole sanitized message.
fn extract_domain(message: &str) -> String {
    message
        .split_whitespace()
        .find(|token| token.contains('.') && !token.starts_with('"'))
        .unwrap_or(message)
        .trim_matches(['"', '.', ','])
        .to_string()
}

impl Resend {
    fn map_status(status: StatusCode, body: &str, retry_after: Option<Duration>) -> MailError {
        let detail = match serde_json::from_str::<ErrorResponse>(body) {
            Ok(parsed) => parsed.message,
            Err(_) => body.to_string(),
        };
        match status {
            StatusCode::UNAUTHORIZED => MailError::Unauthorized,
            StatusCode::FORBIDDEN => {
                let lowered = detail.to_ascii_lowercase();
                if lowered.contains("verify") || lowered.contains("domain") {
                    MailError::DomainNotVerified {
                        domain: extract_domain(&detail),
                    }
                } else {
                    MailError::Unauthorized
                }
            }
            StatusCode::UNPROCESSABLE_ENTITY => MailError::Invalid { detail },
            StatusCode::TOO_MANY_REQUESTS => MailError::RateLimited { retry_after },
            status if status.is_server_error() => MailError::Upstream(status.to_string()),
            status => MailError::Upstream(format!("unexpected status {status}: {detail}")),
        }
    }
}

#[async_trait]
impl Mailer for Resend {
    async fn send(&self, message: Message) -> Result<SendOutcome, MailError> {
        // Outcome logging per issue #14: provider, code, idempotency key;
        // the recipient is never logged.
        let Some(api_key) = &self.api_key else {
            tracing::info!(
                provider = "resend",
                outcome = "not_configured",
                idempotency = message.idempotency_key.as_deref().unwrap_or(""),
                "mailer outcome"
            );
            return Ok(SendOutcome::NotConfigured);
        };

        let from = if message.from.is_empty() {
            self.from.as_str()
        } else {
            message.from.as_str()
        };
        let reply_to = message.reply_to.as_deref().or(self.reply_to.as_deref());

        let payload = OutboundEmail {
            from,
            to: &message.to,
            reply_to,
            subject: &message.subject,
            html: &message.html,
            text: &message.text,
            tags: &message.tags,
        };
        let body =
            serde_json::to_vec(&payload).map_err(|err| MailError::Transport(err.to_string()))?;

        let mut builder = Request::builder()
            .method(http::Method::POST)
            .uri(RESEND_ENDPOINT)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {api_key}"));
        if let Some(key) = &message.idempotency_key {
            builder = builder.header("Idempotency-Key", key);
        }
        let request = builder
            .body(Bytes::from(body))
            .map_err(|err| MailError::Transport(err.to_string()))?;

        let response = self
            .http
            .send(request)
            .await
            .map_err(|err: HttpError| MailError::Transport(err.to_string()))?;

        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after);
        let text = String::from_utf8_lossy(response.body()).to_string();

        if status.is_success() {
            let parsed: SendResponse =
                serde_json::from_str(&text).map_err(|err| MailError::Transport(err.to_string()))?;
            tracing::info!(
                provider = "resend",
                code = status.as_u16(),
                outcome = "sent",
                idempotency = message.idempotency_key.as_deref().unwrap_or(""),
                "mailer outcome"
            );
            return Ok(SendOutcome::Sent { id: parsed.id });
        }
        let error = Self::map_status(status, &text, retry_after);
        tracing::warn!(
            provider = "resend",
            code = status.as_u16(),
            outcome = "failed",
            idempotency = message.idempotency_key.as_deref().unwrap_or(""),
            error = %error,
            "mailer outcome"
        );
        Err(error)
    }
}
