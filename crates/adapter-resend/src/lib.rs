//! `cratefield-adapter-resend`: the [`Mailer`] port over the Resend REST API
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
use cratefield_core::{
    Clock, HttpClient, HttpError, MailError, Mailer, Message, SendOutcome, retry_after,
};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const RESEND_ENDPOINT: &str = "https://api.resend.com/emails";

/// `Mailer` over `POST https://api.resend.com/emails`.
pub struct Resend {
    http: Arc<dyn HttpClient>,
    /// Needed only to read the HTTP-date form of `Retry-After` (issue #278).
    /// A constructor argument rather than a builder default so a deployment
    /// that forgets it fails to compile instead of silently retrying a
    /// date-form 429 immediately.
    clock: Arc<dyn Clock>,
    api_key: Option<String>,
    from: String,
    reply_to: Option<String>,
}

impl Resend {
    /// `api_key: None` => the adapter is `NotConfigured` (no network).
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        api_key: Option<String>,
        from: impl Into<String>,
        reply_to: Option<String>,
    ) -> Self {
        Self {
            http,
            clock,
            api_key,
            from: from.into(),
            reply_to,
        }
    }

    /// Reads `RESEND_API_KEY`, `MAIL_FROM`, `MAIL_REPLY_TO` from the process
    /// environment. On Workers the venture should read the secrets from its
    /// `Env` and use [`Resend::new`] instead (`std::env` has no Workers vars).
    pub fn from_env(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self::new(
            http,
            clock,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<ResendTag>,
    /// Extra RFC 5322 headers. Resend takes them as a JSON object, so a
    /// repeated header name would silently collapse — the harness sends
    /// each name once, and `List-Unsubscribe` is one value by RFC 8058.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    headers: BTreeMap<&'a str, &'a str>,
}

/// Resend requires each tag to be a `{ name, value }` object whose fields
/// contain only ASCII letters, digits, `_` or `-`; a bare string array is
/// rejected with `422 Invalid input`. A harness tag is a single label, so it
/// becomes the `name` (sanitised) with a constant `value`.
#[derive(serde::Serialize)]
struct ResendTag {
    name: String,
    value: &'static str,
}

fn resend_tags(tags: &[String]) -> Vec<ResendTag> {
    tags.iter()
        .map(|tag| ResendTag {
            name: sanitize_tag(tag),
            value: "1",
        })
        .collect()
}

/// Keeps only Resend's allowed tag characters (ASCII letters, digits, `_`,
/// `-`), mapping anything else to `_`, and never emits an empty name.
fn sanitize_tag(tag: &str) -> String {
    let cleaned: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "tag".to_owned()
    } else {
        cleaned
    }
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
            tags: resend_tags(&message.tags),
            headers: message
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect(),
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
        // One parser for both `Retry-After` forms (issue #214/#278); the
        // date form needs the clock this adapter is constructed with.
        let retry_after = retry_after(response.headers(), self.clock.as_ref());
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
