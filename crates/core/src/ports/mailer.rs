//! The `Mailer` port (architecture section 5). The Resend adapter is the
//! reference implementation (issue #6).

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// An outbound mail. `text` is always sent alongside `html`.
#[derive(Debug, Clone)]
pub struct Message {
    pub to: String,
    pub from: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub html: String,
    pub text: String,
    /// Passed through as an `Idempotency-Key` where the provider supports it.
    pub idempotency_key: Option<String>,
    pub tags: Vec<String>,
}

/// Result of a send attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Sent; carries the provider message id.
    Sent { id: String },
    /// The adapter is not configured (no API key / unverified sending
    /// domain). The endpoint reports `503 mail-not-configured` so forms can
    /// degrade instead of breaking.
    NotConfigured,
}

/// Mailer failures, mapped by the adapter from provider responses.
///
/// `Display` output is safe for logs: it never includes the API key.
#[derive(Debug, Clone, Error)]
pub enum MailError {
    #[error("mailer rejected the request as unauthorized (check the API key)")]
    Unauthorized,
    #[error("sending domain {domain:?} is not verified with the mailer")]
    DomainNotVerified { domain: String },
    #[error("mailer rejected the message as invalid: {detail}")]
    Invalid { detail: String },
    #[error("mailer rate limited the request; retry after {retry_after:?}")]
    RateLimited { retry_after: Option<Duration> },
    #[error("mailer upstream error: {0}")]
    Upstream(String),
    #[error("mailer transport error: {0}")]
    Transport(String),
}

#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, message: Message) -> Result<SendOutcome, MailError>;
}
