//! The `Mailer` port (architecture section 5). The Resend adapter is the
//! reference implementation (issue #6).

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// An outbound mail. `text` is always sent alongside `html`.
///
/// `#[non_exhaustive]`: build one with [`Message::new`] and the builder
/// methods rather than a struct literal. A channel that has to set a
/// header — RFC 8058 one-click unsubscribe, say — should not be a
/// breaking change for every other caller, and before this it was.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// Extra RFC 5322 headers, in order.
    ///
    /// For headers the shape of `Message` does not name and should not:
    /// `List-Unsubscribe` and `List-Unsubscribe-Post` are the reason this
    /// exists, because Gmail and Yahoo have required one-click
    /// unsubscribe of bulk senders since 2024. An adapter that cannot
    /// send custom headers must say so rather than drop them silently.
    pub headers: Vec<(String, String)>,
}

impl Message {
    /// The five parts every mail has. Everything else is a builder method.
    #[must_use]
    pub fn new(
        to: impl Into<String>,
        from: impl Into<String>,
        subject: impl Into<String>,
        text: impl Into<String>,
        html: impl Into<String>,
    ) -> Self {
        Self {
            to: to.into(),
            from: from.into(),
            reply_to: None,
            subject: subject.into(),
            html: html.into(),
            text: text.into(),
            idempotency_key: None,
            tags: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Where a reply goes, when it is not `from`.
    #[must_use]
    pub fn reply_to(mut self, address: impl Into<String>) -> Self {
        self.reply_to = Some(address.into());
        self
    }

    /// The key a provider that supports it uses to collapse a retry.
    #[must_use]
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// Labels for the provider's own reporting.
    #[must_use]
    pub fn tags<I, T>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// One extra RFC 5322 header. Repeatable; order is preserved.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
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
