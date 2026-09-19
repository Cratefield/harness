//! The `Tracker` port (issue #432): filing a ticket with an issue tracker —
//! GitHub Issues today, a plain webhook next. Mail reaches an inbox through
//! [`Mailer`](crate::Mailer); nothing reached a project's tracker until this
//! (ADR 0002: modules see this trait and never a vendor client). The
//! reference adapter is `cratefield-adapter-github-issues`.
//!
//! The outbox is at-least-once, so `file` **will** be called twice for one
//! [`TicketDraft`]. The port therefore carries an idempotency key, and the
//! adapter contract is that a repeat file reports the *existing* ticket —
//! `Filed` with `deduplicated` set — rather than filing a duplicate.
//!
//! Deliberately not yet a [`crate::Port`]: the `ports!` list, `Ports`,
//! `view_for` and both runtimes are left to the port's own PR, so sibling
//! branches carrying the adapters do not collide on the same lines.

use async_trait::async_trait;
use std::time::Duration;

/// Where a filed ticket goes. One variant per tracker, because they do not
/// share a shape: GitHub Issues addresses a repository, a webhook is a URL
/// the ticket is posted to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Destination {
    /// The GitHub issue tracker of `owner`'s `repo`.
    GitHubIssues { owner: String, repo: String },
    /// A webhook endpoint that accepts the ticket.
    Webhook { url: String },
}

/// A ticket to file.
///
/// `#[non_exhaustive]`: build one with [`TicketDraft::new`] and the builder
/// methods rather than a struct literal, the way [`Message`](crate::Message)
/// works — a field an adapter later needs must not be a breaking change for
/// every caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TicketDraft {
    pub title: String,
    pub body: String,
    /// Labels for the tracker (GitHub labels; webhook metadata).
    pub labels: Vec<String>,
    /// Collapses the retries the at-least-once outbox guarantees into one
    /// ticket: an adapter must find the ticket a previous `file` created and
    /// report it rather than file a duplicate.
    pub idempotency_key: String,
    pub destination: Destination,
}

impl TicketDraft {
    /// The parts no ticket makes sense without. The idempotency key is one
    /// of them, not a builder afterthought: dedup is what the outbox needs
    /// from it, and a draft without a key would file a duplicate on every
    /// retry instead.
    #[must_use]
    pub fn new(
        title: impl Into<String>,
        body: impl Into<String>,
        destination: Destination,
        idempotency_key: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            labels: Vec::new(),
            idempotency_key: idempotency_key.into(),
            destination,
        }
    }

    /// Labels for the tracker. Repeatable in meaning; one call carries them all.
    #[must_use]
    pub fn labels<I, T>(mut self, labels: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.labels = labels.into_iter().map(Into::into).collect();
        self
    }
}

/// A ticket the tracker accepted — created by this call, or found from an
/// earlier attempt at the same idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filed {
    /// The tracker-side id (a GitHub issue number, say).
    pub id: String,
    /// The tracker's own URL for the ticket, where it has one.
    pub url: Option<String>,
    /// `true` when nothing was created because a ticket with this
    /// idempotency key already existed — the at-least-once outbox calling
    /// `file` twice, answered once.
    pub deduplicated: bool,
}

impl Filed {
    /// A ticket created by this call.
    #[must_use]
    pub fn created(id: impl Into<String>, url: Option<String>) -> Self {
        Self {
            id: id.into(),
            url,
            deduplicated: false,
        }
    }

    /// A ticket found from an earlier attempt at the same key.
    #[must_use]
    pub fn existing(id: impl Into<String>, url: Option<String>) -> Self {
        Self {
            id: id.into(),
            url,
            deduplicated: true,
        }
    }
}

/// Tracker failures, mapped by the adapter from the provider's response.
///
/// The variants that carry provider text are sanitized in `Display`, the
/// same way [`DbError`](crate::DbError)'s, [`MailError`](crate::MailError)'s
/// and [`PushError`](crate::PushError)'s are (issue #235). What an adapter
/// wraps is the provider's own words, and a repository or ticket title is
/// exactly the kind of value that can ride in them. `Display` therefore runs
/// the text through [`crate::logging::scrub_text`], so every `tracing`
/// field, problem detail and `format!` that renders a `TrackerError` gets
/// the sanitized text rather than each call site remembering to. `Debug`
/// still shows the raw string for tests; the logging formatters scrub `{:?}`
/// output too.
///
/// Like those two, this error does **not** derive `thiserror::Error`:
/// `Display` is hand-written so the sanitizer cannot be bypassed by a
/// derived message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackerError {
    /// The token is missing, wrong or revoked. Retrying will not fix it.
    Unauthorized,
    /// The tracker refused the ticket itself (a `4xx`: the repository is
    /// gone or invisible to the token, a validation failure); not retryable
    /// without a change. `detail` is **the provider's** wording — see the
    /// type docs.
    Rejected(String),
    /// A transient failure (a `429`, a `5xx`, a transport error): retry
    /// later, and not before `retry_after` when the provider named one.
    Transient {
        message: String,
        retry_after: Option<Duration>,
    },
}

impl std::fmt::Display for TrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::Unauthorized => {
                f.write_str("tracker rejected the request as unauthorized (check the token)")
            }
            Self::Rejected(detail) => {
                write!(f, "tracker rejected the ticket: {}", scrub(detail))
            }
            Self::Transient { message, .. } => {
                write!(f, "tracker failed, retryable: {}", scrub(message))
            }
        }
    }
}

impl std::error::Error for TrackerError {}

impl TrackerError {
    /// A retryable failure with no provider-supplied delay.
    pub fn transient(message: impl Into<String>) -> Self {
        TrackerError::Transient {
            message: message.into(),
            retry_after: None,
        }
    }

    /// A retryable failure the provider asked us to hold off on.
    pub fn transient_after(message: impl Into<String>, retry_after: Option<Duration>) -> Self {
        TrackerError::Transient {
            message: message.into(),
            retry_after,
        }
    }

    /// How long the provider asked the caller to wait, where it said.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            TrackerError::Transient { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// Files a ticket with an issue tracker. An adapter serves one
/// [`Destination`] kind and returns [`TrackerError::Rejected`] for the rest;
/// a venture that files across destinations puts a router in front (the
/// [`RoutingPush`](crate::RoutingPush) pattern).
#[async_trait]
pub trait Tracker: Send + Sync {
    /// Files `draft`, or finds and reports the ticket an earlier attempt
    /// already filed for the same idempotency key.
    ///
    /// # Errors
    ///
    /// [`TrackerError::Unauthorized`] when the token is wrong;
    /// [`TrackerError::Rejected`] when the tracker (or this adapter, for a
    /// destination it does not serve) refuses the draft and retrying will
    /// not help; [`TrackerError::Transient`] when the call may be retried
    /// after `retry_after`, if one was named.
    async fn file(&self, draft: &TicketDraft) -> Result<Filed, TrackerError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_sanitizes_the_provider_text() {
        // The issue #235 convention: the text an adapter wraps is the
        // provider's own words, and a query string in one is a leaked
        // credential. `Rejected` and `Transient` both carry it.
        let error = TrackerError::Rejected(
            "github issues 422 for https://github.example/acme/widgets?token=abc123".to_owned(),
        );
        let text = error.to_string();
        assert!(!text.contains("abc123"), "{text}");
        assert!(text.contains("?[redacted]"), "{text}");

        let error = TrackerError::transient("github issues 503 for alice@example.test");
        let text = error.to_string();
        assert!(!text.contains('@'), "{text}");
        assert!(text.contains("[subject_hash:"), "{text}");

        assert_eq!(
            TrackerError::Unauthorized.to_string(),
            "tracker rejected the request as unauthorized (check the token)"
        );

        // `Debug` still shows the raw string, which is what a failing test
        // needs to be readable; the log formatters scrub `{:?}` output too.
        assert!(format!("{error:?}").contains("alice@example.test"));
    }

    #[test]
    fn a_draft_builds_and_files_read_back() {
        let draft = TicketDraft::new(
            "Outbox: refund failed",
            "The refund webhook failed twice.",
            Destination::GitHubIssues {
                owner: "acme".to_owned(),
                repo: "widgets".to_owned(),
            },
            "idem-123",
        )
        .labels(["from-outbox", "billing"]);
        assert_eq!(draft.title, "Outbox: refund failed");
        assert_eq!(draft.labels, ["from-outbox", "billing"]);
        assert_eq!(draft.idempotency_key, "idem-123");

        // The two ways a `file` answers.
        assert!(!Filed::created("11", None).deduplicated);
        assert!(Filed::existing("11", None).deduplicated);
    }
}
