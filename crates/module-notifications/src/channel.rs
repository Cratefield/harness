//! The seam a pluggable delivery channel registers through (issue #764):
//! one trait, the message it is handed, and the errors its delivery can
//! answer with.
//!
//! Push and email are built in: their transports are ports (`Push`,
//! `Mailer`) and their recipients live in this module's own tables. A
//! channel like Telegram is neither — its credentials belong to the crate
//! that implements them — so the venture hands the module a [`Channel`]
//! instead, and the module does for it exactly what it does for mail: gate
//! it on the account's preference, queue it in the outbox so it commits
//! atomically with the state change that caused it, re-check the gates at
//! send time, retry what `Transient` and dead-letter what is not.

use std::time::Duration;

use async_trait::async_trait;

use cratefield_core::Database;

/// One notification, as an extra [`Channel`] delivers it: the rendered
/// text, the category it was sent under, and the link a tap opens.
///
/// What it deliberately does not carry is any recipient — no chat id, no
/// bot token. The channel resolves those out of its own tables by the
/// `account_id` its [`Channel::deliver`] is handed, the same way the mail
/// job carries an account and not an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMessage {
    /// The category the notification was sent under — the vocabulary the
    /// account's preferences are written in.
    pub category: String,
    /// The rendered title.
    pub title: String,
    /// The rendered body.
    pub body: String,
    /// Where a tap should take the recipient, when the caller set one.
    pub url: Option<String>,
    /// The id shared by every copy of this notification, stable across
    /// the outbox row's retries — a channel that cannot accept a message
    /// twice dedupes on it, the way mail's idempotency key does.
    pub notification_id: String,
}

/// Why a [`Channel`] could not deliver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// The account cannot be reached on this channel — its linked
    /// credential is gone. Dead-letters rather than retries: only the
    /// account can fix it, by linking again.
    Unreachable,
    /// A permanent refusal. Dead-letters with the message as the reason:
    /// nothing about this notification will ever be accepted.
    Permanent(String),
    /// A transient failure. Retried with backoff, never before the
    /// `retry_after` the channel asked for, to the module's attempt bound.
    Transient { retry_after: Option<Duration> },
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Unreachable => {
                f.write_str("the account is not reachable on this channel")
            }
            ChannelError::Permanent(message) => f.write_str(message),
            ChannelError::Transient { retry_after } => match retry_after {
                Some(after) => write!(f, "transient; retry after {after:?}"),
                None => f.write_str("transient"),
            },
        }
    }
}

impl std::error::Error for ChannelError {}

/// One extra delivery channel, registered next to the built-in push and
/// email through [`crate::Notifications::channel`] (issue #764).
///
/// The module owns everything around the send — preference gates, the
/// outbox, retries, dead letters — and the implementation owns exactly one
/// thing: how a message reaches one account. Its name is written into the
/// outbox payload and matched again in the drain, so it must be stable
/// across deploys.
#[async_trait]
pub trait Channel: Send + Sync + 'static {
    /// The channel's stable, lower-case name — `"telegram"` — as it is
    /// written into outbox payloads and dead-letter reasons. One row per
    /// name: registering two channels with the same name is refused at
    /// composition time.
    fn name(&self) -> &'static str;

    /// Whether this account can be reached on this channel at all — an
    /// account that has linked one, say. Checked when the notification is
    /// enqueued and again immediately before sending: an answer that
    /// changed in between must still win.
    ///
    /// An `Err` is the same as `Ok(false)` for the enqueue decision, and
    /// takes its own outcome in the drain.
    async fn reachable(&self, db: &dyn Database, account_id: &str) -> Result<bool, ChannelError>;

    /// Delivers one message to this account. Called from the drain, once
    /// per outbox row; the outcome decides what happens to the row.
    async fn deliver(
        &self,
        db: &dyn Database,
        account_id: &str,
        message: &ChannelMessage,
    ) -> Result<(), ChannelError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_says_what_a_dead_letter_reason_cannot() {
        assert_eq!(
            ChannelError::Unreachable.to_string(),
            "the account is not reachable on this channel"
        );
        assert_eq!(
            ChannelError::Permanent("telegram 400: chat not found".to_owned()).to_string(),
            "telegram 400: chat not found"
        );
        assert_eq!(
            ChannelError::Transient { retry_after: None }.to_string(),
            "transient"
        );
        assert!(
            ChannelError::Transient {
                retry_after: Some(Duration::from_mins(15))
            }
            .to_string()
            .contains("900"),
            "the delay the channel named is in the text"
        );
    }
}
