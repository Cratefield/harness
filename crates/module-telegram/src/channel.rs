//! The module as a [`Channel`](cratefield_module_notifications::Channel):
//! notifications that already reach people by Telegram, delivered into
//! the chat the person linked.
//!
//! Gated behind the module's `notifications` feature so a venture that
//! does not use the notifications module pays nothing for it.

use std::sync::Arc;

use cratefield_adapter_telegram::{InlineButton, OutgoingMessage, TelegramBot, TelegramError};
use cratefield_core::Database;
use cratefield_module_notifications::{Channel, ChannelError, ChannelMessage};

use crate::store;

/// Delivers the notifications module's mail into linked Telegram chats.
///
/// `reachable` asks the same question every send does — has this subject
/// linked an account? — so a subject without a link is skipped by the
/// fan-out rather than fumbled per notification. `deliver` writes
/// nothing: the channel is transport, and the notifications module owns
/// the record of what was sent.
pub struct TelegramChannel {
    bot: Arc<dyn TelegramBot>,
}

impl TelegramChannel {
    /// A channel over the given bot — the same [`TelegramBot`] the
    /// module was composed with, so tests can substitute the adapter's
    /// fake.
    #[must_use]
    pub fn new(bot: Arc<dyn TelegramBot>) -> Self {
        Self { bot }
    }
}

/// Every Telegram refusal maps to the channel error that says what a
/// retry is worth: `Forbidden` means the chat is gone for good —
/// `Unreachable` — while rate limits and 5xx are worth waiting out, and
/// a bad token (`Unauthorized`) or a refused request (`Invalid`) is
/// nobody's retry to win.
fn map_error(error: &TelegramError) -> ChannelError {
    match error {
        TelegramError::Forbidden(_) => ChannelError::Unreachable,
        TelegramError::RateLimited { retry_after } => ChannelError::Transient {
            retry_after: Some(*retry_after),
        },
        TelegramError::Transient(_) => ChannelError::Transient { retry_after: None },
        TelegramError::Unauthorized | TelegramError::Invalid(_) => {
            ChannelError::Permanent(error.to_string())
        }
    }
}

#[async_trait::async_trait]
impl Channel for TelegramChannel {
    fn name(&self) -> &'static str {
        crate::MODULE_NAME
    }

    /// Whether `account_id` has a linked Telegram chat to receive in.
    ///
    /// # Errors
    /// A failed database read is [`ChannelError::Transient`] — the link
    /// table is fine, the question just went unanswered.
    async fn reachable(&self, db: &dyn Database, account_id: &str) -> Result<bool, ChannelError> {
        store::link_of_subject(db, account_id)
            .await
            .map(|link| link.is_some())
            .map_err(|_| ChannelError::Transient { retry_after: None })
    }

    /// Sends `message`'s title and body into the subject's linked chat,
    /// with a URL button when the notification carries a link.
    ///
    /// # Errors
    /// [`ChannelError::Unreachable`] when the subject has no link (or
    /// Telegram says the chat is gone); [`ChannelError::Transient`] for
    /// rate limits and Telegram's own 5xx; [`ChannelError::Permanent`]
    /// for a misconfigured bot.
    async fn deliver(
        &self,
        db: &dyn Database,
        account_id: &str,
        message: &ChannelMessage,
    ) -> Result<(), ChannelError> {
        let Some((_, chat_id)) = store::link_of_subject(db, account_id)
            .await
            .map_err(|_| ChannelError::Transient { retry_after: None })?
        else {
            return Err(ChannelError::Unreachable);
        };

        // Title first, body under it — how a notification reads as its
        // own message rather than one run-on line.
        let mut text = message.title.clone();
        if !message.body.is_empty() {
            text.push_str("\n\n");
            text.push_str(&message.body);
        }
        let mut outgoing = OutgoingMessage::new(chat_id, text);
        if let Some(url) = &message.url {
            let button = InlineButton::url("Open", url.clone());
            outgoing = outgoing.row(vec![button]);
        }
        self.bot
            .send_message(&outgoing)
            .await
            .map_err(|error| map_error(&error))?;
        Ok(())
    }
}
