//! A [`TelegramBot`] that talks to no one: the fake module tests substitute
//! for [`HttpTelegramBot`](crate::HttpTelegramBot), always compiled. It
//! records every call, hands
//! out increasing message ids per chat like Telegram would, refuses edits
//! and deletes of messages that are not there, and can be told to fail
//! exactly once.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;

use crate::client::{InlineButton, OutgoingMessage, SentMessage, TelegramBot, TelegramError};

// Recording state for the fake — the same category and allowance as the
// fakes in `cratefield-testing` (ADR 0007 policy; see the workspace
// clippy.toml).
#[allow(clippy::disallowed_types)]
type Guarded<T> = std::sync::Mutex<T>;

/// One call the fake received, verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `send_message`, with the message as it was handed over.
    Send(OutgoingMessage),
    /// `edit_message`.
    Edit {
        /// The chat the edited message lives in.
        chat_id: i64,
        /// The message that was edited.
        message_id: i64,
        /// The replacement text.
        text: String,
        /// The replacement keyboard.
        buttons: Vec<Vec<InlineButton>>,
    },
    /// `delete_message`.
    Delete {
        /// The chat the deleted message lived in.
        chat_id: i64,
        /// The message that was deleted.
        message_id: i64,
    },
    /// `answer_callback`.
    AnswerCallback {
        /// The callback query that was acknowledged.
        callback_query_id: String,
        /// The toast shown to the presser, if any.
        text: Option<String>,
    },
}

#[derive(Debug, Default)]
struct FakeState {
    calls: Vec<Call>,
    /// The next message id per chat, starting at 1 like Telegram's do.
    next_id: HashMap<i64, i64>,
    /// The messages the bot has sent and not yet had deleted.
    messages: HashSet<(i64, i64)>,
    failures: VecDeque<TelegramError>,
}

/// An in-memory [`TelegramBot`]. Clone it: every clone shares the one
/// recording state, so the code under test and the assertions meet.
#[derive(Debug, Clone, Default)]
pub struct FakeTelegramBot {
    state: Arc<Guarded<FakeState>>,
}

impl FakeTelegramBot {
    /// A fake that has heard nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every call so far, in order.
    ///
    /// # Panics
    ///
    /// Only if the state mutex is poisoned by a prior panic.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.state.lock().expect("fake telegram lock").calls.clone()
    }

    /// The messages `send_message` received, in order — the common case,
    /// spelled out.
    #[must_use]
    pub fn sent(&self) -> Vec<OutgoingMessage> {
        self.calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Send(message) => Some(message),
                _ => None,
            })
            .collect()
    }

    /// Scripts the next trait call — whichever it is — to fail with
    /// `error` instead of doing its work. One shot per call: script a
    /// failure twice to fail twice.
    ///
    /// # Panics
    ///
    /// Only if the state mutex is poisoned by a prior panic.
    pub fn fail_next(&self, error: TelegramError) {
        self.state
            .lock()
            .expect("fake telegram lock")
            .failures
            .push_back(error);
    }

    /// Pops one scripted failure, if any.
    fn pop_failure(&self) -> Option<TelegramError> {
        self.state
            .lock()
            .expect("fake telegram lock")
            .failures
            .pop_front()
    }
}

#[async_trait]
impl TelegramBot for FakeTelegramBot {
    async fn send_message(&self, message: &OutgoingMessage) -> Result<SentMessage, TelegramError> {
        if let Some(error) = self.pop_failure() {
            return Err(error);
        }
        let mut state = self.state.lock().expect("fake telegram lock");
        let chat = state.next_id.entry(message.chat_id).or_insert(0);
        *chat += 1;
        let message_id = *chat;
        state.messages.insert((message.chat_id, message_id));
        state.calls.push(Call::Send(message.clone()));
        Ok(SentMessage {
            chat_id: message.chat_id,
            message_id,
        })
    }

    async fn edit_message(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        buttons: &[Vec<InlineButton>],
    ) -> Result<(), TelegramError> {
        if let Some(error) = self.pop_failure() {
            return Err(error);
        }
        let mut state = self.state.lock().expect("fake telegram lock");
        if !state.messages.contains(&(chat_id, message_id)) {
            // A message Telegram no longer knows — never sent, too old, or
            // already deleted — is Telegram's own "not found".
            return Err(TelegramError::Invalid(
                "message to edit not found".to_owned(),
            ));
        }
        state.calls.push(Call::Edit {
            chat_id,
            message_id,
            text: text.to_owned(),
            buttons: buttons.to_vec(),
        });
        Ok(())
    }

    async fn delete_message(&self, chat_id: i64, message_id: i64) -> Result<(), TelegramError> {
        if let Some(error) = self.pop_failure() {
            return Err(error);
        }
        let mut state = self.state.lock().expect("fake telegram lock");
        if !state.messages.remove(&(chat_id, message_id)) {
            return Err(TelegramError::Invalid(
                "message to delete not found".to_owned(),
            ));
        }
        state.calls.push(Call::Delete {
            chat_id,
            message_id,
        });
        Ok(())
    }

    async fn answer_callback(
        &self,
        callback_query_id: &str,
        text: Option<&str>,
    ) -> Result<(), TelegramError> {
        if let Some(error) = self.pop_failure() {
            return Err(error);
        }
        let mut state = self.state.lock().expect("fake telegram lock");
        state.calls.push(Call::AnswerCallback {
            callback_query_id: callback_query_id.to_owned(),
            text: text.map(str::to_owned),
        });
        Ok(())
    }
}
