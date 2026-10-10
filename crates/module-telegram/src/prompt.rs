//! The issuing half of the action buttons: [`send_action_prompt`], the
//! call a venture makes when it needs a consent decision.
//!
//! Everything the tap side checks is set up here: the row starts
//! `pending`, the two buttons each carry their own signed token (see
//! [`token`](crate::token)), and the tokens are bound to the Telegram
//! user the prompt is sent to — not to the chat, which forwards.

use std::time::Duration as StdDuration;

use time::Duration as TimeDuration;
use time::OffsetDateTime;

use cratefield_adapter_telegram::{InlineButton, OutgoingMessage, TelegramBot, TelegramError};
use cratefield_core::{Clock, Database, RandomBytes, RandomError};

use crate::store;
use crate::token::{Decision, action_token};

/// How long a prompt may live at most: an hour. A consent request that
/// outlives the conversation it started in is one nobody remembers
/// making.
pub const MAX_ACTION_TTL: TimeDuration = TimeDuration::seconds(60 * 60);

/// One consent request, as the venture files it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRequest {
    /// The account the action belongs to — the prompt goes to whatever
    /// Telegram account this subject has linked.
    pub subject: String,
    /// The app-defined label of what is being approved. Reported back
    /// verbatim in the [`crate::ActionDecision`] the venture's `on_action` hook
    /// receives; this module never interprets it.
    pub action: String,
    /// What the person sees in the chat, above the buttons.
    pub text: String,
    /// Whether approving moves value (money, access, anything hard to
    /// take back). A value-moving prompt can only be **approved for
    /// passkey confirmation** from Telegram: the tap puts it into
    /// `awaiting_passkey` and the web app's `/confirm` route — a fresh
    /// passkey ceremony, via the `StepUp` port — finishes it.
    pub value_moving: bool,
    /// How long the buttons work. Capped at [`MAX_ACTION_TTL`], floored
    /// at one second.
    pub ttl: StdDuration,
}

/// A prompt Telegram accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPrompt {
    /// The action's id — the same string the later decision reports, and
    /// the `{action_id}` of the web app's confirm route when the action
    /// is value-moving.
    pub action_id: String,
    /// The chat the prompt landed in.
    pub chat_id: i64,
    /// When the buttons stop working.
    pub expires_at: OffsetDateTime,
}

/// Why a prompt could not be issued.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActionError {
    /// The subject has no linked Telegram account. Nobody to ask.
    NotLinked,
    /// The entropy source failed; no action id could be drawn.
    Random(RandomError),
    /// A database statement failed.
    Db(cratefield_core::DbError),
    /// Telegram refused the send.
    Telegram(TelegramError),
}

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLinked => f.write_str("the subject has no linked Telegram account"),
            Self::Random(error) => write!(f, "entropy source failed: {error}"),
            Self::Db(error) => write!(f, "a database statement failed: {error}"),
            Self::Telegram(error) => write!(f, "telegram refused the prompt: {error}"),
        }
    }
}

impl std::error::Error for ActionError {}

/// Sends one action prompt to the subject's linked chat: the request's
/// text with an Approve and a Deny button under it.
///
/// The row is inserted before the message is sent, so a Telegram failure
/// (rate limit, chat gone) leaves a `pending` row that simply expires —
/// and a venture that retries the call mints a fresh action rather than
/// re-sending the same one.
///
/// # Errors
///
/// [`ActionError::NotLinked`] when the subject has no linked account;
/// [`ActionError::Random`], [`ActionError::Db`] and
/// [`ActionError::Telegram`] for the failures their names say.
pub async fn send_action_prompt(
    db: &dyn Database,
    clock: &dyn Clock,
    random: &dyn RandomBytes,
    bot: &dyn TelegramBot,
    key: &[u8],
    request: ActionRequest,
) -> Result<ActionPrompt, ActionError> {
    let Some((telegram_user_id, chat_id)) = store::link_of_subject(db, &request.subject)
        .await
        .map_err(ActionError::Db)?
    else {
        return Err(ActionError::NotLinked);
    };

    let mut bytes = [0u8; 16];
    random.fill(&mut bytes).map_err(ActionError::Random)?;
    let action_id = crate::token::b64url(&bytes);

    let now = clock.now();
    let ttl = request
        .ttl
        .try_into()
        .unwrap_or(MAX_ACTION_TTL)
        .clamp(TimeDuration::seconds(1), MAX_ACTION_TTL);
    let expires_at = now + ttl;
    // A timestamp past 2106 wraps the u32 the token carries; the clamp
    // below turns that into "already expired" rather than "lives long".
    let exp_unix = u32::try_from(expires_at.unix_timestamp()).unwrap_or(0);

    store::insert_action(
        db,
        &action_id,
        &request.subject,
        &request.action,
        request.value_moving,
        &store::stamp(expires_at),
        &store::stamp(now),
    )
    .await
    .map_err(ActionError::Db)?;

    let approve = action_token(
        key,
        &action_id,
        Decision::Approve,
        exp_unix,
        telegram_user_id,
    );
    let deny = action_token(key, &action_id, Decision::Deny, exp_unix, telegram_user_id);
    let message = OutgoingMessage::new(chat_id, request.text.clone()).row(vec![
        InlineButton::callback("Approve", approve).map_err(ActionError::Telegram)?,
        InlineButton::callback("Deny", deny).map_err(ActionError::Telegram)?,
    ]);
    bot.send_message(&message)
        .await
        .map_err(ActionError::Telegram)?;

    Ok(ActionPrompt {
        action_id,
        chat_id,
        expires_at,
    })
}
