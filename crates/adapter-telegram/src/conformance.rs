//! The adapter's own conformance walk: one pass over the whole
//! [`TelegramBot`] port any implementation must survive. The crate runs it
//! against the fake and the HTTP client in its tests; a module bringing its
//! own bot (a wrapper, a decorator) runs it against that.

use crate::client::{InlineButton, OutgoingMessage, TelegramBot};

/// Walks one full send → edit → delete → answer-callback round against
/// `bot`, addressed to `chat_id`, and asserts the port's contract at each
/// step.
///
/// # Panics
///
/// Panics, with the step named in the message, when any call fails, when
/// `send_message` does not echo `chat_id` back, or when it reports a
/// non-positive `message_id` — none of which a conforming bot does.
pub async fn bot_conformance(bot: &dyn TelegramBot, chat_id: i64) {
    let message = OutgoingMessage::new(chat_id, "cratefield conformance probe").row(vec![
        InlineButton::callback("Acknowledge", "conformance:ack")
            .expect("conformance callback data is within the 64-byte limit"),
    ]);
    let sent = bot
        .send_message(&message)
        .await
        .unwrap_or_else(|error| panic!("conformance: send_message failed: {error}"));
    assert_eq!(
        sent.chat_id, chat_id,
        "conformance: send_message must echo the chat id back"
    );
    assert!(
        sent.message_id > 0,
        "conformance: send_message must report a positive message id, got {}",
        sent.message_id
    );
    bot.edit_message(
        chat_id,
        sent.message_id,
        "cratefield conformance probe (edited)",
        &[],
    )
    .await
    .unwrap_or_else(|error| panic!("conformance: edit_message failed: {error}"));
    bot.delete_message(chat_id, sent.message_id)
        .await
        .unwrap_or_else(|error| panic!("conformance: delete_message failed: {error}"));
    bot.answer_callback("conformance-callback-query-id", Some("acknowledged"))
        .await
        .unwrap_or_else(|error| panic!("conformance: answer_callback failed: {error}"));
}
