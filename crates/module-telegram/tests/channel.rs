//! The notifications channel (issue #764): reachability is the link
//! table, delivery lands in the linked chat, and every Telegram refusal
//! maps to the channel error that says what a retry is worth.

#![cfg(feature = "notifications")]

use std::sync::Arc;
use std::time::Duration;

use cratefield_adapter_telegram::TelegramError;
use cratefield_adapter_telegram::fake::FakeTelegramBot;
use cratefield_module_notifications::{Channel, ChannelError, ChannelMessage};
use cratefield_module_telegram::TelegramChannel;

mod support;

use support::{ALICE, BOB, CHAT, insert_link, kit};

fn message(url: Option<&str>) -> ChannelMessage {
    ChannelMessage {
        category: "booking".to_owned(),
        title: "Room starting".to_owned(),
        body: "Your room starts in five minutes.".to_owned(),
        url: url.map(str::to_owned),
        notification_id: "ntf_1".to_owned(),
    }
}

#[pollster::test]
async fn the_channel_is_named_telegram() {
    let bot = FakeTelegramBot::new();
    let channel = TelegramChannel::new(Arc::new(bot) as _);
    assert_eq!(Channel::name(&channel), "telegram");
}

#[pollster::test]
async fn reachability_is_the_link_table() {
    let (kit, _bot) = kit(cratefield_module_telegram::TelegramEvents::new());
    insert_link(&kit, ALICE, 42, CHAT);
    let channel = TelegramChannel::new(Arc::new(FakeTelegramBot::new()) as _);

    assert!(
        pollster::block_on(Channel::reachable(&channel, &*kit.db, ALICE)).expect("reachable"),
        "a linked subject is reachable"
    );
    assert!(
        !pollster::block_on(Channel::reachable(&channel, &*kit.db, BOB)).expect("reachable"),
        "an unlinked subject is not"
    );
}

#[pollster::test]
async fn delivery_lands_in_the_linked_chat() {
    let (kit, bot) = kit(cratefield_module_telegram::TelegramEvents::new());
    insert_link(&kit, ALICE, 42, CHAT);
    let channel = TelegramChannel::new(Arc::clone(&bot) as _);

    pollster::block_on(Channel::deliver(
        &channel,
        &*kit.db,
        ALICE,
        &message(Some("https://app.example/rooms/1")),
    ))
    .expect("it delivers");

    let sent = bot.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].chat_id, CHAT);
    assert_eq!(
        sent[0].text, "Room starting\n\nYour room starts in five minutes.",
        "title first, body under it"
    );
    assert_eq!(
        support::button_url(&bot, "Open").as_deref(),
        Some("https://app.example/rooms/1"),
        "the notification's link rides a button"
    );
}

#[pollster::test]
async fn a_subject_without_a_link_is_unreachable() {
    let (kit, _bot) = kit(cratefield_module_telegram::TelegramEvents::new());
    let channel = TelegramChannel::new(Arc::new(FakeTelegramBot::new()) as _);

    let error = pollster::block_on(Channel::deliver(&channel, &*kit.db, BOB, &message(None)))
        .expect_err("nobody to deliver to");
    assert!(matches!(error, ChannelError::Unreachable));
}

#[pollster::test]
async fn a_url_less_message_sends_plain_text() {
    let (kit, bot) = kit(cratefield_module_telegram::TelegramEvents::new());
    insert_link(&kit, ALICE, 42, CHAT);
    let channel = TelegramChannel::new(Arc::clone(&bot) as _);

    pollster::block_on(Channel::deliver(&channel, &*kit.db, ALICE, &message(None)))
        .expect("it delivers");
    assert!(bot.sent()[0].buttons.is_empty(), "no link, no button");
}

#[pollster::test]
async fn refusals_map_to_the_error_a_retry_is_worth() {
    let (kit, bot) = kit(cratefield_module_telegram::TelegramEvents::new());
    insert_link(&kit, ALICE, 42, CHAT);
    let channel = TelegramChannel::new(Arc::clone(&bot) as _);

    // The chat is gone for good: only the account can fix it.
    bot.fail_next(TelegramError::Forbidden("bot was blocked".to_owned()));
    let error = pollster::block_on(Channel::deliver(&channel, &*kit.db, ALICE, &message(None)))
        .expect_err("it fails");
    assert!(matches!(error, ChannelError::Unreachable));

    // Telegram's own rate limit: wait out what it asked for.
    bot.fail_next(TelegramError::RateLimited {
        retry_after: Duration::from_secs(7),
    });
    let error = pollster::block_on(Channel::deliver(&channel, &*kit.db, ALICE, &message(None)))
        .expect_err("it fails");
    assert!(matches!(
        error,
        ChannelError::Transient {
            retry_after: Some(retry_after),
        } if retry_after == Duration::from_secs(7)
    ));

    // A 5xx or a dropped transport: worth retrying, no wait named.
    bot.fail_next(TelegramError::Transient("upstream 502".to_owned()));
    let error = pollster::block_on(Channel::deliver(&channel, &*kit.db, ALICE, &message(None)))
        .expect_err("it fails");
    assert!(matches!(
        error,
        ChannelError::Transient { retry_after: None }
    ));

    // A bad token is a configuration error, not a retry.
    bot.fail_next(TelegramError::Unauthorized);
    let error = pollster::block_on(Channel::deliver(&channel, &*kit.db, ALICE, &message(None)))
        .expect_err("it fails");
    assert!(matches!(error, ChannelError::Permanent(_)));
}
