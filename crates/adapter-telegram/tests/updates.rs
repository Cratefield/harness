//! Typed update tests (issue #764): messages, commands (including the
//! `/command@bot args` form), callback queries, channel posts, the UTF-16
//! entity offsets an emoji shifts, the payloads this crate maps to
//! `UpdateKind::Other`, and the bodies that are errors rather than updates.

use cratefield_adapter_telegram::{ChatKind, UpdateError, UpdateKind, parse_update};

const MESSAGE: &str = include_str!("fixtures/message.json");
const COMMAND_START: &str = include_str!("fixtures/command-start.json");
const CALLBACK_QUERY: &str = include_str!("fixtures/callback-query.json");
const CHANNEL_POST: &str = include_str!("fixtures/channel-post.json");

fn parse(body: &str) -> cratefield_adapter_telegram::Update {
    parse_update(body.as_bytes()).expect("a fixture update parses")
}

#[test]
fn a_plain_message_parses_with_chat_user_and_text() {
    let update = parse(MESSAGE);
    assert_eq!(update.update_id, 100);
    let UpdateKind::Message(message) = update.kind else {
        panic!("expected a message, got {:?}", update.kind);
    };
    assert_eq!(message.message_id, 11);
    assert_eq!(message.chat.id, 42);
    assert_eq!(message.chat.kind, ChatKind::Private);
    assert_eq!(message.chat.username.as_deref(), Some("ada"));
    let from = message.from.expect("the sender is on the wire");
    assert_eq!(from.id, 42);
    assert!(!from.is_bot);
    assert_eq!(from.first_name, "Ada");
    assert_eq!(from.language_code.as_deref(), Some("en"));
    assert_eq!(message.text.as_deref(), Some("hello bot"));
    assert!(message.links.is_empty(), "no entities, no links");
}

#[test]
fn a_command_parses_into_name_bot_and_args() {
    let update = parse(COMMAND_START);
    let UpdateKind::Command(command) = update.kind else {
        panic!("expected a command, got {:?}", update.kind);
    };
    assert_eq!(command.name, "start");
    assert_eq!(command.bot, None);
    assert_eq!(command.args, "abc123");
    assert_eq!(command.message.text.as_deref(), Some("/start abc123"));
}

#[test]
fn a_command_addressed_to_a_bot_keeps_the_bot_and_lowers_the_name() {
    let update = parse(
        r#"{
            "update_id": 104,
            "message": {
                "message_id": 13,
                "chat": { "id": -10099, "type": "supergroup", "title": "Ops" },
                "from": { "id": 7, "is_bot": false, "first_name": "Grace" },
                "date": 1767225600,
                "text": "/Help@MyBot arg ",
                "entities": [{ "type": "bot_command", "offset": 0, "length": 11 }]
            }
        }"#,
    );
    let UpdateKind::Command(command) = update.kind else {
        panic!("expected a command, got {:?}", update.kind);
    };
    assert_eq!(
        command.name, "help",
        "the name is lowercase, without the slash"
    );
    assert_eq!(
        command.bot.as_deref(),
        Some("MyBot"),
        "the bot keeps its case"
    );
    assert_eq!(command.args, "arg", "the rest, trimmed");
}

#[test]
fn a_command_with_no_args_has_empty_args() {
    let update = parse(
        r#"{
            "update_id": 105,
            "message": {
                "message_id": 14,
                "chat": { "id": 42, "type": "private" },
                "from": { "id": 42, "is_bot": false, "first_name": "Ada" },
                "date": 1767225600,
                "text": "/start",
                "entities": [{ "type": "bot_command", "offset": 0, "length": 6 }]
            }
        }"#,
    );
    let UpdateKind::Command(command) = update.kind else {
        panic!("expected a command, got {:?}", update.kind);
    };
    assert_eq!(command.args, "");
}

#[test]
fn a_bot_command_entity_off_the_front_is_not_a_command() {
    // `say /start` — Telegram itself would not send this, but the rule this
    // crate implements is "at offset 0", so prove the offset is read.
    let update = parse(
        r#"{
            "update_id": 106,
            "message": {
                "message_id": 15,
                "chat": { "id": 42, "type": "private" },
                "from": { "id": 42, "is_bot": false, "first_name": "Ada" },
                "date": 1767225600,
                "text": "say /start",
                "entities": [{ "type": "bot_command", "offset": 4, "length": 6 }]
            }
        }"#,
    );
    assert!(matches!(update.kind, UpdateKind::Message(_)));
}

#[test]
fn a_callback_query_parses_with_its_message_reference() {
    let update = parse(CALLBACK_QUERY);
    let UpdateKind::CallbackQuery(callback) = update.kind else {
        panic!("expected a callback query, got {:?}", update.kind);
    };
    assert_eq!(callback.id, "cq1");
    assert_eq!(callback.from.id, 42);
    assert_eq!(callback.chat_id, Some(-10099));
    assert_eq!(callback.message_id, Some(7));
    assert_eq!(callback.data.as_deref(), Some("deploy:ack"));
}

#[test]
fn a_channel_post_parses_links_through_utf16_offsets() {
    let update = parse(CHANNEL_POST);
    let UpdateKind::ChannelPost(post) = update.kind else {
        panic!("expected a channel post, got {:?}", update.kind);
    };
    assert!(!post.edited, "channel_post, not edited_channel_post");
    let message = &post.message;
    assert_eq!(message.chat.id, -1_001_234_567_890);
    assert_eq!(message.chat.kind, ChatKind::Channel);
    assert_eq!(message.chat.title.as_deref(), Some("Releases"));
    assert!(message.from.is_none(), "channel posts name no sender");

    // The 🎉 is two UTF-16 code units, so the URL's offset is 9 — not the
    // 8 a byte offset would give, and the slice must still land exactly on
    // the URL.
    assert_eq!(
        message.links,
        vec![
            "https://example.com/a".to_owned(),
            "https://example.com/docs".to_owned(),
        ],
        "the url entity is sliced, the text_link entity is read verbatim"
    );
}

#[test]
fn an_edited_channel_post_is_edited() {
    let body = CHANNEL_POST.replace("channel_post", "edited_channel_post");
    let update = parse_update(body.as_bytes()).expect("parses");
    let UpdateKind::ChannelPost(post) = update.kind else {
        panic!("expected a channel post, got {:?}", update.kind);
    };
    assert!(post.edited);
}

#[test]
fn a_media_message_exposes_its_caption_and_its_caption_links() {
    // "see " is four units; the URL after it is twenty-one.
    let update = parse(
        r#"{
            "update_id": 107,
            "message": {
                "message_id": 16,
                "chat": { "id": 42, "type": "private" },
                "from": { "id": 42, "is_bot": false, "first_name": "Ada" },
                "date": 1767225600,
                "caption": "see https://example.com/x",
                "caption_entities": [{ "type": "url", "offset": 4, "length": 21 }]
            }
        }"#,
    );
    let UpdateKind::Message(message) = update.kind else {
        panic!("expected a message, got {:?}", update.kind);
    };
    assert_eq!(message.text.as_deref(), Some("see https://example.com/x"));
    assert_eq!(message.links, vec!["https://example.com/x".to_owned()]);
}

#[test]
fn payloads_this_crate_does_not_model_are_other() {
    // `edited_message`, and an update with none of the known payloads at
    // all — both valid deliveries, both `Other`.
    for body in [
        r#"{ "update_id": 108, "edited_message": {
                "message_id": 17, "chat": { "id": 42, "type": "private" }, "date": 1 } }"#,
        r#"{ "update_id": 109 }"#,
    ] {
        let update = parse_update(body.as_bytes()).expect("a known-shaped delivery parses");
        assert_eq!(update.kind, UpdateKind::Other, "{body}");
    }
}

#[test]
fn out_of_range_entities_are_skipped_not_fatal() {
    let update = parse(
        r#"{
            "update_id": 110,
            "message": {
                "message_id": 18,
                "chat": { "id": 42, "type": "private" },
                "from": { "id": 42, "is_bot": false, "first_name": "Ada" },
                "date": 1767225600,
                "text": "short",
                "entities": [
                    { "type": "url", "offset": 0, "length": 999 },
                    { "type": "url", "offset": 1, "length": 2 }
                ]
            }
        }"#,
    );
    let UpdateKind::Message(message) = update.kind else {
        panic!("expected a message, got {:?}", update.kind);
    };
    assert_eq!(
        message.links,
        vec!["ho".to_owned()],
        "the in-range entity survives"
    );
}

#[test]
fn malformed_bodies_are_errors() {
    for body in [
        "not json at all",
        "[]",
        r#"{"update_id": "not a number"}"#,
        // A message without a chat is not an update shape.
        r#"{"update_id": 111, "message": {"message_id": 19}}"#,
    ] {
        let error = parse_update(body.as_bytes()).expect_err("must be malformed");
        assert!(
            matches!(error, UpdateError::Malformed(_)),
            "{body}: {error}"
        );
        assert!(error.to_string().contains("malformed"), "{error}");
    }
}
