//! The conformance walk (issue #764): `bot_conformance` against the fake
//! and against the HTTP client over a scripted fake, so the contract the
//! port promises is checked against both ends of it.

mod common;

use common::{FakeHttp, ManualClock, ok};
use cratefield_adapter_telegram::conformance::bot_conformance;
use cratefield_adapter_telegram::fake::Call;
use cratefield_adapter_telegram::{HttpTelegramBot, RateLimits, TelegramError};
use std::sync::Arc;
use time::OffsetDateTime;

const TOKEN: &str = "123456789:AAExample_dummy-token_not-real";
const BASE: &str = "http://telegram.fake";
const SENT: &str = include_str!("fixtures/sent.json");

#[pollster::test]
async fn the_fake_conforms() {
    let bot = cratefield_adapter_telegram::fake::FakeTelegramBot::new();
    bot_conformance(&bot, 42).await;

    let calls = bot.calls();
    assert_eq!(calls.len(), 4, "one call per port method: {calls:?}");
    assert!(
        matches!(&calls[0], Call::Send(message) if message.chat_id == 42),
        "the walk opens with a send: {calls:?}"
    );
    assert!(
        matches!(
            &calls[1],
            Call::Edit {
                chat_id: 42,
                message_id: 1,
                ..
            }
        ),
        "the walk edits the message the send returned: {calls:?}"
    );
    assert!(
        matches!(
            &calls[2],
            Call::Delete {
                chat_id: 42,
                message_id: 1
            }
        ),
        "then deletes it: {calls:?}"
    );
    assert!(
        matches!(&calls[3], Call::AnswerCallback { callback_query_id, .. }
            if callback_query_id == "conformance-callback-query-id"),
        "and acknowledges the button: {calls:?}"
    );
}

#[pollster::test]
async fn the_fake_conforms_in_a_group_chat_too() {
    let bot = cratefield_adapter_telegram::fake::FakeTelegramBot::new();
    bot_conformance(&bot, -100_200_300).await;
    assert_eq!(bot.sent().len(), 1);
}

#[pollster::test]
async fn the_http_client_conforms_over_a_scripted_fake() {
    let http = FakeHttp::scripted(vec![
        ok(SENT),
        ok(SENT),
        ok(SENT),
        ok(r#"{"ok": true, "result": true}"#),
    ]);
    let clock = ManualClock::new(
        OffsetDateTime::from_unix_timestamp(1_767_225_600).expect("a representable instant"),
    );
    // The walk makes four chat-scoped calls in the same instant, so the
    // default one-per-second private budget would refuse them; a wide
    // budget lets the walk test the port, not the rate limiter.
    let bot = HttpTelegramBot::new(Arc::new(http.clone()), Arc::new(clock), TOKEN)
        .with_base(BASE)
        .with_limits(RateLimits {
            global_per_sec: 100,
            private_chat_per_sec: 100,
            group_per_min: 100,
        });
    bot_conformance(&bot, 42).await;
    assert_eq!(http.captured().len(), 4, "one HTTP call per port method");
}

#[pollster::test]
async fn a_failing_bot_breaks_conformance_with_the_step_named() {
    let bot = cratefield_adapter_telegram::fake::FakeTelegramBot::new();
    bot.fail_next(TelegramError::Unauthorized);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pollster::block_on(bot_conformance(&bot, 42));
    }))
    .expect_err("a bot that refuses the send does not conform");
    let message = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .expect("a string panic");
    assert!(
        message.contains("send_message"),
        "the step is named in the panic: {message}"
    );
}
