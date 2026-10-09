//! HTTP client acceptance tests (issue #764): the request shape on the
//! wire, the envelope parse, the local rate budgets (refusing before any
//! HTTP call, remembering a 429's deadline, global and per-chat buckets),
//! the status-to-error mapping, and the guarantee the URL-path token
//! forces: it never appears in a `Debug`, a `Display` or a log line.

mod common;

use common::{FakeHttp, ManualClock, ok, status};
use cratefield_adapter_telegram::{
    ButtonKind, HttpTelegramBot, InlineButton, OutgoingMessage, RateLimits, TelegramBot,
    TelegramError,
};
use cratefield_core::HttpError;
use http::StatusCode;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

// Obvious dummy values, never real.
const TOKEN: &str = "123456789:AAExample_dummy-token_not-real";
const BASE: &str = "http://telegram.fake";

const SENT: &str = include_str!("fixtures/sent.json");
const ERROR_429: &str = include_str!("fixtures/error-429.json");
const ERROR_401: &str = include_str!("fixtures/error-401.json");
const ERROR_403: &str = include_str!("fixtures/error-403.json");
const ERROR_400: &str = include_str!("fixtures/error-400.json");
const ERROR_500: &str = include_str!("fixtures/error-500.json");

fn clock() -> ManualClock {
    ManualClock::new(
        OffsetDateTime::from_unix_timestamp(1_767_225_600).expect("a representable instant"),
    )
}

fn bot(http: &FakeHttp, clock: &ManualClock) -> HttpTelegramBot {
    bot_with_limits(http, clock, RateLimits::default())
}

fn bot_with_limits(http: &FakeHttp, clock: &ManualClock, limits: RateLimits) -> HttpTelegramBot {
    HttpTelegramBot::new(Arc::new(http.clone()), Arc::new(clock.clone()), TOKEN)
        .with_base(BASE)
        .with_limits(limits)
}

/// The method and path of the Nth captured request.
fn captured_path(http: &FakeHttp, n: usize) -> String {
    let (method, uri, _body) = &http.captured()[n];
    assert_eq!(method, "POST", "every Bot API call is a POST");
    uri.clone()
}

fn captured_body(http: &FakeHttp, n: usize) -> Value {
    let (_method, _uri, body) = &http.captured()[n];
    serde_json::from_str(body).expect("the adapter always sends JSON")
}

#[pollster::test]
async fn send_message_wires_the_expected_request_and_parses_the_result() {
    let http = FakeHttp::scripted(vec![ok(SENT)]);
    let clock = clock();
    let bot = bot(&http, &clock);
    let message = OutgoingMessage::new(42, "Deployment finished")
        .row(vec![
            InlineButton::callback("Acknowledge", "deploy:ack").expect("within the byte limit"),
            InlineButton::url("Docs", "https://example.com/docs"),
        ])
        .row(vec![
            InlineButton::callback("Again", "deploy:again").expect("within the limit"),
        ]);
    let sent = bot
        .send_message(&message)
        .await
        .expect("a scripted 200 must send");

    assert_eq!(
        captured_path(&http, 0),
        format!("{BASE}/bot{TOKEN}/sendMessage")
    );
    let body = captured_body(&http, 0);
    assert_eq!(body["chat_id"], 42);
    assert_eq!(body["text"], "Deployment finished");
    // The keyboard rides `reply_markup.inline_keyboard`, callbacks as
    // `callback_data` and links as `url`.
    assert_eq!(
        body["reply_markup"]["inline_keyboard"][0][0]["text"],
        "Acknowledge"
    );
    assert_eq!(
        body["reply_markup"]["inline_keyboard"][0][0]["callback_data"],
        "deploy:ack"
    );
    assert_eq!(
        body["reply_markup"]["inline_keyboard"][0][1]["url"],
        "https://example.com/docs"
    );
    assert_eq!(
        body["reply_markup"]["inline_keyboard"][1][0]["callback_data"],
        "deploy:again"
    );
    // The second row proves rows survive; a buttonless message sends no
    // keyboard at all (covered below), and an enabled preview sends no
    // option at all — Telegram's default already shows it.
    assert!(
        body.get("link_preview_options").is_none(),
        "an enabled preview sends no option: {body}"
    );

    // The envelope parse: chat and message id read back off `result`.
    assert_eq!(sent.chat_id, 42);
    assert_eq!(sent.message_id, 7);
}

#[pollster::test]
async fn preview_suppression_and_keyboard_omission_are_exact() {
    let http = FakeHttp::scripted(vec![ok(SENT), ok(SENT)]);
    let clock = clock();
    let bot = bot(&http, &clock);
    bot.send_message(&OutgoingMessage::new(42, "plain"))
        .await
        .expect("sends");
    // The chat's one-per-second budget is beside the point here; spacing
    // the two sends keeps the test on the wire shapes.
    clock.advance(Duration::from_secs(1));
    let suppressed = OutgoingMessage {
        disable_link_preview: true,
        ..OutgoingMessage::new(42, "no preview")
    };
    bot.send_message(&suppressed).await.expect("sends");

    let plain = captured_body(&http, 0);
    assert!(
        plain.get("reply_markup").is_none(),
        "no buttons means no reply_markup: {plain}"
    );
    assert!(
        plain.get("link_preview_options").is_none(),
        "an enabled preview sends no option at all: {plain}"
    );
    let muted = captured_body(&http, 1);
    assert_eq!(muted["link_preview_options"]["is_disabled"], true);
}

#[pollster::test]
async fn a_429_sets_a_chat_deadline_the_client_enforces_without_sending() {
    let http = FakeHttp::scripted(vec![
        status(StatusCode::TOO_MANY_REQUESTS, ERROR_429),
        ok(SENT),
    ]);
    let clock = clock();
    let bot = bot(&http, &clock);

    let error = bot
        .send_message(&OutgoingMessage::new(42, "first"))
        .await
        .expect_err("a 429 is RateLimited");
    assert_eq!(
        error,
        TelegramError::RateLimited {
            retry_after: Duration::from_secs(5)
        },
        "parameters.retry_after wins over any header or default"
    );
    assert_eq!(http.captured().len(), 1);
    assert_eq!(error.retry_after(), Some(Duration::from_secs(5)));

    // The next send to that chat is refused locally, without an HTTP call,
    // for exactly as long as Telegram said.
    clock.advance(Duration::from_secs(4));
    let error = bot
        .send_message(&OutgoingMessage::new(42, "again"))
        .await
        .expect_err("still inside the deadline");
    assert_eq!(error.retry_after(), Some(Duration::from_secs(1)));
    assert_eq!(http.captured().len(), 1, "nothing was sent");

    clock.advance(Duration::from_secs(1));
    let sent = bot
        .send_message(&OutgoingMessage::new(42, "after the deadline"))
        .await
        .expect("the deadline has passed");
    assert_eq!(sent.message_id, 7);
    assert_eq!(http.captured().len(), 2);
}

#[pollster::test]
async fn a_private_chat_sends_at_most_one_message_per_second() {
    let http = FakeHttp::scripted(vec![ok(SENT), ok(SENT)]);
    let clock = clock();
    let bot = bot(&http, &clock);

    bot.send_message(&OutgoingMessage::new(42, "one"))
        .await
        .expect("the bucket starts full");
    let error = bot
        .send_message(&OutgoingMessage::new(42, "two"))
        .await
        .expect_err("the private-chat bucket holds one token per second");
    assert_eq!(error.retry_after(), Some(Duration::from_secs(1)));
    assert_eq!(http.captured().len(), 1, "refused locally, nothing sent");

    clock.advance(Duration::from_secs(1));
    bot.send_message(&OutgoingMessage::new(42, "three"))
        .await
        .expect("a second has passed, the bucket refilled");
    assert_eq!(http.captured().len(), 2);
}

#[pollster::test]
async fn a_group_sends_at_most_twenty_messages_per_minute() {
    let http = FakeHttp::scripted(vec![ok(SENT); 21]);
    let clock = clock();
    let bot = bot(&http, &clock);
    let group = -100_200_300;

    for n in 0..20 {
        bot.send_message(&OutgoingMessage::new(group, format!("burst {n}")))
            .await
            .unwrap_or_else(|error| panic!("burst message {n} must send: {error}"));
    }
    assert_eq!(http.captured().len(), 20);
    let error = bot
        .send_message(&OutgoingMessage::new(group, "one over"))
        .await
        .expect_err("the group budget is 20 per minute");
    assert_eq!(
        error.retry_after(),
        Some(Duration::from_secs(3)),
        "20 per minute refills one token every three seconds"
    );

    clock.advance(Duration::from_secs(3));
    bot.send_message(&OutgoingMessage::new(group, "three seconds later"))
        .await
        .expect("the group bucket refilled one token");
    assert_eq!(http.captured().len(), 21);
}

#[pollster::test]
async fn the_global_budget_spans_chats() {
    let http = FakeHttp::scripted(vec![ok(SENT); 3]);
    let clock = clock();
    let bot = bot_with_limits(
        &http,
        &clock,
        RateLimits {
            global_per_sec: 2,
            private_chat_per_sec: 10,
            group_per_min: 100,
        },
    );

    bot.send_message(&OutgoingMessage::new(1, "one"))
        .await
        .expect("sends");
    bot.send_message(&OutgoingMessage::new(2, "two"))
        .await
        .expect("sends");
    let error = bot
        .send_message(&OutgoingMessage::new(1, "three"))
        .await
        .expect_err("the global bucket holds two per second, across chats");
    assert_eq!(
        error.retry_after(),
        Some(Duration::from_millis(500)),
        "2 per second refills one token every half second"
    );
    assert_eq!(http.captured().len(), 2);

    clock.advance(Duration::from_millis(500));
    bot.send_message(&OutgoingMessage::new(1, "four"))
        .await
        .expect("sends");
    assert_eq!(http.captured().len(), 3);
}

#[pollster::test]
async fn a_chat_bucket_refusal_does_not_spend_a_global_token() {
    // The invariant behind the budgets: a token buys an actual request. A
    // call refused on its chat's budget sends nothing, so the global token
    // it would have spent must go back — or a caller retrying one
    // chat-limited chat could drain the budget every other chat shares.
    let http = FakeHttp::scripted(vec![ok(SENT), ok(SENT)]);
    let clock = clock();
    let bot = bot_with_limits(
        &http,
        &clock,
        RateLimits {
            global_per_sec: 2,
            private_chat_per_sec: 1,
            group_per_min: 100,
        },
    );

    // Chat 1 spends one global token and its own.
    bot.send_message(&OutgoingMessage::new(1, "one"))
        .await
        .expect("sends");
    let error = bot
        .send_message(&OutgoingMessage::new(1, "refused"))
        .await
        .expect_err("chat 1 is at its one message per second");
    assert_eq!(error.retry_after(), Some(Duration::from_secs(1)));
    assert_eq!(http.captured().len(), 1, "refused before the wire");

    // The global budget still holds its second token for chat 2.
    bot.send_message(&OutgoingMessage::new(2, "two"))
        .await
        .expect("the refused call never spent the shared token");
    assert_eq!(http.captured().len(), 2);
}

#[pollster::test]
async fn answer_callback_is_scoped_by_the_global_budget_alone() {
    let http = FakeHttp::scripted(vec![ok(SENT), ok(SENT), ok(SENT)]);
    let clock = clock();
    let bot = bot(&http, &clock);

    // The chat's one-per-second token is spent by the message...
    bot.send_message(&OutgoingMessage::new(42, "spends the chat token"))
        .await
        .expect("sends");
    // ...but an answer still goes out: it is not chat-scoped.
    bot.answer_callback("cq1", Some("done"))
        .await
        .expect("sends");
    let body = captured_body(&http, 1);
    assert_eq!(body["callback_query_id"], "cq1");
    assert_eq!(body["text"], "done");

    // And an answer without a toast sends no `text` at all.
    bot.answer_callback("cq2", None).await.expect("sends");
    let body = captured_body(&http, 2);
    assert!(body.get("text").is_none(), "no toast means no text: {body}");
}

#[pollster::test]
async fn edit_delete_and_set_webhook_wire_the_expected_requests() {
    let http = FakeHttp::scripted(vec![
        ok(SENT),
        ok(SENT),
        ok(SENT),
        ok(r#"{"ok": true, "result": true}"#),
    ]);
    let clock = clock();
    let bot = bot(&http, &clock);

    bot.edit_message(42, 7, "edited", &[]).await.expect("edits");
    assert_eq!(
        captured_path(&http, 0),
        format!("{BASE}/bot{TOKEN}/editMessageText")
    );
    let body = captured_body(&http, 0);
    assert_eq!(body["chat_id"], 42);
    assert_eq!(body["message_id"], 7);
    assert_eq!(body["text"], "edited");

    // Spacing the calls past the chat's one-per-second budget keeps the
    // test on the wire shapes.
    clock.advance(Duration::from_secs(1));
    bot.delete_message(42, 7).await.expect("deletes");
    assert_eq!(
        captured_path(&http, 1),
        format!("{BASE}/bot{TOKEN}/deleteMessage")
    );
    let body = captured_body(&http, 1);
    assert_eq!(body["chat_id"], 42);
    assert_eq!(body["message_id"], 7);

    bot.set_webhook(
        "https://example.com/telegram/webhook",
        "cratefield-webhook-secret-1",
        &["message", "callback_query"],
    )
    .await
    .expect("registers");
    assert_eq!(
        captured_path(&http, 2),
        format!("{BASE}/bot{TOKEN}/setWebhook")
    );
    let body = captured_body(&http, 2);
    assert_eq!(body["url"], "https://example.com/telegram/webhook");
    assert_eq!(body["secret_token"], "cratefield-webhook-secret-1");
    assert_eq!(body["allowed_updates"][0], "message");
    assert_eq!(body["allowed_updates"][1], "callback_query");
}

#[pollster::test]
async fn statuses_map_to_the_documented_errors() {
    // (status, body, the error shape, whether the call is worth retrying)
    type ErrorCase = (
        u16,
        &'static str,
        &'static dyn Fn(&TelegramError) -> bool,
        bool,
    );
    let cases: [ErrorCase; 5] = [
        (
            401,
            ERROR_401,
            &|error: &TelegramError| matches!(error, TelegramError::Unauthorized),
            false,
        ),
        (
            403,
            ERROR_403,
            &|error: &TelegramError| matches!(error, TelegramError::Forbidden(what) if what.contains("bot was blocked")),
            false,
        ),
        (
            400,
            ERROR_400,
            &|error: &TelegramError| matches!(error, TelegramError::Invalid(what) if what.contains("message text is empty")),
            false,
        ),
        (
            404,
            r#"{"ok": false, "error_code": 404, "description": "Not Found"}"#,
            &|error: &TelegramError| matches!(error, TelegramError::Invalid(_)),
            false,
        ),
        (
            500,
            ERROR_500,
            &|error: &TelegramError| matches!(error, TelegramError::Transient(what) if what.contains("retry later")),
            true,
        ),
    ];
    for (code, body, matches_error, transient) in cases {
        let http = FakeHttp::scripted(vec![status(
            StatusCode::from_u16(code).expect("a valid status"),
            body,
        )]);
        let clock = clock();
        let bot = bot(&http, &clock);
        let error = bot
            .send_message(&OutgoingMessage::new(42, "hello"))
            .await
            .expect_err("every scripted error status must fail");
        assert!(matches_error(&error), "HTTP {code} mapped to {error:?}");
        assert_eq!(error.is_transient(), transient, "HTTP {code}: {error:?}");
    }
}

#[pollster::test]
async fn a_transport_failure_is_transient_and_scrubbed() {
    let http = FakeHttp::scripted(vec![Err(HttpError::Transport(format!(
        "connect to {BASE}/bot{TOKEN}/sendMessage failed: refused"
    )))]);
    let clock = clock();
    let bot = bot(&http, &clock);
    let error = bot
        .send_message(&OutgoingMessage::new(42, "hello"))
        .await
        .expect_err("a transport failure is an error");
    match &error {
        TelegramError::Transient(detail) => {
            assert!(detail.contains("[redacted]"), "scrubbed: {detail}");
        }
        other => panic!("expected Transient, got {other:?}"),
    }
    assert!(error.is_transient());
    assert!(!error.to_string().contains(TOKEN));
}

#[pollster::test]
async fn local_refusals_never_reach_the_wire() {
    let http = FakeHttp::scripted(vec![]);
    let clock = clock();
    let bot = bot(&http, &clock);

    let error = bot
        .send_message(&OutgoingMessage::new(42, "   "))
        .await
        .expect_err("whitespace-only text is Telegram's 400, refused here");
    assert!(matches!(&error, TelegramError::Invalid(what) if what.contains("empty")));

    // A hand-built button can carry data the constructor would have
    // refused; sending it is refused locally just the same.
    let message = OutgoingMessage::new(42, "buttons").row(vec![InlineButton {
        text: "Big".to_owned(),
        kind: ButtonKind::Callback("x".repeat(65)),
    }]);
    let error = bot
        .send_message(&message)
        .await
        .expect_err("callback_data over 64 bytes is refused");
    assert!(
        matches!(&error, TelegramError::Invalid(what) if what.contains("64 bytes")),
        "{error}"
    );

    // Same for edit_message, and for an unshaped token on any call.
    let error = bot
        .edit_message(
            42,
            7,
            "edited",
            &[vec![InlineButton {
                text: "Big".to_owned(),
                kind: ButtonKind::Callback(String::new()),
            }]],
        )
        .await
        .expect_err("empty callback_data is refused");
    assert!(matches!(error, TelegramError::Invalid(_)));
    assert!(http.captured().is_empty(), "nothing ever reached the wire");
}

#[pollster::test]
async fn an_unshaped_token_is_refused_without_sending() {
    let http = FakeHttp::scripted(vec![]);
    let clock = clock();
    let bot = HttpTelegramBot::new(
        Arc::new(http.clone()),
        Arc::new(clock),
        "bad token/with spaces",
    )
    .with_base(BASE);
    let error = bot
        .send_message(&OutgoingMessage::new(42, "hello"))
        .await
        .expect_err("a token with a space cannot ride the URL path");
    assert!(matches!(error, TelegramError::Invalid(_)));
    assert!(http.captured().is_empty());
}

#[pollster::test]
async fn the_token_never_appears_in_debug_or_display() {
    let http = FakeHttp::scripted(vec![status(StatusCode::BAD_REQUEST, ERROR_400)]);
    let clock = clock();
    let bot = bot(&http, &clock);

    assert!(
        !format!("{bot:?}").contains(TOKEN),
        "the client's Debug never carries the token"
    );

    // The 400's description comes from Telegram and cannot contain the
    // token; every error the adapter mints itself must come back scrubbed
    // too (the transport variant, whose text quotes a URI, has its own
    // test above).
    let invalid = bot
        .send_message(&OutgoingMessage::new(42, "hello"))
        .await
        .expect_err("400 maps to Invalid");
    for error in [
        invalid,
        TelegramError::Transient("connect: refused".to_owned()),
        TelegramError::RateLimited {
            retry_after: Duration::from_secs(1),
        },
        TelegramError::Unauthorized,
        TelegramError::Forbidden("blocked".to_owned()),
    ] {
        assert!(
            !format!("{error}").contains(TOKEN) && !format!("{error:?}").contains(TOKEN),
            "the token leaked through {error:?}"
        );
    }
}

#[pollster::test]
async fn the_dependency_tree_stays_wasm_safe() {
    cratefield_testing::assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
