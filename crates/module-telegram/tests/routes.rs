//! Acceptance for the Telegram module's routes (issue #764): the webhook
//! refuses what does not verify and fails closed without its secret,
//! deduplicates on the update id, dispatches each update kind to its
//! hook, and a failed hook leaves the key unclaimed so Telegram's retry
//! re-runs it. The linking flow: a code issued to a signed-in subject is
//! stored only as a hash, links once, and refuses a second performance.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use axum::http::StatusCode;
use cratefield_core::Statement;
use cratefield_module_telegram::{Linked, TelegramEvents, WEBHOOK_SECRET_KEY};
use sea_query::{Alias, Query};
use serde_json::Value;
use sha2::{Digest, Sha256};

mod support;

use support::{
    ALICE, BOB, CHAT, Calls, SECRET, TG_USER, code_consumed_at, command, deliver, group_command,
    kit, kit_with, linked_subjects, message, post, stored_code_hashes, update,
};

fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

#[pollster::test]
async fn an_unverified_delivery_is_refused_before_anything_runs() {
    let (kit, bot) = kit(TelegramEvents::new());

    // No header at all.
    let (status, body) = deliver(&kit, None, &update(1, "message", message("hi"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    // The right shape, the wrong secret.
    let (status, body) = deliver(
        &kit,
        Some("not-the-secret"),
        &update(1, "message", message("hi")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // The refusal says the delivery did not verify, and nothing else.
    assert_eq!(body["title"], "Unverified delivery");

    // No effect anywhere: the ledger is empty and the bot was not asked
    // for so much as an acknowledgement.
    assert!(
        bot.sent().is_empty() && bot.calls().is_empty(),
        "an unverified delivery must have no effects"
    );
    assert!(stored_code_hashes(&kit).is_empty());
}

#[pollster::test]
async fn a_verified_but_malformed_body_is_a_400() {
    let (kit, bot) = kit(TelegramEvents::new());
    let (status, body) = deliver(&kit, Some(SECRET), b"{not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(bot.calls().is_empty());
}

#[pollster::test]
async fn without_a_configured_secret_every_delivery_fails_closed() {
    // The kit composes the module with no webhook secret at all.
    let (kit, _bot) = kit_with(
        TelegramEvents::new(),
        vec![], // no WEBHOOK_SECRET_KEY: nothing can verify
        None,
    );
    // Even a delivery carrying what would have been the right token is a
    // `503`: there is nothing to check it against, and serving it anyway
    // would trust whoever knows to set a header.
    let (status, body) = deliver(&kit, Some(SECRET), &update(1, "message", message("hi"))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["title"], "Service not ready");
}

#[pollster::test]
async fn a_redelivery_is_a_no_op() {
    let messages: Calls<cratefield_adapter_telegram::Message> = Arc::new(RwLock::default());
    let seen = Arc::clone(&messages);
    let events = TelegramEvents::new().on_message(move |message| {
        let seen = Arc::clone(&seen);
        Box::pin(async move {
            seen.write().expect("hook lock").push(message);
            Ok(())
        })
    });
    let (kit, _bot) = kit(events);

    let body = update(7, "message", message("once"));
    let (status, reply) = deliver(&kit, Some(SECRET), &body).await;
    assert!(status.is_success(), "{status}: {reply}");
    let (status, reply) = deliver(&kit, Some(SECRET), &body).await;
    assert!(status.is_success(), "the redelivery answers 200: {reply}");

    assert_eq!(
        messages.read().expect("hook lock").len(),
        1,
        "Telegram redelivers; the ledger deduplicates"
    );
}

#[pollster::test]
async fn each_update_kind_reaches_its_own_hook() {
    let messages: Calls<cratefield_adapter_telegram::Message> = Arc::new(RwLock::default());
    let commands: Calls<cratefield_adapter_telegram::Command> = Arc::new(RwLock::default());
    let callbacks: Calls<cratefield_adapter_telegram::CallbackQuery> = Arc::new(RwLock::default());
    let posts: Calls<cratefield_adapter_telegram::ChannelPost> = Arc::new(RwLock::default());

    let (m, c, cb, p) = (
        Arc::clone(&messages),
        Arc::clone(&commands),
        Arc::clone(&callbacks),
        Arc::clone(&posts),
    );
    let events = TelegramEvents::new()
        .on_message(move |message| {
            let m = Arc::clone(&m);
            Box::pin(async move {
                m.write().expect("hook lock").push(message);
                Ok(())
            })
        })
        .on_command(move |command| {
            let c = Arc::clone(&c);
            Box::pin(async move {
                c.write().expect("hook lock").push(command);
                Ok(())
            })
        })
        .on_callback(move |callback| {
            let cb = Arc::clone(&cb);
            Box::pin(async move {
                cb.write().expect("hook lock").push(callback);
                Ok(())
            })
        })
        .on_channel_post(move |posted| {
            let p = Arc::clone(&p);
            Box::pin(async move {
                p.write().expect("hook lock").push(posted);
                Ok(())
            })
        });
    let (kit, _bot) = kit(events);

    for (id, body) in [
        (1u64, update(1, "message", message("hello"))),
        (2, update(2, "message", command("/help me"))),
        (
            3,
            update(3, "callback_query", support::callback("deploy:ack")),
        ),
        (
            4,
            update(4, "channel_post", support::channel_post("shipping")),
        ),
    ] {
        let (status, reply) = deliver(&kit, Some(SECRET), &body).await;
        assert!(status.is_success(), "update {id}: {status}: {reply}");
    }

    assert_eq!(messages.read().expect("hook lock").len(), 1);
    assert_eq!(commands.read().expect("hook lock").len(), 1);
    assert_eq!(callbacks.read().expect("hook lock").len(), 1);
    assert_eq!(posts.read().expect("hook lock").len(), 1);
    let commands = commands.read().expect("hook lock");
    assert_eq!(commands[0].name, "help");
    assert_eq!(commands[0].args, "me");
    let callbacks = callbacks.read().expect("hook lock");
    assert_eq!(callbacks[0].data.as_deref(), Some("deploy:ack"));
}

#[pollster::test]
async fn a_start_with_a_code_links_instead_of_reaching_the_command_hook() {
    let commands: Calls<cratefield_adapter_telegram::Command> = Arc::new(RwLock::default());
    let linked: Calls<Linked> = Arc::new(RwLock::default());
    let (c, l) = (Arc::clone(&commands), Arc::clone(&linked));
    let events = TelegramEvents::new()
        .on_command(move |command| {
            let c = Arc::clone(&c);
            Box::pin(async move {
                c.write().expect("hook lock").push(command);
                Ok(())
            })
        })
        .on_linked(move |linked| {
            let l = Arc::clone(&l);
            Box::pin(async move {
                l.write().expect("hook lock").push(linked);
                Ok(())
            })
        });
    let (kit, bot) = kit(events);

    // The signed-in app asks for a code.
    let (status, body) = post(&kit, "/link-codes", Some(ALICE), Value::Null).await;
    assert!(status.is_success(), "{status}: {body}");
    let code = body["code"]
        .as_str()
        .expect("a code is answered")
        .to_owned();

    // The person pastes it into a private chat.
    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &update(5, "message", command(&format!("/start {code}"))),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");

    // The link, not the command hook, took it.
    assert!(commands.read().expect("hook lock").is_empty());
    let links = linked.read().expect("hook lock");
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].subject, ALICE);
    assert_eq!(links[0].telegram_user_id, TG_USER);
    assert_eq!(links[0].chat_id, CHAT);
    assert_eq!(linked_subjects(&kit), vec![(ALICE.to_owned(), TG_USER)]);

    // And the chat heard about it.
    let sent = bot.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].chat_id, CHAT);
    assert_eq!(sent[0].text, "linked");
}

#[pollster::test]
async fn a_start_from_a_group_never_links() {
    let linked: Calls<Linked> = Arc::new(RwLock::default());
    let seen = Arc::clone(&linked);
    let events = TelegramEvents::new().on_linked(move |linked| {
        let seen = Arc::clone(&seen);
        Box::pin(async move {
            seen.write().expect("hook lock").push(linked);
            Ok(())
        })
    });
    let (kit, bot) = kit(events);

    let (status, body) = post(&kit, "/link-codes", Some(ALICE), Value::Null).await;
    assert!(status.is_success(), "{status}: {body}");
    let code = body["code"].as_str().expect("a code").to_owned();

    // Pasted into a group: a command like any other, refused as a link —
    // and surfaced to the venture's command hook instead.
    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &update(6, "message", group_command(&format!("/start {code}"))),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");
    assert!(linked.read().expect("hook lock").is_empty());
    assert!(linked_subjects(&kit).is_empty());
    assert!(
        bot.sent().is_empty(),
        "the group hears nothing from the linking flow"
    );
}

#[pollster::test]
async fn a_code_works_once_and_stores_only_a_hash() {
    let (kit, bot) = kit(TelegramEvents::new());

    let (status, body) = post(&kit, "/link-codes", Some(ALICE), Value::Null).await;
    assert!(status.is_success(), "{status}: {body}");
    let code = body["code"].as_str().expect("a code").to_owned();

    // The database holds the SHA-256 of the code — never the code.
    let hashes = stored_code_hashes(&kit);
    assert_eq!(hashes, vec![sha256_hex(&code)]);
    assert!(
        !hashes[0].contains(&code) && code != hashes[0],
        "the code itself must not sit in the table"
    );

    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &update(10, "message", command(&format!("/start {code}"))),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");
    assert_eq!(linked_subjects(&kit), vec![(ALICE.to_owned(), TG_USER)]);

    // A second performance of the same code: claimed (so Telegram is not
    // asked again), but no link is made twice.
    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &update(11, "message", command(&format!("/start {code}"))),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");
    assert_eq!(linked_subjects(&kit).len(), 1);
    let sent = bot.sent();
    assert!(
        sent.last().is_some_and(|message| message.text != "linked"),
        "the second performance is refused in the chat: {:?}",
        sent.last().map(|message| &message.text)
    );
}

#[pollster::test]
async fn an_expired_code_is_refused() {
    let (kit, bot) = kit(TelegramEvents::new());

    // A code already past its expiry, as the store would hold one.
    let mut insert = Query::insert();
    insert
        .into_table(Alias::new("telegram_link_codes"))
        .columns(["code_hash", "subject", "expires_at"])
        .values_panic([
            sha256_hex("stale-code").into(),
            ALICE.into(),
            support::rfc3339(support::NOW - 1).into(),
        ]);
    pollster::block_on(kit.db.execute(&Statement::render(&insert)))
        .expect("the expired code inserts");

    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &update(12, "message", command("/start stale-code")),
    )
    .await;
    assert!(status.is_success(), "the update is still claimed: {reply}");
    assert!(linked_subjects(&kit).is_empty());
    assert!(
        bot.sent()
            .last()
            .is_some_and(|message| message.text.contains("expired")),
        "the chat is told the code is no good"
    );
}

#[pollster::test]
async fn a_telegram_user_already_linked_elsewhere_is_refused_out_loud() {
    let (kit, bot) = kit(TelegramEvents::new());

    // BOB holds the link to Telegram user 42.
    support::insert_link(&kit, BOB, TG_USER, CHAT);

    // ALICE's code is pasted by the same Telegram user.
    let (status, body) = post(&kit, "/link-codes", Some(ALICE), Value::Null).await;
    assert!(status.is_success(), "{status}: {body}");
    let code = body["code"].as_str().expect("a code").to_owned();
    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &update(13, "message", command(&format!("/start {code}"))),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");

    // Nobody was silently repointed: BOB keeps the link, ALICE has none.
    assert_eq!(linked_subjects(&kit), vec![(BOB.to_owned(), TG_USER)]);
    let sent = bot.sent();
    assert!(
        sent.last()
            .is_some_and(|message| message.text.contains("already linked")),
        "the refusal is said in the chat: {:?}",
        sent.last().map(|message| &message.text)
    );
}

#[pollster::test]
async fn link_codes_name_the_bot_when_a_username_is_set() {
    let (kit, _bot) = kit_with(
        TelegramEvents::new(),
        support::config(vec![
            (WEBHOOK_SECRET_KEY, SECRET),
            ("TELEGRAM_ACTION_SECRET", "tg-test-action-secret"),
            ("TELEGRAM_BOT_USERNAME", "sealb_bot"),
        ]),
        None,
    );
    let (status, body) = post(&kit, "/link-codes", Some(ALICE), Value::Null).await;
    assert!(status.is_success(), "{status}: {body}");
    let code = body["code"].as_str().expect("a code");
    assert_eq!(
        body["deep_link"].as_str(),
        Some(&format!("https://t.me/sealb_bot?start={code}")[..]),
        "the deep link names the configured bot"
    );
}

#[pollster::test]
async fn link_codes_need_a_signed_in_caller() {
    let (kit, _bot) = kit(TelegramEvents::new());

    let (status, body) = post(&kit, "/link-codes", None, Value::Null).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["title"], "Sign in first");

    // Signed in, the code arrives with an expiry.
    let (status, body) = post(&kit, "/link-codes", Some(ALICE), Value::Null).await;
    assert!(status.is_success(), "{status}: {body}");
    assert_eq!(body["code"].as_str().map(str::len), Some(43), "{body}");
    assert!(body["expires_at"].is_string());

    // The code links its own subject when performed.
    let code = body["code"].as_str().expect("a code").to_owned();
    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &update(14, "message", command(&format!("/start {code}"))),
    )
    .await;
    assert!(status.is_success(), "{reply}");
    assert_eq!(
        linked_subjects(&kit),
        vec![(ALICE.to_owned(), TG_USER)],
        "the code linked ALICE, its own subject"
    );
}

#[pollster::test]
async fn delete_link_removes_the_link_and_is_idempotent() {
    let (kit, _bot) = kit(TelegramEvents::new());
    support::insert_link(&kit, ALICE, TG_USER, CHAT);

    let (status, body) = support::delete(&kit, "/link", Some(ALICE)).await;
    assert!(status.is_success(), "{body}");
    assert!(linked_subjects(&kit).is_empty());

    // Again: still fine, still 200.
    let (status, body) = support::delete(&kit, "/link", Some(ALICE)).await;
    assert!(status.is_success(), "{body}");
}

#[pollster::test]
async fn a_hook_failure_is_a_5xx_and_the_redelivery_re_runs_it() {
    let commands: Calls<cratefield_adapter_telegram::Command> = Arc::new(RwLock::default());
    let fail = Arc::new(AtomicBool::new(true));
    let seen = Arc::clone(&commands);
    let fail_for_hook = Arc::clone(&fail);
    let events = TelegramEvents::new().on_command(move |command| {
        let seen = Arc::clone(&seen);
        let fail = Arc::clone(&fail_for_hook);
        Box::pin(async move {
            seen.write().expect("hook lock").push(command);
            if fail.load(Ordering::SeqCst) {
                return Err("the venture's command worker is down".into());
            }
            Ok(())
        })
    });
    let (kit, _bot) = kit(events);

    let body = update(20, "message", command("/deploy now"));
    let (status, reply) = deliver(&kit, Some(SECRET), &body).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{reply}");

    // The venture recovers; Telegram's redelivery re-runs the hook.
    fail.store(false, Ordering::SeqCst);
    let (status, reply) = deliver(&kit, Some(SECRET), &body).await;
    assert!(status.is_success(), "{status}: {reply}");
    assert_eq!(
        commands.read().expect("hook lock").len(),
        2,
        "the failed run and the redelivery both reached the hook"
    );
}

#[pollster::test]
async fn a_failed_on_linked_puts_the_code_back_and_the_redelivery_links_again() {
    let linked: Calls<Linked> = Arc::new(RwLock::default());
    let seen = Arc::clone(&linked);
    let attempts = Arc::new(AtomicUsize::new(0));
    let fail_for_hook = Arc::clone(&attempts);
    let events = TelegramEvents::new().on_linked(move |linked| {
        let seen = Arc::clone(&seen);
        let attempts = Arc::clone(&fail_for_hook);
        Box::pin(async move {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            seen.write().expect("hook lock").push(linked);
            if attempt == 0 {
                return Err("the venture's linking worker is down".into());
            }
            Ok(())
        })
    });
    let (kit, bot) = kit(events);

    let (_status, body) = post(&kit, "/link-codes", Some(ALICE), Value::Null).await;
    let code = body["code"].as_str().expect("a code").to_owned();
    let body = update(40, "message", command(&format!("/start {code}")));

    // The link commits, `on_linked` fails, and the code is put back so
    // the delivery can be retried.
    let (status, reply) = deliver(&kit, Some(SECRET), &body).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{reply}");
    assert_eq!(
        linked_subjects(&kit),
        vec![(ALICE.to_owned(), TG_USER)],
        "the link row itself is not undone"
    );
    assert!(
        code_consumed_at(&kit, &code).is_none(),
        "the spent code was put back for the redelivery"
    );

    // The redelivery re-runs the whole flow: consume again, upsert the
    // same link again, and the hook — healthy now — hears about it.
    let (status, reply) = deliver(&kit, Some(SECRET), &body).await;
    assert!(status.is_success(), "{status}: {reply}");
    {
        let heard = linked.read().expect("hook lock");
        assert_eq!(heard.len(), 2, "the failed run and the retry both fired");
        assert_eq!(heard[1].subject, ALICE);
        assert_eq!(heard[1].telegram_user_id, TG_USER);
    }
    assert_eq!(
        linked_subjects(&kit),
        vec![(ALICE.to_owned(), TG_USER)],
        "still one link row"
    );
    assert!(
        code_consumed_at(&kit, &code).is_some(),
        "the retry spent the code again"
    );

    // A further redelivery is a claimed no-op, and a second performance
    // under a fresh update id is refused: the code is spent for good.
    let (status, _) = deliver(&kit, Some(SECRET), &body).await;
    assert!(status.is_success());
    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &update(41, "message", command(&format!("/start {code}"))),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");
    assert_eq!(
        linked.read().expect("hook lock").len(),
        2,
        "exactly one linking was applied"
    );
    assert!(
        bot.sent()
            .last()
            .is_some_and(|message| message.text != "linked"),
        "the replay is refused in the chat"
    );
}

#[pollster::test]
async fn updates_the_adapter_does_not_model_are_claimed_quietly() {
    let (kit, _bot) = kit(TelegramEvents::new());
    // `edited_message`: a real Telegram payload this adapter maps to
    // `Other`. Claimed without an effect, so the redelivery is a no-op.
    let body = update(
        30,
        "edited_message",
        serde_json::json!({
            "message_id": 11,
            "chat": { "id": CHAT, "type": "private" },
            "from": { "id": TG_USER, "is_bot": false, "first_name": "Ada" },
            "date": support::NOW,
            "text": "hello, edited",
        }),
    );
    let (status, reply) = deliver(&kit, Some(SECRET), &body).await;
    assert!(status.is_success(), "{status}: {reply}");
    let (status, _) = deliver(&kit, Some(SECRET), &body).await;
    assert!(status.is_success());
}
