//! Acceptance for the action buttons (issue #764): a tap decides a
//! pending action exactly once, a value-moving tap only arms the web
//! app's confirmation, and nothing finishes a value-moving action but the
//! confirm route behind a fresh passkey.

use std::sync::{
    Arc, RwLock,
    atomic::{AtomicUsize, Ordering},
};

use axum::http::StatusCode;
use cratefield_adapter_telegram::TelegramError;
use cratefield_adapter_telegram::fake::Call;
use cratefield_core::Clock as _;
use cratefield_core::Statement;
use cratefield_module_telegram::{
    ActionError, ActionPrompt, Decision, MAX_ACTION_TTL, TelegramEvents, action_token,
    send_action_prompt,
};
use sea_query::{Alias, Query};
use serde_json::json;

mod support;

use support::{
    ACTION_KEY, ALICE, BOB, CHAT, Calls, NOW, SECRET, TG_USER, callback, callback_from, deliver,
    insert_action, insert_link, kit, post, send_prompt,
};

/// The `on_action` hook's calls, wired for both flows.
fn action_events() -> (
    TelegramEvents,
    Calls<cratefield_module_telegram::ActionDecision>,
) {
    let calls: Calls<cratefield_module_telegram::ActionDecision> = Arc::new(RwLock::default());
    let seen = Arc::clone(&calls);
    let events = TelegramEvents::new().on_action(move |decision| {
        let seen = Arc::clone(&seen);
        Box::pin(async move {
            seen.write().expect("hook lock").push(decision);
            Ok(())
        })
    });
    (events, calls)
}

/// Mints the token the Approve (or Deny) button would carry for an
/// action — the wire form a tap replays.
fn token_for(prompt: &ActionPrompt, decision: Decision) -> String {
    let exp = u32::try_from(prompt.expires_at.unix_timestamp()).expect("in range");
    action_token(ACTION_KEY, &prompt.action_id, decision, exp, TG_USER)
}

/// An `on_action` hook that fails its **first** invocation and succeeds
/// ever after, recording every decision it was handed either way — the
/// venture whose worker was down for one delivery.
fn flaky_action_events() -> (
    TelegramEvents,
    Calls<cratefield_module_telegram::ActionDecision>,
) {
    let calls: Calls<cratefield_module_telegram::ActionDecision> = Arc::new(RwLock::default());
    let seen = Arc::clone(&calls);
    let attempts = Arc::new(AtomicUsize::new(0));
    let events = TelegramEvents::new().on_action(move |decision| {
        let seen = Arc::clone(&seen);
        let attempts = Arc::clone(&attempts);
        Box::pin(async move {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            seen.write().expect("hook lock").push(decision);
            if attempt == 0 {
                return Err("the venture's worker is down".into());
            }
            Ok(())
        })
    });
    (events, calls)
}

#[pollster::test]
async fn a_prompt_goes_to_the_linked_chat_with_two_buttons() {
    let (kit, bot) = kit(TelegramEvents::new());
    insert_link(&kit, ALICE, TG_USER, CHAT);

    let prompt = send_prompt(&kit, &bot, ALICE, false);
    let sent = bot.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].chat_id, CHAT);
    assert_eq!(sent[0].text, "Send 50 to the pool?");
    let labels: Vec<&str> = sent[0]
        .buttons
        .iter()
        .flatten()
        .map(|button| button.text.as_str())
        .collect();
    assert_eq!(labels, vec!["Approve", "Deny"]);

    // The row exists, pending, under the id the caller holds.
    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("pending")
    );
}

#[pollster::test]
async fn a_prompt_for_an_unlinked_subject_is_refused() {
    let (kit, bot) = kit(TelegramEvents::new());
    let result = support::try_send_prompt(&kit, &bot, ALICE, false);
    assert!(
        matches!(result, Err(ActionError::NotLinked)),
        "no link, no prompt: {result:?}"
    );
}

#[pollster::test]
async fn deny_decides_once_and_fires_the_hook() {
    let (events, calls) = action_events();
    let (kit, bot) = kit(events);
    insert_link(&kit, ALICE, TG_USER, CHAT);
    let prompt = send_prompt(&kit, &bot, ALICE, false);
    let deny = support::callback_data(&bot, "Deny").expect("a Deny button");

    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &support::update(1, "callback_query", callback(&deny)),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");

    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("denied")
    );
    let decisions = calls.read().expect("hook lock");
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].action_id, prompt.action_id);
    assert_eq!(decisions[0].subject, ALICE);
    assert_eq!(decisions[0].decision, Decision::Deny);
    assert!(!decisions[0].passkey_confirmed);

    // The presser's spinner stopped.
    assert!(
        bot.calls()
            .iter()
            .any(|call| matches!(call, Call::AnswerCallback { .. }))
    );
}

#[pollster::test]
async fn a_failed_hook_rolls_the_tap_back_and_the_redelivery_fires_it_once() {
    let (events, calls) = flaky_action_events();
    let (kit, bot) = kit(events);
    insert_link(&kit, ALICE, TG_USER, CHAT);
    let prompt = send_prompt(&kit, &bot, ALICE, false);
    let deny = support::callback_data(&bot, "Deny").expect("a Deny button");
    let body = support::update(30, "callback_query", callback(&deny));

    // The decision commits, the hook fails, the decision is rolled back,
    // and the `5xx` leaves the update unclaimed.
    let (status, reply) = deliver(&kit, Some(SECRET), &body).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{reply}");
    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("pending"),
        "the decision that fired no hook was rolled back"
    );

    // Telegram's redelivery runs the tap again, and the hook — healthy
    // now — gets its decision.
    let (status, reply) = deliver(&kit, Some(SECRET), &body).await;
    assert!(status.is_success(), "{status}: {reply}");
    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("denied")
    );
    assert_eq!(
        calls.read().expect("hook lock").len(),
        2,
        "the failed run and the retry both reached the hook"
    );

    // A further redelivery is a claimed no-op: the decision applied once.
    let (status, _) = deliver(&kit, Some(SECRET), &body).await;
    assert!(status.is_success());
    assert_eq!(
        calls.read().expect("hook lock").len(),
        2,
        "exactly one decision was applied"
    );
}

#[pollster::test]
async fn approve_of_a_harmless_action_is_final() {
    let (events, calls) = action_events();
    let (kit, bot) = kit(events);
    insert_link(&kit, ALICE, TG_USER, CHAT);
    let prompt = send_prompt(&kit, &bot, ALICE, false);
    let approve = support::callback_data(&bot, "Approve").expect("an Approve button");

    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &support::update(2, "callback_query", callback(&approve)),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");

    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("approved")
    );
    let decisions = calls.read().expect("hook lock");
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].decision, Decision::Approve);
    assert!(!decisions[0].passkey_confirmed);
}

#[pollster::test]
async fn approving_a_value_moving_action_only_arms_the_confirmation() {
    let (events, calls) = action_events();
    // A kit that also knows its approval URL.
    let (kit, bot) = support::kit_with(
        events,
        support::config(vec![(
            cratefield_module_telegram::APPROVAL_URL_KEY,
            "https://app.example/approvals",
        )]),
        None,
    );
    insert_link(&kit, ALICE, TG_USER, CHAT);
    let prompt = send_prompt(&kit, &bot, ALICE, true);
    let approve = support::callback_data(&bot, "Approve").expect("an Approve button");

    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &support::update(3, "callback_query", callback(&approve)),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");

    // Armed, not decided. No hook: nothing has happened yet.
    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("awaiting_passkey")
    );
    assert!(calls.read().expect("hook lock").is_empty());

    // The chat was told where to finish it.
    let url = support::button_url(&bot, "Confirm in the web app").expect("a URL button");
    assert_eq!(
        url,
        format!("https://app.example/approvals?action={}", prompt.action_id)
    );
}

#[pollster::test]
async fn the_button_joins_onto_an_approval_url_that_already_carries_a_query() {
    let (events, calls) = action_events();
    // A configured URL with a query string of its own: the action id is
    // joined with `&`, not appended as a second `?`.
    let (kit, bot) = support::kit_with(
        events,
        support::config(vec![(
            cratefield_module_telegram::APPROVAL_URL_KEY,
            "https://app.example/approvals?tenant=acme",
        )]),
        None,
    );
    insert_link(&kit, ALICE, TG_USER, CHAT);
    let prompt = send_prompt(&kit, &bot, ALICE, true);
    let approve = support::callback_data(&bot, "Approve").expect("an Approve button");

    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &support::update(13, "callback_query", callback(&approve)),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");

    let url = support::button_url(&bot, "Confirm in the web app").expect("a URL button");
    assert_eq!(
        url,
        format!(
            "https://app.example/approvals?tenant=acme&action={}",
            prompt.action_id
        )
    );
    // Still armed, still no hook: the URL's shape decides nothing else.
    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("awaiting_passkey")
    );
    assert!(calls.read().expect("hook lock").is_empty());
}

#[pollster::test]
async fn an_arm_without_an_approval_url_still_fails_closed() {
    let (events, calls) = action_events();
    // No APPROVAL_URL configured: the instructions go out without a
    // button, and the action still waits.
    let (kit, bot) = kit(events);
    insert_link(&kit, ALICE, TG_USER, CHAT);
    let prompt = send_prompt(&kit, &bot, ALICE, true);
    let approve = support::callback_data(&bot, "Approve").expect("an Approve button");

    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &support::update(4, "callback_query", callback(&approve)),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");
    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("awaiting_passkey")
    );
    assert!(calls.read().expect("hook lock").is_empty());
    assert!(support::button_url(&bot, "Confirm in the web app").is_none());
}

#[pollster::test]
async fn a_tap_by_a_different_telegram_user_is_refused() {
    let (events, calls) = action_events();
    let (kit, bot) = kit(events);
    insert_link(&kit, ALICE, TG_USER, CHAT);
    let prompt = send_prompt(&kit, &bot, ALICE, false);
    let approve = support::callback_data(&bot, "Approve").expect("an Approve button");

    // The button was forwarded; someone else pressed it.
    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &support::update(5, "callback_query", callback_from(&approve, 999)),
    )
    .await;
    assert!(status.is_success(), "the update is claimed: {reply}");

    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("pending")
    );
    assert!(calls.read().expect("hook lock").is_empty());
}

#[pollster::test]
async fn a_replayed_or_second_button_tap_is_refused() {
    let (events, calls) = action_events();
    let (kit, bot) = kit(events);
    insert_link(&kit, ALICE, TG_USER, CHAT);
    let prompt = send_prompt(&kit, &bot, ALICE, false);
    let approve = support::callback_data(&bot, "Approve").expect("an Approve button");
    let deny = support::callback_data(&bot, "Deny").expect("a Deny button");

    // The first tap decides.
    let (status, _) = deliver(
        &kit,
        Some(SECRET),
        &support::update(6, "callback_query", callback(&approve)),
    )
    .await;
    assert!(status.is_success());

    // The replay — and the other button afterwards — change nothing.
    for (id, data) in [(7, approve.as_str()), (8, deny.as_str())] {
        let (status, reply) = deliver(
            &kit,
            Some(SECRET),
            &support::update(id, "callback_query", callback(data)),
        )
        .await;
        assert!(status.is_success(), "update {id}: {reply}");
    }
    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("approved")
    );
    assert_eq!(
        calls.read().expect("hook lock").len(),
        1,
        "one decision, one hook"
    );
}

#[pollster::test]
async fn tampered_foreign_and_expired_tokens_are_refused() {
    let (events, calls) = action_events();
    let (kit, bot) = kit(events);
    insert_link(&kit, ALICE, TG_USER, CHAT);
    let prompt = send_prompt(&kit, &bot, ALICE, false);

    // A flipped byte: the tag no longer holds.
    let mut tampered = support::callback_data(&bot, "Approve")
        .expect("a token")
        .into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = tampered[last].wrapping_add(1);
    let tampered = String::from_utf8(tampered).expect("still ascii");

    // A token minted for a different Telegram user.
    let foreign = {
        let exp = u32::try_from(prompt.expires_at.unix_timestamp()).expect("in range");
        action_token(ACTION_KEY, &prompt.action_id, Decision::Approve, exp, 999)
    };

    // A token past its own expiry (the row is still young).
    let expired = {
        let exp = u32::try_from(NOW - 1).expect("in range");
        action_token(
            ACTION_KEY,
            &prompt.action_id,
            Decision::Approve,
            exp,
            TG_USER,
        )
    };

    for (id, data) in [(9, tampered), (10, foreign), (11, expired)] {
        let (status, reply) = deliver(
            &kit,
            Some(SECRET),
            &support::update(id, "callback_query", callback(&data)),
        )
        .await;
        assert!(status.is_success(), "update {id}: {reply}");
    }

    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("pending")
    );
    assert!(calls.read().expect("hook lock").is_empty());
}

#[pollster::test]
async fn a_valid_token_on_an_expired_row_is_refused() {
    let (events, calls) = action_events();
    let (kit, _bot) = kit(events);
    insert_link(&kit, ALICE, TG_USER, CHAT);

    // A pending row already past its expiry.
    insert_action(&kit, "expired-action", ALICE, "pending", false, -60);
    let exp = u32::try_from(NOW + 600).expect("in range");
    let approve = action_token(
        ACTION_KEY,
        "expired-action",
        Decision::Approve,
        exp,
        TG_USER,
    );

    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &support::update(12, "callback_query", callback(&approve)),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");
    assert_eq!(
        support::action_status(&kit, "expired-action").as_deref(),
        Some("pending")
    );
    assert!(calls.read().expect("hook lock").is_empty());
}

// ---------------------------------------------------------------------------
// The confirm route

#[pollster::test]
async fn confirm_needs_a_signed_in_owner() {
    let (kit, bot) = kit(TelegramEvents::new());
    insert_link(&kit, ALICE, TG_USER, CHAT);
    let prompt = send_prompt(&kit, &bot, ALICE, true);

    // Arm the action the honest way: tap Approve.
    let approve = token_for(&prompt, Decision::Approve);
    let (status, reply) = deliver(
        &kit,
        Some(SECRET),
        &support::update(20, "callback_query", callback(&approve)),
    )
    .await;
    assert!(status.is_success(), "{reply}");

    // Anonymous: refused before anything is read.
    let (status, body) = post(
        &kit,
        &format!("/actions/{}/confirm", prompt.action_id),
        None,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Signed in but not the owner.
    let (status, body) = post(
        &kit,
        &format!("/actions/{}/confirm", prompt.action_id),
        Some(BOB),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["title"], "Not your action");

    // Neither attempt moved the action.
    assert_eq!(
        support::action_status(&kit, &prompt.action_id).as_deref(),
        Some("awaiting_passkey")
    );
}

#[pollster::test]
async fn confirm_without_a_step_up_is_a_403_fail_closed() {
    // No `.step_up(..)` injected: no confirmation, ever.
    let (events, calls) = action_events();
    let (kit, _bot) = support::kit_with(events, support::config(vec![]), None);
    insert_action(&kit, "armed-action", ALICE, "awaiting_passkey", true, 600);

    let (status, body) = post(
        &kit,
        "/actions/armed-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["title"], "Passkey confirmation required");
    assert_eq!(
        support::action_status(&kit, "armed-action").as_deref(),
        Some("awaiting_passkey")
    );
    assert!(calls.read().expect("hook lock").is_empty());
}

#[pollster::test]
async fn confirm_refuses_a_pending_an_unknown_and_a_foreign_action() {
    let (kit, _bot) = kit(TelegramEvents::new());
    insert_action(&kit, "pending-action", ALICE, "pending", true, 600);
    insert_action(&kit, "armed-action", ALICE, "awaiting_passkey", true, 600);

    // A pending action has nothing to confirm.
    let (status, body) = post(
        &kit,
        "/actions/pending-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["title"], "Action cannot be confirmed");

    // Not the owner: 403 before the step-up is even asked.
    let (status, body) = post(&kit, "/actions/armed-action/confirm", Some(BOB), json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["title"], "Not your action");

    let (status, body) = post(&kit, "/actions/nope/confirm", Some(ALICE), json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[pollster::test]
async fn a_fresh_passkey_confirms_a_value_moving_action() {
    let (events, calls) = action_events();
    let (kit, _bot) = kit(events);
    insert_action(&kit, "armed-action", ALICE, "awaiting_passkey", true, 600);

    let (status, body) = post(
        &kit,
        "/actions/armed-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;
    assert!(status.is_success(), "{status}: {body}");
    assert_eq!(body["status"], "approved");

    assert_eq!(
        support::action_status(&kit, "armed-action").as_deref(),
        Some("approved")
    );
    let decisions = calls.read().expect("hook lock");
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].decision, Decision::Approve);
    assert!(decisions[0].passkey_confirmed, "the whole point");
    assert_eq!(decisions[0].subject, ALICE);
    assert_eq!(decisions[0].action, "transfer");
}

#[pollster::test]
async fn a_stale_passkey_leaves_the_action_armed() {
    let (events, calls) = action_events();
    let (kit, _bot) = support::kit_with(
        events,
        support::config(vec![]),
        Some(support::FakeStepUp::refusing()),
    );
    insert_action(&kit, "armed-action", ALICE, "awaiting_passkey", true, 600);

    let (status, body) = post(
        &kit,
        "/actions/armed-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        support::action_status(&kit, "armed-action").as_deref(),
        Some("awaiting_passkey")
    );
    assert!(calls.read().expect("hook lock").is_empty());
}

#[pollster::test]
async fn confirming_twice_is_refused() {
    let (events, calls) = action_events();
    let (kit, _bot) = kit(events);
    insert_action(&kit, "armed-action", ALICE, "awaiting_passkey", true, 600);

    let (status, _) = post(
        &kit,
        "/actions/armed-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;
    assert!(status.is_success());

    // The retry — a double click, a reloaded page — is refused: the
    // conditional update saw no row in `awaiting_passkey` to move.
    let (status, body) = post(
        &kit,
        "/actions/armed-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        calls.read().expect("hook lock").len(),
        1,
        "one confirmation, one hook"
    );
}

#[pollster::test]
async fn a_failed_confirm_hook_rolls_back_and_the_retry_fires_it_once() {
    let (events, calls) = flaky_action_events();
    let (kit, _bot) = kit(events);
    insert_action(&kit, "armed-action", ALICE, "awaiting_passkey", true, 600);

    // The confirmation commits, the hook fails, and the route rolls the
    // action back — the `5xx` tells the caller to try again.
    let (status, reply) = post(
        &kit,
        "/actions/armed-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{reply}");
    assert_eq!(
        support::action_status(&kit, "armed-action").as_deref(),
        Some("awaiting_passkey"),
        "the approval that fired no hook was rolled back"
    );

    // The retry starts again from `awaiting_passkey` and succeeds.
    let (status, reply) = post(
        &kit,
        "/actions/armed-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;
    assert!(status.is_success(), "{status}: {reply}");
    assert_eq!(
        support::action_status(&kit, "armed-action").as_deref(),
        Some("approved")
    );
    assert_eq!(
        calls.read().expect("hook lock").len(),
        2,
        "the failed run and the retry both reached the hook"
    );

    // A third confirm is refused: the decision applied once.
    let (status, _) = post(
        &kit,
        "/actions/armed-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        calls.read().expect("hook lock").len(),
        2,
        "exactly one decision was applied"
    );
}

#[pollster::test]
async fn an_expired_action_cannot_be_confirmed() {
    let (events, _calls) = action_events();
    let (kit, _bot) = kit(events);
    insert_action(&kit, "late-action", ALICE, "awaiting_passkey", true, -60);

    let (status, body) = post(&kit, "/actions/late-action/confirm", Some(ALICE), json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

// ---------------------------------------------------------------------------
// The prompt's edges

#[pollster::test]
async fn the_prompt_ttl_is_capped_at_an_hour() {
    use std::time::Duration;

    let (kit, bot) = kit(TelegramEvents::new());
    insert_link(&kit, ALICE, TG_USER, CHAT);

    // Ten hours asked for; one hour granted.
    let prompt = pollster::block_on(send_action_prompt(
        &*kit.db,
        &kit.clock,
        &support::FixedRandom(0xA5),
        bot.as_ref(),
        ACTION_KEY,
        cratefield_module_telegram::ActionRequest {
            subject: ALICE.to_owned(),
            action: "transfer".to_owned(),
            text: "Too long".to_owned(),
            value_moving: false,
            ttl: Duration::from_secs(3_600),
        },
    ))
    .expect("the prompt sends");
    let granted = prompt.expires_at.unix_timestamp() - kit.clock.now().unix_timestamp();
    assert!(
        granted <= MAX_ACTION_TTL.whole_seconds() && granted > MAX_ACTION_TTL.whole_seconds() - 5,
        "the hour cap held: {granted}s"
    );

    // An unrepresentable TTL is clamped to the cap, not panicked on.
    // A different draw: the first prompt already spent 0xA5's id.
    let prompt = pollster::block_on(send_action_prompt(
        &*kit.db,
        &kit.clock,
        &support::FixedRandom(0x5A),
        bot.as_ref(),
        ACTION_KEY,
        cratefield_module_telegram::ActionRequest {
            subject: ALICE.to_owned(),
            action: "transfer".to_owned(),
            text: "Still fine".to_owned(),
            value_moving: false,
            ttl: Duration::from_secs(u64::MAX),
        },
    ))
    .expect("the prompt sends");
    assert!(prompt.expires_at > kit.clock.now());
}

#[pollster::test]
async fn a_failed_send_leaves_a_pending_row_behind() {
    // The row is inserted before the send, so a Telegram failure leaves a
    // pending row that expires rather than an unrecorded consent.
    let (kit, bot) = kit(TelegramEvents::new());
    insert_link(&kit, ALICE, TG_USER, CHAT);
    bot.fail_next(TelegramError::RateLimited {
        retry_after: std::time::Duration::from_secs(5),
    });

    let result = support::try_send_prompt(&kit, &bot, ALICE, false);
    assert!(matches!(
        result,
        Err(ActionError::Telegram(TelegramError::RateLimited { .. }))
    ));

    // The pending row exists under some id the caller was never told.
    let mut select = Query::select();
    select
        .column(Alias::new("action_id"))
        .from(Alias::new("telegram_actions"));
    let rows = pollster::block_on(kit.db.query(&Statement::render(&select))).expect("actions read");
    assert_eq!(rows.len(), 1, "the pending row survived the failed send");
}
