//! Issue #232 acceptance: a burst past the cooldown cap coalesces into one
//! summary mail once the window has rolled.
//!
//! The three traps, each with its own test: a suppressed notification
//! leaves a trace (the burst exists to be found), the summary re-checks
//! what a normal send re-checks (an unsubscribe that lands mid-window kills
//! the summary), and the summary is sent once per window (a second tick
//! finds nothing to send).

mod support;

use cratefield_core::Notification;
use cratefield_module_notifications::Category;
use serde_json::json;
use support::{ALICE, BOOKING, Kit, kit_with};

const CAP: &str = "5";
const WINDOW: i64 = 3_600;

fn summary_kit() -> Kit {
    kit_with(
        std::sync::Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        vec![Category::new(BOOKING).email(true)],
        &[("NOTIFICATIONS_EMAIL_MAX_PER_WINDOW", CAP)],
    )
}

async fn set_email(kit: &Kit, address: &str) {
    let token = support::token_for_verified_email(ALICE, address);
    let answer = support::send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/email",
        Some(&token),
        Some(json!({ "email": address })),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
}

async fn notify_and_drain(kit: &Kit) {
    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(&*db, ALICE, BOOKING, Notification::new("Booked", "Tuesday"))
        .await
        .expect("notify");
    if !enqueued.statements().is_empty() {
        db.batch(enqueued.statements()).await.expect("batch");
    }
    kit.notifier.drain(&kit.scope()).await.expect("drain");
}

/// `n` notifications spread a second apart, inside one window.
async fn burst(kit: &Kit, n: usize) {
    for _ in 0..n {
        notify_and_drain(kit).await;
        kit.clock.advance(1);
    }
}

#[pollster::test]
async fn eight_notifies_in_one_window_become_five_mails_plus_one_summary() {
    let kit = summary_kit();
    set_email(&kit, "alice@example.test").await;
    burst(&kit, 8).await;

    assert_eq!(
        kit.harness.mailer.sent().len(),
        5,
        "the cap held inside the window"
    );
    assert_eq!(
        kit.count("notifications_email_suppressed").await,
        3,
        "and the suppressed ones left the trace the summary is found by"
    );

    kit.clock.advance(WINDOW);
    kit.notifier.drain(&kit.scope()).await.expect("drain");

    assert_eq!(
        kit.harness.mailer.sent().len(),
        6,
        "one summary, not a replay of the burst"
    );
    let summary = kit.harness.mailer.last_message().expect("the summary");
    assert_eq!(summary.to, "alice@example.test");
    assert_eq!(summary.subject, "3 new booking notifications");
    assert_eq!(
        kit.count("notifications_email_suppressed").await,
        0,
        "the burst is spent with the summary"
    );

    // The whole point of the idempotency key: a second scheduled tick
    // must be a no-op, not a second copy of the same news.
    kit.clock.advance(60);
    kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(
        kit.harness.mailer.sent().len(),
        6,
        "the second tick sends nothing"
    );
}

#[pollster::test]
async fn an_unsubscribe_that_lands_during_the_window_means_no_summary() {
    let kit = summary_kit();
    set_email(&kit, "alice@example.test").await;
    burst(&kit, 6).await;
    assert_eq!(kit.harness.mailer.sent().len(), 5);
    assert_eq!(kit.count("notifications_email_suppressed").await, 1);

    // One-click off the category, the way the RFC 8058 POST does it.
    let mail = kit.harness.mailer.last_message().expect("one mail");
    let link = mail
        .headers
        .iter()
        .find(|(key, _)| key == "List-Unsubscribe")
        .map(|(_, value)| value.trim_matches(['<', '>']).to_owned())
        .expect("a link");
    let path = link.split_once("/v1").expect("absolute").1;
    let answer = support::send(
        &kit.harness.router,
        http::Method::POST,
        &format!("/v1{path}"),
        None,
        None,
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());

    kit.clock.advance(WINDOW);
    kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(
        kit.harness.mailer.sent().len(),
        5,
        "a summary announcing mail the account opted out of is the flood in miniature"
    );
    assert_eq!(
        kit.count("notifications_email_suppressed").await,
        0,
        "and the burst is not left to summarise on some later tick"
    );
}

#[pollster::test]
async fn a_window_that_has_not_rolled_yet_summary_waits() {
    // The window closes when the cap's worth of sends have aged out of it,
    // not when the burst merely got old enough to ask again. Ticking early
    // must leave the summary unsent — and still sendable later.
    let kit = summary_kit();
    set_email(&kit, "alice@example.test").await;
    burst(&kit, 8).await;

    kit.clock.advance(600);
    kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(
        kit.harness.mailer.sent().len(),
        5,
        "the window is still full"
    );

    kit.clock.advance(WINDOW);
    kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(kit.harness.mailer.sent().len(), 6, "it fires once due");
}

#[pollster::test]
async fn the_summary_counts_against_the_next_window() {
    // The summary is mail actually sent, so it is a row in the send
    // window like any other — the acceptance from #189 counts mail, and a
    // summary is mail.
    let kit = summary_kit();
    set_email(&kit, "alice@example.test").await;
    burst(&kit, 8).await;
    kit.clock.advance(WINDOW);
    kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(kit.harness.mailer.sent().len(), 6);

    // A fresh burst in the new window: four more mails fit beside the
    // summary (cap 5), the fifth is suppressed again.
    burst(&kit, 5).await;
    assert_eq!(
        kit.harness.mailer.sent().len(),
        6 + 4,
        "the summary mail shares the budget it created room in"
    );
    assert_eq!(
        kit.count("notifications_email_suppressed").await,
        1,
        "and the overflow of the second burst is traced like the first"
    );
}
