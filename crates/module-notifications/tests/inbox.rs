//! Issue #187 acceptance: the in-app inbox.
//!
//! The rules under test, in the order they are easy to get wrong: the row
//! is written for an account push cannot reach, it commits with the
//! caller's own write, and one account's list is never another's.

mod support;

use cratefield_core::Notification;
use cratefield_module_notifications::Category;
use cratefield_module_notifications::Skipped;
use serde_json::json;
use support::{ALICE, BOB, BOOKING, COACH_NOTES, Kit, ROOM_STARTING, kit, kit_with};

const INBOX: &str = "notifications_inbox";

/// `notify` + commit, the way a caller with its own batch does it.
async fn notify_and_commit(kit: &Kit, account: &str, category: &str, title: &str) {
    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(&*db, account, category, Notification::new(title, "body"))
        .await
        .expect("notify");
    if !enqueued.statements().is_empty() {
        db.batch_atomic(enqueued.statements()).await.expect("batch");
    }
}

async fn list(kit: &Kit, account: &str, query: &str) -> serde_json::Value {
    let answer = support::send(
        &kit.harness.router,
        http::Method::GET,
        &format!("/v1/notifications{query}"),
        Some(&support::token_for(account)),
        None,
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
    answer.json()
}

#[pollster::test]
async fn an_account_with_no_device_still_gets_an_inbox_row() {
    // The whole point of the channel: push is permission-gated and this
    // is not. An account that never allowed notifications, or never
    // installed the app, still has a list to come back to.
    let kit = kit();
    notify_and_commit(&kit, ALICE, BOOKING, "Booked").await;

    assert_eq!(kit.count(INBOX).await, 1);
    let body = list(&kit, ALICE, "").await;
    assert_eq!(body["notifications"][0]["title"], "Booked");
    assert_eq!(body["notifications"][0]["category"], BOOKING);
}

#[pollster::test]
async fn a_push_opt_out_switches_off_push_and_not_the_record() {
    // `coach_notes` is `default_enabled(false)`, so push is off for an
    // account that never spoke. The inbox row is still written: the
    // account turned off the interruption, not the history.
    let kit = kit();
    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(&*db, ALICE, COACH_NOTES, Notification::new("Notes", "body"))
        .await
        .expect("notify");

    assert!(enqueued.is_empty(), "nothing is pushed");
    assert_eq!(enqueued.skipped(), Some(Skipped::PreferenceOff));
    assert!(enqueued.wrote_inbox(), "but the record is kept");

    db.batch_atomic(enqueued.statements()).await.expect("batch");
    assert_eq!(kit.count(INBOX).await, 1);
    assert_eq!(
        list(&kit, ALICE, "").await["notifications"][0]["title"],
        "Notes"
    );
}

#[pollster::test]
async fn a_category_declared_not_in_app_writes_no_row() {
    // "Your room starts in ten minutes" is worth a push and worth nothing
    // in a list read tomorrow.
    let kit = kit_with(
        std::sync::Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        vec![
            Category::new(BOOKING),
            Category::new(ROOM_STARTING).in_app(false),
        ],
        &[],
    );
    notify_and_commit(&kit, ALICE, ROOM_STARTING, "Starting").await;
    assert_eq!(kit.count(INBOX).await, 0, "declared out of the inbox");

    notify_and_commit(&kit, ALICE, BOOKING, "Booked").await;
    assert_eq!(
        kit.count(INBOX).await,
        1,
        "the sibling category still writes"
    );
}

#[pollster::test]
async fn the_row_is_atomic_with_the_callers_own_write() {
    // `notify` returns statements; nothing is written until the caller's
    // batch runs. A caller whose own write fails leaves no inbox row
    // claiming something happened.
    let kit = kit();
    let enqueued = kit
        .notifier
        .notify(
            &*kit.db(),
            ALICE,
            BOOKING,
            Notification::new("Booked", "body"),
        )
        .await
        .expect("notify");
    assert!(enqueued.wrote_inbox());
    assert_eq!(kit.count(INBOX).await, 0, "not written before the batch");
}

#[pollster::test]
async fn the_listing_is_one_accounts_own_newest_first() {
    let kit = kit();
    notify_and_commit(&kit, ALICE, BOOKING, "first").await;
    kit.clock.advance(1);
    notify_and_commit(&kit, ALICE, BOOKING, "second").await;
    notify_and_commit(&kit, BOB, BOOKING, "bob's").await;

    let body = list(&kit, ALICE, "").await;
    let titles: Vec<&str> = body["notifications"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|item| item["title"].as_str().expect("a title"))
        .collect();
    assert_eq!(
        titles,
        ["second", "first"],
        "newest first, and only Alice's"
    );
}

#[pollster::test]
async fn a_page_hands_back_a_cursor_only_while_there_is_more() {
    let kit = kit();
    for n in 0..3 {
        notify_and_commit(&kit, ALICE, BOOKING, &format!("n{n}")).await;
        kit.clock.advance(1);
    }

    let first = list(&kit, ALICE, "?limit=2").await;
    assert_eq!(first["notifications"].as_array().expect("a list").len(), 2);
    let cursor = first["cursor"].as_str().expect("a cursor").to_owned();

    let second = list(&kit, ALICE, &format!("?limit=2&cursor={cursor}")).await;
    assert_eq!(second["notifications"].as_array().expect("a list").len(), 1);
    assert!(
        second["cursor"].is_null(),
        "a short page is the last page, so the client stops without a \
         round trip that returns nothing"
    );
}

#[pollster::test]
async fn unread_count_and_the_unread_filter_agree() {
    let kit = kit();
    notify_and_commit(&kit, ALICE, BOOKING, "one").await;
    kit.clock.advance(1);
    notify_and_commit(&kit, ALICE, BOOKING, "two").await;

    let id = list(&kit, ALICE, "").await["notifications"][0]["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let read = support::send(
        &kit.harness.router,
        http::Method::POST,
        &format!("/v1/notifications/{id}/read"),
        Some(&support::token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(read.status, http::StatusCode::NO_CONTENT);

    let count = list(&kit, ALICE, "/unread-count").await;
    assert_eq!(count["unread"], 1);
    let unread = list(&kit, ALICE, "?unread=true").await;
    assert_eq!(unread["notifications"].as_array().expect("a list").len(), 1);
}

#[pollster::test]
async fn read_all_is_idempotent_and_says_how_many_moved() {
    let kit = kit();
    notify_and_commit(&kit, ALICE, BOOKING, "one").await;
    kit.clock.advance(1);
    notify_and_commit(&kit, ALICE, BOOKING, "two").await;

    let first = support::send(
        &kit.harness.router,
        http::Method::POST,
        "/v1/notifications/read-all",
        Some(&support::token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(first.json()["marked"], 2);

    let again = support::send(
        &kit.harness.router,
        http::Method::POST,
        "/v1/notifications/read-all",
        Some(&support::token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(again.json()["marked"], 0, "the second call moves nothing");
}

#[pollster::test]
async fn another_accounts_row_is_not_found_rather_than_forbidden() {
    // A 403 would confirm the id exists. The same rule the subscription
    // routes follow.
    let kit = kit();
    notify_and_commit(&kit, ALICE, BOOKING, "Alice's").await;
    let id = list(&kit, ALICE, "").await["notifications"][0]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    for (method, path) in [
        (http::Method::POST, format!("/v1/notifications/{id}/read")),
        (http::Method::DELETE, format!("/v1/notifications/{id}")),
    ] {
        let answer = support::send(
            &kit.harness.router,
            method.clone(),
            &path,
            Some(&support::token_for(BOB)),
            None,
        )
        .await;
        assert_eq!(
            answer.status,
            http::StatusCode::NOT_FOUND,
            "{method} {path}: {}",
            answer.text()
        );
    }
    // And Alice's row is untouched by the attempt.
    assert_eq!(list(&kit, ALICE, "/unread-count").await["unread"], 1);
}

#[pollster::test]
async fn an_archived_row_leaves_the_list_and_stays_in_the_table() {
    // Soft, so `fz data export` still sees it and retention can collect it.
    let kit = kit();
    notify_and_commit(&kit, ALICE, BOOKING, "Booked").await;
    let id = list(&kit, ALICE, "").await["notifications"][0]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let answer = support::send(
        &kit.harness.router,
        http::Method::DELETE,
        &format!("/v1/notifications/{id}"),
        Some(&support::token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::NO_CONTENT);

    let body = list(&kit, ALICE, "").await;
    assert!(body["notifications"].as_array().expect("a list").is_empty());
    assert_eq!(kit.count(INBOX).await, 1, "archived, not deleted");
}

#[pollster::test]
async fn every_inbox_route_refuses_a_request_with_no_token() {
    let kit = kit();
    for (method, path) in [
        (http::Method::GET, "/v1/notifications"),
        (http::Method::GET, "/v1/notifications/unread-count"),
        (http::Method::POST, "/v1/notifications/read-all"),
        (http::Method::POST, "/v1/notifications/anything/read"),
        (http::Method::DELETE, "/v1/notifications/anything"),
    ] {
        let answer = support::send(&kit.harness.router, method.clone(), path, None, None).await;
        assert_eq!(
            answer.status,
            http::StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }
}

#[pollster::test]
async fn the_data_the_inbox_keeps_is_the_data_the_push_carries() {
    // The push payload's `data.notification_id` is the fan-out id, so a
    // client that already rendered the in-app item can dedupe the push
    // that follows it.
    let kit = kit();
    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(
            &*db,
            ALICE,
            BOOKING,
            Notification {
                data: json!({ "booking": "b-1" }),
                ..Notification::new("Booked", "body")
            },
        )
        .await
        .expect("notify");
    db.batch_atomic(enqueued.statements()).await.expect("batch");

    let item = &list(&kit, ALICE, "").await["notifications"][0];
    assert_eq!(item["notification_id"], enqueued.notification_id());
    assert_eq!(item["data"]["booking"], "b-1");
    assert_eq!(
        item["data"]["notification_id"],
        enqueued.notification_id(),
        "the same prepared data the device receives"
    );
}
