//! Issue #244: the declarations, proved against the module that reads them.
//!
//! `Module::personal_data()` is a promise about behaviour that lives in
//! another crate — `cratefield-module-privacy` plans an export and an erasure
//! from it — so asserting the list against itself would prove nothing. These
//! tests compose the two modules the way a venture does and exercise the
//! routes: what the export hands over, what it refuses to copy, and what
//! survives an erasure.
//!
//! The gap this closes was invisible for exactly that reason. Every table was
//! declared in `tables()`, which is what `fz data export` reads, so a whole-
//! database move carried all eight; erasure reads a different list, which was
//! empty, and a subject access request ran straight past the stored address,
//! the device tokens and the inbox.

mod support;

use std::sync::Arc;

use cratefield_core::{Config, MapConfig, PushError, Statement};
use cratefield_module_notifications::{Category, Notifications, Notifier};
use cratefield_module_privacy::Privacy;
use cratefield_testing::TestHarness;
use serde_json::{Value, json};
use support::{ALICE, BOB, BOOKING};

const ADMIN: &str = "test-admin-token-0123456789abcdef";

/// A live Web Push endpoint, the shape a browser hands over. It is a bearer
/// capability: whoever holds it can push to that browser, which is why it is
/// the one column the export must not copy (ADR 0015).
const ENDPOINT: &str = "https://push.example.test/send/abc123-secret-capability";

/// Every table the module owns, in declaration order, so a failure names the
/// table rather than a row count.
const TABLES: &[&str] = &[
    "notifications_subscriptions",
    "notifications_preferences",
    "notifications_locales",
    "notifications_inbox",
    "notifications_email_targets",
    "notifications_email_sends",
    "notifications_dead_letters",
    "notifications_email_suppressed",
];

/// The two modules a venture composes to answer a data-subject request, over
/// one database.
fn privacy_kit() -> TestHarness {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
        (
            "HARNESS_SECRET".to_owned(),
            "cratefield-testing-dummy-secret-0123456789".to_owned(),
        ),
        (
            "NOTIFICATIONS_AUTH_ISSUER".to_owned(),
            support::ISSUER.to_owned(),
        ),
        (
            "NOTIFICATIONS_AUTH_CLIENT_ID".to_owned(),
            support::CLIENT.to_owned(),
        ),
    ]));
    TestHarness::with_ports(
        vec![
            Box::new(Notifications::new().category(Category::new(BOOKING))),
            Box::new(Privacy::new()),
        ],
        move |ports| {
            ports.config = Arc::clone(&config);
        },
    )
}

/// One row of everything, for one account. Written straight to the database:
/// the point under test is what the declarations reach, not how the rows got
/// there, and the routes that write them are covered elsewhere.
async fn seed(kit: &TestHarness, account: &str, endpoint: &str) {
    let recipient =
        json!({ "web_push": { "endpoint": endpoint, "p256dh": "k", "auth": "a" } }).to_string();
    let rows: Vec<(&str, &str, Vec<sea_query::Value>)> = vec![
        (
            "notifications_subscriptions",
            "INSERT INTO notifications_subscriptions (id, account_id, transport, recipient_json, \
             recipient_hash, created_at, last_seen_at) VALUES (?, ?, 'webpush', ?, ?, ?, ?)",
            vec![
                format!("sub-{account}").into(),
                account.into(),
                recipient.into(),
                format!("hash-{account}").into(),
                "2026-01-01T00:00:00Z".into(),
                "2026-01-01T00:00:00Z".into(),
            ],
        ),
        (
            "notifications_preferences",
            "INSERT INTO notifications_preferences (account_id, category, push, in_app, email, \
             updated_at) VALUES (?, ?, 1, 1, 1, ?)",
            vec![
                account.into(),
                BOOKING.into(),
                "2026-01-01T00:00:00Z".into(),
            ],
        ),
        (
            "notifications_locales",
            "INSERT INTO notifications_locales (account_id, locale, updated_at) VALUES (?, 'en', ?)",
            vec![account.into(), "2026-01-01T00:00:00Z".into()],
        ),
        (
            "notifications_inbox",
            "INSERT INTO notifications_inbox (id, account_id, notification_id, category, title, \
             body, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?, '{}', ?)",
            vec![
                format!("inbox-{account}").into(),
                account.into(),
                format!("notif-{account}").into(),
                BOOKING.into(),
                "Booked".into(),
                "See you Tuesday".into(),
                "2026-01-01T00:00:00Z".into(),
            ],
        ),
        (
            "notifications_email_targets",
            "INSERT INTO notifications_email_targets (account_id, email, verified_at, updated_at) \
             VALUES (?, ?, ?, ?)",
            vec![
                account.into(),
                format!("{account}@example.test").into(),
                "2026-01-01T00:00:00Z".into(),
                "2026-01-01T00:00:00Z".into(),
            ],
        ),
        (
            "notifications_email_sends",
            "INSERT INTO notifications_email_sends (id, account_id, category, sent_at) \
             VALUES (?, ?, ?, ?)",
            vec![
                format!("send-{account}").into(),
                account.into(),
                BOOKING.into(),
                "2026-01-01T00:00:00Z".into(),
            ],
        ),
        (
            "notifications_email_suppressed",
            "INSERT INTO notifications_email_suppressed (id, account_id, category, \
             notification_id, suppressed_at) VALUES (?, ?, ?, ?, ?)",
            vec![
                format!("suppressed-{account}").into(),
                account.into(),
                BOOKING.into(),
                format!("notif-suppressed-{account}").into(),
                "2026-01-01T00:00:00Z".into(),
            ],
        ),
    ];
    for (table, sql, values) in rows {
        kit.db
            .execute(&Statement::with_values(sql.to_owned(), values))
            .await
            .unwrap_or_else(|err| panic!("seeding {table} failed: {err}"));
    }
    seed_dead_letter(kit, account).await;
}

/// The dead letter is seeded apart because its `payload` alone needs the
/// JSON literal, and inlining it pushed `seed` over the line-count lint.
async fn seed_dead_letter(kit: &TestHarness, account: &str) {
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO notifications_dead_letters (id, account_id, topic, payload, attempts, \
             reason, last_error, created_at, failed_at) VALUES (?, ?, 'notifications.send', ?, 3, \
             'rejected', 'provider said no', ?, ?)"
                .to_owned(),
            vec![
                format!("dead-{account}").into(),
                account.into(),
                json!({ "account_id": account, "notification": { "title": "Booked" } })
                    .to_string()
                    .into(),
                "2026-01-01T00:00:00Z".into(),
                "2026-01-01T00:00:00Z".into(),
            ],
        ))
        .await
        .unwrap_or_else(|err| panic!("seeding notifications_dead_letters failed: {err}"));
}

/// Rows in one table for one account.
async fn count_for(kit: &TestHarness, table: &str, account: &str) -> i64 {
    let rows = kit
        .db
        .query(&Statement::with_values(
            format!("SELECT COUNT(*) AS n FROM {table} WHERE account_id = ?"),
            vec![account.into()],
        ))
        .await
        .unwrap_or_else(|err| panic!("counting {table} failed: {err}"));
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or(-1)
}

async fn admin(
    kit: &TestHarness,
    method: http::Method,
    path: &str,
    body: Option<Value>,
) -> support::Answer {
    support::send(&kit.router, method, path, Some(ADMIN), body).await
}

#[pollster::test]
async fn an_erasure_reaches_every_table_the_module_owns() {
    // The whole of issue #244 in one assertion: before the declarations
    // existed this erasure removed nothing at all, reported success, and
    // nobody could tell from the response.
    let kit = privacy_kit();
    seed(&kit, ALICE, ENDPOINT).await;
    seed(&kit, BOB, "https://push.example.test/send/bob").await;

    let preview = admin(
        &kit,
        http::Method::POST,
        "/v1/privacy/erase",
        Some(json!({ "subject": ALICE })),
    )
    .await;
    assert_eq!(preview.status, http::StatusCode::OK, "{}", preview.text());
    let body = preview.json();
    let planned = body["plan"].as_array().expect("plan").clone();
    assert_eq!(
        planned.len(),
        TABLES.len(),
        "every declared table is previewed: {planned:?}"
    );
    for table in TABLES {
        let row = planned
            .iter()
            .find(|entry| entry["table"] == *table)
            .unwrap_or_else(|| panic!("{table} missing from the preview: {planned:?}"));
        assert_eq!(row["action"], "erase", "{table}: {row}");
        assert_eq!(row["rows"], 1, "{table}: {row}");
    }
    // The preview writes nothing.
    assert_eq!(count_for(&kit, "notifications_inbox", ALICE).await, 1);

    let confirm = admin(
        &kit,
        http::Method::POST,
        "/v1/privacy/erase/confirm",
        Some(json!({ "token": body["confirm_token"] })),
    )
    .await;
    assert_eq!(confirm.status, http::StatusCode::OK, "{}", confirm.text());
    assert_eq!(confirm.json()["verified"], true);

    for table in TABLES {
        assert_eq!(count_for(&kit, table, ALICE).await, 0, "{table} survived");
        assert_eq!(count_for(&kit, table, BOB).await, 1, "{table} lost Bob");
    }
}

#[pollster::test]
async fn an_export_carries_the_notifications_and_never_the_endpoint() {
    let kit = privacy_kit();
    seed(&kit, ALICE, ENDPOINT).await;

    let response = admin(
        &kit,
        http::Method::GET,
        &format!("/v1/privacy/export?subject={ALICE}"),
        None,
    )
    .await;
    assert_eq!(response.status, http::StatusCode::OK, "{}", response.text());
    let raw = response.text();
    assert!(
        !raw.contains(ENDPOINT) && !raw.contains("abc123-secret-capability"),
        "the export copied a Web Push endpoint, which is a bearer capability"
    );

    let body = response.json();
    let tables = body["tables"].as_array().expect("tables");
    assert_eq!(tables.len(), TABLES.len());

    let subscriptions = tables
        .iter()
        .find(|t| t["table"] == "notifications_subscriptions")
        .expect("subscriptions exported");
    let row = &subscriptions["rows"][0];
    // Named, not dropped: "we hold nothing there" is the one answer a subject
    // access request must not give untruthfully.
    assert_eq!(row["recipient_json"], "[redacted]", "{row}");
    // Everything else about the device is the person's own, and is theirs.
    assert_eq!(row["transport"], "webpush", "{row}");
    assert_eq!(row["recipient_hash"], format!("hash-{ALICE}"), "{row}");

    // The message they were sent is in their export, because it is theirs.
    let inbox = tables
        .iter()
        .find(|t| t["table"] == "notifications_inbox")
        .expect("inbox exported");
    assert_eq!(inbox["rows"][0]["title"], "Booked");
}

#[pollster::test]
async fn the_manifest_says_what_the_outbox_holds_rather_than_staying_silent() {
    // The outbox holds the person's message, so it must not be published as
    // "not personal" — but erasure cannot reach it either (issue #274). Its
    // own bucket is the honest answer.
    let kit = privacy_kit();
    let response = support::send(
        &kit.router,
        http::Method::GET,
        "/v1/privacy/manifest",
        None,
        None,
    )
    .await;
    assert_eq!(response.status, http::StatusCode::OK);
    let body = response.json();

    let listed: Vec<&str> = body["holds"]
        .as_array()
        .expect("holds")
        .iter()
        .filter_map(|entry| entry["table"].as_str())
        .collect();
    assert_eq!(listed, TABLES, "{body}");

    let not_personal = body["not_personal"].as_array().expect("not_personal");
    assert!(
        not_personal
            .iter()
            .all(|entry| entry["table"] != "notifications_outbox"),
        "the outbox holds a message; it cannot be published as not personal: {not_personal:?}"
    );

    let unreachable = body["unreachable"].as_array().expect("unreachable");
    assert_eq!(unreachable.len(), 1, "{unreachable:?}");
    assert_eq!(unreachable[0]["table"], "notifications_outbox");
    assert_eq!(unreachable[0]["kind"], "content");
    let reason = unreachable[0]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("cannot match"),
        "the outbox reason has to say why erasure cannot reach it: {reason}"
    );
    let description = unreachable[0]["description"].as_str().unwrap_or_default();
    assert!(
        description.contains("message"),
        "the outbox description has to say what is in it: {description}"
    );

    // The device column is named on the page, so a reader learns it is held
    // and withheld rather than learning nothing.
    let subscriptions = body["holds"]
        .as_array()
        .expect("holds")
        .iter()
        .find(|entry| entry["table"] == "notifications_subscriptions")
        .expect("subscriptions published");
    assert_eq!(subscriptions["redacted"][0], "recipient_json");
    assert_eq!(subscriptions["on_erasure"]["action"], "erase");
}

/// A table holding the person's message must never be described to them as
/// both holding it and not personal (issue #274). Written against the whole
/// published manifest, so a future bucket cannot reintroduce the split.
#[pollster::test]
async fn the_manifest_never_calls_a_table_both_personal_and_not() {
    let kit = privacy_kit();
    let response = support::send(
        &kit.router,
        http::Method::GET,
        "/v1/privacy/manifest",
        None,
        None,
    )
    .await;
    assert_eq!(response.status, http::StatusCode::OK);
    let body = response.json();

    let names = |bucket: &str| -> Vec<String> {
        body[bucket]
            .as_array()
            .unwrap_or_else(|| panic!("{bucket} missing: {body}"))
            .iter()
            .filter_map(|entry| entry["table"].as_str().map(str::to_owned))
            .collect()
    };
    let holds = names("holds");
    let not_personal = names("not_personal");
    let unreachable = names("unreachable");

    for table in &not_personal {
        assert!(
            !holds.contains(table) && !unreachable.contains(table),
            "{table} is described as not personal and as holding data: {body}"
        );
    }
    for table in holds.iter().chain(unreachable.iter()) {
        assert!(
            !not_personal.contains(table),
            "{table} holds data and is also published as not personal: {body}"
        );
    }

    // The outbox is the case that made the buckets necessary: whatever the
    // manifest says about it, it must not be silence in `not_personal`.
    assert!(
        unreachable.iter().any(|t| t == "notifications_outbox"),
        "the outbox is not published as unreachable: {body}"
    );
}

#[pollster::test]
async fn a_dead_letter_records_the_account_it_was_for() {
    // Written by the drain, not by a fixture: the account id is read back out
    // of the payload at the one place the column is bound, so every caller
    // gets it — including the ones that never parsed the payload themselves.
    let push = support::ScriptedPush::new(vec![Err(PushError::Rejected(
        "apns 400 BadMessageId".to_owned(),
    ))]);
    let kit = support::kit_with(Arc::new(push), support::categories(), &[]);
    let answer = support::send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/subscriptions",
        Some(&support::token_for(ALICE)),
        Some(json!({
            "transport": "apns",
            "recipient": cratefield_core::Recipient::apns("device-alice-ios"),
        })),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
    notify_and_commit(&kit.notifier, &kit).await;

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.dead_lettered, 1);

    let rows = kit.rows("notifications_dead_letters").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get::<String>("account_id").as_deref(),
        Some(ALICE),
        "a dead letter with no account is one an erasure can never reach"
    );
}

#[pollster::test]
async fn a_dead_letter_from_an_unreadable_payload_names_nobody() {
    // The `malformed` path: the payload is not a job, so there is no account
    // to attribute the row to. NULL is the honest answer — a guess would put
    // somebody else's id on somebody's failed notification.
    let kit = support::kit();
    let db = kit.db();
    db.execute(&Statement::with_values(
        "INSERT INTO notifications_outbox (id, topic, payload, attempts, next_attempt_at, \
         created_at) VALUES ('row-1', 'notifications.send', 'not-a-job', 0, ?, ?)"
            .to_owned(),
        vec!["2026-01-01T00:00:00Z".into(), "2026-01-01T00:00:00Z".into()],
    ))
    .await
    .expect("seed outbox");

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.dead_lettered, 1);
    let rows = kit.rows("notifications_dead_letters").await;
    assert_eq!(rows[0].get::<String>("account_id"), None);
}

/// One notification for Alice, committed the way a caller commits it.
async fn notify_and_commit(notifier: &Notifier, kit: &support::Kit) {
    let db = kit.db();
    let enqueued = notifier
        .notify(
            &*db,
            ALICE,
            BOOKING,
            cratefield_core::Notification::new("Booked", "See you Tuesday"),
        )
        .await
        .expect("notify");
    db.batch(enqueued.statements()).await.expect("batch");
}
