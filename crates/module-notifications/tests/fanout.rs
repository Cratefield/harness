//! Issue #182 acceptance: the fan-out and the drain.
//!
//! The rules under test, in the order they are easy to get wrong:
//! `Unregistered` prunes and nothing else does; the preference is read in
//! the drain; and the outbox rows commit in the caller's own batch.

mod support;

use std::sync::Arc;
use std::time::Duration;

use cratefield_core::{Notification, PushError, PushOutcome, Recipient, Statement};
use cratefield_module_notifications::{NotifyError, Skipped};
use cratefield_testing::{FakePush, PushMode};
use serde_json::{Value, json};
use support::{
    ALICE, BOB, BOOKING, COACH_NOTES, Kit, ROOM_STARTING, ScriptedPush, categories, kit_with,
};

const OUTBOX: &str = "notifications_outbox";
const DEAD: &str = "notifications_dead_letters";
const SUBS: &str = "notifications_subscriptions";

fn devices() -> [Recipient; 3] {
    [
        Recipient::apns("device-alice-ios"),
        Recipient::fcm("device-alice-android"),
        Recipient::web_push(
            "https://push.example.test/wp/alice-browser",
            "BAlicesP256dhKey",
            "AlicesAuthSecret",
        ),
    ]
}

/// Registers recipients for an account directly through the module's own
/// route, so the tests exercise the same write the app does.
async fn register(kit: &Kit, account: &str, recipients: &[Recipient]) -> Vec<String> {
    let mut ids = Vec::new();
    for recipient in recipients {
        let transport = match recipient {
            Recipient::Apns { .. } => "apns",
            Recipient::Fcm { .. } => "fcm",
            Recipient::WebPush { .. } => "webpush",
        };
        let answer = support::send(
            &kit.harness.router,
            http::Method::PUT,
            "/v1/notifications/subscriptions",
            Some(&support::token_for(account)),
            Some(json!({ "transport": transport, "recipient": recipient })),
        )
        .await;
        assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
        ids.push(answer.json()["id"].as_str().expect("an id").to_owned());
    }
    ids
}

/// `notify` then commit, the way a calling module does it.
async fn notify_and_commit(kit: &Kit, account: &str, category: &str) -> usize {
    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(
            &*db,
            account,
            category,
            Notification::new("Booked", "See you Tuesday"),
        )
        .await
        .expect("notify");
    if !enqueued.is_empty() {
        db.batch(enqueued.statements()).await.expect("batch");
    }
    enqueued.len()
}

#[pollster::test]
async fn n_subscriptions_become_n_sends_across_every_transport() {
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    let recipients = devices();
    register(&kit, ALICE, &recipients).await;

    assert_eq!(notify_and_commit(&kit, ALICE, BOOKING).await, 3);
    assert_eq!(kit.count(OUTBOX).await, 3);

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.delivered, 3);
    assert_eq!(kit.count(OUTBOX).await, 0, "a delivered row is deleted");
    assert_eq!(kit.count(DEAD).await, 0);

    let sent: Vec<Recipient> = push.sent().into_iter().map(|(to, _)| to).collect();
    for recipient in recipients {
        assert!(sent.contains(&recipient), "{recipient:?} was never sent to");
    }
}

#[pollster::test]
async fn a_category_switched_off_sends_nothing() {
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..1]).await;

    // `coach_notes` is declared default_enabled(false), so an account that
    // never chose is already off.
    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(
            &*db,
            ALICE,
            COACH_NOTES,
            Notification::new("Notes", "Read them"),
        )
        .await
        .expect("notify");
    assert!(enqueued.is_empty());
    assert_eq!(enqueued.skipped(), Some(Skipped::PreferenceOff));

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.claimed, 0);
    assert!(
        push.sent().is_empty(),
        "off means no send, not a silent send"
    );
}

#[pollster::test]
async fn an_opt_out_after_the_commit_still_wins() {
    // The reason the preference is read in the drain and not when the row
    // is written: everything already queued would otherwise still arrive.
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..2]).await;
    assert_eq!(notify_and_commit(&kit, ALICE, BOOKING).await, 2);

    let refused = support::send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/preferences",
        Some(&support::token_for(ALICE)),
        Some(json!({ "preferences": { BOOKING: { "push": false } } })),
    )
    .await;
    assert_eq!(refused.status, http::StatusCode::OK);

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.claimed, 2);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.dropped, 2);
    assert!(push.sent().is_empty(), "the late opt-out wins");
    assert_eq!(kit.count(OUTBOX).await, 0);
    assert_eq!(kit.count(DEAD).await, 0, "an opt-out is not a failure");
}

#[pollster::test]
async fn unregistered_prunes_exactly_that_subscription_and_no_other() {
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    let recipients = devices();
    let ids = register(&kit, ALICE, &recipients).await;
    // Exactly one of three devices is dead.
    push.set_mode_for(&recipients[1], PushMode::Unregistered);

    notify_and_commit(&kit, ALICE, BOOKING).await;
    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.delivered, 2);
    assert_eq!(report.pruned, 1);
    assert_eq!(kit.count(SUBS).await, 2, "one row gone, two untouched");
    assert_eq!(kit.count(OUTBOX).await, 0);
    assert_eq!(
        kit.count(DEAD).await,
        0,
        "a dead token is a delete instruction, not a failed send"
    );

    let survivors: Vec<String> = kit
        .rows(SUBS)
        .await
        .iter()
        .filter_map(|row| row.get::<String>("id"))
        .collect();
    assert!(!survivors.contains(&ids[1]), "the dead one is gone");
    assert!(survivors.contains(&ids[0]) && survivors.contains(&ids[2]));

    // And the venture is told, without the credential material.
    kit.harness.defer.drain().await;
    let events = kit
        .events
        .payloads(cratefield_module_notifications::EVENT_SUBSCRIPTION_PRUNED);
    assert_eq!(events.len(), 1, "one prune, one event");
    assert_eq!(events[0]["subscription_id"], ids[1].as_str());
    assert_eq!(events[0]["transport"], "fcm");
    let text = events[0].to_string();
    assert!(!text.contains("device-alice-android"), "{text}");
}

#[pollster::test]
async fn nothing_but_unregistered_ever_prunes() {
    // Two adapters got this wrong earlier in the epic, so it is asserted
    // one failure mode at a time.
    for mode in [
        PushMode::Transient,
        PushMode::NotConfigured,
        PushMode::DeliverOk,
    ] {
        let push = FakePush::new(mode);
        let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
        register(&kit, ALICE, &devices()[..1]).await;
        notify_and_commit(&kit, ALICE, BOOKING).await;
        kit.notifier.drain(&kit.scope()).await.expect("drain");
        assert_eq!(
            kit.count(SUBS).await,
            1,
            "{mode:?} must never delete a subscription"
        );
    }

    // A `Rejected` — the one FakePush has no mode for — through a script.
    let push = ScriptedPush::new(vec![Err(PushError::Rejected("bad payload".to_owned()))]);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..1]).await;
    notify_and_commit(&kit, ALICE, BOOKING).await;
    kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(
        kit.count(SUBS).await,
        1,
        "a rejected payload says nothing about the recipient"
    );
}

#[pollster::test]
async fn a_rejected_notification_is_dead_lettered_once_and_never_retried() {
    let push = ScriptedPush::new(vec![Err(PushError::Rejected(
        "apns 400 BadMessageId".to_owned(),
    ))]);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..1]).await;
    notify_and_commit(&kit, ALICE, BOOKING).await;

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.dead_lettered, 1);
    assert_eq!(report.retried, 0, "a bad payload does not fix itself");
    assert_eq!(kit.count(OUTBOX).await, 0);
    assert_eq!(kit.count(DEAD).await, 1);

    let row = &kit.rows(DEAD).await[0];
    assert_eq!(row.get::<String>("reason").as_deref(), Some("rejected"));
    assert_eq!(
        row.get::<String>("last_error").as_deref(),
        Some("apns 400 BadMessageId")
    );

    // Draining again finds nothing: it is out of the work queue.
    kit.clock.advance(86_400);
    let again = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(again.claimed, 0);
    assert_eq!(push.calls().len(), 1, "sent once, ever");
}

#[pollster::test]
async fn a_missing_adapter_dead_letters_with_a_reason_ops_can_act_on() {
    let push = FakePush::new(PushMode::NotConfigured);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..1]).await;
    notify_and_commit(&kit, ALICE, BOOKING).await;

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.dead_lettered, 1);
    let row = &kit.rows(DEAD).await[0];
    assert_eq!(
        row.get::<String>("reason").as_deref(),
        Some("not_configured"),
        "distinct from `rejected`: the fix is keys, not a payload"
    );
    let error = row.get::<String>("last_error").unwrap_or_default();
    assert!(error.contains("apns"), "{error}");
}

#[pollster::test]
async fn a_transient_failure_is_retried_with_backoff_and_honours_retry_after() {
    let push = ScriptedPush::new(vec![Err(PushError::transient_after(
        "apns 429",
        Some(Duration::from_mins(15)),
    ))]);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..1]).await;
    notify_and_commit(&kit, ALICE, BOOKING).await;
    let at_enqueue = kit.clock.now_unix();

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.retried, 1);
    assert_eq!(report.dead_lettered, 0);
    assert_eq!(kit.count(OUTBOX).await, 1, "the row is kept, not dropped");

    let row = &kit.rows(OUTBOX).await[0];
    assert_eq!(row.get::<i64>("attempts"), Some(1));
    let next = row
        .get::<String>("next_attempt_at")
        .expect("next_attempt_at");
    assert_eq!(
        next,
        iso(at_enqueue + 900),
        "the provider asked for 900s and the 30s backoff must not win"
    );
    assert_eq!(
        row.get::<Option<String>>("locked_until").flatten(),
        None,
        "the lease is released so another drainer can take it"
    );

    // Not due yet: the retry is a wait, not a busy loop.
    kit.clock.advance(60);
    assert_eq!(
        kit.notifier
            .drain(&kit.scope())
            .await
            .expect("drain")
            .claimed,
        0
    );
    // Due, and this time the provider takes it.
    kit.clock.advance(900);
    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.delivered, 1);
    assert_eq!(push.calls().len(), 2);
}

#[pollster::test]
async fn a_transient_failure_with_no_retry_after_uses_the_backoff() {
    let push = ScriptedPush::new(vec![Err(PushError::transient("apns 503"))]);
    let kit = kit_with(Arc::new(push), categories(), &[]);
    register(&kit, ALICE, &devices()[..1]).await;
    notify_and_commit(&kit, ALICE, BOOKING).await;
    let at_enqueue = kit.clock.now_unix();

    kit.notifier.drain(&kit.scope()).await.expect("drain");
    let row = &kit.rows(OUTBOX).await[0];
    assert_eq!(
        row.get::<String>("next_attempt_at").as_deref(),
        Some(iso(at_enqueue + 30).as_str())
    );
}

#[pollster::test]
async fn retries_are_bounded_and_then_the_row_is_dead_lettered() {
    let push = ScriptedPush::new(vec![
        Err(PushError::transient("apns 503")),
        Err(PushError::transient("apns 503")),
        Err(PushError::transient("apns 503")),
    ]);
    let kit = kit_with(
        Arc::new(push.clone()),
        categories(),
        &[("NOTIFICATIONS_MAX_ATTEMPTS", "3")],
    );
    register(&kit, ALICE, &devices()[..1]).await;
    notify_and_commit(&kit, ALICE, BOOKING).await;

    for _ in 0..3 {
        kit.notifier.drain(&kit.scope()).await.expect("drain");
        kit.clock.advance(7_200);
    }
    assert_eq!(push.calls().len(), 3, "three attempts, then no more");
    assert_eq!(kit.count(OUTBOX).await, 0);
    assert_eq!(kit.count(DEAD).await, 1);
    let row = &kit.rows(DEAD).await[0];
    assert_eq!(
        row.get::<String>("reason").as_deref(),
        Some("attempts_exhausted")
    );
    assert!(
        row.get::<String>("last_error")
            .unwrap_or_default()
            .contains("apns 503"),
        "the dead letter keeps the last error"
    );
    assert_eq!(kit.count(SUBS).await, 1, "and still nothing is pruned");
}

#[pollster::test]
async fn a_crash_between_the_commit_and_the_drain_is_recovered_by_the_scheduled_drain() {
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..2]).await;

    // Commit, then never call `deliver_now` — the isolate died.
    assert_eq!(notify_and_commit(&kit, ALICE, BOOKING).await, 2);
    assert_eq!(
        kit.harness.defer.deferred_count(),
        0,
        "nothing was deferred, so only the schedule can save this"
    );
    assert_eq!(kit.count(OUTBOX).await, 2);

    let ctx = kit.scheduled_context();
    kit.module()
        .scheduled(&ctx, "*/5 * * * *")
        .await
        .expect("the scheduled drain runs");
    assert_eq!(push.sent().len(), 2);
    assert_eq!(kit.count(OUTBOX).await, 0);
}

#[pollster::test]
async fn deliver_now_defers_exactly_one_drain() {
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..1]).await;
    notify_and_commit(&kit, ALICE, BOOKING).await;

    kit.notifier.deliver_now(&kit.scope());
    assert_eq!(kit.harness.defer.deferred_count(), 1);
    assert!(push.sent().is_empty(), "deferred, not done inline");
    kit.harness.defer.drain().await;
    assert_eq!(push.sent().len(), 1);
}

#[pollster::test]
async fn a_notify_inside_another_modules_batch_is_atomic_with_its_write() {
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..2]).await;
    let db = kit.db();

    let enqueued = kit
        .notifier
        .notify(&*db, ALICE, BOOKING, Notification::new("Booked", "Tuesday"))
        .await
        .expect("notify");
    assert_eq!(enqueued.len(), 2);

    // The calling module's own write fails. Its state change and the
    // notification must fall together.
    let mut failing = vec![Statement::new(
        "INSERT INTO no_such_table (id) VALUES ('x')",
    )];
    failing.extend(enqueued.statements().iter().cloned());
    assert!(
        db.batch(&failing).await.is_err(),
        "the caller's own statement must fail this batch"
    );
    assert_eq!(
        kit.count(OUTBOX).await,
        0,
        "no notification survives a batch that rolled back"
    );

    // The control, without which the assertion above proves nothing: the
    // same statements do commit when the caller's write succeeds.
    let mut working = vec![Statement::new(
        "CREATE TABLE IF NOT EXISTS booking_probe (id TEXT PRIMARY KEY)",
    )];
    working.extend(enqueued.into_statements());
    db.batch(&working).await.expect("batch commits");
    assert_eq!(kit.count(OUTBOX).await, 2);
}

#[pollster::test]
async fn a_device_that_signed_out_first_is_dropped_rather_than_sent_to() {
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    let ids = register(&kit, ALICE, &devices()[..2]).await;
    notify_and_commit(&kit, ALICE, BOOKING).await;

    let answer = support::send(
        &kit.harness.router,
        http::Method::DELETE,
        &format!("/v1/notifications/subscriptions/{}", ids[0]),
        Some(&support::token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::NO_CONTENT);

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.delivered, 1);
    assert_eq!(report.dropped, 1);
    assert_eq!(kit.count(DEAD).await, 0, "a sign-out is not a failure");
}

#[pollster::test]
async fn the_stored_payload_carries_the_dedupe_keys_and_no_credential() {
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..1]).await;
    notify_and_commit(&kit, ALICE, BOOKING).await;

    let payload = kit.rows(OUTBOX).await[0]
        .get::<String>("payload")
        .expect("payload");
    assert!(
        !payload.contains("device-alice-ios"),
        "an outbox row is ordinary data; a token is not: {payload}"
    );
    let job: Value = serde_json::from_str(&payload).expect("a job");
    assert_eq!(job["notification"]["data"]["category"], BOOKING);
    assert!(job["notification"]["data"]["notification_id"].is_string());

    kit.notifier.drain(&kit.scope()).await.expect("drain");
    let (_, delivered) = push.last().expect("one send");
    assert_eq!(delivered.data["category"], BOOKING);
    assert_eq!(
        delivered.data["notification_id"], job["notification_id"],
        "every device of one fan-out shares the id, so a client can dedupe"
    );
}

#[pollster::test]
async fn a_badge_travels_only_for_a_category_that_asked_for_one() {
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..1]).await;
    let db = kit.db();

    for (category, expected) in [(BOOKING, None), (ROOM_STARTING, Some(4))] {
        let mut notification = Notification::new("Room", "Starting soon");
        notification.badge = Some(4);
        let enqueued = kit
            .notifier
            .notify(&*db, ALICE, category, notification)
            .await
            .expect("notify");
        db.batch(enqueued.statements()).await.expect("batch");
        kit.notifier.drain(&kit.scope()).await.expect("drain");
        let (_, sent) = push.last().expect("a send");
        assert_eq!(sent.badge, expected, "category {category}");
    }
}

#[pollster::test]
async fn an_undeclared_category_is_an_error_not_a_silent_no_op() {
    let kit = kit_with(
        Arc::new(FakePush::new(PushMode::DeliverOk)),
        categories(),
        &[],
    );
    let db = kit.db();
    let error = kit
        .notifier
        .notify(&*db, ALICE, "typo_category", Notification::new("a", "b"))
        .await
        .expect_err("an unknown category is a caller bug");
    assert!(matches!(error, NotifyError::UnknownCategory(name) if name == "typo_category"));
}

#[pollster::test]
async fn an_account_with_no_device_is_a_no_op_not_an_error() {
    let kit = kit_with(
        Arc::new(FakePush::new(PushMode::DeliverOk)),
        categories(),
        &[],
    );
    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(&*db, BOB, BOOKING, Notification::new("a", "b"))
        .await
        .expect("notify");
    assert!(enqueued.is_empty());
    assert_eq!(enqueued.skipped(), Some(Skipped::NoSubscriptions));
}

#[pollster::test]
async fn the_event_bus_entry_point_fans_out_like_a_direct_call() {
    // For a module that has the bus and cannot take a crate dependency on
    // this one.
    let push = FakePush::new(PushMode::DeliverOk);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..2]).await;

    let module = kit.module();
    let handlers = module.events();
    let (name, handler) = handlers.first().expect("a subscription");
    assert_eq!(name, cratefield_module_notifications::EVENT_REQUESTED);

    handler(
        &kit.scope(),
        json!({
            "account_id": ALICE,
            "category": BOOKING,
            "notification": { "title": "Booked", "body": "Tuesday" },
        }),
    )
    .await
    .expect("the handler fans out");
    assert_eq!(
        kit.count(OUTBOX).await,
        2,
        "committed by the handler itself"
    );
    kit.harness.defer.drain().await;
    assert_eq!(push.sent().len(), 2);
}

#[pollster::test]
async fn a_requested_event_missing_its_account_is_an_error_not_a_send() {
    let kit = kit_with(
        Arc::new(FakePush::new(PushMode::DeliverOk)),
        categories(),
        &[],
    );
    let module = kit.module();
    let handlers = module.events();
    let (_, handler) = handlers.first().expect("a subscription");
    assert!(
        handler(&kit.scope(), json!({ "category": BOOKING }))
            .await
            .is_err()
    );
}

#[pollster::test]
async fn two_drainers_never_deliver_the_same_row_twice() {
    // The lease is core's, but a drain that ignored it would double-send,
    // so the module's use of it is asserted here.
    let push = ScriptedPush::new(vec![Ok(PushOutcome::Delivered { id: None })]);
    let kit = kit_with(Arc::new(push.clone()), categories(), &[]);
    register(&kit, ALICE, &devices()[..1]).await;
    notify_and_commit(&kit, ALICE, BOOKING).await;

    let first = kit.notifier.drain(&kit.scope()).await.expect("drain");
    let second = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(first.claimed, 1);
    assert_eq!(second.claimed, 0);
    assert_eq!(push.calls().len(), 1);
}

/// The RFC 3339 form the module writes, for timestamp assertions.
fn iso(unix: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(unix)
        .expect("in range")
        .format(&Rfc3339)
        .expect("formats")
}
