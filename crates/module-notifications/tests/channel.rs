//! Issue #764 acceptance: the pluggable extra-channel seam.
//!
//! Until the [`Channel`] trait existed no test here could register one, so
//! the arm was written, documented and never executed — the same hole the
//! email failure tests (`email_failures.rs`) were written to close for
//! `Mailer`'s outcome mapping. The rules under test, in the order they are
//! easy to get wrong: a reachable account gets one delivery with the
//! rendered message, an unreachable or opted-out one gets no row at all,
//! a transient failure waits out the `retry_after` it named, a permanent
//! one dead-letters without a retry, and the payload names the channel
//! and the account — never a recipient credential.

// The channel's own recordings — what it was asked, what it answered —
// are test observations, not request state (ADR 0007); the file-level
// allow follows tests/support/mod.rs.
#![allow(clippy::disallowed_types)]

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cratefield_core::{Database, Module as _, Notification, Outbox};
use cratefield_module_notifications::{
    Category, Channel, ChannelError, ChannelMessage, Notifications, TOPIC_CHANNEL,
};
use serde_json::json;
use support::{ALICE, BOOKING, Kit, kit_customised};

const OUTBOX: &str = "notifications_outbox";
const DEAD: &str = "notifications_dead_letters";

/// A channel that records every delivery and answers from a script: the
/// reachability check has its own answer, and `deliver` pops the queue —
/// delivering by default, so a retry after a scripted failure just works.
#[derive(Clone)]
struct FakeChannel {
    inner: Arc<ChannelInner>,
}

struct ChannelInner {
    name: &'static str,
    reachable: Mutex<Result<bool, ChannelError>>,
    results: Mutex<Vec<Result<(), ChannelError>>>,
    delivered: Mutex<Vec<(String, ChannelMessage)>>,
}

impl FakeChannel {
    fn named(name: &'static str) -> Self {
        Self {
            inner: Arc::new(ChannelInner {
                name,
                reachable: Mutex::new(Ok(true)),
                results: Mutex::new(Vec::new()),
                delivered: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Whether the account can be reached at all — the enqueue-time and
    /// send-time answer alike.
    fn reaching(self, reachable: bool) -> Self {
        *self.inner.reachable.lock().expect("reachable") = Ok(reachable);
        self
    }

    /// Re-answers reachability mid-test, the way an account unlinking
    /// between the commit and the drain would.
    fn stop_reaching(&self) {
        *self.inner.reachable.lock().expect("reachable") = Ok(false);
    }

    /// What the next `deliver` calls answer, last popped first.
    fn answer_with(self, results: Vec<Result<(), ChannelError>>) -> Self {
        let mut queue = results;
        queue.reverse();
        *self.inner.results.lock().expect("results") = queue;
        self
    }

    /// Every `(account_id, message)` the channel was handed.
    fn delivered(&self) -> Vec<(String, ChannelMessage)> {
        self.inner.delivered.lock().expect("delivered").clone()
    }
}

#[async_trait]
impl Channel for FakeChannel {
    fn name(&self) -> &'static str {
        self.inner.name
    }

    async fn reachable(&self, _db: &dyn Database, _account_id: &str) -> Result<bool, ChannelError> {
        self.inner.reachable.lock().expect("reachable").clone()
    }

    async fn deliver(
        &self,
        _db: &dyn Database,
        account_id: &str,
        message: &ChannelMessage,
    ) -> Result<(), ChannelError> {
        self.inner
            .delivered
            .lock()
            .expect("delivered")
            .push((account_id.to_owned(), message.clone()));
        self.inner
            .results
            .lock()
            .expect("results")
            .pop()
            .unwrap_or(Ok(()))
    }
}

/// A kit with `channel` registered — taken through the same builder turn a
/// venture's Telegram crate would go through.
fn channel_kit(channel: FakeChannel) -> Kit {
    kit_customised(
        Arc::new(support::ScriptedPush::new(Vec::new())),
        vec![Category::new(BOOKING)],
        &[],
        |module| module.channel(Arc::new(channel)),
    )
}

async fn notify_and_commit(kit: &Kit, notification: Notification) {
    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(&*db, ALICE, BOOKING, notification)
        .await
        .expect("notify");
    if !enqueued.statements().is_empty() {
        db.batch_atomic(enqueued.statements()).await.expect("batch");
    }
}

#[pollster::test]
async fn a_reachable_account_is_delivered_once_with_the_rendered_message() {
    let mut notification = Notification::new("Booked", "See you Tuesday");
    notification.url = Some("https://example.test/b/1".to_owned());
    let channel = FakeChannel::named("test_channel");
    let kit = channel_kit(channel.clone());

    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(&*db, ALICE, BOOKING, notification)
        .await
        .expect("notify");
    assert_eq!(
        enqueued.channel_rows(),
        1,
        "one registered channel, one row"
    );
    db.batch_atomic(enqueued.statements()).await.expect("batch");

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.delivered, 1);

    let delivered = channel.delivered();
    assert_eq!(delivered.len(), 1, "one row, one delivery");
    let (account, message) = &delivered[0];
    assert_eq!(account, ALICE);
    assert_eq!(message.category, BOOKING);
    assert_eq!(message.title, "Booked");
    assert_eq!(message.body, "See you Tuesday");
    assert_eq!(
        message.url.as_deref(),
        Some("https://example.test/b/1"),
        "the link the caller set travels"
    );
    assert_eq!(kit.count(OUTBOX).await, 0, "delivered means gone");

    // And a second drain claims nothing: the row is not retried into a
    // second copy.
    assert_eq!(
        kit.notifier
            .drain(&kit.scope())
            .await
            .expect("drain")
            .claimed,
        0
    );
    assert_eq!(channel.delivered().len(), 1);
}

#[pollster::test]
async fn an_unreachable_account_is_not_enqueued_at_all() {
    let channel = FakeChannel::named("test_channel").reaching(false);
    let kit = channel_kit(channel.clone());

    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(&*db, ALICE, BOOKING, Notification::new("Booked", "Tuesday"))
        .await
        .expect("notify");
    assert_eq!(
        enqueued.channel_rows(),
        0,
        "nothing queued for a channel that cannot reach the account"
    );
    if !enqueued.statements().is_empty() {
        db.batch_atomic(enqueued.statements()).await.expect("batch");
    }

    kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert!(channel.delivered().is_empty());
    assert_eq!(kit.count(OUTBOX).await, 0);
    assert_eq!(kit.count(DEAD).await, 0, "never queued, never failed");
}

#[pollster::test]
async fn the_push_switch_gates_the_extra_channels_too() {
    // Channels follow the push switch until they have a preference column
    // of their own — so switching push off for the category silences
    // every registered channel with it.
    let channel = FakeChannel::named("test_channel");
    let kit = channel_kit(channel.clone());
    let answer = support::send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/preferences",
        Some(&support::token_for(ALICE)),
        Some(json!({ "preferences": { "booking": { "push": false } } })),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());

    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(&*db, ALICE, BOOKING, Notification::new("Booked", "Tuesday"))
        .await
        .expect("notify");
    assert_eq!(enqueued.channel_rows(), 0);
    if !enqueued.statements().is_empty() {
        db.batch_atomic(enqueued.statements()).await.expect("batch");
    }
    kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert!(channel.delivered().is_empty());
}

#[pollster::test]
async fn a_transient_error_waits_out_the_retry_after_it_named() {
    let channel =
        FakeChannel::named("test_channel").answer_with(vec![Err(ChannelError::Transient {
            retry_after: Some(Duration::from_mins(15)),
        })]);
    let kit = channel_kit(channel.clone());
    notify_and_commit(&kit, Notification::new("Booked", "See you Tuesday")).await;
    let at_enqueue = kit.clock.now_unix();

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.retried, 1, "the attempt was made, and backed off");
    assert_eq!(channel.delivered().len(), 1);
    let row = &kit.rows(OUTBOX).await[0];
    assert_eq!(
        row.get::<String>("next_attempt_at").as_deref(),
        Some(iso(at_enqueue + 900).as_str()),
        "the channel asked for 900s and the 30s backoff must not win"
    );

    // Not due yet, then due — and this time it goes.
    kit.clock.advance(60);
    assert_eq!(
        kit.notifier
            .drain(&kit.scope())
            .await
            .expect("drain")
            .claimed,
        0
    );
    kit.clock.advance(900);
    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.delivered, 1);
    assert_eq!(channel.delivered().len(), 2, "the retry is a real send");
    assert_eq!(kit.count(OUTBOX).await, 0);
}

#[pollster::test]
async fn a_permanent_error_dead_letters_and_is_never_retried() {
    let channel = FakeChannel::named("test_channel").answer_with(vec![Err(
        ChannelError::Permanent("telegram 400: chat not found".to_owned()),
    )]);
    let kit = channel_kit(channel.clone());
    notify_and_commit(&kit, Notification::new("Booked", "See you Tuesday")).await;

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.dead_lettered, 1);
    assert_eq!(report.retried, 0, "nothing about this message fixes itself");
    let rows = kit.rows(DEAD).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<String>("reason").as_deref(), Some("rejected"));
    assert!(
        rows[0]
            .get::<String>("last_error")
            .is_some_and(|error| error.contains("chat not found")),
        "the channel's own words are the reason ops reads"
    );

    kit.clock.advance(86_400);
    assert_eq!(
        kit.notifier
            .drain(&kit.scope())
            .await
            .expect("drain")
            .claimed,
        0,
        "a dead letter is out of the work queue for good"
    );
    assert_eq!(channel.delivered().len(), 1);
}

#[pollster::test]
async fn a_channel_that_stops_reaching_the_account_after_enqueue_dead_letters() {
    // The row was queued because the account *was* reachable; unlinking
    // between the commit and the drain dead-letters rather than drops, so
    // the loss is visible somewhere.
    let channel = FakeChannel::named("test_channel");
    let kit = channel_kit(channel.clone());
    notify_and_commit(&kit, Notification::new("Booked", "See you Tuesday")).await;
    channel.stop_reaching();

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.dead_lettered, 1);
    let rows = kit.rows(DEAD).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get::<String>("reason").as_deref(),
        Some("not_configured"),
        "only the account can fix this, by linking again"
    );
}

#[pollster::test]
async fn the_outbox_payload_names_the_channel_and_the_account_and_no_recipient() {
    let kit = channel_kit(FakeChannel::named("test_channel"));
    notify_and_commit(&kit, Notification::new("Booked", "See you Tuesday")).await;

    let rows = kit.rows(OUTBOX).await;
    let payload = rows
        .iter()
        .find_map(|row| row.get::<String>("payload"))
        .expect("the channel row is in the outbox");
    assert!(payload.contains("test_channel"), "{payload}");
    assert!(payload.contains(ALICE), "{payload}");
    assert!(!payload.contains("chat_id"), "{payload}");
    assert!(!payload.contains("recipient"), "{payload}");
    assert!(!payload.contains('@'), "{payload}");
}

#[pollster::test]
async fn a_row_for_a_channel_that_is_no_longer_registered_dead_letters() {
    // The venture removed the crate between the commit and the drain. The
    // notification was real, so it dead-letters rather than vanishing.
    let kit = kit_customised(
        Arc::new(support::ScriptedPush::new(Vec::new())),
        vec![Category::new(BOOKING)],
        &[],
        |module| module,
    );
    let payload = json!({
        "channel": "vanished",
        "notification_id": "n-1",
        "account_id": ALICE,
        "category": BOOKING,
        "notification": { "title": "Booked", "body": "See you Tuesday" },
    });
    let statement = Outbox::new(OUTBOX).enqueue_statement(
        "row-orphan-channel",
        TOPIC_CHANNEL,
        &payload.to_string(),
        Some(ALICE),
        "2020-01-01T00:00:00Z",
    );
    kit.db().execute(&statement).await.expect("enqueued");

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.dead_lettered, 1);
    let rows = kit.rows(DEAD).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get::<String>("reason").as_deref(),
        Some("not_configured")
    );
    assert!(
        rows[0]
            .get::<String>("last_error")
            .is_some_and(|error| error.contains("vanished")),
        "the reason names the channel that is missing"
    );
}

#[test]
fn a_duplicated_channel_name_is_refused_by_validation() {
    let duplicate = Notifications::new()
        .categories([BOOKING])
        .channel(Arc::new(FakeChannel::named("same")))
        .channel(Arc::new(FakeChannel::named("same")));
    let err = duplicate
        .validate_config(&cratefield_core::EmptyConfig)
        .expect_err("two channels cannot share a name: the payload would be ambiguous");
    assert!(err.to_string().contains("registered twice"), "{err}");

    let bad = Notifications::new()
        .categories([BOOKING])
        .channel(Arc::new(FakeChannel::named("Telegram")));
    let err = bad
        .validate_config(&cratefield_core::EmptyConfig)
        .expect_err("a channel name is a slug, like a category name");
    assert!(err.to_string().contains("lower-case"), "{err}");

    Notifications::new()
        .categories([BOOKING])
        .channel(Arc::new(FakeChannel::named("telegram")))
        .channel(Arc::new(FakeChannel::named("sms")))
        .validate_config(&cratefield_core::EmptyConfig)
        .expect("distinct, well-named channels are valid");
}

fn iso(unix: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(unix)
        .expect("in range")
        .format(&Rfc3339)
        .expect("formats")
}
