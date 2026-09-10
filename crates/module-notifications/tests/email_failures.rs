//! Issue #236: every arm of the email outcome mapping, driven by a mailer
//! that actually fails — and issue #235, the leak the arms were hiding.
//!
//! Until the fake could emit an arbitrary [`MailError`] no test in this
//! crate constructed one at all: every email test ran the default
//! `SendOk` kit, so the five-arm `match` in `deliver_email` was written,
//! documented and never executed. `Invalid { detail }` and
//! `DomainNotVerified { domain }` — the two variants that carry the
//! provider's own words, and so the two that can carry a recipient
//! address — could not be produced from a fake at all.
//!
//! That is the same hole that hid three earlier leaks in this epic: a doc
//! promises a value never appears, a test asserts it, and the test only
//! covers the success path.

mod support;

use std::sync::Arc;
use std::time::Duration;

use cratefield_core::{MailError, Notification, PushError};
use cratefield_module_notifications::Category;
use cratefield_testing::{FakePush, MailerMode, PushMode};
use serde_json::json;
use support::{ALICE, BOOKING, Kit, kit_with};

const OUTBOX: &str = "notifications_outbox";
const DEAD: &str = "notifications_dead_letters";
const SENDS: &str = "notifications_email_sends";

/// An address a provider would quote back at us, and the pieces of it
/// that must never reach a column.
const ADDRESS: &str = "alice@example.test";

fn email_kit(config: &[(&str, &str)]) -> Kit {
    kit_with(
        Arc::new(FakePush::new(PushMode::DeliverOk)),
        vec![Category::new(BOOKING).email(true)],
        config,
    )
}

/// A kit with a verified address for Alice and the mailer answering
/// `mode`.
async fn kit_failing_with(mode: MailerMode, config: &[(&str, &str)]) -> Kit {
    let kit = email_kit(config);
    let answer = support::send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/email",
        Some(&support::token_for_verified_email(ALICE, ADDRESS)),
        Some(json!({ "email": ADDRESS })),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
    kit.harness.mailer.set_mode(mode);
    kit
}

async fn notify_and_commit(kit: &Kit) {
    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(
            &*db,
            ALICE,
            BOOKING,
            Notification::new("Booked", "See you Tuesday"),
        )
        .await
        .expect("notify");
    if !enqueued.statements().is_empty() {
        db.batch(enqueued.statements()).await.expect("batch");
    }
}

/// The one dead-letter row's `(reason, last_error)`.
async fn dead_letter(kit: &Kit) -> (String, String) {
    let rows = kit.rows(DEAD).await;
    assert_eq!(rows.len(), 1, "exactly one dead letter");
    (
        rows[0].get::<String>("reason").unwrap_or_default(),
        rows[0].get::<String>("last_error").unwrap_or_default(),
    )
}

// ---------------------------------------------------------------------------
// The five arms (#236)

#[pollster::test]
async fn arm_one_a_send_that_succeeds_records_it_and_clears_the_row() {
    let kit = kit_failing_with(MailerMode::SendOk, &[]).await;
    notify_and_commit(&kit).await;

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.delivered, 1);
    assert_eq!(kit.count(OUTBOX).await, 0);
    assert_eq!(kit.count(DEAD).await, 0);
    assert_eq!(kit.count(SENDS).await, 1, "the cooldown counts it");
}

#[pollster::test]
async fn arm_two_a_mailer_with_no_key_dead_letters_with_its_own_reason() {
    // Not a quiet no-op: a venture that opted a category into email and
    // wired a mailer with no key has a bug, and ops has to be able to see
    // which bug from the reason alone.
    let kit = kit_failing_with(MailerMode::NotConfigured, &[]).await;
    notify_and_commit(&kit).await;

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.dead_lettered, 1);
    assert_eq!(report.retried, 0, "a missing key does not fix itself");
    let (reason, error) = dead_letter(&kit).await;
    assert_eq!(reason, "not_configured", "distinct from `rejected`");
    assert!(error.contains("no API key"), "{error}");
    assert_eq!(
        kit.count(SENDS).await,
        0,
        "nothing was sent, nothing counts"
    );
}

#[pollster::test]
async fn arm_three_a_permanent_refusal_dead_letters_and_is_never_retried() {
    // All three of them, one at a time: nothing about this message will
    // ever be accepted, so retrying only burns the sending reputation the
    // provider is refusing it to protect.
    for error in [
        MailError::Unauthorized,
        MailError::DomainNotVerified {
            domain: "send.example.test".to_owned(),
        },
        MailError::Invalid {
            detail: "the message body is empty".to_owned(),
        },
    ] {
        let kit = kit_failing_with(MailerMode::Error(error.clone()), &[]).await;
        notify_and_commit(&kit).await;

        let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
        assert_eq!(report.dead_lettered, 1, "{error:?}");
        assert_eq!(report.retried, 0, "{error:?}");
        assert_eq!(kit.count(OUTBOX).await, 0, "{error:?}");
        let (reason, _) = dead_letter(&kit).await;
        assert_eq!(reason, "rejected", "{error:?}");

        // And it stays out of the work queue.
        kit.clock.advance(86_400);
        let again = kit.notifier.drain(&kit.scope()).await.expect("drain");
        assert_eq!(again.claimed, 0, "{error:?}");
    }
}

#[pollster::test]
async fn arm_four_a_rate_limit_waits_out_the_delay_the_provider_named() {
    let kit = kit_failing_with(
        MailerMode::Error(MailError::RateLimited {
            retry_after: Some(Duration::from_mins(15)),
        }),
        &[],
    )
    .await;
    notify_and_commit(&kit).await;
    let at_enqueue = kit.clock.now_unix();

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.retried, 1);
    assert_eq!(report.dead_lettered, 0);
    let row = &kit.rows(OUTBOX).await[0];
    assert_eq!(
        row.get::<String>("next_attempt_at").as_deref(),
        Some(iso(at_enqueue + 900).as_str()),
        "the provider asked for 900s and the 30s backoff must not win"
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
    kit.harness.mailer.set_mode(MailerMode::SendOk);
    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.delivered, 1);
    assert_eq!(kit.harness.mailer.sent().len(), 1);
}

#[pollster::test]
async fn arm_five_an_upstream_failure_is_retried_to_the_bound_then_dead_lettered() {
    let kit = kit_failing_with(
        MailerMode::Error(MailError::Upstream("resend 503".to_owned())),
        &[("NOTIFICATIONS_MAX_ATTEMPTS", "3")],
    )
    .await;
    notify_and_commit(&kit).await;

    for _ in 0..3 {
        kit.notifier.drain(&kit.scope()).await.expect("drain");
        kit.clock.advance(7_200);
    }
    assert_eq!(kit.count(OUTBOX).await, 0);
    let (reason, error) = dead_letter(&kit).await;
    assert_eq!(reason, "attempts_exhausted");
    assert!(error.contains("gave up after 3 attempts"), "{error}");
    assert!(error.contains("resend 503"), "{error}");
    assert_eq!(
        kit.rows(DEAD).await[0].get::<i64>("attempts"),
        Some(3),
        "the column says what the message says"
    );
}

#[pollster::test]
async fn a_transport_failure_takes_the_retry_arm_not_the_reject_arm() {
    // `Transport` is the fifth arm's other member: a socket that died is
    // a bad day, not a bad message.
    let kit = kit_failing_with(
        MailerMode::Error(MailError::Transport("connection reset".to_owned())),
        &[],
    )
    .await;
    notify_and_commit(&kit).await;

    let report = kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(report.retried, 1);
    assert_eq!(report.dead_lettered, 0);
    let row = &kit.rows(OUTBOX).await[0];
    assert_eq!(row.get::<i64>("attempts"), Some(1));
}

// ---------------------------------------------------------------------------
// The leak the arms were hiding (#235)

#[pollster::test]
async fn a_dead_letter_row_never_holds_the_address_the_provider_quoted() {
    // Resend's 422 quotes the field it objected to, and for a send that
    // field is the recipient. The log leg of `dead_letter` was already
    // scrubbed by the tracing formatter; the row was not, so an address
    // could sit in a venture's own table outliving the erasure of
    // `notifications_email_targets` while the log a developer checks
    // showed it correctly redacted.
    let kit = kit_failing_with(
        MailerMode::Error(MailError::Invalid {
            detail: format!(
                "validation_error: `to` must be a valid address, got {ADDRESS} (suppressed)"
            ),
        }),
        &[],
    )
    .await;
    notify_and_commit(&kit).await;
    kit.notifier.drain(&kit.scope()).await.expect("drain");

    let (reason, error) = dead_letter(&kit).await;
    assert_eq!(reason, "rejected");
    assert!(!error.contains(ADDRESS), "{error}");
    assert!(!error.contains("alice"), "{error}");
    assert!(!error.contains('@'), "{error}");
    assert!(
        error.contains("[subject_hash:"),
        "the pseudonym stays, so two dead letters about one person still \
         correlate: {error}"
    );
    assert!(
        error.contains("validation_error"),
        "and the part ops needs is untouched: {error}"
    );
}

#[pollster::test]
async fn the_give_up_message_scrubs_the_error_it_quotes() {
    // The retry arm composes `gave up after N attempts: {message}`, so
    // the provider text arrives at the column inside a `format!` rather
    // than as a `MailError`. It has to be covered by the same boundary.
    let kit = kit_failing_with(
        MailerMode::Error(MailError::Upstream(format!("resend 503 for {ADDRESS}"))),
        &[("NOTIFICATIONS_MAX_ATTEMPTS", "2")],
    )
    .await;
    notify_and_commit(&kit).await;
    for _ in 0..2 {
        kit.notifier.drain(&kit.scope()).await.expect("drain");
        kit.clock.advance(7_200);
    }

    let (reason, error) = dead_letter(&kit).await;
    assert_eq!(reason, "attempts_exhausted");
    assert!(error.contains("gave up after 2 attempts"), "{error}");
    assert!(!error.contains(ADDRESS), "{error}");
    assert!(!error.contains('@'), "{error}");
}

#[pollster::test]
async fn a_push_dead_letter_row_never_holds_the_endpoint_it_was_told_about() {
    // The push side has the same shape, and it reaches the column by a
    // different road: `deliver_one` passes `PushError::Rejected`'s inner
    // string straight through, so the error's own `Display` never runs.
    // Whatever a caller passes, the column is what has to be safe.
    let push = FakePush::new(PushMode::Error(PushError::Rejected(format!(
        "web push 400 for https://push.example.test/wp/alice?auth=cap-abcdef (subscriber \
         {ADDRESS})"
    ))));
    let kit = kit_with(
        Arc::new(push),
        vec![Category::new(BOOKING)],
        &[("NOTIFICATIONS_MAX_ATTEMPTS", "2")],
    );
    let answer = support::send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/subscriptions",
        Some(&support::token_for(ALICE)),
        Some(json!({
            "transport": "webpush",
            "recipient": cratefield_core::Recipient::web_push(
                "https://push.example.test/wp/alice",
                "BAlicesP256dhKey",
                "AlicesAuthSecret",
            ),
        })),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
    notify_and_commit(&kit).await;
    kit.notifier.drain(&kit.scope()).await.expect("drain");

    let (reason, error) = dead_letter(&kit).await;
    assert_eq!(reason, "rejected");
    assert!(!error.contains("cap-abcdef"), "{error}");
    assert!(!error.contains(ADDRESS), "{error}");
    assert!(!error.contains('@'), "{error}");
    assert!(error.contains("?[redacted]"), "{error}");
    assert!(error.contains("web push 400"), "{error}");
}

fn iso(unix: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(unix)
        .expect("in range")
        .format(&Rfc3339)
        .expect("formats")
}
