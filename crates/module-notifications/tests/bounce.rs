//! Issue #233 acceptance: suppressing a bounced address from the
//! provider's webhook.
//!
//! The rules under test, in the order they are easy to get wrong: only a
//! hard bounce and a complaint suppress anybody, the signature is the
//! whole authority so an unverified delivery must change nothing, the
//! lookup is by address rather than by account so everyone sharing a
//! mailbox is suppressed, and a redelivery — which the provider *will*
//! send — must be a no-op rather than a second write.

mod support;

use cratefield_core::Notification;
use cratefield_module_notifications::Category;
use serde_json::json;
use support::{ALICE, BOB, BOOKING, Kit, kit_with};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const TARGETS: &str = "notifications_email_targets";
const WEBHOOK: &str = "/v1/notifications/email/webhook";
const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const ADDRESS: &str = "alice@example.com";
/// The kit's `FixedClock`, which the delivery timestamp must be near.
const NOW: i64 = support::NOW;

/// A kit whose `booking` category is opted into email and whose webhook
/// secret is configured.
fn bounce_kit() -> Kit {
    kit_with(
        std::sync::Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        vec![Category::new(BOOKING).email(true)],
        &[("NOTIFICATIONS_RESEND_WEBHOOK_SECRET", SECRET)],
    )
}

/// A kit with no webhook secret at all.
fn unconfigured_kit() -> Kit {
    kit_with(
        std::sync::Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        vec![Category::new(BOOKING).email(true)],
        &[],
    )
}

/// Stores a verified address for `account`, through the authenticated
/// route the module actually ships.
async fn set_verified_email(kit: &Kit, account: &str, address: &str) {
    let status = support::send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/email",
        Some(&support::token_for_verified_email(account, address)),
        Some(json!({ "email": address })),
    )
    .await
    .status;
    assert_eq!(status, http::StatusCode::OK, "the address is stored");
}

/// The body Resend sends for one event.
fn event_body(kind: &str, to: &[&str], bounce_kind: Option<&str>) -> String {
    let mut data = json!({ "to": to, "email_id": "3d4f1b2a", "subject": "Booked" });
    if let Some(bounce_kind) = bounce_kind {
        data["bounce"] = json!({
            "type": bounce_kind,
            "subType": "General",
            "message": "The recipient does not exist",
        });
    }
    json!({
        "type": kind,
        "created_at": "2027-01-15T08:00:00.000Z",
        "data": data,
    })
    .to_string()
}

/// The `svix-signature` header a provider holding `secret` would send.
fn sign(secret: &str, id: &str, timestamp: i64, body: &str) -> String {
    let key = STANDARD
        .decode(secret.strip_prefix("whsec_").unwrap_or(secret))
        .expect("the fixture secret is base64");
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).expect("any key length");
    mac.update(format!("{id}.{timestamp}.{body}").as_bytes());
    format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()))
}

/// Posts one signed delivery, the way the provider would.
async fn deliver(kit: &Kit, body: &str) -> http::StatusCode {
    deliver_at(kit, body, NOW, SECRET).await
}

/// [`deliver`], with the delivery timestamp and signing secret named.
async fn deliver_at(kit: &Kit, body: &str, timestamp: i64, secret: &str) -> http::StatusCode {
    let id = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    let signature = sign(secret, id, timestamp, body);
    let stamp = timestamp.to_string();
    support::send_raw(
        &kit.harness.router,
        http::Method::POST,
        WEBHOOK,
        &[
            ("svix-id", id),
            ("svix-timestamp", &stamp),
            ("svix-signature", &signature),
        ],
        body,
    )
    .await
    .status
}

/// The `unsubscribed_at`/`unsubscribed_reason` of every stored target.
async fn suppressions(kit: &Kit) -> Vec<(Option<String>, Option<String>)> {
    kit.rows(TARGETS)
        .await
        .iter()
        .map(|row| {
            (
                row.get::<String>("unsubscribed_at"),
                row.get::<String>("unsubscribed_reason"),
            )
        })
        .collect()
}

#[pollster::test]
async fn a_hard_bounce_suppresses_the_address() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    let status = deliver(
        &kit,
        &event_body("email.bounced", &[ADDRESS], Some("Permanent")),
    )
    .await;

    assert_eq!(status, http::StatusCode::OK);
    let stored = suppressions(&kit).await;
    assert_eq!(stored.len(), 1);
    assert!(stored[0].0.is_some(), "the address is suppressed");
    assert_eq!(stored[0].1.as_deref(), Some("bounce"));
}

#[pollster::test]
async fn a_suppressed_address_is_never_mailed_again() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;
    deliver(
        &kit,
        &event_body("email.bounced", &[ADDRESS], Some("Permanent")),
    )
    .await;

    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(&*db, ALICE, BOOKING, Notification::new("Booked", "Tuesday"))
        .await
        .expect("notify");
    if !enqueued.statements().is_empty() {
        db.batch_atomic(enqueued.statements()).await.expect("batch");
    }
    kit.notifier.drain(&kit.scope()).await.expect("drain");

    assert!(
        kit.harness.mailer.sent().is_empty(),
        "a hard-bounced mailbox is the one a retry gets the sending domain blocked over"
    );
}

#[pollster::test]
async fn a_soft_bounce_suppresses_nobody() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    // A full mailbox, a greylist, a server having a bad afternoon. None
    // of them is a reason to stop mailing somebody for good.
    for kind in ["Transient", "Undetermined"] {
        let status = deliver(&kit, &event_body("email.bounced", &[ADDRESS], Some(kind))).await;
        assert_eq!(
            status,
            http::StatusCode::OK,
            "accepted, and acted on: {kind}"
        );
    }
    // And a bounce event that carries no classification at all proves
    // nothing either.
    deliver(&kit, &event_body("email.bounced", &[ADDRESS], None)).await;

    assert_eq!(suppressions(&kit).await, vec![(None, None)]);
}

#[pollster::test]
async fn a_complaint_suppresses_the_address() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    let status = deliver(&kit, &event_body("email.complained", &[ADDRESS], None)).await;

    assert_eq!(status, http::StatusCode::OK);
    let stored = suppressions(&kit).await;
    assert!(stored[0].0.is_some(), "somebody pressed 'this is spam'");
    assert_eq!(
        stored[0].1.as_deref(),
        Some("complaint"),
        "a distinct reason from a bounce: the fix is different"
    );
}

#[pollster::test]
async fn an_event_this_module_has_no_rule_for_is_accepted_and_changes_nothing() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    // Subscribing to one Svix event tends to deliver its siblings too.
    // Refusing them would make the provider redeliver until it disabled
    // the endpoint, taking the bounces with it.
    let status = deliver(&kit, &event_body("email.delivered", &[ADDRESS], None)).await;

    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(suppressions(&kit).await, vec![(None, None)]);
}

#[pollster::test]
async fn every_account_sharing_the_mailbox_is_suppressed() {
    let kit = bounce_kit();
    // A couple, a shared team address: the provider knows the mailbox
    // and nothing about who reads it.
    set_verified_email(&kit, ALICE, ADDRESS).await;
    set_verified_email(&kit, BOB, ADDRESS).await;

    deliver(
        &kit,
        &event_body("email.bounced", &[ADDRESS], Some("Permanent")),
    )
    .await;

    let stored = suppressions(&kit).await;
    assert_eq!(stored.len(), 2);
    assert!(
        stored
            .iter()
            .all(|(at, reason)| at.is_some() && reason.as_deref() == Some("bounce")),
        "the bounce is about the mailbox, so it is about everybody holding it"
    );
}

#[pollster::test]
async fn the_address_is_matched_however_the_provider_spells_it() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    // Stored normalised by the authenticated route; the provider echoes
    // back whatever was on the envelope.
    deliver(
        &kit,
        &event_body(
            "email.bounced",
            &["  Alice@Example.COM "],
            Some("Permanent"),
        ),
    )
    .await;

    assert!(
        suppressions(&kit).await[0].0.is_some(),
        "a lookup that is not normalised the same way never finds the row"
    );
}

#[pollster::test]
async fn a_tampered_delivery_changes_nothing() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    // Signed for one body, sent with another: the classic replay of a
    // captured delivery with the payload swapped.
    let signed = event_body("email.delivered", &[ADDRESS], None);
    let sent = event_body("email.bounced", &[ADDRESS], Some("Permanent"));
    let id = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    let signature = sign(SECRET, id, NOW, &signed);
    let stamp = NOW.to_string();
    let answer = support::send_raw(
        &kit.harness.router,
        http::Method::POST,
        WEBHOOK,
        &[
            ("svix-id", id),
            ("svix-timestamp", &stamp),
            ("svix-signature", &signature),
        ],
        &sent,
    )
    .await;

    assert_eq!(answer.status, http::StatusCode::UNAUTHORIZED);
    assert_eq!(suppressions(&kit).await, vec![(None, None)]);
}

#[pollster::test]
async fn a_delivery_signed_with_another_secret_changes_nothing() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    let status = deliver_at(
        &kit,
        &event_body("email.bounced", &[ADDRESS], Some("Permanent")),
        NOW,
        "whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
    .await;

    assert_eq!(status, http::StatusCode::UNAUTHORIZED);
    assert_eq!(suppressions(&kit).await, vec![(None, None)]);
}

#[pollster::test]
async fn an_unsigned_delivery_changes_nothing() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    let answer = support::send_raw(
        &kit.harness.router,
        http::Method::POST,
        WEBHOOK,
        &[],
        &event_body("email.bounced", &[ADDRESS], Some("Permanent")),
    )
    .await;

    assert_eq!(answer.status, http::StatusCode::UNAUTHORIZED);
    assert_eq!(suppressions(&kit).await, vec![(None, None)]);
}

#[pollster::test]
async fn a_delivery_replayed_outside_the_window_changes_nothing() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;
    let body = event_body("email.bounced", &[ADDRESS], Some("Permanent"));

    // Perfectly signed, and the signature will stay valid forever. The
    // timestamp is the only thing that stops a captured delivery being
    // replayed for the rest of the endpoint's life.
    let status = deliver_at(&kit, &body, NOW - 600, SECRET).await;

    assert_eq!(status, http::StatusCode::UNAUTHORIZED);
    assert_eq!(suppressions(&kit).await, vec![(None, None)]);
}

#[pollster::test]
async fn with_no_secret_configured_a_delivery_is_refused_rather_than_trusted() {
    let kit = unconfigured_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    let answer = support::send_raw(
        &kit.harness.router,
        http::Method::POST,
        WEBHOOK,
        &[
            ("svix-id", "msg_1"),
            ("svix-timestamp", &NOW.to_string()),
            ("svix-signature", "v1,AAAA"),
        ],
        &event_body("email.bounced", &[ADDRESS], Some("Permanent")),
    )
    .await;

    assert_eq!(
        answer.status,
        http::StatusCode::UNAUTHORIZED,
        "an endpoint that cannot verify must not accept"
    );
    assert_eq!(suppressions(&kit).await, vec![(None, None)]);
}

#[pollster::test]
async fn a_redelivery_is_idempotent_and_keeps_the_first_reason() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    // The complaint lands first; the bounce that follows must not
    // rewrite why this address is suppressed.
    deliver(&kit, &event_body("email.complained", &[ADDRESS], None)).await;
    let after_first = suppressions(&kit).await;

    kit.clock.advance(60);
    deliver(
        &kit,
        &event_body("email.bounced", &[ADDRESS], Some("Permanent")),
    )
    .await;

    assert_eq!(
        suppressions(&kit).await,
        after_first,
        "a provider retries until it gets a 2xx, so a second delivery must write nothing"
    );
}

#[pollster::test]
async fn an_address_no_account_holds_is_accepted_and_changes_nothing() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    let status = deliver(
        &kit,
        &event_body(
            "email.bounced",
            &["stranger@example.com"],
            Some("Permanent"),
        ),
    )
    .await;

    assert_eq!(
        status,
        http::StatusCode::OK,
        "nothing to suppress is not a failure: a 4xx would make it redeliver forever"
    );
    assert_eq!(suppressions(&kit).await, vec![(None, None)]);
}

#[pollster::test]
async fn a_refusal_answers_nothing_about_the_address() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    let answer = support::send_raw(
        &kit.harness.router,
        http::Method::POST,
        WEBHOOK,
        &[
            ("svix-id", "msg_1"),
            ("svix-timestamp", &NOW.to_string()),
            ("svix-signature", "v1,AAAA"),
        ],
        &event_body("email.bounced", &[ADDRESS], Some("Permanent")),
    )
    .await;

    let body = answer.text();
    assert!(
        !body.contains(ADDRESS) && !body.contains(SECRET),
        "a refusal names neither the recipient nor the secret: {body}"
    );
}

#[pollster::test]
async fn a_verified_delivery_that_does_not_parse_is_accepted_and_changes_nothing() {
    let kit = bounce_kit();
    set_verified_email(&kit, ALICE, ADDRESS).await;

    // Genuinely from the provider — so refusing it only earns a
    // redelivery of the same unreadable body until the endpoint is
    // disabled, taking the real bounces with it.
    let status = deliver(&kit, "not json at all").await;

    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(suppressions(&kit).await, vec![(None, None)]);
}
