//! Issue #189 acceptance: email as the third channel.
//!
//! The rules under test, in the order they are easy to get wrong: an
//! unverified address is never mailed, one notification is one email
//! however many devices the account has, and every refusal is re-read at
//! send time rather than trusted from when the row was written.

mod support;

use cratefield_core::Notification;
use cratefield_module_notifications::Category;
use serde_json::json;
use support::{ALICE, BOB, BOOKING, Kit, kit_with};

const BOOKED: &str = "Booked";

/// A kit whose `booking` category is opted into email.
fn email_kit() -> Kit {
    kit_with(
        std::sync::Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        vec![Category::new(BOOKING).email(true)],
        &[],
    )
}

/// Sets an address through the authenticated route. `verified` mirrors
/// what a real issuer would claim.
async fn set_email(kit: &Kit, account: &str, address: &str, verified: bool) -> http::StatusCode {
    let token = if verified {
        support::token_for_verified_email(account, address)
    } else {
        support::token_for(account)
    };
    support::send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/email",
        Some(&token),
        Some(json!({ "email": address })),
    )
    .await
    .status
}

async fn notify_and_drain(kit: &Kit, account: &str) {
    let db = kit.db();
    let enqueued = kit
        .notifier
        .notify(&*db, account, BOOKING, Notification::new(BOOKED, "Tuesday"))
        .await
        .expect("notify");
    if !enqueued.statements().is_empty() {
        db.batch(enqueued.statements()).await.expect("batch");
    }
    kit.notifier.drain(&kit.scope()).await.expect("drain");
}

#[pollster::test]
async fn a_verified_address_gets_one_email() {
    let kit = email_kit();
    assert_eq!(
        set_email(&kit, ALICE, "alice@example.test", true).await,
        http::StatusCode::OK
    );
    notify_and_drain(&kit, ALICE).await;

    let sent = kit.harness.mailer.sent();
    assert_eq!(sent.len(), 1, "one notification, one email");
    assert_eq!(sent[0].to, "alice@example.test");
    assert_eq!(sent[0].subject, BOOKED);
    assert!(sent[0].text.contains("Tuesday"));
}

#[pollster::test]
async fn an_unverified_address_is_never_mailed() {
    // An unverified address is somebody else's mailbox until proven
    // otherwise, and mailing it is what gets a sending domain blocked.
    let kit = email_kit();
    assert_eq!(
        set_email(&kit, ALICE, "alice@example.test", false).await,
        http::StatusCode::OK
    );
    notify_and_drain(&kit, ALICE).await;
    assert!(kit.harness.mailer.sent().is_empty());
}

#[pollster::test]
async fn an_account_with_no_address_is_a_no_op_not_an_error() {
    let kit = email_kit();
    notify_and_drain(&kit, ALICE).await;
    assert!(kit.harness.mailer.sent().is_empty());
}

#[pollster::test]
async fn a_category_not_opted_in_sends_no_mail() {
    // Email is off unless the venture says otherwise: it is the most
    // intrusive channel and the hardest to take back.
    let kit = kit_with(
        std::sync::Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        vec![Category::new(BOOKING)],
        &[],
    );
    assert_eq!(
        set_email(&kit, ALICE, "alice@example.test", true).await,
        http::StatusCode::OK
    );
    notify_and_drain(&kit, ALICE).await;
    assert!(kit.harness.mailer.sent().is_empty());
}

#[pollster::test]
async fn one_notification_is_one_email_however_many_devices() {
    // Per account, not per device: three phones is still one mail.
    let kit = email_kit();
    set_email(&kit, ALICE, "alice@example.test", true).await;
    for recipient in [
        cratefield_core::Recipient::apns("ios-token"),
        cratefield_core::Recipient::fcm("android-token"),
    ] {
        let transport = match recipient {
            cratefield_core::Recipient::Apns { .. } => "apns",
            _ => "fcm",
        };
        support::send(
            &kit.harness.router,
            http::Method::PUT,
            "/v1/notifications/subscriptions",
            Some(&support::token_for(ALICE)),
            Some(json!({ "transport": transport, "recipient": recipient })),
        )
        .await;
    }
    notify_and_drain(&kit, ALICE).await;
    assert_eq!(kit.harness.mailer.sent().len(), 1);
}

#[pollster::test]
async fn every_mail_carries_the_rfc_8058_headers() {
    // Gmail and Yahoo have required one-click of bulk senders since 2024,
    // and a "click here" line in the footer is not what they check for.
    let kit = email_kit();
    set_email(&kit, ALICE, "alice@example.test", true).await;
    notify_and_drain(&kit, ALICE).await;

    let mail = kit.harness.mailer.last_message().expect("one mail");
    let header = |name: &str| {
        mail.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let unsubscribe = header("List-Unsubscribe").expect("List-Unsubscribe");
    assert!(unsubscribe.starts_with('<') && unsubscribe.ends_with('>'));
    assert!(unsubscribe.contains("/v1/notifications/email/unsubscribe?token="));
    assert_eq!(
        header("List-Unsubscribe-Post").as_deref(),
        Some("List-Unsubscribe=One-Click")
    );
    assert!(
        mail.text.contains("unsubscribe?token="),
        "and a link a person can use, not only a machine"
    );
}

#[pollster::test]
async fn one_click_unsubscribe_stops_that_category_and_is_idempotent() {
    let kit = email_kit();
    set_email(&kit, ALICE, "alice@example.test", true).await;
    notify_and_drain(&kit, ALICE).await;

    let mail = kit.harness.mailer.last_message().expect("one mail");
    let link = mail
        .headers
        .iter()
        .find(|(key, _)| key == "List-Unsubscribe")
        .map(|(_, value)| value.trim_matches(['<', '>']).to_owned())
        .expect("a link");
    let path = link.split_once("/v1").expect("an absolute link").1;

    for _ in 0..2 {
        let answer = support::send(
            &kit.harness.router,
            http::Method::POST,
            &format!("/v1{path}"),
            None,
            None,
        )
        .await;
        assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
    }

    notify_and_drain(&kit, ALICE).await;
    assert_eq!(
        kit.harness.mailer.sent().len(),
        1,
        "the unsubscribe holds, and applying it twice changes nothing"
    );
}

#[pollster::test]
async fn a_tampered_unsubscribe_token_changes_nothing() {
    let kit = email_kit();
    set_email(&kit, ALICE, "alice@example.test", true).await;
    notify_and_drain(&kit, ALICE).await;

    let answer = support::send(
        &kit.harness.router,
        http::Method::POST,
        "/v1/notifications/email/unsubscribe?token=not-a-real-token",
        None,
        None,
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::BAD_REQUEST);

    notify_and_drain(&kit, ALICE).await;
    assert_eq!(
        kit.harness.mailer.sent().len(),
        2,
        "a token that does not verify switches nothing off"
    );
}

#[pollster::test]
async fn one_accounts_unsubscribe_link_cannot_switch_anothers_off() {
    let kit = email_kit();
    set_email(&kit, ALICE, "alice@example.test", true).await;
    set_email(&kit, BOB, "bob@example.test", true).await;
    notify_and_drain(&kit, ALICE).await;

    let alices_link = kit
        .harness
        .mailer
        .last_message()
        .expect("one mail")
        .headers
        .iter()
        .find(|(key, _)| key == "List-Unsubscribe")
        .map(|(_, value)| value.trim_matches(['<', '>']).to_owned())
        .expect("a link");
    let path = alices_link.split_once("/v1").expect("absolute").1;
    support::send(
        &kit.harness.router,
        http::Method::POST,
        &format!("/v1{path}"),
        None,
        None,
    )
    .await;

    notify_and_drain(&kit, BOB).await;
    assert!(
        kit.harness
            .mailer
            .sent()
            .iter()
            .any(|mail| mail.to == "bob@example.test"),
        "the token names Alice, so Bob still gets his mail"
    );
}

#[pollster::test]
async fn the_cooldown_caps_one_category_per_account() {
    let kit = kit_with(
        std::sync::Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        vec![Category::new(BOOKING).email(true)],
        &[("NOTIFICATIONS_EMAIL_MAX_PER_WINDOW", "2")],
    );
    set_email(&kit, ALICE, "alice@example.test", true).await;
    for _ in 0..4 {
        notify_and_drain(&kit, ALICE).await;
        kit.clock.advance(1);
    }
    assert_eq!(kit.harness.mailer.sent().len(), 2, "capped, not queued");

    // The window rolls and the account can be mailed again.
    kit.clock.advance(3_601);
    notify_and_drain(&kit, ALICE).await;
    assert_eq!(kit.harness.mailer.sent().len(), 3);
}

#[pollster::test]
async fn a_changed_address_starts_unverified() {
    // The previous address's verification was about a different mailbox.
    let kit = email_kit();
    set_email(&kit, ALICE, "alice@example.test", true).await;
    assert_eq!(
        set_email(&kit, ALICE, "elsewhere@example.test", false).await,
        http::StatusCode::OK
    );
    notify_and_drain(&kit, ALICE).await;
    assert!(
        kit.harness.mailer.sent().is_empty(),
        "the new address is unverified, so nothing is sent to either"
    );
}

#[pollster::test]
async fn the_email_route_refuses_a_request_with_no_token() {
    let kit = email_kit();
    let answer = support::send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/email",
        None,
        Some(json!({ "email": "someone@example.test" })),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::UNAUTHORIZED);
}

#[pollster::test]
async fn an_address_that_is_not_an_address_is_refused() {
    let kit = email_kit();
    assert_eq!(
        set_email(&kit, ALICE, "not-an-address", true).await,
        http::StatusCode::BAD_REQUEST
    );
}
