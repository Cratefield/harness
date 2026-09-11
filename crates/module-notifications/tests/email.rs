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

/// The `List-Unsubscribe` link of the last mail, as a path this harness
/// can be asked for.
fn unsubscribe_path(kit: &Kit) -> String {
    let link = kit
        .harness
        .mailer
        .last_message()
        .expect("one mail")
        .headers
        .iter()
        .find(|(key, _)| key == "List-Unsubscribe")
        .map(|(_, value)| value.trim_matches(['<', '>']).to_owned())
        .expect("a link");
    format!("/v1{}", link.split_once("/v1").expect("absolute").1)
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
async fn with_no_signer_the_one_click_headers_are_left_off_rather_than_lying() {
    // Issue #234. `Signer` is optional on this module, and without one
    // the link degrades to a venture front-end path this module does not
    // serve. RFC 8058 requires the advertised URI to accept the POST, so
    // a header pointing there either 404s or hits a single-page app that
    // answers `200 HTML` and looks like success while doing nothing —
    // and Gmail and Yahoo bulk-sender compliance fails silently, which is
    // the whole reason the headers were added.
    let kit = support::kit_without_signer(
        std::sync::Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        vec![Category::new(BOOKING).email(true)],
        &[],
    );
    set_email(&kit, ALICE, "alice@example.test", true).await;
    notify_and_drain(&kit, ALICE).await;

    let mail = kit.harness.mailer.last_message().expect("one mail");
    assert!(
        !mail
            .headers
            .iter()
            .any(|(name, _)| name.starts_with("List-Unsubscribe")),
        "a mail with no one-click header is compliant; one whose header \
         lies is not: {:?}",
        mail.headers
    );
    // The footer still tells a person where to go, which is all it ever
    // claimed — it is the header that promises a machine can act.
    assert!(
        mail.text.contains("/settings/notifications"),
        "{}",
        mail.text
    );
    assert!(!mail.text.contains("unsubscribe?token="), "{}", mail.text);
}

#[pollster::test]
async fn a_get_of_the_link_confirms_and_only_the_post_acts() {
    // Issue #237. Microsoft Defender Safe Links, Proofpoint URL Defense
    // and most scanning gateways fetch every link in a message before the
    // recipient sees it. A GET that applied the unsubscribe opted out
    // every member at any such company without a click, with no signal to
    // them or the venture — indistinguishable from a delivery failure.
    let kit = email_kit();
    set_email(&kit, ALICE, "alice@example.test", true).await;
    notify_and_drain(&kit, ALICE).await;
    let path = unsubscribe_path(&kit);

    let answer = support::send(&kit.harness.router, http::Method::GET, &path, None, None).await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
    let page = answer.text();
    assert!(
        page.contains("<form method=\"post\""),
        "the choice is offered, not taken: {page}"
    );
    assert!(
        !page.contains("token="),
        "and the token stays in the address bar rather than the markup: {page}"
    );

    notify_and_drain(&kit, ALICE).await;
    assert_eq!(
        kit.harness.mailer.sent().len(),
        2,
        "a scanner's fetch is not a click"
    );

    // The button the page renders posts to the same URL, and that acts.
    let answer = support::send(&kit.harness.router, http::Method::POST, &path, None, None).await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
    assert!(
        answer.text().contains("will not get these emails again"),
        "and a person who pressed it is told, not left on a blank page: {}",
        answer.text()
    );

    notify_and_drain(&kit, ALICE).await;
    assert_eq!(
        kit.harness.mailer.sent().len(),
        2,
        "the unsubscribe holds after the POST"
    );
}

#[pollster::test]
async fn a_get_with_a_token_that_does_not_verify_renders_no_form() {
    let kit = email_kit();
    let answer = support::send(
        &kit.harness.router,
        http::Method::GET,
        "/v1/notifications/email/unsubscribe?token=not-a-real-token",
        None,
        None,
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::BAD_REQUEST);
    assert!(!answer.text().contains("<form"), "{}", answer.text());
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

    // The window rolls and the account can be mailed again — and the two
    // notifications the cap suppressed (#232) arrive as one summary on the
    // same tick, beside the fresh mail.
    kit.clock.advance(3_601);
    notify_and_drain(&kit, ALICE).await;
    let sent = kit.harness.mailer.sent();
    assert_eq!(sent.len(), 4, "two capped-out drops become one summary");
    assert!(
        sent.iter()
            .any(|mail| mail.subject == "2 new booking notifications"),
        "the summary names the burst: {:?}",
        sent.iter().map(|mail| &mail.subject).collect::<Vec<_>>()
    );
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

#[pollster::test]
async fn the_footer_offers_stopping_every_category_and_it_holds() {
    // The header one-click stops one category. Somebody who wants out
    // entirely should not have to unsubscribe once per category as they
    // arrive, so the footer carries an `all` link — and that one sets
    // `unsubscribed_at` on the address rather than a preference row.
    let kit = kit_with(
        std::sync::Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        vec![
            Category::new(BOOKING).email(true),
            Category::new("coach_notes").email(true),
        ],
        &[],
    );
    set_email(&kit, ALICE, "alice@example.test", true).await;
    notify_and_drain(&kit, ALICE).await;

    let mail = kit.harness.mailer.last_message().expect("one mail");
    let all_link = mail
        .text
        .lines()
        .find(|line| {
            line.contains("unsubscribe?token=")
                && !mail.headers.iter().any(|(_, v)| v.contains(line.trim()))
        })
        .map(str::trim)
        .expect("an all link in the footer")
        .to_owned();
    let path = all_link.split_once("/v1").expect("absolute").1;

    let answer = support::send(
        &kit.harness.router,
        http::Method::POST,
        &format!("/v1{path}"),
        None,
        None,
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());

    // Every category, not just the one the mail was about.
    let db = kit.db();
    for category in [BOOKING, "coach_notes"] {
        let enqueued = kit
            .notifier
            .notify(&*db, ALICE, category, Notification::new(BOOKED, "again"))
            .await
            .expect("notify");
        if !enqueued.statements().is_empty() {
            db.batch(enqueued.statements()).await.expect("batch");
        }
    }
    kit.notifier.drain(&kit.scope()).await.expect("drain");
    assert_eq!(
        kit.harness.mailer.sent().len(),
        1,
        "the address is unsubscribed, so no category reaches it"
    );
}
