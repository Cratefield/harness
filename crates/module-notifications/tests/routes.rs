//! Issue #182 acceptance: the routes.
//!
//! Public writes stay off. The account is the token's `sub` and nothing
//! else, and another account's subscription is a `404` — never a `403`,
//! which would confirm the id exists.

mod support;

use cratefield_core::Recipient;
use cratefield_module_notifications::Transport;
use http::{Method, StatusCode};
use serde_json::json;
use support::{
    ALICE, BOB, BOOKING, CLIENT, COACH_NOTES, ISSUER, NOW, ROOM_STARTING, kit, register_body, send,
    token_for, token_with,
};

const SUBS: &str = "/v1/notifications/subscriptions";
const PREFS: &str = "/v1/notifications/preferences";
const TABLE: &str = "notifications_subscriptions";

fn apns(token: &str) -> Recipient {
    Recipient::apns(token)
}

#[pollster::test]
async fn registering_a_device_returns_its_id_and_stores_one_row() {
    let kit = kit();
    let answer = send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(json!({
            "transport": "apns",
            "recipient": { "apns": { "device_token": "device-alice-1" } },
            "app_id": "com.example.app",
            "app_version": "2.1.0",
        })),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let id = answer.json()["id"].as_str().expect("an id").to_owned();
    assert!(!id.is_empty());
    assert_eq!(kit.count(TABLE).await, 1);

    let listed = send(
        &kit.harness.router,
        Method::GET,
        SUBS,
        Some(&token_for(ALICE)),
        None,
    )
    .await;
    let body = listed.json();
    assert_eq!(body["subscriptions"][0]["id"], id.as_str());
    assert_eq!(body["subscriptions"][0]["transport"], "apns");
    assert_eq!(body["subscriptions"][0]["app_version"], "2.1.0");
}

#[pollster::test]
async fn re_registering_the_same_device_is_an_upsert_not_a_second_row() {
    // The whole reason the identity is (transport, recipient_hash): an app
    // registers on every launch, and a second row would mean a second copy
    // of every notification.
    let kit = kit();
    let first = send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(json!({
            "transport": "apns",
            "recipient": { "apns": { "device_token": "device-alice-1" } },
            "app_version": "2.1.0",
        })),
    )
    .await;
    let second = send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(json!({
            "transport": "apns",
            "recipient": { "apns": { "device_token": "device-alice-1" } },
            "app_version": "2.2.0",
        })),
    )
    .await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(
        first.json()["id"],
        second.json()["id"],
        "re-registration keeps the row it already had"
    );
    assert_eq!(kit.count(TABLE).await, 1);

    let listed = send(
        &kit.harness.router,
        Method::GET,
        SUBS,
        Some(&token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(
        listed.json()["subscriptions"][0]["app_version"],
        "2.2.0",
        "the upsert carries the new app version"
    );
}

#[pollster::test]
async fn a_device_that_signs_into_another_account_re_homes() {
    let kit = kit();
    let body = register_body(Transport::Apns, &apns("shared-device"));
    send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(body.clone()),
    )
    .await;
    send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(BOB)),
        Some(body),
    )
    .await;

    assert_eq!(kit.count(TABLE).await, 1, "one device, one row");
    let alice = send(
        &kit.harness.router,
        Method::GET,
        SUBS,
        Some(&token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(
        alice.json()["subscriptions"].as_array().map(Vec::len),
        Some(0),
        "the device moved: Alice must not keep receiving Bob's notifications"
    );
    let bob = send(
        &kit.harness.router,
        Method::GET,
        SUBS,
        Some(&token_for(BOB)),
        None,
    )
    .await;
    assert_eq!(
        bob.json()["subscriptions"].as_array().map(Vec::len),
        Some(1)
    );
}

#[pollster::test]
async fn a_transport_that_disagrees_with_the_recipient_is_refused() {
    let kit = kit();
    let answer = send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(json!({
            "transport": "fcm",
            "recipient": { "apns": { "device_token": "device-alice-1" } },
        })),
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", answer.text());
    assert_eq!(kit.count(TABLE).await, 0);
}

#[pollster::test]
async fn the_account_can_never_come_from_the_body() {
    // `public_writes = false` means the caller cannot name an account. A
    // body that tries is refused rather than quietly ignored, so a client
    // that believes it can register for someone else finds out.
    let kit = kit();
    let answer = send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(json!({
            "transport": "apns",
            "recipient": { "apns": { "device_token": "d" } },
            "account_id": BOB,
        })),
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", answer.text());
    assert_eq!(kit.count(TABLE).await, 0);
}

#[pollster::test]
async fn every_route_refuses_a_request_with_no_token() {
    let kit = kit();
    for (method, path, body) in [
        (
            Method::PUT,
            SUBS,
            Some(register_body(Transport::Apns, &apns("d"))),
        ),
        (Method::GET, SUBS, None),
        (Method::DELETE, "/v1/notifications/subscriptions/x", None),
        (Method::GET, PREFS, None),
        (
            Method::PUT,
            PREFS,
            Some(json!({ "preferences": { BOOKING: { "push": false } } })),
        ),
    ] {
        let answer = send(&kit.harness.router, method.clone(), path, None, body).await;
        assert_eq!(
            answer.status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} answered {}",
            answer.status
        );
    }
    assert_eq!(kit.count(TABLE).await, 0);
    assert_eq!(kit.count("notifications_preferences").await, 0);
}

#[pollster::test]
async fn a_token_minted_for_another_client_is_refused() {
    // The check a hand-written verifier forgets: the signature is ours,
    // the issuer is ours, and the token is still not for this app.
    let kit = kit();
    let other = token_with(&json!({
        "sub": ALICE, "aud": "client-somewhere-else", "iss": ISSUER,
        "sid": "s", "exp": NOW + 3_600, "iat": NOW - 10,
    }));
    let answer = send(&kit.harness.router, Method::GET, SUBS, Some(&other), None).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);

    let expired = token_with(&json!({
        "sub": ALICE, "aud": CLIENT, "iss": ISSUER,
        "sid": "s", "exp": NOW - 3_600, "iat": NOW - 7_200,
    }));
    let answer = send(&kit.harness.router, Method::GET, SUBS, Some(&expired), None).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
}

#[pollster::test]
async fn another_accounts_subscription_is_not_found_rather_than_forbidden() {
    let kit = kit();
    let created = send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(register_body(Transport::Apns, &apns("device-alice-1"))),
    )
    .await;
    let id = created.json()["id"].as_str().expect("an id").to_owned();

    let answer = send(
        &kit.harness.router,
        Method::DELETE,
        &format!("{SUBS}/{id}"),
        Some(&token_for(BOB)),
        None,
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::NOT_FOUND,
        "403 would confirm the id exists"
    );
    assert_eq!(kit.count(TABLE).await, 1, "and it must not be deleted");

    // Indistinguishable from an id that never existed.
    let missing = send(
        &kit.harness.router,
        Method::DELETE,
        &format!("{SUBS}/01JNOSUCHSUBSCRIPTION"),
        Some(&token_for(BOB)),
        None,
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let without_instance = |answer: &support::Answer| {
        let mut body = answer.json();
        body.as_object_mut()
            .expect("problem body")
            .remove("instance");
        body
    };
    assert_eq!(
        without_instance(&missing),
        without_instance(&answer),
        "an id that exists and one that never did must be indistinguishable"
    );
}

#[pollster::test]
async fn signing_out_deletes_your_own_subscription() {
    let kit = kit();
    let created = send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(register_body(Transport::Apns, &apns("device-alice-1"))),
    )
    .await;
    let id = created.json()["id"].as_str().expect("an id").to_owned();
    let answer = send(
        &kit.harness.router,
        Method::DELETE,
        &format!("{SUBS}/{id}"),
        Some(&token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    assert_eq!(kit.count(TABLE).await, 0);
}

#[pollster::test]
async fn the_listing_shows_only_your_own_and_redacts_the_recipient() {
    let kit = kit();
    send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(BOB)),
        Some(register_body(Transport::Apns, &apns("device-bob"))),
    )
    .await;
    send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(register_body(
            Transport::Webpush,
            &Recipient::web_push(
                "https://fcm.googleapis.com/wp/cAPABILITYtokenPATH",
                "BP256dhPublicKeyValue",
                "AuthSecretValue",
            ),
        )),
    )
    .await;

    let listed = send(
        &kit.harness.router,
        Method::GET,
        SUBS,
        Some(&token_for(ALICE)),
        None,
    )
    .await;
    let text = listed.text();
    assert_eq!(
        listed.json()["subscriptions"].as_array().map(Vec::len),
        Some(1),
        "another account's device is not listed"
    );
    assert!(!text.contains("device-bob"), "{text}");
    // A Web Push endpoint is a bearer capability URL and `auth` is the
    // RFC 8291 secret. Neither may leave the database.
    assert!(!text.contains("cAPABILITYtokenPATH"), "{text}");
    assert!(!text.contains("AuthSecretValue"), "{text}");
    assert!(!text.contains("BP256dhPublicKeyValue"), "{text}");
    assert_eq!(
        listed.json()["subscriptions"][0]["recipient_preview"],
        "https://fcm.googleapis.com/\u{2026}"
    );
}

#[pollster::test]
async fn preferences_start_at_the_declared_defaults() {
    let kit = kit();
    let answer = send(
        &kit.harness.router,
        Method::GET,
        PREFS,
        Some(&token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let prefs = &answer.json()["preferences"];
    assert_eq!(prefs[BOOKING]["push"], true);
    assert_eq!(
        prefs[COACH_NOTES]["push"], false,
        "a category declared default_enabled(false) is off"
    );
    assert_eq!(prefs[ROOM_STARTING]["push"], true);
    assert_eq!(
        kit.count("notifications_preferences").await,
        0,
        "reading defaults writes nothing"
    );
}

#[pollster::test]
async fn writing_one_channel_leaves_the_others_alone() {
    // The in-app and email switches exist here so #187 and #189 need no
    // migration. This child must carry them through untouched.
    let kit = kit();
    let answer = send(
        &kit.harness.router,
        Method::PUT,
        PREFS,
        Some(&token_for(ALICE)),
        Some(json!({ "preferences": { BOOKING: { "push": false } } })),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let prefs = &answer.json()["preferences"];
    assert_eq!(prefs[BOOKING]["push"], false);
    assert_eq!(prefs[BOOKING]["in_app"], true, "untouched, at its default");
    assert_eq!(prefs[BOOKING]["email"], true, "untouched, at its default");

    // And a second write updates the row rather than inserting another.
    let answer = send(
        &kit.harness.router,
        Method::PUT,
        PREFS,
        Some(&token_for(ALICE)),
        Some(json!({ "preferences": { BOOKING: { "email": false } } })),
    )
    .await;
    let prefs = &answer.json()["preferences"];
    assert_eq!(prefs[BOOKING]["push"], false, "the earlier choice survives");
    assert_eq!(prefs[BOOKING]["email"], false);
    assert_eq!(kit.count("notifications_preferences").await, 1);
}

#[pollster::test]
async fn an_undeclared_category_is_refused_and_writes_nothing() {
    let kit = kit();
    let answer = send(
        &kit.harness.router,
        Method::PUT,
        PREFS,
        Some(&token_for(ALICE)),
        Some(json!({
            "preferences": { BOOKING: { "push": false }, "not_a_category": { "push": true } }
        })),
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", answer.text());
    assert!(
        answer.text().contains("unknown-category"),
        "{}",
        answer.text()
    );
    assert_eq!(
        kit.count("notifications_preferences").await,
        0,
        "the whole write is refused, not the unknown half"
    );
}

#[pollster::test]
async fn one_accounts_preferences_are_not_anothers() {
    let kit = kit();
    send(
        &kit.harness.router,
        Method::PUT,
        PREFS,
        Some(&token_for(ALICE)),
        Some(json!({ "preferences": { BOOKING: { "push": false } } })),
    )
    .await;
    let bob = send(
        &kit.harness.router,
        Method::GET,
        PREFS,
        Some(&token_for(BOB)),
        None,
    )
    .await;
    assert_eq!(bob.json()["preferences"][BOOKING]["push"], true);
}
