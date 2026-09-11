//! Issue #190 acceptance: one notification, four recipients, four
//! languages.
//!
//! The rules under test, in the order they are easy to get wrong:
//!
//! - the language is resolved **per recipient at delivery**, never when
//!   the caller queues the message;
//! - a venture that renders its own strings pays nothing and behaves
//!   exactly as it did before this existed;
//! - a missing translation is visible from both ends — the recipient sees
//!   the message id, the venture gets an event — and the event carries
//!   identifiers only;
//! - `native` and `both` reach APNs and FCM as loc keys, and **never**
//!   reach Web Push, which has no such mechanism.

mod support;

use std::sync::Arc;

use cratefield_core::{LocKeys, Notification, Recipient};
use cratefield_i18n::FluentCatalog;
use cratefield_module_notifications::{
    Category, EVENT_MISSING_TRANSLATION, Localizable, Notifications, RenderMode,
};
use serde_json::{Value, json};
use support::{
    ALICE, BOOKING, Kit, ROOM_STARTING, ScriptedPush, kit_customised, register_body, send,
    send_with_headers, token_for,
};

const EN: &str = "\
booking-confirmed =
    .title = Booking confirmed
    .body = { $places ->
        [one] One place with { $coach }
       *[other] { $places } places with { $coach }
    }
    .subject = Your booking with { $coach }
";

const ID: &str = "\
booking-confirmed =
    .title = Pesanan dikonfirmasi
    .body = { $places } tempat bersama { $coach }
    .subject = Pesanan Anda
";

const AR: &str = "\
booking-confirmed =
    .title = تم تأكيد الحجز
    .body = مع { $coach }
";

fn catalog() -> FluentCatalog {
    FluentCatalog::builder()
        .default_locale("en")
        .locale("en", EN)
        .locale("id", ID)
        .locale("ar", AR)
        .build()
        .expect("the catalog parses")
}

/// The message every test sends unless it says otherwise.
fn booking() -> Localizable {
    Localizable::new("booking-confirmed")
        .arg("places", 2)
        .arg("coach", "Sari")
}

/// A kit with a catalog, a `booking` category opted into email, and a
/// `room_starting` category whose render mode the caller picks.
fn localised_kit(push: Arc<ScriptedPush>, room_mode: RenderMode) -> Kit {
    kit_customised(
        push,
        vec![
            Category::new(BOOKING).email(true),
            Category::new(ROOM_STARTING).render(room_mode),
        ],
        &[],
        |module: Notifications| {
            module
                .catalog(catalog())
                .messages(["booking-confirmed"])
                .default_locale("en")
        },
    )
}

/// Registers one device, optionally telling the server its language.
async fn register(kit: &Kit, account: &str, recipient: &Recipient, locale: Option<&str>) -> String {
    let mut body = register_body(
        cratefield_module_notifications::Transport::of(recipient),
        recipient,
    );
    if let Some(locale) = locale {
        body["locale"] = json!(locale);
    }
    let answer = send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/subscriptions",
        Some(&token_for(account)),
        Some(body),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
    answer.json()["id"].as_str().expect("an id").to_owned()
}

/// Sets the account's own language through the preferences route.
async fn set_account_locale(kit: &Kit, account: &str, locale: &str) -> Value {
    let answer = send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/preferences",
        Some(&token_for(account)),
        Some(json!({ "preferences": {}, "locale": locale })),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
    answer.json()
}

/// A verified address, so the email channel is open.
async fn set_email(kit: &Kit, account: &str, address: &str) {
    let answer = send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/email",
        Some(&support::token_for_verified_email(account, address)),
        Some(json!({ "email": address })),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
}

async fn notify_and_drain(
    kit: &Kit,
    account: &str,
    category: &str,
    message: impl Into<cratefield_module_notifications::Message>,
) {
    let db = kit.db();
    kit.notifier
        .notify_now(&*db, &kit.scope(), account, category, message)
        .await
        .expect("notify");
    kit.notifier.drain(&kit.scope()).await.expect("drain");
    // Events are emitted through `Defer`, which the kit queues rather
    // than runs: nothing reaches the bus until this.
    kit.harness.defer.drain().await;
}

/// The notification one subscription actually received.
fn sent_to(push: &ScriptedPush, recipient: &Recipient) -> Notification {
    push.calls()
        .into_iter()
        .find(|(to, _)| to == recipient)
        .map_or_else(
            || panic!("nothing was sent to {recipient:?}"),
            |(_, notification)| notification,
        )
}

// ---------------------------------------------------------------------------
// The headline: one notify, four languages

#[pollster::test]
async fn one_notify_reaches_each_recipient_in_its_own_language() {
    let push = Arc::new(ScriptedPush::default());
    let kit = localised_kit(Arc::clone(&push), RenderMode::Server);

    let browser = Recipient::web_push("https://push.example.test/wp/aaa", "p256dh", "auth");
    let phone = Recipient::fcm("registration-token-for-the-phone");
    // The browser says English; the phone says Indonesian. One account,
    // two answers — which is the whole reason the language cannot be
    // chosen when the caller queues the notification.
    register(&kit, ALICE, &browser, Some("en-GB")).await;
    register(&kit, ALICE, &phone, Some("id-ID")).await;
    // And the account itself reads Indonesian, which is what the inbox
    // and the mailbox use: there is one of each.
    set_account_locale(&kit, ALICE, "id").await;
    set_email(&kit, ALICE, "alice@example.test").await;

    notify_and_drain(&kit, ALICE, BOOKING, booking()).await;

    assert_eq!(
        sent_to(&push, &browser).title,
        "Booking confirmed",
        "the browser said English"
    );
    assert_eq!(
        sent_to(&push, &phone).title,
        "Pesanan dikonfirmasi",
        "the phone said Indonesian"
    );
    assert_eq!(
        sent_to(&push, &phone).body,
        "2 tempat bersama Sari",
        "arguments are substituted in the recipient's own string"
    );

    // The inbox row: the account's language, stored rendered.
    let inbox = kit.rows("notifications_inbox").await;
    assert_eq!(inbox.len(), 1, "one row per account, not per device");
    assert_eq!(
        inbox[0].get::<String>("title").as_deref(),
        Some("Pesanan dikonfirmasi")
    );
    assert_eq!(inbox[0].get::<String>("locale").as_deref(), Some("id"));
    assert_eq!(
        inbox[0].get::<String>("loc_key").as_deref(),
        Some("booking-confirmed"),
        "the message is kept beside the text so a client can re-render"
    );

    // And the mail.
    let mail = kit.harness.mailer.last_message().expect("one mail");
    assert_eq!(mail.subject, "Pesanan Anda", "the catalog's own `.subject`");
    assert!(mail.text.contains("Pesanan dikonfirmasi"), "{}", mail.text);
    assert!(
        mail.headers
            .iter()
            .any(|(name, value)| name == "Content-Language" && value == "id"),
        "{:?}",
        mail.headers
    );
}

// ---------------------------------------------------------------------------
// Precedence

#[pollster::test]
async fn the_subscription_beats_the_account_which_beats_the_venture() {
    let push = Arc::new(ScriptedPush::default());
    let kit = localised_kit(Arc::clone(&push), RenderMode::Server);

    let told = Recipient::apns("device-that-said-arabic");
    let silent = Recipient::apns("device-that-said-nothing");
    register(&kit, ALICE, &told, Some("ar")).await;
    register(&kit, ALICE, &silent, None).await;
    set_account_locale(&kit, ALICE, "id").await;

    notify_and_drain(&kit, ALICE, BOOKING, booking()).await;
    assert_eq!(
        sent_to(&push, &told).title,
        "تم تأكيد الحجز",
        "the subscription's own locale wins"
    );
    assert_eq!(
        sent_to(&push, &silent).title,
        "Pesanan dikonfirmasi",
        "a device that never said falls through to the account"
    );

    // And with no account answer either, the venture's default.
    let push = Arc::new(ScriptedPush::default());
    let kit = localised_kit(Arc::clone(&push), RenderMode::Server);
    register(&kit, ALICE, &silent, None).await;
    notify_and_drain(&kit, ALICE, BOOKING, booking()).await;
    assert_eq!(sent_to(&push, &silent).title, "Booking confirmed");
}

#[pollster::test]
async fn accept_language_is_read_with_its_quality_values() {
    let push = Arc::new(ScriptedPush::default());
    let kit = localised_kit(Arc::clone(&push), RenderMode::Server);
    let browser = Recipient::web_push("https://push.example.test/wp/bbb", "p256dh", "auth");

    // No `locale` field: a browser has nothing else to offer. `id` wins on
    // quality even though English is listed first.
    let answer = send_with_headers(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/subscriptions",
        &token_for(ALICE),
        &[("accept-language", "en-US;q=0.5, id;q=0.9, de;q=0.1")],
        Some(register_body(
            cratefield_module_notifications::Transport::Webpush,
            &browser,
        )),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());

    notify_and_drain(&kit, ALICE, BOOKING, booking()).await;
    assert_eq!(sent_to(&push, &browser).title, "Pesanan dikonfirmasi");
}

#[pollster::test]
async fn garbage_never_reaches_a_column_and_nothing_panics() {
    // The failure arm. Every one of these is text somebody can send, and
    // the column must be left empty rather than hold it — because from a
    // column it reaches a log, an export, and a `lang` attribute in
    // somebody's browser.
    const JUNK: [&str; 4] = [
        "not a language",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "",
    ];
    let push = Arc::new(ScriptedPush::default());
    let kit = localised_kit(Arc::clone(&push), RenderMode::Server);

    for (index, junk) in JUNK.into_iter().enumerate() {
        // In the body field and in the header, which are the two doors.
        let recipient = Recipient::apns(format!("device-{index}"));
        let mut body = register_body(cratefield_module_notifications::Transport::Apns, &recipient);
        body["locale"] = json!(junk);
        let answer = send_with_headers(
            &kit.harness.router,
            http::Method::PUT,
            "/v1/notifications/subscriptions",
            &token_for(ALICE),
            &[("accept-language", junk)],
            Some(body),
        )
        .await;
        assert_eq!(
            answer.status,
            http::StatusCode::OK,
            "registration is not refused over a language nobody can read: {}",
            answer.text()
        );
    }

    for row in kit.rows("notifications_subscriptions").await {
        assert_eq!(
            row.get::<String>("locale"),
            None,
            "a tag that does not parse is dropped, never stored"
        );
    }

    // And the delivery still happens, in the venture's default.
    notify_and_drain(&kit, ALICE, BOOKING, booking()).await;
    assert_eq!(push.calls().len(), JUNK.len());
    for (_, notification) in push.calls() {
        assert_eq!(notification.title, "Booking confirmed");
    }
}

#[pollster::test]
async fn a_header_that_is_half_usable_yields_only_the_half_that_parses() {
    // `Accept-Language` is a parameterised list, so everything after the
    // `;` of an entry is a parameter — junk included. The tag in front of
    // it is a real request for English and is honoured; nothing after it
    // reaches the column.
    let kit = localised_kit(Arc::new(ScriptedPush::default()), RenderMode::Server);
    let recipient = Recipient::apns("a-phone");
    let answer = send_with_headers(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/subscriptions",
        &token_for(ALICE),
        &[(
            "accept-language",
            "en; DROP TABLE notifications_subscriptions",
        )],
        Some(register_body(
            cratefield_module_notifications::Transport::Apns,
            &recipient,
        )),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::OK, "{}", answer.text());
    let rows = kit.rows("notifications_subscriptions").await;
    assert_eq!(
        rows[0].get::<String>("locale").as_deref(),
        Some("en"),
        "the canonical tag and nothing else"
    );
}

#[pollster::test]
async fn an_account_locale_that_is_not_a_tag_is_refused_without_being_echoed() {
    let kit = localised_kit(Arc::new(ScriptedPush::default()), RenderMode::Server);
    let secret = "en'; DROP TABLE notifications_locales; --";
    let answer = send(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/preferences",
        Some(&token_for(ALICE)),
        Some(json!({ "preferences": {}, "locale": secret })),
    )
    .await;
    assert_eq!(answer.status, http::StatusCode::BAD_REQUEST);
    assert!(
        !answer.text().contains("DROP TABLE"),
        "a validation message is a log line and a support ticket: {}",
        answer.text()
    );
    assert!(
        kit.rows("notifications_locales").await.is_empty(),
        "and nothing was written"
    );
}

#[pollster::test]
async fn the_preferences_route_reports_the_language_and_its_direction() {
    let kit = localised_kit(Arc::new(ScriptedPush::default()), RenderMode::Server);

    let body = send(
        &kit.harness.router,
        http::Method::GET,
        "/v1/notifications/preferences",
        Some(&token_for(ALICE)),
        None,
    )
    .await
    .json();
    assert_eq!(
        body["locale"], "en",
        "the venture's default until it is set"
    );
    assert_eq!(body["dir"], "ltr");

    let body = set_account_locale(&kit, ALICE, "ar").await;
    assert_eq!(body["locale"], "ar");
    assert_eq!(
        body["dir"], "rtl",
        "direction is the server's answer: no browser API gives it, and a \
         second list in the client would drift"
    );
}

#[pollster::test]
async fn a_first_visit_is_seeded_from_accept_language_and_a_later_one_is_not() {
    let kit = localised_kit(Arc::new(ScriptedPush::default()), RenderMode::Server);

    let body = send_with_headers(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/preferences",
        &token_for(ALICE),
        &[("accept-language", "id-ID,id;q=0.9,en;q=0.5")],
        Some(json!({ "preferences": {} })),
    )
    .await
    .json();
    assert_eq!(body["locale"], "id-ID", "an account with none is seeded");

    // A borrowed English browser must not un-choose it.
    let body = send_with_headers(
        &kit.harness.router,
        http::Method::PUT,
        "/v1/notifications/preferences",
        &token_for(ALICE),
        &[("accept-language", "en-GB")],
        Some(json!({ "preferences": {} })),
    )
    .await
    .json();
    assert_eq!(
        body["locale"], "id-ID",
        "and an account with one is left alone"
    );
}

// ---------------------------------------------------------------------------
// A missing translation is visible, and says nothing it should not

#[pollster::test]
async fn a_missing_key_renders_the_key_and_emits_an_event() {
    let push = Arc::new(ScriptedPush::default());
    let kit = localised_kit(Arc::clone(&push), RenderMode::Server);
    let phone = Recipient::apns("a-phone");
    register(&kit, ALICE, &phone, Some("id")).await;

    // `room-starting` is in no locale. Every argument here is a value this
    // module must never put in an event or a log.
    let message = Localizable::new("room-starting")
        .arg("coach", "alice@example.test")
        .arg("code", "tok_live_51H8secret")
        .url("https://push.example.test/wp/cAPABILITYtoken");
    notify_and_drain(&kit, ALICE, ROOM_STARTING, message).await;

    let sent = sent_to(&push, &phone);
    assert_eq!(
        sent.title, "room-starting.title",
        "an empty title looks delivered; the key is a bug report"
    );
    assert_eq!(sent.body, "room-starting.body");
    assert_eq!(
        sent.url.as_deref(),
        Some("https://push.example.test/wp/cAPABILITYtoken"),
        "and the caller's url still reaches the device, which is where it belongs"
    );

    let events = kit.events.payloads(EVENT_MISSING_TRANSLATION);
    assert!(!events.is_empty(), "a missing translation is never silent");
    for payload in &events {
        let text = payload.to_string();
        assert!(text.contains("room-starting"), "{text}");
        assert!(
            text.contains("\"locale\""),
            "the event names the locale so a venture knows which file to edit: {text}"
        );
        for secret in [
            "alice@example.test",
            "tok_live_51H8secret",
            "cAPABILITYtoken",
            "push.example.test",
        ] {
            assert!(
                !text.contains(secret),
                "the event carries identifiers only: {text}"
            );
        }
    }
}

#[pollster::test]
async fn a_missing_key_is_reported_even_for_an_account_with_nothing_to_deliver_to() {
    // No device, no mailbox: the inbox row is the only thing written, and
    // the drain never runs. The report has to come from the fan-out.
    let kit = localised_kit(Arc::new(ScriptedPush::default()), RenderMode::Server);
    let db = kit.db();
    kit.notifier
        .notify_now(
            &*db,
            &kit.scope(),
            ALICE,
            ROOM_STARTING,
            Localizable::new("room-starting"),
        )
        .await
        .expect("notify");
    kit.harness.defer.drain().await;
    assert!(
        !kit.events.payloads(EVENT_MISSING_TRANSLATION).is_empty(),
        "the account nobody can reach is exactly the one whose broken message would be silent"
    );
}

// ---------------------------------------------------------------------------
// Native passthrough

/// The loc keys an app that ships its own strings supplies.
fn app_keys() -> LocKeys {
    LocKeys {
        title_loc_key: Some("ROOM_STARTING".to_owned()),
        title_loc_args: vec!["Yoga".to_owned()],
        body_loc_key: Some("ROOM_BODY".to_owned()),
        body_loc_args: Vec::new(),
    }
}

#[pollster::test]
async fn native_sends_the_apps_keys_to_apns_and_fcm_and_never_to_web_push() {
    for mode in [RenderMode::Native, RenderMode::Both] {
        let push = Arc::new(ScriptedPush::default());
        let kit = localised_kit(Arc::clone(&push), mode);

        let phone = Recipient::apns("an-iphone");
        let android = Recipient::fcm("an-android");
        let browser = Recipient::web_push("https://push.example.test/wp/ccc", "p", "a");
        for recipient in [&phone, &android, &browser] {
            register(&kit, ALICE, recipient, Some("id")).await;
        }

        notify_and_drain(
            &kit,
            ALICE,
            ROOM_STARTING,
            Localizable::new("booking-confirmed")
                .arg("places", 1)
                .arg("coach", "Sari")
                .loc(app_keys()),
        )
        .await;

        for recipient in [&phone, &android] {
            assert_eq!(
                sent_to(&push, recipient).loc,
                Some(app_keys()),
                "{mode}: a token transport gets the app's own keys"
            );
        }
        assert_eq!(
            sent_to(&push, &browser).loc,
            None,
            "{mode}: Web Push has no loc-key mechanism, so it never sees them"
        );
        assert_eq!(
            sent_to(&push, &browser).title,
            "Pesanan dikonfirmasi",
            "{mode}: and a browser is always sent the rendered text, in its own language"
        );
    }
}

#[pollster::test]
async fn native_and_both_differ_in_the_language_of_the_text_beside_the_keys() {
    // The only thing that separates them, and the reason both exist:
    // `native` says the app owns the language, so the text is a fallback
    // for a build too old to have the key and the venture's default is the
    // right thing to send. `both` renders for the recipient as well.
    let expected = [
        (RenderMode::Native, "Booking confirmed"),
        (RenderMode::Both, "Pesanan dikonfirmasi"),
    ];
    for (mode, title) in expected {
        let push = Arc::new(ScriptedPush::default());
        let kit = localised_kit(Arc::clone(&push), mode);
        let phone = Recipient::apns("an-iphone");
        register(&kit, ALICE, &phone, Some("id")).await;
        notify_and_drain(
            &kit,
            ALICE,
            ROOM_STARTING,
            Localizable::new("booking-confirmed")
                .arg("places", 1)
                .arg("coach", "Sari")
                .loc(app_keys()),
        )
        .await;
        assert_eq!(sent_to(&push, &phone).title, title, "{mode}");
    }
}

#[pollster::test]
async fn server_is_the_default_and_attaches_no_keys_at_all() {
    let push = Arc::new(ScriptedPush::default());
    let kit = localised_kit(Arc::clone(&push), RenderMode::Server);
    let phone = Recipient::apns("an-iphone");
    register(&kit, ALICE, &phone, Some("id")).await;
    notify_and_drain(
        &kit,
        ALICE,
        ROOM_STARTING,
        Localizable::new("booking-confirmed")
            .arg("places", 1)
            .arg("coach", "Sari")
            .loc(app_keys()),
    )
    .await;
    assert_eq!(
        sent_to(&push, &phone).loc,
        None,
        "a category that did not ask for native rendering does not get it, however \
         the caller filled the message in"
    );
}

// ---------------------------------------------------------------------------
// A single-language venture pays nothing

#[pollster::test]
async fn a_caller_that_passes_rendered_text_keeps_working_untouched() {
    // No catalog at all — the composition a venture with one language has
    // — and the call site is the one that existed before #190.
    let push = Arc::new(ScriptedPush::default());
    let kit = support::kit_with(push.clone(), vec![Category::new(BOOKING).email(true)], &[]);
    let phone = Recipient::apns("an-iphone");
    register(&kit, ALICE, &phone, Some("id")).await;
    set_account_locale(&kit, ALICE, "id").await;
    set_email(&kit, ALICE, "alice@example.test").await;

    let mut notification = Notification::new("Booked", "See you Tuesday");
    // Including the native passthrough that was documented before this
    // issue: a rendered caller's `loc` travels exactly as it did.
    notification.loc = Some(app_keys());
    notify_and_drain(&kit, ALICE, BOOKING, notification).await;

    let sent = sent_to(&push, &phone);
    assert_eq!(sent.title, "Booked", "an Indonesian device changes nothing");
    assert_eq!(sent.body, "See you Tuesday");
    assert_eq!(sent.loc, Some(app_keys()));

    let inbox = kit.rows("notifications_inbox").await;
    assert_eq!(inbox[0].get::<String>("title").as_deref(), Some("Booked"));
    assert_eq!(
        inbox[0].get::<String>("locale"),
        None,
        "no locale is claimed for a string the venture wrote itself"
    );
    let mail = kit.harness.mailer.last_message().expect("one mail");
    assert_eq!(mail.subject, "Booked");
    assert!(kit.events.payloads(EVENT_MISSING_TRANSLATION).is_empty());
}

#[pollster::test]
async fn a_localizable_message_without_a_catalog_is_an_error_not_a_silent_english_fallback() {
    let kit = support::kit_with(
        Arc::new(ScriptedPush::default()),
        vec![Category::new(BOOKING)],
        &[],
    );
    let db = kit.db();
    let err = kit
        .notifier
        .notify(&*db, ALICE, BOOKING, booking())
        .await
        .expect_err("a venture that named a message it has no strings for has a bug");
    assert!(err.to_string().contains("booking-confirmed"), "{err}");
    assert!(err.to_string().contains("catalog"), "{err}");
}

// ---------------------------------------------------------------------------
// Right to left

#[pollster::test]
async fn an_arabic_mail_is_marked_right_to_left_in_the_body_and_the_headers() {
    let kit = localised_kit(Arc::new(ScriptedPush::default()), RenderMode::Server);
    set_account_locale(&kit, ALICE, "ar").await;
    set_email(&kit, ALICE, "alice@example.test").await;
    notify_and_drain(&kit, ALICE, BOOKING, booking()).await;

    let mail = kit.harness.mailer.last_message().expect("one mail");
    assert!(mail.html.contains("dir=\"rtl\""), "{}", mail.html);
    assert!(mail.html.contains("lang=\"ar\""), "{}", mail.html);
    assert!(mail.html.contains("تم تأكيد الحجز"), "{}", mail.html);
    assert!(
        mail.headers
            .iter()
            .any(|(name, value)| name == "Content-Language" && value == "ar"),
        "{:?}",
        mail.headers
    );
}

#[pollster::test]
async fn a_mail_that_fell_back_to_english_is_not_labelled_arabic() {
    // `ar` has no `.subject`, and the whole `room-starting` message is in
    // no locale at all. A mail that fell back must say what it is: marking
    // English text `ar` would right-align it in every client that obeys.
    let kit = kit_customised(
        Arc::new(ScriptedPush::default()),
        vec![Category::new(ROOM_STARTING).email(true)],
        &[],
        |module: Notifications| module.catalog(catalog()).default_locale("en"),
    );
    set_account_locale(&kit, ALICE, "ar").await;
    set_email(&kit, ALICE, "alice@example.test").await;
    notify_and_drain(
        &kit,
        ALICE,
        ROOM_STARTING,
        Localizable::new("room-starting"),
    )
    .await;

    let mail = kit.harness.mailer.last_message().expect("one mail");
    assert!(mail.html.contains("dir=\"ltr\""), "{}", mail.html);
    assert!(
        mail.headers
            .iter()
            .any(|(name, value)| name == "Content-Language" && value == "en"),
        "{:?}",
        mail.headers
    );
}

// ---------------------------------------------------------------------------
// The completeness check

#[test]
fn the_self_check_lists_every_gap_and_names_no_string() {
    use cratefield_core::Module as _;

    let module = Notifications::new()
        .category(Category::new(BOOKING))
        .catalog(catalog())
        .messages(["booking-confirmed", "room-starting"]);
    let problems = module.self_check();
    assert_eq!(
        problems.len(),
        6,
        "three locales, two attributes each of the one message nothing \
         translates — and nothing about `.subject`, which is optional: \
         {problems:?}"
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("id: room-starting.title")),
        "{problems:?}"
    );
    for problem in &problems {
        assert!(
            !problem.contains("Pesanan") && !problem.contains("Booking confirmed"),
            "the report is identifiers only: {problem}"
        );
    }

    // And the same gaps refuse the boot.
    let err = module
        .validate_config(&cratefield_core::EmptyConfig)
        .expect_err("a declared message with no translation is a misconfiguration");
    assert!(err.to_string().contains("room-starting"), "{err}");
}

#[test]
fn a_complete_catalog_and_a_venture_with_none_both_pass() {
    use cratefield_core::Module as _;

    let complete = Notifications::new()
        .category(Category::new(BOOKING))
        .catalog(
            FluentCatalog::builder()
                .default_locale("en")
                .locale("en", EN)
                .locale("id", ID)
                .build()
                .expect("parses"),
        )
        .messages(["booking-confirmed"]);
    assert_eq!(complete.self_check(), Vec::<String>::new());

    let single_language = Notifications::new().category(Category::new(BOOKING));
    assert_eq!(single_language.self_check(), Vec::<String>::new());
    single_language
        .validate_config(&cratefield_core::EmptyConfig)
        .expect("a venture with one language configures none of this");
}

#[test]
fn a_default_locale_the_deployment_cannot_read_is_refused_without_being_echoed() {
    use cratefield_core::Module as _;

    let cfg = cratefield_core::MapConfig::from_pairs([(
        "NOTIFICATIONS_DEFAULT_LOCALE",
        "en'; DROP TABLE notifications_locales; --",
    )]);
    let err = Notifications::new()
        .category(Category::new(BOOKING))
        .validate_config(&cfg)
        .expect_err("a default nobody can read would silently become the compiled-in one");
    assert!(
        err.to_string().contains("NOTIFICATIONS_DEFAULT_LOCALE"),
        "{err}"
    );
    assert!(
        !err.to_string().contains("DROP TABLE"),
        "names the variable, never the value: {err}"
    );
}
