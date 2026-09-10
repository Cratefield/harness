//! The adapter's behaviour under a scripted `HttpClient`: the RFC 8030
//! request it builds, the RFC 8292 header it signs, and every status the
//! push services answer with mapped to the port's outcome.
//!
//! No network. The live path against a real push service is the sibling
//! issue's CI leg (#181), which stands up a self-hosted UnifiedPush server
//! and asserts a 2xx; the mapping below stays a unit test because a real
//! service will not produce a `410` on demand.

mod support;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cratefield_adapter_webpush::vapid::VapidKeys;
use cratefield_adapter_webpush::{DEFAULT_TTL, WebPush, WebPushConfigError, ece};
use cratefield_core::{Notification, Platform, Priority, Push, PushError, PushOutcome, Recipient};
use cratefield_testing::push_recipient_conformance;
use support::{Reply, ScriptedHttp, StepClock, decrypt, public_key_of};

// A throwaway P-256 key, generated for these tests only — NOT a real VAPID
// key. The same one `cratefield-push-auth` and `cratefield-adapter-apns`
// use, so the three suites assert bytes from one key.
const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcXMgRpW+eLn7ZvCx\nIuTdd8csWMZ69azlRzS0dy2FN6GhRANCAATJ6GazR2lhWcC3JYsazLR0uWOyDKrC\nmeP4HPWghRmfoa4z3Ux7mG3Ylz+auRaBukKGicSdSvVG+jGeQwr3fNag\n-----END PRIVATE KEY-----";
const SUBJECT: &str = "mailto:ops@example.test";

/// The subscription every test pushes to: RFC 8291 Appendix A's user agent,
/// so the request body can be opened with a key the RFC publishes.
const UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
const UA_PUBLIC: &str =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
const AUTH_SECRET: &str = "BTBZMqHH6r4Tts7J_aSIgg";
const ENDPOINT: &str = "https://updates.push.services.mozilla.com/wpush/v2/gAAAAAsubscription";

fn b64(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value).expect("base64url")
}

fn fixed<const N: usize>(value: &str) -> [u8; N] {
    b64(value).try_into().expect("fixed-size value")
}

fn subscriber() -> Recipient {
    Recipient::web_push(ENDPOINT, UA_PUBLIC, AUTH_SECRET)
}

fn adapter(http: &Arc<ScriptedHttp>, clock: &Arc<StepClock>) -> WebPush {
    WebPush::new(
        http.clone(),
        clock.clone(),
        VapidKeys::new(TEST_PEM, SUBJECT),
    )
    .expect("a valid VAPID key")
}

/// `vapid t=<jwt>, k=<key>` split into its two parameters.
fn vapid_parts(header: &str) -> (String, String) {
    let rest = header
        .strip_prefix("vapid ")
        .expect("the vapid auth scheme");
    let (t, k) = rest.split_once(", ").expect("t= and k=");
    (
        t.strip_prefix("t=").expect("t=").to_owned(),
        k.strip_prefix("k=").expect("k=").to_owned(),
    )
}

fn claims_of(jwt: &str) -> serde_json::Value {
    let segment = jwt.split('.').nth(1).expect("header.claims.signature");
    serde_json::from_slice(&b64(segment)).expect("claims are JSON")
}

fn header_of(jwt: &str) -> serde_json::Value {
    let segment = jwt.split('.').next().expect("header");
    serde_json::from_slice(&b64(segment)).expect("header is JSON")
}

// ---------------------------------------------------------------------------
// Configuration and recipients

#[test]
fn a_malformed_vapid_key_is_refused_at_construction() {
    let error = WebPush::new(
        ScriptedHttp::new(),
        StepClock::at(0),
        VapidKeys::new("not a key", SUBJECT),
    )
    .expect_err("not a key");
    assert!(matches!(error, WebPushConfigError::Vapid(_)), "{error}");

    let error = WebPush::new(
        ScriptedHttp::new(),
        StepClock::at(0),
        VapidKeys::new(TEST_PEM, "ops@example.test"),
    )
    .expect_err("a bare address is not a contact URI");
    assert!(matches!(error, WebPushConfigError::Vapid(_)), "{error}");

    let error = WebPush::with_record_size(
        ScriptedHttp::new(),
        StepClock::at(0),
        VapidKeys::new(TEST_PEM, SUBJECT),
        17,
    )
    .expect_err("below RFC 8188's floor");
    assert!(matches!(error, WebPushConfigError::Ece(_)), "{error}");
}

#[test]
fn not_configured_never_calls_the_network() {
    let push = WebPush::not_configured();
    let outcome =
        pollster::block_on(push.send(&subscriber(), &Notification::new("t", "b"))).unwrap();
    assert_eq!(outcome, PushOutcome::NotConfigured);
    assert_eq!(push.public_key(), None);
    assert_eq!(push.max_payload(), None);
}

#[test]
fn not_configured_still_refuses_the_transports_it_does_not_serve() {
    // Being unconfigured is a fact about credentials, not about transports:
    // answering `NotConfigured` for an APNs recipient would claim to serve
    // it, and a router reading that answer would stop looking for the
    // adapter that actually does.
    let push = WebPush::not_configured();
    pollster::block_on(push_recipient_conformance(&push, &[Platform::Web]));

    for other in [Recipient::apns("tok"), Recipient::fcm("tok")] {
        let error =
            pollster::block_on(push.send(&other, &Notification::new("a", "b"))).unwrap_err();
        assert!(
            matches!(error, PushError::Rejected(m) if m.contains("unsupported recipient")),
            "{other:?}"
        );
    }
}

#[test]
fn a_live_adapter_serves_web_push_and_nothing_else() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(1_700_000_000));
    pollster::block_on(push_recipient_conformance(&push, &[Platform::Web]));

    // APNs and FCM are refused without a request being made.
    let before = http.count();
    for other in [Recipient::apns("tok"), Recipient::fcm("tok")] {
        assert!(
            pollster::block_on(push.send(&other, &Notification::new("a", "b"))).is_err(),
            "{other:?}"
        );
    }
    assert_eq!(http.count(), before, "no request for a foreign transport");
}

#[test]
fn the_public_key_is_the_application_server_key_a_browser_subscribes_with() {
    let push = adapter(&ScriptedHttp::new(), &StepClock::at(0));
    let key = push.public_key().expect("configured");
    let decoded = b64(key);
    assert_eq!(decoded.len(), 65, "an uncompressed SEC1 point");
    assert_eq!(decoded[0], 0x04);
    assert_eq!(push.max_payload(), Some(3_993));
}

// ---------------------------------------------------------------------------
// The RFC 8030 request

#[test]
fn delivers_and_sends_the_rfc8030_request() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(1_700_000_000));

    let outcome = pollster::block_on(push.send(&subscriber(), &Notification::new("Hi", "there")))
        .expect("delivered");
    assert_eq!(
        outcome,
        PushOutcome::Delivered {
            id: Some("https://push.example/message/abc123".to_owned())
        },
        "the id is the Location of the push message resource"
    );

    http.last(|seen| {
        assert_eq!(seen.method, "POST");
        assert_eq!(seen.uri, ENDPOINT, "the endpoint verbatim, path included");
        assert_eq!(seen.header("content-encoding"), "aes128gcm");
        assert_eq!(seen.header("content-type"), "application/octet-stream");
        assert_eq!(seen.header("ttl"), DEFAULT_TTL.as_secs().to_string());
        assert_eq!(seen.header("ttl"), "86400");
        assert_eq!(seen.header("urgency"), "high");
        assert_eq!(seen.maybe_header("topic"), None, "no collapse_id, no Topic");
        // The legacy pre-RFC header is deliberately not sent.
        assert_eq!(seen.maybe_header("crypto-key"), None);
        assert!(seen.header("authorization").starts_with("vapid t="));
        // The body is the encrypted record, never the JSON.
        assert!(!seen.body.starts_with(b"{"));
        assert_eq!(
            seen.body.len(),
            ece::WEB_PUSH_HEADER_LEN
                + 17
                + b"{\"title\":\"Hi\",\"body\":\"there\",\"silent\":false}".len()
        );
    });
}

/// What the browser actually receives. This is the end of the chain: the
/// adapter's request body, opened with the subscription's private key, is
/// the payload JSON a service worker reads.
#[test]
fn the_body_on_the_wire_decrypts_to_the_service_worker_payload() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(1_700_000_000));

    let mut notification = Notification::new("Room starting", "Yoga in 10 min");
    notification.icon = Some("https://example.test/icon.png".to_owned());
    notification.url = Some("https://example.test/rooms/42".to_owned());
    notification.thread_id = Some("room-42".to_owned());
    notification.data = serde_json::json!({ "room_id": "42", "kind": "reminder" });

    pollster::block_on(push.send(&subscriber(), &notification)).expect("delivered");

    let body = http.last(|seen| seen.body.clone());
    let opened = decrypt(&fixed(UA_PRIVATE), &fixed(AUTH_SECRET), &body).expect("the browser");
    let payload: serde_json::Value = serde_json::from_slice(&opened).expect("JSON");

    assert_eq!(payload["title"], "Room starting");
    assert_eq!(payload["body"], "Yoga in 10 min");
    assert_eq!(payload["icon"], "https://example.test/icon.png");
    assert_eq!(payload["url"], "https://example.test/rooms/42");
    assert_eq!(payload["tag"], "room-42", "thread_id is the web `tag`");
    assert_eq!(payload["silent"], false);
    assert_eq!(payload["data"]["room_id"], "42", "custom data is nested");
    assert_eq!(payload["data"]["kind"], "reminder");
}

#[test]
fn the_payload_drops_the_fields_web_push_has_no_home_for() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    let mut notification = Notification::new("Hi", "there");
    notification.badge = Some(3); // an iOS icon count, not a web badge URL
    notification.category = Some("SESSION".to_owned());
    notification.loc = Some(cratefield_core::LocKeys {
        title_loc_key: Some("ROOM_STARTING".to_owned()),
        ..Default::default()
    });
    notification.silent = true;
    notification.collapse_id = Some("room-42".to_owned());

    pollster::block_on(push.send(&subscriber(), &notification)).expect("delivered");

    let body = http.last(|seen| seen.body.clone());
    let opened = decrypt(&fixed(UA_PRIVATE), &fixed(AUTH_SECRET), &body).expect("the browser");
    let payload: serde_json::Value = serde_json::from_slice(&opened).expect("JSON");
    let object = payload.as_object().expect("object");

    assert!(!object.contains_key("badge"), "{payload}");
    assert!(!object.contains_key("category"), "{payload}");
    assert!(!object.contains_key("loc"), "{payload}");
    // `collapse_id` is a header, not a payload field.
    assert!(!object.contains_key("collapse_id"), "{payload}");
    assert_eq!(payload["silent"], true);
    http.last(|seen| assert_eq!(seen.header("topic"), "room-42"));
}

#[test]
fn the_ttl_urgency_and_topic_headers_follow_the_notification() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    let mut notification = Notification::new("Hi", "there");
    notification.ttl = Some(Duration::ZERO);
    notification.priority = Priority::Conserve;
    // Longer than the 32 characters RFC 8030 §5.4 allows.
    notification.collapse_id = Some("thread/with a space/and-a-very-long-tail".to_owned());
    pollster::block_on(push.send(&subscriber(), &notification)).expect("delivered");

    http.last(|seen| {
        assert_eq!(seen.header("ttl"), "0", "deliver only if online now");
        assert_eq!(seen.header("urgency"), "normal");
        let topic = seen.header("topic");
        assert_eq!(topic.len(), 32);
        assert!(
            topic
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{topic}"
        );
    });

    // A sub-second TTL rounds up rather than becoming the drop-now
    // instruction.
    notification.ttl = Some(Duration::from_millis(900));
    pollster::block_on(push.send(&subscriber(), &notification)).expect("delivered");
    http.last(|seen| assert_eq!(seen.header("ttl"), "1"));
}

// ---------------------------------------------------------------------------
// VAPID

#[test]
fn the_vapid_header_is_signed_over_the_origin_and_verifies_under_its_own_key() {
    use p256::ecdsa::signature::Verifier as _;

    let http = ScriptedHttp::new();
    let clock = StepClock::at(1_700_000_000);
    let push = adapter(&http, &clock);
    pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).expect("delivered");

    let authorization = http.last(|seen| seen.header("authorization").to_owned());
    let (jwt, key) = vapid_parts(&authorization);

    assert_eq!(
        header_of(&jwt),
        serde_json::json!({"typ": "JWT", "alg": "ES256"})
    );
    let claims = claims_of(&jwt);
    assert_eq!(
        claims["aud"], "https://updates.push.services.mozilla.com",
        "the aud is the origin, never the subscription path"
    );
    assert_eq!(claims["sub"], SUBJECT);
    assert_eq!(
        claims["exp"],
        1_700_000_000_i64 + 12 * 3_600,
        "12 hours out, well inside RFC 8292's 24-hour cap"
    );

    // `k=` is the public half of the key that signed `t=`: verified with
    // p256 rather than taken on trust, because a mismatched pair is the
    // VAPID failure that looks like nothing at all until a service rejects
    // every send.
    assert_eq!(key, push.public_key().expect("configured"));
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&b64(&key)).expect("SEC1 point");
    let mut segments = jwt.rsplitn(2, '.');
    let signature_segment = segments.next().expect("signature");
    let signing_input = segments.next().expect("header.claims");
    let signature =
        p256::ecdsa::Signature::from_slice(&b64(signature_segment)).expect("64-byte r||s");
    verifying
        .verify(signing_input.as_bytes(), &signature)
        .expect("the JWT verifies under the key it advertises");
}

/// The `aud` is derived per endpoint, so a second push service gets its own
/// token — and the same one gets the cached one.
#[test]
fn a_token_is_minted_per_push_service_origin_and_reused() {
    let http = ScriptedHttp::new();
    let clock = StepClock::at(1_700_000_000);
    let push = adapter(&http, &clock);
    let notification = Notification::new("a", "b");

    let chrome = Recipient::web_push(
        "https://fcm.googleapis.com/fcm/send/abc:DEF",
        UA_PUBLIC,
        AUTH_SECRET,
    );
    let unified = Recipient::web_push("http://ntfy.local:8080/upabc123", UA_PUBLIC, AUTH_SECRET);

    pollster::block_on(push.send(&subscriber(), &notification)).expect("delivered");
    pollster::block_on(push.send(&chrome, &notification)).expect("delivered");
    pollster::block_on(push.send(&unified, &notification)).expect("delivered");
    pollster::block_on(push.send(&subscriber(), &notification)).expect("delivered");

    let token = |n: usize| http.nth(n, |seen| vapid_parts(seen.header("authorization")).0);
    let mozilla = token(0);
    let google = token(1);
    let ntfy = token(2);
    assert_ne!(mozilla, google, "a different aud is a different token");
    assert_ne!(mozilla, ntfy);
    assert_ne!(google, ntfy);
    assert_eq!(token(3), mozilla, "the same origin reuses its token");

    assert_eq!(
        claims_of(&ntfy)["aud"],
        "http://ntfy.local:8080",
        "a non-default port is part of the origin"
    );

    // Past the cache TTL the token is re-signed, with a later `exp`.
    clock.advance(12 * 3_600);
    pollster::block_on(push.send(&subscriber(), &notification)).expect("delivered");
    let refreshed = token(4);
    assert_ne!(refreshed, mozilla);
    assert_eq!(claims_of(&refreshed)["aud"], claims_of(&mozilla)["aud"]);
    assert!(
        claims_of(&refreshed)["exp"].as_i64() > claims_of(&mozilla)["exp"].as_i64(),
        "the fresh token expires later"
    );
}

/// A refused VAPID token drops the cached token for that origin **and** asks
/// the caller to retry.
///
/// The commonest cause is a clock a few minutes out or a token that aged past
/// its `exp` in flight, and both are fixed by the re-sign this send just
/// arranged. Returning a non-retryable `Rejected` arranged that re-sign and
/// then threw away the message that would have used it — the fix is never
/// applied to the notification that triggered it.
#[test]
fn a_refused_vapid_token_re_signs_and_stays_retryable() {
    for status in [401, 403] {
        let http = ScriptedHttp::new();
        let clock = StepClock::at(1_700_000_000);
        let push = adapter(&http, &clock);
        let notification = Notification::new("a", "b");

        pollster::block_on(push.send(&subscriber(), &notification)).expect("delivered");
        let first = http.nth(0, |seen| vapid_parts(seen.header("authorization")).0);

        http.set(Reply::status(status).with_body("UnauthorizedRegistration"));
        let error = pollster::block_on(push.send(&subscriber(), &notification)).unwrap_err();
        assert!(
            matches!(&error, PushError::Transient { message, .. }
                if message.contains(&status.to_string())
                    && message.contains("UnauthorizedRegistration")),
            "status {status}: a refused token discarded the notification: {error:?}"
        );

        // Same instant, so only a dropped cache entry can change the token —
        // and ES256 here is deterministic, so a re-mint at the same second is
        // the *same* string. Advancing the clock by a second makes the
        // re-mint visible.
        http.set(Reply::created());
        clock.advance(1);
        pollster::block_on(push.send(&subscriber(), &notification)).expect("delivered");
        let third = http.nth(2, |seen| vapid_parts(seen.header("authorization")).0);
        assert_ne!(
            third, first,
            "status {status}: the token was served from cache, not re-signed"
        );
    }
}

// ---------------------------------------------------------------------------
// Status mapping

#[test]
fn every_success_status_is_delivered() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    // RFC 8030 specifies `201 Created` with a `Location`; ntfy answers `200`
    // to a UnifiedPush publish and some services `202`.
    http.set(Reply::status(201).with_header("location", "https://push.example/m/1"));
    assert_eq!(
        pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap(),
        PushOutcome::Delivered {
            id: Some("https://push.example/m/1".to_owned())
        }
    );
    for status in [200, 202, 204] {
        http.set(Reply::status(status));
        assert_eq!(
            pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap(),
            PushOutcome::Delivered { id: None },
            "status {status}"
        );
    }
}

/// `410 Gone` is the only status that prunes a subscription — RFC 8030 §5
/// defines no other, and `Unregistered` is a delete instruction.
#[test]
fn a_gone_subscription_is_unregistered() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    http.set(Reply::status(410).with_body("subscription gone"));
    let error =
        pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(error, PushError::Unregistered), "{error}");
}

/// A `404` must **not** prune.
///
/// A self-hosted UnifiedPush distributor behind a proxy that came back
/// without its routes, or an edited ingress rule, answers `404` for every
/// path. Pruning on it deletes every Web Push subscription a venture holds,
/// and unlike a device token none of them can be recreated server-side —
/// only the browser can call `pushManager.subscribe()` again. So it is
/// retryable, and the routing fix makes the next attempt succeed.
#[test]
fn a_404_is_retried_and_never_prunes_the_subscription() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    http.set(Reply::status(404).with_body("Not Found"));
    let error =
        pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
    assert!(
        !matches!(error, PushError::Unregistered),
        "a 404 pruned the subscription: {error}"
    );
    assert!(
        matches!(&error, PushError::Transient { message, .. } if message.contains("404")),
        "{error:?}"
    );

    // And the proxy comes back: the same subscription still delivers,
    // because nothing told the caller to delete it.
    http.set(Reply::created());
    pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b")))
        .expect("the subscription survived the outage");
}

/// `507` is an operator state, not load.
///
/// ntfy answers it — `"cannot publish to UnifiedPush topic without
/// previously active subscriber"` — when it runs with
/// `visitor-subscriber-rate-limiting` on, as the public `ntfy.sh` does. It
/// never clears on its own, so retrying it as a 5xx retries forever.
#[test]
fn a_507_is_rejected_rather_than_retried_forever() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    http.set(
        Reply::status(507)
            .with_body("cannot publish to UnifiedPush topic without previously active subscriber"),
    );
    let error =
        pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
    match error {
        PushError::Rejected(message) => {
            assert!(message.contains("507"), "{message}");
            assert!(
                message.contains("previously active subscriber"),
                "{message}"
            );
            // Named, because the fix is a setting on the push server and
            // nobody reading a log line knows that without being told.
            assert!(
                message.contains("visitor-subscriber-rate-limiting"),
                "{message}"
            );
        }
        other => panic!("507 should be Rejected, got {other:?}"),
    }
}

/// A distributor that moved answers `3xx`. The redirect is not followed —
/// the VAPID token is signed over the original origin — but a move is at
/// worst temporary and never a reason to destroy the notification.
#[test]
fn a_redirect_is_transient_rather_than_a_permanent_rejection() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    for status in [301, 302, 307, 308] {
        http.set(
            Reply::status(status).with_header("location", "https://push.example/wpush/v2/moved"),
        );
        let error =
            pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
        assert!(
            matches!(&error, PushError::Transient { message, .. } if message.contains(&status.to_string())),
            "status {status}: {error:?}"
        );
        // The `Location` is a push endpoint: it is not quoted back.
        assert!(!error.to_string().contains("moved"), "{error}");
    }
}

#[test]
fn a_client_error_is_rejected_and_names_the_status() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    // `401`/`403` are deliberately absent: a refused VAPID token is
    // retryable, and has a test of its own.
    for status in [400, 413] {
        http.set(Reply::status(status).with_body("nope"));
        let error =
            pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
        match error {
            PushError::Rejected(message) => {
                assert!(message.contains(&status.to_string()), "{message}");
                assert!(message.contains("nope"), "{message}");
            }
            other => panic!("status {status} should be Rejected, got {other:?}"),
        }
    }
}

/// The subscription endpoint is a bearer capability that
/// `crates/core/src/ports/push.rs` says must appear "never in a log, an
/// event payload, or an error body". Error pages echo the request path, so
/// the check is on what comes out of a real send.
#[test]
fn no_error_message_carries_the_subscription_endpoint() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    // What nginx, Apache and a CDN in front of a push service answer with:
    // the request path, verbatim.
    for status in [400, 404, 410, 401, 413, 429, 500, 507, 301] {
        http.set(Reply::status(status).with_body(
            "The requested URL \
             https://updates.push.services.mozilla.com/wpush/v2/gAAAAAsubscription \
             was not found on this server.",
        ));
        let outcome = pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b")));
        let message = match outcome {
            Err(error) => error.to_string(),
            Ok(outcome) => panic!("status {status} should not have delivered: {outcome:?}"),
        };
        assert!(
            !message.contains("gAAAAAsubscription"),
            "status {status} leaked the subscription path: {message}"
        );
        assert!(
            !message.contains("mozilla.com"),
            "status {status} leaked the push service host: {message}"
        );
    }
}

#[test]
fn throttling_and_server_errors_are_transient() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    for status in [429, 500, 502, 503, 504] {
        http.set(Reply::status(status));
        let error =
            pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
        assert!(
            matches!(&error, PushError::Transient { message, .. } if message.contains(&status.to_string())),
            "status {status}: {error:?}"
        );
        assert_eq!(error.retry_after(), None, "no Retry-After was sent");
    }
}

#[test]
fn retry_after_is_read_in_both_the_seconds_and_the_http_date_forms() {
    let http = ScriptedHttp::new();
    // 1994-11-06T08:49:07Z, thirty seconds before the date below.
    let clock = StepClock::at(784_111_747);
    let push = adapter(&http, &clock);

    http.set(Reply::status(503).with_header("retry-after", "120"));
    let error =
        pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
    assert_eq!(error.retry_after(), Some(Duration::from_secs(120)));

    // The HTTP-date form: legal, emitted by some CDNs in front of a push
    // service, and worth an hour of unnecessary retries if it is ignored.
    http.set(Reply::status(429).with_header("retry-after", "Sun, 06 Nov 1994 08:49:37 GMT"));
    let error =
        pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
    assert_eq!(error.retry_after(), Some(Duration::from_secs(30)));

    // A date already past means "retry now", not "no delay stated".
    clock.advance(600);
    http.set(Reply::status(429).with_header("retry-after", "Sun, 06 Nov 1994 08:49:37 GMT"));
    let error =
        pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
    assert_eq!(error.retry_after(), Some(Duration::ZERO));

    // Something that is neither form is ignored rather than guessed at.
    http.set(Reply::status(429).with_header("retry-after", "soon"));
    let error =
        pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(error, PushError::Transient { .. }), "{error}");
    assert_eq!(error.retry_after(), None);
}

#[test]
fn a_transport_failure_is_transient() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));
    http.fail_transport();

    let error =
        pollster::block_on(push.send(&subscriber(), &Notification::new("a", "b"))).unwrap_err();
    assert!(
        matches!(&error, PushError::Transient { message, .. } if message.contains("connection reset")),
        "{error:?}"
    );
}

// ---------------------------------------------------------------------------
// Refused before the network

#[test]
fn an_oversize_payload_is_rejected_locally_with_no_request() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    // One byte past what the record holds, measured through the adapter's
    // own limit rather than a number written here.
    let limit = push.max_payload().expect("configured");
    let body = "b".repeat(limit);
    let error =
        pollster::block_on(push.send(&subscriber(), &Notification::new("t", &body))).unwrap_err();

    match error {
        PushError::Rejected(message) => {
            assert!(message.contains("payload too large"), "{message}");
            assert!(message.contains(&limit.to_string()), "{message}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    assert_eq!(http.count(), 0, "refused before the network");

    // And a notification that fits is sent, so the limit is a boundary and
    // not a blanket refusal — and the body it produces stays inside the
    // 4096 octets a push service is required to accept.
    let body = "b".repeat(limit - 100);
    pollster::block_on(push.send(&subscriber(), &Notification::new("t", &body)))
        .expect("delivered");
    assert_eq!(http.count(), 1);
    http.last(|seen| {
        assert!(
            seen.body.len() <= ece::MIN_SUPPORTED_BODY_LEN,
            "a {}-byte body would risk a 413",
            seen.body.len()
        );
        // Exactly the RFC 8188 arithmetic: header, plaintext, delimiter, tag.
        assert_eq!(
            seen.body.len(),
            ece::WEB_PUSH_HEADER_LEN + (body.len() + 38) + 17,
            "the plaintext is the payload JSON, not the body string alone"
        );
    });
}

#[test]
fn a_malformed_subscription_is_rejected_locally_with_no_request() {
    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(0));

    let cases = [
        // Not base64url.
        Recipient::web_push(ENDPOINT, "!!!", AUTH_SECRET),
        // A well-formed key of the wrong length.
        Recipient::web_push(ENDPOINT, URL_SAFE_NO_PAD.encode([4u8; 33]), AUTH_SECRET),
        // A 12-byte auth secret.
        Recipient::web_push(ENDPOINT, UA_PUBLIC, URL_SAFE_NO_PAD.encode([0u8; 12])),
        // An endpoint that is not an absolute http(s) URL, so there is no
        // origin to sign an `aud` over.
        Recipient::web_push("/wpush/v2/abc", UA_PUBLIC, AUTH_SECRET),
        Recipient::web_push("ftp://push.example/x", UA_PUBLIC, AUTH_SECRET),
    ];
    for recipient in cases {
        let error =
            pollster::block_on(push.send(&recipient, &Notification::new("a", "b"))).unwrap_err();
        assert!(
            matches!(error, PushError::Rejected(_)),
            "{recipient:?}: {error:?}"
        );
    }
    assert_eq!(http.count(), 0, "none of these reached the network");
}

/// A subscription generated outside the RFC, pushed to through the whole
/// adapter, decrypted on the far side — the shape a venture actually has.
#[test]
fn a_venture_subscription_round_trips_through_the_adapter() {
    let ua_private = [
        0x2a, 0x91, 0x5f, 0x03, 0xc7, 0x64, 0x18, 0xbd, 0x39, 0xe2, 0x70, 0x4c, 0xa5, 0x16, 0x8f,
        0xd1, 0x6b, 0x22, 0xee, 0x07, 0x93, 0x50, 0xac, 0x18, 0x74, 0xcd, 0x3b, 0x69, 0xf2, 0x85,
        0x41, 0x0e,
    ];
    let auth = [0x5au8; 16];
    let recipient = Recipient::web_push(
        "https://wns2-par02p.notify.windows.com/w/?token=Bearer",
        URL_SAFE_NO_PAD.encode(public_key_of(&ua_private)),
        URL_SAFE_NO_PAD.encode(auth),
    );

    let http = ScriptedHttp::new();
    let push = adapter(&http, &StepClock::at(1_700_000_000));
    pollster::block_on(push.send(&recipient, &Notification::new("Hi", "there")))
        .expect("delivered");

    let body = http.last(|seen| seen.body.clone());
    let opened = decrypt(&ua_private, &auth, &body).expect("the browser opens it");
    let payload: serde_json::Value = serde_json::from_slice(&opened).expect("JSON");
    assert_eq!(payload["title"], "Hi");
    http.last(|seen| {
        assert_eq!(
            claims_of(&vapid_parts(seen.header("authorization")).0)["aud"],
            "https://wns2-par02p.notify.windows.com"
        );
    });
}
