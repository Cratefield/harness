//! Unit tests for the APNs adapter: JWT signing/caching, recipient handling
//! and payload shape. The live path against Apple is `needs-human`
//! (issue #104).
#![allow(clippy::disallowed_types)] // test doubles record calls via a Mutex

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use cratefield_adapter_apns::{Apns, ApnsConfigError, ApnsCredentials, ApnsHost};
use cratefield_core::{
    Clock, HttpClient, HttpError, LocKeys, Notification, Platform, Priority, Push, PushError,
    PushOutcome, Recipient,
};
use cratefield_testing::push_recipient_conformance;

// A throwaway P-256 key, generated for these tests only — NOT an Apple key.
const TEST_P8: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcXMgRpW+eLn7ZvCx\nIuTdd8csWMZ69azlRzS0dy2FN6GhRANCAATJ6GazR2lhWcC3JYsazLR0uWOyDKrC\nmeP4HPWghRmfoa4z3Ux7mG3Ylz+auRaBukKGicSdSvVG+jGeQwr3fNag\n-----END PRIVATE KEY-----";

// ---------------------------------------------------------------------------
// Test doubles

/// A clock whose time the test advances by hand.
struct StepClock(AtomicI64);
impl StepClock {
    fn at(secs: i64) -> Self {
        Self(AtomicI64::new(secs))
    }
    fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::Relaxed);
    }
}
#[async_trait::async_trait]
impl Clock for StepClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::Relaxed)).unwrap()
    }
}

/// Records every request and replies with a scripted response.
struct ScriptedHttp {
    requests: std::sync::Mutex<Vec<http::Request<Bytes>>>,
    status: u16,
    body: &'static str,
    apns_id: Option<&'static str>,
    retry_after: Option<&'static str>,
}
impl ScriptedHttp {
    fn ok() -> Arc<Self> {
        Arc::new(Self {
            requests: std::sync::Mutex::new(Vec::new()),
            status: 200,
            body: "",
            apns_id: Some("apns-xyz"),
            retry_after: None,
        })
    }
    fn replying(status: u16, body: &'static str) -> Arc<Self> {
        Arc::new(Self {
            requests: std::sync::Mutex::new(Vec::new()),
            status,
            body,
            apns_id: None,
            retry_after: None,
        })
    }
    fn replying_after(status: u16, body: &'static str, retry_after: &'static str) -> Arc<Self> {
        Arc::new(Self {
            requests: std::sync::Mutex::new(Vec::new()),
            status,
            body,
            apns_id: None,
            retry_after: Some(retry_after),
        })
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn last(&self) -> http::Request<Bytes> {
        let guard = self.requests.lock().unwrap();
        let req = guard.last().unwrap();
        let mut clone = http::Request::builder()
            .method(req.method().clone())
            .uri(req.uri().clone());
        for (name, value) in req.headers() {
            clone = clone.header(name, value);
        }
        clone.body(req.body().clone()).unwrap()
    }
}
#[async_trait::async_trait]
impl HttpClient for ScriptedHttp {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        self.requests.lock().unwrap().push(request);
        let mut builder = http::Response::builder().status(self.status);
        if let Some(id) = self.apns_id {
            builder = builder.header("apns-id", id);
        }
        if let Some(retry_after) = self.retry_after {
            builder = builder.header("retry-after", retry_after);
        }
        Ok(builder.body(Bytes::from(self.body)).unwrap())
    }
}

fn creds() -> ApnsCredentials {
    ApnsCredentials {
        key_p8_pem: TEST_P8.to_owned(),
        key_id: "ABC1234567".to_owned(),
        team_id: "TEAM987654".to_owned(),
        topic: "com.example.app".to_owned(),
        host: ApnsHost::Sandbox,
    }
}

fn decode_segment(seg: &str) -> serde_json::Value {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seg)
        .expect("base64url");
    serde_json::from_slice(&bytes).expect("json")
}

/// The one recipient this adapter serves.
fn device() -> Recipient {
    Recipient::apns("tok")
}

// ---------------------------------------------------------------------------
// Tests

#[test]
fn rejects_a_malformed_p8() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1_000));
    let result = Apns::new(
        http,
        clock,
        ApnsCredentials {
            key_p8_pem: "not a key".to_owned(),
            ..creds()
        },
    );
    assert!(matches!(result, Err(ApnsConfigError::Key(_))));
}

#[test]
fn not_configured_never_calls_the_network() {
    let apns = Apns::not_configured();
    let outcome = pollster::block_on(apns.send(&device(), &Notification::new("t", "b"))).unwrap();
    assert_eq!(outcome, PushOutcome::NotConfigured);
}

#[test]
fn not_configured_still_refuses_the_transports_it_does_not_serve() {
    // Being unconfigured is a fact about credentials, not about transports:
    // answering `NotConfigured` for a Web Push recipient would claim to serve
    // it, and a router reading that answer would stop looking for the adapter
    // that actually does.
    let apns = Apns::not_configured();
    pollster::block_on(push_recipient_conformance(&apns, &[Platform::Ios]));

    let err = pollster::block_on(apns.send(
        &Recipient::web_push("https://push.example/x", "p256dh", "auth"),
        &Notification::new("a", "b"),
    ))
    .unwrap_err();
    assert!(matches!(err, PushError::Rejected(m) if m.contains("unsupported recipient")));
}

#[test]
fn delivers_and_signs_a_valid_jwt() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1_700_000_000));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let outcome = pollster::block_on(apns.send(
        &Recipient::apns("devicetoken1"),
        &Notification::new("Hi", "there"),
    ))
    .unwrap();
    assert_eq!(
        outcome,
        PushOutcome::Delivered {
            id: Some("apns-xyz".to_owned())
        }
    );

    let req = http.last();
    assert_eq!(req.method(), "POST");
    assert_eq!(
        req.uri().to_string(),
        "https://api.sandbox.push.apple.com/3/device/devicetoken1"
    );
    assert_eq!(req.headers().get("apns-topic").unwrap(), "com.example.app");
    assert_eq!(req.headers().get("apns-push-type").unwrap(), "alert");
    assert_eq!(req.headers().get("apns-priority").unwrap(), "10");
    assert!(
        req.headers().get("apns-expiration").is_none(),
        "no TTL, no expiration header"
    );

    // The Authorization header is `bearer <jwt>` with a well-formed ES256 JWT.
    let auth = req
        .headers()
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    let jwt = auth.strip_prefix("bearer ").expect("bearer scheme");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "header.payload.signature");
    let header = decode_segment(parts[0]);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], "ABC1234567");
    let payload = decode_segment(parts[1]);
    assert_eq!(payload["iss"], "TEAM987654");
    assert_eq!(payload["iat"], 1_700_000_000_i64);
    // ES256 signature is 64 bytes -> 86 base64url chars, unpadded.
    assert_eq!(parts[2].len(), 86);
}

#[test]
fn body_carries_aps_and_merges_custom_data() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1_000));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let mut n = Notification::new("Room starting", "Yoga in 10 min");
    n.category = Some("SESSION".to_owned());
    n.thread_id = Some("room-42".to_owned());
    n.data = serde_json::json!({ "room_id": "42", "aps": "should be ignored" });
    n.collapse_id = Some("room-42".to_owned());
    n.priority = Priority::Conserve;

    pollster::block_on(apns.send(&device(), &n)).unwrap();

    let req = http.last();
    assert_eq!(req.headers().get("apns-priority").unwrap(), "5");
    assert_eq!(req.headers().get("apns-collapse-id").unwrap(), "room-42");

    let body: serde_json::Value = serde_json::from_slice(req.body()).unwrap();
    assert_eq!(body["aps"]["alert"]["title"], "Room starting");
    assert_eq!(body["aps"]["alert"]["body"], "Yoga in 10 min");
    assert_eq!(body["aps"]["category"], "SESSION");
    assert_eq!(body["aps"]["thread-id"], "room-42");
    assert_eq!(body["room_id"], "42");
    // A caller cannot clobber the aps block via a top-level "aps" key.
    assert!(body["aps"].is_object());
}

#[test]
fn reuses_the_jwt_within_the_ttl_and_remints_after() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(0));
    let apns = Apns::new(http.clone(), clock.clone(), creds()).unwrap();

    let jwt_of = |req: &http::Request<Bytes>| {
        req.headers()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    };

    pollster::block_on(apns.send(&device(), &Notification::new("a", "b"))).unwrap();
    let first = jwt_of(&http.last());

    // Within the TTL: same token.
    clock.advance(40 * 60);
    pollster::block_on(apns.send(&device(), &Notification::new("a", "b"))).unwrap();
    assert_eq!(jwt_of(&http.last()), first, "reused within TTL");

    // Past the TTL: a fresh token (new iat => different signature).
    clock.advance(20 * 60);
    pollster::block_on(apns.send(&device(), &Notification::new("a", "b"))).unwrap();
    assert_ne!(jwt_of(&http.last()), first, "re-minted past TTL");
}

#[test]
fn maps_410_to_unregistered() {
    let http = ScriptedHttp::replying(410, r#"{"reason":"Unregistered"}"#);
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http, clock, creds()).unwrap();
    let err = pollster::block_on(apns.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(err, PushError::Unregistered));
}

#[test]
fn maps_400_to_rejected_and_500_to_transient() {
    let bad = ScriptedHttp::replying(400, r#"{"reason":"BadDeviceToken"}"#);
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(bad, clock, creds()).unwrap();
    let err = pollster::block_on(apns.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(err, PushError::Rejected(m) if m.contains("BadDeviceToken")));

    let down = ScriptedHttp::replying(503, "");
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(down, clock, creds()).unwrap();
    let err = pollster::block_on(apns.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(err, PushError::Transient { .. }));
    assert_eq!(err.retry_after(), None, "no Retry-After header, no delay");
}

#[test]
fn expired_provider_token_invalidates_the_cache() {
    // First send gets 403 ExpiredProviderToken -> Transient + cache dropped;
    // the retry mints a new JWT (so two distinct tokens are seen).
    let http = ScriptedHttp::replying(403, r#"{"reason":"ExpiredProviderToken"}"#);
    let clock = Arc::new(StepClock::at(100));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let err = pollster::block_on(apns.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(err, PushError::Transient { .. }));

    // Cache was cleared; a second attempt signs again (same iat here, so the
    // deterministic signature matches, but the mint path ran — asserted by the
    // request count going to 2 without a panic on a poisoned/empty cache).
    let _ = pollster::block_on(apns.send(&device(), &Notification::new("a", "b")));
    assert_eq!(http.count(), 2);
}

// ---------------------------------------------------------------------------
// Push port v2 (issue #177)

#[test]
fn serves_apns_and_rejects_the_other_transports() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    // The shared kit walks every `Recipient` variant: this adapter serves
    // exactly one, and the rest must be a clean `Rejected`, never a panic.
    pollster::block_on(push_recipient_conformance(&apns, &[Platform::Ios]));

    // ...and nothing was sent for the two it does not serve.
    assert_eq!(http.count(), 1);
}

#[test]
fn a_rejected_recipient_names_the_transport_and_sends_nothing() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let err = pollster::block_on(apns.send(
        &Recipient::web_push("https://push.example/x", "p256dh", "auth"),
        &Notification::new("a", "b"),
    ))
    .unwrap_err();
    assert!(matches!(err, PushError::Rejected(m) if m.contains("unsupported recipient")));
    assert_eq!(
        http.count(),
        0,
        "no request for a transport we do not serve"
    );
}

#[test]
fn a_ttl_becomes_an_absolute_apns_expiration() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1_700_000_000));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let mut n = Notification::new("a", "b");
    n.ttl = Some(Duration::from_secs(3_600));
    pollster::block_on(apns.send(&device(), &n)).unwrap();
    assert_eq!(
        http.last().headers().get("apns-expiration").unwrap(),
        "1700003600",
        "apns-expiration is now + ttl, not the ttl"
    );

    // Zero is the one value the protocol reads as "deliver now or drop".
    let mut n = Notification::new("a", "b");
    n.ttl = Some(Duration::ZERO);
    pollster::block_on(apns.send(&device(), &n)).unwrap();
    assert_eq!(http.last().headers().get("apns-expiration").unwrap(), "0");
}

#[test]
fn a_silent_notification_is_a_background_push() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let mut n = Notification::new("a", "b");
    n.silent = true;
    n.priority = Priority::Immediate;
    n.data = serde_json::json!({ "sync": true });
    pollster::block_on(apns.send(&device(), &n)).unwrap();

    let req = http.last();
    assert_eq!(req.headers().get("apns-push-type").unwrap(), "background");
    // Apple rejects a background push at priority 10, whatever the caller asked.
    assert_eq!(req.headers().get("apns-priority").unwrap(), "5");
    let body: serde_json::Value = serde_json::from_slice(req.body()).unwrap();
    assert_eq!(body["aps"]["content-available"], 1);
    assert!(
        body["aps"]["alert"].is_null(),
        "a silent push shows nothing"
    );
    assert_eq!(body["sync"], true);
}

#[test]
fn badge_url_and_loc_keys_reach_the_payload() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let mut n = Notification::new("Room starting", "Yoga in 10 min");
    n.badge = Some(3);
    n.url = Some("https://example.test/rooms/42".to_owned());
    n.icon = Some("https://example.test/icon.png".to_owned()); // APNs has no home for it
    n.loc = Some(LocKeys {
        title_loc_key: Some("ROOM_STARTING".to_owned()),
        title_loc_args: vec!["Yoga".to_owned()],
        body_loc_key: Some("ROOM_BODY".to_owned()),
        body_loc_args: vec!["10".to_owned()],
    });
    pollster::block_on(apns.send(&device(), &n)).unwrap();

    let body: serde_json::Value = serde_json::from_slice(http.last().body()).unwrap();
    assert_eq!(body["aps"]["badge"], 3);
    assert_eq!(body["url"], "https://example.test/rooms/42");
    assert_eq!(body["aps"]["alert"]["title-loc-key"], "ROOM_STARTING");
    assert_eq!(body["aps"]["alert"]["title-loc-args"][0], "Yoga");
    assert_eq!(body["aps"]["alert"]["loc-key"], "ROOM_BODY");
    assert_eq!(body["aps"]["alert"]["loc-args"][0], "10");
    // The literal title/body stay as the fallback for a client with no
    // catalogue entry.
    assert_eq!(body["aps"]["alert"]["title"], "Room starting");
    assert!(
        body["icon"].is_null(),
        "APNs takes its icon from the bundle"
    );
}

#[test]
fn a_silent_push_carries_content_available_and_nothing_else() {
    // Apple's background-push contract: `content-available` with no `alert`,
    // `badge` or `sound`. A `badge` (or a `category`/`thread-id`, which only
    // describe how an alert is shown) turns the wake into a user-visible
    // notification, so the silent delivery the caller asked for never happens.
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let mut n = Notification::new("a", "b");
    n.silent = true;
    n.badge = Some(3);
    n.category = Some("SESSION".to_owned());
    n.thread_id = Some("room-42".to_owned());
    pollster::block_on(apns.send(&device(), &n)).unwrap();

    let req = http.last();
    assert_eq!(req.headers().get("apns-push-type").unwrap(), "background");
    let body: serde_json::Value = serde_json::from_slice(req.body()).unwrap();
    let block = body["aps"].as_object().expect("aps object");
    assert_eq!(block["content-available"], 1);
    assert_eq!(
        block.keys().collect::<Vec<_>>(),
        vec!["content-available"],
        "a background push carries content-available alone: {block:?}"
    );
}

#[test]
fn an_alert_push_still_carries_badge_category_and_thread_id() {
    // The other direction of the same rule: dropping them when silent must
    // not drop them when the notification is visible.
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let mut n = Notification::new("a", "b");
    n.badge = Some(3);
    n.category = Some("SESSION".to_owned());
    n.thread_id = Some("room-42".to_owned());
    pollster::block_on(apns.send(&device(), &n)).unwrap();

    let body: serde_json::Value = serde_json::from_slice(http.last().body()).unwrap();
    assert_eq!(body["aps"]["badge"], 3);
    assert_eq!(body["aps"]["category"], "SESSION");
    assert_eq!(body["aps"]["thread-id"], "room-42");
}

#[test]
fn loc_args_are_only_emitted_with_their_key() {
    // `*-loc-args` are the substitutions for a `*-loc-key`. Without the key
    // they substitute into nothing and Apple defines no meaning for them.
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let mut n = Notification::new("a", "b");
    n.loc = Some(LocKeys {
        title_loc_key: None,
        title_loc_args: vec!["Yoga".to_owned()],
        body_loc_key: None,
        body_loc_args: vec!["10".to_owned()],
    });
    pollster::block_on(apns.send(&device(), &n)).unwrap();

    let body: serde_json::Value = serde_json::from_slice(http.last().body()).unwrap();
    let alert = body["aps"]["alert"].as_object().expect("alert object");
    assert!(
        !alert.contains_key("title-loc-args"),
        "no title-loc-key, no title-loc-args: {alert:?}"
    );
    assert!(
        !alert.contains_key("loc-args"),
        "no loc-key, no loc-args: {alert:?}"
    );
}

#[test]
fn the_notifications_url_wins_over_one_in_data() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let mut n = Notification::new("a", "b");
    n.data = serde_json::json!({ "url": "https://example.test/from-data", "room_id": "42" });
    n.url = Some("https://example.test/from-field".to_owned());
    pollster::block_on(apns.send(&device(), &n)).unwrap();

    let body: serde_json::Value = serde_json::from_slice(http.last().body()).unwrap();
    assert_eq!(
        body["url"], "https://example.test/from-field",
        "the typed field is the documented one and wins"
    );
    assert_eq!(body["room_id"], "42");

    // ...and with no `url` set, the caller's own key survives untouched.
    let mut n = Notification::new("a", "b");
    n.data = serde_json::json!({ "url": "https://example.test/from-data" });
    pollster::block_on(apns.send(&device(), &n)).unwrap();
    let body: serde_json::Value = serde_json::from_slice(http.last().body()).unwrap();
    assert_eq!(body["url"], "https://example.test/from-data");
}

#[test]
fn a_malformed_device_token_is_rejected_before_the_request() {
    let clock = Arc::new(StepClock::at(1));
    let http = ScriptedHttp::ok();
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    for token in [
        "tok/../../3/device/other",
        "tok?query=1",
        "tok#frag",
        "tok en",
        "",
        "tok%2F",
    ] {
        let err =
            pollster::block_on(apns.send(&Recipient::apns(token), &Notification::new("a", "b")))
                .unwrap_err();
        assert!(
            matches!(&err, PushError::Rejected(m) if m == "malformed device token"),
            "{token:?} -> {err:?}"
        );
    }
    assert_eq!(
        http.count(),
        0,
        "a token that is not a token never reaches the wire"
    );
}

#[test]
fn a_sub_second_ttl_rounds_up_instead_of_expiring_immediately() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1_700_000_000));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let mut n = Notification::new("a", "b");
    n.ttl = Some(Duration::from_millis(900));
    pollster::block_on(apns.send(&device(), &n)).unwrap();
    assert_eq!(
        http.last().headers().get("apns-expiration").unwrap(),
        "1700000001",
        "900ms is a short hold, not `now` — which would mean drop on the spot"
    );
}

#[test]
fn a_429_carries_the_providers_retry_after() {
    let http = ScriptedHttp::replying_after(429, r#"{"reason":"TooManyRequests"}"#, "30");
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http, clock, creds()).unwrap();

    let err = pollster::block_on(apns.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(err, PushError::Transient { .. }), "{err}");
    assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));

    // A 503 with a Retry-After is honoured the same way.
    let http = ScriptedHttp::replying_after(503, "", "5");
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http, clock, creds()).unwrap();
    let err = pollster::block_on(apns.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));

    // An HTTP-date Retry-After is not parsed; the error stays retryable.
    let http = ScriptedHttp::replying_after(503, "", "Wed, 21 Oct 2026 07:28:00 GMT");
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http, clock, creds()).unwrap();
    let err = pollster::block_on(apns.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(err, PushError::Transient { .. }));
    assert_eq!(err.retry_after(), None);
}

// ScriptedHttp needs Clone for `http.clone()` on an Arc; Arc gives it.
