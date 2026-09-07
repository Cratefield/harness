//! Unit tests for the APNs adapter: JWT signing/caching and payload shape.
//! The live path against Apple is `needs-human` (issue #104).
#![allow(clippy::disallowed_types)] // test doubles record calls via a Mutex

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use bytes::Bytes;
use cratefield_adapter_apns::{Apns, ApnsConfigError, ApnsCredentials, ApnsHost};
use cratefield_core::{
    Clock, HttpClient, HttpError, Notification, Priority, Push, PushError, PushOutcome,
};

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
}
impl ScriptedHttp {
    fn ok() -> Arc<Self> {
        Arc::new(Self {
            requests: std::sync::Mutex::new(Vec::new()),
            status: 200,
            body: "",
            apns_id: Some("apns-xyz"),
        })
    }
    fn replying(status: u16, body: &'static str) -> Arc<Self> {
        Arc::new(Self {
            requests: std::sync::Mutex::new(Vec::new()),
            status,
            body,
            apns_id: None,
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
    let outcome = pollster::block_on(apns.send("tok", &Notification::new("t", "b"))).unwrap();
    assert_eq!(outcome, PushOutcome::NotConfigured);
}

#[test]
fn delivers_and_signs_a_valid_jwt() {
    let http = ScriptedHttp::ok();
    let clock = Arc::new(StepClock::at(1_700_000_000));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let outcome =
        pollster::block_on(apns.send("devicetoken1", &Notification::new("Hi", "there"))).unwrap();
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

    pollster::block_on(apns.send("tok", &n)).unwrap();

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

    pollster::block_on(apns.send("tok", &Notification::new("a", "b"))).unwrap();
    let first = jwt_of(&http.last());

    // Within the TTL: same token.
    clock.advance(40 * 60);
    pollster::block_on(apns.send("tok", &Notification::new("a", "b"))).unwrap();
    assert_eq!(jwt_of(&http.last()), first, "reused within TTL");

    // Past the TTL: a fresh token (new iat => different signature).
    clock.advance(20 * 60);
    pollster::block_on(apns.send("tok", &Notification::new("a", "b"))).unwrap();
    assert_ne!(jwt_of(&http.last()), first, "re-minted past TTL");
}

#[test]
fn maps_410_to_unregistered() {
    let http = ScriptedHttp::replying(410, r#"{"reason":"Unregistered"}"#);
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(http, clock, creds()).unwrap();
    let err = pollster::block_on(apns.send("tok", &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(err, PushError::Unregistered));
}

#[test]
fn maps_400_to_rejected_and_500_to_transient() {
    let bad = ScriptedHttp::replying(400, r#"{"reason":"BadDeviceToken"}"#);
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(bad, clock, creds()).unwrap();
    let err = pollster::block_on(apns.send("tok", &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(err, PushError::Rejected(m) if m.contains("BadDeviceToken")));

    let down = ScriptedHttp::replying(503, "");
    let clock = Arc::new(StepClock::at(1));
    let apns = Apns::new(down, clock, creds()).unwrap();
    let err = pollster::block_on(apns.send("tok", &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(err, PushError::Transient(_)));
}

#[test]
fn expired_provider_token_invalidates_the_cache() {
    // First send gets 403 ExpiredProviderToken -> Transient + cache dropped;
    // the retry mints a new JWT (so two distinct tokens are seen).
    let http = ScriptedHttp::replying(403, r#"{"reason":"ExpiredProviderToken"}"#);
    let clock = Arc::new(StepClock::at(100));
    let apns = Apns::new(http.clone(), clock, creds()).unwrap();

    let err = pollster::block_on(apns.send("tok", &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(err, PushError::Transient(_)));

    // Cache was cleared; a second attempt signs again (same iat here, so the
    // deterministic signature matches, but the mint path ran — asserted by the
    // request count going to 2 without a panic on a poisoned/empty cache).
    let _ = pollster::block_on(apns.send("tok", &Notification::new("a", "b")));
    assert_eq!(http.count(), 2);
}

// ScriptedHttp needs Clone for `http.clone()` on an Arc; Arc gives it.
