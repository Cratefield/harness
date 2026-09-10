//! Unit tests for the FCM adapter: the service-account token exchange and
//! its cache, the HTTP v1 payload (golden), and the `FcmError` mapping. The
//! live path against a real Firebase project and Android device is
//! `needs-human` (issue #186) and does not block this crate.
#![allow(clippy::disallowed_types)] // test doubles record calls via a Mutex

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use cratefield_adapter_fcm::{Fcm, FcmConfigError, FcmCredentials};
use cratefield_core::{
    Clock, HttpClient, HttpError, LocKeys, Notification, Platform, Priority, Push, PushError,
    PushOutcome, Recipient,
};
use cratefield_testing::push_recipient_conformance;
use serde_json::{Value, json};

/// A throwaway 2048-bit RSA key, generated for tests only — NOT a Google
/// service-account key. The same PEM `cratefield-push-auth` signs with in its
/// own tests.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCgQ/qAORkSKZjW
xMCbrhGXqbVCHpslcKpb3Ew/5qpRclIDXmJcaXehqY4swKuYdyqcQloRH5inZ/6U
DR/p72s+6Gu5ExAje64hw2AChozIdmKA/xZYxPjQ5AtFXLofTglg1VeudH+6/bDw
sXKGsaqRPWghb0lc1cai0ETHZDfP9frfJKjJRm2HlZqp8CKwwl1Jy6CQOGrjKlQX
ThV07JKPpRPTZFscZTMzjG9fIfYCcxWt7c7HcPN4G7QUrx4oEX/jkuJcA2zgQ0WL
0gJ4IKUc1BiNDP67UniFq8bxlcqePQc8MN3bBDrPKktX24u9ZJJZjx6otgBIWCaB
nIKyuyfzAgMBAAECggEAS0Af+tzUfMazUQSJO4/8Cq5QwX8Fcgr4srE5zDdOeXeo
MpS6spGC7pFihHjjGW+6viwZhjjDwLb/vhx7g6g7Pwp6qifdSAvms0u9ZPIwYF/V
2KPtpji2a77n2+WyLsjBdoo15WAmKXK9BgcLs1rwr8mZfzl1xPVLk18fLFBONIKY
ySiiGRQC2NZXfAEZF/pDMaBT5+my7hjZkw07XMrV//DnR71Gre2IPj0SNPWjS+Fd
qMQq5UvxaJxLP6dDswYqXNvoWC7YAlsnf9ySD3ykLThATh4yUCL6y97wvKEdU9yb
1mruLpOGNCnjCDqx+spY49qt+3uWBcj2BXjAPUlQoQKBgQDPOLZSz772jquTiyk0
4OiUkCofmhLdpKU/vJW6TWGjGWv3MSUvi1wA5q/AByljCtr+/lwzkj1c9/6Hzo0N
zv0kagaVRmb5INhTEu+1957lBP/WucHOvKPhiUvLjiH0YTqFSl+uB5ZbzbIxMOko
T86cq9/qFkOl3BhR8CFoRWwbbwKBgQDF/avnjCFOEVzluU+FnNepR36mZWlhQPNt
xT/wlavbPVQbIYbUJ4vKaU2OjIRE0fPJiC/XXEdD74LeX3gfoufau/M3hSmUDLoq
DZCng5zGKtOlPMLQkf0Q2xVesM5eCJ2dPWZDR8jgkoXaLRa1YIFUofl24AkeabqO
u56pgEwJvQKBgAaN+65o5dh0sNas6zPB/XldigeP3xLlt1hpxa6r7e+zySd7hXqY
hON+aIbBczyvxjeUoiP7dzdunL18+hc6ueUh+W1VWcJ9mHogOjbeS0dhPhpzq763
VtO2fRBGQaqyPKCktpwRn17uBbnqmyVsSNPJ1/5Wj/M6IAbPeq8Kqx2/AoGAPy6u
lxu+3RzpWl4CpI7iu6CXKB6gvGpvxI3305zP1Q0DNA1E65sbHyLvnxf0dcnSVHPj
YISQMXvTdYdd3Cqudr0X5pXWKOrO1fCyQuLbOtob5FU5jjmoWqKvdSJTGOsC8VTQ
t5PG5POdR3ywDH2ZiBqQc4EXJ99xq27wOQM6QLkCgYB9f9GrE+DQIYBzb7hf1SMz
ELvz+3ijy43njvIg4CihiUAzIuc0VJaVCKZcxIMZxLoDB6roeLoYBS+GhVrMoHUj
mbv4voW/HXdaIlZUbMa0y9q0cg3Q8oaw5bwSzrSZxEkadudn4+MFKbLRvmYFX7We
6OmL9MfIa/kocbiIIu0TSA==
-----END PRIVATE KEY-----";

const SEND_URL: &str = "https://fcm.googleapis.com/v1/projects/demo-project/messages:send";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const MESSAGE_NAME: &str = "projects/demo-project/messages/0:1500000000000000%31bd1c9631bd1c96";

// ---------------------------------------------------------------------------
// Test doubles

/// A clock whose time the test advances by hand.
struct StepClock(AtomicI64);
impl StepClock {
    fn at(secs: i64) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(secs)))
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

/// One scripted reply.
struct Reply {
    status: u16,
    body: String,
    retry_after: Option<String>,
}

impl Reply {
    fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            retry_after: None,
        }
    }
    fn after(mut self, retry_after: &str) -> Self {
        self.retry_after = Some(retry_after.to_owned());
        self
    }
}

/// A bearer token, valid for the hour Google actually states.
fn token_reply(access_token: &str) -> Reply {
    Reply::new(
        200,
        json!({ "access_token": access_token, "expires_in": 3_599, "token_type": "Bearer" })
            .to_string(),
    )
}

/// `messages:send` accepted.
fn send_reply() -> Reply {
    Reply::new(200, json!({ "name": MESSAGE_NAME }).to_string())
}

/// An FCM v1 error body with the `FcmError` detail Google attaches.
fn fcm_error(status: u16, error_code: &str) -> Reply {
    Reply::new(
        status,
        json!({
            "error": {
                "code": status,
                "message": "the message",
                "status": "ERROR_STATUS",
                "details": [{
                    "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                    "errorCode": error_code,
                }],
            }
        })
        .to_string(),
    )
}

/// What the fake recorded about one request.
struct Recorded {
    method: String,
    uri: String,
    headers: http::HeaderMap,
    body: Bytes,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("a JSON body")
    }
    fn form(&self) -> Vec<(String, String)> {
        serde_urlencoded_pairs(std::str::from_utf8(&self.body).expect("utf-8"))
    }
}

/// A minimal `application/x-www-form-urlencoded` reader, so the test decodes
/// the body rather than string-matching the adapter's own encoding.
fn serde_urlencoded_pairs(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).expect("hex escape"));
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).expect("utf-8")
}

/// Replies from a script, in order, and records every request. Running off
/// the end of the script **panics**: an unexpected extra call is a bug the
/// test must see, not a silent success.
struct ScriptedHttp {
    requests: std::sync::Mutex<Vec<Recorded>>,
    replies: std::sync::Mutex<VecDeque<Reply>>,
}

impl ScriptedHttp {
    fn new(replies: impl IntoIterator<Item = Reply>) -> Arc<Self> {
        Arc::new(Self {
            requests: std::sync::Mutex::new(Vec::new()),
            replies: std::sync::Mutex::new(replies.into_iter().collect()),
        })
    }
    /// The happy path: exchange a token, then accept the message.
    fn happy() -> Arc<Self> {
        Self::new([token_reply("ya29.first"), send_reply()])
    }
    /// A token exchange followed by one scripted send failure.
    fn failing(reply: Reply) -> Arc<Self> {
        Self::new([token_reply("ya29.first"), reply])
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn remaining(&self) -> usize {
        self.replies.lock().unwrap().len()
    }
    /// The nth recorded request.
    fn nth<T>(&self, index: usize, read: impl FnOnce(&Recorded) -> T) -> T {
        let guard = self.requests.lock().unwrap();
        read(guard.get(index).expect("a request at that index"))
    }
    fn last<T>(&self, read: impl FnOnce(&Recorded) -> T) -> T {
        let guard = self.requests.lock().unwrap();
        read(guard.last().expect("at least one request"))
    }
}

#[async_trait::async_trait]
impl HttpClient for ScriptedHttp {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        self.requests.lock().unwrap().push(Recorded {
            method: request.method().to_string(),
            uri: request.uri().to_string(),
            headers: request.headers().clone(),
            body: request.body().clone(),
        });
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("the adapter made more HTTP calls than the test scripted");
        let mut builder = http::Response::builder().status(reply.status);
        if let Some(retry_after) = &reply.retry_after {
            builder = builder.header("retry-after", retry_after);
        }
        Ok(builder.body(Bytes::from(reply.body)).unwrap())
    }
}

// ---------------------------------------------------------------------------
// Fixtures

fn creds() -> FcmCredentials {
    FcmCredentials {
        client_email: "pusher@demo-project.iam.gserviceaccount.com".to_owned(),
        private_key_pem: TEST_KEY.to_owned(),
        project_id: "demo-project".to_owned(),
        token_uri: TOKEN_URL.to_owned(),
    }
}

fn service_account_json() -> String {
    json!({
        "type": "service_account",
        "project_id": "demo-project",
        "private_key_id": "abc123",
        "private_key": TEST_KEY,
        "client_email": "pusher@demo-project.iam.gserviceaccount.com",
        "client_id": "123456789",
        "token_uri": TOKEN_URL,
    })
    .to_string()
}

fn adapter(http: Arc<ScriptedHttp>, clock: Arc<StepClock>) -> Fcm {
    Fcm::new(http, clock, creds()).expect("valid credentials")
}

/// The one recipient this adapter serves.
fn device() -> Recipient {
    Recipient::fcm("reg-token")
}

fn decode_segment(segment: &str) -> Value {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("base64url");
    serde_json::from_slice(&bytes).expect("json")
}

// ---------------------------------------------------------------------------
// Configuration

#[test]
fn parses_a_service_account_json_file() {
    let creds = FcmCredentials::from_service_account_json(&service_account_json()).unwrap();
    assert_eq!(
        creds.client_email,
        "pusher@demo-project.iam.gserviceaccount.com"
    );
    assert_eq!(creds.project_id, "demo-project");
    assert_eq!(creds.token_uri, TOKEN_URL);
    assert!(creds.private_key_pem.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn a_service_account_without_a_token_uri_falls_back_to_googles() {
    let json = json!({
        "project_id": "demo-project",
        "private_key": TEST_KEY,
        "client_email": "pusher@demo-project.iam.gserviceaccount.com",
    })
    .to_string();
    let creds = FcmCredentials::from_service_account_json(&json).unwrap();
    assert_eq!(creds.token_uri, "https://oauth2.googleapis.com/token");
}

#[test]
fn rejects_a_service_account_that_is_missing_a_field() {
    for missing in ["client_email", "private_key", "project_id"] {
        let mut value: Value = serde_json::from_str(&service_account_json()).unwrap();
        value.as_object_mut().unwrap().remove(missing);
        let error =
            FcmCredentials::from_service_account_json(&value.to_string()).expect_err(missing);
        assert!(
            matches!(&error, FcmConfigError::ServiceAccount(m) if m.contains(missing)),
            "{missing}: {error}"
        );
    }
    let error = FcmCredentials::from_service_account_json("not json").unwrap_err();
    assert!(
        matches!(error, FcmConfigError::ServiceAccount(_)),
        "{error}"
    );
}

#[test]
fn rejects_a_private_key_that_is_not_a_key() {
    let error = Fcm::new(
        ScriptedHttp::happy(),
        StepClock::at(1),
        FcmCredentials {
            private_key_pem: "not a key".to_owned(),
            ..creds()
        },
    )
    .unwrap_err();
    assert!(matches!(error, FcmConfigError::Key(_)), "{error}");
}

#[test]
fn rejects_a_project_id_that_could_retarget_the_request() {
    // The project id is spliced into the send path; anything that is not an
    // id would silently point the send at another endpoint.
    for project_id in [
        "demo/../../v1/projects/other",
        "demo?x=1",
        "demo#frag",
        "demo project",
        "demo%2Fother",
        "",
    ] {
        let http = ScriptedHttp::new([]);
        let error = Fcm::new(
            http.clone(),
            StepClock::at(1),
            FcmCredentials {
                project_id: project_id.to_owned(),
                ..creds()
            },
        )
        .expect_err(project_id);
        assert!(
            matches!(error, FcmConfigError::ProjectId(_)),
            "{project_id:?}: {error}"
        );
        assert_eq!(http.count(), 0);
    }
}

#[test]
fn rejects_a_token_endpoint_that_is_not_https() {
    // The assertion is a bearer credential; it never travels in the clear.
    let error = Fcm::new(
        ScriptedHttp::new([]),
        StepClock::at(1),
        FcmCredentials {
            token_uri: "http://oauth2.googleapis.com/token".to_owned(),
            ..creds()
        },
    )
    .unwrap_err();
    assert!(matches!(error, FcmConfigError::TokenUri(_)), "{error}");
}

#[test]
fn builds_straight_from_a_service_account_json() {
    let http = ScriptedHttp::happy();
    let fcm =
        Fcm::from_service_account_json(http.clone(), StepClock::at(1), &service_account_json())
            .unwrap();
    pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap();
    assert_eq!(http.nth(1, |request| request.uri.clone()), SEND_URL);
}

// ---------------------------------------------------------------------------
// Not configured

#[test]
fn not_configured_never_calls_the_network() {
    let http = ScriptedHttp::new([]); // any call at all panics
    let fcm = Fcm::not_configured();
    let outcome = pollster::block_on(fcm.send(&device(), &Notification::new("t", "b"))).unwrap();
    assert_eq!(outcome, PushOutcome::NotConfigured);
    assert_eq!(http.count(), 0, "not configured means not one request");
}

#[test]
fn not_configured_still_refuses_the_transports_it_does_not_serve() {
    // Being unconfigured is a fact about credentials, not about transports:
    // answering `NotConfigured` for a Web Push recipient would claim to serve
    // it, and a router reading that answer would stop looking for the adapter
    // that actually does.
    let fcm = Fcm::not_configured();
    pollster::block_on(push_recipient_conformance(&fcm, &[Platform::Android]));

    let error = pollster::block_on(fcm.send(
        &Recipient::web_push("https://push.example/x", "p256dh", "auth"),
        &Notification::new("a", "b"),
    ))
    .unwrap_err();
    assert!(matches!(error, PushError::Rejected(m) if m.contains("unsupported recipient")));
}

// ---------------------------------------------------------------------------
// Recipients

#[test]
fn serves_fcm_and_rejects_the_other_transports() {
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));

    // The shared kit walks every `Recipient` variant: this adapter serves
    // exactly one, and the rest must be a clean `Rejected`, never a panic.
    pollster::block_on(push_recipient_conformance(&fcm, &[Platform::Android]));

    // ...and nothing was sent for the two it does not serve: one token
    // exchange plus one message is the whole traffic.
    assert_eq!(http.count(), 2);
}

#[test]
fn a_rejected_recipient_names_the_transport_and_sends_nothing() {
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    let error = pollster::block_on(fcm.send(
        &Recipient::apns("device-token"),
        &Notification::new("a", "b"),
    ))
    .unwrap_err();
    assert!(matches!(error, PushError::Rejected(m) if m.contains("unsupported recipient")));
    assert_eq!(http.count(), 0, "not even a token was exchanged");
}

#[test]
fn an_empty_registration_token_never_reaches_the_wire() {
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    for token in ["", "   "] {
        let error =
            pollster::block_on(fcm.send(&Recipient::fcm(token), &Notification::new("a", "b")))
                .unwrap_err();
        assert!(
            matches!(&error, PushError::Rejected(m) if m == "malformed registration token"),
            "{token:?}: {error}"
        );
    }
    assert_eq!(http.count(), 0);
}

// ---------------------------------------------------------------------------
// The OAuth 2.0 token exchange

#[test]
fn exchanges_a_signed_assertion_for_a_bearer_token() {
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1_700_000_000));
    pollster::block_on(fcm.send(&device(), &Notification::new("Hi", "there"))).unwrap();

    // 1. the token request
    let (method, uri, content_type, form) = http.nth(0, |request| {
        (
            request.method.clone(),
            request.uri.clone(),
            request.header("content-type").map(str::to_owned),
            request.form(),
        )
    });
    assert_eq!(method, "POST");
    assert_eq!(uri, TOKEN_URL);
    assert_eq!(
        content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    let field = |name: &str| {
        form.iter().find(|(key, _)| key == name).map_or_else(
            || panic!("no {name} field in {form:?}"),
            |(_, value)| value.clone(),
        )
    };
    assert_eq!(
        field("grant_type"),
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "the colons must survive form encoding"
    );

    // 2. the assertion itself
    let assertion = field("assertion");
    let parts: Vec<&str> = assertion.split('.').collect();
    assert_eq!(parts.len(), 3, "header.claims.signature");
    let header = decode_segment(parts[0]);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
    let claims = decode_segment(parts[1]);
    assert_eq!(claims["iss"], "pusher@demo-project.iam.gserviceaccount.com");
    assert_eq!(
        claims["scope"], "https://www.googleapis.com/auth/firebase.messaging",
        "the assertion must ask for the messaging scope and no other"
    );
    assert_eq!(claims["aud"], TOKEN_URL);
    assert_eq!(claims["iat"], 1_700_000_000_i64);
    assert_eq!(claims["exp"], 1_700_003_600_i64, "one hour, per Google");

    // 3. the message carries the exchanged token, not the assertion
    let (uri, authorization, content_type) = http.nth(1, |request| {
        (
            request.uri.clone(),
            request.header("authorization").map(str::to_owned),
            request.header("content-type").map(str::to_owned),
        )
    });
    assert_eq!(uri, SEND_URL);
    assert_eq!(authorization.as_deref(), Some("Bearer ya29.first"));
    assert_eq!(content_type.as_deref(), Some("application/json"));
}

#[test]
fn reuses_the_bearer_token_and_re_exchanges_once_it_expires() {
    let clock = StepClock::at(0);
    let http = ScriptedHttp::new([
        token_reply("ya29.first"),
        send_reply(),
        send_reply(), // the second send reuses the cached token
        token_reply("ya29.second"),
        send_reply(),
    ]);
    let fcm = adapter(http.clone(), clock.clone());
    let authorization = || http.last(|request| request.header("authorization").unwrap().to_owned());

    pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap();
    assert_eq!(authorization(), "Bearer ya29.first");
    assert_eq!(http.count(), 2, "one exchange, one send");

    // Google says 3599s; the adapter retires the token five minutes early,
    // so it is still good at 3298 and gone at 3299.
    clock.advance(3_298);
    pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap();
    assert_eq!(authorization(), "Bearer ya29.first", "still cached");
    assert_eq!(http.count(), 3, "no second exchange");

    clock.advance(1);
    pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap();
    assert_eq!(authorization(), "Bearer ya29.second", "re-exchanged");
    assert_eq!(http.count(), 5);
    assert_eq!(http.remaining(), 0, "the script was consumed exactly");
}

#[test]
fn a_failed_token_exchange_is_transient_and_sends_no_message() {
    let http = ScriptedHttp::new([Reply::new(
        400,
        json!({ "error": "invalid_grant", "error_description": "Invalid JWT Signature." })
            .to_string(),
    )]);
    let fcm = adapter(http.clone(), StepClock::at(1));
    let error = pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(error, PushError::Transient { .. }), "{error}");
    assert!(error.to_string().contains("invalid_grant"), "{error}");
    assert!(
        error.to_string().contains("Invalid JWT Signature."),
        "{error}"
    );
    assert_eq!(http.count(), 1, "the message was never attempted");
}

#[test]
fn a_token_response_without_an_expiry_is_used_but_not_cached() {
    // Nothing says how long it lives, so it is exchanged again next time
    // rather than reused past its life.
    let http = ScriptedHttp::new([
        Reply::new(200, json!({ "access_token": "ya29.mystery" }).to_string()),
        send_reply(),
        Reply::new(200, json!({ "access_token": "ya29.mystery" }).to_string()),
        send_reply(),
    ]);
    let fcm = adapter(http.clone(), StepClock::at(1));
    pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap();
    pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap();
    assert_eq!(http.count(), 4);
    assert_eq!(http.remaining(), 0);
}

// ---------------------------------------------------------------------------
// The 401 re-mint

#[test]
fn a_401_unauthenticated_re_exchanges_the_token_and_retries_once() {
    let http = ScriptedHttp::new([
        token_reply("ya29.stale"),
        fcm_error(401, "UNSPECIFIED_ERROR"), // an expired bearer token
        token_reply("ya29.fresh"),
        send_reply(),
    ]);
    let fcm = adapter(http.clone(), StepClock::at(1));

    let outcome = pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap();
    assert_eq!(
        outcome,
        PushOutcome::Delivered {
            id: Some(MESSAGE_NAME.to_owned())
        }
    );
    assert_eq!(http.count(), 4, "token, 401, re-exchange, retry");
    assert_eq!(
        http.nth(1, |request| request
            .header("authorization")
            .unwrap()
            .to_owned()),
        "Bearer ya29.stale"
    );
    assert_eq!(
        http.nth(3, |request| request
            .header("authorization")
            .unwrap()
            .to_owned()),
        "Bearer ya29.fresh",
        "the retry presents the newly exchanged token"
    );
}

#[test]
fn a_401_that_persists_is_transient_and_retried_exactly_once() {
    let http = ScriptedHttp::new([
        token_reply("ya29.first"),
        fcm_error(401, "UNSPECIFIED_ERROR"),
        token_reply("ya29.second"),
        fcm_error(401, "UNSPECIFIED_ERROR"),
        // Nothing after this: a third attempt would panic the fake.
    ]);
    let fcm = adapter(http.clone(), StepClock::at(1));

    let error = pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(error, PushError::Transient { .. }), "{error}");
    assert!(
        error.to_string().contains("freshly exchanged"),
        "the message says the re-mint was tried: {error}"
    );
    assert_eq!(http.count(), 4);
    assert_eq!(http.remaining(), 0);
}

#[test]
fn third_party_auth_error_is_a_rejection_and_never_re_exchanges() {
    // A 401 that is *not* about our bearer token: the Firebase project is
    // missing the APNs credential for an iOS-via-FCM send. Re-minting our
    // token cannot fix it, so the send must not be retried.
    for code in ["THIRD_PARTY_AUTH_ERROR", "APNS_AUTH_ERROR"] {
        let http = ScriptedHttp::failing(fcm_error(401, code));
        let fcm = adapter(http.clone(), StepClock::at(1));
        let error =
            pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
        assert!(
            matches!(&error, PushError::Rejected(m) if m.contains(code)),
            "{code}: {error:?}"
        );
        assert_eq!(http.count(), 2, "{code}: one exchange, one send, no retry");
    }
}

// ---------------------------------------------------------------------------
// Error mapping

#[test]
fn maps_unregistered_to_the_prune_signal() {
    let http = ScriptedHttp::failing(fcm_error(404, "UNREGISTERED"));
    let fcm = adapter(http, StepClock::at(1));
    let error = pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(error, PushError::Unregistered), "{error}");
}

#[test]
fn maps_every_rejected_error_code() {
    // Status *and* code, because the status alone is ambiguous:
    // THIRD_PARTY_AUTH_ERROR arrives as a 401, which is otherwise the
    // adapter's own token being refused.
    for (status, code) in [
        (400, "INVALID_ARGUMENT"),
        (403, "SENDER_ID_MISMATCH"),
        (401, "THIRD_PARTY_AUTH_ERROR"),
    ] {
        let http = ScriptedHttp::failing(fcm_error(status, code));
        let fcm = adapter(http, StepClock::at(1));
        let error =
            pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
        assert!(
            matches!(&error, PushError::Rejected(m) if m.contains(code)),
            "{code}: {error:?}"
        );
        assert_eq!(error.retry_after(), None);
    }
}

#[test]
fn maps_every_retryable_error_code_and_honours_retry_after() {
    for (status, code) in [
        (429, "QUOTA_EXCEEDED"),
        (503, "UNAVAILABLE"),
        (500, "INTERNAL"),
    ] {
        let http = ScriptedHttp::failing(fcm_error(status, code).after("30"));
        let fcm = adapter(http, StepClock::at(1));
        let error =
            pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
        assert!(
            matches!(&error, PushError::Transient { message, .. } if message.contains(code)),
            "{code}: {error:?}"
        );
        assert_eq!(
            error.retry_after(),
            Some(Duration::from_secs(30)),
            "{code}: the provider's back-off must reach the outbox"
        );
    }

    // No header, no delay — and an HTTP-date form is not parsed, which just
    // means "retry on your own schedule".
    for reply in [
        fcm_error(503, "UNAVAILABLE"),
        fcm_error(503, "UNAVAILABLE").after("Wed, 21 Oct 2026 07:28:00 GMT"),
    ] {
        let http = ScriptedHttp::failing(reply);
        let fcm = adapter(http, StepClock::at(1));
        let error =
            pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
        assert!(matches!(error, PushError::Transient { .. }), "{error}");
        assert_eq!(error.retry_after(), None);
    }
}

#[test]
fn falls_back_to_the_http_status_when_the_body_carries_no_error_code() {
    // A proxy, a load balancer or an outage answers with something that is
    // not an FCM error body at all.
    type Expectation = fn(&PushError) -> bool;
    let cases: [(u16, &str, Expectation); 4] = [
        (404, "", |e| matches!(e, PushError::Unregistered)),
        (400, "<html>bad request</html>", |e| {
            matches!(e, PushError::Rejected(_))
        }),
        (429, "", |e| matches!(e, PushError::Transient { .. })),
        (502, "upstream boom", |e| {
            matches!(e, PushError::Transient { .. })
        }),
    ];
    for (status, body, expected) in cases {
        let http = ScriptedHttp::failing(Reply::new(status, body));
        let fcm = adapter(http, StepClock::at(1));
        let error =
            pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
        assert!(expected(&error), "{status}: {error:?}");
    }
}

#[test]
fn an_unknown_error_code_still_maps_by_status_and_keeps_the_code() {
    // Google adds codes; an unrecognised one must not become a success or a
    // panic, and the code has to reach the log.
    let http = ScriptedHttp::failing(fcm_error(503, "SOMETHING_NEW"));
    let fcm = adapter(http, StepClock::at(1));
    let error = pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(
        matches!(&error, PushError::Transient { message, .. } if message.contains("SOMETHING_NEW")),
        "{error:?}"
    );
}

#[test]
fn an_error_with_a_status_but_no_detail_still_says_something_useful() {
    let http = ScriptedHttp::failing(Reply::new(
        400,
        json!({ "error": { "code": 400, "status": "INVALID_ARGUMENT", "message": "bad token" } })
            .to_string(),
    ));
    let fcm = adapter(http, StepClock::at(1));
    let error = pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(
        matches!(&error, PushError::Rejected(m) if m.contains("INVALID_ARGUMENT")),
        "{error:?}"
    );
}

#[test]
fn a_transport_error_is_transient() {
    struct Broken;
    #[async_trait::async_trait]
    impl HttpClient for Broken {
        async fn send(&self, _: http::Request<Bytes>) -> Result<http::Response<Bytes>, HttpError> {
            Err(HttpError::Transport("connection reset".to_owned()))
        }
    }
    let fcm = Fcm::new(Arc::new(Broken), StepClock::at(1), creds()).unwrap();
    let error = pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(error, PushError::Transient { .. }), "{error}");
}

// ---------------------------------------------------------------------------
// The payload

/// The golden: one rich notification, asserted whole. Every mapping decision
/// this adapter makes is visible here, including the rule that FCM `data`
/// values are **strings** and nested JSON is serialised into one.
#[test]
fn the_v1_message_is_this_exact_json() {
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1_700_000_000));

    let mut notification = Notification::new("Room starting", "Yoga in 10 min");
    notification.category = Some("sessions".to_owned());
    notification.thread_id = Some("room-42".to_owned());
    notification.data = json!({
        "room_id": "42",
        "seats": 3,
        "vip": true,
        "room": { "id": 42, "name": "Studio A" },
        "tags": ["yoga", "beginner"],
        "nothing": null,
    });
    notification.collapse_id = Some("room-42".to_owned());
    notification.priority = Priority::Conserve;
    notification.icon = Some("https://example.test/hero.png".to_owned());
    notification.url = Some("https://example.test/rooms/42".to_owned());
    notification.ttl = Some(Duration::from_secs(3_600));
    notification.badge = Some(3); // FCM has no badge; dropped
    notification.loc = Some(LocKeys {
        title_loc_key: Some("ROOM_STARTING".to_owned()),
        title_loc_args: vec!["Yoga".to_owned()],
        body_loc_key: Some("ROOM_BODY".to_owned()),
        body_loc_args: vec!["10".to_owned()],
    });

    pollster::block_on(fcm.send(&Recipient::fcm("reg-token"), &notification)).unwrap();

    assert_eq!(
        http.nth(1, Recorded::json),
        json!({
            "message": {
                "token": "reg-token",
                "notification": {
                    "title": "Room starting",
                    "body": "Yoga in 10 min",
                    "image": "https://example.test/hero.png"
                },
                "android": {
                    "priority": "NORMAL",
                    "ttl": "3600s",
                    "collapse_key": "room-42",
                    "notification": {
                        "channel_id": "sessions",
                        "tag": "room-42",
                        "click_action": "https://example.test/rooms/42",
                        "title_loc_key": "ROOM_STARTING",
                        "title_loc_args": ["Yoga"],
                        "body_loc_key": "ROOM_BODY",
                        "body_loc_args": ["10"]
                    }
                },
                "data": {
                    "room_id": "42",
                    "seats": "3",
                    "vip": "true",
                    "room": "{\"id\":42,\"name\":\"Studio A\"}",
                    "tags": "[\"yoga\",\"beginner\"]",
                    "nothing": "null",
                    "url": "https://example.test/rooms/42"
                }
            }
        })
    );
}

#[test]
fn every_data_value_is_a_string() {
    // FCM rejects a message whose `data` holds anything but strings, so the
    // adapter serialises rather than passing structure through. Asserted on
    // the types, not only on the golden's literal text.
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    let mut notification = Notification::new("a", "b");
    notification.data = json!({
        "string": "already a string",
        "number": 42,
        "float": 1.5,
        "bool": false,
        "null": null,
        "array": [1, 2],
        "object": { "nested": true },
    });
    pollster::block_on(fcm.send(&device(), &notification)).unwrap();

    let data = http.nth(1, Recorded::json)["message"]["data"].clone();
    let data = data.as_object().expect("a data object");
    for (key, value) in data {
        assert!(value.is_string(), "data[{key}] is {value:?}, not a string");
    }
    assert_eq!(data["string"], "already a string", "no double quoting");
    assert_eq!(data["number"], "42");
    assert_eq!(data["float"], "1.5");
    assert_eq!(data["bool"], "false");
    assert_eq!(data["null"], "null");
    assert_eq!(data["array"], "[1,2]");
    assert_eq!(data["object"], "{\"nested\":true}");
}

#[test]
fn a_minimal_notification_carries_no_data_key_at_all() {
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    pollster::block_on(fcm.send(&device(), &Notification::new("Hi", "there"))).unwrap();

    assert_eq!(
        http.nth(1, Recorded::json),
        json!({
            "message": {
                "token": "reg-token",
                "notification": { "title": "Hi", "body": "there" },
                "android": { "priority": "HIGH" }
            }
        })
    );
}

#[test]
fn a_silent_notification_is_a_data_only_message() {
    // No `notification` and no `android.notification`: that is precisely what
    // makes Android hand the payload to the app instead of drawing it.
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));

    let mut notification = Notification::new("not shown", "not shown either");
    notification.silent = true;
    notification.category = Some("sessions".to_owned());
    notification.thread_id = Some("room-42".to_owned());
    notification.icon = Some("https://example.test/hero.png".to_owned());
    notification.url = Some("https://example.test/rooms/42".to_owned());
    notification.data = json!({ "sync": true });
    pollster::block_on(fcm.send(&device(), &notification)).unwrap();

    let body = http.nth(1, Recorded::json);
    assert_eq!(
        body,
        json!({
            "message": {
                "token": "reg-token",
                "android": { "priority": "HIGH" },
                "data": {
                    "sync": "true",
                    // The tap target still travels, because a silent message
                    // has no notification block to hold `click_action`.
                    "url": "https://example.test/rooms/42"
                }
            }
        })
    );
    assert!(body["message"]["notification"].is_null());
    assert!(body["message"]["android"]["notification"].is_null());
}

#[test]
fn a_silent_notification_keeps_the_priority_the_caller_asked_for() {
    // Unlike APNs, which rejects a background push at priority 10, FCM wants
    // HIGH on a data message — that is what wakes the app.
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    let mut notification = Notification::new("a", "b");
    notification.silent = true;
    notification.priority = Priority::Immediate;
    pollster::block_on(fcm.send(&device(), &notification)).unwrap();
    assert_eq!(
        http.nth(1, Recorded::json)["message"]["android"]["priority"],
        "HIGH"
    );
}

#[test]
fn a_ttl_is_a_duration_string_and_sub_second_rounds_up() {
    for (ttl, expected) in [
        (Duration::from_secs(3_600), "3600s"),
        (Duration::ZERO, "0s"),
        // 900ms is "hold it briefly", not "drop it the moment the device is
        // offline", which is what `0s` would mean.
        (Duration::from_millis(900), "1s"),
    ] {
        let http = ScriptedHttp::happy();
        let fcm = adapter(http.clone(), StepClock::at(1));
        let mut notification = Notification::new("a", "b");
        notification.ttl = Some(ttl);
        pollster::block_on(fcm.send(&device(), &notification)).unwrap();
        assert_eq!(
            http.nth(1, Recorded::json)["message"]["android"]["ttl"],
            expected,
            "{ttl:?}"
        );
    }
}

#[test]
fn a_url_icon_is_the_image_and_a_bare_name_is_the_drawable() {
    // `notification.image` is downloaded by the device; `android.notification
    // .icon` names a drawable inside the app. Putting one in the other's
    // place shows nothing at all.
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    let mut notification = Notification::new("a", "b");
    notification.icon = Some("https://example.test/hero.png".to_owned());
    pollster::block_on(fcm.send(&device(), &notification)).unwrap();
    let body = http.nth(1, Recorded::json);
    assert_eq!(
        body["message"]["notification"]["image"],
        "https://example.test/hero.png"
    );
    assert!(body["message"]["android"]["notification"].is_null());

    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    let mut notification = Notification::new("a", "b");
    notification.icon = Some("ic_notification".to_owned());
    pollster::block_on(fcm.send(&device(), &notification)).unwrap();
    let body = http.nth(1, Recorded::json);
    assert!(body["message"]["notification"]["image"].is_null());
    assert_eq!(
        body["message"]["android"]["notification"]["icon"],
        "ic_notification"
    );
}

#[test]
fn the_notifications_url_wins_over_one_in_data() {
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    let mut notification = Notification::new("a", "b");
    notification.data = json!({ "url": "https://example.test/from-data", "room_id": "42" });
    notification.url = Some("https://example.test/from-field".to_owned());
    pollster::block_on(fcm.send(&device(), &notification)).unwrap();
    let data = http.nth(1, Recorded::json)["message"]["data"].clone();
    assert_eq!(data["url"], "https://example.test/from-field");
    assert_eq!(data["room_id"], "42");

    // ...and with no `url` set, the caller's own key survives untouched.
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    let mut notification = Notification::new("a", "b");
    notification.data = json!({ "url": "https://example.test/from-data" });
    pollster::block_on(fcm.send(&device(), &notification)).unwrap();
    assert_eq!(
        http.nth(1, Recorded::json)["message"]["data"]["url"],
        "https://example.test/from-data"
    );
}

#[test]
fn loc_args_are_only_emitted_with_their_key() {
    // `*_loc_args` are the substitutions for a `*_loc_key`. Without the key
    // they substitute into nothing and FCM defines no meaning for them.
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    let mut notification = Notification::new("a", "b");
    notification.loc = Some(LocKeys {
        title_loc_key: None,
        title_loc_args: vec!["Yoga".to_owned()],
        body_loc_key: None,
        body_loc_args: vec!["10".to_owned()],
    });
    pollster::block_on(fcm.send(&device(), &notification)).unwrap();
    let body = http.nth(1, Recorded::json);
    assert!(
        body["message"]["android"]["notification"].is_null(),
        "nothing to say, so no block at all: {body}"
    );
}

#[test]
fn a_non_object_data_payload_is_left_out_rather_than_mangled() {
    // The port types `data` as any JSON value, but FCM's is a flat string
    // map: an array has no keys to flatten into it.
    let http = ScriptedHttp::happy();
    let fcm = adapter(http.clone(), StepClock::at(1));
    let mut notification = Notification::new("a", "b");
    notification.data = json!(["not", "a", "map"]);
    pollster::block_on(fcm.send(&device(), &notification)).unwrap();
    assert!(http.nth(1, Recorded::json)["message"]["data"].is_null());
}

#[test]
fn delivered_carries_the_message_name_and_a_nameless_success_still_delivers() {
    let http = ScriptedHttp::happy();
    let fcm = adapter(http, StepClock::at(1));
    let outcome = pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap();
    assert_eq!(
        outcome,
        PushOutcome::Delivered {
            id: Some(MESSAGE_NAME.to_owned())
        }
    );

    let http = ScriptedHttp::new([token_reply("ya29.first"), Reply::new(200, "")]);
    let fcm = adapter(http, StepClock::at(1));
    let outcome = pollster::block_on(fcm.send(&device(), &Notification::new("a", "b"))).unwrap();
    assert_eq!(outcome, PushOutcome::Delivered { id: None });
}
