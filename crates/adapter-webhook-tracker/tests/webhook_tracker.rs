//! Webhook tracker acceptance tests (issue #432): the signature a receiver
//! can recompute from the raw wire bytes, the timestamp bound into it, the
//! status mapping table, the delegated idempotency, and the signing secret
//! never appearing in any error string, header or body.

#![allow(clippy::disallowed_types)]
// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_webhook_tracker::WebhookTracker;
use cratefield_core::{
    Clock, Destination, HttpClient, HttpError, TicketDraft, Tracker, TrackerError,
};
use hmac::{Hmac, KeyInit, Mac};
use http::{HeaderMap, Request, Response, StatusCode};
use serde_json::Value;
use sha2::Sha256;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// Obvious dummy secret, never real.
const SECRET: &str = "whsec_dummy_secret_0000000000";
const URL: &str = "http://hooks.fake/tickets";

/// Frozen wall clock, so the HTTP-date form of `Retry-After` has a
/// deterministic delta.
struct FixedClock(time::OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

fn clock_at(secs_past_epoch: i64) -> Arc<dyn Clock> {
    Arc::new(FixedClock(
        time::OffsetDateTime::from_unix_timestamp(secs_past_epoch).expect("valid timestamp"),
    ))
}

/// IMF-fixdate, the one date form RFC 9110 requires senders to emit.
fn http_date(at: time::OffsetDateTime) -> String {
    let format = time::format_description::parse_borrowed::<2>(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT",
    )
    .expect("valid format");
    at.format(&format).expect("formats")
}

struct CapturedRequest {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: String,
}

/// One queued response, in the order the adapter will ask for it. A file
/// call is one request, so most tests queue exactly one.
struct Scripted {
    status: u16,
    body: String,
    retry_after: Option<String>,
}

fn respond(status: u16, body: impl Into<String>) -> Scripted {
    Scripted {
        status,
        body: body.into(),
        retry_after: None,
    }
}

/// A scripted fake: records every request (method, uri, headers, body) out
/// through a channel and hands back the queued responses in order.
struct FakeHttp {
    responses: std::sync::Mutex<mpsc::Receiver<Scripted>>,
    calls: AtomicUsize,
    tx: mpsc::Sender<CapturedRequest>,
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (parts, body) = request.into_parts();
        self.tx
            .send(CapturedRequest {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body: String::from_utf8_lossy(&body).to_string(),
            })
            .expect("test channel open");
        let scripted = self
            .responses
            .lock()
            .expect("response queue lock")
            .try_recv()
            .expect("every request has a queued response");
        let mut builder = Response::builder()
            .status(StatusCode::from_u16(scripted.status).expect("valid status"));
        if let Some(retry) = &scripted.retry_after {
            builder = builder.header("retry-after", retry.as_str());
        }
        builder
            .body(Bytes::from(scripted.body))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

/// A fake whose vetting refuses the destination — what the real port
/// implementations do before any socket opens (issue #136, destinations).
struct BlockingHttp;

#[async_trait]
impl HttpClient for BlockingHttp {
    async fn send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        Err(HttpError::BlockedDestination(
            "169.254.169.254 is not a public destination".to_owned(),
        ))
    }
}

/// A fake whose sends always fail, for the transport half of the mapping.
struct FailingHttp {
    tx: mpsc::Sender<CapturedRequest>,
}

#[async_trait]
impl HttpClient for FailingHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        self.tx
            .send(CapturedRequest {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body: String::from_utf8_lossy(&body).to_string(),
            })
            .expect("test channel open");
        Err(HttpError::Transport("dns is down".to_string()))
    }
}

fn fixture(responses: Vec<Scripted>) -> (Arc<FakeHttp>, mpsc::Receiver<CapturedRequest>) {
    let (stx, srx) = mpsc::channel();
    for response in responses {
        stx.send(response).expect("queue holds");
    }
    drop(stx);
    let (tx, rx) = mpsc::channel();
    (
        Arc::new(FakeHttp {
            responses: std::sync::Mutex::new(srx),
            calls: AtomicUsize::new(0),
            tx,
        }),
        rx,
    )
}

fn captured(rx: &mpsc::Receiver<CapturedRequest>) -> Vec<CapturedRequest> {
    let mut seen = Vec::new();
    while let Ok(request) = rx.try_recv() {
        seen.push(request);
    }
    seen
}

fn draft() -> TicketDraft {
    TicketDraft::new(
        "Outbox: refund failed",
        "The refund webhook failed twice.",
        Destination::Webhook {
            url: URL.to_owned(),
        },
        "idem-123",
    )
    .labels(["from-outbox"])
}

fn adapter(http: Arc<FakeHttp>) -> WebhookTracker {
    WebhookTracker::new(http, clock_at(0), SECRET)
}

/// Pulls `t` and `v1` out of `Cratefield-Signature: t=<unix>,v1=<hex>`.
fn signature_parts(header: &str) -> (String, String) {
    let mut t = None;
    let mut v1 = None;
    for part in header.split(',') {
        let (key, value) = part.split_once('=').expect("k=v pairs");
        match key {
            "t" => t = Some(value.to_owned()),
            "v1" => v1 = Some(value.to_owned()),
            other => panic!("unexpected signature part: {other}"),
        }
    }
    (t.expect("a t part"), v1.expect("a v1 part"))
}

/// The independent recomputation the issue asks for — HMAC-SHA256 under the
/// secret over `{t}.{body}`, lowercase hex. Test-side: this never calls the
/// adapter's own helper, or verifying it would be a round trip.
fn expected_signature(secret: &str, t: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(t.as_bytes());
    mac.update(b".");
    mac.update(body);
    hex_encode(&mac.finalize().into_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The one POST a happy-path file call makes, with its signature header
/// split into `(t, v1)`.
async fn one_signed_post() -> (CapturedRequest, String, String) {
    let (http, rx) = fixture(vec![respond(200, "{}")]);
    adapter(http).file(&draft()).await.expect("file ok");
    let mut requests = captured(&rx);
    assert_eq!(requests.len(), 1, "a file call is one request");
    let post = requests.remove(0);
    let header = post
        .headers
        .get("cratefield-signature")
        .expect("a signature header")
        .to_str()
        .expect("ascii header");
    let (t, v1) = signature_parts(header);
    (post, t, v1)
}

// ---------------------------------------------------------------------------
// The signature

#[pollster::test]
async fn the_signature_verifies_against_the_captured_raw_body() {
    let (post, t, v1) = one_signed_post().await;
    assert_eq!(post.method, "POST");
    assert_eq!(post.uri, URL);
    assert_eq!(
        post.headers.get("content-type").unwrap(),
        "application/json"
    );

    // The issue's acceptance criterion, recomputed from scratch: the raw
    // body exactly as it went out (the JSON is UTF-8, so the lossy capture
    // above is byte-exact), HMAC'd by the test's own hmac/sha2 calls.
    let expected = expected_signature(SECRET, &t, post.body.as_bytes());
    assert_eq!(v1, expected, "v1 must equal HMAC-SHA256(secret, t.body)");
    assert_eq!(v1.len(), 64, "SHA-256 in hex");
}

#[pollster::test]
async fn a_tampered_body_fails_the_verification() {
    let (post, t, v1) = one_signed_post().await;

    // Flip the first body byte and recompute over the tampered bytes: a
    // mismatch proves the MAC actually covers the body, not just the `t`.
    let mut tampered = post.body.clone().into_bytes();
    tampered[0] = if tampered[0] == b'{' { b'X' } else { b'{' };
    let expected = expected_signature(SECRET, &t, &tampered);
    assert_ne!(v1, expected, "the MAC must not survive a body edit");
}

#[pollster::test]
async fn a_replay_cannot_be_re_stamped_with_a_fresh_timestamp() {
    let (post, t, v1) = one_signed_post().await;

    // Re-stamp: the same body under a timestamp one second later. The
    // mismatch is the point of binding `t` into the MAC — a replayed
    // delivery cannot be given a fresh timestamp without invalidating it.
    let forged_t = (t.parse::<i64>().expect("unix seconds") + 1).to_string();
    let expected = expected_signature(SECRET, &forged_t, post.body.as_bytes());
    assert_ne!(v1, expected, "a fresh t must invalidate the MAC");
}

#[pollster::test]
async fn the_timestamp_comes_from_the_injected_clock() {
    let at = 1_800_000_000_i64;
    let (http, rx) = fixture(vec![respond(200, "{}")]);
    let filed = WebhookTracker::new(http, clock_at(at), SECRET)
        .file(&draft())
        .await
        .expect("file ok");
    // The `Filed` this adapter can honestly report: the key is the id,
    // there is no tracker-side URL, and a webhook answer is never a dedupe
    // verdict of ours.
    assert_eq!(filed.id, "idem-123");
    assert_eq!(filed.url, None);
    assert!(!filed.deduplicated);

    let requests = captured(&rx);
    let post = &requests[0];
    let header = post
        .headers
        .get("cratefield-signature")
        .expect("a signature header")
        .to_str()
        .expect("ascii header");
    let (t, _v1) = signature_parts(header);
    assert_eq!(t, at.to_string(), "t is the injected clock's instant");

    // The same instant rides in the payload, so a receiver-side freshness
    // check agrees with the signature it verifies against.
    let payload: Value = serde_json::from_str(&post.body).expect("json body");
    assert_eq!(payload["filed_at"], at);
}

// ---------------------------------------------------------------------------
// The body

#[pollster::test]
async fn the_body_carries_the_draft_and_its_idempotency_key() {
    let (post, _t, _v1) = one_signed_post().await;
    let payload: Value = serde_json::from_str(&post.body).expect("json body");
    // The receiver dedupes on this field, so it must survive the wire.
    assert_eq!(payload["idempotency_key"], "idem-123");
    assert_eq!(payload["title"], "Outbox: refund failed");
    assert_eq!(payload["body"], "The refund webhook failed twice.");
    assert_eq!(payload["labels"][0], "from-outbox");
    assert!(
        payload["filed_at"].is_i64(),
        "the filing timestamp is in the payload"
    );
}

// ---------------------------------------------------------------------------
// Status mapping

#[pollster::test]
async fn status_mapping_is_the_issue_table() {
    // (status, expected): 401/403 the shared secret is wrong or powerless;
    // 404 the endpoint is gone; 422 the ticket itself was refused; every
    // other 4xx is a fact about our request; 429 and the 5xx family are
    // the receiver having a moment.
    let cases = [
        (401u16, "unauthorized"),
        (403, "unauthorized"),
        (404, "rejected"),
        (422, "rejected"),
        (400, "rejected"),
        (418, "rejected"),
        (429, "transient"),
        (500, "transient"),
        (502, "transient"),
        (503, "transient"),
    ];
    for (status, expected) in cases {
        let (http, rx) = fixture(vec![respond(status, r#"{"message":"nope"}"#)]);
        let err = adapter(http)
            .file(&draft())
            .await
            .expect_err("a failed delivery must fail the call");
        match expected {
            "unauthorized" => assert!(
                matches!(err, TrackerError::Unauthorized),
                "status {status}: {err}"
            ),
            "rejected" => assert!(
                matches!(err, TrackerError::Rejected(_)),
                "status {status}: {err}"
            ),
            _ => assert!(
                matches!(err, TrackerError::Transient { .. }),
                "status {status}: {err}"
            ),
        }
        assert_eq!(
            captured(&rx).len(),
            1,
            "status {status} stopped at the one delivery"
        );
    }
}

#[pollster::test]
async fn rate_limit_reads_the_seconds_form_of_retry_after() {
    let (http, _rx) = fixture(vec![
        respond(429, r#"{"message":"slow down"}"#).with_retry_after("5"),
    ]);
    let err = adapter(http).file(&draft()).await.unwrap_err();
    match err {
        TrackerError::Transient { retry_after, .. } => {
            assert_eq!(retry_after, Some(Duration::from_secs(5)));
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn rate_limit_reads_the_http_date_form_of_retry_after() {
    // A CDN in front of the receiver answers with a date (issue #278): one
    // hour from the adapter's clock, not an immediate retry.
    let at = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid timestamp");
    let date = http_date(at + time::Duration::seconds(3_600));
    let (http, _rx) = fixture(vec![
        respond(503, r#"{"message":"slow down"}"#).with_retry_after(&date),
    ]);
    let err = WebhookTracker::new(http, clock_at(1_800_000_000), SECRET)
        .file(&draft())
        .await
        .unwrap_err();
    match err {
        TrackerError::Transient { retry_after, .. } => {
            assert_eq!(retry_after, Some(Duration::from_secs(3_600)));
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn a_transport_failure_is_transient() {
    let (tx, rx) = mpsc::channel();
    let err = WebhookTracker::new(Arc::new(FailingHttp { tx }), clock_at(0), SECRET)
        .file(&draft())
        .await
        .expect_err("dns is down");
    match err {
        TrackerError::Transient {
            message,
            retry_after,
        } => {
            assert!(message.contains("dns is down"), "{message}");
            assert_eq!(retry_after, None);
        }
        other => panic!("wrong error: {other}"),
    }
    assert_eq!(captured(&rx).len(), 1, "the one delivery attempt");
}

// ---------------------------------------------------------------------------
// Destinations

#[pollster::test]
async fn a_blocked_destination_is_rejected_not_transient() {
    // The port's SSRF vetting refused the tenant-configured URL. A config
    // error, not weather: `Rejected`, and no retry delay is named.
    let err = WebhookTracker::new(Arc::new(BlockingHttp), clock_at(0), SECRET)
        .file(&draft())
        .await
        .expect_err("the port refused the destination");
    match &err {
        TrackerError::Rejected(detail) => {
            assert!(detail.contains("169.254.169.254"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
    assert_eq!(err.retry_after(), None);
    let rendered = err.to_string();
    assert!(!rendered.contains(SECRET), "{rendered}");
}

#[pollster::test]
async fn a_github_issues_destination_is_rejected_without_network() {
    let (http, rx) = fixture(vec![]);
    let gh = TicketDraft::new(
        "Outbox: refund failed",
        "The refund webhook failed twice.",
        Destination::GitHubIssues {
            owner: "acme".to_owned(),
            repo: "widgets".to_owned(),
        },
        "idem-123",
    );
    let err = adapter(http.clone())
        .file(&gh)
        .await
        .expect_err("this adapter does not file GitHub issues");
    match err {
        TrackerError::Rejected(detail) => {
            assert!(detail.contains("GitHubIssues"), "{detail}");
            assert!(detail.contains("webhook"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
    assert_eq!(
        http.calls.load(Ordering::SeqCst),
        0,
        "the mismatch is known before any network call"
    );
    assert!(captured(&rx).is_empty());
}

// ---------------------------------------------------------------------------
// The secret

#[pollster::test]
async fn every_error_display_omits_the_secret() {
    let variants = [
        (401u16, r#"{"message":"Bad signature"}"#),
        (403, r#"{"message":"Forbidden"}"#),
        (404, r#"{"message":"Not Found"}"#),
        (422, r#"{"message":"Unprocessable Entity"}"#),
        (429, r#"{"message":"Too Many Requests"}"#),
        (500, "server error"),
        (418, r#"{"message":"teapot"}"#),
    ];
    for (status, body) in variants {
        let (http, rx) = fixture(vec![respond(status, body)]);
        let err = adapter(http).file(&draft()).await.expect_err("must fail");
        let rendered = err.to_string();
        // An empty rendering omits the secret and everything else. The
        // display has to remain useful for this absence to mean anything.
        assert!(
            rendered.len() > 8,
            "status {status} rendered an error that says nothing: {rendered:?}"
        );
        assert!(
            !rendered.contains(SECRET),
            "status {status} leaked the secret: {rendered}"
        );
        assert!(
            !format!("{err:?}").contains(SECRET),
            "status {status} leaked the secret in Debug: {err:?}"
        );
        // And the wire: the secret rides only in the MAC, never raw.
        for request in captured(&rx) {
            for value in request.headers.values() {
                assert!(
                    !value.to_str().is_ok_and(|value| value.contains(SECRET)),
                    "status {status} leaked the secret in a header"
                );
            }
            assert!(
                !request.body.contains(SECRET),
                "status {status} leaked the secret in the body"
            );
        }
    }
}

#[test]
fn webhook_tracker_deps_are_wasm_safe() {
    cratefield_testing::assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}

impl Scripted {
    fn with_retry_after(mut self, value: &str) -> Self {
        self.retry_after = Some(value.to_owned());
        self
    }
}
