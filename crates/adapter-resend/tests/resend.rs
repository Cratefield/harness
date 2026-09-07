//! Resend adapter acceptance tests (issue #6): success, every error
//! mapping, `Idempotency-Key`, `NotConfigured` short-circuit, and the API key
//! never appearing in any error string.

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_resend::Resend;
use cratefield_core::{HttpClient, HttpError, MailError, Mailer, Message, SendOutcome};
use http::{HeaderMap, Request, Response, StatusCode};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// Obvious dummy key, never real.
const DUMMY_KEY: &str = "re_dummy_key_000000000000";

struct FakeHttp {
    status: u16,
    body: &'static str,
    retry_after: Option<&'static str>,
    calls: AtomicUsize,
    tx: mpsc::Sender<CapturedRequest>,
}

struct CapturedRequest {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: String,
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
        let mut builder =
            Response::builder().status(StatusCode::from_u16(self.status).expect("valid status"));
        if let Some(retry) = self.retry_after {
            builder = builder.header("retry-after", retry);
        }
        builder
            .body(Bytes::from(self.body))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

fn fixture(
    status: u16,
    body: &'static str,
    retry_after: Option<&'static str>,
) -> (Arc<FakeHttp>, mpsc::Receiver<CapturedRequest>) {
    let (tx, rx) = mpsc::channel();
    (
        Arc::new(FakeHttp {
            status,
            body,
            retry_after,
            calls: AtomicUsize::new(0),
            tx,
        }),
        rx,
    )
}

fn message() -> Message {
    Message {
        to: "nick@example.com".to_string(),
        from: String::new(),
        reply_to: None,
        subject: "Confirm".to_string(),
        html: "<p>hi</p>".to_string(),
        text: "hi".to_string(),
        idempotency_key: Some("idem-123".to_string()),
        tags: vec!["transactional".to_string()],
    }
}

fn adapter(http: Arc<FakeHttp>) -> Resend {
    Resend::new(
        http,
        Some(DUMMY_KEY.to_string()),
        "Factory Zero <no-reply@test.factory0.dev>",
        None,
    )
}

#[pollster::test]
async fn success_returns_sent_with_provider_id() {
    let (http, rx) = fixture(200, r#"{"id":"email-xyz"}"#, None);
    let outcome = adapter(http.clone())
        .send(message())
        .await
        .expect("send ok");
    assert_eq!(
        outcome,
        SendOutcome::Sent {
            id: "email-xyz".into()
        }
    );

    let captured = rx.try_recv().expect("one request");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.uri, "https://api.resend.com/emails");
    assert_eq!(
        captured.headers.get("authorization").unwrap(),
        format!("Bearer {DUMMY_KEY}").as_str()
    );
    assert_eq!(captured.headers.get("idempotency-key").unwrap(), "idem-123");
    assert_eq!(
        captured.headers.get("content-type").unwrap(),
        "application/json"
    );

    let body: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["from"], "Factory Zero <no-reply@test.factory0.dev>");
    assert_eq!(body["to"], "nick@example.com");
    assert_eq!(body["html"], "<p>hi</p>");
    assert_eq!(body["text"], "hi");
    // Resend requires tags as `{ name, value }` objects; a bare string array
    // is rejected with `422 Invalid input` (verified against the live API).
    assert_eq!(body["tags"][0]["name"], "transactional");
    assert_eq!(body["tags"][0]["value"], "1");
}

#[pollster::test]
async fn tag_names_are_sanitized_to_resend_charset() {
    let (http, rx) = fixture(200, r#"{"id":"x"}"#, None);
    let mut msg = message();
    // A tag with characters Resend forbids (only a-z A-Z 0-9 _ - allowed).
    msg.tags = vec!["waitlist:cratefield".to_string()];
    adapter(http).send(msg).await.expect("send ok");
    let captured = rx.try_recv().expect("one request");
    let body: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["tags"][0]["name"], "waitlist_cratefield");
}

#[pollster::test]
async fn unauthorized_maps_to_unauthorized() {
    let (http, _rx) = fixture(401, r#"{"message":"invalid api key"}"#, None);
    let err = adapter(http).send(message()).await.unwrap_err();
    assert!(matches!(err, MailError::Unauthorized));
    assert!(!err.to_string().contains(DUMMY_KEY));
}

#[pollster::test]
async fn forbidden_with_domain_message_maps_to_domain_not_verified() {
    let (http, _rx) = fixture(
        403,
        r#"{"message":"Domain send.factory0.ventures is not verified"}"#,
        None,
    );
    let err = adapter(http).send(message()).await.unwrap_err();
    match &err {
        MailError::DomainNotVerified { domain } => {
            assert_eq!(domain, "send.factory0.ventures");
        }
        other => panic!("wrong error: {other}"),
    }
    assert!(!err.to_string().contains(DUMMY_KEY));
}

#[pollster::test]
async fn forbidden_without_domain_maps_to_unauthorized() {
    let (http, _rx) = fixture(403, r#"{"message":"restricted action"}"#, None);
    let err = adapter(http).send(message()).await.unwrap_err();
    assert!(matches!(err, MailError::Unauthorized));
}

#[pollster::test]
async fn unprocessable_maps_to_invalid_with_detail() {
    let (http, _rx) = fixture(422, r#"{"message":"invalid to address"}"#, None);
    let err = adapter(http).send(message()).await.unwrap_err();
    match err {
        MailError::Invalid { detail } => assert_eq!(detail, "invalid to address"),
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn rate_limited_maps_with_retry_after() {
    let (http, _rx) = fixture(429, r#"{"message":"rate limit"}"#, Some("5"));
    let err = adapter(http).send(message()).await.unwrap_err();
    match err {
        MailError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(Duration::from_secs(5)));
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn rate_limited_without_header_has_none() {
    let (http, _rx) = fixture(429, r#"{"message":"rate limit"}"#, None);
    let err = adapter(http).send(message()).await.unwrap_err();
    match err {
        MailError::RateLimited { retry_after } => assert!(retry_after.is_none()),
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn server_error_maps_to_upstream() {
    let (http, _rx) = fixture(500, "boom", None);
    let err = adapter(http).send(message()).await.unwrap_err();
    assert!(matches!(err, MailError::Upstream(_)));
}

#[pollster::test]
async fn transport_error_maps_to_transport() {
    let (tx, _rx) = mpsc::channel();
    let http = Arc::new(FailingHttp { tx });
    let err = Resend::new(http, Some(DUMMY_KEY.into()), "from@x.dev", None)
        .send(message())
        .await
        .unwrap_err();
    match err {
        MailError::Transport(_) => {}
        other => panic!("wrong error: {other}"),
    }
    assert!(!err.to_string().contains(DUMMY_KEY));
}

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

#[pollster::test]
async fn not_configured_short_circuits_without_network() {
    let (http, _rx) = fixture(200, "{}", None);
    let resend = Resend::new(http.clone(), None, "from@x.dev", None);
    let outcome = resend.send(message()).await.expect("ok");
    assert_eq!(outcome, SendOutcome::NotConfigured);
    assert_eq!(
        http.calls.load(Ordering::SeqCst),
        0,
        "no network call when the key is absent"
    );
}

#[pollster::test]
async fn message_from_overrides_adapter_default() {
    let (http, rx) = fixture(200, r#"{"id":"e1"}"#, None);
    let mut msg = message();
    msg.from = "Override <custom@x.dev>".to_string();
    msg.reply_to = Some("reply@x.dev".to_string());
    adapter(http).send(msg).await.expect("ok");
    let captured = rx.try_recv().expect("captured");
    let body: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["from"], "Override <custom@x.dev>");
    assert_eq!(body["reply_to"], "reply@x.dev");
}

#[pollster::test]
async fn every_error_display_omits_the_key() {
    let variants = [
        (401u16, r#"{"message":"bad key"}"#),
        (403, r#"{"message":"Domain send.x.dev is not verified"}"#),
        (422, r#"{"message":"nope"}"#),
        (429, r#"{"message":"slow"}"#),
        (500, "oops"),
        (418, r#"{"message":"teapot"}"#),
    ];
    for (status, body) in variants {
        let (http, _rx) = fixture(status, body, None);
        let err = adapter(http).send(message()).await.expect_err("must fail");
        let rendered = err.to_string();
        assert!(
            !rendered.contains(DUMMY_KEY),
            "status {status} leaked the key: {rendered}"
        );
    }
}
