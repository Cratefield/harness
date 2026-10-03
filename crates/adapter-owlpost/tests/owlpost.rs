//! Owlpost adapter acceptance tests (issue #591): success and the recorded
//! request (headers, tags, idempotency), error mapping, the `NotConfigured`
//! short-circuit, the API key never appearing in any `Debug`/`Display`
//! string, and the recorded body against the schema fixture.

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_owlpost::{
    DEFAULT_BASE_URL, MAX_BATCH, Owlpost, OwlpostError, SendOptions, Stream,
};
use cratefield_core::{Clock, HttpClient, HttpError, MailError, Mailer, Message, SendOutcome};
use http::{HeaderMap, Request, Response, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// Obvious dummy key, never real.
const DUMMY_KEY: &str = "op_test_dummy_key_000000000000";

/// The committed request schema. See its `$comment` for provenance.
const REQUEST_SCHEMA: &str = include_str!("fixtures/owlpost-send-email-request.schema.json");

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

struct FakeHttp {
    status: u16,
    body: &'static str,
    retry_after: Option<String>,
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
        if let Some(retry) = &self.retry_after {
            builder = builder.header("retry-after", retry.as_str());
        }
        builder
            .body(Bytes::from(self.body))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

struct FailingHttp {
    tx: mpsc::Sender<CapturedRequest>,
    message: String,
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
        Err(HttpError::Transport(self.message.clone()))
    }
}

fn fixture(
    status: u16,
    body: &'static str,
    retry_after: Option<&str>,
) -> (Arc<FakeHttp>, mpsc::Receiver<CapturedRequest>) {
    let (tx, rx) = mpsc::channel();
    (
        Arc::new(FakeHttp {
            status,
            body,
            retry_after: retry_after.map(str::to_owned),
            calls: AtomicUsize::new(0),
            tx,
        }),
        rx,
    )
}

fn message() -> Message {
    Message::new("nick@example.com", "", "Confirm", "hi", "<p>hi</p>")
        .idempotency_key("idem-123")
        .tags(["transactional"])
}

fn adapter(http: Arc<FakeHttp>) -> Owlpost {
    Owlpost::new(
        http,
        clock_at(0),
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
    assert_eq!(captured.uri, format!("{DEFAULT_BASE_URL}/v1/emails"));
    assert_eq!(
        captured.headers.get("authorization").unwrap(),
        format!("Bearer {DUMMY_KEY}").as_str()
    );
    assert_eq!(captured.headers.get("idempotency-key").unwrap(), "idem-123");
    assert_eq!(
        captured.headers.get("content-type").unwrap(),
        "application/json"
    );

    let body: Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["from"], "Factory Zero <no-reply@test.factory0.dev>");
    assert_eq!(body["to"], "nick@example.com");
    assert_eq!(body["html"], "<p>hi</p>");
    assert_eq!(body["text"], "hi");
    assert_eq!(body["subject"], "Confirm");
    // Resend-compatible tags: `{ name, value }` objects, sanitised.
    assert_eq!(body["tags"][0]["name"], "transactional");
    assert_eq!(body["tags"][0]["value"], "1");
}

#[pollster::test]
async fn custom_headers_reach_the_provider_in_order() {
    // RFC 8058 one-click unsubscribe is why `Message::headers` exists; an
    // adapter that accepted the field and dropped it would look like one
    // that works, and only Gmail would notice. The names must also arrive in
    // the caller's order — a sorted map would flip Z/A and unpair the
    // List-Unsubscribe pair.
    let (http, rx) = fixture(200, r#"{"id":"x"}"#, None);
    let msg = message()
        // Deliberately reverse-alphabetical, so a sorted map would flip it.
        .header("Z-Custom", "z")
        .header("A-Custom", "a")
        .header("List-Unsubscribe", "<https://test.example/u?token=abc>")
        .header("List-Unsubscribe-Post", "List-Unsubscribe=One-Click");
    adapter(http).send(msg).await.expect("send ok");
    let captured = rx.try_recv().expect("one request");
    let body: Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(
        body["headers"]["List-Unsubscribe"],
        "<https://test.example/u?token=abc>"
    );
    assert_eq!(
        body["headers"]["List-Unsubscribe-Post"],
        "List-Unsubscribe=One-Click"
    );

    // On the raw body bytes: the caller's insertion order, not a sort.
    let at = |needle: &str| {
        captured
            .body
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not serialised: {}", captured.body))
    };
    assert!(
        at("\"Z-Custom\":") < at("\"A-Custom\":"),
        "headers were sorted, not kept in order: {}",
        captured.body
    );
    assert!(
        at("\"List-Unsubscribe\":") < at("\"List-Unsubscribe-Post\":"),
        "List-Unsubscribe pair reordered: {}",
        captured.body
    );
}

#[pollster::test]
async fn a_message_with_no_headers_sends_no_headers_field() {
    // Not `"headers": {}` — an empty object is a claim about headers, and
    // the provider has no reason to see one.
    let (http, rx) = fixture(200, r#"{"id":"x"}"#, None);
    adapter(http).send(message()).await.expect("send ok");
    let captured = rx.try_recv().expect("one request");
    let body: Value = serde_json::from_str(&captured.body).unwrap();
    assert!(body.get("headers").is_none(), "{body}");
}

#[pollster::test]
async fn message_from_overrides_adapter_default() {
    let (http, rx) = fixture(200, r#"{"id":"e1"}"#, None);
    let mut msg = message();
    msg.from = "Override <custom@x.dev>".to_string();
    msg.reply_to = Some("reply@x.dev".to_string());
    adapter(http).send(msg).await.expect("ok");
    let captured = rx.try_recv().expect("captured");
    let body: Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["from"], "Override <custom@x.dev>");
    assert_eq!(body["reply_to"], "reply@x.dev");
}

#[pollster::test]
async fn custom_base_url_is_used() {
    let (http, rx) = fixture(200, r#"{"id":"x"}"#, None);
    let adapter = Owlpost::new(
        http,
        clock_at(0),
        Some(DUMMY_KEY.into()),
        "from@x.dev",
        None,
    )
    .with_base_url("http://owlpost.fake/");
    adapter.send(message()).await.expect("ok");
    let captured = rx.try_recv().expect("captured");
    // One trailing slash is trimmed, not doubled.
    assert_eq!(captured.uri, "http://owlpost.fake/v1/emails");
}

/// One send against a stored status/body, returning the mapped error.
async fn error_for(status: u16, body: &'static str, retry_after: Option<&str>) -> MailError {
    let (http, _rx) = fixture(status, body, retry_after);
    adapter(http).send(message()).await.expect_err("must fail")
}

#[pollster::test]
async fn statuses_map_to_their_mail_error_variant() {
    // (status, problem body, Retry-After, expected). One row per acceptance
    // criterion and per branch of `map_status`.
    let cases: &[(u16, &str, Option<&str>, MailError)] = &[
        (
            400,
            r#"{"type":"about:blank","title":"Bad Request","status":400,"detail":"`to` is required"}"#,
            None,
            MailError::Invalid {
                detail: "Bad Request: `to` is required".into(),
            },
        ),
        (
            401,
            r#"{"title":"Unauthorized","status":401,"detail":"invalid api key"}"#,
            None,
            MailError::Unauthorized,
        ),
        (
            403,
            r#"{"title":"Forbidden","status":403,"detail":"Domain send.factory0.ventures is not verified"}"#,
            None,
            MailError::DomainNotVerified {
                domain: "send.factory0.ventures".into(),
            },
        ),
        (
            403,
            r#"{"title":"Forbidden","status":403,"detail":"restricted action"}"#,
            None,
            MailError::Unauthorized,
        ),
        (
            422,
            r#"{"title":"Unprocessable Entity","status":422,"detail":"invalid to address"}"#,
            None,
            MailError::Invalid {
                detail: "Unprocessable Entity: invalid to address".into(),
            },
        ),
        (
            429,
            r#"{"title":"Too Many Requests","status":429,"detail":"slow down"}"#,
            Some("5"),
            MailError::RateLimited {
                retry_after: Some(Duration::from_secs(5)),
            },
        ),
        (
            429,
            r#"{"title":"Too Many Requests","status":429}"#,
            None,
            MailError::RateLimited { retry_after: None },
        ),
        (
            503,
            r#"{"title":"Service Unavailable","status":503,"detail":"try later"}"#,
            Some("30"),
            MailError::Upstream("Service Unavailable: try later (retry after 30s)".into()),
        ),
        (500, "boom", None, MailError::Upstream("boom".into())),
    ];
    for (status, body, retry_after, expected) in cases {
        let err = error_for(*status, body, *retry_after).await;
        assert_eq!(&err, expected, "status {status}");
        // The API key never reaches a rendered or debugged error.
        assert!(
            !err.to_string().contains(DUMMY_KEY),
            "status {status}: {err}"
        );
        assert!(
            !format!("{err:?}").contains(DUMMY_KEY),
            "status {status} leaked in Debug"
        );
    }
}

#[pollster::test]
async fn transport_error_maps_to_transport() {
    let (tx, _rx) = mpsc::channel();
    let err = Owlpost::new(
        Arc::new(FailingHttp {
            tx,
            message: "dns is down".to_owned(),
        }),
        clock_at(0),
        Some(DUMMY_KEY.into()),
        "from@x.dev",
        None,
    )
    .send(message())
    .await
    .unwrap_err();
    assert!(matches!(err, MailError::Transport(_)), "{err:?}");
    assert!(!err.to_string().contains(DUMMY_KEY));
}

#[pollster::test]
async fn a_blank_or_absent_key_is_not_configured_without_network() {
    // Empty and whitespace-only both read as "no key", like an unset one:
    // `Bearer ` is not a credential, and the provider must not be called.
    for key in [None, Some(String::new()), Some("   ".to_owned())] {
        let (http, _rx) = fixture(200, "{}", None);
        let owlpost = Owlpost::new(http.clone(), clock_at(0), key, "from@x.dev", None);
        let outcome = owlpost.send(message()).await.expect("ok");
        assert_eq!(outcome, SendOutcome::NotConfigured);
        assert_eq!(
            http.calls.load(Ordering::SeqCst),
            0,
            "no network call when the key is blank or absent"
        );
    }
}

#[test]
fn debug_never_prints_the_key() {
    let (http, _rx) = fixture(200, "{}", None);
    let debug = format!("{:?}", adapter(http));
    assert!(!debug.contains(DUMMY_KEY), "{debug}");
    assert!(debug.contains("api_key_configured: true"), "{debug}");
    assert!(debug.contains(DEFAULT_BASE_URL), "{debug}");

    let (http, _rx) = fixture(200, "{}", None);
    let unconfigured = Owlpost::new(http, clock_at(0), None, "from@x.dev", None);
    assert!(
        format!("{unconfigured:?}").contains("api_key_configured: false"),
        "a blank key must not read as configured"
    );
}

// --- Contract test: the recorded request against the schema fixture. -----

fn type_matches(value: &Value, ty: &str) -> bool {
    match ty {
        "string" => value.is_string(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        other => panic!("schema names a type this check does not know: {other}"),
    }
}

/// A hand-rolled subset of JSON Schema — `type`, `properties`, `required`,
/// `additionalProperties`, `items` — enough for this one fixture and no
/// dependency. A member is checked against its named property's schema, else
/// against `additionalProperties` (which for `headers` is the value type).
fn assert_conforms(value: &Value, schema: &Value, path: &str) {
    if let Some(ty) = schema["type"].as_str() {
        assert!(type_matches(value, ty), "{path}: {value} is not {ty}");
    }
    match value {
        Value::Object(obj) => {
            let properties = schema["properties"].as_object();
            for (key, child) in obj {
                let child_schema = properties
                    .and_then(|props| props.get(key))
                    .unwrap_or(&schema["additionalProperties"]);
                assert!(
                    *child_schema != Value::Bool(false),
                    "{path}: adapter sent a field the schema does not list: {key}"
                );
                assert_conforms(child, child_schema, &format!("{path}.{key}"));
            }
            for required in schema["required"].as_array().into_iter().flatten() {
                let name = required.as_str().expect("required entries are strings");
                assert!(
                    obj.contains_key(name),
                    "{path}: required field missing from the request: {name}"
                );
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                assert_conforms(child, &schema["items"], &format!("{path}[{i}]"));
            }
        }
        _ => {}
    }
}

#[pollster::test]
async fn recorded_requests_conform_to_the_schema_fixture() {
    let schema: Value =
        serde_json::from_str(REQUEST_SCHEMA).expect("the committed schema is valid JSON");

    // A maximal message: every optional field set, both headers, two tags.
    let (http, rx) = fixture(200, r#"{"id":"contract"}"#, None);
    let msg = Message::new(
        "to@example.com",
        "From <from@example.com>",
        "Subject",
        "text",
        "<p>html</p>",
    )
    .reply_to("reply@example.com")
    .idempotency_key("idem-contract")
    .tags(["transactional", "waitlist"])
    .header("List-Unsubscribe", "<https://example.com/u?t=1>")
    .header("List-Unsubscribe-Post", "List-Unsubscribe=One-Click");
    adapter(http).send(msg).await.expect("send ok");
    let body: Value =
        serde_json::from_str(&rx.try_recv().expect("one request").body).expect("recorded body");
    assert_conforms(&body, &schema, "request");
    // The optional fields this message set are present, not dropped.
    assert!(body.get("reply_to").is_some());
    assert!(body.get("headers").is_some());
    assert!(body.get("tags").is_some());

    // A minimal message: exactly the `required` set, nothing optional leaks.
    let (http, rx) = fixture(200, r#"{"id":"contract"}"#, None);
    adapter(http).send(message()).await.expect("send ok");
    let body: Value =
        serde_json::from_str(&rx.try_recv().expect("one request").body).expect("recorded body");
    assert_conforms(&body, &schema, "request");
    assert!(body.get("reply_to").is_none(), "{body}");
}

// --- Beyond the Mailer port: send_with, batch, get_email. -----------------

/// A broadcast with a topic and every addressing field set. `SendOptions` is
/// `#[non_exhaustive]`, so fields are set on a `Default`, not a literal.
fn broadcast_options() -> SendOptions {
    let mut options = SendOptions::default();
    options.stream = Some(Stream::Broadcast);
    options.topic = Some("launch".to_owned());
    options.cc = vec!["a@example.com".to_owned(), "b@example.com".to_owned()];
    options.bcc = vec!["c@example.com".to_owned()];
    options.scheduled_at = Some("2026-10-04T09:00:00Z".to_owned());
    options
}

#[pollster::test]
async fn send_with_records_broadcast_options_in_the_body() {
    let (http, rx) = fixture(200, r#"{"id":"bc-1"}"#, None);
    let outcome = adapter(http)
        .send_with(message(), broadcast_options())
        .await
        .expect("send ok");
    assert_eq!(outcome, SendOutcome::Sent { id: "bc-1".into() });

    let body: Value = serde_json::from_str(&rx.try_recv().expect("one request").body).unwrap();
    assert_eq!(body["stream"], "broadcast");
    assert_eq!(body["topic"], "launch");
    assert_eq!(
        body["cc"],
        serde_json::json!(["a@example.com", "b@example.com"])
    );
    assert_eq!(body["bcc"], serde_json::json!(["c@example.com"]));
    assert_eq!(body["scheduled_at"], "2026-10-04T09:00:00Z");
}

#[pollster::test]
async fn a_topic_on_a_transactional_stream_is_refused_locally() {
    let (http, _rx) = fixture(200, "{}", None);
    let mut bad = SendOptions::default();
    bad.stream = Some(Stream::Transactional);
    bad.topic = Some("launch".to_owned());
    let err = adapter(http.clone())
        .send_with(message(), bad.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, MailError::Invalid { .. }), "{err:?}");
    let err = adapter(http.clone())
        .batch(vec![(message(), bad)], None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, OwlpostError::Mail(MailError::Invalid { .. })),
        "{err:?}"
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 0, "refusals are local");
}

#[pollster::test]
async fn local_refusals_precede_the_not_configured_check() {
    // A keyless adapter still refuses a programming error locally, in all
    // three operations: the refusal is not a provider outcome.
    let (http, _rx) = fixture(200, "{}", None);
    let keyless = Owlpost::new(http.clone(), clock_at(0), None, "from@x.dev", None);
    let mut options = SendOptions::default();
    options.stream = Some(Stream::Transactional);
    options.topic = Some("launch".to_owned());
    let err = keyless.send_with(message(), options).await.unwrap_err();
    assert!(matches!(err, MailError::Invalid { .. }), "{err:?}");
    let err = keyless.get_email("../x").await.unwrap_err();
    assert!(
        matches!(err, OwlpostError::Mail(MailError::Invalid { .. })),
        "{err:?}"
    );
    let err = keyless.batch(Vec::new(), None).await.unwrap_err();
    assert!(
        matches!(err, OwlpostError::Mail(MailError::Invalid { .. })),
        "{err:?}"
    );
    assert_eq!(
        http.calls.load(Ordering::SeqCst),
        0,
        "nothing reached the network"
    );
}

#[pollster::test]
async fn batch_posts_an_array_and_returns_the_ids() {
    let (http, rx) = fixture(200, r#"{"data":[{"id":"b-1"},{"id":"b-2"}]}"#, None);
    let ids = adapter(http)
        .batch(
            vec![
                (message(), SendOptions::default()),
                (message(), SendOptions::default()),
            ],
            Some("batch-idem".to_owned()),
        )
        .await
        .expect("batch ok");
    assert_eq!(ids, ["b-1", "b-2"]);

    let captured = rx.try_recv().expect("one request");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.uri, format!("{DEFAULT_BASE_URL}/v1/emails/batch"));
    assert_eq!(
        captured.headers.get("idempotency-key").unwrap(),
        "batch-idem"
    );
    // The body is a JSON array of two per-email objects.
    let body: Value = serde_json::from_str(&captured.body).unwrap();
    let items = body.as_array().expect("a JSON array");
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(Value::is_object));
}

#[pollster::test]
async fn batch_refuses_empty_and_oversized_locally() {
    let (http, _rx) = fixture(200, r#"{"data":[]}"#, None);
    let too_many: Vec<_> = (0..=MAX_BATCH)
        .map(|_| (message(), SendOptions::default()))
        .collect();
    for batch in [Vec::new(), too_many] {
        let err = adapter(http.clone()).batch(batch, None).await.unwrap_err();
        assert!(
            matches!(err, OwlpostError::Mail(MailError::Invalid { .. })),
            "{err:?}"
        );
    }
    assert_eq!(http.calls.load(Ordering::SeqCst), 0, "refusals are local");
}

#[pollster::test]
async fn get_email_reads_one_and_refuses_bad_ids() {
    let (http, rx) = fixture(
        200,
        r#"{"id":"e-1","from":"from@x.dev","to":["to@y.dev"],"subject":"Hi","created_at":"2026-10-01T00:00:00Z","last_event":"delivered"}"#,
        None,
    );
    let email = adapter(http).get_email("e-1").await.expect("get ok");
    assert_eq!(email.id, "e-1");
    assert_eq!(email.to, ["to@y.dev"]);
    assert_eq!(email.last_event.as_deref(), Some("delivered"));

    let captured = rx.try_recv().expect("one request");
    assert_eq!(captured.method, "GET");
    assert_eq!(captured.uri, format!("{DEFAULT_BASE_URL}/v1/emails/e-1"));
    assert!(captured.body.is_empty(), "a GET carries no body");

    // A path-like id never reaches the network.
    let (http, _rx) = fixture(200, "{}", None);
    for id in ["", "../x", "a/b", "e%2f"] {
        let err = adapter(http.clone()).get_email(id).await.unwrap_err();
        assert!(
            matches!(err, OwlpostError::Mail(MailError::Invalid { .. })),
            "{id:?}: {err:?}"
        );
    }
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
}

#[pollster::test]
async fn the_key_never_leaks_in_debug_or_a_provider_echo() {
    // Kept in sync with DUMMY_KEY by asserting the literal names it.
    const ECHO: &str =
        r#"{"title":"Bad Request","detail":"the key op_test_dummy_key_000000000000 is invalid"}"#;
    assert!(ECHO.contains(DUMMY_KEY));

    // A provider echoing the key back must not smuggle it into an error,
    // through either surface.
    let (http, _rx) = fixture(400, ECHO, None);
    let err = adapter(http).get_email("e-1").await.unwrap_err();
    assert!(
        !err.to_string().contains(DUMMY_KEY) && !format!("{err:?}").contains(DUMMY_KEY),
        "{err}"
    );
    assert!(err.to_string().contains("[redacted]"), "{err}");

    // A transport error whose own text names the key is redacted too.
    let (tx, _rx) = mpsc::channel();
    let err = Owlpost::new(
        Arc::new(FailingHttp {
            tx,
            message: format!("connect failed for {DUMMY_KEY}"),
        }),
        clock_at(0),
        Some(DUMMY_KEY.into()),
        "from@x.dev",
        None,
    )
    .send(message())
    .await
    .unwrap_err();
    assert!(
        !err.to_string().contains(DUMMY_KEY) && !format!("{err:?}").contains(DUMMY_KEY),
        "{err:?}"
    );
}
