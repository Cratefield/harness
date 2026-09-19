//! Anthropic adapter acceptance tests (issue #430): request shape, every
//! row of the error-mapping table, JSON-schema output, the port's response
//! cap enforced for real through `BoundedHttpClient`, the `NotConfigured`
//! short-circuit, and the API key never appearing in any error rendering
//! or log line.

// Test-side recording fixture, not request state — the same category
// and allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_anthropic::Anthropic;
use cratefield_core::{
    BoundedHttpClient, Clock, HttpClient, HttpError, MAX_RESPONSE_BYTES, ModelTier, Prompt,
    TextModel, TextModelError,
};
use cratefield_testing::FakeHttpClient;
use http::{HeaderMap, Request, Response, StatusCode};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

// Obvious dummy key, never real.
const DUMMY_KEY: &str = "sk-ant-dummy-key-000000000000";

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

/// Captures headers, which `cratefield_testing::FakeHttpClient` does not.
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

/// A scripted fake behind `BoundedHttpClient`, the way every runtime wires
/// the port — so the port's own caps are in force, not bypassed.
fn scripted(responses: Vec<Result<Response<Bytes>, HttpError>>) -> Anthropic {
    let http: Arc<dyn HttpClient> = Arc::new(BoundedHttpClient::new(
        Arc::new(FakeHttpClient::scripted(responses)),
        clock_at(0),
    ));
    Anthropic::new(
        http,
        clock_at(0),
        Some(DUMMY_KEY.to_string()),
        "claude-opus-5",
    )
}

fn adapter(http: Arc<FakeHttp>) -> Anthropic {
    Anthropic::new(
        http,
        clock_at(0),
        Some(DUMMY_KEY.to_string()),
        "claude-opus-5",
    )
}

fn prompt() -> Prompt {
    // `Fast` because these tests assert on transport behaviour, not on
    // which model a tier picks; the adapter maps the tier to its own id.
    Prompt::new(ModelTier::Fast)
        .user("Say hello")
        .max_tokens(256)
}

/// A real 200 shape: two text blocks (they must join), model and usage.
const SUCCESS_BODY: &str = r#"{
    "id": "msg_01",
    "type": "message",
    "role": "assistant",
    "model": "claude-opus-5",
    "content": [
        {"type": "text", "text": "Hello, "},
        {"type": "text", "text": "world."}
    ],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 12, "output_tokens": 34}
}"#;

#[pollster::test]
async fn request_shape_method_uri_headers_and_body() {
    let (http, rx) = fixture(200, SUCCESS_BODY, None);
    let completion = adapter(http)
        .complete(&prompt().system("be brief"))
        .await
        .expect("completes");
    assert_eq!(completion.text, "Hello, world.");

    let captured = rx.try_recv().expect("one request");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.uri, "https://api.anthropic.com/v1/messages");
    assert_eq!(captured.headers.get("x-api-key").unwrap(), DUMMY_KEY);
    assert_eq!(
        captured.headers.get("anthropic-version").unwrap(),
        "2023-06-01"
    );
    assert_eq!(
        captured.headers.get("content-type").unwrap(),
        "application/json"
    );

    let body: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["model"], "claude-opus-5");
    assert_eq!(body["max_tokens"], 256);
    assert_eq!(body["system"], "be brief");
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "Say hello");
    // No schema requested: no tools, no tool_choice — not even empty ones.
    assert!(body.get("tools").is_none(), "{body}");
    assert!(body.get("tool_choice").is_none(), "{body}");
}

#[pollster::test]
async fn success_maps_to_completion_with_text_model_and_usage() {
    let (http, _rx) = fixture(200, SUCCESS_BODY, None);
    let completion = adapter(http).complete(&prompt()).await.expect("completes");
    assert_eq!(completion.text, "Hello, world.");
    assert_eq!(completion.model, "claude-opus-5");
    assert_eq!(completion.input_tokens, 12);
    assert_eq!(completion.output_tokens, 34);
    assert_eq!(completion.json, None);
}

#[pollster::test]
async fn a_truncated_text_completion_still_succeeds() {
    // No schema was asked for, so `max_tokens` cutting the answer short
    // leaves half a prose answer — still an answer, and the caller gets it
    // rather than an error.
    let body = r#"{
        "id": "msg_03",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "content": [{"type": "text", "text": "Hel"}],
        "stop_reason": "max_tokens",
        "usage": {"input_tokens": 9, "output_tokens": 1}
    }"#;
    let (http, _rx) = fixture(200, body, None);
    let completion = adapter(http).complete(&prompt()).await.expect("completes");
    assert_eq!(completion.text, "Hel");
    assert_eq!(completion.json, None);
}

#[pollster::test]
async fn json_schema_sends_a_forced_tool_and_returns_its_input() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"summary": {"type": "string"}},
        "required": ["summary"]
    });
    let body = r#"{
        "id": "msg_02",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "content": [
            {"type": "tool_use", "id": "toolu_01", "name": "respond", "input": {"summary": "hi"}}
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 9, "output_tokens": 4}
    }"#;
    let (http, rx) = fixture(200, body, None);
    let prompt = prompt().json_schema(schema.clone());
    let completion = adapter(http).complete(&prompt).await.expect("completes");
    assert_eq!(completion.json, Some(serde_json::json!({"summary": "hi"})));

    let captured = rx.try_recv().expect("one request");
    let sent: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(sent["tools"][0]["name"], "respond");
    assert_eq!(sent["tools"][0]["input_schema"], schema);
    assert_eq!(sent["tool_choice"]["type"], "tool");
    assert_eq!(sent["tool_choice"]["name"], "respond");
}

// --- The error table ---------------------------------------------------

#[pollster::test]
async fn rate_limited_reads_retry_after_delta_seconds() {
    let (http, _rx) = fixture(
        429,
        r#"{"type":"error","error":{"type":"rate_limit_error","message":"Number of requests too high"}}"#,
        Some("5"),
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Transient { retry_after } => {
            assert_eq!(retry_after, Some(Duration::from_secs(5)));
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn rate_limited_reads_the_http_date_form() {
    // A CDN in front of the API answers with a date: one hour from the
    // adapter's clock, not an immediate retry. The clock the adapter was
    // constructed with is what makes the delta deterministic.
    let at = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid timestamp");
    let date = http_date(at + time::Duration::seconds(3600));
    let (http, _rx) = fixture(
        429,
        r#"{"error":{"type":"rate_limit_error","message":"slow"}}"#,
        Some(&date),
    );
    let model = Anthropic::new(
        http,
        clock_at(1_800_000_000),
        Some(DUMMY_KEY.to_string()),
        "claude-opus-5",
    );
    let err = model.complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Transient { retry_after } => {
            assert_eq!(retry_after, Some(Duration::from_secs(3600)));
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn rate_limited_without_header_has_none() {
    let (http, _rx) = fixture(429, r#"{"error":{"message":"rate limit"}}"#, None);
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Transient { retry_after } => assert!(retry_after.is_none()),
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn server_error_maps_to_transient() {
    let (http, _rx) = fixture(
        500,
        r#"{"type":"error","error":{"type":"api_error","message":"internal"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Transient { retry_after } => assert_eq!(retry_after, None),
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn overloaded_529_maps_to_transient() {
    // 529 `overloaded_error` is Anthropic's own "come back later"; it is a
    // 5xx, so it lands in the same arm without a special case.
    let (http, _rx) = fixture(
        529,
        r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    assert!(
        matches!(err, TextModelError::Transient { retry_after: None }),
        "got {err}"
    );
}

#[pollster::test]
async fn bad_request_maps_to_rejected_with_the_provider_message() {
    let (http, _rx) = fixture(
        400,
        r#"{"type":"error","error":{"type":"invalid_request_error","message":"messages: roles must alternate"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => {
            assert_eq!(detail, "messages: roles must alternate");
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn unprocessable_maps_to_rejected_with_the_provider_message() {
    let (http, _rx) = fixture(
        422,
        r#"{"type":"error","error":{"type":"invalid_request_error","message":"content was filtered"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => assert_eq!(detail, "content was filtered"),
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn unauthorized_maps_to_rejected() {
    // A bad key is a configuration mistake, not a transient condition:
    // retrying with the same key burns the rate budget and fails again.
    let (http, _rx) = fixture(
        401,
        r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => assert_eq!(detail, "invalid x-api-key"),
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn forbidden_maps_to_rejected() {
    let (http, _rx) = fixture(
        403,
        r#"{"type":"error","error":{"type":"permission_error","message":"not allowed for this key"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => assert_eq!(detail, "not allowed for this key"),
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn any_other_client_error_maps_to_rejected() {
    // 404: the model is not available to this org — the prompt's fault in
    // the only sense that matters: retrying unchanged fails the same way.
    let (http, _rx) = fixture(
        404,
        r#"{"type":"error","error":{"type":"not_found_error","message":"model: claude-nope"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => assert_eq!(detail, "model: claude-nope"),
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn anything_unexpected_maps_to_transport() {
    // A redirect never became a response: the call did not complete.
    let (http, _rx) = fixture(302, "<html>see other</html>", None);
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Transport(message) => {
            assert!(message.contains("302"), "{message}");
        }
        other => panic!("wrong error: {other}"),
    }
}

// --- Transport-layer failures ------------------------------------------

#[pollster::test]
async fn deadline_exceeded_maps_to_transport() {
    let model = scripted(vec![Err(HttpError::DeadlineExceeded {
        after: Duration::from_secs(30),
    })]);
    let err = model.complete(&prompt()).await.unwrap_err();
    assert!(matches!(err, TextModelError::Transport(_)), "got {err}");
    assert!(!err.to_string().contains(DUMMY_KEY));
}

#[pollster::test]
async fn connect_failure_maps_to_transport() {
    let model = scripted(vec![Err(HttpError::Transport("dns is down".to_owned()))]);
    let err = model.complete(&prompt()).await.unwrap_err();
    assert!(matches!(err, TextModelError::Transport(_)), "got {err}");
}

#[pollster::test]
async fn scripted_response_too_large_maps_to_transport() {
    let model = scripted(vec![Err(HttpError::ResponseTooLarge {
        limit: MAX_RESPONSE_BYTES,
    })]);
    let err = model.complete(&prompt()).await.unwrap_err();
    assert!(matches!(err, TextModelError::Transport(_)), "got {err}");
}

#[pollster::test]
async fn a_response_body_over_the_port_cap_is_refused_as_transport() {
    // The cap proven for real, not scripted: the adapter asks for the
    // port's own ceiling, so `BoundedHttpClient` — which every runtime
    // wires the port through — refuses a body one byte past it, and the
    // adapter never sees a response at all.
    let oversized = Bytes::from(vec![b'x'; MAX_RESPONSE_BYTES + 1]);
    let model = scripted(vec![Ok(Response::builder()
        .status(200)
        .body(oversized)
        .expect("response"))]);
    let err = model.complete(&prompt()).await.unwrap_err();
    assert!(matches!(err, TextModelError::Transport(_)), "got {err}");
}

#[pollster::test]
async fn a_declared_length_over_the_cap_is_refused_before_the_body_is_read() {
    // The port checks the declared `Content-Length` first, so a hostile
    // length is refused without the allocation it claims (issue #136).
    let response = Response::builder()
        .status(200)
        .header(http::header::CONTENT_LENGTH, "99999999")
        .body(Bytes::from_static(b"tiny"))
        .expect("response");
    let model = scripted(vec![Ok(response)]);
    let err = model.complete(&prompt()).await.unwrap_err();
    assert!(matches!(err, TextModelError::Transport(_)), "got {err}");
}

#[pollster::test]
async fn an_unparseable_success_body_maps_to_transport() {
    // Not `Rejected`: nothing about the prompt was refused — the answer
    // just never arrived in usable form.
    let (http, _rx) = fixture(200, "<html>gateway error</html>", None);
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    assert!(
        matches!(&err, TextModelError::Transport(message) if message.contains("did not parse")),
        "got {err}"
    );
}

#[pollster::test]
async fn a_forced_json_call_without_a_tool_block_maps_to_transport() {
    // Forced tool use was the whole point of the call; a text-only answer
    // means the JSON path broke between provider and here.
    let (http, _rx) = fixture(200, SUCCESS_BODY, None);
    let prompt = prompt().json_schema(serde_json::json!({"type": "object"}));
    let err = adapter(http).complete(&prompt).await.unwrap_err();
    match err {
        TextModelError::Transport(message) => {
            assert!(message.contains("tool_use block"), "{message}");
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn a_truncated_forced_json_call_is_rejected() {
    // `max_tokens` cut the forced tool call off before `input` became a
    // schema-shaped value (a JSON `null` parses to `Value::Null` here);
    // handing that back as a success would fail the caller's schema check
    // downstream. `Rejected`, because retrying unchanged truncates again.
    let body = r#"{
        "id": "msg_04",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "content": [
            {"type": "tool_use", "id": "toolu_01", "name": "respond", "input": null}
        ],
        "stop_reason": "max_tokens",
        "usage": {"input_tokens": 9, "output_tokens": 4}
    }"#;
    let (http, _rx) = fixture(200, body, None);
    let prompt = prompt().json_schema(serde_json::json!({"type": "object"}));
    let err = adapter(http).complete(&prompt).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => {
            assert!(detail.contains("max_tokens"), "{detail}");
            assert!(detail.contains("truncated"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
}

// --- Configuration and leakage ------------------------------------------

#[pollster::test]
async fn not_configured_fails_before_any_network_call() {
    let http = Arc::new(FakeHttpClient::scripted(vec![]));
    let model = Anthropic::new(http.clone(), clock_at(0), None, "claude-opus-5");
    let err = model.complete(&prompt()).await.unwrap_err();
    assert!(matches!(err, TextModelError::NotConfigured));
    assert!(
        http.captured().is_empty(),
        "no network call when the key is absent"
    );
}

#[pollster::test]
async fn every_error_display_and_debug_omit_the_key() {
    let variants = [
        (401u16, r#"{"error":{"message":"invalid x-api-key"}}"#),
        (403, r#"{"error":{"message":"not allowed"}}"#),
        (400, r#"{"error":{"message":"bad prompt"}}"#),
        (422, r#"{"error":{"message":"filtered"}}"#),
        (429, r#"{"error":{"message":"slow down"}}"#),
        (500, r#"{"error":{"message":"boom"}}"#),
        (418, r#"{"error":{"message":"teapot"}}"#),
        (302, "<html>see other</html>"),
    ];
    for (status, body) in variants {
        let (http, _rx) = fixture(status, body, None);
        let err = adapter(http)
            .complete(&prompt())
            .await
            .expect_err("must fail");
        let rendered = err.to_string();
        // An empty rendering would omit the key and everything else; the
        // display has to stay useful for its absence to mean anything.
        assert!(
            rendered.len() > 8,
            "status {status} rendered an error that says nothing: {rendered:?}"
        );
        assert!(
            !rendered.contains(DUMMY_KEY),
            "status {status} leaked the key: {rendered}"
        );
        // `Debug` shows the raw wrapped text; the key must not be there
        // either.
        let debug = format!("{err:?}");
        assert!(
            !debug.contains(DUMMY_KEY),
            "status {status} leaked the key in Debug: {debug}"
        );
    }
}

#[pollster::test]
async fn a_provider_message_that_echoes_secrets_is_scrubbed() {
    // The provider's message can quote back whatever the request carried;
    // `Display` routes it through the core scrubber, so an address is
    // hashed and a query string redacted before anyone logs it.
    let body = r#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt rejected for alice@example.test: see https://x.test/rules?ref=live-abcdef"}}"#;
    let (http, _rx) = fixture(400, body, None);
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    let rendered = err.to_string();
    assert!(!rendered.contains('@'), "{rendered}");
    assert!(!rendered.contains("alice"), "{rendered}");
    assert!(!rendered.contains("live-abcdef"), "{rendered}");
    assert!(rendered.contains("[subject_hash:"), "{rendered}");
}

// --- Log-line leakage ----------------------------------------------------

/// Captures each event's fields as one raw `name=value` line. Deliberately
/// *not* core's `RedactingVisitor`: the assertion is about what the adapter
/// emits, so no redaction may stand between the event and the test.
#[derive(Default)]
struct LogCapture {
    lines: Mutex<Vec<String>>,
}

/// Renders one event's fields; every record kind defaults to
/// `record_debug`, so this is the only method the line needs.
#[derive(Default)]
struct RawLine(String);

impl tracing::field::Visit for RawLine {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        let _ = write!(self.0, "{}={value:?}", field.name());
    }
}

impl Subscriber for LogCapture {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _id: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _follows: &Id, _to: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut line = RawLine::default();
        event.record(&mut line);
        self.lines.lock().expect("log lock").push(line.0);
    }

    fn enter(&self, _id: &Id) {}

    fn exit(&self, _id: &Id) {}
}

/// The global dispatch needs a `Send + Sync` subscriber it owns; forward
/// to the shared capture so the test can read the lines afterwards.
#[derive(Clone)]
struct SharedCapture(Arc<LogCapture>);

impl Subscriber for SharedCapture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.0.enabled(metadata)
    }
    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        self.0.new_span(attributes)
    }
    fn record(&self, id: &Id, values: &Record<'_>) {
        self.0.record(id, values);
    }
    fn record_follows_from(&self, follows: &Id, to: &Id) {
        self.0.record_follows_from(follows, to);
    }
    fn event(&self, event: &Event<'_>) {
        self.0.event(event);
    }
    fn enter(&self, id: &Id) {
        self.0.enter(id);
    }
    fn exit(&self, id: &Id) {
        self.0.exit(id);
    }
}

#[pollster::test]
async fn no_log_line_carries_the_key_prompt_or_completion() {
    let capture = Arc::new(LogCapture::default());
    // Global, not thread-scoped `with_default`: every other test here also
    // fires the adapter's event callsites, with no subscriber in sight, and
    // a callsite registered `never` against that no-dispatch default stays
    // silent for the whole process — whichever thread fires it first after
    // any cache reset re-registers the same way. The global dispatch is the
    // one registration every thread agrees on (the reason core's
    // `sidecar_events` capture is global too); nothing else in this binary
    // claims it, and extra lines from concurrent tests only make the leak
    // assertions below scan more, not less.
    tracing::subscriber::set_global_default(SharedCapture(Arc::clone(&capture)))
        .expect("no other global subscriber in this test binary");
    // Callsites other tests already fired carry a stale `never` interest;
    // re-register them against the dispatch just installed.
    tracing::callsite::rebuild_interest_cache();

    let (http, _rx) = fixture(200, SUCCESS_BODY, None);
    let _ = adapter(http).complete(&prompt()).await;
    let (http, _rx) = fixture(
        401,
        r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
        None,
    );
    let _ = adapter(http).complete(&prompt()).await;
    let unconfigured = Anthropic::new(
        Arc::new(FakeHttpClient::scripted(vec![])),
        clock_at(0),
        None,
        "claude-opus-5",
    );
    let _ = unconfigured.complete(&prompt()).await;

    let lines = capture.lines.lock().expect("log lock").clone();
    // All three paths really were captured; a silent subscriber would make
    // the leak assertions below vacuous. String fields render quoted.
    assert!(
        lines.iter().any(|l| l.contains("outcome=\"completed\"")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("outcome=\"failed\"")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("outcome=\"not_configured\"")),
        "{lines:?}"
    );
    for line in &lines {
        assert!(!line.contains(DUMMY_KEY), "key leaked: {line}");
        assert!(!line.contains("Say hello"), "prompt leaked: {line}");
        assert!(!line.contains("Hello, world."), "completion leaked: {line}");
    }
}
