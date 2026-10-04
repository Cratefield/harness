//! OpenAI-compatible adapter acceptance tests (issue #560): request shape
//! (URL, auth header, body with the leading system message and the
//! `response_format`), the success parse with usage including cached
//! tokens, every row of the error-mapping table that differs from prose,
//! the JSON-schema path, the `NotConfigured` short-circuit, and the API
//! key never appearing in any error rendering.

// Test-side recording fixture, not request state — the same category
// and allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_openai_compatible::{DEFAULT_ENDPOINT, OpenAiCompatible};
use cratefield_core::{
    BoundedHttpClient, Clock, HttpClient, HttpError, ModelTier, Prompt, TextModel, TextModelError,
};
use cratefield_testing::FakeHttpClient;
use http::{HeaderMap, Request, Response, StatusCode};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// Obvious dummy key, never real.
const DUMMY_KEY: &str = "sk-openai-dummy-key-000000000000";

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

fn adapter(http: Arc<FakeHttp>) -> OpenAiCompatible {
    OpenAiCompatible::new(
        http,
        clock_at(0),
        Some(DUMMY_KEY.to_string()),
        "gpt-4o-mini",
    )
}

fn prompt() -> Prompt {
    // `Fast` because these tests assert on transport behaviour, not on
    // which model a tier picks; the adapter maps the tier to its own id.
    Prompt::new(ModelTier::Fast)
        .user("Say hello")
        .max_tokens(256)
}

/// A real 200 shape: one choice, the model that answered, and a usage
/// block with cached-token details.
const SUCCESS_BODY: &str = r#"{
    "id": "chatcmpl_01",
    "object": "chat.completion",
    "model": "gpt-4o-mini-2026-01-15",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "Hello, world."},
            "finish_reason": "stop"
        }
    ],
    "usage": {
        "prompt_tokens": 12,
        "completion_tokens": 34,
        "total_tokens": 46,
        "prompt_tokens_details": {"cached_tokens": 9}
    }
}"#;

#[pollster::test]
async fn request_shape_method_uri_auth_header_and_body() {
    // A custom base URL, with the trailing slash the configuration will
    // one day carry: trimmed, then the wire path appended.
    let (http, rx) = fixture(200, SUCCESS_BODY, None);
    let model = adapter(http).with_base_url("http://127.0.0.1:11434/v1/");
    let completion = model
        .complete(&prompt().system("be brief"))
        .await
        .expect("completes");
    assert_eq!(completion.text, "Hello, world.");

    let captured = rx.try_recv().expect("one request");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.uri, "http://127.0.0.1:11434/v1/chat/completions");
    assert_eq!(
        captured
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .expect("visible ascii"),
        format!("Bearer {DUMMY_KEY}")
    );
    assert_eq!(
        captured.headers.get("content-type").unwrap(),
        "application/json"
    );

    let body: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["model"], "gpt-4o-mini");
    assert_eq!(body["max_tokens"], 256);
    // The system prompt is a leading message on this wire.
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(body["messages"][0]["content"], "be brief");
    assert_eq!(body["messages"][1]["role"], "user");
    assert_eq!(body["messages"][1]["content"], "Say hello");
    // No schema requested: no response_format at all — not an empty one.
    assert!(body.get("response_format").is_none(), "{body}");
}

#[pollster::test]
async fn the_default_endpoint_is_openai_and_a_custom_one_replaces_it() {
    let (http, rx) = fixture(200, SUCCESS_BODY, None);
    adapter(http).complete(&prompt()).await.expect("completes");
    let captured = rx.try_recv().expect("one request");
    assert_eq!(captured.uri, format!("{DEFAULT_ENDPOINT}/chat/completions"));
}

#[pollster::test]
async fn success_maps_to_completion_with_text_model_and_usage() {
    let (http, _rx) = fixture(200, SUCCESS_BODY, None);
    let completion = adapter(http).complete(&prompt()).await.expect("completes");
    assert_eq!(completion.text, "Hello, world.");
    // The model that answered, from the response — not the configured id.
    assert_eq!(completion.model, "gpt-4o-mini-2026-01-15");
    assert_eq!(completion.input_tokens, 12);
    assert_eq!(completion.output_tokens, 34);
    assert_eq!(completion.cached_input_tokens, Some(9));
    assert_eq!(completion.json, None);
}

#[pollster::test]
async fn missing_usage_details_leaves_the_cached_subset_absent() {
    // A server that does no caching (or predates the details block):
    // totals still arrive, the subset stays `None`. No `model` in the
    // answer either, so the configured id stands in.
    let body = r#"{
        "choices": [
            {"message": {"role": "assistant", "content": "Hello."}, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 7, "completion_tokens": 2}
    }"#;
    let (http, _rx) = fixture(200, body, None);
    let completion = adapter(http).complete(&prompt()).await.expect("completes");
    assert_eq!(completion.input_tokens, 7);
    assert_eq!(completion.output_tokens, 2);
    assert_eq!(completion.cached_input_tokens, None);
    assert_eq!(completion.model, "gpt-4o-mini");
}

#[pollster::test]
async fn a_reported_zero_cache_is_a_cache_miss_not_an_absent_report() {
    // The details block present with a zero is the vendor *reporting*
    // caching: `Some(0)`, distinguishable from a vendor that says nothing.
    let body = r#"{
        "model": "m",
        "choices": [{"message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1,
                  "prompt_tokens_details": {"cached_tokens": 0}}
    }"#;
    let (http, _rx) = fixture(200, body, None);
    let completion = adapter(http).complete(&prompt()).await.expect("completes");
    assert_eq!(completion.cached_input_tokens, Some(0));
}

// --- The JSON-schema path ----------------------------------------------

#[pollster::test]
async fn json_schema_sends_a_response_format_and_parses_the_answer() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"summary": {"type": "string"}},
        "required": ["summary"]
    });
    let body = r#"{
        "model": "gpt-4o-mini",
        "choices": [
            {"message": {"role": "assistant", "content": "{\"summary\":\"hi\"}"},
             "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 9, "completion_tokens": 4}
    }"#;
    let (http, rx) = fixture(200, body, None);
    let prompt = prompt().json_schema(schema.clone());
    let completion = adapter(http).complete(&prompt).await.expect("completes");
    assert_eq!(completion.json, Some(serde_json::json!({"summary": "hi"})));

    let captured = rx.try_recv().expect("one request");
    let sent: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(sent["response_format"]["type"], "json_schema");
    assert_eq!(sent["response_format"]["json_schema"]["name"], "response");
    assert_eq!(sent["response_format"]["json_schema"]["schema"], schema);
    // `strict: false`: the port allows any draft 2020-12 schema, and
    // first-party `OpenAI` 400s an ordinary one under strict mode. The
    // adapter's enforcement is the parse, not the flag.
    assert_eq!(sent["response_format"]["json_schema"]["strict"], false);
}

#[pollster::test]
async fn a_schema_answer_cut_off_at_max_tokens_is_rejected() {
    // `finish_reason: "length"` cut the JSON off mid-string; handing the
    // fragment back as a schema-shaped success would fail the caller's
    // check downstream. `Rejected`, because retrying unchanged truncates
    // identically — the same line the Anthropic adapter draws on
    // `stop_reason: "max_tokens"`.
    let body = r#"{
        "model": "gpt-4o-mini",
        "choices": [
            {"message": {"role": "assistant", "content": "{\"summary\":\"hi"},
             "finish_reason": "length"}
        ],
        "usage": {"prompt_tokens": 9, "completion_tokens": 16}
    }"#;
    let (http, _rx) = fixture(200, body, None);
    let prompt = prompt().json_schema(serde_json::json!({"type": "object"}));
    let err = adapter(http).complete(&prompt).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => {
            assert!(detail.contains("truncated"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn a_schema_answer_that_is_not_json_stays_text_for_the_port_to_repair() {
    // The server ignored the `response_format` and answered in prose (a
    // local server, a fenced reply). The adapter does not fail the call:
    // the raw content rides in `text` with no parsed value, and the port's
    // `complete_json` parses, validates and repairs it — the same fallback
    // a provider without native structured output takes.
    let body = r#"{
        "model": "gpt-4o-mini",
        "choices": [
            {"message": {"role": "assistant", "content": "I will not be boxed."},
             "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 9, "completion_tokens": 7}
    }"#;
    let (http, _rx) = fixture(200, body, None);
    let prompt = prompt().json_schema(serde_json::json!({"type": "object"}));
    let completion = adapter(http).complete(&prompt).await.expect("completes");
    assert_eq!(completion.text, "I will not be boxed.");
    assert_eq!(completion.json, None);
}

#[pollster::test]
async fn a_truncated_text_completion_still_succeeds() {
    // No schema was asked for, so `finish_reason: "length"` leaves half a
    // prose answer — still an answer, and the caller gets it rather than
    // an error.
    let body = r#"{
        "model": "gpt-4o-mini",
        "choices": [
            {"message": {"role": "assistant", "content": "Hel"}, "finish_reason": "length"}
        ],
        "usage": {"prompt_tokens": 9, "completion_tokens": 1}
    }"#;
    let (http, _rx) = fixture(200, body, None);
    let completion = adapter(http).complete(&prompt()).await.expect("completes");
    assert_eq!(completion.text, "Hel");
    assert_eq!(completion.json, None);
}

#[pollster::test]
async fn a_refusal_is_rejected_and_never_the_completion_text() {
    // A refusal arrives as `content: null` with `refusal` set; left
    // unread, the null content became `Ok` with empty text (and on the
    // schema path, a transport error). The caller gets `Rejected` in the
    // adapter's own words — the provider's refusal text goes to the log,
    // never into the error the caller matches on.
    let body = r#"{
        "model": "gpt-4o-mini",
        "choices": [
            {"message": {"role": "assistant", "content": null,
                         "refusal": "I cannot help with that request."},
             "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 11, "completion_tokens": 5}
    }"#;
    let (http, _rx) = fixture(200, body, None);
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => {
            assert!(detail.contains("declined"), "{detail}");
            assert!(
                !detail.contains("cannot help"),
                "the refusal text leaks into the error: {detail}"
            );
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn content_filter_finish_reason_is_rejected_on_the_text_path() {
    // The server's filter stopped the answer before it was one — checked
    // before the schema path forks, so it covers both. `Rejected`, not
    // `Transient`: the prompt is what tripped it, so retrying unchanged
    // fails the same way.
    let body = r#"{
        "model": "gpt-4o-mini",
        "choices": [
            {"message": {"role": "assistant", "content": ""},
             "finish_reason": "content_filter"}
        ],
        "usage": {"prompt_tokens": 11, "completion_tokens": 0}
    }"#;
    let (http, _rx) = fixture(200, body, None);
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => {
            assert!(detail.contains("content filter"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
}

// --- The error table ---------------------------------------------------

#[pollster::test]
async fn rate_limited_reads_retry_after_delta_seconds() {
    let (http, _rx) = fixture(
        429,
        r#"{"error":{"message":"Rate limit reached","type":"requests"}}"#,
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
    // A proxy in front of the server answers with a date: one hour from
    // the adapter's clock, not an immediate retry. The clock the adapter
    // was constructed with is what makes the delta deterministic.
    let at = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid timestamp");
    let date = http_date(at + time::Duration::seconds(3600));
    let (http, _rx) = fixture(429, r#"{"error":{"message":"slow"}}"#, Some(&date));
    let model = OpenAiCompatible::new(
        http,
        clock_at(1_800_000_000),
        Some(DUMMY_KEY.to_string()),
        "gpt-4o-mini",
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
async fn server_error_maps_to_transient() {
    let (http, _rx) = fixture(
        503,
        r#"{"error":{"message":"The server is overloaded"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Transient { retry_after } => assert_eq!(retry_after, None),
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn unauthorized_maps_to_rejected_with_the_provider_message() {
    let (http, _rx) = fixture(
        401,
        r#"{"error":{"message":"Incorrect API key provided","type":"invalid_request_error"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => {
            assert_eq!(detail, "Incorrect API key provided");
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn forbidden_maps_to_rejected() {
    let (http, _rx) = fixture(
        403,
        r#"{"error":{"message":"not allowed for this key"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    assert!(matches!(err, TextModelError::Rejected(_)), "got {err}");
}

#[pollster::test]
async fn any_other_client_error_maps_to_rejected() {
    // 404: the model is not served here — retrying unchanged fails the
    // same way.
    let (http, _rx) = fixture(
        404,
        r#"{"error":{"message":"The model 'gpt-nope' does not exist"}}"#,
        None,
    );
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => {
            assert_eq!(detail, "The model 'gpt-nope' does not exist");
        }
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
async fn transport_failures_map_to_transport() {
    // Scripted through `BoundedHttpClient`, the way every runtime wires
    // the port — a deadline and a cut-off connection are the port's own
    // errors, mapped one row at a time.
    for failure in [
        HttpError::DeadlineExceeded {
            after: Duration::from_secs(30),
        },
        HttpError::Transport("dns is down".to_owned()),
    ] {
        let http: Arc<dyn HttpClient> = Arc::new(BoundedHttpClient::new(
            Arc::new(FakeHttpClient::scripted(vec![Err(failure)])),
            clock_at(0),
        ));
        let model = OpenAiCompatible::new(
            http,
            clock_at(0),
            Some(DUMMY_KEY.to_string()),
            "gpt-4o-mini",
        );
        let err = model.complete(&prompt()).await.unwrap_err();
        assert!(matches!(err, TextModelError::Transport(_)), "got {err}");
        assert!(!err.to_string().contains(DUMMY_KEY));
    }
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
async fn a_success_without_a_choice_maps_to_transport() {
    let body = r#"{"model": "gpt-4o-mini", "choices": [], "usage": null}"#;
    let (http, _rx) = fixture(200, body, None);
    let err = adapter(http).complete(&prompt()).await.unwrap_err();
    match err {
        TextModelError::Transport(message) => {
            assert!(message.contains("without a choice"), "{message}");
        }
        other => panic!("wrong error: {other}"),
    }
}

// --- Configuration and leakage ------------------------------------------

#[pollster::test]
async fn not_configured_fails_before_any_network_call() {
    let http = Arc::new(FakeHttpClient::scripted(vec![]));
    let model = OpenAiCompatible::new(http.clone(), clock_at(0), None, "gpt-4o-mini");
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
        (401u16, r#"{"error":{"message":"bad key"}}"#),
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
