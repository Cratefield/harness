//! Native streaming over the Messages event stream (issue #859): the
//! deltas a streamed answer produces, their equivalence with the buffered
//! `complete` over the recorded fixtures — including under every chunk
//! boundary the transport could pick — incremental delivery, cancellation
//! by drop, and the two error paths (a mid-stream `error` event, a non-2xx
//! head).

// Test-side recording fixture, not request state — the same category
// and allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_anthropic::Anthropic;
use cratefield_core::{
    ByteStream, Completion, CompletionBuilder, FinishReason, HttpClient, HttpError, ModelTier,
    Prompt, TextDelta, TextModel, TextModelError, ToolCall, ToolChoice, ToolSpec,
};
use cratefield_testing::{FakeHttpClient, FixedClock};
use futures_util::FutureExt as _;
use futures_util::StreamExt;
use http::{Request, Response, StatusCode};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The docs' weather answer as a stream — the recorded
/// `tool-use-response-2.json` answer, event for event.
const TEXT_STREAM: &str = include_str!("fixtures/text-stream.sse");
/// The docs' tool-use answer as a stream — the recorded
/// `tool-use-response-1.json` answer, its arguments arriving as
/// `input_json_delta` chunks.
const TOOL_USE_STREAM: &str = include_str!("fixtures/tool-use-stream.sse");
const TEXT_RESPONSE: &str = include_str!("fixtures/tool-use-response-2.json");
const TOOL_USE_RESPONSE: &str = include_str!("fixtures/tool-use-response-1.json");

/// A stream that answers one text run, then fails the way the provider
/// does under load: an `error` event carrying its `overloaded_error`.
const OVERLOADED_STREAM: &str = r#"event: message_start
data: {"type":"message_start","message":{"id":"msg_overloaded","type":"message","role":"assistant","model":"claude-opus-5","content":[],"usage":{"input_tokens":5,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}

event: error
data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}

"#;

/// The stream's opening frames only: the head, the text block opening,
/// and its first run — what a provider has produced before the rest of
/// the answer exists.
const STREAM_HEAD: &str = concat!(
    "event: message_start\n",
    r#"data: {"type":"message_start","message":{"id":"msg_head","model":"claude-opus-5","usage":{"input_tokens":710,"output_tokens":1}}}"#,
    "\n\n",
    "event: content_block_start\n",
    r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
    "\n\n",
    "event: content_block_delta\n",
    r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"The current weather"}}"#,
    "\n\n",
);

/// The frames after [`STREAM_HEAD`]: the rest of the text, the close, and
/// the clean end.
const STREAM_REST: &str = concat!(
    "event: content_block_delta\n",
    r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" in San Francisco is 15 degrees Celsius."}}"#,
    "\n\n",
    "event: content_block_stop\n",
    r#"data: {"type":"content_block_stop","index":0}"#,
    "\n\n",
    "event: message_delta\n",
    r#"data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":28}}"#,
    "\n\n",
    "event: message_stop\n",
    r#"data: {"type":"message_stop"}"#,
    "\n\n",
);

/// Obvious dummy key, never real.
const DUMMY_KEY: &str = "test-anthropic-key";

/// A stream the provider ends under its own policy: `stop_reason:
/// "refusal"` — the wire's content-filter word.
const REFUSAL_STREAM: &str = concat!(
    "event: message_start\n",
    r#"data: {"type":"message_start","message":{"id":"msg_refusal","model":"claude-opus-5","usage":{"input_tokens":5,"output_tokens":1}}}"#,
    "\n\n",
    "event: content_block_start\n",
    r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
    "\n\n",
    "event: content_block_delta\n",
    r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I cannot answer that."}}"#,
    "\n\n",
    "event: content_block_stop\n",
    r#"data: {"type":"content_block_stop","index":0}"#,
    "\n\n",
    "event: message_delta\n",
    r#"data: {"type":"message_delta","delta":{"stop_reason":"refusal","stop_sequence":null},"usage":{"output_tokens":9}}"#,
    "\n\n",
    "event: message_stop\n",
    r#"data: {"type":"message_stop"}"#,
    "\n\n",
);

/// The buffered twin of [`REFUSAL_STREAM`].
const REFUSAL_RESPONSE: &str = r#"{"model":"claude-opus-5","content":[{"type":"text","text":"I cannot answer that."}],"stop_reason":"refusal","usage":{"input_tokens":5,"output_tokens":9}}"#;

/// A stream whose `message_delta` carries no `usage` block — a server or
/// proxy that dropped the cumulative count on the way through.
const NO_DELTA_USAGE_STREAM: &str = concat!(
    "event: message_start\n",
    r#"data: {"type":"message_start","message":{"id":"msg_nousage","model":"claude-opus-5","usage":{"input_tokens":5,"output_tokens":1}}}"#,
    "\n\n",
    "event: content_block_start\n",
    r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
    "\n\n",
    "event: content_block_delta\n",
    r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Short."}}"#,
    "\n\n",
    "event: content_block_stop\n",
    r#"data: {"type":"content_block_stop","index":0}"#,
    "\n\n",
    "event: message_delta\n",
    r#"data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null}}"#,
    "\n\n",
    "event: message_stop\n",
    r#"data: {"type":"message_stop"}"#,
    "\n\n",
);

/// The buffered twin of [`NO_DELTA_USAGE_STREAM`]: the one usage report
/// there is sits on the message itself.
const NO_DELTA_USAGE_RESPONSE: &str = r#"{"model":"claude-opus-5","content":[{"type":"text","text":"Short."}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":1}}"#;

fn clock() -> Arc<dyn cratefield_core::Clock> {
    Arc::new(FixedClock(
        time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
    ))
}

fn anthropic(http: Arc<dyn HttpClient>) -> Anthropic {
    Anthropic::new(http, clock(), Some(DUMMY_KEY.to_owned()), "claude-opus-5")
}

fn ok(body: &str) -> Result<Response<Bytes>, HttpError> {
    Response::builder()
        .status(200)
        .body(Bytes::from(body.to_owned()))
        .map_err(|err| HttpError::Transport(err.to_string()))
}

/// The buffered answer `complete` returns for a recorded JSON response —
/// what every streamed reassembly is held against.
async fn completed(response: &str, prompt: &Prompt) -> Completion {
    let http: Arc<dyn HttpClient> = Arc::new(FakeHttpClient::scripted(vec![ok(response)]));
    anthropic(http)
        .complete(prompt)
        .await
        .expect("the buffered call completes")
}

/// The docs' `get_weather` tool, exactly as the tool-use tests declare it.
fn weather_tool() -> ToolSpec {
    ToolSpec::new(
        "get_weather",
        "Get the current weather for a given location.",
        serde_json::json!({
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "City and state, e.g. San Francisco, CA"
                }
            },
            "required": ["location"]
        }),
    )
}

fn text_prompt() -> Prompt {
    Prompt::new(ModelTier::Fast).user("What's the weather in San Francisco?")
}

fn tool_prompt() -> Prompt {
    Prompt::new(ModelTier::Fast)
        .user("What's the weather in San Francisco?")
        .max_tokens(1024)
        .tool(weather_tool())
        .tool_choice(ToolChoice::Auto)
}

/// A transport whose `send_streaming` head and chunked body the test
/// picks — the seam the streaming tests drive, since `FakeHttpClient`
/// only answers buffered. Request bodies are recorded, so a test can
/// assert the wire said `stream: true`.
struct ChunkedHttpClient {
    head: u16,
    retry_after: Option<String>,
    chunks: Vec<Result<Bytes, HttpError>>,
    requests: Mutex<Vec<String>>,
}

impl ChunkedHttpClient {
    /// A 2xx head over a body arriving as `chunks`.
    fn streaming(chunks: Vec<Result<Bytes, HttpError>>) -> Arc<Self> {
        Arc::new(Self {
            head: 200,
            retry_after: None,
            chunks,
            requests: Mutex::new(Vec::new()),
        })
    }

    /// A non-2xx head over `body`, with the `Retry-After` a rate limit
    /// carries.
    fn failing(head: u16, body: &str, retry_after: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            head,
            retry_after: retry_after.map(str::to_owned),
            chunks: vec![Ok(Bytes::from(body.to_owned()))],
            requests: Mutex::new(Vec::new()),
        })
    }

    /// The request bodies it was handed, in order.
    fn captured(&self) -> Vec<String> {
        self.requests.lock().expect("client lock").clone()
    }
}

#[async_trait]
impl HttpClient for ChunkedHttpClient {
    async fn send(&self, _: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        Err(HttpError::Transport(
            "the streaming tests drive send_streaming".to_owned(),
        ))
    }

    async fn send_streaming(
        &self,
        request: Request<Bytes>,
    ) -> Result<Response<ByteStream>, HttpError> {
        self.requests
            .lock()
            .expect("client lock")
            .push(String::from_utf8_lossy(request.body()).to_string());
        let mut builder =
            Response::builder().status(StatusCode::from_u16(self.head).expect("valid status"));
        if let Some(retry_after) = &self.retry_after {
            builder = builder.header("retry-after", retry_after.as_str());
        }
        let body: ByteStream = Box::pin(futures_util::stream::iter(self.chunks.clone()));
        builder
            .body(body)
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

/// A transport whose streaming body arrives over an mpsc channel the test
/// holds the other end of — how the incremental-delivery and cancellation
/// proofs control exactly which bytes exist when.
struct ChannelHttpClient {
    body: Mutex<Option<futures_channel::mpsc::Receiver<Result<Bytes, HttpError>>>>,
}

#[async_trait]
impl HttpClient for ChannelHttpClient {
    async fn send(&self, _: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        Err(HttpError::Transport(
            "the streaming tests drive send_streaming".to_owned(),
        ))
    }

    async fn send_streaming(&self, _: Request<Bytes>) -> Result<Response<ByteStream>, HttpError> {
        let body: ByteStream = Box::pin(
            self.body
                .lock()
                .expect("channel lock")
                .take()
                .expect("one streaming exchange per test"),
        );
        Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

/// Splits `body` into chunks at `splits` (byte offsets, in any order) —
/// the rechunkings the equivalence property runs over.
fn chunked(body: &str, splits: &[usize]) -> Vec<Result<Bytes, HttpError>> {
    let bytes = body.as_bytes();
    let mut edges = vec![0, bytes.len()];
    edges.extend(splits.iter().copied().filter(|at| at <= &bytes.len()));
    edges.sort_unstable();
    edges.dedup();
    edges
        .windows(2)
        .map(|pair| Ok(Bytes::copy_from_slice(&bytes[pair[0]..pair[1]])))
        .collect()
}

/// Collects every item of the streamed answer for `prompt`.
async fn streamed(
    http: Arc<ChunkedHttpClient>,
    prompt: &Prompt,
) -> Vec<Result<TextDelta, TextModelError>> {
    let model = anthropic(http);
    let mut stream = model.stream(prompt);
    let mut items = Vec::new();
    while let Some(item) = stream.next().await {
        items.push(item);
    }
    items
}

/// The finished calls a stream yielded, in order.
fn finished_calls(items: &[Result<TextDelta, TextModelError>]) -> Vec<ToolCall> {
    items
        .iter()
        .filter_map(|item| match item {
            Ok(TextDelta::ToolCallFinished { call, .. }) => Some(call.clone()),
            _ => None,
        })
        .collect()
}

/// The tool calls `complete` returns for the recorded non-streamed
/// fixture — what every rechunking of the recorded stream must add up to.
fn buffered_tool_calls() -> Vec<ToolCall> {
    pollster::block_on(async {
        completed(TOOL_USE_RESPONSE, &tool_prompt())
            .await
            .tool_calls
    })
}

/// xorshift64* — a seeded, deterministic stand-in for the transport's
/// chunking whims.
fn split_points(seed: u64, len: usize, count: usize) -> Vec<usize> {
    let mut state = seed | 1;
    let mut points = Vec::with_capacity(count);
    for _ in 0..count {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        points.push(usize::try_from(state).unwrap_or(0) % (len + 1));
    }
    points.sort_unstable();
    points.dedup();
    points
}

#[pollster::test]
async fn a_text_stream_yields_the_deltas_complete_would_have_answered() {
    let prompt = text_prompt();
    let items = streamed(
        ChunkedHttpClient::streaming(vec![Ok(Bytes::from(TEXT_STREAM.to_owned()))]),
        &prompt,
    )
    .await;

    // The stream said: the prompt-side usage, the answer in its three
    // runs, the usage again with the cumulative output, then one Finish.
    assert_eq!(items.len(), 6, "{items:?}");
    assert!(matches!(
        &items[0],
        Ok(TextDelta::Usage {
            input_tokens: 710,
            output_tokens: 1,
            cached_input_tokens: None
        })
    ));
    assert_eq!(
        items[1..4]
            .iter()
            .filter_map(|item| match item {
                Ok(TextDelta::Text(run)) => Some(run.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(""),
        "The current weather in San Francisco is 15 degrees Celsius with partly cloudy skies.",
    );
    assert!(matches!(
        &items[4],
        Ok(TextDelta::Usage {
            input_tokens: 710,
            output_tokens: 28,
            cached_input_tokens: None
        })
    ));
    assert!(matches!(
        &items[5],
        Ok(TextDelta::Finish { reason: FinishReason::Stop, model })
            if model == "claude-opus-5"
    ));

    // The reassembled completion is the buffered one, field for field.
    let mut builder = CompletionBuilder::default();
    for item in &items {
        builder.push(item.as_ref().expect("no errors"));
    }
    assert_eq!(builder.finish(), completed(TEXT_RESPONSE, &prompt).await);
}

#[pollster::test]
async fn a_tool_call_stream_reassembles_the_call_complete_returns() {
    let prompt = tool_prompt();
    let items = streamed(
        ChunkedHttpClient::streaming(vec![Ok(Bytes::from(TOOL_USE_STREAM.to_owned()))]),
        &prompt,
    )
    .await;

    assert_eq!(items.len(), 8, "{items:?}");
    // The call's index is its ordinal among tool calls — 0 — though it is
    // content block 1 on the wire.
    assert!(matches!(
        &items[2],
        Ok(TextDelta::ToolCallStarted { index: 0, id, name })
            if id == "toolu_01A09q90qw90lq917835lq9" && name == "get_weather"
    ));
    assert!(matches!(
        &items[5],
        Ok(TextDelta::ToolCallFinished { index: 0, call })
            if call.arguments == serde_json::json!({ "location": "San Francisco, CA" })
    ));
    assert!(matches!(
        items.last().expect("items"),
        Ok(TextDelta::Finish {
            reason: FinishReason::ToolUse,
            ..
        })
    ));

    let mut builder = CompletionBuilder::default();
    for item in &items {
        builder.push(item.as_ref().expect("no errors"));
    }
    let reassembled = builder.finish();
    assert_eq!(reassembled, completed(TOOL_USE_RESPONSE, &prompt).await);
    assert_eq!(
        finished_calls(&items),
        reassembled.tool_calls,
        "the finished deltas are the calls the builder holds"
    );
}

#[test]
fn the_recorded_tool_stream_reassembles_identically_after_every_single_split() {
    let expected = buffered_tool_calls();
    let prompt = tool_prompt();
    let len = TOOL_USE_STREAM.len();
    for at in 0..=len {
        let http = ChunkedHttpClient::streaming(chunked(TOOL_USE_STREAM, &[at]));
        let calls = finished_calls(&pollster::block_on(streamed(http, &prompt)));
        assert_eq!(calls, expected, "single split at byte {at}");
    }
}

#[test]
fn the_recorded_tool_stream_reassembles_identically_under_seeded_multi_splits() {
    let expected = buffered_tool_calls();
    let prompt = tool_prompt();
    let len = TOOL_USE_STREAM.len();
    for seed in 1..=32u64 {
        let points = split_points(seed, len, 1 + usize::try_from(seed).unwrap_or(0) % 8);
        let http = ChunkedHttpClient::streaming(chunked(TOOL_USE_STREAM, &points));
        let calls = finished_calls(&pollster::block_on(streamed(http, &prompt)));
        assert_eq!(calls, expected, "seed {seed}, splits {points:?}");
    }
}

#[pollster::test]
async fn a_delta_is_readable_before_the_rest_of_the_answer_exists() {
    let (mut tx, rx) = futures_channel::mpsc::channel::<Result<Bytes, HttpError>>(8);
    let http: Arc<dyn HttpClient> = Arc::new(ChannelHttpClient {
        body: Mutex::new(Some(rx)),
    });
    let model = anthropic(http);
    let prompt = text_prompt();

    tx.try_send(Ok(Bytes::from(STREAM_HEAD.to_owned())))
        .expect("channel open");

    let mut stream = model.stream(&prompt);
    let mut builder = CompletionBuilder::default();
    // The head opened and its deltas are readable at once, though the
    // provider has produced nothing else.
    let usage = stream
        .next()
        .now_or_never()
        .expect("usage is readable at once")
        .expect("the stream yielded an item")
        .expect("no errors");
    assert!(matches!(
        &usage,
        TextDelta::Usage {
            input_tokens: 710,
            ..
        }
    ));
    let first_run = stream
        .next()
        .now_or_never()
        .expect("the first text run is readable before the rest exists")
        .expect("the stream yielded an item")
        .expect("no errors");
    assert!(matches!(&first_run, TextDelta::Text(text) if text == "The current weather"));
    builder.push(&usage);
    builder.push(&first_run);
    assert!(
        stream.next().now_or_never().is_none(),
        "nothing further has been sent"
    );

    // Then the rest arrives, and the stream ends the way the buffered
    // call would have.
    tx.try_send(Ok(Bytes::from(STREAM_REST.to_owned())))
        .expect("channel open");
    while let Some(item) = stream.next().await {
        builder.push(&item.expect("no errors"));
    }
    assert_eq!(
        builder.finish().text,
        "The current weather in San Francisco is 15 degrees Celsius."
    );
}

#[pollster::test]
async fn dropping_the_delta_stream_drops_the_upstream_body() {
    let (mut tx, rx) = futures_channel::mpsc::channel::<Result<Bytes, HttpError>>(8);
    let http: Arc<dyn HttpClient> = Arc::new(ChannelHttpClient {
        body: Mutex::new(Some(rx)),
    });
    let model = anthropic(http);
    let prompt = text_prompt();

    tx.try_send(Ok(Bytes::from(STREAM_HEAD.to_owned())))
        .expect("channel open");

    // The first poll opens the exchange; the body lives inside the stream.
    let mut stream = model.stream(&prompt);
    assert!(
        stream.next().now_or_never().is_some(),
        "the head opened on the first poll"
    );
    assert!(!tx.is_closed());

    // Dropping the stream drops the body, and the sender can tell: this
    // is the cancellation contract, a client that disconnects stopping
    // the spend.
    drop(stream);
    assert!(tx.is_closed(), "the upstream body dropped with the stream");
}

#[pollster::test]
async fn an_error_event_mid_stream_fails_the_stream_without_a_finish() {
    let items = streamed(
        ChunkedHttpClient::streaming(vec![Ok(Bytes::from(OVERLOADED_STREAM.to_owned()))]),
        &text_prompt(),
    )
    .await;

    assert_eq!(items.len(), 3, "two deltas, then the failure: {items:?}");
    assert!(matches!(&items[0], Ok(TextDelta::Usage { .. })));
    assert!(
        matches!(&items[1], Ok(TextDelta::Text(text)) if text == "partial"),
        "{items:?}"
    );
    assert!(
        matches!(
            &items[2],
            Err(TextModelError::Transient { retry_after: None })
        ),
        "overloaded is the provider's 529: transient, no Retry-After to honour"
    );
    assert!(
        items
            .iter()
            .all(|item| !matches!(item, Ok(TextDelta::Finish { .. }))),
        "a failed stream has no Finish"
    );
}

#[pollster::test]
async fn a_non_2xx_head_maps_like_the_buffered_call_does() {
    let prompt = text_prompt();

    // A 5xx: transient, no Retry-After to honour.
    let items = streamed(
        ChunkedHttpClient::failing(
            500,
            r#"{"type":"error","error":{"type":"api_error","message":"overloaded"}}"#,
            None,
        ),
        &prompt,
    )
    .await;
    assert_eq!(items.len(), 1, "the failure is the whole stream: {items:?}");
    assert!(matches!(
        &items[0],
        Err(TextModelError::Transient { retry_after: None })
    ));

    // A 429 with a seconds-form Retry-After: the wait travels.
    let items = streamed(ChunkedHttpClient::failing(429, "{}", Some("5")), &prompt).await;
    assert!(matches!(
        &items[0],
        Err(TextModelError::Transient { retry_after: Some(wait) })
            if *wait == Duration::from_secs(5)
    ));
}

#[pollster::test]
async fn the_streamed_request_says_stream_true_and_keeps_the_request_shape() {
    let http = ChunkedHttpClient::streaming(vec![Ok(Bytes::from(TOOL_USE_STREAM.to_owned()))]);
    let prompt = tool_prompt();
    streamed(Arc::clone(&http), &prompt).await;

    let recorded = http.captured();
    assert_eq!(recorded.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&recorded[0]).expect("json");
    assert_eq!(body["stream"], true, "{body}");
    // Everything else about the request is the buffered one's.
    assert_eq!(body["tools"][0]["name"], "get_weather");
    assert_eq!(body["tool_choice"], serde_json::json!({ "type": "auto" }));
    assert_eq!(
        body["messages"][0]["content"],
        "What's the weather in San Francisco?"
    );
}

#[pollster::test]
async fn a_refusal_stop_reason_finishes_like_complete() {
    // The wire's `refusal` is the port's content-filter bucket. The
    // buffered `complete` does not refuse it — the answer arrives like any
    // other, whatever the provider withheld — so the stream does not
    // refuse it either: the two halves agree, unlike the
    // openai-compatible wire, whose `finish_reason: "content_filter"` is
    // a `Rejected` on both of its halves.
    let prompt = text_prompt();
    let items = streamed(
        ChunkedHttpClient::streaming(vec![Ok(Bytes::from(REFUSAL_STREAM.to_owned()))]),
        &prompt,
    )
    .await;

    assert!(
        items.iter().all(Result::is_ok),
        "a refusal stop reason is not an error on this wire: {items:?}"
    );
    assert!(
        matches!(
            items.last().expect("items"),
            Ok(TextDelta::Finish {
                reason: FinishReason::ContentFilter,
                model,
            }) if model == "claude-opus-5"
        ),
        "{items:?}"
    );

    // Reassembled, it is the buffered answer field for field.
    let mut builder = CompletionBuilder::default();
    for item in &items {
        builder.push(item.as_ref().expect("no errors"));
    }
    assert_eq!(builder.finish(), completed(REFUSAL_RESPONSE, &prompt).await);
}

#[pollster::test]
async fn a_message_delta_without_usage_warns_and_keeps_the_last_known_counts() {
    let (lines, items) = captured(|| {
        pollster::block_on(streamed(
            ChunkedHttpClient::streaming(vec![Ok(Bytes::from(NO_DELTA_USAGE_STREAM.to_owned()))]),
            &text_prompt(),
        ))
    });

    // The omission said itself out loud, the way the openai-compatible
    // adapter says a missing usage block — a warn, not silence.
    assert!(
        lines
            .iter()
            .any(|line| line.contains("without a usage block")),
        "{lines:?}"
    );

    // And the counts stand: the stream's Usage delta reports
    // message_start's numbers, and the stream finishes cleanly.
    assert!(
        matches!(
            items.first().expect("items"),
            Ok(TextDelta::Usage {
                input_tokens: 5,
                output_tokens: 1,
                cached_input_tokens: None,
            })
        ),
        "{items:?}"
    );
    assert!(items.iter().all(Result::is_ok), "{items:?}");
    assert!(matches!(
        items.last().expect("items"),
        Ok(TextDelta::Finish {
            reason: FinishReason::Stop,
            ..
        })
    ));

    // Reassembled, it is the buffered answer — whose only usage report
    // also sits on the message — field for field.
    let mut builder = CompletionBuilder::default();
    for item in &items {
        builder.push(item.as_ref().expect("no errors"));
    }
    let prompt = text_prompt();
    assert_eq!(
        builder.finish(),
        completed(NO_DELTA_USAGE_RESPONSE, &prompt).await
    );
}

// ---- the log capture ------------------------------------------------------

/// Renders one event's fields as one raw `name=value` line. Deliberately
/// *not* core's `RedactingVisitor`: the assertion is about what the
/// adapter emits, so no redaction may stand between the event and the test.
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

/// A subscriber that appends every event's fields to a shared list.
struct CapturingSubscriber {
    lines: Arc<Mutex<Vec<String>>>,
}

impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = RawLine(String::new());
        event.record(&mut line);
        self.lines.lock().expect("log lock").push(line.0);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Runs `run` under the capturing subscriber, returning the emitted lines
/// and whatever `run` produced.
///
/// Tests run in parallel, and tracing caches each callsite's interest
/// globally: while at most one dispatcher is registered, a parallel test
/// with no subscriber could cache `never` for the warn this test waits on,
/// and the line would never arrive. Keeping a second dispatcher alive for
/// the whole process makes tracing consult every registered dispatcher,
/// and rebuilding the cache under the scoped default clears a `never`
/// cached before either existed — the same arrangement
/// `adapter-turnstile`'s log tests use.
fn captured<T>(run: impl FnOnce() -> T) -> (Vec<String>, T) {
    static KEEP_MULTI_DISPATCH: std::sync::OnceLock<tracing::dispatcher::Dispatch> =
        std::sync::OnceLock::new();
    KEEP_MULTI_DISPATCH.get_or_init(|| {
        tracing::dispatcher::Dispatch::new(CapturingSubscriber {
            lines: Arc::new(Mutex::new(Vec::new())),
        })
    });
    let lines = Arc::new(Mutex::new(Vec::new()));
    let dispatch = tracing::dispatcher::Dispatch::new(CapturingSubscriber {
        lines: Arc::clone(&lines),
    });
    let value = tracing::dispatcher::with_default(&dispatch, || {
        tracing::callsite::rebuild_interest_cache();
        run()
    });
    let lines = lines.lock().expect("log lock").clone();
    (lines, value)
}
