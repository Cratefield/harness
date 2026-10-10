//! Native streaming acceptance tests (issue #859): a recorded chat-completion
//! chunk stream decodes into the deltas the answer arrived in and — through
//! `CompletionBuilder` — reassembles into the very `Completion` `complete`
//! returns for the equivalent buffered fixture; chunk boundaries are
//! invisible to the reassembled tool calls; a delta arrives while the rest
//! of the answer does not exist yet; dropping the stream drops the upstream
//! body; and every failure path maps like the buffered one.

// Test-side recording fixtures, not request state — the same category and
// allowance as `tools.rs` and the fakes in `cratefield-testing` (ADR 0007
// policy).
#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_openai_compatible::OpenAiCompatible;
use cratefield_core::{
    ByteStream, Completion, CompletionBuilder, FinishReason, HttpClient, HttpError, ModelTier,
    Prompt, TextDelta, TextModel, TextModelError, ToolCall, ToolChoice, ToolSpec,
};
use cratefield_testing::{FakeHttpClient, FixedClock};
use futures_util::{FutureExt as _, StreamExt as _};
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// Obvious dummy key, never real.
const DUMMY_KEY: &str = "test-openai-key";

/// The chunk-stream form of `tools.rs`' `TOOL_CALL_RESPONSE` fixture (the
/// vendor docs' `get_weather` example): same id, name, arguments,
/// `finish_reason`, usage and model, with the arguments arriving in three
/// fragments the way a real stream sends them.
const TOOL_CALL_STREAM: &str = include_str!("fixtures/tool-call-stream.sse");
/// The buffered fixture the recorded stream must reassemble into.
const TOOL_CALL_RESPONSE: &str = include_str!("fixtures/tool-call-response.json");
/// The chunk-stream form of `tools.rs`' `PLAIN_RESPONSE` — same text,
/// model and usage.
const TEXT_STREAM: &str = include_str!("fixtures/text-stream.sse");
/// The buffered counterpart of [`TEXT_STREAM`], written out here because
/// `tools.rs` keeps its copy private.
const PLAIN_RESPONSE: &str = r#"{
    "model": "gpt-4o-2024-08-06",
    "choices": [{"message": {"role": "assistant", "content": "Sunny."}, "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 5, "completion_tokens": 2}
}"#;

/// The head of a streamed answer, sent alone in the incremental tests: one
/// complete SSE event, all that exists of the completion at that moment.
const HELLO_HEAD: &str = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"},\"finish_reason\":null}]}\n\n";
/// The rest of the answer, sent after the first delta was already read.
const HELLO_TAIL: &[&str] = &[
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n",
    "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
    "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2}}\n\n",
    "data: [DONE]\n\n",
];

fn adapter(http: impl HttpClient + 'static) -> OpenAiCompatible {
    OpenAiCompatible::new(
        Arc::new(http),
        Arc::new(FixedClock(
            time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
        )),
        Some(DUMMY_KEY.to_owned()),
        "gpt-4o-2024-08-06",
    )
}

/// The docs' `get_weather` tool, as in `tools.rs`.
fn weather_prompt() -> Prompt {
    Prompt::new(ModelTier::Fast)
        .user("What is the weather like in Boston?")
        .tool(ToolSpec::new(
            "get_weather",
            "Get the current weather in a given location",
            json!({
                "type": "object",
                "properties": {
                    "location": {"type": "string", "description": "The city and state"}
                },
                "required": ["location"]
            }),
        ))
        .tool_choice(ToolChoice::Auto)
}

/// Drains a delta stream into its items.
async fn items(
    model: &OpenAiCompatible,
    prompt: &Prompt,
) -> Vec<Result<TextDelta, TextModelError>> {
    model.stream(prompt).collect().await
}

/// The finished tool calls a delta list carries, in index order.
fn finished_calls(items: &[Result<TextDelta, TextModelError>]) -> Vec<ToolCall> {
    items
        .iter()
        .filter_map(|item| item.as_ref().ok())
        .filter_map(|delta| match delta {
            TextDelta::ToolCallFinished { call, .. } => Some(call.clone()),
            _ => None,
        })
        .collect()
}

/// Folds a delta list back into the `Completion` it adds up to — the
/// caller's side of the streaming contract.
fn reassemble(items: &[Result<TextDelta, TextModelError>]) -> Completion {
    let mut builder = CompletionBuilder::default();
    for item in items {
        builder.push(item.as_ref().expect("the stream to be error-free here"));
    }
    builder.finish()
}

/// One scripted response: a status and the body chunks `send_streaming`
/// hands out verbatim.
struct Scripted {
    status: u16,
    chunks: Vec<Vec<u8>>,
}

/// The delta path's counterpart of `FakeHttpClient`, which only speaks the
/// buffered `send`: `send_streaming` answers the scripted status and
/// streams the scripted chunks, recording every request body. Cloneable
/// like `FakeHttpClient`, so a test keeps a handle to read the captures.
#[derive(Clone)]
struct StreamingHttpClient {
    inner: Arc<StreamingInner>,
}

/// The state the handles share: the scripted responses still to hand out,
/// and every request body that reached the wire.
struct StreamingInner {
    responses: Mutex<VecDeque<Scripted>>,
    captured: Mutex<Vec<String>>,
}

impl StreamingHttpClient {
    /// One response whose body is `sse`, split into its events — one chunk
    /// each, the way a server writes them.
    fn sse(status: u16, sse: &str) -> Self {
        Self::chunks(
            status,
            sse.split_inclusive("\n\n")
                .map(str::as_bytes)
                .map(<[u8]>::to_vec)
                .collect(),
        )
    }

    /// One response whose body arrives as `chunks` — arbitrary re-chunkings
    /// for the boundary tests.
    fn chunks(status: u16, chunks: Vec<Vec<u8>>) -> Self {
        Self {
            inner: Arc::new(StreamingInner {
                responses: Mutex::new(VecDeque::from([Scripted { status, chunks }])),
                captured: Mutex::new(Vec::new()),
            }),
        }
    }

    fn captured(&self) -> Vec<String> {
        self.inner.captured.lock().expect("http lock").clone()
    }
}

#[async_trait]
impl HttpClient for StreamingHttpClient {
    /// The buffered half, for the `complete` side of the equivalence tests:
    /// the same scripted body, drained and joined.
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let response = self.send_streaming(request).await?;
        let (parts, mut body) = response.into_parts();
        let mut buffered = Vec::new();
        while let Some(chunk) = body.next().await {
            buffered.extend_from_slice(&chunk?);
        }
        Ok(Response::from_parts(parts, Bytes::from(buffered)))
    }

    async fn send_streaming(
        &self,
        request: Request<Bytes>,
    ) -> Result<Response<ByteStream>, HttpError> {
        let (_, body) = request.into_parts();
        self.inner
            .captured
            .lock()
            .expect("http lock")
            .push(String::from_utf8_lossy(&body).to_string());
        let scripted = self
            .inner
            .responses
            .lock()
            .expect("http lock")
            .pop_front()
            .ok_or_else(|| HttpError::Transport("fake http exhausted".to_owned()))?;
        let status = StatusCode::from_u16(scripted.status).expect("scripted status");
        let chunks: Vec<Result<Bytes, HttpError>> = scripted
            .chunks
            .into_iter()
            .map(|chunk| Ok(Bytes::from(chunk)))
            .collect();
        let body: ByteStream = Box::pin(futures_util::stream::iter(chunks));
        Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/event-stream")
            .body(body)
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

/// A client whose streamed body arrives over a `futures_channel` mpsc
/// receiver the test holds the sender half of: chunks are dripped in one at
/// a time, which is what makes "a delta before the whole answer exists" and
/// "dropping the stream drops the body" observable.
struct ChannelClient {
    body: Mutex<Option<futures_channel::mpsc::Receiver<Bytes>>>,
}

impl ChannelClient {
    fn new(receiver: futures_channel::mpsc::Receiver<Bytes>) -> Self {
        Self {
            body: Mutex::new(Some(receiver)),
        }
    }
}

#[async_trait]
impl HttpClient for ChannelClient {
    async fn send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        // These tests drive the streaming half only.
        Err(HttpError::Transport(
            "buffered send is not scripted here".to_owned(),
        ))
    }

    async fn send_streaming(
        &self,
        _request: Request<Bytes>,
    ) -> Result<Response<ByteStream>, HttpError> {
        let receiver = self
            .body
            .lock()
            .expect("channel lock")
            .take()
            .ok_or_else(|| HttpError::Transport("streaming body already handed out".to_owned()))?;
        let body: ByteStream = Box::pin(receiver.map(Ok::<Bytes, HttpError>));
        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/event-stream")
            .body(body)
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

/// A fixed-seed xorshift64*: the multi-split chunkings must be
/// reproducible, and a generator this small needs no `rand` dependency.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

#[pollster::test]
async fn a_text_stream_yields_the_answer_as_it_arrived_and_reassembles_into_complete_s_answer() {
    let prompt = Prompt::new(ModelTier::Fast).user("What is the weather like in Boston?");
    // The buffered half of the equivalence: `complete`'s answer for the
    // plain JSON response the recorded stream is the chunk form of.
    let expected = adapter(FakeHttpClient::scripted(vec![ok(PLAIN_RESPONSE)]))
        .complete(&prompt)
        .await
        .expect("completes");

    let deltas = items(
        &adapter(StreamingHttpClient::sse(200, TEXT_STREAM)),
        &prompt,
    )
    .await;
    assert_eq!(
        deltas,
        vec![
            Ok(TextDelta::Text("Sunny.".to_owned())),
            Ok(TextDelta::Usage {
                input_tokens: 5,
                output_tokens: 2,
                cached_input_tokens: None,
            }),
            Ok(TextDelta::Finish {
                reason: FinishReason::Stop,
                model: "gpt-4o-2024-08-06".to_owned(),
            }),
        ],
        "the deltas are the answer as it arrived"
    );
    assert_eq!(reassemble(&deltas), expected);
}

#[pollster::test]
async fn a_tool_call_stream_reassembles_into_complete_s_tool_calls() {
    let prompt = weather_prompt();
    let expected = adapter(FakeHttpClient::scripted(vec![ok(TOOL_CALL_RESPONSE)]))
        .complete(&prompt)
        .await
        .expect("completes");

    let deltas = items(
        &adapter(StreamingHttpClient::sse(200, TOOL_CALL_STREAM)),
        &prompt,
    )
    .await;

    // The arguments arrived as fragments, not one blob.
    assert_eq!(
        deltas
            .iter()
            .filter(|item| matches!(item, Ok(TextDelta::ToolCallArguments { .. })))
            .count(),
        3,
        "the arguments arrived in three fragments"
    );
    assert_eq!(finished_calls(&deltas), expected.tool_calls);
    assert_eq!(reassemble(&deltas), expected);
}

#[pollster::test]
async fn chunk_boundaries_are_invisible_to_the_reassembled_tool_call() {
    let prompt = weather_prompt();
    let expected = adapter(FakeHttpClient::scripted(vec![ok(TOOL_CALL_RESPONSE)]))
        .complete(&prompt)
        .await
        .expect("completes")
        .tool_calls;
    let bytes = TOOL_CALL_STREAM.as_bytes();

    // Every single split point of the recorded stream reassembles the same
    // call: the SSE decoder buffers bytes until a line ends, so the
    // transport's chunking must not matter.
    for split in 0..=bytes.len() {
        let chunks = vec![bytes[..split].to_vec(), bytes[split..].to_vec()];
        let deltas = items(&adapter(StreamingHttpClient::chunks(200, chunks)), &prompt).await;
        assert_eq!(finished_calls(&deltas), expected, "single split at {split}");
    }

    // And several seeded multi-split chunkings, reproducible without a
    // proptest dependency.
    for seed in 1..=8u64 {
        let mut rng = XorShift(seed ^ 0x9E37_79B9_7F4A_7C15);
        let count = 2 + (rng.next() % 5);
        let upper = bytes.len() as u64 + 1;
        let mut cuts: Vec<usize> = (0..count)
            .map(|_| usize::try_from(rng.next() % upper).expect("a cut fits usize"))
            .collect();
        cuts.sort_unstable();
        cuts.dedup();
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut start = 0;
        for cut in cuts {
            chunks.push(bytes[start..cut].to_vec());
            start = cut;
        }
        chunks.push(bytes[start..].to_vec());

        let deltas = items(&adapter(StreamingHttpClient::chunks(200, chunks)), &prompt).await;
        assert_eq!(finished_calls(&deltas), expected, "seed {seed} chunking");
    }
}

#[pollster::test]
async fn the_first_delta_arrives_before_the_whole_answer_exists() {
    let (mut tx, rx) = futures_channel::mpsc::channel::<Bytes>(4);
    let model = adapter(ChannelClient::new(rx));
    let prompt = Prompt::new(ModelTier::Fast).user("Say hello");
    let mut stream = model.stream(&prompt);

    // Only the head chunk has been sent — one complete SSE event.
    tx.try_send(Bytes::from(HELLO_HEAD.to_owned()))
        .expect("channel open");

    // One poll, no blocking: the first text delta is already there, and
    // nothing else is.
    let first = stream
        .next()
        .now_or_never()
        .expect("a delta is available now");
    assert_eq!(first, Some(Ok(TextDelta::Text("Hel".to_owned()))));
    assert!(
        stream.next().now_or_never().is_none(),
        "no further delta before the next chunk is sent"
    );

    for chunk in HELLO_TAIL {
        tx.try_send(Bytes::from((*chunk).to_owned()))
            .expect("channel open");
    }
    let rest: Vec<Result<TextDelta, TextModelError>> = stream.collect().await;
    assert_eq!(
        rest,
        vec![
            Ok(TextDelta::Text("lo".to_owned())),
            Ok(TextDelta::Usage {
                input_tokens: 1,
                output_tokens: 2,
                cached_input_tokens: None,
            }),
            Ok(TextDelta::Finish {
                reason: FinishReason::Stop,
                model: "gpt-4o-2024-08-06".to_owned(),
            }),
        ],
    );
}

#[pollster::test]
async fn dropping_the_stream_drops_the_upstream_body() {
    let (mut tx, rx) = futures_channel::mpsc::channel::<Bytes>(4);
    let model = adapter(ChannelClient::new(rx));
    let prompt = Prompt::new(ModelTier::Fast).user("Say hello");
    let mut stream = model.stream(&prompt);
    tx.try_send(Bytes::from(HELLO_HEAD.to_owned()))
        .expect("channel open");
    let _ = stream.next().now_or_never();
    assert!(!tx.is_closed(), "the body lives while the stream does");

    drop(stream);
    assert!(
        tx.is_closed(),
        "the body — and with it the upstream exchange — dropped with the stream"
    );
}

#[pollster::test]
async fn an_error_payload_inside_the_stream_ends_it_with_an_err() {
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"He\"}}]}\n\n",
        "data: {\"error\":{\"message\":\"the server tripped mid-stream\",\"type\":\"server_error\"}}\n\n",
    );
    let deltas = items(
        &adapter(StreamingHttpClient::sse(200, body)),
        &Prompt::new(ModelTier::Fast).user("hi"),
    )
    .await;
    assert_eq!(
        deltas.len(),
        2,
        "the text delta, then the error, then the end"
    );
    assert_eq!(
        deltas[0].as_ref().unwrap(),
        &TextDelta::Text("He".to_owned())
    );
    let Err(TextModelError::Transport(detail)) = &deltas[1] else {
        panic!("expected a Transport error, got {:?}", deltas[1]);
    };
    assert!(detail.contains("the server tripped mid-stream"), "{detail}");
}

#[pollster::test]
async fn a_non_2xx_head_maps_like_the_buffered_path() {
    let prompt = Prompt::new(ModelTier::Fast).user("hi");
    let rejected = items(
        &adapter(StreamingHttpClient::chunks(
            401,
            vec![br#"{"error":{"message":"bad key"}}"#.to_vec()],
        )),
        &prompt,
    )
    .await;
    assert_eq!(
        rejected,
        vec![Err(TextModelError::Rejected("bad key".to_owned()))]
    );

    let transient = items(
        &adapter(StreamingHttpClient::chunks(429, vec![b"{}".to_vec()])),
        &prompt,
    )
    .await;
    assert_eq!(
        transient,
        vec![Err(TextModelError::Transient { retry_after: None })]
    );
}

#[pollster::test]
async fn the_streaming_request_carries_the_stream_flags_and_the_shared_shape() {
    let http = StreamingHttpClient::sse(200, TEXT_STREAM);
    adapter(http.clone())
        .stream(&weather_prompt())
        .collect::<Vec<_>>()
        .await;

    let captured = http.captured();
    let sent: Value = serde_json::from_str(&captured[0]).expect("request is JSON");
    assert_eq!(sent["stream"], true);
    assert_eq!(sent["stream_options"]["include_usage"], true);
    // Everything else is the request `complete` sends: same model, tools
    // and choice.
    assert_eq!(sent["model"], "gpt-4o-2024-08-06");
    assert_eq!(sent["tools"][0]["function"]["name"], "get_weather");
    assert_eq!(sent["tool_choice"], "auto");
}

#[pollster::test]
async fn a_server_that_omits_done_after_a_finish_reason_still_finishes() {
    // finish_reason and the usage chunk arrived; the [DONE] sentinel never
    // did. Some compatible servers end this way; the answer still finished.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n",
    );
    let deltas = items(
        &adapter(StreamingHttpClient::sse(200, body)),
        &Prompt::new(ModelTier::Fast).user("hi"),
    )
    .await;
    assert_eq!(
        deltas,
        vec![
            Ok(TextDelta::Usage {
                input_tokens: 1,
                output_tokens: 1,
                cached_input_tokens: None,
            }),
            Ok(TextDelta::Finish {
                reason: FinishReason::Stop,
                model: "gpt-4o-2024-08-06".to_owned(),
            }),
        ],
    );
}

#[pollster::test]
async fn a_stream_that_ends_without_a_finish_reason_or_done_is_transport() {
    // Half an answer, then EOF: nothing about the prompt was refused, the
    // answer just never completed — the same bucket as a cut-off body.
    let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half an\"}}]}\n\n";
    let deltas = items(
        &adapter(StreamingHttpClient::sse(200, body)),
        &Prompt::new(ModelTier::Fast).user("hi"),
    )
    .await;
    assert_eq!(deltas.len(), 2);
    assert_eq!(
        deltas[0].as_ref().unwrap(),
        &TextDelta::Text("half an".to_owned())
    );
    assert!(
        matches!(&deltas[1], Err(TextModelError::Transport(_))),
        "{deltas:?}"
    );
}

#[pollster::test]
async fn a_tool_call_truncated_at_max_tokens_rejects_like_complete() {
    // The streaming twin of `tools.rs`' truncation test: `finish_reason`
    // "length" cut the arguments off mid-string, and the stream must end
    // with `complete`'s own Rejected — never a ToolCallFinished carrying
    // truncated JSON a caller could mistake for a success.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_cut\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"location\\\": \\\"Bos\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"length\"}]}\n\n",
        "data: [DONE]\n\n",
    );
    let deltas = items(
        &adapter(StreamingHttpClient::sse(200, body)),
        &weather_prompt(),
    )
    .await;
    let Err(TextModelError::Rejected(detail)) = deltas.last().expect("non-empty") else {
        panic!("expected the truncation Rejected, got {deltas:?}");
    };
    assert!(detail.contains("truncated"), "{detail}");
    assert!(
        !deltas
            .iter()
            .any(|item| matches!(item, Ok(TextDelta::ToolCallFinished { .. }))),
        "no finished call may carry truncated JSON"
    );
}

#[pollster::test]
async fn a_content_filter_finish_rejects_with_complete_s_own_error() {
    // The buffered `refusal_guard` turns `finish_reason: "content_filter"`
    // into a `Rejected`; the stream must end with the very same error, not
    // a `Finish{ContentFilter}` a caller could assemble into the
    // completion `complete` refuses.
    let prompt = Prompt::new(ModelTier::Fast).user("hi");
    let streamed = items(
        &adapter(StreamingHttpClient::sse(
            200,
            concat!(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"part\"}}]}\n\n",
                "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"content_filter\"}]}\n\n",
                "data: [DONE]\n\n",
            ),
        )),
        &prompt,
    )
    .await;
    let buffered = adapter(FakeHttpClient::scripted(vec![ok(
        r#"{"choices":[{"message":{"role":"assistant","content":"part"},"finish_reason":"content_filter"}]}"#,
    )]))
    .complete(&prompt)
    .await
    .expect_err("the buffered path refuses a filtered answer");

    assert_eq!(
        streamed,
        vec![Ok(TextDelta::Text("part".to_owned())), Err(buffered),],
        "the stream ends on the exact error `complete` returns"
    );
    assert!(
        !streamed
            .iter()
            .any(|item| matches!(item, Ok(TextDelta::Finish { .. }))),
        "a filtered stream has no Finish"
    );
}

#[pollster::test]
async fn reasoning_chunks_surface_as_reasoning_deltas() {
    // Both spellings the compatible-server ecosystem ships: the first
    // chunk speaks `reasoning_content`, the second the `reasoning` alias.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"thinking\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning\":\" harder\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"done\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n",
    );
    let deltas = items(
        &adapter(StreamingHttpClient::sse(200, body)),
        &Prompt::new(ModelTier::Fast).user("hi"),
    )
    .await;
    assert_eq!(
        deltas,
        vec![
            Ok(TextDelta::Reasoning("thinking".to_owned())),
            Ok(TextDelta::Reasoning(" harder".to_owned())),
            Ok(TextDelta::Text("done".to_owned())),
            Ok(TextDelta::Finish {
                reason: FinishReason::Stop,
                model: "gpt-4o-2024-08-06".to_owned(),
            }),
        ],
    );
}

#[pollster::test]
async fn two_tool_calls_finish_in_index_order() {
    // Two parallel calls, their fragments interleaved the way servers send
    // them: call 1 opens while call 0's arguments are still arriving. The
    // finished calls come out in index order regardless.
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_0\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"location\\\": \"}},{\"index\":1,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"Boston\\\"}\"}},{\"index\":1,\"function\":{\"arguments\":\"{\\\"location\\\": \\\"Paris\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\n",
        "data: [DONE]\n\n",
    );
    let deltas = items(
        &adapter(StreamingHttpClient::sse(200, body)),
        &weather_prompt(),
    )
    .await;

    let calls = finished_calls(&deltas);
    assert_eq!(calls.len(), 2, "{deltas:?}");
    assert_eq!(calls[0].id, "call_0");
    assert_eq!(calls[1].id, "call_1");
    assert_eq!(calls[0].arguments, json!({"location": "Boston"}));
    assert_eq!(calls[1].arguments, json!({"location": "Paris"}));
    // The closing Finish names the tool use.
    assert_eq!(
        deltas.last(),
        Some(&Ok(TextDelta::Finish {
            reason: FinishReason::ToolUse,
            model: "gpt-4o-2024-08-06".to_owned(),
        })),
    );
}

fn ok(body: &str) -> Result<Response<Bytes>, HttpError> {
    Response::builder()
        .status(200)
        .body(Bytes::from(body.to_owned()))
        .map_err(|err| HttpError::Transport(err.to_string()))
}
