//! End-to-end streamed text (issue #859): the real adapters behind a
//! real route — a raw-TCP mock upstream speaking each provider's SSE,
//! the route answering `ResponseStream::new(stream_owned(..))`, the
//! route's first delta out while the upstream still holds the rest of
//! the answer, the whole chain unwinding when a client drops the body,
//! and a completion that streams for over thirty simulated seconds
//! arriving whole through the production `BoundedHttpClient` bounds.

use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use bytes::Bytes;
use cratefield_adapter_anthropic::Anthropic;
use cratefield_adapter_openai_compatible::OpenAiCompatible;
use cratefield_core::{
    BoundedHttpClient, ByteStream, CompletionBuilder, HttpClient, HttpError, ModelTier, Prompt,
    ResponseStream, TextModel, stream_owned,
};
use cratefield_runtime_native::{OutboundOptions, ReqwestClient, TokioClock};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Obvious dummy keys, never real.
const DUMMY_ANTHROPIC_KEY: &str = "test-anthropic-key";
const DUMMY_OPENAI_KEY: &str = "test-openai-key";
const ANSWER: &str = "The current weather in San Francisco is 15 degrees.";

/// Each provider's stream, trimmed to a plain text answer and split in
/// two halves: `open` goes on the wire at once, `close` only when the
/// test releases it.
const ANTHROPIC_OPEN: &str = r#"event: message_start
data: {"type":"message_start","message":{"id":"msg_e2e","role":"assistant","model":"mock-model","usage":{"input_tokens":6,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"The current weather"}}

"#;
const ANTHROPIC_CLOSE: &str = r#"event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" in San Francisco is 15 degrees."}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":9}}

event: message_stop
data: {"type":"message_stop"}

"#;
const OPENAI_OPEN: &str = r#"data: {"id":"chatcmpl-e2e","model":"mock-model","choices":[{"index":0,"delta":{"role":"assistant","content":"The current weather"}}]}

data: {"id":"chatcmpl-e2e","model":"mock-model","choices":[{"index":0,"delta":{"content":" in San Francisco is 15 degrees."}}]}

"#;
const OPENAI_CLOSE: &str = r#"data: {"id":"chatcmpl-e2e","model":"mock-model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: {"id":"chatcmpl-e2e","model":"mock-model","choices":[],"usage":{"prompt_tokens":6,"completion_tokens":9,"total_tokens":15}}

data: [DONE]

"#;

/// One provider's wire shape, everything the mocks and wiring need.
/// `tick` is a complete mid-answer event, so the cancellation mock's
/// drip keeps the route writing and the disconnect surfaces on a
/// write, not a timeout. `first_delta` is what the stream opens with:
/// usage on Messages, text on chat-completions.
struct Script {
    path: &'static str,
    open: &'static str,
    close: &'static str,
    tick: &'static str,
    first_delta: &'static str,
}

const ANTHROPIC: Script = Script {
    path: "/v1/messages",
    open: ANTHROPIC_OPEN,
    close: ANTHROPIC_CLOSE,
    tick: "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"t\"}}\n\n",
    first_delta: "usage",
};

const OPENAI: Script = Script {
    path: "/chat/completions",
    open: OPENAI_OPEN,
    close: OPENAI_CLOSE,
    tick: "data: {\"id\":\"chatcmpl-e2e\",\"model\":\"mock-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"t\"}}]}\n\n",
    first_delta: "text",
};

/// The two adapters the acceptance runs walk through.
#[derive(Debug, Clone, Copy)]
enum Adapter {
    Anthropic,
    OpenAi,
}

impl Adapter {
    fn script(self) -> &'static Script {
        match self {
            Adapter::Anthropic => &ANTHROPIC,
            Adapter::OpenAi => &OPENAI,
        }
    }

    /// The adapter wired to a mock upstream at `addr` through the
    /// production transport: `BoundedHttpClient` over a loopback-allowed
    /// `ReqwestClient`. The `OpenAI` adapter takes the mock's address as
    /// its base URL; the Anthropic adapter's endpoint is the provider's
    /// own, so a redirect moves the request onto the mock instead.
    fn wired(self, addr: SocketAddr) -> Arc<dyn TextModel> {
        match self {
            Adapter::Anthropic => Arc::new(Anthropic::new(
                Arc::new(RedirectToMock {
                    inner: loopback_client(),
                    authority: addr.to_string(),
                }),
                Arc::new(TokioClock),
                Some(DUMMY_ANTHROPIC_KEY.to_owned()),
                "mock-model",
            )),
            Adapter::OpenAi => Arc::new(
                OpenAiCompatible::new(
                    Arc::new(loopback_client()),
                    Arc::new(TokioClock),
                    Some(DUMMY_OPENAI_KEY.to_owned()),
                    "mock-model",
                )
                .with_base_url(format!("http://{addr}")),
            ),
        }
    }
}

fn loopback_client() -> BoundedHttpClient {
    BoundedHttpClient::new(
        Arc::new(ReqwestClient::with_options(OutboundOptions {
            allow_loopback: true,
            max_concurrent: 32,
        })),
        Arc::new(TokioClock),
    )
}

/// The Anthropic adapter speaks to `https://api.anthropic.com`; the
/// redirect keeps the request intact and only moves it onto the mock.
struct RedirectToMock {
    inner: BoundedHttpClient,
    authority: String,
}

/// `uri` re-homed onto the mock: its own path, the mock's authority.
fn redirected(authority: &str, uri: &http::Uri) -> http::Uri {
    let path = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    http::Uri::builder()
        .scheme("http")
        .authority(authority)
        .path_and_query(path)
        .build()
        .expect("a loopback uri builds")
}

#[async_trait]
impl HttpClient for RedirectToMock {
    async fn send(
        &self,
        mut request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        *request.uri_mut() = redirected(&self.authority, request.uri());
        self.inner.send(request).await
    }

    async fn send_streaming(
        &self,
        mut request: http::Request<Bytes>,
    ) -> Result<http::Response<ByteStream>, HttpError> {
        *request.uri_mut() = redirected(&self.authority, request.uri());
        self.inner.send_streaming(request).await
    }
}

/// Reads one request off the socket as (method, target). The body must
/// have arrived too, or a pipelined answer races the read.
async fn read_request(socket: &mut TcpStream) -> Option<(String, String)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let read = socket.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(request) = parse_request(&buffer) {
            return Some(request);
        }
    }
}

fn parse_request(buffer: &[u8]) -> Option<(String, String)> {
    let head_end = buffer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buffer[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_owned();
    let target = request_line.next()?.to_owned();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    (buffer.len() >= head_end + 4 + content_length).then_some((method, target))
}

/// The head of a streamed answer: no declared length, and the
/// connection stays open — the server decides when the body ends.
fn stream_head() -> &'static str {
    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
}

async fn write_chunk(socket: &mut TcpStream, chunk: &str) -> std::io::Result<()> {
    socket
        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
        .await?;
    socket.write_all(chunk.as_bytes()).await?;
    socket.write_all(b"\r\n").await?;
    socket.flush().await
}

/// The mock upstream: answers the adapter's endpoint with the provider
/// SSE — `open` at once, then either the `close` half on release, or
/// (`drip`) a tick every 20 ms whose first failed write is reported
/// through `seen`: the disconnect a dropped route body must make.
async fn mock_upstream(adapter: Adapter, drip: bool) -> (SocketAddr, Rest) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (release, held) = tokio::sync::oneshot::channel::<()>();
    let (report, seen) = tokio::sync::oneshot::channel::<()>();
    let script = adapter.script();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let (method, target) = read_request(&mut socket).await.expect("a request");
        assert_eq!(method, "POST");
        assert_eq!(target, script.path, "the adapter hit its endpoint");
        let _ = socket.write_all(stream_head().as_bytes()).await;
        write_chunk(&mut socket, script.open)
            .await
            .expect("open written");
        if drip {
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if write_chunk(&mut socket, script.tick).await.is_err() {
                    let _ = report.send(());
                    break;
                }
            }
        } else {
            held.await.expect("the test still runs");
            write_chunk(&mut socket, script.close)
                .await
                .expect("close written");
            socket.write_all(b"0\r\n\r\n").await.expect("end written");
        }
    });
    (addr, Rest { release, seen })
}

/// The handles a test holds on its mock: when to let the rest through,
/// and what the drip saw.
struct Rest {
    release: tokio::sync::oneshot::Sender<()>,
    seen: tokio::sync::oneshot::Receiver<()>,
}

/// The route under test: its answer is the model's delta stream, one
/// JSON-encoded `TextDelta` per line, held together by `stream_owned`
/// so dropping the response body cancels the completion.
async fn answer(State(model): State<Arc<dyn TextModel>>) -> ResponseStream {
    let prompt = Prompt::new(ModelTier::Fast).user("What's the weather in San Francisco?");
    ResponseStream::new(stream_owned(model, prompt).map(|delta| {
        Ok::<_, Infallible>(Bytes::from(format!(
            "{}\n",
            serde_json::to_string(&delta.expect("the mock never fails a delta"))
                .expect("a delta serialises")
        )))
    }))
}

fn answer_router(model: Arc<dyn TextModel>) -> Router {
    Router::new().route("/answer", get(answer).with_state(model))
}

/// Serves the route on a real loopback socket.
async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service())
            .await
            .expect("serve runs");
    });
    addr
}

/// GETs the route through the production transport and returns its body.
async fn route_body(addr: SocketAddr) -> ByteStream {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("http://{addr}/answer"))
        .body(Bytes::new())
        .expect("a test request builds");
    let response = loopback_client()
        .send_streaming(request)
        .await
        .expect("the route answers");
    assert_eq!(response.status(), http::StatusCode::OK);
    response.into_body()
}

/// Pulls body frames until one full NDJSON line has arrived, and decodes it.
async fn next_delta(body: &mut ByteStream, buffer: &mut Vec<u8>) -> serde_json::Value {
    loop {
        if let Some(end) = buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<_> = buffer.drain(..=end).collect();
            return serde_json::from_slice(&line[..line.len() - 1]).expect("a delta line");
        }
        let frame = body
            .next()
            .await
            .expect("the route kept streaming")
            .expect("no transport error");
        buffer.extend_from_slice(&frame);
    }
}

/// The acceptance run both adapters walk: the route's first delta is out
/// before a byte of `close` exists — the provider still holds the
/// answer — and the release lets the rest through, assembling whole.
async fn first_delta_while_the_upstream_holds_the_rest(adapter: Adapter) {
    let (mock, rest) = mock_upstream(adapter, false).await;
    let addr = serve(answer_router(adapter.wired(mock))).await;
    let mut body = route_body(addr).await;
    let mut buffer = Vec::new();

    let mut delta = next_delta(&mut body, &mut buffer).await;
    assert_eq!(
        delta["type"].as_str(),
        Some(adapter.script().first_delta),
        "{delta}"
    );

    rest.release.send(()).expect("the mock is still held");
    let mut text = String::new();
    loop {
        match delta["type"].as_str() {
            Some("text") => {
                text.push_str(delta["data"].as_str().expect("text carries a string"));
            }
            Some("finish") => {
                assert_eq!(
                    delta["data"]["model"].as_str(),
                    Some("mock-model"),
                    "{delta}"
                );
                break;
            }
            _ => {}
        }
        delta = next_delta(&mut body, &mut buffer).await;
    }
    assert_eq!(text, ANSWER);
}

#[tokio::test]
async fn anthropic_deltas_leave_the_route_before_the_answer_exists() {
    first_delta_while_the_upstream_holds_the_rest(Adapter::Anthropic).await;
}

#[tokio::test]
async fn openai_deltas_leave_the_route_before_the_answer_exists() {
    first_delta_while_the_upstream_holds_the_rest(Adapter::OpenAi).await;
}

/// Dropping the route's response body is a disconnect the mock upstream
/// sees: the whole chain — client body, route, `stream_owned`, adapter
/// stream, upstream body — unwinds, so the provider stops answering
/// nobody is reading.
async fn dropping_disconnects(adapter: Adapter) {
    let (mock, rest) = mock_upstream(adapter, true).await;
    let addr = serve(answer_router(adapter.wired(mock))).await;
    let mut body = route_body(addr).await;
    let mut buffer = Vec::new();
    let _ = next_delta(&mut body, &mut buffer).await;
    drop(body);
    tokio::time::timeout(Duration::from_secs(5), rest.seen)
        .await
        .expect("the mock saw the disconnect within 5 s")
        .expect("the mock's write failed");
}

#[tokio::test]
async fn dropping_the_route_body_disconnects_the_anthropic_upstream() {
    dropping_disconnects(Adapter::Anthropic).await;
}

#[tokio::test]
async fn dropping_the_route_body_disconnects_the_openai_upstream() {
    dropping_disconnects(Adapter::OpenAi).await;
}

/// A transport whose streamed body is the given chunks, one simulated
/// second apart — no TCP, so under `start_paused` the seconds cost
/// microseconds while remaining as real to the bounds as any server.
struct PacedSse {
    chunks: Vec<Bytes>,
    gap: Duration,
}

#[async_trait]
impl HttpClient for PacedSse {
    async fn send(&self, _: http::Request<Bytes>) -> Result<http::Response<Bytes>, HttpError> {
        Ok(http::Response::new(Bytes::new()))
    }

    async fn send_streaming(
        &self,
        _: http::Request<Bytes>,
    ) -> Result<http::Response<ByteStream>, HttpError> {
        let gap = self.gap;
        let body: ByteStream = Box::pin(futures_util::stream::iter(self.chunks.clone()).then(
            move |chunk| async move {
                tokio::time::sleep(gap).await;
                Ok(chunk)
            },
        ));
        Ok(http::Response::new(body))
    }
}

fn text_delta_event(text: &str) -> Bytes {
    Bytes::from(format!(
        "event: content_block_delta\n\
         data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{text}\"}}}}\n\n"
    ))
}

/// A completion that takes over thirty simulated seconds to stream
/// arrives whole: the fake transport spaces the recorded events one
/// simulated second apart, `BoundedHttpClient` bounds them the
/// production way, and the adapter folds every one. `TokioClock::now`
/// is the real wall clock, so the total ceiling sees only the
/// microseconds `start_paused` leaves behind — the production wiring,
/// not a shortened policy.
#[tokio::test(start_paused = true)]
async fn a_completion_longer_than_thirty_seconds_arrives_whole() {
    // Forty text runs one simulated second apart, then the block's
    // close: forty-three seconds of body, far past the 30 s head a
    // buffered call is answered under.
    let mut chunks = vec![Bytes::from(ANTHROPIC_OPEN.to_owned())];
    chunks.extend((1..=40).map(|word| text_delta_event(&format!("word{word} "))));
    chunks.push(Bytes::from(ANTHROPIC_CLOSE.to_owned()));
    let model = Anthropic::new(
        Arc::new(BoundedHttpClient::new(
            Arc::new(PacedSse {
                chunks,
                gap: Duration::from_secs(1),
            }),
            Arc::new(TokioClock),
        )),
        Arc::new(TokioClock),
        Some(DUMMY_ANTHROPIC_KEY.to_owned()),
        "mock-model",
    );

    let prompt = Prompt::new(ModelTier::Fast).user("What's the weather in San Francisco?");
    let mut stream = model.stream(&prompt);
    let mut builder = CompletionBuilder::default();
    let started = tokio::time::Instant::now();
    while let Some(delta) = stream.next().await {
        builder.push(&delta.expect("the paced stream never fails"));
    }
    let completion = builder.finish();

    let mut expected = String::from("The current weather");
    for word in 1..=40 {
        let _ = write!(expected, "word{word} ");
    }
    expected.push_str(" in San Francisco is 15 degrees.");
    assert_eq!(completion.text, expected, "every run arrived");
    assert_eq!(completion.model, "mock-model");
    assert_eq!((completion.input_tokens, completion.output_tokens), (6, 9));
    assert!(
        started.elapsed() >= Duration::from_secs(39),
        "the whole simulated exchange ran past the buffered cap: {:?}",
        started.elapsed()
    );
}
