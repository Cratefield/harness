//! Opt-in streamed bodies (issue #585): a route a module names in
//! `streaming_routes()` gets its body as a [`RequestStream`] with the
//! route's own ceiling enforced chunk by chunk, may answer with a
//! [`ResponseStream`], and keeps every other property of a route — the
//! request id, CORS, a guard, and the buffered ceiling on everything it did
//! not declare.

mod common;

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use common::*;
use cratefield_core::{
    ApiKeys, Config, ConfigError, Harness, Json, Migrations, Module, ModuleContext, Port, Ports,
    Problem, RandomBytes, RandomError, RequestStream, ResponseStream, StreamRoute, SystemClock,
    require_api_key,
};
use futures_core::Stream;
use serde_json::json;
use tower::ServiceExt;

/// The streamed routes this module serves. A `static` so `router()` and
/// `streaming_routes()` name one slice, the way the migrations do.
///
/// `/upload` has a ceiling far above the buffered default (the whole point:
/// a body larger than 64 KiB); `/tiny` is small so a few chunks cross it and
/// the mid-stream refusal is observable; `/download` streams a response with
/// no request body; `/guarded` is behind an API key; the two `/files` routes
/// exist for the pattern-matching tests.
static ROUTES: &[StreamRoute] = &[
    StreamRoute::post("/upload", 2 * 1024 * 1024),
    StreamRoute::post("/tiny", 8),
    StreamRoute::get("/download", 2 * 1024 * 1024),
    StreamRoute::post("/guarded", 1024),
    StreamRoute::get("/files/{id}", 1024),
    StreamRoute::put("/files/{*rest}", 4 * 1024 * 1024),
];

struct StreamyModule {
    completed: Arc<AtomicUsize>,
}

impl Module for StreamyModule {
    fn name(&self) -> &'static str {
        "streamz"
    }
    fn version(&self) -> &'static str {
        "0.0.0-test"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn streaming_routes(&self) -> &'static [StreamRoute] {
        ROUTES
    }
    fn router(&self, _: ModuleContext) -> Router {
        // The key store is a `FailingDb` on purpose: a request with no
        // bearer must be refused before the store is ever consulted, so a
        // key-store failure here would be the bug this test would catch.
        let store = Arc::new(ApiKeys::new(
            Arc::new(FailingDb),
            Arc::new(SystemClock),
            Arc::new(ZeroBytes),
            "api_keys",
        ));
        let completed = Arc::clone(&self.completed);
        Router::new()
            .route(
                "/upload",
                axum::routing::post(upload).with_state(Arc::clone(&completed)),
            )
            .route(
                "/tiny",
                axum::routing::post(upload).with_state(Arc::clone(&completed)),
            )
            .route("/download", axum::routing::get(download))
            .route("/guarded", axum::routing::post(guarded).with_state(store))
    }
}

/// An entropy source that is never drawn from (the guard refuses first).
struct ZeroBytes;

impl RandomBytes for ZeroBytes {
    fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        dest.fill(0);
        Ok(())
    }
}

/// Drains the request stream, counts the bytes, and only then records that
/// an upload finished — so a stream refused mid-way leaves the count at
/// zero, which is what "no side effect past the abort" means.
async fn upload(State(completed): State<Arc<AtomicUsize>>, mut stream: RequestStream) -> Response {
    let mut total = 0usize;
    loop {
        match stream.next_chunk().await {
            Some(Ok(chunk)) => total += chunk.len(),
            Some(Err(error)) => return Problem::from(error).into_response(),
            None => break,
        }
    }
    completed.fetch_add(1, Ordering::Relaxed);
    Json(json!({ "bytes": total })).into_response()
}

/// A 4 MiB streamed response, in four 1 MiB chunks.
async fn download() -> ResponseStream {
    let block = Bytes::from(vec![b'x'; 1024 * 1024]);
    let chunks: Vec<Bytes> = (0..4).map(|_| block.clone()).collect();
    ResponseStream::new(Chunks(chunks.into_iter()))
}

/// A streaming route behind an API key: the guard runs before a byte of the
/// body is read, and a missing key is refused without touching the store.
async fn guarded(
    State(store): State<Arc<ApiKeys>>,
    headers: HeaderMap,
    mut stream: RequestStream,
) -> Response {
    if let Err(problem) = require_api_key(&store, &headers, "write").await {
        return problem.into_response();
    }
    while let Some(item) = stream.next_chunk().await {
        if let Err(error) = item {
            return Problem::from(error).into_response();
        }
    }
    Json(json!({ "ok": true })).into_response()
}

/// A `Send` chunk stream over a `Vec<Bytes>`: the kit has no `futures-util`,
/// and a test needs nothing more than this.
struct Chunks(std::vec::IntoIter<Bytes>);

impl Stream for Chunks {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.get_mut().0.next().map(Ok))
    }
}

fn stream_harness() -> (Harness, Arc<AtomicUsize>) {
    let completed = Arc::new(AtomicUsize::new(0));
    let harness = Harness::builder()
        .venture(base_venture())
        .module(StreamyModule {
            completed: Arc::clone(&completed),
        })
        .runtime(FakeRuntime(all_ports()))
        .build()
        .expect("streamy harness builds");
    (harness, completed)
}

/// A request whose body is the given chunks with **no** `content-length`:
/// the shape that exercises the mid-stream ceiling rather than the declared
/// pre-check.
async fn chunked(router: &Router, method: Method, path: &str, chunks: Vec<Bytes>) -> Response {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(axum::body::Body::from_stream(Chunks(chunks.into_iter())))
        .expect("request builds");
    router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers")
}

#[pollster::test]
async fn a_chunked_body_larger_than_the_buffered_ceiling_streams_through() {
    let (harness, completed) = stream_harness();
    let router = harness.router(Ports::empty());
    // 1 MiB in sixteen 64 KiB chunks — sixteen times MAX_BODY_BYTES, which
    // a buffered route would refuse.
    let chunks: Vec<Bytes> = (0..16).map(|_| Bytes::from(vec![0u8; 65_536])).collect();
    let response = chunked(&router, Method::POST, "/v1/streamz/upload", chunks).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["bytes"], 16 * 65_536);
    assert_eq!(completed.load(Ordering::Relaxed), 1);
}

#[pollster::test]
async fn a_declared_content_length_over_the_route_ceiling_is_refused_before_the_handler() {
    let (harness, completed) = stream_harness();
    let router = harness.router(Ports::empty());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/streamz/tiny")
        .header(header::CONTENT_LENGTH, "2048")
        .body(axum::body::Body::from(vec![0u8; 2048]))
        .expect("request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let problem = body_json(response).await;
    // The 413 is decorated like any other problem: named under the venture's
    // own base by the outermost layer.
    assert_eq!(
        problem["type"],
        "https://test.example/problems/request-too-large"
    );
    assert_eq!(completed.load(Ordering::Relaxed), 0, "handler never ran");
}

#[pollster::test]
async fn a_chunk_crossing_the_ceiling_mid_stream_is_refused_and_aborts() {
    let (harness, completed) = stream_harness();
    let router = harness.router(Ports::empty());
    // 8 is the ceiling; 4 + 4 fits, the third 4 crosses it and is refused.
    let chunks = vec![
        Bytes::from_static(b"1234"),
        Bytes::from_static(b"5678"),
        Bytes::from_static(b"more"),
    ];
    let response = chunked(&router, Method::POST, "/v1/streamz/tiny", chunks).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        completed.load(Ordering::Relaxed),
        0,
        "no side effect past the abort"
    );
}

#[pollster::test]
async fn a_body_exactly_at_the_ceiling_streams_cleanly() {
    let (harness, completed) = stream_harness();
    let router = harness.router(Ports::empty());
    let chunks = vec![Bytes::from_static(b"1234"), Bytes::from_static(b"5678")];
    let response = chunked(&router, Method::POST, "/v1/streamz/tiny", chunks).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(completed.load(Ordering::Relaxed), 1);
}

#[pollster::test]
async fn a_streamed_response_larger_than_the_buffered_ceiling_reaches_the_wire() {
    let (harness, _) = stream_harness();
    let router = harness.router(Ports::empty());
    let response = request(&router, Method::GET, "/v1/streamz/download", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_parts().1, 16 * 1024 * 1024)
        .await
        .expect("body reads");
    assert_eq!(bytes.len(), 4 * 1024 * 1024);
    assert!(bytes.iter().all(|byte| *byte == b'x'));
}

#[pollster::test]
async fn a_streaming_route_keeps_the_request_id_and_cors_headers() {
    let (harness, _) = stream_harness();
    let router = harness.router(Ports::empty());
    let response = request(
        &router,
        Method::GET,
        "/v1/streamz/download",
        &[
            ("origin", "https://test.example"),
            ("x-request-id", "client-id-12345678"),
        ],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://test.example"
    );
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "client-id-12345678"
    );
}

#[pollster::test]
async fn a_guarded_streaming_route_refuses_without_a_key_and_never_reads_the_body() {
    let (harness, _) = stream_harness();
    let router = harness.router(Ports::empty());
    let response = chunked(
        &router,
        Method::POST,
        "/v1/streamz/guarded",
        vec![Bytes::from_static(b"anything")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(response).await["type"],
        "https://test.example/problems/api-key-unauthorized"
    );
}

#[pollster::test]
async fn an_undeclared_route_keeps_the_buffered_body_limit() {
    // `SampleModule`'s `/echo` takes a buffered `Json` body and declares no
    // streaming route, so the 64 KiB default still applies even to a
    // chunked upload: the streaming layer leaves the request untouched and
    // the `Json` extractor enforces the buffered ceiling.
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());
    let payload = format!("{{\"email\":\"{}\"}}", "a".repeat(70_000));
    let chunks: Vec<Bytes> = payload
        .into_bytes()
        .chunks(40_000)
        .map(Bytes::copy_from_slice)
        .collect();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/sample/echo")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from_stream(Chunks(chunks.into_iter())))
        .expect("request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn streaming_route_matches_literal_param_rest_and_method() {
    let (harness, _) = stream_harness();

    assert_eq!(
        harness.streaming_route("/v1/streamz/upload", &Method::POST),
        Some(2 * 1024 * 1024)
    );
    // A `{param}` segment takes exactly one, whatever it is.
    assert_eq!(
        harness.streaming_route("/v1/streamz/files/abc123", &Method::GET),
        Some(1024)
    );
    assert_eq!(
        harness.streaming_route("/v1/streamz/files", &Method::GET),
        None,
        "the param needs one segment"
    );
    // `{*rest}` takes the remaining one-or-more.
    assert_eq!(
        harness.streaming_route("/v1/streamz/files/a/b/c", &Method::PUT),
        Some(4 * 1024 * 1024)
    );
    assert_eq!(
        harness.streaming_route("/v1/streamz/files", &Method::PUT),
        None,
        "the rest needs at least one segment"
    );
    // Method and module both have to match.
    assert_eq!(
        harness.streaming_route("/v1/streamz/upload", &Method::GET),
        None
    );
    assert_eq!(
        harness.streaming_route("/v1/nowhere/upload", &Method::POST),
        None
    );
    // The declaration is a query/fragment-free path only.
    assert_eq!(
        harness.streaming_route("/v1/streamz/upload?part=1", &Method::POST),
        Some(2 * 1024 * 1024)
    );
    // The path is split exactly, not collapsed: a trailing or doubled slash
    // is a segment of its own, so it matches nothing — axum 404s such a path
    // rather than redirecting, and streaming must not claim it.
    assert_eq!(
        harness.streaming_route("/v1/streamz/upload/", &Method::POST),
        None,
        "a trailing slash is not the declared route"
    );
    assert_eq!(
        harness.streaming_route("/v1/streamz//upload", &Method::POST),
        None,
        "a doubled slash is not the declared route"
    );
    assert_eq!(
        harness.streaming_route("/v1/streamz/files/abc123/", &Method::GET),
        None,
        "a trailing slash leaves the param an extra segment"
    );
}
