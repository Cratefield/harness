//! End-to-end streamed responses (issue #859): a raw-TCP server that
//! answers a chunked SSE-shaped body under the test's control, and the
//! `ReqwestClient` + `BoundedHttpClient` pair that streams it — chunks
//! arriving while the upstream still holds the rest, a dropped stream
//! surfacing as a disconnect the server can see, and a body that keeps
//! arriving well past the 30 s buffered deadline.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{BoundedHttpClient, ByteStream, HttpClient, HttpError, StreamPolicy};
use cratefield_runtime_native::{OutboundOptions, ReqwestClient, TokioClock};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the mock server saw on the wire.
struct Incoming {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

async fn read_request(socket: &mut TcpStream) -> Option<Incoming> {
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

fn parse_request(buffer: &[u8]) -> Option<Incoming> {
    let head_end = buffer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buffer[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_owned();
    let target = request_line.next()?.to_owned();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().unwrap_or(0);
        }
        headers.push((name, value.trim().to_owned()));
    }
    // The body must have arrived too, or a pipelined answer races the read.
    if buffer.len() < head_end + 4 + content_length {
        return None;
    }
    Some(Incoming {
        method,
        target,
        headers,
    })
}

fn response(status: &str, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// The head of a chunked, streamed answer: no declared length, and the
/// connection stays open after it — the server decides when (or whether)
/// the body ever ends.
fn stream_head(content_type: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes()
}

/// Writes one chunked-body chunk onto an open connection.
async fn write_chunk(socket: &mut TcpStream, chunk: &[u8]) -> std::io::Result<()> {
    socket
        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
        .await?;
    socket.write_all(chunk).await?;
    socket.write_all(b"\r\n").await?;
    socket.flush().await
}

/// The terminal chunk of a chunked body.
async fn write_end(socket: &mut TcpStream) -> std::io::Result<()> {
    socket.write_all(b"0\r\n\r\n").await?;
    socket.flush().await
}

/// One SSE-shaped event: the shape a streamed model completion carries.
fn sse(event: &str) -> Vec<u8> {
    format!("data: {event}\n\n").into_bytes()
}

fn bounded_client(max_concurrent: usize) -> BoundedHttpClient {
    BoundedHttpClient::new(
        Arc::new(ReqwestClient::with_options(OutboundOptions {
            allow_loopback: true,
            max_concurrent,
        })),
        Arc::new(TokioClock),
    )
}

fn stream_request(uri: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(Bytes::new())
        .expect("test request")
}

fn addr_request(addr: SocketAddr, path: &str) -> http::Request<Bytes> {
    stream_request(&format!("http://{addr}{path}"))
}

fn transport_detail(err: &HttpError) -> String {
    match err {
        HttpError::Transport(detail) => detail.clone(),
        other => other.to_string(),
    }
}

/// An in-process client whose streamed body paces itself with tokio
/// sleeps — no TCP anywhere, so under `start_paused` the seconds cost
/// microseconds while remaining as real to the bounds as any server.
struct PacedClient {
    chunks: usize,
    gap: Duration,
}

#[async_trait]
impl HttpClient for PacedClient {
    async fn send(
        &self,
        _request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        Ok(http::Response::new(Bytes::new()))
    }

    async fn send_streaming(
        &self,
        _request: http::Request<Bytes>,
    ) -> Result<http::Response<ByteStream>, HttpError> {
        let gap = self.gap;
        let body: ByteStream = Box::pin(futures_util::stream::iter(0..self.chunks).then(
            move |i| async move {
                tokio::time::sleep(gap).await;
                Ok(Bytes::from(format!("chunk {i}\n")))
            },
        ));
        Ok(http::Response::new(body))
    }
}

#[tokio::test]
async fn the_first_chunk_arrives_while_the_server_still_holds_the_rest() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (send_rest, rest) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let request = read_request(&mut socket).await.expect("a request");
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/stream");
        assert!(
            request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("host")),
            "an ordinary GET arrived"
        );
        let _ = socket.write_all(&stream_head("text/event-stream")).await;
        write_chunk(&mut socket, &sse("first"))
            .await
            .expect("first chunk written");
        // Nothing more goes on the wire until the test says so: whatever
        // the client reads past this point, it read while the server
        // sat waiting.
        rest.await.expect("the test still runs");
        write_chunk(&mut socket, &sse("second"))
            .await
            .expect("second chunk written");
        write_end(&mut socket).await.expect("end written");
    });

    let client = bounded_client(32);
    let response = client
        .send_streaming(addr_request(addr, "/stream"))
        .await
        .expect("the head answers");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(http::HeaderValue::as_bytes),
        Some(&b"text/event-stream"[..]),
    );
    let mut body = response.into_body();
    assert_eq!(
        &*body.next().await.expect("first chunk").expect("ok"),
        &sse("first")[..]
    );
    send_rest.send(()).expect("release the server");
    assert_eq!(
        &*body.next().await.expect("second chunk").expect("ok"),
        &sse("second")[..]
    );
    assert!(
        body.next().await.is_none(),
        "the terminal chunk ends the body"
    );
}

#[tokio::test]
async fn a_dropped_stream_is_a_disconnect_the_server_sees() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (report_disconnect, seen) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        read_request(&mut socket).await.expect("a request");
        let _ = socket.write_all(&stream_head("text/event-stream")).await;
        write_chunk(&mut socket, &sse("only"))
            .await
            .expect("first chunk written");
        // A small chunk every 20 ms: a client that stopped reading must
        // turn this into a failed write within seconds, not keep a
        // silent socket for the body's whole ceiling.
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if write_chunk(&mut socket, b"tick").await.is_err() {
                let _ = report_disconnect.send(());
                break;
            }
        }
    });

    let client = bounded_client(32);
    let response = client
        .send_streaming(addr_request(addr, "/stream"))
        .await
        .expect("the head answers");
    let mut body = response.into_body();
    body.next().await.expect("first chunk").expect("ok");
    // The cancellation contract: dropping the body aborts the exchange.
    drop(body);

    tokio::time::timeout(Duration::from_secs(5), seen)
        .await
        .expect("the server noticed the disconnect within 5 s")
        .expect("the server's write failed");
}

#[tokio::test(start_paused = true)]
async fn a_steady_stream_outlives_the_buffered_deadline() {
    // Forty one-second gaps: forty simulated seconds, far past the 30 s
    // ceiling a buffered send answers under, delivered whole because the
    // body is governed by the stream bounds instead.
    let client = BoundedHttpClient::new(
        Arc::new(PacedClient {
            chunks: 40,
            gap: Duration::from_secs(1),
        }),
        Arc::new(TokioClock),
    );
    let started = tokio::time::Instant::now();
    let response = client
        .send_streaming(stream_request("http://paced.test/stream"))
        .await
        .expect("the head answers");
    let mut body = response.into_body();
    for i in 0..40 {
        let chunk = body
            .next()
            .await
            .unwrap_or_else(|| panic!("chunk {i} never arrived"))
            .expect("a paced chunk is not an error");
        assert_eq!(&*chunk, format!("chunk {i}\n").as_bytes(), "chunk {i}");
    }
    assert!(
        body.next().await.is_none(),
        "a clean end after the last chunk"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(39),
        "the whole simulated exchange ran past the buffered cap: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_gap_past_the_idle_timeout_abandons_the_body() {
    let client = BoundedHttpClient::new(
        Arc::new(PacedClient {
            chunks: 3,
            gap: Duration::from_millis(200),
        }),
        Arc::new(TokioClock),
    );
    let mut request = stream_request("http://paced.test/stream");
    request.extensions_mut().insert(StreamPolicy {
        idle_timeout: Duration::from_millis(50),
        total_timeout: Duration::from_secs(30),
        max_bytes: 64 * 1024,
    });
    let response = client
        .send_streaming(request)
        .await
        .expect("the head answers");
    let mut body = response.into_body();
    let err = body
        .next()
        .await
        .expect("a terminal error, not silence")
        .expect_err("a 200 ms gap is past the 50 ms idle bound");
    assert!(
        matches!(err, HttpError::DeadlineExceeded { after } if after == Duration::from_millis(50)),
        "the idle bound is what expired: {err}"
    );
    assert!(body.next().await.is_none(), "fused after the error");
}

#[tokio::test]
async fn a_steady_stream_still_meets_its_total_ceiling() {
    let client = BoundedHttpClient::new(
        Arc::new(PacedClient {
            chunks: 20,
            gap: Duration::from_millis(20),
        }),
        Arc::new(TokioClock),
    );
    let mut request = stream_request("http://paced.test/stream");
    request.extensions_mut().insert(StreamPolicy {
        idle_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_millis(50),
        max_bytes: 64 * 1024,
    });
    let response = client
        .send_streaming(request)
        .await
        .expect("the head answers");
    let mut body = response.into_body();
    let mut delivered = 0;
    let terminal = loop {
        match body.next().await {
            Some(Ok(_)) => delivered += 1,
            Some(Err(err)) => break err,
            None => panic!("the ceiling ends the body, not a clean stream end"),
        }
    };
    assert!(
        matches!(terminal, HttpError::DeadlineExceeded { after } if after <= Duration::from_millis(50)),
        "a total-shaped deadline is what expired: {terminal}"
    );
    assert!(
        delivered < 20,
        "the ceiling stopped a stream that kept arriving: {delivered} chunks"
    );
}

#[tokio::test]
async fn a_dropped_stream_releases_the_concurrency_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (finish, let_go) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        // The first exchange gets a head and one chunk, then the
        // connection is held: the stream stays alive as long as this
        // task does.
        let (mut held, _) = listener.accept().await.expect("first connection");
        read_request(&mut held).await.expect("first request");
        let _ = held.write_all(&stream_head("text/event-stream")).await;
        write_chunk(&mut held, &sse("held"))
            .await
            .expect("first chunk written");
        // The second exchange is answered whole.
        let (mut done, _) = listener.accept().await.expect("second connection");
        read_request(&mut done).await.expect("second request");
        let _ = done
            .write_all(&response(
                "200 OK",
                &[("Content-Type", "text/plain".to_owned())],
                b"released",
            ))
            .await;
        let _ = done.flush().await;
        let _ = let_go.await;
    });

    let client = bounded_client(1);
    let live = client
        .send_streaming(addr_request(addr, "/held"))
        .await
        .expect("the head answers");
    let mut live_body = live.into_body();
    live_body.next().await.expect("first chunk").expect("ok");

    // The one permit is spent on the live stream: the next send is
    // refused, not queued. No `Debug` on a streaming response, so
    // `expect_err` cannot name this arm — a `match` refuses it just as
    // loudly.
    let refused = match client.send_streaming(addr_request(addr, "/second")).await {
        Ok(response) => {
            drop(response);
            panic!("the budget is spent on the live stream");
        }
        Err(err) => err,
    };
    assert!(
        transport_detail(&refused).contains("budget exhausted"),
        "{refused}"
    );

    // Dropping the stream drops the permit that rode in it.
    drop(live_body);
    let after = client
        .send_streaming(addr_request(addr, "/third"))
        .await
        .expect("the budget was released by the drop");
    let mut after_body = after.into_body();
    assert_eq!(
        &*after_body
            .next()
            .await
            .expect("the answered exchange streams")
            .expect("ok"),
        &b"released"[..]
    );
    finish.send(()).expect("done with the server");
}
