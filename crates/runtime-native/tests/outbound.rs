//! End-to-end outbound bounds (issue #136): a hand-rolled mock server
//! that misbehaves on purpose — over-long declared bodies, chunked bodies
//! that keep coming, answers that never come, redirects into the cloud
//! metadata range — and the hardened `ReqwestClient` that refuses them.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cratefield_core::{HttpClient, HttpError, HttpPolicy};
use cratefield_runtime_native::{OutboundOptions, ReqwestClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

/// What the mock server saw on the wire.
struct Incoming {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

/// Accepts connections forever; each connection carries exactly one
/// request, answered with the responder's raw bytes and closed.
async fn mock(responder: impl Fn(&Incoming) -> Vec<u8> + Send + Sync + 'static) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("mock binds");
    let addr = listener.local_addr().expect("mock addr");
    let responder = Arc::new(responder);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let responder = Arc::clone(&responder);
            tokio::spawn(async move {
                if let Some(request) = read_request(&mut socket).await {
                    let _ = socket.write_all(&responder(&request)).await;
                    let _ = socket.flush().await;
                }
            });
        }
    });
    addr
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

fn ok(body: &[u8]) -> Vec<u8> {
    response(
        "200 OK",
        &[("Content-Length", body.len().to_string())],
        body,
    )
}

fn chunked(chunks: &[&[u8]]) -> Vec<u8> {
    let mut out =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for chunk in chunks {
        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

fn probe(addr: SocketAddr, policy: HttpPolicy) -> http::Request<Bytes> {
    let mut request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("http://{addr}/probe"))
        .body(Bytes::new())
        .expect("test request");
    request.extensions_mut().insert(policy);
    request
}

fn loopback_allows() -> OutboundOptions {
    OutboundOptions {
        allow_loopback: true,
        ..Default::default()
    }
}

fn policy(max_bytes: usize, timeout: Duration) -> HttpPolicy {
    HttpPolicy {
        max_response_bytes: max_bytes,
        timeout,
    }
}

fn transport_detail(err: &HttpError) -> String {
    match err {
        HttpError::Transport(detail) => detail.clone(),
        other => other.to_string(),
    }
}

#[tokio::test]
async fn an_oversized_declared_length_is_refused() {
    let addr = mock(|_| response("200 OK", &[("Content-Length", "9000".to_owned())], b"hi")).await;
    let client = ReqwestClient::with_options(loopback_allows());
    let err = client
        .send(probe(addr, policy(1024, Duration::from_secs(5))))
        .await
        .expect_err("a declared 9 KB over a 1 KiB cap must be refused");
    assert!(
        matches!(err, HttpError::ResponseTooLarge { limit: 1024 }),
        "{err}"
    );
}

#[tokio::test]
async fn an_oversized_chunked_body_is_refused_mid_stream() {
    // No Content-Length to lean on: the cap has to hold while streaming.
    let big = vec![7u8; 900];
    let addr = mock(move |incoming| {
        assert_eq!(incoming.target, "/probe");
        chunked(&[&big, &big])
    })
    .await;
    let client = ReqwestClient::with_options(loopback_allows());
    let err = client
        .send(probe(addr, policy(1024, Duration::from_secs(5))))
        .await
        .expect_err("900 + 900 bytes over a 1 KiB cap must be refused");
    assert!(
        matches!(err, HttpError::ResponseTooLarge { limit: 1024 }),
        "{err}"
    );
}

#[tokio::test]
async fn a_server_that_never_answers_hits_the_deadline() {
    // Connected into the kernel backlog, never accepted: the client must
    // stop at its deadline rather than hang (issue #136).
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = ReqwestClient::with_options(loopback_allows());
    let err = client
        .send(probe(addr, policy(1024, Duration::from_millis(250))))
        .await
        .expect_err("a silent server must end in a deadline");
    assert!(
        matches!(err, HttpError::DeadlineExceeded { after } if after == Duration::from_millis(250)),
        "{err}"
    );
    drop(listener);
}

#[tokio::test]
async fn the_hardened_client_refuses_its_own_host_and_the_metadata_range() {
    let addr = mock(|_| ok(b"never served")).await;
    let client = ReqwestClient::new();
    let err = client
        .send(probe(addr, policy(1024, Duration::from_secs(5))))
        .await
        .expect_err("loopback must be refused without the opt-in");
    assert!(matches!(err, HttpError::BlockedDestination(_)), "{err}");
    let metadata: http::Request<Bytes> = http::Request::builder()
        .uri("http://169.254.169.254/latest/meta-data/")
        .body(Bytes::new())
        .expect("test request");
    let err = client
        .send(metadata)
        .await
        .expect_err("the metadata endpoint must be refused before any connect");
    assert!(matches!(err, HttpError::BlockedDestination(_)), "{err}");
}

#[tokio::test]
async fn a_foreign_scheme_is_refused_before_any_connect() {
    let client = ReqwestClient::new();
    let err = client
        .send(
            http::Request::builder()
                .uri("gopher://127.0.0.1:6379/")
                .body(Bytes::new())
                .expect("test request"),
        )
        .await
        .expect_err("gopher:// is not a destination");
    assert!(matches!(err, HttpError::BlockedDestination(_)), "{err}");
}

#[tokio::test]
async fn a_redirect_into_the_metadata_range_is_refused() {
    let addr = mock(|_| {
        response(
            "302 Found",
            &[(
                "Location",
                "http://169.254.169.254/latest/meta-data/".to_owned(),
            )],
            b"",
        )
    })
    .await;
    let client = ReqwestClient::with_options(loopback_allows());
    let err = client
        .send(probe(addr, policy(1024, Duration::from_secs(5))))
        .await
        .expect_err("a hop into the metadata range must be refused");
    assert!(matches!(err, HttpError::BlockedDestination(_)), "{err}");
}

#[tokio::test]
async fn a_cross_origin_redirect_is_followed_with_credentials_stripped() {
    // The mock's authority (port) changes between hops, so the
    // Authorization header must not ride along (issue #136).
    let final_addr = mock(|incoming| {
        let auth = incoming
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map_or_else(|| "none".to_owned(), |(_, value)| value.clone());
        ok(format!("auth={auth}; via={}", incoming.target).as_bytes())
    })
    .await;
    let first_addr = mock(move |incoming| {
        assert_eq!(incoming.method, "GET");
        response(
            "302 Found",
            &[("Location", format!("http://{final_addr}/final"))],
            b"",
        )
    })
    .await;
    let client = ReqwestClient::with_options(loopback_allows());
    let mut request = probe(first_addr, policy(1024, Duration::from_secs(5)));
    request.headers_mut().insert(
        "authorization",
        "Bearer s3cret".parse().expect("test header"),
    );
    let response = client.send(request).await.expect("redirect followed");
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = String::from_utf8(response.body().to_vec()).expect("utf-8 body");
    assert_eq!(body, "auth=none; via=/final");
}

#[tokio::test]
async fn the_concurrency_budget_refuses_instead_of_queueing() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (gate, release) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        if read_request(&mut socket).await.is_some() {
            let _ = release.await;
            let _ = socket.write_all(&ok(b"late")).await;
            let _ = socket.flush().await;
        }
    });
    let client = Arc::new(ReqwestClient::with_options(OutboundOptions {
        allow_loopback: true,
        max_concurrent: 1,
    }));
    let busy = {
        let client = Arc::clone(&client);
        tokio::spawn(async move { client.send(probe(addr, loopback_policy())).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second = client
        .send(probe(addr, loopback_policy()))
        .await
        .expect_err("the second request must be refused, not queued");
    assert!(
        transport_detail(&second).contains("budget exhausted"),
        "{second}"
    );
    gate.send(()).expect("release the gate");
    busy.await
        .expect("first send task")
        .expect("the permitted request completes");
}

fn loopback_policy() -> HttpPolicy {
    policy(64 * 1024, Duration::from_secs(5))
}

#[tokio::test]
async fn requests_without_a_policy_get_the_port_defaults() {
    let body = vec![7u8; 1024 * 1024];
    let addr = mock(move |_| ok(&body)).await;
    let client = ReqwestClient::with_options(loopback_allows());
    let request = http::Request::builder()
        .uri(format!("http://{addr}/one-mebibyte"))
        .body(Bytes::new())
        .expect("test request");
    let response = client.send(request).await.expect("1 MiB is under the cap");
    assert_eq!(response.body().len(), 1024 * 1024);
}
