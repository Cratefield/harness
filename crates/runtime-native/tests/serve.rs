//! End-to-end server tests (issue #19): a real `TcpListener` on an
//! ephemeral port, real HTTP through the crate's own `ReqwestClient`,
//! SQLite behind the `Database` port — `/__health`, `/__ready`, and the
//! client-IP sanitization a module actually observes.
//!
//! Redis-backed tests live in `tests/redis.rs` and are gated on
//! `FZ_TEST_REDIS_URL`.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{
    Config, ConfigError, Harness, HttpClient, Json, Migrations, Module, ModuleContext, Port,
    Venture,
};
use cratefield_runtime_native::{Native, OutboundOptions, ReqwestClient, serve_on};
use serde_json::Value;

/// A module whose one route answers with exactly what
/// `cratefield_core::client_ip` sees — the sanitization oracle. Requires
/// the `Database` port so `/__ready` has something to probe.
struct IpEchoModule;

impl Module for IpEchoModule {
    fn name(&self) -> &'static str {
        "ip-echo"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ctx);
        axum::Router::new().route("/ip", get(echo_ip).with_state(Arc::clone(&state)))
    }
}

async fn echo_ip(
    headers: axum::http::HeaderMap,
    State(_ctx): State<Arc<ModuleContext>>,
) -> Json<Value> {
    Json(serde_json::json!({
        "client_ip": cratefield_core::client_ip(&headers),
        "raw_xff": headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok()),
    }))
}

async fn http_get(
    client: &ReqwestClient,
    url: &str,
) -> Result<http::Response<bytes::Bytes>, String> {
    let request = http::Request::builder()
        .uri(url)
        .body(bytes::Bytes::new())
        .expect("GET request builds");
    client.send(request).await.map_err(|err| err.to_string())
}

async fn get_until_ready(client: &ReqwestClient, url: &str) -> http::Response<bytes::Bytes> {
    for _ in 0..50 {
        if let Ok(response) = http_get(client, url).await
            && response.status() == 200
        {
            return response;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("server never answered {url}");
}

#[tokio::test]
async fn serves_health_ready_and_spoofed_headers_go_nowhere() {
    let sqlite = Arc::new(SqliteDatabase::open(":memory:").expect("in-memory sqlite"));
    let runtime = Native::new().db_arc(sqlite);
    let harness = Arc::new(
        Harness::builder()
            .venture(
                Venture::new("test-venture", "test.example")
                    .public_url("https://test.example")
                    .cors_origins(["https://test.example"]),
            )
            .module(IpEchoModule)
            .runtime(runtime.clone())
            .build()
            .expect("harness is valid"),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        let _ = serve_on(harness, runtime, listener).await;
    });

    // The client under test probes this process's own loopback listener,
    // which the hardened default refuses (issue #136) — the explicit
    // opt-in is the sanctioned way a self-hosted caller says so.
    let client = ReqwestClient::with_options(OutboundOptions {
        allow_loopback: true,
        ..Default::default()
    });

    let health = get_until_ready(&client, &format!("http://{addr}/__health")).await;
    let body: Value = serde_json::from_slice(health.body()).expect("health is JSON");
    assert_eq!(body["venture"], "test-venture");
    assert_eq!(body["modules"][0]["name"], "ip-echo");
    assert!(body["harness_api"].is_number());
    assert!(
        health.headers().contains_key("x-request-id"),
        "every response carries a request id"
    );

    let ready = http_get(&client, &format!("http://{addr}/__ready"))
        .await
        .expect("ready probe succeeds");
    assert_eq!(ready.status(), 200);
    let body: Value = serde_json::from_slice(ready.body()).expect("ready is JSON");
    assert_eq!(body["ok"], true);

    // The UI surface is served on the native runtime too (ADR 0010); the
    // module declares none, so the document lists no modules.
    let surface = http_get(&client, &format!("http://{addr}/__surface"))
        .await
        .expect("surface succeeds");
    assert_eq!(surface.status(), 200);
    assert!(surface.headers().contains_key("etag"));
    let body: Value = serde_json::from_slice(surface.body()).expect("surface is JSON");
    assert_eq!(body["surface_api"], 1);
    assert_eq!(body["modules"].as_array().map(Vec::len), Some(0));

    // The sanitization oracle: the client sends a forged x-forwarded-for
    // (and cf-connecting-ip), TRUSTED_PROXY_HEADERS is unset, so the
    // module must see the loopback peer and no trace of either header.
    let request = http::Request::builder()
        .uri(format!("http://{addr}/v1/ip-echo/ip"))
        .header("x-forwarded-for", "6.6.6.6, 7.7.7.7")
        .header("cf-connecting-ip", "9.9.9.9")
        .body(bytes::Bytes::new())
        .expect("request builds");
    let response = client.send(request).await.expect("echo succeeds");
    assert_eq!(response.status(), 200);
    let body: Value = serde_json::from_slice(response.body()).expect("echo is JSON");
    assert_eq!(body["client_ip"], "127.0.0.1");
    assert_eq!(body["raw_xff"], Value::Null);

    server.abort();
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Sends one request with the given `Host` and returns its status line.
async fn status_for_host(addr: std::net::SocketAddr, host: &str) -> String {
    for _ in 0..50 {
        let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await else {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            continue;
        };
        let request =
            format!("GET /__health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        if stream.write_all(request.as_bytes()).await.is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            continue;
        }
        let mut answer = Vec::new();
        if stream.read_to_end(&mut answer).await.is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            continue;
        }
        let text = String::from_utf8_lossy(&answer);
        if let Some(line) = text.lines().next() {
            return line.to_owned();
        }
    }
    panic!("server never answered");
}

/// Issue #129. A native process answered whatever `Host` a caller sent,
/// and `Host` is the key ADR 0008's database-per-tenant resolution reads
/// once phase three lands — so an unvalidated one is a link-forgery and
/// cache-poisoning vector now and the cross-tenant vector then.
///
/// Driven over a raw socket rather than through a client library, because
/// the assertion is about the exact bytes on the wire: a `Host` header
/// naming another venture must not be served, whatever a client would
/// normally put there.
#[tokio::test]
async fn a_production_deployment_refuses_another_ventures_host() {
    let sqlite = Arc::new(SqliteDatabase::open(":memory:").expect("in-memory sqlite"));
    let runtime = Native::new().db_arc(sqlite);
    let harness = Arc::new(
        Harness::builder()
            .venture(
                Venture::new("tenant-a", "tenant-a.example")
                    .public_url("https://tenant-a.example")
                    .cors_origins(["https://tenant-a.example"])
                    // Compiled as production so the gate enforces without
                    // mutating this process's environment, which the rest
                    // of the suite shares.
                    .env(cratefield_core::VentureEnv::Production),
            )
            .module(IpEchoModule)
            .runtime(runtime.clone())
            .build()
            .expect("harness is valid"),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        let _ = serve_on(harness, runtime, listener).await;
    });

    // Its own host is served.
    let own = status_for_host(addr, "tenant-a.example").await;
    assert!(own.contains("200"), "own host must be served: {own}");

    // Another venture's host is refused, before any handler runs.
    let foreign = status_for_host(addr, "tenant-b.example").await;
    assert!(
        foreign.contains("421"),
        "a neighbour's host must be refused: {foreign}"
    );

    // A lookalike is not a match either.
    let lookalike = status_for_host(addr, "tenant-a.example.evil.test").await;
    assert!(
        lookalike.contains("421"),
        "a suffix lookalike must be refused: {lookalike}"
    );

    // And the loopback probe keeps working, or the deployment is
    // unmonitorable.
    let probe = status_for_host(addr, &addr.to_string()).await;
    assert!(probe.contains("200"), "loopback probe must work: {probe}");

    server.abort();
}
