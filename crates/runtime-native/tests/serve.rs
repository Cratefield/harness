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
use factory0_adapter_sqlite::SqliteDatabase;
use factory0_core::{
    Config, ConfigError, Harness, HttpClient, Json, Migrations, Module, ModuleContext, Port,
    Venture,
};
use factory0_runtime_native::{Native, ReqwestClient, serve_on};
use serde_json::Value;

/// A module whose one route answers with exactly what
/// `factory0_core::client_ip` sees — the sanitization oracle. Requires
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
        "client_ip": factory0_core::client_ip(&headers),
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

    let client = ReqwestClient::new();

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
