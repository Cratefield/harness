//! Shared fixtures for core's integration tests (issue #2): a sample
//! module, fake ports, and a no-network request helper.

#![allow(dead_code)]

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Method, Request, header};
use axum::response::Response;
use cratefield_core::{
    Config, ConfigError, Database, DbError, Form, Harness, HarnessBuilder, Json, Migrations,
    Module, ModuleContext, Port, Ports, Row, Rows, Runtime, Statement, SystemClock,
};
use futures_channel::oneshot::Receiver;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

pub type ParkGate = Receiver<&'static str>;
// Test-fixture synchronization is not request state; the scoped allow
// follows the policy in clippy.toml (interior mutability for fakes).
#[allow(clippy::disallowed_types)]
pub type SharedParkGate = Arc<std::sync::Mutex<Option<ParkGate>>>;

/// The sample module from issue #2's acceptance: mounts one route reachable
/// at `/v1/sample`. Optionally parks one request on a channel for the
/// concurrency test, serves `/.well-known/test` at the root (issue #46),
/// or both under a custom name (the duplicate-well-known build error).
pub struct SampleModule {
    pub name: &'static str,
    pub harness_api: u32,
    pub requires: &'static [Port],
    pub optional: &'static [Port],
    pub tables: &'static [&'static str],
    pub park: Option<SharedParkGate>,
    pub well_known: bool,
    pub depends_on: &'static [&'static str],
}

impl Default for SampleModule {
    fn default() -> Self {
        Self {
            name: "sample",
            harness_api: cratefield_core::HARNESS_API,
            requires: &[],
            optional: &[],
            tables: &[],
            park: None,
            well_known: false,
            depends_on: &[],
        }
    }
}

impl SampleModule {
    pub fn parking(park: SharedParkGate) -> Self {
        Self {
            park: Some(park),
            ..Self::default()
        }
    }

    pub fn named(name: &'static str) -> Self {
        Self {
            name,
            ..Self::default()
        }
    }

    /// Declares this module's schema dependencies (issue #26).
    pub fn depending_on(self, depends_on: &'static [&'static str]) -> Self {
        Self { depends_on, ..self }
    }

    pub fn with_well_known(self) -> Self {
        Self {
            well_known: true,
            ..self
        }
    }
}

#[derive(Deserialize)]
pub struct EchoBody {
    pub email: String,
}

/// Shaped like a Sign in with Apple `form_post` callback body.
#[derive(Deserialize)]
pub struct CallbackBody {
    pub code: String,
    pub state: String,
}

impl Module for SampleModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn depends_on(&self) -> &'static [&'static str] {
        self.depends_on
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn harness_api(&self) -> u32 {
        self.harness_api
    }

    fn requires(&self) -> &'static [Port] {
        self.requires
    }

    fn optional(&self) -> &'static [Port] {
        self.optional
    }

    fn tables(&self) -> &'static [&'static str] {
        self.tables
    }

    fn migrations(&self) -> Migrations {
        Migrations::default()
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ctx);
        let mut router = axum::Router::new()
            .route(
                "/hello",
                axum::routing::get(hello).with_state(Arc::clone(&state)),
            )
            .route(
                "/echo",
                axum::routing::post(echo).with_state(Arc::clone(&state)),
            )
            .route(
                "/callback",
                axum::routing::post(callback).with_state(Arc::clone(&state)),
            )
            // Reports whether an `authorization` header reached the module.
            // The sidecar gateway re-materializes the sidecar's own admin
            // token for a request the host authorized (issue #131), and this
            // is where a test can see whether it did.
            .route(
                "/admin/whoami",
                axum::routing::get(|headers: axum::http::HeaderMap| async move {
                    Json(json!({
                        "authorized": headers.contains_key("authorization"),
                    }))
                }),
            );
        if let Some(park) = &self.park {
            let park = Arc::clone(park);
            router = router.route(
                "/park",
                axum::routing::get(move |scope: cratefield_core::Scope| async move {
                    let receiver = park
                        .lock()
                        .expect("park lock uncontended")
                        .take()
                        .expect("park gate used twice");
                    let gate: &'static str = receiver.await.expect("park gate dropped");
                    Json(json!({
                        "gate": gate,
                        "request_id": scope.request_id,
                    }))
                }),
            );
        }
        router
    }

    fn well_known(&self) -> Option<axum::Router> {
        if self.well_known {
            Some(axum::Router::new().route(
                "/test",
                axum::routing::get(|| async { Json(json!({ "served": "well-known" })) }),
            ))
        } else {
            None
        }
    }
}

async fn hello(
    scope: cratefield_core::Scope,
    State(ctx): State<Arc<ModuleContext>>,
) -> Json<serde_json::Value> {
    Json(json!({
        "request_id": scope.request_id,
        "venture": ctx.venture.name,
    }))
}

async fn echo(Json(body): Json<EchoBody>) -> Json<serde_json::Value> {
    Json(json!({ "email": body.email }))
}

async fn callback(Form(body): Form<CallbackBody>) -> Json<serde_json::Value> {
    Json(json!({ "code": body.code, "state": body.state }))
}

/// A runtime that claims a fixed `provides` set.
pub struct FakeRuntime(pub Vec<Port>);

impl Runtime for FakeRuntime {
    fn provides(&self) -> Vec<Port> {
        self.0.clone()
    }
}

pub fn all_ports() -> Vec<Port> {
    Port::ALL.to_vec()
}

pub fn base_venture() -> cratefield_core::Venture {
    cratefield_core::Venture::new("test-venture", "test.example")
        .cors_origins(["https://test.example"])
}

pub fn builder_with_sample() -> HarnessBuilder {
    Harness::builder()
        .venture(
            cratefield_core::Venture::new("test-venture", "test.example")
                .cors_origins(["https://test.example"]),
        )
        .module(SampleModule::default())
        .runtime(FakeRuntime(all_ports()))
}

/// A harness whose one module claims `tables`, for the cross-boundary
/// collision check: the host has to *have* a claim before a sidecar can
/// clash with it (issue #66).
pub fn builder_with_sample_claiming(tables: &'static [&'static str]) -> Harness {
    Harness::builder()
        .venture(
            cratefield_core::Venture::new("test-venture", "test.example")
                .cors_origins(["https://test.example"]),
        )
        .module(SampleModule {
            tables,
            ..SampleModule::default()
        })
        .runtime(FakeRuntime(all_ports()))
        .build()
        .expect("sample harness builds")
}

pub fn harness_with_sample() -> Harness {
    builder_with_sample()
        .build()
        .expect("sample harness builds")
}

/// `SELECT 1` succeeds; every other statement is an error.
pub struct SelectOneDb;

#[async_trait]
impl Database for SelectOneDb {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        Err(DbError::Execute(format!("unsupported: {}", stmt.sql)))
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        if stmt.sql.trim() == "SELECT 1" {
            Ok(Rows::new(vec![Row::new(vec![(
                "1".to_string(),
                sea_query::Value::Int(Some(1)),
            )])]))
        } else {
            Err(DbError::Query(format!("unsupported: {}", stmt.sql)))
        }
    }

    async fn batch_atomic(&self, _stmts: &[Statement]) -> Result<(), DbError> {
        Err(DbError::Batch("unsupported".to_string()))
    }
}

/// Every operation fails with a fixed message.
pub struct FailingDb;

#[async_trait]
impl Database for FailingDb {
    async fn execute(&self, _stmt: &Statement) -> Result<u64, DbError> {
        Err(DbError::Execute("db is down".to_string()))
    }

    async fn query(&self, _stmt: &Statement) -> Result<Rows, DbError> {
        Err(DbError::Query("db is down".to_string()))
    }

    async fn batch_atomic(&self, _stmts: &[Statement]) -> Result<(), DbError> {
        Err(DbError::Batch("db is down".to_string()))
    }
}

/// A clock whose timeout abandons immediately (tests the slow-db path).
pub struct InstantTimeoutClock;

#[async_trait]
impl cratefield_core::Clock for InstantTimeoutClock {
    fn now(&self) -> time::OffsetDateTime {
        SystemClock.now()
    }

    async fn timeout_any(
        &self,
        _fut: futures_core::future::BoxFuture<'static, Box<dyn std::any::Any + Send>>,
        _after: Duration,
    ) -> Option<Box<dyn std::any::Any + Send>> {
        None
    }
}

pub fn ports_with(db: Option<Arc<dyn Database>>) -> Ports {
    let mut ports = Ports::empty();
    ports.db = db;
    ports
}

/// Sends a request through the router without a network.
pub async fn request(
    router: &axum::Router,
    method: Method,
    uri: &str,
    headers: &[(&'static str, &str)],
    body: Option<Vec<u8>>,
) -> Response {
    use tower::ServiceExt;
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = match body {
        Some(bytes) => builder
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )
            .body(Body::from(bytes))
            .expect("request builds"),
        None => builder.body(Body::empty()).expect("request builds"),
    };
    router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers")
}

/// Sends a urlencoded form body without a network (issue #46).
pub async fn form_request(
    router: &axum::Router,
    method: Method,
    uri: &str,
    body: String,
) -> Response {
    use tower::ServiceExt;
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .body(Body::from(body))
        .expect("request builds");
    router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers")
}

pub async fn body_json(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_parts().1, MAX_TEST_BODY)
        .await
        .expect("body reads");
    serde_json::from_slice(&bytes).expect("body is JSON")
}

pub async fn body_string(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_parts().1, MAX_TEST_BODY)
        .await
        .expect("body reads");
    String::from_utf8_lossy(&bytes).to_string()
}

const MAX_TEST_BODY: usize = 1024 * 1024;
