//! Tenant resolution and `TenantConn` (issue #32, TENANT-ROUTING.md).
//!
//! The load-bearing test here is `interleaved_requests_touch_only_their_own_database`.
//! Everything else checks a rule; that one checks the property the whole
//! issue exists for, and it checks it **from the databases' side** — each
//! fake records what it was asked, so the assertion is about what was
//! executed, not about what the code looked like on the way there.

// Recording fakes are not request state (ADR 0007); the same allowance
// the fakes in `cratefield-testing` take.
#![allow(clippy::disallowed_types)]

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::{Method, StatusCode, header};
use common::{body_json, request};
use cratefield_core::{
    Config, ConfigError, Database, DbError, Harness, Migrations, Module, ModuleContext, Port,
    Ports, Resolution, ResolveTenant, Rows, Runtime, Statement, Tenant, TenantConn,
    TenantDatabases, TenantDbError, TenantStatus, Venture,
};

/// Records every statement it was given, so a test can ask each tenant's
/// database what it actually saw.
#[derive(Default)]
struct RecordingDb {
    seen: std::sync::Mutex<Vec<String>>,
}

impl RecordingDb {
    fn statements(&self) -> Vec<String> {
        self.seen.lock().expect("seen lock").clone()
    }
}

#[async_trait]
impl Database for RecordingDb {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        self.seen.lock().expect("seen lock").push(stmt.sql.clone());
        Ok(0)
    }
    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        self.seen.lock().expect("seen lock").push(stmt.sql.clone());
        Ok(Rows::new(Vec::new()))
    }
    async fn batch(&self, stmts: &[Statement]) -> Result<(), DbError> {
        for stmt in stmts {
            self.seen.lock().expect("seen lock").push(stmt.sql.clone());
        }
        Ok(())
    }
}

/// A two-tenant registry: `a.example` and `b.example`, each with its own
/// database, plus a degraded one and an unreachable one.
struct TwoTenants {
    a: Arc<RecordingDb>,
    b: Arc<RecordingDb>,
    /// Every tenant whose handle was asked for. A refusal at *resolution*
    /// and a refusal at *connect* are both `503 tenant-degraded`, so the
    /// status code cannot tell them apart — this can.
    asked: std::sync::Mutex<Vec<String>>,
}

impl TwoTenants {
    fn new(a: Arc<RecordingDb>, b: Arc<RecordingDb>) -> Self {
        Self {
            a,
            b,
            asked: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn asked_for(&self) -> Vec<String> {
        self.asked.lock().expect("asked lock").clone()
    }
}

impl ResolveTenant for TwoTenants {
    fn resolve(&self, host: &str) -> Resolution {
        match host.split(':').next().unwrap_or(host) {
            "a.example" => Resolution::Found {
                id: "tenant-a".to_owned(),
                status: TenantStatus::Active,
            },
            "b.example" => Resolution::Found {
                id: "tenant-b".to_owned(),
                status: TenantStatus::Active,
            },
            "sick.example" => Resolution::Found {
                id: "tenant-sick".to_owned(),
                status: TenantStatus::Degraded,
            },
            "new.example" => Resolution::Found {
                id: "tenant-new".to_owned(),
                status: TenantStatus::Provisioning,
            },
            "gone.example" => Resolution::Found {
                id: "tenant-gone".to_owned(),
                status: TenantStatus::Active,
            },
            _ => Resolution::Unknown,
        }
    }
}

#[async_trait]
impl TenantDatabases for TwoTenants {
    async fn database(&self, tenant: &Tenant) -> Result<Arc<dyn Database>, TenantDbError> {
        self.asked
            .lock()
            .expect("asked lock")
            .push(tenant.id().to_string());
        match tenant.id().as_str() {
            "tenant-a" => Ok(Arc::clone(&self.a) as Arc<dyn Database>),
            "tenant-b" => Ok(Arc::clone(&self.b) as Arc<dyn Database>),
            other => Err(TenantDbError::Unreachable {
                tenant: other.to_owned(),
            }),
        }
    }
}

/// Writes one row naming the tenant it was given, through the only handle
/// it can reach.
struct WriterModule;

impl Module for WriterModule {
    fn name(&self) -> &'static str {
        "writer"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
            .route(
                "/write",
                axum::routing::post(|db: TenantConn| async move {
                    let tenant = db.tenant().id().to_string();
                    db.execute(&Statement::new(format!("INSERT INTO rows -- {tenant}")))
                        .await
                        .expect("the fake accepts everything");
                    axum::Json(serde_json::json!({ "tenant": tenant }))
                }),
            )
            .route(
                "/whoami",
                axum::routing::get(|db: TenantConn| async move {
                    axum::Json(serde_json::json!({ "tenant": db.tenant().id().to_string() }))
                }),
            )
    }
}

struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

fn harness() -> Harness {
    Harness::builder()
        .venture(
            Venture::new("test-venture", "test.example").cors_origins(["https://test.example"]),
        )
        .module(WriterModule)
        .runtime(AllPorts)
        .build()
        .expect("harness builds")
}

fn routed() -> (
    axum::Router,
    Arc<RecordingDb>,
    Arc<RecordingDb>,
    Arc<TwoTenants>,
) {
    let a = Arc::new(RecordingDb::default());
    let b = Arc::new(RecordingDb::default());
    let registry = Arc::new(TwoTenants::new(Arc::clone(&a), Arc::clone(&b)));
    let mut ports = Ports::empty();
    ports.tenants = Some(Arc::clone(&registry) as Arc<dyn cratefield_core::TenantRouting>);
    (harness().router(ports), a, b, registry)
}

async fn post_as(router: &axum::Router, host: &str, path: &str) -> axum::response::Response {
    request(
        router,
        Method::POST,
        path,
        &[(header::HOST.as_str(), host)],
        None,
    )
    .await
}

// ------------------------------------------------------- the whole point

#[pollster::test]
async fn interleaved_requests_touch_only_their_own_database() {
    // #32's required check. Interleaved on purpose: a layer that resolved
    // once and cached the handle in module state would pass a test that
    // ran A's requests and then B's, and fail this one.
    let (router, a, b, registry) = routed();

    for _ in 0..3 {
        assert_eq!(
            post_as(&router, "a.example", "/v1/writer/write")
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            post_as(&router, "b.example", "/v1/writer/write")
                .await
                .status(),
            StatusCode::OK
        );
    }

    // Checked from the databases' side: what was executed, not what the
    // code looked like on the way there.
    let seen_a = a.statements();
    let seen_b = b.statements();
    assert_eq!(seen_a.len(), 3, "A saw only its own three: {seen_a:?}");
    assert_eq!(seen_b.len(), 3, "B saw only its own three: {seen_b:?}");
    assert!(
        seen_a.iter().all(|sql| sql.contains("tenant-a")),
        "nothing of B's reached A: {seen_a:?}"
    );
    assert!(
        seen_b.iter().all(|sql| sql.contains("tenant-b")),
        "nothing of A's reached B: {seen_b:?}"
    );
}

#[pollster::test]
async fn the_handler_is_given_the_tenant_the_host_resolved_to() {
    let (router, _, _, _registry) = routed();
    for (host, expected) in [("a.example", "tenant-a"), ("b.example", "tenant-b")] {
        let response = request(
            &router,
            Method::GET,
            "/v1/writer/whoami",
            &[(header::HOST.as_str(), host)],
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["tenant"], expected);
    }
}

// --------------------------------------------------------- the refusals

#[pollster::test]
async fn an_unknown_host_is_404_and_a_degraded_tenant_is_503() {
    let (router, a, b, registry) = routed();

    let unknown = post_as(&router, "nobody.example", "/v1/writer/write").await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(unknown).await["type"],
        "https://factory0.ventures/problems/unknown-tenant"
    );

    let degraded = post_as(&router, "sick.example", "/v1/writer/write").await;
    assert_eq!(degraded.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(degraded).await["type"],
        "https://factory0.ventures/problems/tenant-degraded"
    );

    // Distinguishable on purpose, and neither touched a database.
    assert!(a.statements().is_empty() && b.statements().is_empty());
    // And neither was even *looked up*: a status refusal happens before
    // any pool is opened. Without this the test passes just as well when
    // `admit` accepts everything, because an unreachable database is also
    // `503 tenant-degraded`.
    assert!(
        registry.asked_for().is_empty(),
        "resolution refused before asking for a handle: {:?}",
        registry.asked_for()
    );
}

#[pollster::test]
async fn a_provisioning_tenant_is_refused_before_its_database_is_opened() {
    // Registered but not yet reconciled: its schema is not known to match
    // the code. Refusing at resolution means the pool is never opened, so
    // a half-provisioned tenant costs nothing.
    let (router, _, _, registry) = routed();
    let response = post_as(&router, "new.example", "/v1/writer/write").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(response).await["type"],
        "https://factory0.ventures/problems/tenant-degraded"
    );
    assert!(
        registry.asked_for().is_empty(),
        "the pool is never opened for a tenant that must not serve: {:?}",
        registry.asked_for()
    );
}

#[pollster::test]
async fn an_unreachable_tenant_database_is_503_and_names_no_dsn() {
    let (router, _, _, registry) = routed();
    let response = post_as(&router, "gone.example", "/v1/writer/write").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(response).await;
    assert_eq!(
        body["type"],
        "https://factory0.ventures/problems/tenant-degraded"
    );
    let rendered = body.to_string();
    assert!(
        !rendered.contains("postgres://") && !rendered.contains('@'),
        "a connection string must never reach a response body: {rendered}"
    );
    // The mirror of the two tests above: this tenant *was* admitted, so
    // its handle was asked for and the refusal came from the connect.
    assert_eq!(
        registry.asked_for(),
        vec!["tenant-gone".to_owned()],
        "an active tenant is admitted, then fails at the pool"
    );
}

// ------------------------------------------------- what resolution skips

#[pollster::test]
async fn probes_are_not_resolved_and_keep_answering() {
    // Resolution outside the module routes would 404 every liveness probe
    // in production: they arrive by loopback with a host the registry has
    // never heard of.
    let (router, _, _, _registry) = routed();
    for path in ["/__health", "/__ready"] {
        let response = request(
            &router,
            Method::GET,
            path,
            &[(header::HOST.as_str(), "nobody.example")],
            None,
        )
        .await;
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} must answer for an unresolvable host"
        );
    }
}

// ------------------------------------------- the no-registry deployment

#[pollster::test]
async fn without_a_tenant_plane_every_host_is_the_implicit_tenant() {
    // Cloudflare, the browser, and native in development and test. A
    // module is written once against the stricter shape.
    let db = Arc::new(RecordingDb::default());
    let mut ports = Ports::empty();
    ports.db = Some(Arc::clone(&db) as Arc<dyn Database>);
    let router = harness().router(ports);

    let response = post_as(&router, "anything.at.all", "/v1/writer/write").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["tenant"], "default");
    assert_eq!(db.statements().len(), 1);
}
