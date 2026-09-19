//! One bearer, two hosts, two databases (issue #385).
//!
//! The decision tests next door assert the refusal against a `Tenancy`
//! value handed in by hand. This file asserts it against the thing the
//! issue actually describes: a deployment with a tenant registry, driven
//! over HTTP with the same bearer at two hosts, each resolved to its own
//! real database.
//!
//! A separate file rather than more tests in `routes.rs`, for two
//! reasons. The `send`/`get_as` helpers there set no `Host` header —
//! the deployments they test have no registry, so no request needs one,
//! and under a registry every such request 404s at resolution — and
//! retrofitting a host parameter through their thirty-odd call sites
//! would bury the one scenario that needs it. And the registry fixture
//! owns its databases itself: once `ports.tenants` is wired, `kit.db` is
//! only a fallback nothing reads, so seeding has to go through the
//! `Arc`s the registry hands out.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::Method;
use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{
    Config, ConfigError, Database, Migrations, Module, ModuleContext, Port, Ports, Resolution,
    ResolveTenant, SqlMigration, Statement, Tenant, TenantDatabases, TenantDbError, TenantRouting,
    TenantStatus,
};
use cratefield_manifest::Access;
use cratefield_tables::{Schema, TableDef};
use cratefield_tables_api::{TableApi, Tables};
use cratefield_testing::{AuthMode, FakeAuth, TestHarness};

#[derive(serde::Deserialize)]
struct Fragment {
    tables: Schema,
}

/// `note` is the table the issue is about, declared `tenant-members`;
/// `bulletin` is declared `public-read` and is the control: it is what
/// proves the registry wiring is live at all.
const TABLES: &str = r#"
[tables.note]
primary_key = "id"

[[tables.note.fields]]
name = "id"
kind = "text"
required = true

[[tables.note.fields]]
name = "author"
kind = "text"
required = true

[[tables.note.fields]]
name = "body"
kind = "text"

[tables.bulletin]
primary_key = "id"

[[tables.bulletin.fields]]
name = "id"
kind = "text"
required = true

[[tables.bulletin.fields]]
name = "body"
kind = "text"
required = true
"#;

const DDL: &str = "CREATE TABLE IF NOT EXISTS note (id TEXT PRIMARY KEY NOT NULL, author TEXT NOT NULL, body TEXT); \
     CREATE TABLE IF NOT EXISTS bulletin (id TEXT PRIMARY KEY NOT NULL, body TEXT NOT NULL)";

const MIGRATIONS: [SqlMigration; 1] = [SqlMigration::new("0001", "tables", DDL)];

fn table(name: &str) -> TableDef {
    toml::from_str::<Fragment>(TABLES)
        .expect("parses")
        .tables
        .table(name)
        .expect("declared")
        .clone()
}

/// What `fz build` generates for this venture, written by hand: `note`
/// at `tenant-members`, `bulletin` at `public-read`.
struct RegistryTables;

impl Module for RegistryTables {
    fn name(&self) -> &'static str {
        "tables"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Auth]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["note", "bulletin"]
    }
    fn migrations(&self) -> Migrations {
        Migrations::sqlite(&MIGRATIONS)
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, ctx: ModuleContext) -> axum::Router {
        cratefield_tables_api::router(Arc::new(Tables {
            tables: vec![
                TableApi {
                    table: table("note"),
                    access: Access::TenantMembers,
                    subject: Some("author".to_owned()),
                },
                TableApi {
                    table: table("bulletin"),
                    access: Access::PublicRead,
                    subject: None,
                },
            ],
            ctx: Arc::new(ctx),
        }))
    }
}

/// A two-tenant registry on the shape of `TwoTenants` in core's
/// `tenant_routing` tests: each host maps to its own tenant, and each
/// tenant's "database" is a real in-memory SQLite of its own, seeded
/// with the same declared tables and distinguishable rows.
struct TwoTenants {
    a: Arc<SqliteDatabase>,
    b: Arc<SqliteDatabase>,
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
            _ => Resolution::Unknown,
        }
    }
}

#[async_trait]
impl TenantDatabases for TwoTenants {
    async fn database(&self, tenant: &Tenant) -> Result<Arc<dyn Database>, TenantDbError> {
        match tenant.id().as_str() {
            "tenant-a" => Ok(Arc::clone(&self.a) as Arc<dyn Database>),
            "tenant-b" => Ok(Arc::clone(&self.b) as Arc<dyn Database>),
            other => Err(TenantDbError::Unreachable {
                tenant: other.to_owned(),
            }),
        }
    }
}

/// The declared tables on one tenant's database, with rows that name
/// which tenant they live in. Both tenants hold the same note keys, so
/// a read of `note` can only be answered from *one* of them.
async fn seed(db: &SqliteDatabase, which: &str) {
    // One statement per `execute`: the migrations path splits DDL, and a
    // raw `execute` refuses to.
    for table in [
        "CREATE TABLE IF NOT EXISTS note (id TEXT PRIMARY KEY NOT NULL, author TEXT NOT NULL, body TEXT)",
        "CREATE TABLE IF NOT EXISTS bulletin (id TEXT PRIMARY KEY NOT NULL, body TEXT NOT NULL)",
    ] {
        db.execute(&Statement::new(table.to_owned()))
            .await
            .expect("the tables are created");
    }
    for (id, author, body) in [
        ("n1", "ada", format!("{which}'s copy")),
        ("n2", "grace", format!("grace of {which}")),
    ] {
        db.execute(&Statement::with_values(
            "INSERT INTO note (id, author, body) VALUES (?, ?, ?)".to_owned(),
            vec![id.into(), author.into(), body.into()],
        ))
        .await
        .expect("seeded");
    }
    db.execute(&Statement::with_values(
        "INSERT INTO bulletin (id, body) VALUES (?, ?)".to_owned(),
        vec!["b1".into(), format!("bulletin of tenant {which}").into()],
    ))
    .await
    .expect("seeded");
}

/// A registry deployment plus the two tenant databases it routes to.
/// The rows are seeded through the `Arc`s the registry owns, because
/// once the tenant plane is wired those are the databases that answer —
/// `kit.db` is a fallback nothing reads.
async fn routed() -> (TestHarness, Arc<SqliteDatabase>, Arc<SqliteDatabase>) {
    let a = Arc::new(SqliteDatabase::in_memory().expect("in-memory sqlite"));
    let b = Arc::new(SqliteDatabase::in_memory().expect("in-memory sqlite"));
    seed(&a, "a").await;
    seed(&b, "b").await;

    let registry = Arc::new(TwoTenants {
        a: Arc::clone(&a),
        b: Arc::clone(&b),
    });
    let kit = TestHarness::with_ports(vec![Box::new(RegistryTables) as Box<dyn Module>], |ports| {
        ports.auth = Some(Arc::new(FakeAuth::new(AuthMode::TokenIsTheSubject)));
        ports.tenants = Some(Arc::clone(&registry) as Arc<dyn TenantRouting>);
    });
    (kit, a, b)
}

/// What a driven request answered. Built here rather than borrowed from
/// `routes.rs` because this is the test file that needs a `Host` on
/// every request.
struct Answer {
    status: axum::http::StatusCode,
    body: String,
}

async fn send_as(
    kit: &TestHarness,
    method: Method,
    host: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> Answer {
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, host);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(json) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json.to_owned())),
        None => builder.body(Body::empty()),
    }
    .expect("request");
    let response = kit.router.clone().oneshot(request).await.expect("answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    Answer {
        status,
        body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
    }
}

fn ids(body: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(body).expect("json")["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["id"].as_str().expect("id").to_owned())
        .collect()
}

// ------------------------------------------------- the issue's scenario

#[pollster::test]
async fn one_bearer_gets_the_deployment_fault_at_both_hosts_of_a_registry_deployment() {
    // The scenario of #385, over HTTP: ada's bearer, signed in against
    // the deployment's one verifier, carried to both hosts. Before the
    // tenancy reached the decision, the second request answered `200`
    // with tenant-b's rows — the verifier's "yes" served as a member's.
    // Now the level refuses on both hosts: a registry named each tenant
    // and the harness has no membership fact, not even for the tenant
    // the bearer "belongs" to, so it fails closed rather than guess.
    let (kit, _a, _b) = routed().await;

    for host in ["a.example", "b.example"] {
        let response = send_as(
            &kit,
            Method::GET,
            host,
            "/v1/tables/note",
            Some("ada"),
            None,
        )
        .await;
        assert_eq!(response.status, 500, "{host}: {}", response.body);
        assert!(
            response.body.contains("no-membership-fact"),
            "{host}: {}",
            response.body
        );
    }
}

#[pollster::test]
async fn a_write_refuses_the_same_way_at_the_other_hosts_database() {
    // The read half closing without the write half would leave the level
    // writable by everybody the verifier accepts — the same set on the
    // same missing fact.
    let (kit, _a, _b) = routed().await;

    let created = send_as(
        &kit,
        Method::POST,
        "b.example",
        "/v1/tables/note",
        Some("ada"),
        Some(r#"{"id":"n9","author":"ada","body":"mine"}"#),
    )
    .await;
    assert_eq!(created.status, 500, "{}", created.body);
    assert!(
        created.body.contains("no-membership-fact"),
        "{}",
        created.body
    );
}

#[pollster::test]
async fn an_anonymous_caller_gets_the_deployment_fault_not_a_sign_in_prompt() {
    // What the tenancy-before-caller order answers on the wire. `who()`
    // does not refuse a request that carries no credential — the `Auth`
    // port answers `Ok(Caller::Anonymous)` for one, and reserves
    // `unauthenticated` for a credential that was presented and did not
    // verify — so an anonymous caller reaches the decision, and the
    // registry arm answers before the caller's credential is read. The
    // answer is the deployment's 500, where reading the credential
    // first would have handed them a 401 about themselves.
    let (kit, _a, _b) = routed().await;

    let read = send_as(
        &kit,
        Method::GET,
        "a.example",
        "/v1/tables/note",
        None,
        None,
    )
    .await;
    assert_eq!(read.status, 500, "{}", read.body);
    assert!(read.body.contains("no-membership-fact"), "{}", read.body);
    assert!(!read.body.contains("unauthenticated"), "{}", read.body);

    let write = send_as(
        &kit,
        Method::POST,
        "a.example",
        "/v1/tables/note",
        None,
        Some(r#"{"id":"n9","author":"ada","body":"mine"}"#),
    )
    .await;
    assert_eq!(write.status, 500, "{}", write.body);
    assert!(write.body.contains("no-membership-fact"), "{}", write.body);
}

#[pollster::test]
async fn one_replace_and_remove_refuse_the_same_way_on_a_registry_deployment() {
    // The row-reaching routes the two tests above do not drive. A route
    // mounted without `conn.tenancy()` would serve this level through
    // any of them, so each of them is pinned to the same refusal.
    let (kit, _a, _b) = routed().await;

    let one = send_as(
        &kit,
        Method::GET,
        "b.example",
        "/v1/tables/note/n1",
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(one.status, 500, "{}", one.body);
    assert!(one.body.contains("no-membership-fact"), "{}", one.body);

    let replaced = send_as(
        &kit,
        Method::PUT,
        "b.example",
        "/v1/tables/note/n1",
        Some("ada"),
        Some(r#"{"id":"n1","author":"ada","body":"mine"}"#),
    )
    .await;
    assert_eq!(replaced.status, 500, "{}", replaced.body);
    assert!(
        replaced.body.contains("no-membership-fact"),
        "{}",
        replaced.body
    );

    let removed = send_as(
        &kit,
        Method::DELETE,
        "b.example",
        "/v1/tables/note/n1",
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(removed.status, 500, "{}", removed.body);
    assert!(
        removed.body.contains("no-membership-fact"),
        "{}",
        removed.body
    );
}

#[pollster::test]
async fn the_by_query_route_refuses_the_same_way_on_a_registry_deployment() {
    // The addressing route the composite-key work added goes through the
    // same decision, so the registry refusal reaches it too — a route
    // that bypassed `conn.tenancy()` would serve this level through
    // `__by` after every path route had been pinned shut above.
    let (kit, _a, _b) = routed().await;

    let one = send_as(
        &kit,
        Method::GET,
        "b.example",
        "/v1/tables/note/__by?id=n1",
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(one.status, 500, "{}", one.body);
    assert!(one.body.contains("no-membership-fact"), "{}", one.body);

    let replaced = send_as(
        &kit,
        Method::PUT,
        "b.example",
        "/v1/tables/note/__by?id=n1",
        Some("ada"),
        Some(r#"{"id":"n1","author":"ada","body":"mine"}"#),
    )
    .await;
    assert_eq!(replaced.status, 500, "{}", replaced.body);
    assert!(
        replaced.body.contains("no-membership-fact"),
        "{}",
        replaced.body
    );

    let removed = send_as(
        &kit,
        Method::DELETE,
        "b.example",
        "/v1/tables/note/__by?id=n1",
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(removed.status, 500, "{}", removed.body);
    assert!(
        removed.body.contains("no-membership-fact"),
        "{}",
        removed.body
    );
}

// ------------------------------------------- the routing is not the bug

#[pollster::test]
async fn a_registry_deployment_still_serves_each_host_its_own_database() {
    // The control for the refusals above. The public table is served,
    // and each host answers from its own database — so the 500s are a
    // decision about membership, not a broken deployment answering
    // unformly, and the isolation of the two databases is real.
    let (kit, _a, _b) = routed().await;

    let at_a = send_as(
        &kit,
        Method::GET,
        "a.example",
        "/v1/tables/bulletin",
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(at_a.status, 200, "{}", at_a.body);
    assert!(at_a.body.contains("bulletin of tenant a"), "{}", at_a.body);

    let at_b = send_as(
        &kit,
        Method::GET,
        "b.example",
        "/v1/tables/bulletin",
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(at_b.status, 200, "{}", at_b.body);
    assert!(
        at_b.body.contains("bulletin of tenant b"),
        "the same bearer at the other host answered another database: {}",
        at_b.body
    );
}

#[pollster::test]
async fn the_by_query_still_serves_each_host_its_own_row() {
    // The positive control the refusal above needs. `__by` cannot be
    // proven safe by its refusal alone: on the table where the tenancy
    // check passes — `bulletin` is `public-read` — the route answers,
    // and answers from the host's own database. The same bearer asking
    // for the same key at two hosts gets two different rows, so the
    // addressing route read the tenant-bound connection and not the
    // fallback nothing seeds.
    let (kit, _a, _b) = routed().await;

    let at_a = send_as(
        &kit,
        Method::GET,
        "a.example",
        "/v1/tables/bulletin/__by?id=b1",
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(at_a.status, 200, "{}", at_a.body);
    assert!(at_a.body.contains("bulletin of tenant a"), "{}", at_a.body);

    let at_b = send_as(
        &kit,
        Method::GET,
        "b.example",
        "/v1/tables/bulletin/__by?id=b1",
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(at_b.status, 200, "{}", at_b.body);
    assert!(
        at_b.body.contains("bulletin of tenant b"),
        "the same bearer at the other host answered another database: {}",
        at_b.body
    );
}

// --------------------------------------- the no-registry deployment too

#[pollster::test]
async fn without_a_registry_the_same_bearer_still_serves_every_row() {
    // The counterpart that keeps the fix from over-reaching. No
    // `ports.tenants`, so the request is the one implicit tenant however
    // the Host reads: "any verified caller" and "a member of this
    // tenant" are the same set, and the level serves exactly as it did
    // before #385 touched it — every row, grace's included.
    let kit = TestHarness::with_ports(
        vec![Box::new(RegistryTables) as Box<dyn Module>],
        |ports: &mut Ports| {
            ports.auth = Some(Arc::new(FakeAuth::new(AuthMode::TokenIsTheSubject)));
        },
    );
    // The fallback database is the only database this deployment has,
    // and the module's migrations made it the declared tables'.
    for (id, author, body) in [
        ("n1", "ada", "a's copy"),
        ("n2", "grace", "grace of a"),
        ("n3", "ada", "second"),
    ] {
        kit.db
            .execute(&Statement::with_values(
                "INSERT INTO note (id, author, body) VALUES (?, ?, ?)".to_owned(),
                vec![id.into(), author.into(), body.into()],
            ))
            .await
            .expect("seeded");
    }

    let response = send_as(
        &kit,
        Method::GET,
        "anything.at.all",
        "/v1/tables/note",
        Some("ada"),
        None,
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(ids(&response.body), ["n1", "n2", "n3"]);
}
