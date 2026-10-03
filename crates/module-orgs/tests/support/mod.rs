//! Doubles and helpers for the orgs suite (issue #652): a verifier the test
//! drives by bearer token, a clock it can move, and one fixture per available
//! dialect with a `MapConfig` carrying the admin token.
//!
//! Included with `mod support;` into every test binary here, so `pub` is how
//! a helper reads; the recording fixtures carry the same `disallowed_types`
//! allowance as the fakes in `cratefield-testing` (ADR 0007).

#![allow(unreachable_pub)]
#![allow(dead_code)]
#![allow(clippy::disallowed_types)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use http::header::AUTHORIZATION;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use cratefield_core::{Auth, AuthError, Caller, Clock, Config, MapConfig, Module, Ports, Subject};
use cratefield_module_orgs::Orgs;
use cratefield_testing::TestHarness;

/// The admin bearer the deployment is configured with, for the machine path
/// of the admin listing.
pub const ADMIN: &str = "test-admin-token-0123456789abcdef";

/// The instant the test clock starts from — the harness's own fixed epoch.
const BASE_EPOCH: i64 = 1_800_000_000;

/// The organization's accepted name in the route tests.
pub const ORG_NAME: &str = "Acme";

// ---------------------------------------------------------------------------
// The clock

/// A clock a test can move: an invitation's lifetime only means something if
/// time can pass.
#[derive(Clone)]
pub struct TestClock(Arc<AtomicI64>);

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TestClock {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicI64::new(BASE_EPOCH)))
    }

    pub fn advance_secs(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }

    /// Back to the start, so the next dialect of a `for kit` loop begins
    /// where this one did.
    pub fn reset(&self) {
        self.0.store(BASE_EPOCH, Ordering::SeqCst);
    }

    #[must_use]
    pub fn read(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("in range")
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        self.read()
    }
}

// ---------------------------------------------------------------------------
// The verifier

/// A verifier the test drives by bearer token: `Authorization: Bearer <sub>`
/// proves `<sub>`, and `Bearer <sub>|<address>` proves the same subject with a
/// **verified** address — which is the shape a real verifier puts an address
/// in, and the one the invitation accept path keys on. No header at all is an
/// anonymous caller.
#[derive(Clone, Default)]
pub struct TestAuth;

impl TestAuth {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Auth for TestAuth {
    async fn identify(&self, headers: &HeaderMap) -> Result<Caller, AuthError> {
        let Some(value) = headers.get(AUTHORIZATION) else {
            return Ok(Caller::Anonymous);
        };
        let token = value
            .to_str()
            .map_err(|_| AuthError::NotVerified)?
            .strip_prefix("Bearer ")
            .ok_or(AuthError::NotVerified)?
            .trim();
        match token.split_once('|') {
            Some((sub, email)) => Ok(Caller::Subject(
                Subject::new(sub).email(Some(email.to_owned())),
            )),
            None => Ok(Caller::Subject(Subject::new(token))),
        }
    }
}

// ---------------------------------------------------------------------------
// The fixture

/// What to build the module with. One instance per test, one module per
/// dialect.
#[derive(Clone)]
pub struct Spec {
    pub roles: Vec<String>,
    pub managers: Vec<String>,
    pub staff_org: String,
    pub staff_roles: Vec<String>,
    pub invitation_ttl_secs: i64,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            roles: vec!["owner".to_owned(), "manager".to_owned(), "staff".to_owned()],
            managers: vec!["manager".to_owned()],
            staff_org: String::new(),
            staff_roles: Vec::new(),
            invitation_ttl_secs: 7 * 86_400,
        }
    }
}

impl Spec {
    /// A spec with a staff organization and a staff role, so the admin
    /// listing has a person path as well as the machine one.
    #[must_use]
    pub fn with_staff(org_id: &str, role: &str) -> Self {
        let mut roles = Self::default().roles;
        roles.push(role.to_owned());
        Self {
            roles,
            staff_org: org_id.to_owned(),
            staff_roles: vec![role.to_owned()],
            ..Self::default()
        }
    }
}

/// One dialect's harness with its shared doubles.
pub struct Kit {
    pub harness: TestHarness,
    pub clock: TestClock,
}

impl Kit {
    /// A `GET` as `as_` (a bearer token: `sub` or `sub|address`).
    pub async fn get(&self, path: &str, as_: &str) -> Res {
        send(self, Method::GET, path, Some(as_), None).await
    }

    /// A `POST` with a JSON body as `as_`.
    pub async fn post(&self, path: &str, as_: &str, json: &str) -> Res {
        send(self, Method::POST, path, Some(as_), Some(json)).await
    }

    /// A `PATCH` with a JSON body as `as_`.
    pub async fn patch(&self, path: &str, as_: &str, json: &str) -> Res {
        send(self, Method::PATCH, path, Some(as_), Some(json)).await
    }

    /// A `DELETE` as `as_`.
    pub async fn delete(&self, path: &str, as_: &str) -> Res {
        send(self, Method::DELETE, path, Some(as_), None).await
    }

    /// Creates an organization as `owner` and returns its id. Panics when the
    /// creation itself fails, which is the failure a caller of this helper
    /// wants reported at the call site.
    pub async fn create_org(&self, owner: &str, name: &str) -> String {
        let response = self
            .post("/v1/orgs", owner, &format!(r#"{{"name":"{name}"}}"#))
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{:?}",
            response.text()
        );
        response.json()["id"]
            .as_str()
            .expect("the created org carries an id")
            .to_owned()
    }

    /// Adds `sub` to `org_id` as `role`, as `actor`.
    pub async fn add_member(&self, org_id: &str, actor: &str, sub: &str, role: &str) -> Res {
        self.post(
            &format!("/v1/orgs/{org_id}/members"),
            actor,
            &format!(r#"{{"sub":"{sub}","role":"{role}"}}"#),
        )
        .await
    }

    /// Writes an organization and one membership straight into storage. The
    /// venture's staff organization is named in the builder before any id
    /// exists, so a test that needs the two to agree seeds the row itself
    /// rather than driving a creation that would mint a different id.
    pub async fn seed_org(&self, id: &str, name: &str, sub: &str, role: &str) {
        const SEEDED_AT: &str = "2026-01-02T00:00:00Z";
        self.harness
            .db
            .batch_atomic(&[
                cratefield_core::Statement::with_values(
                    "INSERT INTO orgs (id, name, created_by, created_at) VALUES (?, ?, ?, ?)",
                    vec![id.into(), name.into(), sub.into(), SEEDED_AT.into()],
                ),
                cratefield_core::Statement::with_values(
                    "INSERT INTO org_members (org_id, user_sub, role, invited_by, created_at) \
                     VALUES (?, ?, ?, NULL, ?)",
                    vec![id.into(), sub.into(), role.into(), SEEDED_AT.into()],
                ),
            ])
            .await
            .expect("seeds the organization");
    }

    /// Adds one membership straight into storage, for a fixture that needs a
    /// member whose role was never going to permit the write.
    pub async fn seed_member(&self, org_id: &str, sub: &str, role: &str) {
        self.harness
            .db
            .execute(&cratefield_core::Statement::with_values(
                "INSERT INTO org_members (org_id, user_sub, role, invited_by, created_at) \
                 VALUES (?, ?, ?, NULL, ?)",
                vec![
                    org_id.into(),
                    sub.into(),
                    role.into(),
                    "2026-01-02T00:00:00Z".into(),
                ],
            ))
            .await
            .expect("seeds the membership");
    }

    /// How many rows a table holds, read directly rather than through the
    /// module, so a test can prove the module wrote exactly what it said.
    pub async fn rows(&self, table: &str) -> usize {
        self.harness
            .db
            .query(&cratefield_core::Statement::new(format!(
                "SELECT * FROM {table}"
            )))
            .await
            .expect("counts the rows")
            .len()
    }

    /// How many rows a table holds for one subject.
    pub async fn rows_for(&self, table: &str, column: &str, subject: &str) -> i64 {
        let rows = self
            .harness
            .db
            .query(&cratefield_core::Statement::with_values(
                format!("SELECT COUNT(*) AS n FROM {table} WHERE {column} = ?"),
                vec![subject.into()],
            ))
            .await
            .expect("counts the subject rows");
        rows.first().and_then(|row| row.get("n")).unwrap_or(0)
    }

    /// How many owners one organization has, read directly. A race that runs
    /// many rounds keeps one organization per round, so a bare count of owner
    /// rows would be counting every round's; this scopes to the one under
    /// test.
    pub async fn owners_in(&self, org_id: &str) -> i64 {
        self.harness
            .db
            .query(&cratefield_core::Statement::with_values(
                "SELECT COUNT(*) AS n FROM org_members WHERE org_id = ? AND role = 'owner'",
                vec![org_id.into()],
            ))
            .await
            .expect("counts the owners")
            .first()
            .and_then(|row| row.get("n"))
            .unwrap_or(0)
    }

    /// The raw token out of the last invitation mail — the one value the
    /// module never returns over HTTP.
    #[must_use]
    pub fn invitation_token(&self) -> String {
        let message = self
            .harness
            .mailer
            .last_message()
            .expect("an invitation mail was sent");
        let marker = "?token=";
        let start = message
            .text
            .find(marker)
            .expect("the accept link carries the token")
            + marker.len();
        let rest = &message.text[start..];
        let end = rest
            .find(|ch: char| ch.is_whitespace())
            .unwrap_or(rest.len());
        percent_decode(&rest[..end])
    }
}

/// A built fixture: one kit per available dialect.
pub struct Fixture {
    pub kits: Vec<Kit>,
    pub clock: TestClock,
}

/// Builds one kit per available dialect, each with a fresh module, the test
/// verifier, a movable clock, and a `MapConfig` carrying `ADMIN_TOKEN`.
/// Panics like the harness does when a migration or the build fails.
#[must_use]
pub fn fixture(spec: &Spec) -> Fixture {
    fixture_with(spec, Vec::new)
}

/// [`fixture`] with `extra` modules mounted alongside Orgs — the privacy
/// suite composes the Privacy module this way. `extra` is a factory, so every
/// dialect gets fresh instances too.
///
/// # Panics
/// Panics like `fixture`.
#[must_use]
pub fn fixture_with(spec: &Spec, extra: impl Fn() -> Vec<Box<dyn Module>>) -> Fixture {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([(
        String::from("ADMIN_TOKEN"),
        ADMIN.to_owned(),
    )]));
    build(spec, extra, &config)
}

/// [`fixture`] with no `ADMIN_TOKEN` in the configuration — the deployment
/// that never set one, so the machine path is closed and only a staff member
/// opens the admin listing.
#[must_use]
pub fn fixture_without_admin(spec: &Spec) -> Fixture {
    let config: Arc<dyn Config> = Arc::new(MapConfig::default());
    build(spec, Vec::new, &config)
}

/// One fixture over the given configuration, one kit per available dialect.
#[must_use]
fn build(
    spec: &Spec,
    extra: impl Fn() -> Vec<Box<dyn Module>>,
    config: &Arc<dyn Config>,
) -> Fixture {
    let clock = TestClock::new();
    let spec_for_modules = spec.clone();
    let make = move || {
        let module = Orgs::builder()
            .roles(spec_for_modules.roles.clone())
            .managers(spec_for_modules.managers.clone())
            .staff_org(spec_for_modules.staff_org.clone())
            .staff_roles(spec_for_modules.staff_roles.clone())
            .invitation_ttl(Duration::seconds(spec_for_modules.invitation_ttl_secs))
            .build();
        let mut modules = vec![Box::new(module) as Box<dyn Module>];
        modules.extend(extra());
        modules
    };

    let clock_for_ports = clock.clone();
    let config_for_ports = Arc::clone(config);
    let harnesses = TestHarness::all_dialects_with_ports(make, move |ports: &mut Ports| {
        ports.clock = Some(Arc::new(clock_for_ports.clone()));
        ports.auth = Some(Arc::new(TestAuth::new()));
        ports.config = Arc::clone(&config_for_ports);
    });

    let kits = harnesses
        .into_iter()
        .map(|harness| Kit {
            harness,
            clock: clock.clone(),
        })
        .collect();

    Fixture { kits, clock }
}

/// The standard module the conformance suite runs: the default role set, one
/// manager role.
#[must_use]
pub fn module() -> Orgs {
    Orgs::builder()
        .roles(["owner", "manager", "staff"])
        .managers(["manager"])
        .build()
}

// ---------------------------------------------------------------------------
// Requests

/// A fully-buffered response.
pub struct Res {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Res {
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {}", self.text()))
    }

    /// The problem's `type` slug, for an error response.
    #[must_use]
    pub fn problem_slug(&self) -> String {
        self.json()["type"].as_str().map_or_else(
            || panic!("no problem type: {}", self.text()),
            |uri| uri.rsplit('/').next().unwrap_or(uri).to_owned(),
        )
    }
}

/// Sends one request through a kit's router. `as_` is the bearer token the
/// test verifier reads (`sub` or `sub|address`); `None` sends no credential.
///
/// # Panics
/// Panics when the router itself fails (never for ordinary responses).
pub async fn send(
    kit: &Kit,
    method: Method,
    path: &str,
    as_: Option<&str>,
    json: Option<&str>,
) -> Res {
    call(
        kit.harness.router.clone(),
        build_request(method, path, as_, json),
    )
    .await
}

/// The same send, but owning its router and blocking the calling thread — so a
/// race can move it onto a plain OS thread (the postgres harness marshals its
/// own calls onto the kit's runtime, so any thread may drive it).
pub fn race_send(
    router: axum::Router,
    method: Method,
    path: &str,
    as_: &str,
    json: Option<&str>,
) -> Res {
    pollster::block_on(call(router, build_request(method, path, Some(as_), json)))
}

/// One request, built and ready to hand to a router.
fn build_request(
    method: Method,
    path: &str,
    as_: Option<&str>,
    json: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = as_ {
        builder = builder.header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("a header value"),
        );
    }
    let body = match json {
        Some(payload) => {
            builder = builder.header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Body::from(payload.to_owned())
        }
        None => Body::empty(),
    };
    builder.body(body).expect("request builds")
}

/// Sends one prepared request and buffers the response.
async fn call(router: axum::Router, request: Request<Body>) -> Res {
    use tower::ServiceExt;
    let response = router.oneshot(request).await.expect("router answers");
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: bytes.to_vec(),
    }
}

/// Percent-decodes one query value, the way a browser would before pasting
/// it back. A ULID is already unreserved, so this only matters for a venture
/// that shipped its own token shape.
#[must_use]
pub fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
