//! Test doubles and request helpers for the device-auth suite.
//!
//! Everything here is a value a test can read after the fact: a clock a
//! test moves, an issuer that counts its calls, an approver that answers
//! from a mode, and a deterministic entropy source — plus thin wrappers
//! over the harness router that carry the headers the approval routes
//! actually inspect.
//!
//! Each double is cheap to clone (an `Arc` behind the newtype), because
//! the harness needs one copy in the module and the test needs another to
//! read afterwards.

// A test-support module, included with `mod support;` into each test binary
// in this crate. `pub` is how a helper reads here, and the lint is right
// that nothing outside can reach it — the module is private to every binary
// that includes it. Saying so once beats `pub(crate)` on every helper.
#![allow(unreachable_pub)]
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use cratefield_core::{Clock, Database, RandomBytes, RandomError, Statement};
use cratefield_module_device_auth::{
    Approval, Approver, ApproverError, DeviceAuth, DeviceClient, IssueRequest, Issuer, IssuerError,
};
use cratefield_testing::TestHarness;
use serde_json::{Value, json};
use time::OffsetDateTime;

/// Both test clients, and the scopes the first declares.
pub const CLIENT_A: &str = "sealb-cli";
pub const CLIENT_B: &str = "weave-cli";
pub const SCOPES: [&str; 2] = ["read", "write"];

/// The instant the test clock starts from — the harness's own fixed epoch,
/// so a test that never moves it sees the same "now" the kit would have.
const BASE_EPOCH: i64 = 1_800_000_000;

// ---------------------------------------------------------------------------
// The clock

/// A clock a test can move: expiry and the polling interval only mean
/// something if time can pass.
#[derive(Clone)]
pub struct TestClock(Arc<AtomicI64>);

impl TestClock {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicI64::new(BASE_EPOCH)))
    }

    /// Moves "now" forward.
    pub fn advance_secs(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }

    /// Back to the start, so the next dialect of a `for kit` loop begins
    /// where this one did.
    pub fn reset(&self) {
        self.0.store(BASE_EPOCH, Ordering::SeqCst);
    }

    /// The current instant as an `OffsetDateTime`.
    #[must_use]
    pub fn read(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("in range")
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        self.read()
    }
}

// ---------------------------------------------------------------------------
// The issuer

/// An [`Issuer`] that records how often it was called and returns a fixed
/// credential body. `calls()` is the at-most-once assertion: the consuming
/// poll must reach it, and a racing loser must not.
#[derive(Clone)]
pub struct CountingIssuer {
    calls: Arc<AtomicUsize>,
    failing: Arc<AtomicBool>,
}

impl CountingIssuer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            failing: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Zeroes the count. The double is shared by every dialect's kit, so a
    /// test that loops over the kits resets before each one and reads a
    /// per-dialect count rather than an accumulating one.
    pub fn reset(&self) {
        self.calls.store(0, Ordering::SeqCst);
    }

    /// Makes the next issues fail, so a test can watch what happens when
    /// the credential cannot be minted.
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }
}

impl Default for CountingIssuer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Issuer for CountingIssuer {
    async fn issue(&self, request: IssueRequest) -> Result<Value, IssuerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            return Err(IssuerError::new("the test issuer was told to fail"));
        }
        Ok(json!({
            "token_type": "api_key",
            "api_key": "cf_test_0123456789",
            "prefix": "sealb_live_0001",
            "subject": request.subject,
            "client_id": request.client_id,
            "name": request.name,
            "scopes": request.scopes,
        }))
    }
}

// ---------------------------------------------------------------------------
// The approver

/// What a [`TestApprover`] answers, mirroring the two arms of `Approval`.
#[derive(Clone)]
pub enum ApproverKind {
    /// A signed-in person.
    SignedIn(String),
    /// An anonymous visitor; the page sends the browser to sign in.
    Anonymous,
    /// The bearer token names the subject, so one kit can act for two
    /// people (the privacy suite keys an erasure on the approver).
    HeaderSubject,
    /// The approver cannot answer at all.
    Failing,
}

/// An approver that answers from a mode rather than from a session.
#[derive(Clone)]
pub struct TestApprover {
    pub kind: ApproverKind,
}

impl TestApprover {
    #[must_use]
    pub fn signed_in(subject: &str) -> Self {
        Self {
            kind: ApproverKind::SignedIn(subject.to_owned()),
        }
    }

    #[must_use]
    pub fn anonymous() -> Self {
        Self {
            kind: ApproverKind::Anonymous,
        }
    }

    #[must_use]
    pub fn failing() -> Self {
        Self {
            kind: ApproverKind::Failing,
        }
    }
}

#[async_trait::async_trait]
impl Approver for TestApprover {
    async fn approve(
        &self,
        headers: &HeaderMap,
        return_to: &str,
    ) -> Result<Approval, ApproverError> {
        match &self.kind {
            ApproverKind::SignedIn(subject) => Ok(Approval::Subject(subject.clone())),
            ApproverKind::HeaderSubject => {
                let subject = headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .unwrap_or("anonymous");
                Ok(Approval::Subject(subject.to_owned()))
            }
            ApproverKind::Anonymous => {
                #[derive(serde::Serialize)]
                struct ReturnTo<'a> {
                    return_to: &'a str,
                }
                let query = serde_urlencoded::to_string(ReturnTo { return_to })
                    .unwrap_or_else(|_| "return_to=".to_owned());
                Ok(Approval::SignIn {
                    location: format!("/login?{query}"),
                })
            }
            ApproverKind::Failing => Err(ApproverError::new("the test approver was told to fail")),
        }
    }
}

// ---------------------------------------------------------------------------
// The entropy source

/// A deterministic [`RandomBytes`]: every draw is a fresh sequence derived
/// from a counter, so two calls never collide but every run is identical.
#[derive(Clone)]
pub struct SeqRandom(Arc<AtomicUsize>);

impl SeqRandom {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(1)))
    }
}

impl Default for SeqRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomBytes for SeqRandom {
    fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        let base = self.0.fetch_add(1, Ordering::SeqCst);
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = u8::try_from((base.wrapping_mul(31) + index * 7 + 13) % 256)
                .expect("modulo 256 fits a byte");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The module and its kits

/// How to build the module under test, one instance per dialect.
#[derive(Clone)]
pub struct Spec {
    pub clients: Vec<(String, Vec<String>)>,
    pub approver: Option<ApproverKind>,
    pub expires_in_secs: i64,
    pub interval_secs: i64,
    pub max_wrong_entries: u32,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            clients: vec![
                (
                    CLIENT_A.to_owned(),
                    SCOPES.iter().map(|s| (*s).to_owned()).collect(),
                ),
                (CLIENT_B.to_owned(), Vec::new()),
            ],
            approver: Some(ApproverKind::SignedIn("alice".to_owned())),
            expires_in_secs: 600,
            interval_secs: 5,
            max_wrong_entries: 5,
        }
    }
}

/// A built kit plus the doubles a test reads after the fact.
pub struct Fixture {
    pub kits: Vec<Kit>,
    pub clock: TestClock,
    pub issuer: CountingIssuer,
}

/// One dialect's harness with its shared doubles.
pub struct Kit {
    pub harness: TestHarness,
    pub clock: TestClock,
    pub issuer: CountingIssuer,
}

impl Kit {
    /// The database the router writes through.
    #[must_use]
    pub fn db(&self) -> &Arc<dyn Database> {
        &self.harness.db
    }
}

/// Builds one kit per available dialect from `spec`, with `patch` applied
/// to every kit's ports (a scripted limiter, an `Auth` fake).
///
/// # Panics
///
/// Panics like the harness does when a migration or the build fails.
#[must_use]
pub fn fixture(spec: &Spec, patch: impl Fn(&mut cratefield_core::Ports) + Clone) -> Fixture {
    let clock = TestClock::new();
    let issuer = CountingIssuer::new();
    let spec_for_modules = spec.clone();
    let issuer_for_modules = issuer.clone();
    let make = move || {
        let spec = spec_for_modules.clone();
        let mut builder = DeviceAuth::builder()
            .expires_in(time::Duration::seconds(spec.expires_in_secs))
            .interval(time::Duration::seconds(spec.interval_secs))
            .max_wrong_entries(spec.max_wrong_entries)
            .issuer(issuer_for_modules.clone())
            .random(SeqRandom::new());
        for (id, scopes) in &spec.clients {
            builder = builder.client(DeviceClient::new(id).scopes(scopes.clone()));
        }
        if let Some(kind) = &spec.approver {
            builder = builder.approver(TestApprover { kind: kind.clone() });
        }
        vec![Box::new(builder.build()) as Box<dyn cratefield_core::Module>]
    };
    let clock_for_ports = clock.clone();
    let kits = TestHarness::all_dialects_with_ports(make, move |ports| {
        ports.clock = Some(Arc::new(clock_for_ports.clone()));
        patch(ports);
    })
    .into_iter()
    .map(|harness| Kit {
        harness,
        clock: clock.clone(),
        issuer: issuer.clone(),
    })
    .collect();
    Fixture {
        kits,
        clock,
        issuer,
    }
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
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|err| {
            panic!(
                "body is not JSON ({err}): {}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The `Location` header, when present.
    #[must_use]
    pub fn location(&self) -> Option<String> {
        self.headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

    /// The OAuth `error` field of a machine-route rejection.
    #[must_use]
    pub fn oauth_error(&self) -> String {
        self.json()["error"]
            .as_str()
            .unwrap_or_else(|| panic!("no error field: {}", self.text()))
            .to_owned()
    }
}

/// Sends a request through the router, with an optional `(content-type,
/// body)` pair and extra headers.
///
/// # Panics
///
/// Panics when the router itself fails (never for ordinary responses).
pub async fn send(
    kit: &TestHarness,
    method: Method,
    path: &str,
    content_type: Option<&str>,
    body: Option<&str>,
    headers: &[(&str, &str)],
) -> Res {
    send_router(
        kit.router.clone(),
        method,
        path,
        content_type,
        body,
        headers,
    )
    .await
}

/// [`send`] against a router the caller owns, so a test can move one into
/// a thread and race two requests.
///
/// # Panics
///
/// Panics when the router itself fails (never for ordinary responses).
pub async fn send_router(
    router: axum::Router,
    method: Method,
    path: &str,
    content_type: Option<&str>,
    body: Option<&str>,
    headers: &[(&str, &str)],
) -> Res {
    use tower::ServiceExt;
    let mut builder = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = match (content_type, body) {
        (Some(content_type), Some(body)) => {
            builder = builder.header(header::CONTENT_TYPE, content_type);
            Body::from(body.to_owned())
        }
        _ => Body::empty(),
    };
    let request = builder.body(body).expect("request builds");
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

/// `POST` with a JSON body.
pub async fn post_json(kit: &TestHarness, path: &str, body: &str) -> Res {
    send(
        kit,
        Method::POST,
        path,
        Some("application/json"),
        Some(body),
        &[],
    )
    .await
}

/// `GET` with no body.
pub async fn get(kit: &TestHarness, path: &str) -> Res {
    send(kit, Method::GET, path, None, None, &[]).await
}

/// `GET` carrying extra headers.
pub async fn get_with(kit: &TestHarness, path: &str, headers: &[(&str, &str)]) -> Res {
    send(kit, Method::GET, path, None, None, headers).await
}

/// `POST` with an `application/x-www-form-urlencoded` body, the shape the
/// two decision forms submit.
pub async fn post_form(kit: &TestHarness, path: &str, form: &str) -> Res {
    send(
        kit,
        Method::POST,
        path,
        Some("application/x-www-form-urlencoded"),
        Some(form),
        &[],
    )
    .await
}

/// `POST` a form carrying extra headers (the cross-site cases).
pub async fn post_form_with(
    kit: &TestHarness,
    path: &str,
    form: &str,
    headers: &[(&str, &str)],
) -> Res {
    send(
        kit,
        Method::POST,
        path,
        Some("application/x-www-form-urlencoded"),
        Some(form),
        headers,
    )
    .await
}

// ---------------------------------------------------------------------------
// Flow helpers

/// The `/code` route: a fresh device authorization request.
pub async fn create_code(
    kit: &TestHarness,
    client_id: &str,
    scope: &str,
    name: Option<&str>,
) -> Res {
    let body = match name {
        Some(name) => json!({"client_id": client_id, "scope": scope, "name": name}).to_string(),
        None => json!({"client_id": client_id, "scope": scope}).to_string(),
    };
    post_json(kit, "/v1/device-auth/code", &body).await
}

/// The `/token` route: one poll of the device access-token request.
pub async fn poll(kit: &TestHarness, device_code: &str, client_id: &str) -> Res {
    poll_on(kit.router.clone(), device_code, client_id).await
}

/// [`poll`] on another thread, so two of them are genuinely in flight at
/// once and the guarded updates are what decide the outcome.
pub fn poll_thread(
    router: axum::Router,
    device_code: String,
    client_id: String,
) -> std::thread::JoinHandle<Res> {
    std::thread::spawn(move || pollster::block_on(poll_on(router, &device_code, &client_id)))
}

/// [`poll`] against a router the caller owns, for the race.
pub async fn poll_on(router: axum::Router, device_code: &str, client_id: &str) -> Res {
    let body = json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "client_id": client_id,
    })
    .to_string();
    send_router(
        router,
        Method::POST,
        "/v1/device-auth/token",
        Some("application/json"),
        Some(&body),
        &[],
    )
    .await
}

/// The `/approve` route with a form body.
pub async fn approve(kit: &TestHarness, user_code: &str) -> Res {
    post_form(
        kit,
        "/v1/device-auth/approve",
        &format!("user_code={}", encode(user_code)),
    )
    .await
}

/// The `/deny` route with a form body.
pub async fn deny(kit: &TestHarness, user_code: &str) -> Res {
    post_form(
        kit,
        "/v1/device-auth/deny",
        &format!("user_code={}", encode(user_code)),
    )
    .await
}

/// The browser page for a code.
pub async fn page(kit: &TestHarness, user_code: &str) -> Res {
    get(
        kit,
        &format!("/v1/device-auth?user_code={}", encode(user_code)),
    )
    .await
}

/// A created request's two codes.
pub struct Codes {
    pub device_code: String,
    pub user_code: String,
}

/// Creates a request and returns its codes, asserting the 200 the way the
/// client would see it.
pub async fn issue(kit: &TestHarness, client_id: &str, scope: &str, name: Option<&str>) -> Codes {
    let response = create_code(kit, client_id, scope, name).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "code request: {}",
        response.text()
    );
    let body = response.json();
    Codes {
        device_code: body["device_code"]
            .as_str()
            .expect("device_code")
            .to_owned(),
        user_code: body["user_code"].as_str().expect("user_code").to_owned(),
    }
}

/// A minimal percent-encoder for a form value, so a `user_code` with a
/// separator survives the trip.
fn encode(raw: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            other => write!(out, "%{other:02X}").expect("writing to a String is infallible"),
        }
    }
    out
}

/// The `device_auth_codes` row count, for the privacy and purge tests.
pub async fn code_rows(kit: &TestHarness) -> i64 {
    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT COUNT(*) AS n FROM device_auth_codes".to_owned(),
            Vec::new(),
        ))
        .await
        .expect("count query");
    rows.first().and_then(|row| row.get("n")).unwrap_or(0)
}
