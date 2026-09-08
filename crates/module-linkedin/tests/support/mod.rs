//! The test kit (issue #16): a fake LinkedIn that models the parts of the
//! real one that actually bite, plus a clock a test can drive.
//!
//! CI has no LinkedIn credentials and never reaches the network. The fake
//! `HttpClient` is the enforcement: a module can only talk to the outside
//! through the port it was handed, so a test that forgets to script a call
//! gets a failure rather than a request.

#![allow(dead_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, Config, Database, HttpClient, HttpError, MapConfig, Module, ModuleContext, Ports, Scope,
    UlidIdGen,
};
use cratefield_testing::{FakeDefer, TestHarness};
use fz_module_linkedin::Linkedin;
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;

pub const ADMIN: &str = "test-admin-token-0123456789abcdef";
pub const TOKEN_KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
pub const ORG: &str = "2414183";
pub const SHOWCASE: &str = "89758488";

/// A clock a test can move. `FixedClock` cannot advance, and the token
/// lifecycle only makes sense over days.
pub struct TestClock {
    unix: std::sync::atomic::AtomicI64,
}

impl TestClock {
    pub fn new() -> Arc<Self> {
        // 2026-09-07T10:00:00Z, a fixed point so stored timestamps are
        // readable in failure output.
        Arc::new(Self {
            unix: std::sync::atomic::AtomicI64::new(1_788_775_200),
        })
    }

    pub fn advance_days(&self, days: i64) {
        self.unix.fetch_add(days * 86_400, Ordering::SeqCst);
    }

    pub fn advance_secs(&self, secs: i64) {
        self.unix.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.unix.load(Ordering::SeqCst))
            .expect("test clock stays in range")
    }
}

/// One captured request.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub url: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Call {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

#[derive(Debug, Clone)]
struct FakePost {
    urn: String,
    commentary: String,
    lifecycle: String,
    created_at_ms: i64,
    author: String,
}

#[derive(Debug, Clone)]
struct Injected {
    url_contains: String,
    status: u16,
    body: Value,
    retry_after: Option<String>,
}

#[derive(Default)]
struct Inner {
    calls: RwLock<Vec<Call>>,
    posts: RwLock<Vec<FakePost>>,
    next_post: AtomicUsize,
    lifecycle: RwLock<Option<String>>,
    image_statuses: RwLock<VecDeque<String>>,
    acls: RwLock<Vec<(String, String)>>,
    organizations: RwLock<Vec<Value>>,
    showcases: RwLock<Vec<(String, Value)>>,
    token_response: RwLock<Option<Value>>,
    token_error: RwLock<Option<(u16, Value)>>,
    injected: RwLock<VecDeque<Injected>>,
    lose_next_create: AtomicBool,
    now_ms: RwLock<i64>,
}

/// A LinkedIn that never leaves the process.
#[derive(Clone, Default)]
pub struct FakeLinkedIn {
    inner: Arc<Inner>,
}

impl FakeLinkedIn {
    pub fn new() -> Self {
        let fake = Self::default();
        *fake.inner.now_ms.write().expect("lock") = 1_788_775_200_000;
        fake.set_acls(&[(ORG, "ADMINISTRATOR")]);
        fake.set_organizations(vec![organization(ORG, "DevTestCo", "NONE", None)]);
        fake
    }

    // --- scripting -------------------------------------------------------

    /// What newly created posts report as their lifecycle state.
    pub fn set_lifecycle(&self, state: &str) {
        *self.inner.lifecycle.write().expect("lock") = Some(state.to_owned());
    }

    /// The statuses `GET /rest/images/{urn}` will serve, in order. The last
    /// one repeats.
    pub fn set_image_statuses(&self, statuses: &[&str]) {
        *self.inner.image_statuses.write().expect("lock") =
            statuses.iter().map(|s| (*s).to_owned()).collect();
    }

    /// Moves every post already created to a new lifecycle state, the way
    /// LinkedIn does when its asynchronous processing finishes.
    pub fn settle_posts(&self, state: &str) {
        for post in self.inner.posts.write().expect("lock").iter_mut() {
            state.clone_into(&mut post.lifecycle);
        }
    }

    pub fn set_acls(&self, acls: &[(&str, &str)]) {
        *self.inner.acls.write().expect("lock") = acls
            .iter()
            .map(|(org, role)| ((*org).to_owned(), (*role).to_owned()))
            .collect();
    }

    pub fn set_organizations(&self, organizations: Vec<Value>) {
        *self.inner.organizations.write().expect("lock") = organizations;
    }

    pub fn add_showcase(&self, parent: &str, showcase: Value) {
        self.inner
            .showcases
            .write()
            .expect("lock")
            .push((parent.to_owned(), showcase));
    }

    pub fn set_token_response(&self, response: Value) {
        *self.inner.token_response.write().expect("lock") = Some(response);
    }

    pub fn set_token_error(&self, status: u16, body: Value) {
        *self.inner.token_error.write().expect("lock") = Some((status, body));
    }

    pub fn clear_token_error(&self) {
        *self.inner.token_error.write().expect("lock") = None;
    }

    /// Fails the next request whose URL contains `url_contains`.
    pub fn fail_next(&self, url_contains: &str, status: u16, body: Value) {
        self.inner
            .injected
            .write()
            .expect("lock")
            .push_back(Injected {
                url_contains: url_contains.to_owned(),
                status,
                body,
                retry_after: None,
            });
    }

    pub fn rate_limit_next(&self, url_contains: &str, retry_after: &str) {
        self.inner
            .injected
            .write()
            .expect("lock")
            .push_back(Injected {
                url_contains: url_contains.to_owned(),
                status: 429,
                body: json!({ "message": "too many requests" }),
                retry_after: Some(retry_after.to_owned()),
            });
    }

    /// The next create will happen on LinkedIn's side but the response will
    /// be lost, which is exactly the case that would double-post.
    pub fn lose_next_create(&self) {
        self.inner.lose_next_create.store(true, Ordering::SeqCst);
    }

    pub fn set_now_ms(&self, now_ms: i64) {
        *self.inner.now_ms.write().expect("lock") = now_ms;
    }

    // --- assertions ------------------------------------------------------

    pub fn calls(&self) -> Vec<Call> {
        self.inner.calls.read().expect("lock").clone()
    }

    pub fn calls_to(&self, url_contains: &str) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|call| call.url.contains(url_contains))
            .collect()
    }

    /// How many posts LinkedIn actually holds. The number that matters: a
    /// double-publish shows up here and nowhere else.
    pub fn created_posts(&self) -> usize {
        self.inner.posts.read().expect("lock").len()
    }

    pub fn post_commentaries(&self) -> Vec<String> {
        self.inner
            .posts
            .read()
            .expect("lock")
            .iter()
            .map(|post| post.commentary.clone())
            .collect()
    }

    // --- routing ---------------------------------------------------------

    fn record(&self, request: &Request<Bytes>, body: &Bytes) {
        let headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        self.inner.calls.write().expect("lock").push(Call {
            method: request.method().as_str().to_owned(),
            url: request.uri().to_string(),
            body: String::from_utf8_lossy(body).to_string(),
            headers,
        });
    }

    fn injected_for(&self, url: &str) -> Option<Injected> {
        let mut queue = self.inner.injected.write().expect("lock");
        let index = queue
            .iter()
            .position(|injected| url.contains(&injected.url_contains))?;
        queue.remove(index)
    }
}

fn json_response(status: u16, body: &Value) -> Response<Bytes> {
    Response::builder()
        .status(StatusCode::from_u16(status).expect("status"))
        .header("content-type", "application/json")
        .header("x-li-uuid", "test-uuid")
        .body(Bytes::from(serde_json::to_vec(body).expect("json")))
        .expect("response")
}

fn empty_response(status: u16) -> Response<Bytes> {
    Response::builder()
        .status(StatusCode::from_u16(status).expect("status"))
        .body(Bytes::new())
        .expect("response")
}

pub fn organization(id: &str, name: &str, primary_type: &str, parent: Option<&str>) -> Value {
    let mut value = json!({
        "id": id.parse::<i64>().unwrap_or_default(),
        "localizedName": name,
        "vanityName": name.to_lowercase(),
        "primaryOrganizationType": primary_type,
        "logoV2": { "original": "urn:li:digitalmediaAsset:C4D0" },
    });
    if let Some(parent) = parent {
        value["parentRelationship"] = json!({ "parent": format!("urn:li:organization:{parent}"), "relationshipStatus": "ACTIVE" });
    }
    value
}

#[async_trait]
impl HttpClient for FakeLinkedIn {
    // A routing table is long by nature, and splitting it would scatter the
    // one place a reader goes to ask "what does the fake do for this call".
    #[allow(clippy::too_many_lines)]
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let url = request.uri().to_string();
        let method = request.method().clone();
        let body = request.body().clone();
        self.record(&request, &body);

        let is_rest = url.starts_with("https://api.linkedin.com/rest/");
        let has_version = request.headers().contains_key("linkedin-version");
        let has_restli = request.headers().contains_key("x-restli-protocol-version");

        // LinkedIn treats a missing version as an error rather than
        // defaulting to the newest, and the OAuth and upload hosts take
        // neither header. Both directions are enforced, because sending them
        // where they do not belong is just as much a bug.
        if is_rest && !(has_version && has_restli) {
            return Ok(json_response(
                400,
                &json!({ "message": "missing LinkedIn-Version or X-Restli-Protocol-Version" }),
            ));
        }
        if !is_rest && (has_version || has_restli) {
            return Ok(json_response(
                400,
                &json!({ "message": "versioning headers do not belong on this host" }),
            ));
        }

        if let Some(injected) = self.injected_for(&url) {
            let mut response = json_response(injected.status, &injected.body);
            if let Some(retry_after) = injected.retry_after {
                response.headers_mut().insert(
                    "retry-after",
                    retry_after.parse().expect("retry-after header"),
                );
            }
            return Ok(response);
        }

        // --- OAuth -------------------------------------------------------
        if url.contains("/oauth/v2/accessToken") {
            if let Some((status, body)) = self.inner.token_error.read().expect("lock").clone() {
                return Ok(json_response(status, &body));
            }
            let scripted = self.inner.token_response.read().expect("lock").clone();
            return Ok(json_response(
                200,
                &scripted.unwrap_or_else(|| {
                    json!({
                        "access_token": "access-token-value",
                        "expires_in": 5_184_000i64,
                        "refresh_token": "refresh-token-value",
                        "refresh_token_expires_in": 31_536_000i64,
                        "scope": "rw_organization_admin,r_organization_admin,r_organization_social,w_organization_social",
                    })
                }),
            ));
        }

        // --- media upload host -------------------------------------------
        if url.contains("/dms-uploads/") {
            // Image uploads require the bearer; video uploads forbid it. This
            // is an image, so its absence is a bug.
            if !request.headers().contains_key("authorization") {
                return Ok(json_response(
                    401,
                    &json!({ "message": "image upload needs the bearer token" }),
                ));
            }
            return Ok(empty_response(201));
        }

        // --- organizations -----------------------------------------------
        if url.contains("/rest/organizationAcls") {
            let elements: Vec<Value> = self
                .inner
                .acls
                .read()
                .expect("lock")
                .iter()
                .map(|(org, role)| {
                    json!({
                        "role": role,
                        // Deliberately the `organizationTarget` spelling: the
                        // module has to read both.
                        "organizationTarget": format!("urn:li:organization:{org}"),
                        "roleAssignee": "urn:li:person:A839rocZ",
                        "state": "APPROVED",
                    })
                })
                .collect();
            return Ok(json_response(
                200,
                &json!({ "elements": elements, "paging": { "start": 0, "count": 50, "links": [] } }),
            ));
        }

        if url.contains("/rest/organizations?q=parentOrganization") {
            let parent = url
                .split("parent=")
                .nth(1)
                .unwrap_or_default()
                .replace("%3A", ":");
            let elements: Vec<Value> = self
                .inner
                .showcases
                .read()
                .expect("lock")
                .iter()
                .filter(|(owner, _)| parent.ends_with(owner.as_str()))
                .map(|(_, showcase)| showcase.clone())
                .collect();
            return Ok(json_response(200, &json!({ "elements": elements })));
        }

        if url.contains("/rest/organizations?ids=List(") {
            let mut results = serde_json::Map::new();
            let mut statuses = serde_json::Map::new();
            let requested = url
                .split("List(")
                .nth(1)
                .and_then(|rest| rest.split(')').next())
                .unwrap_or_default()
                .to_owned();
            for organization in self.inner.organizations.read().expect("lock").iter() {
                let id = organization["id"].to_string();
                if requested.split(',').any(|wanted| wanted == id) {
                    results.insert(id.clone(), organization.clone());
                    statuses.insert(id, json!(200));
                }
            }
            // One id the caller cannot see, exactly as a real batch reports
            // it: per-id statuses and errors, not a failed call.
            let mut errors = serde_json::Map::new();
            for wanted in requested.split(',') {
                if !results.contains_key(wanted) && !wanted.is_empty() {
                    statuses.insert(wanted.to_owned(), json!(403));
                    errors.insert(
                        wanted.to_owned(),
                        json!({ "message": "not an admin", "status": 403 }),
                    );
                }
            }
            return Ok(json_response(
                200,
                &json!({ "results": results, "statuses": statuses, "errors": errors }),
            ));
        }

        // --- images -------------------------------------------------------
        if url.contains("/rest/images?action=initializeUpload") {
            let index = self.inner.next_post.fetch_add(1, Ordering::SeqCst);
            return Ok(json_response(
                200,
                &json!({
                    "value": {
                        "uploadUrlExpiresAt": 1_650_567_510_704i64,
                        "uploadUrl": format!("https://www.linkedin.com/dms-uploads/image{index}"),
                        "image": format!("urn:li:image:C4E10AQ{index}"),
                    }
                }),
            ));
        }

        if url.contains("/rest/images/") {
            let mut statuses = self.inner.image_statuses.write().expect("lock");
            let status = if statuses.len() > 1 {
                statuses
                    .pop_front()
                    .unwrap_or_else(|| "AVAILABLE".to_owned())
            } else {
                statuses
                    .front()
                    .cloned()
                    .unwrap_or_else(|| "AVAILABLE".to_owned())
            };
            return Ok(json_response(200, &json!({ "status": status })));
        }

        // --- posts --------------------------------------------------------
        if url == "https://api.linkedin.com/rest/posts" && method == http::Method::POST {
            let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let index = self.inner.next_post.fetch_add(1, Ordering::SeqCst);
            let urn = format!(
                "urn:li:share:{}",
                6_844_785_523_593_134_080u64 + index as u64
            );
            let lifecycle = self
                .inner
                .lifecycle
                .read()
                .expect("lock")
                .clone()
                .unwrap_or_else(|| "PUBLISHED".to_owned());
            self.inner.posts.write().expect("lock").push(FakePost {
                urn: urn.clone(),
                commentary: payload["commentary"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                lifecycle,
                created_at_ms: *self.inner.now_ms.read().expect("lock"),
                author: payload["author"].as_str().unwrap_or_default().to_owned(),
            });
            // The post exists now. Losing the response is what makes the
            // caller think it does not.
            if self.inner.lose_next_create.swap(false, Ordering::SeqCst) {
                return Err(HttpError::Transport("connection reset".to_owned()));
            }
            return Ok(Response::builder()
                .status(201)
                .header("x-restli-id", urn)
                .body(Bytes::new())
                .expect("response"));
        }

        if url.contains("/rest/posts?author=") {
            let author = url
                .split("author=")
                .nth(1)
                .and_then(|rest| rest.split('&').next())
                .unwrap_or_default()
                .replace("%3A", ":");
            let elements: Vec<Value> = self
                .inner
                .posts
                .read()
                .expect("lock")
                .iter()
                .filter(|post| post.author == author)
                .map(|post| {
                    json!({
                        "id": post.urn,
                        "commentary": post.commentary,
                        "lifecycleState": post.lifecycle,
                        "createdAt": post.created_at_ms,
                        "author": post.author,
                    })
                })
                .collect();
            return Ok(json_response(200, &json!({ "elements": elements })));
        }

        if url.contains("/rest/posts/") {
            let urn = url
                .split("/rest/posts/")
                .nth(1)
                .and_then(|rest| rest.split('?').next())
                .unwrap_or_default()
                .replace("%3A", ":");

            if method == http::Method::DELETE {
                self.inner
                    .posts
                    .write()
                    .expect("lock")
                    .retain(|post| post.urn != urn);
                return Ok(empty_response(204));
            }
            if method == http::Method::POST {
                // PARTIAL_UPDATE
                let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                if let Some(commentary) = payload["patch"]["$set"]["commentary"].as_str() {
                    for post in self.inner.posts.write().expect("lock").iter_mut() {
                        if post.urn == urn {
                            commentary.clone_into(&mut post.commentary);
                        }
                    }
                }
                return Ok(empty_response(204));
            }

            let found = self
                .inner
                .posts
                .read()
                .expect("lock")
                .iter()
                .find(|post| post.urn == urn)
                .cloned();
            return Ok(match found {
                Some(post) => json_response(
                    200,
                    &json!({
                        "id": post.urn,
                        "commentary": post.commentary,
                        "lifecycleState": post.lifecycle,
                        "createdAt": post.created_at_ms,
                        "author": post.author,
                    }),
                ),
                None => json_response(404, &json!({ "message": "not found" })),
            });
        }

        Ok(json_response(
            404,
            &json!({ "message": format!("the fake has no route for {url}") }),
        ))
    }
}

/// A built kit: the router, the ports behind it, and the handles a test needs
/// to drive time, the network and deferred work.
pub struct Kit {
    pub harness: TestHarness,
    pub fake: FakeLinkedIn,
    pub clock: Arc<TestClock>,
    pub defer: FakeDefer,
    pub db: Arc<dyn Database>,
    pub config: Arc<dyn Config>,
    pub module: Arc<dyn Module>,
}

pub fn config_pairs() -> Vec<(String, String)> {
    vec![
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
        ("LINKEDIN_CLIENT_ID".to_owned(), "client-id".to_owned()),
        (
            "LINKEDIN_CLIENT_SECRET".to_owned(),
            "client-secret".to_owned(),
        ),
        ("LINKEDIN_TOKEN_KEY".to_owned(), TOKEN_KEY.to_owned()),
        (
            "LINKEDIN_REDIRECT_URI".to_owned(),
            "https://api.test.example/v1/linkedin/callback".to_owned(),
        ),
    ]
}

pub fn kit() -> Kit {
    kit_with(config_pairs())
}

pub fn kit_with(pairs: Vec<(String, String)>) -> Kit {
    let fake = FakeLinkedIn::new();
    let clock = TestClock::new();
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(pairs));

    let http = fake.clone();
    let clock_for_ports = clock.clone();
    let config_for_ports = config.clone();
    let harness = TestHarness::with_ports(vec![Box::new(Linkedin::new())], move |ports| {
        ports.http = Some(Arc::new(http));
        ports.clock = Some(clock_for_ports);
        ports.config = config_for_ports;
    });

    let db = harness.db.clone();
    let defer = harness.defer.clone();
    let module = harness.modules[0].clone();
    Kit {
        harness,
        fake,
        clock,
        defer,
        db,
        config,
        module,
    }
}

impl Kit {
    /// The ports a scheduled pass sees. `Module::scheduled` is not reachable
    /// through the router, so a cron test builds the context the runtime
    /// would have built.
    fn ports(&self) -> Ports {
        let mut ports = Ports::with_config(self.config.clone());
        ports.db = Some(self.db.clone());
        ports.http = Some(Arc::new(self.fake.clone()));
        ports.clock = Some(self.clock.clone());
        ports.signer = Some(self.harness.signer.clone());
        ports.id_gen = Some(Arc::new(UlidIdGen));
        ports.defer = Some(Arc::new(self.defer.clone()));
        ports
    }

    pub fn context(&self) -> ModuleContext {
        let ports = self.ports();
        self.harness
            .harness
            .module_context(self.module.as_ref(), &ports)
    }

    /// Runs one cron pass, the way the runtime would.
    pub async fn cron(&self, expression: &str) {
        let ctx = self.context();
        self.module
            .scheduled(&ctx, expression)
            .await
            .expect("scheduled work does not fail the run");
    }

    /// Runs whatever the handlers deferred.
    pub async fn drain(&self) {
        self.defer.drain().await;
    }

    /// A scope for calling module internals directly.
    pub fn scope(&self) -> Scope {
        Scope {
            request_id: "test-request".to_owned(),
            defer: Arc::new(self.defer.clone()),
            span: tracing::info_span!("test"),
        }
    }
}

/// A buffered response from the router.
pub struct Res {
    pub status: StatusCode,
    pub headers: http::HeaderMap,
    pub body: Vec<u8>,
}

impl Res {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "body is not JSON ({error}): {}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn content_type(&self) -> &str {
        self.headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }
}

/// Sends a request through the router. `admin` adds the bearer the admin
/// routes require.
pub async fn send(
    kit: &Kit,
    method: http::Method,
    path: &str,
    body: Option<(&str, Vec<u8>)>,
    admin: bool,
) -> Res {
    use tower::ServiceExt;
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if admin {
        builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {ADMIN}"));
    }
    let request = match body {
        Some((content_type, bytes)) => builder
            .header(http::header::CONTENT_TYPE, content_type)
            .body(axum::body::Body::from(bytes))
            .expect("request"),
        None => builder.body(axum::body::Body::empty()).expect("request"),
    };
    let response = kit
        .harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 16 * 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

pub async fn get(kit: &Kit, path: &str) -> Res {
    send(kit, http::Method::GET, path, None, true).await
}

pub async fn post_json(kit: &Kit, path: &str, body: &str) -> Res {
    send(
        kit,
        http::Method::POST,
        path,
        Some(("application/json", body.as_bytes().to_vec())),
        true,
    )
    .await
}

pub async fn patch_json(kit: &Kit, path: &str, body: &str) -> Res {
    send(
        kit,
        http::Method::PATCH,
        path,
        Some(("application/json", body.as_bytes().to_vec())),
        true,
    )
    .await
}

pub async fn delete(kit: &Kit, path: &str) -> Res {
    send(kit, http::Method::DELETE, path, None, true).await
}

/// Connects an account the way a person would: start, then follow the
/// callback with the state the module issued.
pub async fn connect(kit: &Kit) {
    let started = post_json(kit, "/v1/linkedin/admin/connect", "{}").await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text());
    let url = started.json()["authorize_url"]
        .as_str()
        .expect("authorize_url")
        .to_owned();
    let state = state_of(&url);
    let callback = send(
        kit,
        http::Method::GET,
        &format!("/v1/linkedin/callback?code=auth-code&state={state}"),
        None,
        false,
    )
    .await;
    assert_eq!(callback.status, StatusCode::OK, "{}", callback.text());
}

/// The `state` parameter out of an authorize URL.
pub fn state_of(authorize_url: &str) -> String {
    authorize_url
        .split("state=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("state in the authorize url")
        .to_owned()
}

/// A minimal valid PNG of the given size, for the upload tests.
pub fn png(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    bytes.extend_from_slice(&13u32.to_be_bytes());
    bytes.extend_from_slice(b"IHDR");
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
    bytes
}

/// One column of one row, for assertions the API does not expose.
pub fn column(kit: &Kit, sql: &str) -> Option<String> {
    let rows =
        pollster::block_on(kit.db.query(&cratefield_core::Statement::new(sql))).expect("query");
    rows.first().and_then(|row| {
        row.column_names()
            .next()
            .map(str::to_owned)
            .and_then(|name| row.get::<String>(&name))
    })
}

pub fn count(kit: &Kit, table: &str, where_clause: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) AS n FROM {table} WHERE {where_clause}");
    let rows =
        pollster::block_on(kit.db.query(&cratefield_core::Statement::new(&sql))).expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
}
