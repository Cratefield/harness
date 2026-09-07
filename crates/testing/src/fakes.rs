//! Fake ports for module tests (issue #9). All fakes are `Clone` handles
//! over shared interiors so they can be wired into `Ports` and still be
//! asserted on from the test.
//!
//! Interior mutability here records test observations; it is not request
//! state (ADR 0007) — the scoped `Mutex` allow follows the policy in the
//! workspace `clippy.toml`.

#![allow(clippy::disallowed_types)]
// Every accessor locks an unpoisoned fixture mutex; per-method `# Panics`
// sections would add noise without information.
#![allow(clippy::missing_panics_doc)]

use async_trait::async_trait;
use bytes::Bytes;
use factory0_core::{
    Captcha, CaptchaError, Clock, Database, DbError, Decision, Defer, HttpClient, HttpError,
    KeyValue, KvError, MailError, Mailer, Message, RateLimitError, RateLimiter, Row, Rows,
    SendOutcome, Statement, Verdict,
};
use futures_core::future::BoxFuture;
use http::{Request, Response};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// Recording fixtures, not request state (see module docs).
#[allow(clippy::disallowed_types)]
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// FakeMailer

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailerMode {
    SendOk,
    NotConfigured,
    Fail,
}

#[derive(Clone)]
pub struct FakeMailer {
    inner: Arc<FakeMailerInner>,
}

struct FakeMailerInner {
    mode: Mutex<MailerMode>,
    sent: Mutex<Vec<Message>>,
}

impl FakeMailer {
    #[must_use]
    pub fn new(mode: MailerMode) -> Self {
        Self {
            inner: Arc::new(FakeMailerInner {
                mode: Mutex::new(mode),
                sent: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Every message recorded so far.
    #[must_use]
    pub fn sent(&self) -> Vec<Message> {
        self.inner.sent.lock().expect("mailer lock").clone()
    }

    /// The most recent message.
    #[must_use]
    pub fn last_message(&self) -> Option<Message> {
        self.inner.sent.lock().expect("mailer lock").last().cloned()
    }

    /// Switches the mode (e.g. degrade to `NotConfigured` mid-test).
    pub fn set_mode(&self, mode: MailerMode) {
        *self.inner.mode.lock().expect("mailer lock") = mode;
    }
}

#[async_trait]
impl Mailer for FakeMailer {
    async fn send(&self, message: Message) -> Result<SendOutcome, MailError> {
        let mode = *self.inner.mode.lock().expect("mailer lock");
        match mode {
            MailerMode::SendOk => {
                let id = format!(
                    "fake-{}",
                    self.inner.sent.lock().expect("mailer lock").len()
                );
                self.inner.sent.lock().expect("mailer lock").push(message);
                Ok(SendOutcome::Sent { id })
            }
            MailerMode::NotConfigured => Ok(SendOutcome::NotConfigured),
            MailerMode::Fail => Err(MailError::Upstream("fake mailer failure".to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// FakeCaptcha

#[derive(Clone)]
pub struct FakeCaptcha {
    allow_all: bool,
    allowed_tokens: Arc<Vec<String>>,
}

impl FakeCaptcha {
    /// Every token verifies.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            allow_all: true,
            allowed_tokens: Arc::new(Vec::new()),
        }
    }

    /// Only the listed tokens verify.
    #[must_use]
    pub fn with_tokens(tokens: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allow_all: false,
            allowed_tokens: Arc::new(tokens.into_iter().map(Into::into).collect()),
        }
    }
}

#[async_trait]
impl Captcha for FakeCaptcha {
    async fn verify(&self, token: &str, _remote_ip: Option<&str>) -> Result<Verdict, CaptchaError> {
        let ok = self.allow_all || self.allowed_tokens.iter().any(|t| t == token);
        Ok(Verdict {
            ok,
            reason: (!ok).then(|| "token not allowed".to_string()),
        })
    }
}

// ---------------------------------------------------------------------------
// FakeRateLimiter (scripted)

#[derive(Clone)]
pub struct FakeRateLimiter {
    inner: Arc<FakeRateLimiterInner>,
}

struct FakeRateLimiterInner {
    scripted: Mutex<VecDeque<Decision>>,
    default: Decision,
    calls: AtomicUsize,
}

impl FakeRateLimiter {
    /// Falls through to `default` once the script is exhausted.
    #[must_use]
    pub fn scripted(decisions: Vec<Decision>, default: Decision) -> Self {
        Self {
            inner: Arc::new(FakeRateLimiterInner {
                scripted: Mutex::new(decisions.into_iter().collect()),
                default,
                calls: AtomicUsize::new(0),
            }),
        }
    }

    /// Always allows.
    #[must_use]
    pub fn always_allow() -> Self {
        Self::scripted(
            Vec::new(),
            Decision {
                ok: true,
                retry_after: None,
            },
        )
    }

    #[must_use]
    pub fn calls(&self) -> usize {
        self.inner.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl RateLimiter for FakeRateLimiter {
    async fn limit(&self, _key: &str) -> Result<Decision, RateLimitError> {
        self.inner.calls.fetch_add(1, Ordering::SeqCst);
        let scripted = self
            .inner
            .scripted
            .lock()
            .expect("limiter lock")
            .pop_front();
        Ok(scripted.unwrap_or_else(|| self.inner.default.clone()))
    }
}

// ---------------------------------------------------------------------------
// FixedClock

#[derive(Debug, Clone)]
pub struct FixedClock(pub time::OffsetDateTime);

#[async_trait]
impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

// ---------------------------------------------------------------------------
// MemoryKeyValue

#[derive(Clone, Default)]
pub struct MemoryKeyValue {
    inner: Arc<MemoryKeyValueInner>,
}

#[derive(Default)]
struct MemoryKeyValueInner {
    entries: Mutex<HashMap<String, String>>,
}

impl MemoryKeyValue {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KeyValue for MemoryKeyValue {
    async fn get(&self, key: &str) -> Result<Option<String>, KvError> {
        Ok(self
            .inner
            .entries
            .lock()
            .expect("kv lock")
            .get(key)
            .cloned())
    }

    async fn put(&self, key: &str, value: &str, _ttl: Option<Duration>) -> Result<(), KvError> {
        self.inner
            .entries
            .lock()
            .expect("kv lock")
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.inner.entries.lock().expect("kv lock").remove(key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FakeHttpClient (scripted responses, captures requests)

#[derive(Clone)]
pub struct FakeHttpClient {
    inner: Arc<FakeHttpInner>,
}

struct FakeHttpInner {
    responses: Mutex<VecDeque<Result<Response<Bytes>, HttpError>>>,
    captured: Mutex<Vec<(String, String, String)>>, // method, uri, body
}

impl FakeHttpClient {
    /// Responds with `responses` in order, then always with a 500.
    #[must_use]
    pub fn scripted(responses: Vec<Result<Response<Bytes>, HttpError>>) -> Self {
        Self {
            inner: Arc::new(FakeHttpInner {
                responses: Mutex::new(responses.into_iter().collect()),
                captured: Mutex::new(Vec::new()),
            }),
        }
    }

    #[must_use]
    pub fn ok_json(body: &'static str) -> Self {
        Self::scripted(vec![
            Response::builder()
                .status(200)
                .body(Bytes::from(body))
                .map_err(|err| HttpError::Transport(err.to_string())),
        ])
    }

    /// Every captured request as `(method, uri, body)`.
    #[must_use]
    pub fn captured(&self) -> Vec<(String, String, String)> {
        self.inner.captured.lock().expect("http lock").clone()
    }
}

#[async_trait]
impl HttpClient for FakeHttpClient {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        self.inner.captured.lock().expect("http lock").push((
            parts.method.to_string(),
            parts.uri.to_string(),
            String::from_utf8_lossy(&body).to_string(),
        ));
        let next = self.inner.responses.lock().expect("http lock").pop_front();
        next.unwrap_or_else(|| Err(HttpError::Transport("fake http exhausted".to_string())))
    }
}

// ---------------------------------------------------------------------------
// FakeDefer (collects futures; drain runs them)

#[derive(Clone, Default)]
pub struct FakeDefer {
    inner: Arc<FakeDeferInner>,
}

#[derive(Default)]
struct FakeDeferInner {
    pending: Mutex<Vec<BoxFuture<'static, ()>>>,
    deferred: AtomicUsize,
}

impl FakeDefer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs every deferred future to completion, in deferral order.
    // Async for API symmetry with `drain().await` call sites (the futures
    // run on a sync block-on inside).
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn drain(&self) {
        while !self.inner.pending.lock().expect("defer lock").is_empty() {
            let next = self.inner.pending.lock().expect("defer lock").remove(0);
            pollster::block_on(next);
        }
    }

    #[must_use]
    pub fn deferred_count(&self) -> usize {
        self.inner.deferred.load(Ordering::SeqCst)
    }
}

impl Defer for FakeDefer {
    fn wait_until(&self, fut: BoxFuture<'static, ()>) {
        self.inner.deferred.fetch_add(1, Ordering::SeqCst);
        self.inner.pending.lock().expect("defer lock").push(fut);
    }
}

// ---------------------------------------------------------------------------
// Transparent Database passthrough (re-exported for tests that need a
// trivial Database without SQLite): an always-empty database.

#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyDatabase;

#[async_trait]
impl Database for EmptyDatabase {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        Err(DbError::Execute(format!("empty database: {}", stmt.sql)))
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        if stmt.sql.trim() == "SELECT 1" {
            Ok(Rows::new(vec![Row::new(vec![(
                "1".to_string(),
                sea_query::Value::Int(Some(1)),
            )])]))
        } else {
            Err(DbError::Query(format!("empty database: {}", stmt.sql)))
        }
    }

    async fn batch(&self, _stmts: &[Statement]) -> Result<(), DbError> {
        Err(DbError::Batch("empty database".to_string()))
    }
}

/// An in-process [`Dispatcher`] that answers from an axum [`Router`], so a
/// module can be exercised through a sidecar mount without a network or a
/// second Worker (ADR 0009). The conformance kit uses it to run the same
/// assertions against both mounts (#64).
///
/// Also the failure fixture: [`unbound`](FakeDispatcher::unbound) has no
/// binding at all, and [`failing`](FakeDispatcher::failing) accepts the
/// binding and then refuses to answer.
#[derive(Clone)]
pub struct FakeDispatcher {
    binding: String,
    behaviour: FakeDispatch,
    calls: Arc<AtomicUsize>,
}

#[derive(Clone)]
enum FakeDispatch {
    Serve(Arc<Mutex<axum::Router>>),
    Unbound,
    Failing(String),
}

impl FakeDispatcher {
    /// Serves `router` on `binding`.
    #[must_use]
    pub fn serving(binding: impl Into<String>, router: axum::Router) -> Self {
        Self {
            binding: binding.into(),
            behaviour: FakeDispatch::Serve(Arc::new(Mutex::new(router))),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Has no bindings, so `has()` is always false: the "mounted but this
    /// deployment has no such binding" case.
    #[must_use]
    pub fn unbound() -> Self {
        Self {
            binding: String::new(),
            behaviour: FakeDispatch::Unbound,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Accepts `binding` and then fails to answer.
    #[must_use]
    pub fn failing(binding: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            binding: binding.into(),
            behaviour: FakeDispatch::Failing(reason.into()),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// How many dispatches were attempted. A forwarder must not retry, so a
    /// single request must leave this at one.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl factory0_core::Dispatcher for FakeDispatcher {
    fn has(&self, binding: &str) -> bool {
        !matches!(self.behaviour, FakeDispatch::Unbound) && binding == self.binding
    }

    async fn dispatch(
        &self,
        binding: &str,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, factory0_core::DispatchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.behaviour {
            FakeDispatch::Unbound => {
                Err(factory0_core::DispatchError::NotBound(binding.to_owned()))
            }
            FakeDispatch::Failing(reason) => Err(factory0_core::DispatchError::Unavailable {
                binding: binding.to_owned(),
                reason: reason.clone(),
            }),
            FakeDispatch::Serve(router) => {
                let router = router.lock().unwrap().clone();
                let (parts, body) = request.into_parts();
                let request = Request::from_parts(parts, axum::body::Body::from(body));
                let response =
                    tower::ServiceExt::oneshot(router, request)
                        .await
                        .map_err(|err| factory0_core::DispatchError::Unavailable {
                            binding: binding.to_owned(),
                            reason: err.to_string(),
                        })?;
                let (parts, body) = response.into_parts();
                let bytes = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .map_err(|err| factory0_core::DispatchError::Unavailable {
                        binding: binding.to_owned(),
                        reason: err.to_string(),
                    })?;
                Ok(Response::from_parts(parts, bytes))
            }
        }
    }
}
