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
use cratefield_core::{
    Captcha, CaptchaError, Clock, Completion, Credential, Database, DbError, Decision, Defer,
    Destination, Filed, HttpClient, HttpError, KeyValue, KvError, Mailer, MailError, Message,
    ModelTier, Prompt, RateLimiter, RateLimitError, Row, Rows, SendOutcome, Statement, TextModel,
    TextModelError, TicketDraft, TicketState, TicketStatus, Tracker, TrackerError, Verdict,
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

/// How a [`FakeMailer`] answers.
///
/// [`Error`](Self::Error) is what makes the failure arms testable at all
/// (issue #236): before it the fake could only ever produce
/// `MailError::Upstream("fake mailer failure")`, so `Invalid { detail }`
/// and `DomainNotVerified { domain }` — the two variants that carry the
/// provider's own text, and therefore the two that can carry a recipient
/// address — could not be driven from a test. Every arm of a caller's
/// outcome mapping is now reachable, with the text the caller chooses:
///
/// ```
/// # use cratefield_testing::{FakeMailer, MailerMode};
/// # use cratefield_core::MailError;
/// let mailer = FakeMailer::new(MailerMode::Error(MailError::Invalid {
///     detail: "to: alice@example.test is suppressed".to_owned(),
/// }));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailerMode {
    /// Accept and record the message.
    SendOk,
    /// Report that the adapter has no API key or no verified domain.
    NotConfigured,
    /// A generic upstream failure, for a caller that does not care which.
    Fail,
    /// Exactly this error, text and all.
    Error(MailError),
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
        let mode = self.inner.mode.lock().expect("mailer lock").clone();
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
            MailerMode::Error(error) => Err(error),
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

    fn binding(&self) -> Option<cratefield_core::CaptchaBinding> {
        Some(cratefield_core::CaptchaBinding {
            hostname_bound: true,
            action_bound: true,
            fail_open: false,
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

    async fn batch_atomic(&self, _stmts: &[Statement]) -> Result<(), DbError> {
        Err(DbError::Batch("empty database".to_string()))
    }
}

/// An in-process [`Dispatcher`](cratefield_core::Dispatcher) that answers from an
/// axum [`Router`](axum::Router), so a
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
impl cratefield_core::Dispatcher for FakeDispatcher {
    fn has(&self, binding: &str) -> bool {
        !matches!(self.behaviour, FakeDispatch::Unbound) && binding == self.binding
    }

    async fn dispatch(
        &self,
        binding: &str,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, cratefield_core::DispatchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.behaviour {
            FakeDispatch::Unbound => {
                Err(cratefield_core::DispatchError::NotBound(binding.to_owned()))
            }
            FakeDispatch::Failing(reason) => Err(cratefield_core::DispatchError::Unavailable {
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
                        .map_err(|err| cratefield_core::DispatchError::Unavailable {
                            binding: binding.to_owned(),
                            reason: err.to_string(),
                        })?;
                let (parts, body) = response.into_parts();
                let bytes = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .map_err(|err| cratefield_core::DispatchError::Unavailable {
                        binding: binding.to_owned(),
                        reason: err.to_string(),
                    })?;
                Ok(Response::from_parts(parts, bytes))
            }
        }
    }
}

/// An in-memory [`cratefield_core::Blob`] store for module tests: keeps objects
/// in a map, and has no presigned URLs (so `signed_url` reports `Unsupported`,
/// as a directory store does).
#[derive(Clone, Default)]
pub struct MemoryBlob {
    objects: Arc<std::sync::Mutex<std::collections::HashMap<String, cratefield_core::BlobObject>>>,
}

impl MemoryBlob {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many objects are stored, for assertions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.lock().unwrap().len()
    }

    /// Whether the store is empty, for assertions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl cratefield_core::Blob for MemoryBlob {
    async fn put(
        &self,
        key: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> Result<(), cratefield_core::BlobError> {
        cratefield_core::check_blob_size(bytes)?;
        self.objects.lock().unwrap().insert(
            key.to_owned(),
            cratefield_core::BlobObject {
                bytes: bytes.to_vec(),
                content_type: content_type.to_owned(),
            },
        );
        Ok(())
    }
    async fn get(
        &self,
        key: &str,
    ) -> Result<Option<cratefield_core::BlobObject>, cratefield_core::BlobError> {
        Ok(self.objects.lock().unwrap().get(key).cloned())
    }
    async fn delete(&self, key: &str) -> Result<(), cratefield_core::BlobError> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }
    async fn signed_url(
        &self,
        _key: &str,
        _ttl: std::time::Duration,
    ) -> Result<String, cratefield_core::BlobError> {
        Err(cratefield_core::BlobError::Unsupported(
            "in-memory store has no presigned URLs".to_owned(),
        ))
    }
}

// ---------------------------------------------------------------------------
// FakePush

/// How a [`FakePush`] responds, mirroring [`MailerMode`] for the push port.
///
/// [`Error`](Self::Error) carries the provider text a real adapter would
/// have wrapped (issue #236). The fixed modes only ever produce clean
/// strings, so no test using them could show a device token or a push
/// endpoint arriving somewhere it should not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushMode {
    /// Accept and record the notification.
    DeliverOk,
    /// Report the adapter is not configured (no key).
    NotConfigured,
    /// Report the device token is dead (APNs `410`): the caller prunes it.
    Unregistered,
    /// A retryable failure.
    Transient,
    /// Exactly this error, text and all.
    Error(cratefield_core::PushError),
}

/// An in-memory [`cratefield_core::Push`] for module tests: records every
/// `(recipient, notification)` and answers according to its [`PushMode`].
///
/// The mode is global by default and can be overridden **per recipient**
/// ([`FakePush::set_mode_for`]), so a fan-out test can make exactly one of
/// five devices dead and assert that only that one is pruned — the thing a
/// single global mode cannot express (issue #177).
#[derive(Clone)]
pub struct FakePush {
    inner: Arc<FakePushInner>,
}

struct FakePushInner {
    mode: Mutex<PushMode>,
    per_recipient: Mutex<HashMap<cratefield_core::Recipient, PushMode>>,
    sent: Mutex<Vec<(cratefield_core::Recipient, cratefield_core::Notification)>>,
}

impl FakePush {
    #[must_use]
    pub fn new(mode: PushMode) -> Self {
        Self {
            inner: Arc::new(FakePushInner {
                mode: Mutex::new(mode),
                per_recipient: Mutex::new(HashMap::new()),
                sent: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Every `(recipient, notification)` delivered so far. A send that
    /// answered `NotConfigured` or failed is not recorded.
    #[must_use]
    pub fn sent(&self) -> Vec<(cratefield_core::Recipient, cratefield_core::Notification)> {
        self.inner.sent.lock().expect("push lock").clone()
    }

    /// The most recent `(recipient, notification)`.
    #[must_use]
    pub fn last(&self) -> Option<(cratefield_core::Recipient, cratefield_core::Notification)> {
        self.inner.sent.lock().expect("push lock").last().cloned()
    }

    /// Everything delivered to one recipient.
    #[must_use]
    pub fn sent_to(
        &self,
        recipient: &cratefield_core::Recipient,
    ) -> Vec<cratefield_core::Notification> {
        self.inner
            .sent
            .lock()
            .expect("push lock")
            .iter()
            .filter(|(to, _)| to == recipient)
            .map(|(_, notification)| notification.clone())
            .collect()
    }

    /// Switches the mode every recipient without an override answers with
    /// (e.g. flip to `Unregistered` mid-test).
    pub fn set_mode(&self, mode: PushMode) {
        *self.inner.mode.lock().expect("push lock") = mode;
    }

    /// Makes one recipient answer with `mode`, whatever the global mode is —
    /// one dead token among live ones, say.
    pub fn set_mode_for(&self, recipient: &cratefield_core::Recipient, mode: PushMode) {
        self.inner
            .per_recipient
            .lock()
            .expect("push lock")
            .insert(recipient.clone(), mode);
    }

    /// Drops one recipient's override, putting it back on the global mode.
    pub fn clear_mode_for(&self, recipient: &cratefield_core::Recipient) {
        self.inner
            .per_recipient
            .lock()
            .expect("push lock")
            .remove(recipient);
    }

    /// The mode `recipient` will answer with.
    #[must_use]
    pub fn mode_for(&self, recipient: &cratefield_core::Recipient) -> PushMode {
        self.inner
            .per_recipient
            .lock()
            .expect("push lock")
            .get(recipient)
            .cloned()
            .unwrap_or_else(|| self.inner.mode.lock().expect("push lock").clone())
    }
}

impl Default for FakePush {
    fn default() -> Self {
        Self::new(PushMode::DeliverOk)
    }
}

#[async_trait]
impl cratefield_core::Push for FakePush {
    async fn send(
        &self,
        to: &cratefield_core::Recipient,
        notification: &cratefield_core::Notification,
    ) -> Result<cratefield_core::PushOutcome, cratefield_core::PushError> {
        match self.mode_for(to) {
            PushMode::DeliverOk => {
                let id = format!(
                    "fake-push-{}",
                    self.inner.sent.lock().expect("push lock").len()
                );
                self.inner
                    .sent
                    .lock()
                    .expect("push lock")
                    .push((to.clone(), notification.clone()));
                Ok(cratefield_core::PushOutcome::Delivered { id: Some(id) })
            }
            PushMode::NotConfigured => Ok(cratefield_core::PushOutcome::NotConfigured),
            PushMode::Unregistered => Err(cratefield_core::PushError::Unregistered),
            PushMode::Transient => Err(cratefield_core::PushError::transient("fake push failure")),
            PushMode::Error(error) => Err(error),
        }
    }
}

// ---------------------------------------------------------------------------
// FakeTextModel

/// How a [`FakeTextModel`] answers, mirroring [`PushMode`] for the text
/// model port (issue #429).
///
/// [`Error`](Self::Error) carries the exact error a test wants, and
/// [`Rejected`](Self::Rejected)/[`Transient`](Self::Transient) are the two
/// fixed modes the port's own contract names — a caller's retry and
/// back-off arms stay reachable without inventing provider responses.
#[derive(Debug, Clone, PartialEq)]
pub enum TextModelMode {
    /// Complete with this text, under a deterministic `fake-<tier>` model
    /// name and plausible token counts.
    Reply(String),
    /// Answer exactly this completion, usage and parsed JSON included.
    Complete(cratefield_core::Completion),
    /// Report the tier is unwired (`TextModelError::NotConfigured`).
    NotConfigured,
    /// A non-retryable refusal carrying the provider text.
    Rejected(String),
    /// A retryable failure with the provider's back-off, where it said one.
    Transient { retry_after: Option<Duration> },
    /// Exactly this error, text and all.
    Error(cratefield_core::TextModelError),
}

/// An in-memory [`TextModel`] for module tests: records every [`Prompt`]
/// it completed and answers according to its [`TextModelMode`].
///
/// The mode is global by default and can be overridden **per tier**
/// ([`FakeTextModel::set_mode_for`]), mirroring [`FakePush`]'s
/// per-recipient override — the natural analogue, and the thing the port
/// exists for: one test can wire the fast tier to a drafted reply and the
/// strong tier to a refusal, and watch a module treat the two differently
/// without either vendor being named.
///
/// A completion that answered `NotConfigured` or failed is **not**
/// recorded, the same rule [`FakePush`] applies to a send — the recording
/// means "the model answered", and a caller that retried on
/// `Transient { .. }` then sees one recorded prompt per attempt it got an
/// answer for.
#[derive(Clone)]
pub struct FakeTextModel {
    inner: Arc<FakeTextModelInner>,
}

struct FakeTextModelInner {
    mode: Mutex<TextModelMode>,
    per_tier: Mutex<HashMap<ModelTier, TextModelMode>>,
    prompts: Mutex<Vec<Prompt>>,
}

/// Plausible, deterministic token counts for a fake answer: roughly four
/// characters per token on both sides. Stable for a given prompt and text,
/// which is what an assertion needs — no test wants to guess a provider's
/// tokenizer.
fn fake_usage(prompt: &Prompt, text: &str) -> (u64, u64) {
    let prompt_chars = prompt.system.as_deref().map_or(0, str::len)
        + prompt
            .messages
            .iter()
            .map(|turn| turn.content.len())
            .sum::<usize>();
    let input = (prompt_chars / 4).max(1) as u64;
    let output = (text.len() / 4).max(1) as u64;
    (input, output)
}

impl FakeTextModel {
    #[must_use]
    pub fn new(mode: TextModelMode) -> Self {
        Self {
            inner: Arc::new(FakeTextModelInner {
                mode: Mutex::new(mode),
                per_tier: Mutex::new(HashMap::new()),
                prompts: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Every prompt answered so far, in order. A completion that answered
    /// `NotConfigured` or failed is not recorded.
    #[must_use]
    pub fn prompts(&self) -> Vec<Prompt> {
        self.inner.prompts.lock().expect("text model lock").clone()
    }

    /// The most recent prompt answered.
    #[must_use]
    pub fn last(&self) -> Option<Prompt> {
        self.inner
            .prompts
            .lock()
            .expect("text model lock")
            .last()
            .cloned()
    }

    /// Switches the mode every tier without an override answers with
    /// (e.g. flip to `NotConfigured` mid-test).
    pub fn set_mode(&self, mode: TextModelMode) {
        *self.inner.mode.lock().expect("text model lock") = mode;
    }

    /// Makes one tier answer with `mode`, whatever the global mode is —
    /// the fast tier drafting and the strong tier refusing, say.
    pub fn set_mode_for(&self, tier: ModelTier, mode: TextModelMode) {
        self.inner
            .per_tier
            .lock()
            .expect("text model lock")
            .insert(tier, mode);
    }

    /// Drops one tier's override, putting it back on the global mode.
    pub fn clear_mode_for(&self, tier: ModelTier) {
        self.inner
            .per_tier
            .lock()
            .expect("text model lock")
            .remove(&tier);
    }

    /// The mode `tier` will answer with.
    #[must_use]
    pub fn mode_for(&self, tier: ModelTier) -> TextModelMode {
        self.inner
            .per_tier
            .lock()
            .expect("text model lock")
            .get(&tier)
            .cloned()
            .unwrap_or_else(|| self.inner.mode.lock().expect("text model lock").clone())
    }

    fn record(&self, prompt: &Prompt) {
        self.inner
            .prompts
            .lock()
            .expect("text model lock")
            .push(prompt.clone());
    }
}

impl Default for FakeTextModel {
    fn default() -> Self {
        Self::new(TextModelMode::Reply("fake completion".to_owned()))
    }
}

#[async_trait]
impl TextModel for FakeTextModel {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError> {
        match self.mode_for(prompt.tier) {
            TextModelMode::Reply(text) => {
                self.record(prompt);
                let (input_tokens, output_tokens) = fake_usage(prompt, &text);
                Ok(
                    Completion::new(text, format!("fake-{}", prompt.tier.name()))
                        .usage(input_tokens, output_tokens),
                )
            }
            TextModelMode::Complete(completion) => {
                self.record(prompt);
                Ok(completion)
            }
            TextModelMode::NotConfigured => Err(TextModelError::NotConfigured),
            TextModelMode::Rejected(message) => Err(TextModelError::Rejected(message)),
            TextModelMode::Transient { retry_after } => {
                Err(TextModelError::Transient { retry_after })
            }
            TextModelMode::Error(error) => Err(error),
        }
    }
}

// ---------------------------------------------------------------------------
// FakePayments

/// How a [`FakePayments`] responds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentsMode {
    /// Succeed and record the call.
    Ok,
    /// Report `NotConfigured` (no Stripe key).
    NotConfigured,
    /// A retryable failure.
    Transient,
}

/// What a [`FakePayments`] recorded, for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentsCall {
    Checkout,
    SubscriptionCheckout,
    ConnectAccountLink,
    ChargeWithTransfer,
    Refund,
    VerifyWebhook,
}

/// An in-memory [`cratefield_core::Payments`] for module tests: records which
/// calls were made and answers per its [`PaymentsMode`]. `verify_webhook`
/// treats a signature header of `"invalid"` as a tampered event.
#[derive(Clone)]
pub struct FakePayments {
    inner: Arc<FakePaymentsInner>,
}

struct FakePaymentsInner {
    mode: Mutex<PaymentsMode>,
    calls: Mutex<Vec<PaymentsCall>>,
}

impl FakePayments {
    #[must_use]
    pub fn new(mode: PaymentsMode) -> Self {
        Self {
            inner: Arc::new(FakePaymentsInner {
                mode: Mutex::new(mode),
                calls: Mutex::new(Vec::new()),
            }),
        }
    }

    /// The calls recorded so far.
    #[must_use]
    pub fn calls(&self) -> Vec<PaymentsCall> {
        self.inner.calls.lock().expect("payments lock").clone()
    }

    pub fn set_mode(&self, mode: PaymentsMode) {
        *self.inner.mode.lock().expect("payments lock") = mode;
    }

    fn record(&self, call: PaymentsCall) {
        self.inner.calls.lock().expect("payments lock").push(call);
    }

    fn guard(&self) -> Result<(), cratefield_core::PaymentsError> {
        match *self.inner.mode.lock().expect("payments lock") {
            PaymentsMode::Ok => Ok(()),
            PaymentsMode::NotConfigured => Err(cratefield_core::PaymentsError::NotConfigured),
            PaymentsMode::Transient => Err(cratefield_core::PaymentsError::Transient(
                "fake payments failure".to_owned(),
            )),
        }
    }
}

impl Default for FakePayments {
    fn default() -> Self {
        Self::new(PaymentsMode::Ok)
    }
}

#[async_trait]
impl cratefield_core::Payments for FakePayments {
    async fn create_checkout(
        &self,
        _request: &cratefield_core::CheckoutRequest,
    ) -> Result<cratefield_core::CheckoutSession, cratefield_core::PaymentsError> {
        self.guard()?;
        self.record(PaymentsCall::Checkout);
        Ok(cratefield_core::CheckoutSession {
            id: "cs_fake".to_owned(),
            url: "https://checkout.stripe.test/cs_fake".to_owned(),
        })
    }

    async fn create_subscription_checkout(
        &self,
        _request: &cratefield_core::SubscriptionCheckoutRequest,
    ) -> Result<cratefield_core::CheckoutSession, cratefield_core::PaymentsError> {
        self.guard()?;
        self.record(PaymentsCall::SubscriptionCheckout);
        Ok(cratefield_core::CheckoutSession {
            id: "cs_sub_fake".to_owned(),
            url: "https://checkout.stripe.test/cs_sub_fake".to_owned(),
        })
    }

    async fn create_connect_account_link(
        &self,
        _request: &cratefield_core::ConnectAccountLinkRequest,
    ) -> Result<cratefield_core::ConnectAccountLink, cratefield_core::PaymentsError> {
        self.guard()?;
        self.record(PaymentsCall::ConnectAccountLink);
        Ok(cratefield_core::ConnectAccountLink {
            account_id: "acct_fake".to_owned(),
            url: "https://connect.stripe.test/acct_fake".to_owned(),
        })
    }

    async fn charge_with_transfer(
        &self,
        _request: &cratefield_core::TransferCharge,
    ) -> Result<cratefield_core::Charge, cratefield_core::PaymentsError> {
        self.guard()?;
        self.record(PaymentsCall::ChargeWithTransfer);
        Ok(cratefield_core::Charge {
            id: "pi_fake".to_owned(),
            status: "succeeded".to_owned(),
        })
    }

    async fn refund(
        &self,
        _request: &cratefield_core::RefundRequest,
    ) -> Result<cratefield_core::Refund, cratefield_core::PaymentsError> {
        self.guard()?;
        self.record(PaymentsCall::Refund);
        Ok(cratefield_core::Refund {
            id: "re_fake".to_owned(),
        })
    }

    async fn verify_webhook(
        &self,
        signature_header: &str,
        _body: &[u8],
    ) -> Result<cratefield_core::WebhookEvent, cratefield_core::PaymentsError> {
        self.record(PaymentsCall::VerifyWebhook);
        if signature_header == "invalid" {
            return Err(cratefield_core::PaymentsError::SignatureInvalid(
                "fake tampered signature".to_owned(),
            ));
        }
        self.guard()?;
        Ok(cratefield_core::WebhookEvent {
            id: "evt_fake".to_owned(),
            kind: "checkout.session.completed".to_owned(),
            data: serde_json::json!({ "object": "checkout.session" }),
        })
    }
}

// ---------------------------------------------------------------------------
// FakeTracker

/// A short, non-reversible stand-in for a [`Credential`] in a recorded
/// call, after `push.rs`'s `fingerprint` for `Recipient`: enough to tell
/// two credentials apart in an assertion, useless for recovering the
/// token.
///
/// `push.rs` hashes with `sha2`, which is not a dependency of the kit; a
/// test fake needs no cross-version stability and no collision resistance
/// beyond "different credentials assert differently", so std's
/// [`DefaultHasher`](std::hash::DefaultHasher) does the same job. The
/// plaintext is never stored — that is the point of the port: a fake that
/// recorded the secret would make every "the token went nowhere" assertion
/// unfalsifiable.
fn fingerprint(credential: &Credential) -> String {
    use std::hash::{Hash, Hasher};

    // The one `expose` in the kit: the fingerprint is computed and the
    // borrow dropped before anything is recorded.
    let mut hasher = std::hash::DefaultHasher::new();
    credential.expose().hash(&mut hasher);
    format!("fp:{:016x}", hasher.finish())
}

/// How a [`FakeTracker`] answers, mirroring [`MailerMode`] and [`PushMode`]
/// for the tracker port (issue #431).
///
/// [`Error`](Self::Error) carries the exact `TrackerError` a test wants,
/// text and delay and all (issue #236's rule): the fixed modes only ever
/// produce clean strings, so the arms of a caller's outcome mapping — a
/// `Rejected` carrying the tracker's own words, a `Transient` carrying a
/// provider-stated delay — would otherwise be unreachable from a test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackerMode {
    /// Accept and record the ticket.
    FileOk,
    /// Report that no adapter is configured for this destination.
    NotConfigured,
    /// Report that the per-tenant credential was refused (`401`/`403`).
    Unauthorized,
    /// Report that the tracker refused the ticket — a `4xx` about the
    /// draft, not about the credential.
    Rejected,
    /// A retryable failure with no delay stated.
    Transient,
    /// Exactly this error, text and all.
    Error(TrackerError),
}

/// One `Tracker::file` a [`FakeTracker`] accepted, for assertions.
///
/// The credential appears only as its non-reversible
/// `fingerprint`: proof that a credential reached the port, and never
/// the secret itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiledCall {
    /// Where the ticket was filed.
    pub dest: Destination,
    /// The ticket as the caller handed it over.
    pub draft: TicketDraft,
    /// A fingerprint of the credential the caller passed.
    pub credential_fingerprint: String,
}

/// One `Tracker::status` a [`FakeTracker`] accepted, for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusedCall {
    /// Where the ticket lives.
    pub dest: Destination,
    /// The external id the caller asked about.
    pub external_id: String,
    /// A fingerprint of the credential the caller passed.
    pub credential_fingerprint: String,
}

/// An in-memory [`Tracker`] for module tests: records every accepted
/// `file`/`status` call and answers according to its [`TrackerMode`]. A
/// call the mode answered with an error is not recorded, as [`FakePush`]
/// does not record a failed send.
///
/// The mode is global by default and can be overridden **per destination**
/// ([`FakeTracker::set_mode_for`]), the [`FakePush`] shape: one tenant's
/// expired token among live ones. The state an accepted `status` reports
/// is scripted separately ([`FakeTracker::set_state`]), because "the file
/// succeeded" and "the ticket has moved on since" are two different
/// answers a test wants to set independently.
#[derive(Clone, Debug)]
pub struct FakeTracker {
    inner: Arc<FakeTrackerInner>,
}

#[derive(Debug)]
struct FakeTrackerInner {
    mode: Mutex<TrackerMode>,
    per_destination: Mutex<HashMap<Destination, TrackerMode>>,
    filed: Mutex<Vec<FiledCall>>,
    statused: Mutex<Vec<StatusedCall>>,
    state: Mutex<TicketState>,
}

impl FakeTracker {
    #[must_use]
    pub fn new(mode: TrackerMode) -> Self {
        Self {
            inner: Arc::new(FakeTrackerInner {
                mode: Mutex::new(mode),
                per_destination: Mutex::new(HashMap::new()),
                filed: Mutex::new(Vec::new()),
                statused: Mutex::new(Vec::new()),
                state: Mutex::new(TicketState::Open),
            }),
        }
    }

    /// Every `file` accepted so far, in order.
    #[must_use]
    pub fn filed(&self) -> Vec<FiledCall> {
        self.inner.filed.lock().expect("tracker lock").clone()
    }

    /// The most recent `file` accepted.
    #[must_use]
    pub fn last_filed(&self) -> Option<FiledCall> {
        self.inner
            .filed
            .lock()
            .expect("tracker lock")
            .last()
            .cloned()
    }

    /// Every `status` accepted so far, in order.
    #[must_use]
    pub fn statused(&self) -> Vec<StatusedCall> {
        self.inner.statused.lock().expect("tracker lock").clone()
    }

    /// Switches the mode every destination without an override answers
    /// with (e.g. flip to `Unauthorized` mid-test).
    pub fn set_mode(&self, mode: TrackerMode) {
        *self.inner.mode.lock().expect("tracker lock") = mode;
    }

    /// Makes one destination answer with `mode`, whatever the global mode
    /// is — one tenant's expired token among live ones, say.
    pub fn set_mode_for(&self, dest: &Destination, mode: TrackerMode) {
        self.inner
            .per_destination
            .lock()
            .expect("tracker lock")
            .insert(dest.clone(), mode);
    }

    /// Drops one destination's override, putting it back on the global
    /// mode.
    pub fn clear_mode_for(&self, dest: &Destination) {
        self.inner
            .per_destination
            .lock()
            .expect("tracker lock")
            .remove(dest);
    }

    /// The mode `dest` will answer with.
    #[must_use]
    pub fn mode_for(&self, dest: &Destination) -> TrackerMode {
        self.inner
            .per_destination
            .lock()
            .expect("tracker lock")
            .get(dest)
            .cloned()
            .unwrap_or_else(|| self.inner.mode.lock().expect("tracker lock").clone())
    }

    /// The state an accepted `status` reports.
    pub fn set_state(&self, state: TicketState) {
        *self.inner.state.lock().expect("tracker lock") = state;
    }

    /// The state an accepted `status` currently reports.
    #[must_use]
    pub fn state(&self) -> TicketState {
        *self.inner.state.lock().expect("tracker lock")
    }

    /// The error arms shared by `file` and `status`: the same fixed modes
    /// script both, the way a real adapter answers the one `TrackerError`
    /// vocabulary on both methods.
    fn error_for(mode: &TrackerMode) -> Option<TrackerError> {
        match mode {
            TrackerMode::FileOk => None,
            TrackerMode::NotConfigured => Some(TrackerError::NotConfigured),
            TrackerMode::Unauthorized => Some(TrackerError::Unauthorized),
            TrackerMode::Rejected => {
                Some(TrackerError::Rejected("fake tracker rejection".to_owned()))
            }
            TrackerMode::Transient => Some(TrackerError::Transient { retry_after: None }),
            TrackerMode::Error(error) => Some(error.clone()),
        }
    }
}

impl Default for FakeTracker {
    fn default() -> Self {
        Self::new(TrackerMode::FileOk)
    }
}

#[async_trait]
impl Tracker for FakeTracker {
    async fn file(
        &self,
        dest: &Destination,
        cred: &Credential,
        draft: &TicketDraft,
    ) -> Result<Filed, TrackerError> {
        if let Some(error) = Self::error_for(&self.mode_for(dest)) {
            return Err(error);
        }
        let id = format!(
            "fake-{}",
            self.inner.filed.lock().expect("tracker lock").len()
        );
        self.inner
            .filed
            .lock()
            .expect("tracker lock")
            .push(FiledCall {
                dest: dest.clone(),
                draft: draft.clone(),
                credential_fingerprint: fingerprint(cred),
            });
        Ok(Filed {
            url: format!("https://tracker.fake.test/browse/{id}"),
            external_id: id,
        })
    }

    async fn status(
        &self,
        dest: &Destination,
        cred: &Credential,
        external_id: &str,
    ) -> Result<TicketStatus, TrackerError> {
        if let Some(error) = Self::error_for(&self.mode_for(dest)) {
            return Err(error);
        }
        self.inner
            .statused
            .lock()
            .expect("tracker lock")
            .push(StatusedCall {
                dest: dest.clone(),
                external_id: external_id.to_owned(),
                credential_fingerprint: fingerprint(cred),
            });
        Ok(TicketStatus {
            external_id: external_id.to_owned(),
            state: self.state(),
            url: None,
        })
    }
}

// ---------------------------------------------------------------------------
// FakeRealtime

/// Room id -> the member ids a [`FakeRealtime`] reports for it.
type RealtimeMembers = std::collections::HashMap<String, Vec<String>>;
/// The `(room_id, message)` broadcasts a [`FakeRealtime`] recorded.
type RealtimeBroadcasts = Vec<(String, Vec<u8>)>;

/// An in-memory [`cratefield_core::Realtime`] for module tests: records every
/// broadcast per room and reports a fixed member list. It exercises the port a
/// module holds (broadcast/members from outside a socket); the socket lifecycle
/// and `RoomHandler` are the runtime adapter's job, covered by the native
/// adapter's own tests.
#[derive(Clone, Default)]
pub struct FakeRealtime {
    broadcasts: Arc<Mutex<RealtimeBroadcasts>>,
    members: Arc<Mutex<RealtimeMembers>>,
}

impl FakeRealtime {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Presets the members a room reports (for `members` assertions).
    pub fn set_members(&self, room_id: &str, ids: &[&str]) {
        self.members.lock().expect("realtime lock").insert(
            room_id.to_owned(),
            ids.iter().map(|id| (*id).to_owned()).collect(),
        );
    }

    /// Every `(room_id, message)` broadcast so far.
    #[must_use]
    pub fn broadcasts(&self) -> Vec<(String, Vec<u8>)> {
        self.broadcasts.lock().expect("realtime lock").clone()
    }
}

#[async_trait]
impl cratefield_core::Realtime for FakeRealtime {
    async fn broadcast(
        &self,
        room_id: &str,
        message: &[u8],
    ) -> Result<(), cratefield_core::RealtimeError> {
        self.broadcasts
            .lock()
            .expect("realtime lock")
            .push((room_id.to_owned(), message.to_vec()));
        Ok(())
    }

    async fn members(
        &self,
        room_id: &str,
    ) -> Result<Vec<cratefield_core::Member>, cratefield_core::RealtimeError> {
        Ok(self
            .members
            .lock()
            .expect("realtime lock")
            .get(room_id)
            .map(|ids| ids.iter().map(cratefield_core::Member::new).collect())
            .unwrap_or_default())
    }
}

/// What a [`FakeAuth`] answers.
///
/// Every outcome the port has, because a fake that cannot produce one
/// makes the arm handling it unreachable from every test — which is how
/// a five-arm mapping shipped with four of the arms never executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Every request is anonymous, header or not. The deployment where
    /// nobody signs in.
    Anonymous,
    /// A bearer token is taken at face value as the subject's id, and a
    /// request with no `Authorization` header is anonymous. The mode for
    /// a test that wants both branches without minting a JWT.
    TokenIsTheSubject,
    /// Every presented credential is refused, and a request with no
    /// header is still anonymous — the distinction the port exists to
    /// keep.
    NotVerified,
    /// The verifier cannot answer, credential or not.
    Unavailable,
}

/// A [`cratefield_core::Auth`] answering from a mode rather than from
/// a key set.
pub struct FakeAuth {
    mode: AuthMode,
    calls: std::sync::Mutex<Vec<String>>,
}

impl FakeAuth {
    /// A fake in `mode`.
    #[must_use]
    pub fn new(mode: AuthMode) -> Self {
        Self {
            mode,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A fake that reads the bearer token as the subject's id.
    #[must_use]
    pub fn subjects() -> Self {
        Self::new(AuthMode::TokenIsTheSubject)
    }

    /// The bearer values it was asked about, in order. `""` records a
    /// request that carried no `Authorization` header at all.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("uncontended").clone()
    }
}

#[async_trait::async_trait]
impl cratefield_core::Auth for FakeAuth {
    async fn identify(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<cratefield_core::Caller, cratefield_core::AuthError> {
        let presented = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::to_owned);
        self.calls
            .lock()
            .expect("uncontended")
            .push(presented.clone().unwrap_or_default());
        match self.mode {
            AuthMode::Anonymous => Ok(cratefield_core::Caller::Anonymous),
            AuthMode::Unavailable => Err(cratefield_core::AuthError::Unavailable(
                "the fake is in Unavailable mode".to_owned(),
            )),
            AuthMode::NotVerified | AuthMode::TokenIsTheSubject => match presented {
                None => Ok(cratefield_core::Caller::Anonymous),
                Some(_) if self.mode == AuthMode::NotVerified => {
                    Err(cratefield_core::AuthError::NotVerified)
                }
                Some(token) => Ok(cratefield_core::Caller::Subject(
                    cratefield_core::Subject::new(token).session("fake-session"),
                )),
            },
        }
    }
}
