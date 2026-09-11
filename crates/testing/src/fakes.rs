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

    async fn batch(&self, _stmts: &[Statement]) -> Result<(), DbError> {
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
