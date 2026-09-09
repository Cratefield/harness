//! Port traits (ADR 0002, architecture section 5). Modules see these traits
//! and nothing else — never a Cloudflare binding, never a vendor client.
//!
//! All traits are `Send + Sync` and object-safe, used as `Arc<dyn Trait>`.
//! Async methods use `async_trait` until native `async fn` in traits is
//! ergonomic for trait objects.

mod blob;
mod captcha;
mod clock;
mod database;
mod defer;
mod dispatcher;
mod http;
mod idgen;
mod kv;
mod mailer;
mod payments;
mod push;
mod rate_limiter;
mod realtime;
pub(crate) mod signer;

pub use blob::{Blob, BlobError, BlobObject, MAX_BLOB_BYTES, ScopedBlob, check_blob_size};
pub use captcha::{Captcha, CaptchaBinding, CaptchaError, Verdict};
pub use clock::{Clock, SystemClock, timeout};
pub use database::{Database, DbError, Row, Rows, Statement, TryFromValue};
pub use defer::{Defer, NoopDefer};
pub use dispatcher::{DispatchError, Dispatcher};
pub use http::{
    BoundedHttpClient, DEFAULT_RESPONSE_TIMEOUT, HttpClient, HttpError, HttpPolicy,
    MAX_CONCURRENT_REQUESTS, MAX_RESPONSE_BYTES, MAX_RESPONSE_TIMEOUT, declared_content_length,
};
pub use idgen::{IdGen, UlidIdGen};
pub use kv::{KeyValue, KvError};
pub use mailer::{MailError, Mailer, Message, SendOutcome};
pub use payments::{
    Charge, CheckoutRequest, CheckoutSession, ConnectAccountLink, ConnectAccountLinkRequest,
    LineItem, Money, Payments, PaymentsError, Refund, RefundRequest, SubscriptionCheckoutRequest,
    TransferCharge, WebhookEvent,
};
pub use push::{
    LocKeys, Notification, Platform, Priority, Push, PushError, PushOutcome, Recipient, RoutingPush,
};
pub use rate_limiter::{Decision, RateLimitError, RateLimiter};
pub use realtime::{Member, Realtime, RealtimeError, RoomContext, RoomHandler};
pub use signer::{Kid, MAX_KID_NAME, Payload, SignatureError, Signer};

use crate::config::Config;
use crate::module::Module;
use std::sync::Arc;
use tracing::warn;

/// Every port a module can declare in `requires()` / `optional()`
/// (architecture section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Port {
    Db,
    Mailer,
    Captcha,
    RateLimiter,
    Signer,
    KeyValue,
    Blob,
    Push,
    Payments,
    Realtime,
    HttpClient,
    Clock,
    IdGen,
    Defer,
}

impl Port {
    pub const ALL: &'static [Port] = &[
        Port::Db,
        Port::Mailer,
        Port::Captcha,
        Port::RateLimiter,
        Port::Signer,
        Port::KeyValue,
        Port::Blob,
        Port::Push,
        Port::Payments,
        Port::Realtime,
        Port::HttpClient,
        Port::Clock,
        Port::IdGen,
        Port::Defer,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Port::Db => "Database",
            Port::Mailer => "Mailer",
            Port::Captcha => "Captcha",
            Port::RateLimiter => "RateLimiter",
            Port::Signer => "Signer",
            Port::KeyValue => "KeyValue",
            Port::Blob => "Blob",
            Port::Push => "Push",
            Port::Payments => "Payments",
            Port::Realtime => "Realtime",
            Port::HttpClient => "HttpClient",
            Port::Clock => "Clock",
            Port::IdGen => "IdGen",
            Port::Defer => "Defer",
        }
    }
}

/// The per-request bundle of resolved port implementations plus the typed
/// config the runtime built from environment/secrets.
///
/// Every port is optional: the Cloudflare runtime resolves what the venture's
/// bindings actually provide and leaves the rest `None`.
pub struct Ports {
    pub config: Arc<dyn Config>,
    pub db: Option<Arc<dyn Database>>,
    pub mailer: Option<Arc<dyn Mailer>>,
    pub captcha: Option<Arc<dyn Captcha>>,
    pub rate_limiter: Option<Arc<dyn RateLimiter>>,
    pub signer: Option<Arc<dyn Signer>>,
    pub kv: Option<Arc<dyn KeyValue>>,
    pub blob: Option<Arc<dyn Blob>>,
    pub push: Option<Arc<dyn Push>>,
    pub payments: Option<Arc<dyn Payments>>,
    pub realtime: Option<Arc<dyn Realtime>>,
    pub http: Option<Arc<dyn HttpClient>>,
    pub clock: Option<Arc<dyn Clock>>,
    pub id_gen: Option<Arc<dyn IdGen>>,
    pub defer: Option<Arc<dyn Defer>>,
    /// Set by the runtime when the venture mounts sidecar modules. Not a
    /// [`Port`], so `view_for` never copies it and no module can reach it.
    pub dispatcher: Option<Arc<dyn Dispatcher>>,
}

impl Ports {
    /// An empty bundle with no ports resolved and an
    /// [`EmptyConfig`](crate::config::EmptyConfig).
    pub fn empty() -> Self {
        Self::with_config(Arc::new(crate::config::EmptyConfig))
    }

    pub fn with_config(config: Arc<dyn Config>) -> Self {
        Self {
            config,
            db: None,
            mailer: None,
            captcha: None,
            rate_limiter: None,
            signer: None,
            kv: None,
            blob: None,
            push: None,
            payments: None,
            realtime: None,
            http: None,
            clock: None,
            id_gen: None,
            defer: None,
            dispatcher: None,
        }
    }

    /// The set of ports this bundle actually provides.
    pub fn provides(&self) -> Vec<Port> {
        let mut provided = Vec::new();
        if self.db.is_some() {
            provided.push(Port::Db);
        }
        if self.mailer.is_some() {
            provided.push(Port::Mailer);
        }
        if self.captcha.is_some() {
            provided.push(Port::Captcha);
        }
        if self.rate_limiter.is_some() {
            provided.push(Port::RateLimiter);
        }
        if self.signer.is_some() {
            provided.push(Port::Signer);
        }
        if self.kv.is_some() {
            provided.push(Port::KeyValue);
        }
        if self.blob.is_some() {
            provided.push(Port::Blob);
        }
        if self.push.is_some() {
            provided.push(Port::Push);
        }
        if self.payments.is_some() {
            provided.push(Port::Payments);
        }
        if self.realtime.is_some() {
            provided.push(Port::Realtime);
        }
        if self.http.is_some() {
            provided.push(Port::HttpClient);
        }
        if self.clock.is_some() {
            provided.push(Port::Clock);
        }
        if self.id_gen.is_some() {
            provided.push(Port::IdGen);
        }
        if self.defer.is_some() {
            provided.push(Port::Defer);
        }
        provided
    }

    /// A copy of this bundle in which every port the module did not declare
    /// in `requires()` or `optional()` is `None`, so a module cannot use
    /// what it did not declare (issue #3). Undeclared-but-provided ports are
    /// logged once per module by `Harness::build`.
    #[must_use]
    pub fn view_for(&self, module: &dyn Module) -> Self {
        let declared = module
            .requires()
            .iter()
            .chain(module.optional())
            .copied()
            .collect::<Vec<_>>();
        let allows = |p: &[Port], port: Port| p.contains(&port);
        let mut view = Ports::with_config(self.config.clone());
        if allows(&declared, Port::Db) {
            view.db.clone_from(&self.db);
        }
        if allows(&declared, Port::Mailer) {
            view.mailer.clone_from(&self.mailer);
        }
        if allows(&declared, Port::Captcha) {
            view.captcha.clone_from(&self.captcha);
        }
        if allows(&declared, Port::RateLimiter) {
            view.rate_limiter.clone_from(&self.rate_limiter);
        }
        if allows(&declared, Port::Signer) {
            view.signer.clone_from(&self.signer);
        }
        if allows(&declared, Port::KeyValue) {
            view.kv.clone_from(&self.kv);
        }
        if allows(&declared, Port::Blob) {
            // Scope the store to this module's prefix, the blob equivalent of
            // the table-ownership rule: a module cannot name another's objects.
            view.blob = self.blob.as_ref().map(|blob| {
                Arc::new(ScopedBlob::new(Arc::clone(blob), module.name())) as Arc<dyn Blob>
            });
        }
        if allows(&declared, Port::Push) {
            view.push.clone_from(&self.push);
        }
        if allows(&declared, Port::Payments) {
            view.payments.clone_from(&self.payments);
        }
        if allows(&declared, Port::Realtime) {
            view.realtime.clone_from(&self.realtime);
        }
        if allows(&declared, Port::HttpClient) {
            view.http.clone_from(&self.http);
        }
        if allows(&declared, Port::Clock) {
            view.clock.clone_from(&self.clock);
        }
        if allows(&declared, Port::IdGen) {
            view.id_gen.clone_from(&self.id_gen);
        }
        if allows(&declared, Port::Defer) {
            view.defer.clone_from(&self.defer);
        }
        view
    }
}

/// Log (once, at `Harness::build`) the provided ports a module did not
/// declare — the ports `view_for` will hide from it.
pub(crate) fn warn_undeclared_ports(module: &dyn Module, provided: &[Port]) {
    for port in provided {
        if !module.requires().contains(port) && !module.optional().contains(port) {
            warn!(
                module = module.name(),
                port = port.name(),
                "runtime provides a port the module did not declare; hiding it",
            );
        }
    }
}
