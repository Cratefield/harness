//! `cratefield-module-owlpost`: turns Owlpost's signed webhooks into harness
//! events (issue #673).
//!
//! ```no_run
//! use cratefield_module_owlpost::{Owlpost, OwlpostEvents};
//!
//! let module = Owlpost::new(OwlpostEvents::new().on_inbound(|mail| {
//!     Box::pin(async move { Ok(()) })
//! }));
//! ```
//!
//! `POST /v1/owlpost/events` verifies with the adapter's webhook verifier
//! against `OWLPOST_WEBHOOK_SECRET` — the signature is the only authorisation,
//! and a deployment without the secret fails closed. Every verified delivery
//! deduplicates on the envelope's id through the
//! [`Inbox`](cratefield_core::Inbox) ledger shipped as the module's one
//! migration, so a redelivery is a `200` no-op.

#![forbid(unsafe_code)]

mod handlers;

pub use crate::handlers::{EVENT_INBOUND, EVENTS};

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext,
    PersonalDataSet, Port, SignatureVerification, SqlMigration,
};
use std::sync::Arc;

/// The module's name: mounted at `/v1/owlpost`, config keys prefixed
/// `OWLPOST_`.
pub const MODULE_NAME: &str = "owlpost";

/// The config key holding the signing secret. Read per request; absent
/// fails closed, present-but-blank fails [`Module::validate_config`].
pub const SECRET_KEY: &str = "OWLPOST_WEBHOOK_SECRET";

/// The `{MODULE}_`-scoped suffix [`SECRET_KEY`] composes from: what
/// [`SignatureVerification::Hmac`] declares and `validate_config` reads,
/// so the two cannot drift apart.
const SECRET_KEY_SUFFIX: &str = "WEBHOOK_SECRET";

/// The one migration: the `owlpost_inbox` dedup ledger.
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// The venture's inbound hook: called inline per verified received or held
/// delivery, before the dedup claim commits. Its error is the delivery's
/// `5xx` — which is what makes Owlpost retry.
pub type InboundHook =
    Arc<dyn Fn(InboundMail) -> BoxFuture<'static, Result<(), AnyError>> + Send + Sync>;

/// What an inbound delivery said, metadata only. A held message carries
/// nothing beyond its id and reason — no sender, recipients, subject or
/// body — because the adapter's envelope never carries them; a hook that
/// wants them fetches from Owlpost itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InboundMail {
    /// Owlpost's message id — the join key back to the provider.
    pub message_id: String,
    /// The sender. Empty for a held message, which names nobody.
    #[serde(default)]
    pub from: String,
    /// The receiving addresses.
    #[serde(default)]
    pub to: Vec<String>,
    /// The subject line, when the delivery said.
    #[serde(default)]
    pub subject: Option<String>,
    /// `true` for `message.held`: quarantined, not received.
    #[serde(default)]
    pub held: bool,
    /// Why a held message was held, when the delivery said.
    #[serde(default)]
    pub reason: Option<String>,
}

impl InboundMail {
    pub(crate) fn received(data: &cratefield_adapter_owlpost::webhook::InboundData) -> Self {
        Self {
            message_id: data.message_id.clone(),
            from: data.from.clone(),
            to: data.to.clone(),
            subject: data.subject.clone(),
            held: false,
            reason: None,
        }
    }

    /// Only what the hold said: id and reason; sender, recipients and
    /// subject stay behind.
    pub(crate) fn held(data: &cratefield_adapter_owlpost::webhook::HeldData) -> Self {
        Self {
            message_id: data.message_id.clone(),
            from: String::new(),
            to: Vec::new(),
            subject: None,
            held: true,
            reason: data.reason.clone(),
        }
    }
}

/// The venture's hooks: `OwlpostEvents::new().on_inbound(|mail| ...)`.
#[derive(Clone, Default)]
pub struct OwlpostEvents {
    inbound: Option<InboundHook>,
}

// Closures are not `Debug`; whether a hook is wired is, and the hook itself
// never is.
impl std::fmt::Debug for OwlpostEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwlpostEvents")
            .field("on_inbound", &self.inbound.is_some())
            .finish()
    }
}

impl OwlpostEvents {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Calls `hook` with every verified inbound mail. A hook error fails the
    /// delivery with a `5xx` and leaves the dedup key unclaimed, so
    /// Owlpost's retry re-runs it.
    #[must_use]
    pub fn on_inbound(
        mut self,
        hook: impl Fn(InboundMail) -> BoxFuture<'static, Result<(), AnyError>> + Send + Sync + 'static,
    ) -> Self {
        self.inbound = Some(Arc::new(hook));
        self
    }
}

/// The Owlpost inbound-events module.
#[derive(Debug, Default, Clone)]
pub struct Owlpost {
    events: OwlpostEvents,
}

impl Owlpost {
    /// A module with the given venture hooks; `OwlpostEvents::new()` for
    /// none.
    #[must_use]
    pub fn new(events: OwlpostEvents) -> Self {
        Self { events }
    }
}

impl Module for Owlpost {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        // Clock: the replay tolerance's now.
        &[Port::Db, Port::Clock]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["owlpost_inbox"]
    }

    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[PersonalDataSet::none(
            "owlpost_inbox",
            "The ids of the mail events this venture has already processed — a dedup \
             ledger, so a provider that delivers twice is processed once. It holds event \
             ids and timestamps and nothing about a person.",
        )];
        SETS
    }

    fn emits(&self) -> &'static [&'static str] {
        handlers::EVENTS
    }

    /// The route is a provider webhook guarded by an HMAC over the raw body.
    fn signature_verification(&self) -> SignatureVerification {
        SignatureVerification::Hmac {
            secret: SECRET_KEY_SUFFIX,
        }
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        // Absent stays legal: the endpoint fails closed per request, so a
        // venture that mounts the module but never points Owlpost at it is
        // not unbootable. Set-but-blank is a typo, not a choice.
        let module = ModuleConfig::new(MODULE_NAME, cfg);
        let mut errors = ConfigError::default();
        if let Some(secret) = cfg.get(&module.key(SECRET_KEY_SUFFIX))
            && secret.trim().is_empty()
        {
            errors.push(format!(
                "owlpost: {SECRET_KEY} is set but blank; unset it or give the real signing \
                 secret"
            ));
        }
        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(Arc::new(ctx), self.events.clone())
    }

    fn surface(&self) -> cratefield_core::Surface {
        handlers::surface()
    }
}
