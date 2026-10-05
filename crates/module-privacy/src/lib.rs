//! `cratefield-module-privacy`: what this deployment holds about a person, and
//! everything it holds about one.
//!
//! The module knows no venture's schema. Every table it reads is one another
//! module declared through
//! [`Module::personal_data`](cratefield_core::Module::personal_data), composed
//! at build into the
//! [`PersonalDataCatalog`](cratefield_core::PersonalDataCatalog) this reads —
//! declaring a table is the whole wiring, so a composed venture gets subject
//! access over whatever else it composed, per table, with none of its own.
//!
//! Data held **outside** the harness — a warehouse, a CRM, another product's
//! database — is reached by registering a provider with
//! [`Privacy::provider`]; each is called over one signed HTTP contract, and
//! `requires()` grows the `HttpClient` and `Defer` ports it needs with it.
//! The other end of that same contract is [`Privacy::serve_provider`]: a
//! deployment that holds such a system of its own, or is itself the system
//! another deployment reaches, can answer `/v1/privacy/provider/*` over the
//! same declarations, with the same signature and the same answer.
//!
//! What catches a table nobody declared is `cratefield_core::undeclared_tables`,
//! through `cratefield_testing::conformance` — a **kit check, not a build
//! error** (issue #268). Silence is legitimate for a module with no tables,
//! and a venture should not be unable to boot because some module's author
//! has not got to this yet. Declaring a table the module does *not* own is
//! still a build error, which is the rule this one was confused with.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod erase;
mod handlers;
mod provider;
mod provider_server;

use cratefield_core::{ConfigError, Migrations, Module, ModuleContext, Port};
use std::sync::Arc;

pub use provider::{HttpProvider, SIGNATURE_HEADER};

/// Subject access and erasure over whatever the venture composed, plus the
/// external providers a venture registered.
#[derive(Clone, Debug, Default)]
pub struct Privacy {
    providers: Arc<Vec<HttpProvider>>,
    /// The env var holding this deployment's *provider server* secret, or
    /// `None` where the deployment does not serve the protocol. `Option`, not
    /// an empty `String`: "serving" and "serving with an unset secret" are
    /// different states, and the second one must refuse rather than serve.
    server_secret_env: Option<Arc<str>>,
}

impl Privacy {
    /// The module, with no providers. What it reads is what the other modules
    /// declared; add a system the harness never sees with [`Self::provider`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an external system holding data about subjects (issue
    /// #653). A provider is called on export and erasure, and its sections
    /// are merged into the response under `providers`; a failure there never
    /// obscures the local answer.
    #[must_use]
    pub fn provider(mut self, provider: HttpProvider) -> Self {
        Arc::make_mut(&mut self.providers).push(provider);
        self
    }

    /// Serves the same protocol this module calls out on (issue #656), so
    /// this deployment can be the provider *another* deployment reaches:
    /// `/v1/privacy/provider/export`, `/provider/erase/plan` and
    /// `/provider/erase/apply` answer over this composition's declarations.
    ///
    /// `secret_env` names the config/env variable holding the shared HMAC
    /// secret — the same one an outbound [`HttpProvider::secret_env`] points
    /// at. The **name** is taken here; the value is read from the config port
    /// at request time, so one build works in every environment and a
    /// deployment that was built before the secret existed does not have to be
    /// rebuilt to start answering.
    ///
    /// Opt-in rather than always-on because the routes are a public door: a
    /// deployment that never opted in does not answer, and a deployment that
    /// did but has no secret refuses every call rather than opening.
    ///
    /// **No admin token, deliberately.** The HMAC over the raw body *is* the
    /// authorisation — a caller on another deployment has no account here and
    /// no `ADMIN_TOKEN` to present, so an admin guard would refuse every
    /// legitimate call while authorising nothing the protocol lacks.
    #[must_use]
    pub fn serve_provider(mut self, secret_env: impl Into<String>) -> Self {
        self.server_secret_env = Some(Arc::from(secret_env.into()));
        self
    }
}

impl Module for Privacy {
    fn name(&self) -> &'static str {
        "privacy"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// The database it reads and erases is other modules' tables; it owns
    /// none itself.
    /// `Signer` is required, not optional: without it there is no
    /// confirmation token, and erasure would have to be a single call.
    /// `HttpClient` and `Defer` join only when a provider is registered —
    /// with none, this module makes no outbound call and defers nothing.
    /// Serving the protocol ([`Self::serve_provider`]) adds no port: it
    /// reads the same tables through the `Db` already required here and
    /// takes its secret from the config every route already has, so a
    /// deployment that only serves does not ask for an outbound client it
    /// will never use.
    fn requires(&self) -> &'static [Port] {
        if self.providers.is_empty() {
            &[Port::Db, Port::Signer]
        } else {
            &[Port::Db, Port::Signer, Port::HttpClient, Port::Defer]
        }
    }

    /// No tables. A module that owned one would have to declare its own
    /// personal data, and a privacy module keeping records about the people who
    /// asked what it keeps is a joke that writes itself. Erasure keeps none
    /// either: its receipt is the confirm response, not a stored record.
    fn tables(&self) -> &'static [&'static str] {
        &[]
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    /// Nothing to validate: the module has no configuration of its own, and
    /// what it reads is what other modules declared, which
    /// `HarnessBuilder::build` already checked. A provider's secret is read
    /// at call time and its absence reported as `not_configured`, not
    /// refused at build.
    fn validate_config(&self, _cfg: &dyn cratefield_core::Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let ctx = Arc::new(ctx);
        let mut router = handlers::router(Arc::clone(&ctx), Arc::clone(&self.providers));
        if let Some(secret_env) = &self.server_secret_env {
            router = router.merge(provider_server::router(
                Arc::clone(&ctx),
                Arc::clone(secret_env),
            ));
        }
        router
    }
}
