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

use cratefield_core::{ConfigError, Migrations, Module, ModuleContext, Port};
use std::sync::Arc;

pub use provider::{HttpProvider, SIGNATURE_HEADER};

/// Subject access and erasure over whatever the venture composed, plus the
/// external providers a venture registered.
#[derive(Clone, Debug, Default)]
pub struct Privacy {
    providers: Arc<Vec<HttpProvider>>,
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
        handlers::router(Arc::new(ctx), Arc::clone(&self.providers))
    }
}
