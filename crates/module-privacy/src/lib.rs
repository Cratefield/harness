//! `cratefield-module-privacy`: what this deployment holds about a person, and
//! everything it holds about one.
//!
//! The module knows no venture's schema. Every table it reads is one another
//! module declared through
//! [`Module::personal_data`](cratefield_core::Module::personal_data), composed
//! at build into the [`PersonalDataCatalog`] this reads. Compose it and a
//! venture gets subject access over whatever else it composed, with no wiring:
//!
//! ```no_run
//! use cratefield_module_privacy::Privacy;
//!
//! let module = Privacy::new();
//! ```
//!
//! **Two routes, both read-only.**
//!
//! - `GET /v1/privacy/manifest` — the table a privacy page publishes: every
//!   declaration, its kind, what erasure would do to it, and the sentence the
//!   owning module wrote. No database, no subject, no authentication: it
//!   describes the deployment, not a person.
//! - `GET /v1/privacy/export?subject=<id>` — every row every module holds for
//!   one subject. Admin-guarded, because it returns somebody's data.
//!
//! Erasure is deliberately not here yet. It is the destructive half and it
//! wants its own review, its own two-step confirmation and its own receipt;
//! shipping the reading half first means a venture can answer "what do you have
//! about me" before it can answer "remove it", which is the order those two
//! questions usually arrive in anyway.
//!
//! **The manifest is the point.** A privacy page written beside the schema
//! drifts from it the first time a migration lands and nobody remembers the
//! page. A page rendered from this endpoint cannot: the sentence a member reads
//! is the sentence the module that owns the table wrote, and a table with no
//! declaration is a build error rather than an omission.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod handlers;

use cratefield_core::{ConfigError, Migrations, Module, ModuleContext, Port};
use std::sync::Arc;

/// Subject access over whatever the venture composed.
#[derive(Clone, Debug, Default)]
pub struct Privacy {
    _private: (),
}

impl Privacy {
    /// The module, with no configuration. There is nothing to configure: what
    /// it reads is what the other modules declared.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Module for Privacy {
    fn name(&self) -> &'static str {
        "privacy"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// The database it reads is other modules' tables; it owns none itself.
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }

    /// No tables. A module that owned one would have to declare its own
    /// personal data, and a privacy module keeping records about the people who
    /// asked what it keeps is a joke that writes itself. Erasure will need a
    /// receipts table and will have to answer that question honestly then.
    fn tables(&self) -> &'static [&'static str] {
        &[]
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    /// Nothing to validate: the module has no configuration of its own, and
    /// what it reads is what other modules declared, which
    /// `HarnessBuilder::build` already checked.
    fn validate_config(&self, _cfg: &dyn cratefield_core::Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(Arc::new(ctx))
    }
}
