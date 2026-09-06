//! The module contract (architecture section 4). A module is a crate that
//! contributes one router under `/v1/<name>`, its migrations, its events and
//! its scheduled work — and sees nothing but ports.

use crate::config::{Config, ConfigError};
use crate::events::{AnyError, EventBus, EventHandler, EventName};
use crate::ports::{Port, Ports};
use crate::template::TemplateRegistry;
use crate::venture::Venture;
use std::sync::Arc;

pub use futures_core::future::BoxFuture;

/// Contract version shared by core and every module. `Harness::build`
/// rejects modules whose `harness_api` differs. Bumped only on breaking
/// contract changes; `factory0-core`'s major follows it.
pub const HARNESS_API: u32 = 1;

/// One migration step, embedded with `include_str!` from
/// `crates/<module>/migrations/<dialect>/NNNN_name.sql` (issue #8).
#[derive(Debug, Clone)]
pub struct SqlMigration {
    /// Sortable id: `0001`, `0002`, ... — zero-padded so lexical order is
    /// apply order.
    pub id: &'static str,
    /// Short slug from the file name (`0001_init.sql` -> `init`), used in
    /// the wrangler-facing collected file names.
    pub name: &'static str,
    pub sql: &'static str,
}

/// The module's migrations, per dialect. `postgres` differs from `sqlite`
/// only where the SQL truly differs (ADR 0004).
#[derive(Debug, Clone)]
pub struct Migrations {
    pub sqlite: &'static [SqlMigration],
    pub postgres: &'static [SqlMigration],
}

impl Migrations {
    pub const EMPTY: Migrations = Migrations {
        sqlite: &[],
        postgres: &[],
    };

    pub const fn sqlite(migrations: &'static [SqlMigration]) -> Self {
        Migrations {
            sqlite: migrations,
            postgres: &[],
        }
    }
}

impl Default for Migrations {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Everything a module's router needs: its declared ports, the typed
/// config, the bus, the templates and the venture identity.
pub struct ModuleContext {
    /// Only the ports the module declared in `requires()`/`optional()`.
    pub ports: Ports,
    /// Full config; module keys are prefixed (`EMAIL_SIGNUP_CONFIRM_TTL_DAYS`).
    pub config: Arc<dyn Config>,
    pub events: EventBus,
    pub templates: Arc<TemplateRegistry>,
    pub venture: Arc<Venture>,
}

/// A Factory Zero module. Object-safe; composed as `Arc<dyn Module>`.
///
/// Handlers get the request scope as an axum extractor:
/// `async fn join(scope: Scope, State(ctx): State<Arc<ModuleContext>>, ...)`.
/// There is no ambient "current request" (ADR 0007).
pub trait Module: Send + Sync + 'static {
    /// Kebab-case name; mounted at `/v1/<name>`.
    fn name(&self) -> &'static str;
    /// `env!("CARGO_PKG_VERSION")`, surfaced by `/__health`.
    fn version(&self) -> &'static str;
    /// Contract version, checked by `Harness::build`.
    fn harness_api(&self) -> u32 {
        HARNESS_API
    }
    /// Ports the module cannot run without; missing = build error.
    fn requires(&self) -> &'static [Port];
    /// Ports the module uses when present.
    fn optional(&self) -> &'static [Port] {
        &[]
    }
    /// Table names this module owns; duplicates across modules are a build
    /// error.
    fn tables(&self) -> &'static [&'static str] {
        &[]
    }
    /// Event names this module emits (`"<module>.<event>"`), listed by
    /// `/__health`.
    fn emits(&self) -> &'static [&'static str] {
        &[]
    }
    /// Whether the module has public write endpoints; drives the
    /// production-captcha rule (section 11).
    fn public_writes(&self) -> bool {
        false
    }
    /// The module's migrations, embedded per dialect.
    fn migrations(&self) -> Migrations;
    /// Rejects invalid configuration. Called by `fz doctor` and by tests;
    /// missing required keys are reported together with the module name.
    ///
    /// # Errors
    ///
    /// `Err` listing every invalid or missing key for this module.
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError>;
    /// The module's router, nested under `/v1/<name>`.
    fn router(&self, ctx: ModuleContext) -> axum::Router;
    /// Handlers for events other modules emit; registered at
    /// `Harness::build`.
    fn events(&self) -> Vec<(EventName, EventHandler)> {
        Vec::new()
    }
    /// Scheduled work (`cron` is the trigger expression). Default: none.
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        let _ = (ctx, cron);
        Box::pin(async { Ok(()) })
    }
}
