//! `factory0-module-hello`: the example module built step by step by
//! [docs/MODULE-AUTHORING.md](../../docs/MODULE-AUTHORING.md). One table,
//! one public write, one public read, one event — the smallest module that
//! still exercises every rule a real module must obey.
//!
//! ```no_run
//! use factory0_module_hello::Hello;
//!
//! let module = Hello::new().max_name_len(64);
//! ```
//!
//! Module rules it demonstrates: `#![forbid(unsafe_code)]`, no `worker` /
//! `tokio` / `std::fs` / `std::net` in the dependency tree, sea-query for
//! queries, `include_str!` migrations in the portable SQL subset, config
//! keys prefixed `HELLO_*`, and the shared conformance suite.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod handlers;

use factory0_core::{
    Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext, Port, SqlMigration,
};
use std::sync::Arc;

/// The module's only migration: the `hello_visits` table in the portable
/// SQL subset (ADR 0004).
const MIGRATION_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
};

/// Says hello, and counts how many times it was said.
pub struct Hello {
    settings: handlers::Settings,
}

impl Default for Hello {
    fn default() -> Self {
        Self::new()
    }
}

impl Hello {
    /// A 64-character name limit; override at runtime with
    /// `HELLO_MAX_NAME_LEN`.
    pub fn new() -> Self {
        Self {
            settings: handlers::Settings { max_name_len: 64 },
        }
    }

    /// Compile-time default for the longest accepted name.
    #[must_use]
    pub fn max_name_len(mut self, len: u32) -> Self {
        self.settings.max_name_len = len;
        self
    }
}

impl Module for Hello {
    fn name(&self) -> &'static str {
        "hello"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::IdGen]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["hello_visits"]
    }

    fn emits(&self) -> &'static [&'static str] {
        &[handlers::EVENT_RECORDED]
    }

    fn public_writes(&self) -> bool {
        true
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("hello", cfg);
        let mut errors = ConfigError::default();
        if let Some(raw) = cfg
            .get(&module.key("MAX_NAME_LEN"))
            .map(|raw| raw.parse::<u32>())
            && matches!(raw, Ok(0) | Err(_))
        {
            errors.push(format!(
                "hello: {} must be a positive integer",
                module.key("MAX_NAME_LEN")
            ));
        }
        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(Arc::new(ctx), self.settings.clone())
    }
}
