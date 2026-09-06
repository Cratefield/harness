//! `factory0-auth-core`: the schema of the auth service — `users`,
//! `identities`, `credentials`, `sessions`, `single_use_tokens`,
//! `clients`, `client_redirect_uris` (auth issue #5).
//!
//! The two rules this module exists to enforce:
//!
//! 1. **Anything single-use lives in D1, never KV.** KV is eventually
//!    consistent; magic links, `WebAuthn` challenges, authorization codes
//!    and refresh tokens all go in `single_use_tokens` with a `kind`,
//!    consumed by a guarded update whose affected-row count is checked,
//!    so two concurrent consumes cannot both win.
//! 2. **Nothing that can log a user in is stored in the clear.** Session
//!    cookie values, magic-link tokens and client secrets are stored only
//!    as hashes; `tests/schema.rs` greps the schema for forbidden column
//!    names.
//!
//! This issue lands the schema and the module shell. Handlers, login
//! methods and token issuing are issues #6 onward.

#![forbid(unsafe_code)]

use factory0_core::{Config, ConfigError, Migrations, Module, ModuleContext, Port, SqlMigration};

/// The module's one migration: the seven-table schema of issue #5 in the
/// harness's portable SQL subset, embedded per the module contract.
const MIGRATION_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
};

/// The auth-core module: schema, clients, sessions, tokens, the
/// authorization flow and account linking (README module table).
///
/// Requires `Database` (the tables) and `Clock` (expiry decisions and the
/// scheduled purge never read a wall clock directly — ADR 0100: chrono's
/// `Utc::now` and `std::time` are unusable on wasm32).
#[derive(Debug, Clone, Default)]
pub struct AuthCore;

impl AuthCore {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Module for AuthCore {
    fn name(&self) -> &'static str {
        "auth-core"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Clock]
    }

    fn tables(&self) -> &'static [&'static str] {
        &[
            "users",
            "identities",
            "credentials",
            "sessions",
            "single_use_tokens",
            "clients",
            "client_redirect_uris",
        ]
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        // No routes in this issue (BUILD-BRIEF.md: no handlers, no routes
        // beyond what the `Module` impl requires).
        axum::Router::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_core::HARNESS_API;

    #[test]
    fn module_metadata_matches_the_issue() {
        let module = AuthCore::new();
        assert_eq!(module.name(), "auth-core");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(module.harness_api(), HARNESS_API);
        assert_eq!(module.requires(), [Port::Db, Port::Clock]);
        assert!(module.optional().is_empty());
        assert_eq!(
            module.tables(),
            [
                "users",
                "identities",
                "credentials",
                "sessions",
                "single_use_tokens",
                "clients",
                "client_redirect_uris"
            ]
        );
        assert!(!module.public_writes());
    }

    #[test]
    fn migrations_are_the_single_embedded_init() {
        let migrations = AuthCore::new().migrations();
        assert_eq!(migrations.sqlite.len(), 1);
        assert_eq!(migrations.sqlite[0].id, "0001");
        assert_eq!(migrations.sqlite[0].name, "init");
        assert!(migrations.postgres.is_empty());
        assert_eq!(
            migrations.sqlite[0].sql,
            include_str!("../migrations/sqlite/0001_init.sql")
        );
    }
}
