//! `factory0-auth-core`: the schema and shared flows of the auth
//! service — `users`, `identities`, `credentials`, `sessions`,
//! `single_use_tokens`, `clients`, `client_redirect_uris` (auth issue
//! #5), the client-registration admin API (issue #6), exact-match
//! redirect URI validation (issue #7) and sessions (issue #8).
//!
//! The rules this module exists to enforce:
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

#![forbid(unsafe_code)]

mod clients;
mod secrets;
mod sessions;
mod store;

/// Exact-match redirect URI validation (issue #7): the one matching
/// rule, used at registration and — from issue #10 — at `/authorize`.
pub mod redirect_uri;

pub use secrets::{
    CLIENT_DISABLED, SECRET_BYTES, SecretError, ensure_client_usable, generate_secret, hash_secret,
    kind_allows_secret, verify_client_secret, verify_secret,
};
pub use sessions::{
    ABSOLUTE_CAP_DAYS, COOKIE_NAME, IssuedSession, Login, SESSION_INVALID, SESSION_VALUE_BYTES,
    SLIDE_AFTER_SECS, SLIDE_WINDOW_DAYS, Session, SessionError, ValidSession, clear_cookie,
    cookie_value, issue, revoke_all, set_cookie, ua_family, validate,
};
pub use store::{
    Bytes, CLIENT_CONFIDENTIAL, CLIENT_PUBLIC, CREDENTIAL_PASSKEY, CREDENTIAL_PASSWORD,
    ClientRedirectUriRow, ClientRow, CredentialRow, IdentityRow, PROVIDER_APPLE, PROVIDER_GOOGLE,
    PROVIDER_MAGIC_LINK, PROVIDER_META, PROVIDER_PASSKEY, PROVIDER_PASSWORD, Redacted,
    STATUS_ACTIVE, STATUS_DISABLED, SessionRow, SingleUseTokenRow, TOKEN_AUTHORIZATION_CODE,
    TOKEN_MAGIC_LINK, TOKEN_WEBAUTHN_CHALLENGE, UserRow, client_by_id, consume_single_use_token,
    credentials_by_user, identities_by_user, identity_by_provider_subject, insert_client,
    insert_credential, insert_identity, insert_redirect_uri, insert_session,
    insert_single_use_token, insert_user, list_clients, passkey_by_credential_id,
    purge_expired_sessions, purge_expired_single_use_tokens, redirect_uris_for_client,
    replace_redirect_uris, revoke_all_sessions, revoke_session, rotate_client_secret,
    session_by_token_hash, sessions_by_user, single_use_token_by_hash, slide_session,
    touch_credential_used, touch_identity_login, touch_session_seen, update_client_name,
    update_client_status, update_passkey_sign_count, user_by_id, user_by_primary_email,
};

use factory0_core::{
    AnyError, BoxFuture, Config, ConfigError, Module, ModuleConfig, ModuleContext, Port,
    SqlMigration,
};
use std::sync::Arc;

/// Default rotation overlap: the old client secret keeps verifying for
/// one hour after a rotation, then stops.
pub const DEFAULT_SECRET_OVERLAP_SECS: u64 = 3600;

/// The schema migration of issue #5: the seven-table schema in the
/// harness's portable SQL subset, embedded per the module contract.
const MIGRATION_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
};

/// The rotation migration of issue #6: the previous client secret's
/// hash and the instant it stops verifying.
const MIGRATION_ROTATION: SqlMigration = SqlMigration {
    id: "0002",
    name: "client_secret_rotation",
    sql: include_str!("../migrations/sqlite/0002_client_secret_rotation.sql"),
};

/// Router state: the module context plus the resolved rotation overlap.
pub(crate) struct ModuleState {
    pub(crate) ctx: Arc<ModuleContext>,
    pub(crate) secret_overlap_secs: u64,
}

/// The auth-core module: schema, clients, sessions, tokens, the
/// authorization flow and account linking (README module table).
///
/// Requires `Database` (the tables), `Clock` (every expiry decision
/// reads it, never a wall clock — ADR 0100) and `IdGen` (ULID client and
/// session ids).
#[derive(Debug, Clone)]
pub struct AuthCore {
    secret_overlap_secs: u64,
}

impl Default for AuthCore {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthCore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            secret_overlap_secs: DEFAULT_SECRET_OVERLAP_SECS,
        }
    }

    /// How long the previous client secret keeps verifying after a
    /// rotation (default one hour). Overridable per environment with
    /// `AUTH_CORE_SECRET_OVERLAP_SECS`.
    #[must_use]
    pub fn secret_overlap_secs(mut self, secs: u64) -> Self {
        self.secret_overlap_secs = secs;
        self
    }

    fn resolved_overlap(&self, cfg: &dyn Config) -> u64 {
        ModuleConfig::new("auth-core", cfg)
            .get_u32(
                "SECRET_OVERLAP_SECS",
                u32::try_from(self.secret_overlap_secs).unwrap_or(u32::MAX),
            )
            .into()
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
        &[Port::Db, Port::Clock, Port::IdGen]
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

    fn migrations(&self) -> factory0_core::Migrations {
        const MIGRATIONS: [SqlMigration; 2] = [MIGRATION_INIT, MIGRATION_ROTATION];
        factory0_core::Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("auth-core", cfg);
        if let Some(raw) = cfg.get(&module.key("SECRET_OVERLAP_SECS"))
            && raw.parse::<u32>().is_err()
        {
            let mut errors = ConfigError::default();
            errors.push(format!(
                "auth-core: {} must be a non-negative integer, got {raw:?}",
                module.key("SECRET_OVERLAP_SECS")
            ));
            return Err(errors);
        }
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ModuleState {
            secret_overlap_secs: self.resolved_overlap(&*ctx.config),
            ctx: Arc::new(ctx),
        });
        clients::router(Arc::clone(&state)).merge(sessions::router().with_state(state))
    }

    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(store::scheduled_purge(ctx, cron))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_core::{HARNESS_API, MapConfig};

    #[test]
    fn module_metadata_matches_the_issues() {
        let module = AuthCore::new();
        assert_eq!(module.name(), "auth-core");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(module.harness_api(), HARNESS_API);
        assert_eq!(module.requires(), [Port::Db, Port::Clock, Port::IdGen]);
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
    fn migrations_are_the_embedded_pair() {
        let migrations = AuthCore::new().migrations();
        assert_eq!(migrations.sqlite.len(), 2);
        assert_eq!(migrations.sqlite[0].id, "0001");
        assert_eq!(migrations.sqlite[0].name, "init");
        assert_eq!(migrations.sqlite[1].id, "0002");
        assert_eq!(migrations.sqlite[1].name, "client_secret_rotation");
        assert!(migrations.postgres.is_empty());
        assert_eq!(
            migrations.sqlite[0].sql,
            include_str!("../migrations/sqlite/0001_init.sql")
        );
        assert_eq!(
            migrations.sqlite[1].sql,
            include_str!("../migrations/sqlite/0002_client_secret_rotation.sql")
        );
    }

    #[test]
    fn overlap_comes_from_the_builder_or_config() {
        let config = MapConfig::from_pairs([("AUTH_CORE_SECRET_OVERLAP_SECS", "90")]);
        assert_eq!(AuthCore::new().resolved_overlap(&config), 90);
        assert_eq!(
            AuthCore::new()
                .secret_overlap_secs(1200)
                .resolved_overlap(&config),
            90,
            "config wins over the builder"
        );
        assert_eq!(
            AuthCore::new().resolved_overlap(&MapConfig::default()),
            DEFAULT_SECRET_OVERLAP_SECS
        );
    }

    #[test]
    fn invalid_overlap_config_is_rejected() {
        let config = MapConfig::from_pairs([("AUTH_CORE_SECRET_OVERLAP_SECS", "soon")]);
        assert!(AuthCore::new().validate_config(&config).is_err());
        assert!(
            AuthCore::new()
                .validate_config(&MapConfig::default())
                .is_ok()
        );
    }
}
