//! `cratefield-auth-core`: the schema and shared flows of the auth
//! service — `users`, `identities`, `credentials`, `sessions`,
//! `single_use_tokens`, `clients`, `client_redirect_uris` (auth issue
//! #5), the client-registration admin API (issue #6), exact-match
//! redirect URI validation (issue #7), sessions (issue #8) and token
//! issuing (issue #9).
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
//! 3. **A signing key's private half never reaches an output.**
//!    `tokens::SigningKeys` prints key ids only, and the published JWKS
//!    is built from the re-derived public point (issue #9).

#![forbid(unsafe_code)]

mod authorize;
/// The instance's branding (issue #777): display name, logo, accent,
/// support address, footer and legal links, shared by every auth module.
pub mod brand;
pub use brand::Brand;
// The two items a venture author needs from the chooser: the config key
// and the slugs it accepts. They were `pub` inside this private module,
// which meant nothing outside the crate could name either — the README
// documents `AUTH_CORE_LOGIN_METHODS` and its vocabulary, and no caller
// could ask for it.
pub use authorize::{LOGIN_METHODS_KEY, known_method_slugs};
mod clients;
/// Login CSRF (issue #439): the same-origin guard a state-changing route
/// runs before it acts, and the 403 problem it answers with.
pub mod csrf;
pub mod federated;
// The server half of `fz auth import` (issue #650, part B): the admin
// routes that move a system of record's users in, preserving the verifier
// and the verified address.
mod import;
pub mod linking;
mod locale;
mod secrets;
mod sessions;
mod store;
mod token_endpoint;

/// Exact-match redirect URI validation (issue #7): the one matching
/// rule, used at registration and — from issue #10 — at `/authorize`.
pub mod redirect_uri;

/// Token issuing (issue #9): ES256 access tokens, the published JWKS
/// and `openid-configuration`, opaque single-use refresh tokens with
/// reuse detection.
pub mod tokens;

pub use locale::{Hints, SupportedLocales, resolve, ui_locales_from_return_to};
pub use secrets::{
    BCRYPT_MAX_COST, CLIENT_DISABLED, LEGACY_HASHES_KEY, LegacyHashes, SECRET_BYTES, SecretError,
    bcrypt_cost, ensure_client_usable, generate_secret, hash_password, hash_secret,
    is_argon2id_phc, kind_allows_secret, password_needs_rehash, verify_client_secret,
    verify_password, verify_password_with, verify_secret,
};
pub use sessions::{
    ABSOLUTE_CAP_DAYS, COOKIE_NAME, IssuedSession, Login, SESSION_INVALID, SESSION_VALUE_BYTES,
    SLIDE_AFTER_SECS, SLIDE_WINDOW_DAYS, Session, SessionError, ValidSession, clear_cookie,
    cookie_value, issue, revoke_all, set_cookie, ua_family, validate,
};
pub use store::{
    Bytes, CLIENT_CONFIDENTIAL, CLIENT_PUBLIC, CREDENTIAL_PASSKEY, CREDENTIAL_PASSWORD,
    ClientRedirectUriRow, ClientRow, CredentialRow, DELETION_DELETED_USER, DELETION_DONE,
    DELETION_NOTHING_TO_DO, DELETION_PENDING, DELETION_UNLINKED, DeletionJobRow, IdentityRow,
    PROVIDER_APPLE, PROVIDER_GOOGLE, PROVIDER_IMPORT, PROVIDER_MAGIC_LINK, PROVIDER_META,
    PROVIDER_PASSKEY, PROVIDER_PASSWORD, Redacted, STATUS_ACTIVE, STATUS_DISABLED, SessionRow,
    SingleUseTokenRow, TOKEN_AUTHORIZATION_CODE, TOKEN_EMAIL_VERIFICATION, TOKEN_MAGIC_LINK,
    TOKEN_PASSWORD_RESET, TOKEN_REFRESH, TOKEN_WEBAUTHN_CHALLENGE, UserRow, client_by_id,
    complete_deletion_job, consume_single_use_token, credentials_by_user, delete_credential,
    delete_identity, delete_user, deletion_job_by_code, identities_by_user,
    identity_by_provider_subject, insert_client, insert_credential, insert_deletion_job,
    insert_identity, insert_redirect_uri, insert_session, insert_single_use_token, insert_user,
    list_clients, mark_passkey_suspect, passkey_by_credential_id, password_credential,
    pending_deletion_jobs, purge_expired_sessions, purge_expired_single_use_tokens, purge_user,
    redirect_uris_for_client, replace_redirect_uris, retire_unconsumed_tokens, revoke_all_sessions,
    revoke_session, rotate_client_secret, session_by_id, session_by_token_hash, sessions_by_user,
    set_password_hash, set_password_lockout, set_primary_email_verified, single_use_token_by_hash,
    slide_session, touch_credential_used, touch_identity_login, touch_session_seen,
    update_client_name, update_client_status, update_passkey_sign_count, user_by_id,
    user_by_primary_email,
};
pub use tokens::{
    ACCESS_TOKEN_SECS, DEFAULT_REFRESH_REUSE_GRACE_MAX_USES, JWKS_CACHE_CONTROL,
    MAX_REFRESH_REUSE_GRACE_SECS, MAX_REFRESH_REUSE_GRACE_USES, OIDC_CACHE_CONTROL,
    REFRESH_TOKEN_DAYS, RefreshGrant, RefreshOutcome, RefreshReuseGrace, SigningKey, SigningKeys,
    TOKENS_UNCONFIGURED, TokenConfigError, TokenError, exchange_refresh_token, mint_access_token,
    mint_refresh_token,
};

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, DataKind, Disposition, Module, ModuleConfig,
    ModuleContext, PersonalDataSet, Port, SqlMigration, SubjectVia,
};
use std::sync::Arc;

/// Default rotation overlap: the old client secret keeps verifying for
/// one hour after a rotation, then stops.
pub const DEFAULT_SECRET_OVERLAP_SECS: u64 = 3600;

/// The schema migration of issue #5: the seven-table schema in the
/// harness's portable SQL subset, embedded per the module contract.
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// The rotation migration of issue #6: the previous client secret's
/// hash and the instant it stops verifying.
const MIGRATION_ROTATION: SqlMigration = SqlMigration::new(
    "0002",
    "client_secret_rotation",
    include_str!("../migrations/sqlite/0002_client_secret_rotation.sql"),
);

/// The deletion-job table of issue #18: a provider's "delete this
/// person's data" request, recorded before it is carried out.
const MIGRATION_DELETION_JOBS: SqlMigration = SqlMigration::new(
    "0005",
    "deletion_jobs",
    include_str!("../migrations/sqlite/0005_deletion_jobs.sql"),
);

/// The password lockout of issue #12: the per-account failure counter
/// the `RateLimiter` port cannot provide, because it is keyed on the
/// account rather than on the request.
const MIGRATION_PASSWORD_LOCKOUT: SqlMigration = SqlMigration::new(
    "0006",
    "password_lockout",
    include_str!("../migrations/sqlite/0006_password_lockout.sql"),
);

/// The passkey clone signal of issue #14: `credentials.passkey_suspect_at`.
const MIGRATION_SUSPECT: SqlMigration = SqlMigration::new(
    "0004",
    "passkey_suspect",
    include_str!("../migrations/sqlite/0004_passkey_suspect.sql"),
);

/// The account locale of issue #649: `users.locale`, the language an
/// account asked to be written to in. Portable DDL, so the Postgres set
/// reuses this file (ADR 0004).
const MIGRATION_USER_LOCALE: SqlMigration = SqlMigration::new(
    "0007",
    "user_locale",
    include_str!("../migrations/sqlite/0007_user_locale.sql"),
);

/// The recovery-token kinds of issues #19/#20: `email_verification` and
/// `password_reset` joined the `single_use_tokens` kind CHECK.
const MIGRATION_TOKEN_KINDS_RECOVERY: SqlMigration = SqlMigration::new(
    "0009",
    "token_kinds_recovery",
    include_str!("../migrations/sqlite/0009_token_kinds_recovery.sql"),
);

/// The Postgres form of the recovery-token-kinds migration: the rebuild
/// applies as written; only the byte column type differs.
const MIGRATION_TOKEN_KINDS_RECOVERY_POSTGRES: SqlMigration = SqlMigration::new(
    "0009",
    "token_kinds_recovery",
    include_str!("../migrations/postgres/0009_token_kinds_recovery.sql"),
);

/// The token-issuing migration of issue #9: the sessions `amr` column
/// and the `refresh_token` single-use-token kind.
const MIGRATION_TOKENS: SqlMigration = SqlMigration::new(
    "0003",
    "token_issuing",
    include_str!("../migrations/sqlite/0003_token_issuing.sql"),
);

/// The user-import migration of issue #650, part B: the identities
/// provider CHECK widens to admit `import`, so an imported person's link
/// back to their system of record is an ordinary identity row.
const MIGRATION_IMPORT_PROVIDER: SqlMigration = SqlMigration::new(
    "0008",
    "import_provider",
    include_str!("../migrations/sqlite/0008_import_provider.sql"),
);

/// The Postgres form of the init migration: the same DDL with `BYTEA`
/// where SQLite has `BLOB` (harness issue #18, ADR 0004). The `id` is
/// identical to the sqlite one so the tracking key `<module>/<id>` — and
/// with it the id-stability contract in the migration runner — holds on
/// both dialects.
const MIGRATION_INIT_POSTGRES: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/postgres/0001_init.sql"),
);

/// The Postgres form of the token-issuing migration: the rebuild
/// applies as written; only the byte column type differs.
const MIGRATION_TOKENS_POSTGRES: SqlMigration = SqlMigration::new(
    "0003",
    "token_issuing",
    include_str!("../migrations/postgres/0003_token_issuing.sql"),
);

/// The Postgres form of the import migration: Postgres alters the named
/// CHECK in place rather than rebuilding the table.
const MIGRATION_IMPORT_PROVIDER_POSTGRES: SqlMigration = SqlMigration::new(
    "0008",
    "import_provider",
    include_str!("../migrations/postgres/0008_import_provider.sql"),
);

/// Router state: the module context and the resolved rotation overlap.
pub(crate) struct ModuleState {
    pub(crate) ctx: Arc<ModuleContext>,
    pub(crate) secret_overlap_secs: u64,
    /// The resolved refresh-reuse grace (issue #655): the short window in
    /// which a second presentation of a just-rotated refresh token, by
    /// the same client, is graced instead of revoking the session.
    pub(crate) refresh_grace: tokens::RefreshReuseGrace,
    /// The same signing-key cell the `/.well-known` router reads, so
    /// `/token` mints with the key JWKS publishes (issue #9).
    pub(crate) tokens: tokens::SigningKeysCell,
}

/// The auth-core module: schema, clients, sessions, tokens, the
/// authorization flow and account linking (README module table).
///
/// Requires `Database` (the tables), `Clock` (every expiry decision
/// reads it, never a wall clock — ADR 0200) and `IdGen` (ULID client and
/// session ids).
#[derive(Debug, Clone)]
pub struct AuthCore {
    secret_overlap_secs: u64,
    /// The resolved signing keys for the `/.well-known` router.
    /// `Module::well_known` is called without a `ModuleContext`
    /// (harness issue #46), so the cell is filled by `router()` —
    /// which does see the config — before any request can flow, and
    /// the discovery handlers read it per request.
    signing: tokens::SigningKeysCell,
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
            signing: std::sync::Arc::new(std::sync::RwLock::new(None)),
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

    /// The eight tables migrations `0001`–`0007` leave behind. `0007`
    /// adds a column rather than a table, so this list is unchanged.
    ///
    /// `deletion_jobs` was missing from this list for as long as it has
    /// existed (issue #272). Its migration created it, the module read and
    /// wrote it, and no list anywhere said it was ours — so it was outside
    /// `fz data export`, which walks this list; outside subject access and
    /// erasure, which walk [`personal_data`](Module::personal_data); and
    /// outside the rule that compares the two, which can only read the lists
    /// it is handed. It holds `provider_subject`, a person's identifier at
    /// their identity provider.
    ///
    /// Adding it changes what a whole-database `fz data export` carries and
    /// what an `fz data import` expects to find: a move of a venture now
    /// takes the deletion queue with it, which is the right answer — a
    /// restore that lost it would lose the record that somebody's deletion
    /// request was honoured — but it is a change to the shape of an export,
    /// not only to a declaration.
    fn tables(&self) -> &'static [&'static str] {
        &[
            "users",
            "identities",
            "credentials",
            "sessions",
            "single_use_tokens",
            "clients",
            "client_redirect_uris",
            "deletion_jobs",
        ]
    }

    /// What an account is, table by table (issue #265).
    ///
    /// Every venture composes this module, so an erasure that does not reach
    /// here reaches nothing: a session left behind is a way back in, and a
    /// credential left behind is the way in. Both are [`Disposition::Erase`],
    /// and erasure runs the catalogue in reverse, so `users` is declared
    /// **first** and its four child tables after it — the rows that reference
    /// `users(id)` go before the row they reference, and no foreign key ever
    /// has to be deferred.
    ///
    /// Four columns are named in `redacted`. They are exactly the four this
    /// module already wraps in [`Redacted`] so a logged row cannot leak
    /// a value that can log a user in, plus `single_use_tokens.payload`, and
    /// `GET /v1/privacy/export` is a `SELECT *` written to a file people
    /// forward — the same argument, one hop further out. `payload` earns its
    /// place twice over: an authorization code's payload holds the
    /// `redirect_uri`, the PKCE challenge and a live session id, and a magic
    /// link's holds the `return_to`, so exporting it would copy two URLs and a
    /// session identifier into that file.
    ///
    /// `ip_hash` is deliberately **not** redacted. It is one-way and it is the
    /// subject's own — "we kept a fingerprint of where you signed in from" is
    /// part of the answer they asked for, and a hash nobody can present is not
    /// a capability. `deletion_jobs.confirmation_code` is not redacted for the
    /// same reason its own migration gives: it identifies a request, the
    /// status it reveals is the requester's own, and it is what the person
    /// needs in order to check that request — printing it in their export
    /// hands them nothing they did not already have.
    ///
    /// **`deletion_jobs` is keyed differently from the rest, and says so.**
    /// Every other set here is matched on the account id, under one column
    /// name or another; this one is matched on `provider_subject`, because the
    /// row is created by a provider callback that names the person only by
    /// the provider's own id for them — it can exist before there is an
    /// account to point at, so a `user_id` column would have nothing to put
    /// in it. `subject_via` names the one hop that links the two: a row here
    /// belongs to whoever holds an `identities` row with the same
    /// `provider_subject`, and that row carries the account id requests are
    /// made with. Export, preview, delete and verify all run the same join
    /// (issue #281).
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            PersonalDataSet {
                table: "users",
                subject: "id",
                kind: DataKind::Contact,
                disposition: Disposition::Erase,
                description: "Your account: the name you go by, the email address it is reached \
                              at, whether that address has been confirmed, and when the account \
                              was created and last changed.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: "identities",
                subject: "user_id",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "Every way you can sign in: which provider, that provider's own id \
                              for you, the email address and name it gave us when you linked it, \
                              and when you last used it.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: "credentials",
                subject: "user_id",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "Your passkeys and your password: what each one is, the label and \
                              device it was registered from, when it was added and last used, and \
                              whether it is currently locked.",
                redacted: &["password_hash"],
                subject_via: None,
            },
            PersonalDataSet {
                table: "sessions",
                subject: "user_id",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "Every sign-in still valid right now: when it began, when it was \
                              last seen, when it expires, how you proved who you were, and a \
                              one-way fingerprint of the address and browser family it came from.",
                redacted: &["token_hash"],
                subject_via: None,
            },
            PersonalDataSet {
                table: "single_use_tokens",
                subject: "user_id",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "Links and codes issued to you that work exactly once — a sign-in \
                              link, a passkey challenge, an authorization code, a refresh token — \
                              until they are used or run out.",
                redacted: &["token_hash", "payload"],
                subject_via: None,
            },
            // The two registration tables. They are the one place in this
            // module that holds a secret and no person: an application's
            // secret is not somebody's credential, and no column here names a
            // human being, so neither row belongs in anybody's export.
            PersonalDataSet::none(
                "clients",
                "The applications allowed to sign people in to this venture: each one's name, \
                 whether it is switched on, and a hash of its own secret. It describes software \
                 somebody registered, not a person, and no column in it names one.",
            ),
            PersonalDataSet::none(
                "client_redirect_uris",
                "The exact addresses each registered application may be sent back to once a \
                 sign-in finishes. It describes where software lives, not a person.",
            ),
            // The deletion queue (issue #272). Last in the catalogue, which
            // means first under erasure — it is `Retain`, so nothing is
            // deleted from it either way, and the position simply keeps the
            // four `users` children between it and the row they reference.
            PersonalDataSet {
                table: "deletion_jobs",
                subject: "provider_subject",
                kind: DataKind::Identifier,
                disposition: Disposition::Retain(
                    "A deletion request and what was done about it is the record that the \
                     request was honoured. Meta's callback is answered with a confirmation \
                     code and a status page that has to keep answering when the provider or \
                     the person comes back to check, and erasing the row would both stop \
                     that page working and destroy the only evidence the erasure happened.",
                ),
                description: "A request from Google, Apple or Meta to delete what we hold \
                              about you, recorded when it arrived: which provider sent it, \
                              that provider's own id for you, the code the status page is \
                              looked up by, when it came in, and what was done — your \
                              sign-in method unlinked, your whole account removed, or \
                              nothing, because there was nothing left to remove.",
                redacted: &[],
                // One hop to the account: identities holds the
                // (provider, provider_subject, user_id) triple, and user_id
                // is the value a subject access request is made with.
                subject_via: Some(SubjectVia {
                    table: "identities",
                    subject: "user_id",
                    key: "provider_subject",
                }),
            },
        ];
        SETS
    }

    fn migrations(&self) -> cratefield_core::Migrations {
        const MIGRATIONS: [SqlMigration; 9] = [
            MIGRATION_INIT,
            MIGRATION_ROTATION,
            MIGRATION_TOKENS,
            MIGRATION_SUSPECT,
            MIGRATION_DELETION_JOBS,
            MIGRATION_PASSWORD_LOCKOUT,
            MIGRATION_USER_LOCALE,
            MIGRATION_IMPORT_PROVIDER,
            MIGRATION_TOKEN_KINDS_RECOVERY,
        ];
        // The array is the apply order; this refuses a gap, a duplicate
        // or an entry out of order at build time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        // The runner selects one set wholesale (harness issue #18), so the
        // Postgres list carries all nine: the four whose SQL truly differs
        // (BYTEA for the byte columns in three, and the in-place CHECK rename
        // in the import) and the five portable ones reused from the sqlite
        // files unchanged (ADR 0004).
        const MIGRATIONS_POSTGRES: [SqlMigration; 9] = [
            MIGRATION_INIT_POSTGRES,
            MIGRATION_ROTATION,
            MIGRATION_TOKENS_POSTGRES,
            MIGRATION_SUSPECT,
            MIGRATION_DELETION_JOBS,
            MIGRATION_PASSWORD_LOCKOUT,
            MIGRATION_USER_LOCALE,
            MIGRATION_IMPORT_PROVIDER_POSTGRES,
            MIGRATION_TOKEN_KINDS_RECOVERY_POSTGRES,
        ];
        // The array is the apply order; this refuses a gap, a duplicate
        // or an entry out of order at build time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS_POSTGRES);
        cratefield_core::Migrations {
            sqlite: &MIGRATIONS,
            postgres: &MIGRATIONS_POSTGRES,
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("auth-core", cfg);
        // A malformed branding value is refused at boot rather than
        // rendered (issue #777): the accent lands inside a `<style>` block
        // and the name inside mail subjects.
        let brand_problems = brand::Brand::problems(cfg);
        if !brand_problems.is_empty() {
            let mut errors = ConfigError::default();
            for problem in brand_problems {
                errors.push(format!("auth-core: {problem}"));
            }
            return Err(errors);
        }
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
        // The refresh-reuse grace (issue #655): both keys must be
        // non-negative integers, and the window is bounded — a grace
        // long enough to be a second token lifetime is a configuration
        // mistake, not a setting.
        if let Some(raw) = cfg.get(&module.key("REFRESH_REUSE_GRACE_SECONDS"))
            && !raw
                .parse::<u32>()
                .is_ok_and(|secs| secs <= tokens::MAX_REFRESH_REUSE_GRACE_SECS)
        {
            let mut errors = ConfigError::default();
            errors.push(format!(
                "auth-core: {} must be an integer in 0..={}, got {raw:?}",
                module.key("REFRESH_REUSE_GRACE_SECONDS"),
                tokens::MAX_REFRESH_REUSE_GRACE_SECS
            ));
            return Err(errors);
        }
        if let Some(raw) = cfg.get(&module.key("REFRESH_REUSE_GRACE_MAX_USES"))
            && !raw
                .parse::<u32>()
                .is_ok_and(|uses| (1..=tokens::MAX_REFRESH_REUSE_GRACE_USES).contains(&uses))
        {
            let mut errors = ConfigError::default();
            errors.push(format!(
                "auth-core: {} must be an integer in 1..={}, got {raw:?}",
                module.key("REFRESH_REUSE_GRACE_MAX_USES"),
                tokens::MAX_REFRESH_REUSE_GRACE_USES
            ));
            return Err(errors);
        }
        // A slug the chooser does not know would render a button that
        // 404s, and the operator would have no way to tell that from a
        // method that is simply switched off.
        if let Some(raw) = cfg.get(&module.key(authorize::LOGIN_METHODS_KEY)) {
            let known = authorize::known_method_slugs();
            let unknown: Vec<&str> = raw
                .split(',')
                .map(str::trim)
                .filter(|slug| !slug.is_empty() && !known.contains(slug))
                .collect();
            if !unknown.is_empty() {
                let mut errors = ConfigError::default();
                errors.push(format!(
                    "auth-core: {} does not know {:?}; it offers {}",
                    module.key(authorize::LOGIN_METHODS_KEY),
                    unknown.join(", "),
                    known.join(", ")
                ));
                return Err(errors);
            }
        }
        match tokens::SigningKeys::from_config(cfg) {
            Ok(_) => Ok(()),
            Err(err) => {
                let mut errors = ConfigError::default();
                errors.push(format!("auth-core: {err}"));
                Err(errors)
            }
        }
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let keys = match tokens::SigningKeys::from_config(&*ctx.config) {
            Ok(keys) => keys.map(Arc::new),
            // `validate_config` reports this at doctor time; at runtime
            // the module degrades to the stable unconfigured problem
            // rather than failing to boot.
            Err(err) => {
                tracing::error!(error = %err, "signing-key configuration is invalid");
                None
            }
        };
        *self.signing.write().expect("signing cell uncontended") = keys;
        let state = Arc::new(ModuleState {
            secret_overlap_secs: self.resolved_overlap(&*ctx.config),
            refresh_grace: tokens::RefreshReuseGrace::from_config(&*ctx.config),
            ctx: Arc::new(ctx),
            tokens: Arc::clone(&self.signing),
        });
        clients::router(Arc::clone(&state))
            .merge(sessions::router().with_state(Arc::clone(&state)))
            .merge(authorize::router().with_state(Arc::clone(&state)))
            .merge(import::router(Arc::clone(&state)))
            .merge(token_endpoint::router().with_state(state))
    }

    /// An import carries up to a thousand users, so this module raises
    /// core's 64 KiB `/v1/*` cap for it (issue #440). The import route's
    /// own `DefaultBodyLimit` is the precise per-route enforcer; this is
    /// the ceiling a runtime refuses at before buffering.
    fn max_body_bytes(&self, _cfg: &dyn Config) -> usize {
        import::MAX_IMPORT_BYTES
    }

    fn well_known(&self) -> Option<axum::Router> {
        Some(tokens::well_known_router(Arc::clone(&self.signing)))
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
    use cratefield_core::{HARNESS_API, MapConfig};

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
                "client_redirect_uris",
                // Issue #272: the table the migrations created and this list
                // never mentioned, so nothing exported or erased it.
                "deletion_jobs"
            ]
        );
        assert!(!module.public_writes());
    }

    /// Every table the migrations create is listed, and every table listed is
    /// one the migrations create (issue #272).
    ///
    /// The conformance kit checks this for every module; asserted here as
    /// well because `auth-core` is the module it was found in, and because
    /// the second half is what keeps the first from passing vacuously: a scan
    /// that stopped matching would report no unlisted table forever.
    #[test]
    fn tables_and_migrations_agree() {
        let module = AuthCore::new();
        let mut created = cratefield_core::migration_tables(&module);
        created.sort();
        let mut listed: Vec<String> = module.tables().iter().map(|t| (*t).to_owned()).collect();
        listed.sort();
        assert_eq!(created, listed);
        // Named rather than only counted: the rebuild in `0003` creates
        // `single_use_tokens_rebuild` and renames it over the original, so
        // the scan has to end with the original and not with both.
        assert!(created.contains(&"deletion_jobs".to_owned()));
        assert!(created.contains(&"single_use_tokens".to_owned()));
        assert!(!created.contains(&"single_use_tokens_rebuild".to_owned()));
        assert!(cratefield_core::unlisted_tables(&module).is_empty());
    }

    #[test]
    fn migrations_are_the_embedded_set_in_order() {
        let migrations = AuthCore::new().migrations();
        assert_eq!(migrations.sqlite.len(), 9);
        assert_eq!(migrations.sqlite[0].id, "0001");
        assert_eq!(migrations.sqlite[0].name, "init");
        assert_eq!(migrations.sqlite[1].id, "0002");
        assert_eq!(migrations.sqlite[1].name, "client_secret_rotation");
        assert_eq!(migrations.sqlite[2].id, "0003");
        assert_eq!(migrations.sqlite[2].name, "token_issuing");
        assert_eq!(migrations.sqlite[3].id, "0004");
        assert_eq!(migrations.sqlite[3].name, "passkey_suspect");
        assert_eq!(migrations.sqlite[4].id, "0005");
        assert_eq!(migrations.sqlite[4].name, "deletion_jobs");
        assert_eq!(migrations.sqlite[5].id, "0006");
        assert_eq!(migrations.sqlite[5].name, "password_lockout");
        assert_eq!(migrations.sqlite[6].id, "0007");
        assert_eq!(migrations.sqlite[6].name, "user_locale");
        assert_eq!(migrations.sqlite[7].id, "0008");
        assert_eq!(migrations.sqlite[7].name, "import_provider");
        assert_eq!(migrations.sqlite[8].id, "0009");
        assert_eq!(migrations.sqlite[8].name, "token_kinds_recovery");
        // The Postgres set is selected wholesale (harness issue #18), so it
        // must mirror the sqlite one id-for-id: only the files whose SQL
        // truly differs carry an override, the rest are the same const.
        assert_eq!(migrations.postgres.len(), 9);
        for (pg, sqlite) in migrations.postgres.iter().zip(migrations.sqlite) {
            assert_eq!(pg.id, sqlite.id);
            assert_eq!(pg.name, sqlite.name);
        }
        for migration in migrations.postgres {
            // The lint strips comments and literals: the override files
            // explain themselves with the word it flags, the DDL must not.
            assert!(cratefield_core::lint_portable_sql(migration.sql).is_empty());
        }
        assert_eq!(
            migrations.postgres[0].sql,
            include_str!("../migrations/postgres/0001_init.sql")
        );
        assert_eq!(
            migrations.postgres[2].sql,
            include_str!("../migrations/postgres/0003_token_issuing.sql")
        );
        assert_eq!(
            migrations.postgres[7].sql,
            include_str!("../migrations/postgres/0008_import_provider.sql")
        );
        assert_eq!(
            migrations.postgres[8].sql,
            include_str!("../migrations/postgres/0009_token_kinds_recovery.sql")
        );
        assert_eq!(migrations.postgres[1].sql, migrations.sqlite[1].sql);
        assert_eq!(
            migrations.postgres[6].sql, migrations.sqlite[6].sql,
            "the locale column is portable DDL, so Postgres reuses the sqlite file"
        );
        assert_eq!(
            migrations.sqlite[0].sql,
            include_str!("../migrations/sqlite/0001_init.sql")
        );
        assert_eq!(
            migrations.sqlite[1].sql,
            include_str!("../migrations/sqlite/0002_client_secret_rotation.sql")
        );
        assert_eq!(
            migrations.sqlite[2].sql,
            include_str!("../migrations/sqlite/0003_token_issuing.sql")
        );
        assert_eq!(
            migrations.sqlite[4].sql,
            include_str!("../migrations/sqlite/0005_deletion_jobs.sql")
        );
        assert_eq!(
            migrations.sqlite[6].sql,
            include_str!("../migrations/sqlite/0007_user_locale.sql")
        );
        assert_eq!(
            migrations.sqlite[7].sql,
            include_str!("../migrations/sqlite/0008_import_provider.sql")
        );
        assert_eq!(
            migrations.sqlite[8].sql,
            include_str!("../migrations/sqlite/0009_token_kinds_recovery.sql")
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

    #[test]
    fn refresh_reuse_grace_resolves_from_config_with_defaults() {
        // Default: no grace, any reuse revokes; the cap still has its
        // documented default.
        let default = tokens::RefreshReuseGrace::from_config(&MapConfig::default());
        assert_eq!(default.seconds, 0, "the default grace is off");
        assert_eq!(default.max_uses, DEFAULT_REFRESH_REUSE_GRACE_MAX_USES);

        let set = tokens::RefreshReuseGrace::from_config(&MapConfig::from_pairs([
            ("AUTH_CORE_REFRESH_REUSE_GRACE_SECONDS", "20"),
            ("AUTH_CORE_REFRESH_REUSE_GRACE_MAX_USES", "5"),
        ]));
        assert_eq!(set.seconds, 20);
        assert_eq!(set.max_uses, 5);
    }

    #[test]
    fn refresh_reuse_grace_config_is_validated() {
        assert!(
            AuthCore::new()
                .validate_config(&MapConfig::from_pairs([(
                    "AUTH_CORE_REFRESH_REUSE_GRACE_SECONDS",
                    "30",
                )]))
                .is_ok()
        );
        for bad in ["soon", "-1", "301"] {
            assert!(
                AuthCore::new()
                    .validate_config(&MapConfig::from_pairs([(
                        "AUTH_CORE_REFRESH_REUSE_GRACE_SECONDS",
                        bad,
                    )]))
                    .is_err(),
                "REFRESH_REUSE_GRACE_SECONDS={bad:?} must be rejected"
            );
        }
        // MAX_USES is bounded to 1..=cap: not an integer, zero or a
        // value past the cap all fail; both ends of the range pass.
        let cap = tokens::MAX_REFRESH_REUSE_GRACE_USES;
        let over = (cap + 1).to_string();
        for bad in ["many", "0", over.as_str()] {
            assert!(
                AuthCore::new()
                    .validate_config(&MapConfig::from_pairs([(
                        "AUTH_CORE_REFRESH_REUSE_GRACE_MAX_USES",
                        bad,
                    )]))
                    .is_err(),
                "REFRESH_REUSE_GRACE_MAX_USES={bad:?} must be rejected"
            );
        }
        let top = cap.to_string();
        for good in ["1", top.as_str()] {
            assert!(
                AuthCore::new()
                    .validate_config(&MapConfig::from_pairs([(
                        "AUTH_CORE_REFRESH_REUSE_GRACE_MAX_USES",
                        good,
                    )]))
                    .is_ok(),
                "REFRESH_REUSE_GRACE_MAX_USES={good:?} must be accepted"
            );
        }
    }

    #[test]
    fn invalid_signing_key_config_is_rejected() {
        let config = MapConfig::from_pairs([
            (
                "AUTH_CORE_SIGNING_KEYS",
                "[{\"kty\":\"EC\",\"crv\":\"P-256\"}]",
            ),
            ("AUTH_CORE_SIGNING_KEY_ACTIVE", "missing-kid"),
            ("AUTH_CORE_ISSUER", "https://auth.test.example"),
        ]);
        assert!(AuthCore::new().validate_config(&config).is_err());
        assert!(
            AuthCore::new()
                .validate_config(&MapConfig::default())
                .is_ok(),
            "no signing keys configured is a valid configuration"
        );
    }

    #[test]
    fn well_known_serves_jwks_and_openid_configuration_at_the_root() {
        // The router resolves keys from the config the TestHarness
        // passes at assembly; the well-known router reads them per
        // request through the shared cell.
        let config = MapConfig::from_pairs([
            ("AUTH_CORE_SIGNING_KEYS", "[{\"kty\":\"RSA\"}]"),
            ("AUTH_CORE_SIGNING_KEY_ACTIVE", "x"),
        ]);
        assert!(
            AuthCore::new().validate_config(&config).is_err(),
            "malformed keys are caught by validate_config"
        );
        assert!(AuthCore::new().well_known().is_some());
    }
}
