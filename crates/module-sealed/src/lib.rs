#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod audit;
pub mod notify;
pub mod record;
pub mod store;

mod handlers;
mod outer;

use std::sync::Arc;

use cratefield_core::{
    Config, ConfigError, DataKind, Disposition, Migrations, Module, ModuleContext, PersonalDataSet,
    Port, SqlMigration,
};
use cratefield_kms::Kms;

pub use crate::notify::{
    MailNotifier, NoopNotifier, Notice, NotifyError, UnlockNotifier,
    conformance as notifier_conformance,
};

/// The module's name: mounted at `/v1/sealed`.
pub const MODULE_NAME: &str = "sealed";

/// The largest request body any route of this module accepts: what
/// [`Module::max_body_bytes`] reports — so the runtime's door guard and the
/// router's own per-route `DefaultBodyLimit` cannot disagree — and a full
/// order of magnitude above the harness-wide default, because a record
/// carries a payload plus a wrap set.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// Why the sealed store refused something on the way in, or noticed
/// tampering on the way out. The route layer turns these into problem+json;
/// [`store::StoreError`] is the storage-shaped superset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealedError {
    /// A field failed its wire grammar.
    #[error("{0}")]
    BadInput(String),
    /// A wrap failed the shape invariants `keys.ts` enforces.
    #[error("{0}")]
    BadWrap(String),
    /// A recovery wrap's Argon2id cost is below the accepted floor —
    /// refused, so a record can never be the weak link.
    #[error("{0}")]
    WeakParams(String),
    /// The audit chain does not follow from genesis; `verify` named the row.
    #[error("{0}")]
    ChainBroken(String),
    /// An outer ciphertext did not authenticate.
    #[error("{0}")]
    Tampered(String),
    /// The RNG failed, or a state was reached that only a writer outside
    /// this module could have produced.
    #[error("{0}")]
    Internal(String),
}

impl From<cratefield_core::DbError> for SealedError {
    fn from(err: cratefield_core::DbError) -> Self {
        Self::Internal(format!("a database statement failed: {err}"))
    }
}

/// The sealed-blob store. Compose it with a [`Kms`] — the only thing that
/// can open a wrapped data key, and therefore the thing erasure and
/// compromise both answer to — and an [`UnlockNotifier`] for the per-download
/// notice ([`NoopNotifier`] when none is wanted).
pub struct Sealed {
    pub(crate) kms: Arc<dyn Kms>,
    pub(crate) notifier: Arc<dyn UnlockNotifier>,
}

impl Sealed {
    /// A module that seals under `kms` and notifies through `notifier`.
    #[must_use]
    pub fn new(kms: Arc<dyn Kms>, notifier: Arc<dyn UnlockNotifier>) -> Self {
        Self { kms, notifier }
    }
}

/// The one migration: the three tables of the crypto-shredding contract.
/// The Postgres set differs only in `BYTEA` for `BLOB` and in how
/// append-only is enforced; see `migrations/`.
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

const MIGRATION_INIT_PG: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/postgres/0001_init.sql"),
);

impl Module for Sealed {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        // Auth: every route is subject-scoped, and a deployment that cannot
        // identify callers has no sealed store, only a public ciphertext
        // drop. Blob: bodies above `INLINE_BODY_MAX_BYTES` have nowhere to
        // live without one.
        &[Port::Db, Port::Auth, Port::Blob]
    }

    fn optional(&self) -> &'static [Port] {
        // RateLimiter: reads fail open without one — the durable backstops
        // are the auth gate and per-subject row scoping. Clock: wall-clock
        // fallback for timestamps.
        &[Port::RateLimiter, Port::Clock]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["sealed_blobs", "sealed_deks", "sealed_audit"]
    }

    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            PersonalDataSet {
                table: "sealed_blobs",
                subject: "subject",
                kind: DataKind::Content,
                disposition: Disposition::Erase,
                description: "Blobs you sealed in your browser: we hold the encrypted \
                     bytes and the wrapped keys for them — never the plaintext, and \
                     never the key that opens it. An export lists the metadata, the \
                     wrap set and our own encrypted copy of the body; the copy you \
                     can open exists only in your browser. Erasing a blob deletes it \
                     and the internal key that unlocks our encrypted copy, after \
                     which nothing on our side can open what you stored.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: "sealed_deks",
                subject: "subject",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "The internal, wrapped key that unlocks our encrypted copy \
                     of each of your blobs, kept in its own table so erasure deletes it \
                     first — the step that makes every remaining copy unreadable. It is \
                     key material, so an export lists it without copying it.",
                redacted: &["wrapped_dek"],
                subject_via: None,
            },
            PersonalDataSet {
                table: "sealed_audit",
                subject: "subject",
                kind: DataKind::Usage,
                disposition: Disposition::Retain(
                    "The access chain is append-only and hash-linked: its value is that \
                     no one — including an operator — can remove one person's rows \
                     without breaking the proof that nobody altered anyone else's. A \
                     row holds your account id, the blob's id, the action and the time, \
                     and never any content, because the server never has any.",
                ),
                description: "Which of your blobs were stored, opened, edited, rotated or \
                     erased, and when.",
                redacted: &[],
                subject_via: None,
            },
        ];
        SETS
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        const MIGRATIONS_PG: [SqlMigration; 1] = [MIGRATION_INIT_PG];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &MIGRATIONS_PG,
        }
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        // Nothing to configure: every choice — the KMS, the notifier, the
        // sending address — is a constructor argument a venture composes in
        // code, so there is no key to miss and no value to mistype here.
        Ok(())
    }

    fn max_body_bytes(&self, _cfg: &dyn Config) -> usize {
        MAX_RECORD_BYTES
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(self, ctx)
    }
}
