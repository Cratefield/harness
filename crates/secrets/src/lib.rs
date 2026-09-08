//! `cratefield-secrets` — the secrets store (issue #39,
//! `docs/SECRETS-DESIGN.md`, ADR 0102).
//!
//! Envelope encryption over the `Database` port, in two tiers. **Global**
//! secrets (tenant connection strings, platform keys) live in the control
//! database; **tenant** secrets live in that tenant's database and nowhere
//! else. Each store holds its own wrapped data key, which the KMS unwraps
//! and never stores (§3 of the design: a database dump is ciphertext plus
//! a blob nobody outside the KMS can open).
//!
//! Every ciphertext is bound to its row by the AEAD's additional data:
//! store, name, version and key id, length-prefixed (§5). A row copied to
//! another database, renamed, rolled back a version, or repointed at
//! another key **fails to decrypt** rather than quietly succeeding.
//!
//! What this crate deliberately does not do: rotation (#42) and the
//! append-only audit log (#41). [`Audit`] is the seam the latter fills;
//! until then every access is logged through `tracing` with no value in
//! it.

#![forbid(unsafe_code)]

pub mod audit;
mod rotate;
mod store;

use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

pub use audit::{Anchor, ChainAudit, chain_sink, verify};
pub use rotate::{RewrapReport, RotationReport};
pub use store::{HarnessOnly, SecretStore, Secrets};

/// The store's schema, per dialect, applied the same way a module's is.
/// The tables are portable; only the append-only trigger differs, which
/// is what `Migrations`' two sets are for (ADR 0004).
#[must_use]
pub fn migrations() -> cratefield_core::Migrations {
    const SQLITE: [cratefield_core::SqlMigration; 3] = [
        cratefield_core::SqlMigration {
            id: "0001",
            name: "init",
            sql: include_str!("../migrations/sqlite/0001_init.sql"),
        },
        cratefield_core::SqlMigration {
            id: "0002",
            name: "audit",
            sql: include_str!("../migrations/sqlite/0002_audit.sql"),
        },
        cratefield_core::SqlMigration {
            id: "0003",
            name: "audit-store",
            sql: include_str!("../migrations/sqlite/0003_audit_store.sql"),
        },
    ];
    const POSTGRES: [cratefield_core::SqlMigration; 3] = [
        cratefield_core::SqlMigration {
            id: "0001",
            name: "init",
            sql: include_str!("../migrations/postgres/0001_init.sql"),
        },
        cratefield_core::SqlMigration {
            id: "0002",
            name: "audit",
            sql: include_str!("../migrations/postgres/0002_audit.sql"),
        },
        cratefield_core::SqlMigration {
            id: "0003",
            name: "audit-store",
            sql: include_str!("../migrations/postgres/0003_audit_store.sql"),
        },
    ];
    cratefield_core::Migrations {
        sqlite: &SQLITE,
        postgres: &POSTGRES,
    }
}

/// The AEAD this crate seals with, recorded on every key row so a store
/// can never mix ciphers within one key id (design §4).
pub const CIPHER: &str = "xchacha20poly1305";

/// Which store a secret belongs to. Part of the AAD, so it is also what
/// stops a row being useful anywhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreId {
    /// The control database: connection strings and platform keys. Not
    /// reachable from module code.
    Global,
    /// One tenant's database, by tenant id.
    Tenant(String),
}

impl StoreId {
    /// The bytes that go in the AAD.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            StoreId::Global => "global",
            StoreId::Tenant(id) => id,
        }
    }
}

impl fmt::Display for StoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who is asking. Every method takes one because the audit log needs one
/// and there is no anonymous access to a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor(String);

impl Actor {
    /// Names the caller: a module name, an operator, a job.
    ///
    /// # Errors
    ///
    /// [`SecretsError::Invalid`] when empty: "who did this" with no
    /// answer is not an audit record.
    pub fn new(who: impl Into<String>) -> Result<Self, SecretsError> {
        let who = who.into();
        if who.trim().is_empty() {
            return Err(SecretsError::Invalid(
                "an actor cannot be empty: every access is attributed".to_owned(),
            ));
        }
        Ok(Self(who))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A secret's bytes. Zeroised on drop, prints as `[redacted]`, and
/// implements neither `Display`, `Serialize` nor `Clone`: a secret that
/// can be formatted, serialised or copied is a secret that ends up in a
/// log line, a JSON body, or a buffer nobody cleared.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The bytes. Named `expose` so a reader has to notice.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The bytes as text, when the secret is one (an API key).
    ///
    /// # Errors
    ///
    /// [`SecretsError::Invalid`] when the value is not UTF-8.
    pub fn expose_str(&self) -> Result<&str, SecretsError> {
        std::str::from_utf8(&self.0)
            .map_err(|_| SecretsError::Invalid("this secret is not UTF-8".to_owned()))
    }
}

impl From<&str> for SecretBytes {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes().to_vec())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([redacted])")
    }
}

/// What `list` returns: names and versions, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    pub name: String,
    pub version: u32,
    pub created_at: String,
    pub created_by: String,
    /// `true` once `delete` has soft-deleted every version.
    pub deleted: bool,
}

/// A secret's version. Monotonic per name, starting at 1.
pub type Version = u32;

#[derive(Debug, Error)]
pub enum SecretsError {
    /// The KMS could not wrap or unwrap. Carries the port's error so the
    /// caller can still tell retryable from not.
    #[error("the key could not be unwrapped: {0}")]
    Kms(#[from] cratefield_kms::KmsError),
    /// The database refused or was unreachable.
    #[error("the secrets database: {0}")]
    Database(#[from] cratefield_core::DbError),
    /// A ciphertext did not authenticate under its context. Either the
    /// row was altered, or it was moved between stores, renamed, rolled
    /// back, or repointed at another key.
    #[error(
        "secret `{name}` version {version} did not decrypt in store `{store}`: the row does not \
         match the context it was sealed with (moved, renamed, rolled back, or altered)"
    )]
    NotAuthentic {
        store: String,
        name: String,
        version: Version,
    },
    /// The store has no data key yet, or its key row is gone (an
    /// offboarding shred). Every ciphertext in it is unreadable, which
    /// is a deliberate state, not a fault to paper over.
    #[error("store `{0}` has no usable data key: nothing in it can be decrypted")]
    NoKey(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    /// The access could not be recorded, so it did not happen: the
    /// store refuses rather than serving a secret nobody can account
    /// for.
    #[error("the access could not be audited, so it was refused: {0}")]
    NotAudited(String),
    /// The audit chain does not verify. The `seq` is the first row whose
    /// hash does not follow from its predecessor.
    #[error("the audit chain for store `{store}` breaks at seq {seq}: {detail}")]
    ChainBroken {
        store: String,
        seq: i64,
        detail: String,
    },
}

/// Where the append-only audit log (#41) attaches. Every store method
/// calls this before returning, on success and on failure, so a refused
/// read is recorded as loudly as a successful one.
///
/// The event never carries a secret value; the type makes that hard by
/// not offering one.
#[async_trait::async_trait]
pub trait Audit: Send + Sync {
    /// Records one access. A sink that writes to a database is async,
    /// which is why this is: the store awaits it **before returning**,
    /// so a value never reaches a caller whose access went unrecorded.
    ///
    /// A sink that cannot record must say so. The store turns that into
    /// a refusal rather than serving the secret anyway: an unrecorded
    /// read is exactly what the log exists to make impossible.
    async fn record(&self, event: &AuditEvent<'_>) -> Result<(), SecretsError>;
}

/// One access, as the audit log will store it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Put,
    Get,
    List,
    Delete,
    /// The data key was replaced and every live secret re-encrypted.
    RotateDek,
    /// Every data key was re-wrapped under the master key's current
    /// material. No secret changed.
    Rewrap,
}

impl Access {
    /// The inverse of [`Access::as_str`], for reading a chain back.
    /// Deliberately not `FromStr`: an unknown action is `None` rather
    /// than an error type nobody would match on.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "put" => Access::Put,
            "get" => Access::Get,
            "list" => Access::List,
            "delete" => Access::Delete,
            "rotate_dek" => Access::RotateDek,
            "rewrap" => Access::Rewrap,
            _ => return None,
        })
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Put => "put",
            Access::Get => "get",
            Access::List => "list",
            Access::Delete => "delete",
            Access::RotateDek => "rotate_dek",
            Access::Rewrap => "rewrap",
        }
    }
}

/// What the audit log records. No value, ever.
#[derive(Debug)]
pub struct AuditEvent<'a> {
    pub store: &'a StoreId,
    pub access: Access,
    pub actor: &'a Actor,
    /// Absent for `list`, which is about the store rather than one name.
    pub name: Option<&'a str>,
    pub version: Option<Version>,
    /// `false` when the call returned an error; the log records the
    /// attempt either way.
    pub allowed: bool,
    /// The request this access belongs to, when there is one, so an
    /// audit row can be tied to a log line (`cratefield_core::Scope`).
    pub request_id: Option<&'a str>,
}

/// The default audit sink until #41 lands: one structured `tracing` line
/// per access, with no value in it.
pub struct TracingAudit;

#[async_trait::async_trait]
impl Audit for TracingAudit {
    async fn record(&self, event: &AuditEvent<'_>) -> Result<(), SecretsError> {
        tracing::info!(
            store = %event.store,
            access = event.access.as_str(),
            actor = event.actor.as_str(),
            name = event.name.unwrap_or("-"),
            version = event.version.unwrap_or(0),
            allowed = event.allowed,
            "secret access"
        );
        Ok(())
    }
}

/// The additional authenticated data every ciphertext is sealed with
/// (`docs/SECRETS-DESIGN.md` §5): a domain-separation prefix, then each
/// field with an explicit little-endian length prefix so the encoding is
/// injective and no two distinct contexts can share an AAD.
///
/// Ported unchanged from the #38 spike, whose tests prove each failure
/// mode against every candidate cipher.
#[must_use]
pub fn aad(store: &StoreId, name: &str, version: Version, key_id: &str) -> Vec<u8> {
    fn push(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(b"FZ-SECRETS-AAD-v1");
    push(&mut out, store.as_str().as_bytes());
    push(&mut out, name.as_bytes());
    push(&mut out, &version.to_le_bytes());
    push(&mut out, key_id.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_does_not_print_itself() {
        let secret = SecretBytes::from("sk_live_do_not_log_me");
        let shown = format!("{secret:?}");
        assert_eq!(shown, "SecretBytes([redacted])");
        assert!(!shown.contains("sk_live"), "{shown}");
    }

    #[test]
    fn an_actor_is_never_empty() {
        assert!(Actor::new("").is_err());
        assert!(Actor::new("   ").is_err());
        assert_eq!(Actor::new("waitlist").expect("ok").as_str(), "waitlist");
    }

    /// The property the whole design rests on: distinct contexts cannot
    /// share an AAD, so a row is only valid where it was written.
    #[test]
    fn the_aad_is_injective_across_every_field() {
        let base = aad(&StoreId::Global, "resend/api_key", 1, "k1");
        let variants = [
            aad(&StoreId::Tenant("t1".into()), "resend/api_key", 1, "k1"),
            aad(&StoreId::Global, "resend/api_keys", 1, "k1"),
            aad(&StoreId::Global, "resend/api_key", 2, "k1"),
            aad(&StoreId::Global, "resend/api_key", 1, "k2"),
        ];
        for variant in &variants {
            assert_ne!(&base, variant, "two contexts produced the same AAD");
        }
        assert_eq!(base, aad(&StoreId::Global, "resend/api_key", 1, "k1"));
    }

    /// Length prefixes are what make it injective: without them
    /// `("ab", "c")` and `("a", "bc")` would collide.
    #[test]
    fn field_boundaries_cannot_be_slid() {
        let left = aad(&StoreId::Tenant("ab".into()), "c", 1, "k");
        let right = aad(&StoreId::Tenant("a".into()), "bc", 1, "k");
        assert_ne!(left, right);
    }
}
