//! The append-only, tamper-evident audit chain (issue #41).
//!
//! One chain per store, in the store's own database, so a tenant's
//! auditor sees only that tenant's chain and the log lives and dies with
//! the data it describes. Every row's hash covers the previous row's
//! hash, so altering or removing any row breaks every link after it, and
//! [`verify`] names the first one that broke.
//!
//! Three things enforce this, and they are not the same thing:
//!
//! - **Append-only** is the database's job: a trigger refuses `UPDATE`
//!   and `DELETE` for every role, including the migration role. Role
//!   grants that stop an application role even trying are deployment
//!   configuration.
//! - **Tamper evidence** is the chain's job: an edit made by something
//!   that can bypass the trigger (a superuser, a file edit) still breaks
//!   the hashes.
//! - **Truncation** is the anchor's job: the chain cannot detect the
//!   removal of its own tail, because a shorter valid chain is still a
//!   valid chain. [`Anchor`] is the value to publish somewhere the
//!   database cannot reach.

use std::sync::Arc;

use cratefield_core::{Database, Statement};
use sea_query::Value as SeaValue;
use sha2::{Digest, Sha256};

use crate::{Access, Audit, AuditEvent, SecretsError, StoreId};

/// The genesis link: what the first row's `prev_hash` is.
const GENESIS: [u8; 32] = [0; 32];

/// An audit sink that writes the chain into a store's own database.
pub struct ChainAudit {
    db: Arc<dyn Database>,
    store: StoreId,
}

impl ChainAudit {
    #[must_use]
    pub fn new(store: StoreId, db: Arc<dyn Database>) -> Self {
        Self { db, store }
    }

    /// The tail of the chain: the last row's seq and hash, or the
    /// genesis pair when the chain is empty.
    async fn tail(&self) -> Result<(i64, Vec<u8>), SecretsError> {
        let rows = self
            .db
            .query(&Statement::new(
                "SELECT seq, hash FROM harness_secret_audit ORDER BY seq DESC LIMIT 1",
            ))
            .await?;
        match rows.first() {
            Some(row) => {
                let seq: i64 = row.get("seq").ok_or_else(|| {
                    SecretsError::NotAudited("an audit row has no seq".to_owned())
                })?;
                let hash: Vec<u8> = row.get("hash").ok_or_else(|| {
                    SecretsError::NotAudited("an audit row has no hash".to_owned())
                })?;
                Ok((seq, hash))
            }
            None => Ok((0, GENESIS.to_vec())),
        }
    }
}

#[async_trait::async_trait]
impl Audit for ChainAudit {
    async fn record(&self, event: &AuditEvent<'_>) -> Result<(), SecretsError> {
        let (last_seq, prev_hash) = self.tail().await?;
        let seq = last_seq.saturating_add(1);
        let ts = now();
        let name = event.name.unwrap_or("");
        let entry = Entry {
            seq,
            ts: &ts,
            actor: event.actor.as_str(),
            name,
            version: event.version,
            action: event.access,
            allowed: event.allowed,
            request_id: event.request_id,
        };
        let hash = entry.hash(&prev_hash);

        self.db
            .execute(&Statement::with_values(
                "INSERT INTO harness_secret_audit \
                 (seq, ts, actor, name, version, action, allowed, request_id, prev_hash, hash) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    SeaValue::BigInt(Some(seq)),
                    text(&ts),
                    text(event.actor.as_str()),
                    text(name),
                    match event.version {
                        Some(version) => SeaValue::BigInt(Some(i64::from(version))),
                        None => SeaValue::BigInt(None),
                    },
                    text(event.access.as_str()),
                    SeaValue::BigInt(Some(i64::from(event.allowed))),
                    match event.request_id {
                        Some(id) => text(id),
                        None => SeaValue::String(None),
                    },
                    bytes(prev_hash),
                    bytes(hash),
                ],
            ))
            .await
            .map_err(|err| SecretsError::NotAudited(err.to_string()))?;
        let _ = &self.store;
        Ok(())
    }
}

/// One row's canonical fields, for hashing. Kept separate from the
/// database row so the encoding is defined by this type rather than by
/// whatever order a `SELECT` returned.
struct Entry<'a> {
    seq: i64,
    ts: &'a str,
    actor: &'a str,
    name: &'a str,
    version: Option<u32>,
    action: Access,
    allowed: bool,
    request_id: Option<&'a str>,
}

impl Entry<'_> {
    /// `sha256(prev_hash || canonical fields)`, every field
    /// length-prefixed so the encoding is injective: no two distinct
    /// rows can hash the same whatever the field contents.
    fn hash(&self, prev_hash: &[u8]) -> Vec<u8> {
        fn push(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
            hasher.update(bytes);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"FZ-SECRET-AUDIT-v1");
        hasher.update(prev_hash);
        push(&mut hasher, &self.seq.to_le_bytes());
        push(&mut hasher, self.ts.as_bytes());
        push(&mut hasher, self.actor.as_bytes());
        push(&mut hasher, self.name.as_bytes());
        // `None` and `Some(0)` must not hash alike.
        match self.version {
            Some(version) => {
                push(&mut hasher, b"v");
                push(&mut hasher, &version.to_le_bytes());
            }
            None => push(&mut hasher, b"-"),
        }
        push(&mut hasher, self.action.as_str().as_bytes());
        push(&mut hasher, &[u8::from(self.allowed)]);
        push(&mut hasher, self.request_id.unwrap_or("").as_bytes());
        hasher.finalize().to_vec()
    }
}

/// What to publish outside the databases so truncation is detectable.
/// A chain cannot notice the loss of its own tail — a shorter valid
/// chain is still valid — so the length and last hash have to be
/// recorded somewhere the database cannot reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub store: String,
    pub seq: i64,
    /// Lowercase hex of the last row's hash.
    pub hash: String,
}

/// Walks the chain and returns its [`Anchor`].
///
/// # Errors
///
/// [`SecretsError::ChainBroken`] naming the **first** row whose hash
/// does not follow from its predecessor, or whose `seq` is not the next
/// one (a removed row).
pub async fn verify(store: &StoreId, db: &dyn Database) -> Result<Anchor, SecretsError> {
    let rows = db
        .query(&Statement::new(
            "SELECT seq, ts, actor, name, version, action, allowed, request_id, prev_hash, hash \
             FROM harness_secret_audit ORDER BY seq ASC",
        ))
        .await?;

    let mut prev_hash = GENESIS.to_vec();
    let mut expected_seq: i64 = 1;
    let mut last = Anchor {
        store: store.to_string(),
        seq: 0,
        hash: hex(&GENESIS),
    };

    for row in &rows.rows {
        let seq: i64 = row
            .get("seq")
            .ok_or_else(|| broken(store, expected_seq, "a row has no seq"))?;
        if seq != expected_seq {
            return Err(broken(
                store,
                seq,
                &format!("expected seq {expected_seq}: a row is missing or out of order"),
            ));
        }
        let recorded_prev: Vec<u8> = row
            .get("prev_hash")
            .ok_or_else(|| broken(store, seq, "a row has no prev_hash"))?;
        if recorded_prev != prev_hash {
            return Err(broken(
                store,
                seq,
                "its prev_hash is not the previous row's hash",
            ));
        }
        let ts: String = row
            .get("ts")
            .ok_or_else(|| broken(store, seq, "a row has no timestamp"))?;
        let actor: String = row
            .get("actor")
            .ok_or_else(|| broken(store, seq, "a row has no actor"))?;
        let name: String = row.get("name").unwrap_or_default();
        let action: String = row
            .get("action")
            .ok_or_else(|| broken(store, seq, "a row has no action"))?;
        let action = Access::parse(&action)
            .ok_or_else(|| broken(store, seq, &format!("unknown action `{action}`")))?;
        let version = row
            .get::<i64>("version")
            .and_then(|v| u32::try_from(v).ok());
        let allowed = row.get::<i64>("allowed").unwrap_or_default() != 0;
        let request_id: Option<String> = row.get("request_id");
        let recorded_hash: Vec<u8> = row
            .get("hash")
            .ok_or_else(|| broken(store, seq, "a row has no hash"))?;

        let computed = Entry {
            seq,
            ts: &ts,
            actor: &actor,
            name: &name,
            version,
            action,
            allowed,
            request_id: request_id.as_deref(),
        }
        .hash(&prev_hash);
        if computed != recorded_hash {
            return Err(broken(
                store,
                seq,
                "its hash does not match its contents: the row was altered",
            ));
        }

        prev_hash = recorded_hash;
        last = Anchor {
            store: store.to_string(),
            seq,
            hash: hex(&prev_hash),
        };
        expected_seq = seq.saturating_add(1);
    }
    Ok(last)
}

fn broken(store: &StoreId, seq: i64, detail: &str) -> SecretsError {
    SecretsError::ChainBroken {
        store: store.to_string(),
        seq,
        detail: detail.to_owned(),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

fn bytes(value: Vec<u8>) -> SeaValue {
    SeaValue::Bytes(Some(Box::new(value)))
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}
