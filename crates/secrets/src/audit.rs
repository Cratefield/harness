//! The append-only, tamper-evident audit chain (issue #41).
//!
//! One chain per store. The store's own database always holds its chain;
//! since issue #142 a single database may also carry several stores'
//! chains side by side (the control database is one ledger for the
//! global store and every tenant store that lives in it) — stamped rows
//! keep each store's linked list its own, and a ledger holding only
//! foreign chains verifies as nothing. Every row's hash covers the previous row's
//! hash, so altering or removing any row breaks every link after it, and
//! [`verify`] names the first one that broke.
//!
//! Since issue #142 each row also **names the store it belongs to**:
//! the hash covers the store, so a chain copied whole from another
//! database is rejected at its first stamped row rather than passing as
//! this store's history. Rows written before that change carry the empty
//! default and hash exactly as they always did — attribution is
//! forward-effective and rewrites nothing, which in an audit chain is
//! the entire point. The presence of the trailing store segment *is*
//! the version marker: old rows cannot be back-dated into it, new rows
//! cannot dodge it, and the encoding stays injective.
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

    /// Where the next row of **this store's** chain goes: the seq the
    /// shared ledger hands out (`seq` is the table's primary key, so it
    /// counts every store's rows), and the hash of this store's own last
    /// row — or genesis when this store has none. Legacy unstamped rows
    /// belong to the ledger's original chain, the same claim `verify`
    /// makes (issue #142).
    async fn tail(&self) -> Result<(i64, Vec<u8>), SecretsError> {
        let rows = self
            .db
            .query(&Statement::new(
                "SELECT seq FROM harness_secret_audit ORDER BY seq DESC LIMIT 1",
            ))
            .await?;
        let next_seq = rows
            .first()
            .map(|row| {
                row.get("seq")
                    .ok_or_else(|| SecretsError::NotAudited("an audit row has no seq".to_owned()))
            })
            .transpose()?
            .map_or(1, |seq: i64| seq.saturating_add(1));

        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT hash FROM harness_secret_audit WHERE store = ? OR store = '' \
                 ORDER BY seq DESC LIMIT 1",
                vec![text(self.store.as_str())],
            ))
            .await?;
        let prev_hash = rows
            .first()
            .map(|row| {
                row.get("hash")
                    .ok_or_else(|| SecretsError::NotAudited("an audit row has no hash".to_owned()))
            })
            .transpose()?
            .unwrap_or_else(|| GENESIS.to_vec());
        Ok((next_seq, prev_hash))
    }
}

#[async_trait::async_trait]
impl Audit for ChainAudit {
    async fn record(&self, event: &AuditEvent<'_>) -> Result<(), SecretsError> {
        // An empty store name would collide with the pre-#142 legacy
        // encoding, where empty means "not stamped, hash as v1". A row
        // must name a real store to carry the attribution at all
        // (issue #142).
        if event.store.as_str().is_empty() {
            return Err(SecretsError::Invalid(
                "an audit event must name its store".to_owned(),
            ));
        }
        // The sink is constructed with one store and only ever writes
        // for it: an event wired to the wrong sink is a wiring bug, and
        // a misattributed row is worse than no row (issue #142).
        if &self.store != event.store {
            return Err(SecretsError::Invalid(format!(
                "this chain sink is bound to store `{}`; it will not record an event for store \
                 `{}`",
                self.store, event.store
            )));
        }
        let (seq, prev_hash) = self.tail().await?;
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
            store: event.store.as_str(),
        };
        let hash = entry.hash(&prev_hash);

        self.db
            .execute(&Statement::with_values(
                "INSERT INTO harness_secret_audit \
                 (seq, ts, actor, name, version, action, allowed, request_id, store, prev_hash, \
                  hash) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    text(event.store.as_str()),
                    bytes(prev_hash),
                    bytes(hash),
                ],
            ))
            .await
            .map_err(|err| SecretsError::NotAudited(err.to_string()))?;
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
    /// The owning store; empty only for rows predating the attribution
    /// migration, which hash exactly as they did when written
    /// (issue #142).
    store: &'a str,
}

impl Entry<'_> {
    /// `sha256(prev_hash || canonical fields)`, every field
    /// length-prefixed so the encoding is injective: no two distinct
    /// rows can hash the same whatever the field contents. A stamped
    /// row appends its store as a trailing length-prefixed segment;
    /// an empty one omits it, so the pre-#142 encoding is preserved
    /// byte for byte and the segment's presence is the version marker.
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
        if !self.store.is_empty() {
            push(&mut hasher, self.store.as_bytes());
        }
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

/// The first row of **another** store's stamped chain in this ledger, as
/// `(seq, store)`, if the ledger holds one.
async fn first_foreign(
    store: &StoreId,
    db: &dyn Database,
) -> Result<Option<(i64, String)>, SecretsError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT seq, store FROM harness_secret_audit WHERE store <> '' AND store <> ? \
             ORDER BY seq ASC LIMIT 1",
            vec![text(store.as_str())],
        ))
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    Ok(Some((
        row.get("seq")
            .ok_or_else(|| broken(store, 0, "an audit row has no seq"))?,
        row.get::<String>("store")
            .ok_or_else(|| broken(store, 0, "an audit row has no store"))?,
    )))
}

/// The ledger-position rule for one row: in a single-store ledger a
/// chain's rows are the ledger's rows, so `seq` must run 1, 2, 3… and a
/// gap is a removed row. In a shared ledger `seq` is contiguity of *the
/// ledger*, not of this chain, so the only thing the position can prove
/// is order — the hash link remains what catches a hole.
fn seq_violation(
    store: &StoreId,
    seq: i64,
    expected_seq: i64,
    last_seq: i64,
    shared_ledger: bool,
) -> Option<SecretsError> {
    if !shared_ledger && seq != expected_seq {
        return Some(broken(
            store,
            seq,
            &format!("expected seq {expected_seq}: a row is missing or out of order"),
        ));
    }
    if shared_ledger && seq <= last_seq {
        return Some(broken(
            store,
            seq,
            "its seq is not greater than its predecessor's",
        ));
    }
    None
}

/// The sentence for a ledger that holds a foreign chain and none of this
/// store's rows: someone pasted another database's history here.
fn copied_chain(store: &StoreId, seq: i64, other: &str) -> SecretsError {
    broken(
        store,
        seq,
        &format!(
            "it belongs to store `{other}`: a chain copied from another database is not this \
             store's history"
        ),
    )
}

/// Walks one store's chain and returns its [`Anchor`].
///
/// # Errors
///
/// [`SecretsError::ChainBroken`] naming the **first** row whose hash
/// does not follow from its predecessor, or whose `seq` is not the next
/// one (a removed row). A ledger that holds another store's stamped
/// chain and none of this store's rows is refused as a copied chain.
pub async fn verify(store: &StoreId, db: &dyn Database) -> Result<Anchor, SecretsError> {
    // Does the ledger hold any *other* store's stamped chain? The
    // control database keeps one audit table for several tenant stores,
    // so this store's chain may be a subsequence of the ledger — and
    // `seq`, which the table hands out to all rows (it is the primary
    // key), is then contiguous for the ledger, not for the chain. The
    // hash links still are: they only ever point at this store's own
    // previous row. Without foreign rows, strict seq contiguity is kept
    // as the single-store (and pre-#142) contract.
    let first_foreign = first_foreign(store, db).await?;
    let shared_ledger = first_foreign.is_some();

    let rows = db
        .query(&Statement::new(
            "SELECT seq, ts, actor, name, version, action, allowed, request_id, store, \
             prev_hash, hash FROM harness_secret_audit ORDER BY seq ASC",
        ))
        .await?;

    let mut prev_hash = GENESIS.to_vec();
    let mut expected_seq: i64 = 1;
    let mut mine: i64 = 0;
    let mut last = Anchor {
        store: store.to_string(),
        seq: 0,
        hash: hex(&GENESIS),
    };

    for row in &rows.rows {
        let seq: i64 = row
            .get("seq")
            .ok_or_else(|| broken(store, expected_seq, "a row has no seq"))?;
        let row_store: String = row.get("store").unwrap_or_default();
        // Attribution (issue #142): a stamped row of another store is
        // not part of this chain — skipped in a shared ledger, and if
        // *only* foreign chains exist the whole ledger is refused below
        // as a copied chain. Legacy rows carry the empty default and
        // predate attribution, so they belong to this ledger's chain.
        if !row_store.is_empty() && row_store != store.as_str() {
            continue;
        }
        if let Some(err) = seq_violation(store, seq, expected_seq, last.seq, shared_ledger) {
            return Err(err);
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
            store: &row_store,
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
        mine += 1;
    }
    if mine == 0
        && let Some((seq, other)) = &first_foreign
    {
        return Err(copied_chain(store, *seq, other));
    }
    Ok(last)
}

/// A durable sink that routes each event to a [`ChainAudit`] bound to
/// **that event's** store.
///
/// A [`crate::Secrets`] service holds one sink but hands out a store per
/// tenant, and since issue #142 a store-bound `ChainAudit` *refuses*
/// another store's events rather than silently relabeling them — so a
/// multi-tenant service cannot carry one `ChainAudit`. The router keeps
/// the per-store chain intact: each store's rows land only in its own
/// ledger, and [`verify`] still checks one store at a time.
pub fn chain_sink(db: Arc<dyn Database>) -> Arc<dyn Audit> {
    Arc::new(ChainSink { db })
}

struct ChainSink {
    db: Arc<dyn Database>,
}

#[async_trait::async_trait]
impl Audit for ChainSink {
    async fn record(&self, event: &AuditEvent<'_>) -> Result<(), SecretsError> {
        ChainAudit::new(event.store.clone(), Arc::clone(&self.db))
            .record(event)
            .await
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use cratefield_adapter_sqlite::SqliteDatabase;

    use crate::{Actor, Audit, StoreId};

    /// The pre-#142 (v1) encoding, duplicated from the shipped
    /// implementation field by field: the reference this test pins. If
    /// `Entry::hash` ever changes what a legacy (unstamped) row hashes
    /// to, existing chains would silently stop verifying — this is the
    /// test that catches that.
    // One parameter per hashed field, so the encoding reads against
    // `Entry::hash` side by side; folding them into a struct would hide
    // exactly the field list this reference exists to pin.
    #[allow(clippy::too_many_arguments)]
    fn v1_hash(
        prev_hash: &[u8],
        seq: i64,
        ts: &str,
        actor: &str,
        name: &str,
        version: Option<u32>,
        action: &str,
        allowed: bool,
        request_id: Option<&str>,
    ) -> Vec<u8> {
        fn push(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
            hasher.update(bytes);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"FZ-SECRET-AUDIT-v1");
        hasher.update(prev_hash);
        push(&mut hasher, &seq.to_le_bytes());
        push(&mut hasher, ts.as_bytes());
        push(&mut hasher, actor.as_bytes());
        push(&mut hasher, name.as_bytes());
        match version {
            Some(version) => {
                push(&mut hasher, b"v");
                push(&mut hasher, &version.to_le_bytes());
            }
            None => push(&mut hasher, b"-"),
        }
        push(&mut hasher, action.as_bytes());
        push(&mut hasher, &[u8::from(allowed)]);
        push(&mut hasher, request_id.unwrap_or("").as_bytes());
        hasher.finalize().to_vec()
    }

    fn entry(store: &'static str) -> Entry<'static> {
        Entry {
            seq: 7,
            ts: "2026-09-01T00:00:00Z",
            actor: "auditor",
            name: "stripe/api_key",
            version: Some(3),
            action: Access::Get,
            allowed: true,
            request_id: Some("req-9"),
            store,
        }
    }

    #[test]
    fn a_legacy_row_still_hashes_exactly_as_v1() {
        let prev = GENESIS.to_vec();
        let legacy = entry("").hash(&prev);
        assert_eq!(
            legacy,
            v1_hash(
                &prev,
                7,
                "2026-09-01T00:00:00Z",
                "auditor",
                "stripe/api_key",
                Some(3),
                "get",
                true,
                Some("req-9"),
            ),
            "the pre-#142 encoding must not move, or migrated chains stop verifying"
        );
        // And a stamped row is a different digest over the same fields:
        // attribution cannot be dodged by claiming the old encoding.
        assert_ne!(legacy, entry("tenant-a").hash(&prev));
    }

    #[pollster::test]
    async fn a_migrated_chain_continues_under_the_new_encoding() {
        let db = SqliteDatabase::in_memory().expect("in-memory db");
        db.apply_migrations("secrets", crate::migrations().sqlite)
            .expect("schema");
        let db: Arc<dyn Database> = Arc::new(db);

        // A row exactly as the pre-#142 writer left it: no store value
        // (the migration's empty default), hash over the v1 fields.
        let hash = v1_hash(
            GENESIS.as_ref(),
            1,
            "2026-08-01T00:00:00Z",
            "auditor",
            "stripe/api_key",
            Some(1),
            "get",
            true,
            None,
        );
        db.execute(&Statement::with_values(
            "INSERT INTO harness_secret_audit \
             (seq, ts, actor, name, version, action, allowed, request_id, prev_hash, hash) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                SeaValue::BigInt(Some(1)),
                text("2026-08-01T00:00:00Z"),
                text("auditor"),
                text("stripe/api_key"),
                SeaValue::BigInt(Some(1)),
                text("get"),
                SeaValue::BigInt(Some(1)),
                SeaValue::String(None),
                bytes(GENESIS.to_vec()),
                bytes(hash),
            ],
        ))
        .await
        .expect("legacy row");

        // The live chain appends a stamped row on top of it.
        let id = StoreId::Tenant("tenant-a".to_owned());
        let sink = ChainAudit::new(id.clone(), Arc::clone(&db));
        let actor = Actor::new("auditor").expect("named");
        sink.record(&crate::AuditEvent {
            store: &id,
            access: Access::Put,
            actor: &actor,
            name: Some("stripe/api_key"),
            version: Some(2),
            allowed: true,
            request_id: None,
        })
        .await
        .expect("record");

        let anchor = verify(&id, &*db).await.expect("chain verifies");
        assert_eq!(
            anchor.seq, 2,
            "the legacy row is part of the chain, not a wall"
        );
    }

    #[pollster::test]
    async fn a_router_sink_keeps_each_stores_chain_its_own() {
        let db = SqliteDatabase::in_memory().expect("in-memory db");
        db.apply_migrations("secrets", crate::migrations().sqlite)
            .expect("schema");
        let db: Arc<dyn Database> = Arc::new(db);

        let sink = chain_sink(Arc::clone(&db));
        let actor = Actor::new("auditor").expect("named");
        let a = StoreId::Tenant("tenant-a".to_owned());
        let b = StoreId::Tenant("tenant-b".to_owned());
        sink.record(&crate::AuditEvent {
            store: &a,
            access: Access::Put,
            actor: &actor,
            name: Some("k"),
            version: Some(1),
            allowed: true,
            request_id: None,
        })
        .await
        .expect("record for a");
        sink.record(&crate::AuditEvent {
            store: &b,
            access: Access::Get,
            actor: &actor,
            name: Some("k"),
            version: Some(1),
            allowed: false,
            request_id: None,
        })
        .await
        .expect("record for b");

        // One shared ledger, two chains: each store verifies only its own
        // rows, linked to their own genesis — interleaving must not merge
        // them. (seq is the ledger's primary key, so tenant-b's first row
        // sits at ledger position 2 while being position 1 of its chain.)
        let anchor_a = verify(&a, &*db).await.expect("chain a verifies");
        let anchor_b = verify(&b, &*db).await.expect("chain b verifies");
        assert_eq!(anchor_a.seq, 1, "tenant-a's chain ends at its own row");
        assert_eq!(anchor_b.seq, 2, "tenant-b's chain ends at its own row");
    }

    #[pollster::test]
    async fn a_sink_refuses_events_for_another_store() {
        let db = SqliteDatabase::in_memory().expect("in-memory db");
        db.apply_migrations("secrets", crate::migrations().sqlite)
            .expect("schema");
        let db: Arc<dyn Database> = Arc::new(db);

        let actor = Actor::new("auditor").expect("named");
        let global = ChainAudit::new(StoreId::Global, Arc::clone(&db));
        let tenant = StoreId::Tenant("tenant-a".to_owned());
        let err = global
            .record(&crate::AuditEvent {
                store: &tenant,
                access: Access::Get,
                actor: &actor,
                name: None,
                version: None,
                allowed: true,
                request_id: None,
            })
            .await
            .expect_err("a Global sink will not write a tenant's row");
        assert!(err.to_string().contains("bound to store"), "{err}");
        assert_eq!(
            verify(&StoreId::Global, &*db)
                .await
                .expect("nothing was written")
                .seq,
            0
        );
    }
}
