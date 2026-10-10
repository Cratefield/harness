//! The append-only, tamper-evident access chain, modelled on
//! `cratefield-secrets`' audit ledger.
//!
//! One row per create, read, wrap edit, rotation and erasure. Every row's
//! hash covers the previous row's hash, so altering or removing any row
//! breaks every link after it; the migration's triggers refuse `UPDATE` and
//! `DELETE` outright. [`verify`] names the first link that broke.

use sea_query::Value as SeaValue;
use sha2::{Digest, Sha256};

use cratefield_core::{Database, Row, Statement};

use crate::SealedError;

/// The genesis link: what the first row's `prev_hash` is.
const GENESIS: [u8; 32] = [0; 32];

/// What happened, as the chain records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The blob was created.
    Create,
    /// The blob's body was served to its subject.
    Read,
    /// The wrap set was replaced.
    Wraps,
    /// The content key was rotated.
    Rotate,
    /// The blob was erased (the crypto-shred).
    Erase,
}

impl Action {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Wraps => "wraps",
            Self::Rotate => "rotate",
            Self::Erase => "erase",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "create" => Some(Self::Create),
            "read" => Some(Self::Read),
            "wraps" => Some(Self::Wraps),
            "rotate" => Some(Self::Rotate),
            "erase" => Some(Self::Erase),
            _ => None,
        }
    }
}

/// One event to append.
#[derive(Debug, Clone)]
pub struct Event<'a> {
    pub subject: &'a str,
    pub action: Action,
    pub blob_id: &'a str,
    pub version: u32,
}

/// Where a verified chain ends: the last `seq` and its hash, lowercase hex —
/// the value an operator publishes somewhere the database cannot reach, so
/// the loss of the chain's own tail is detectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub seq: i64,
    pub hash: String,
}

/// `sha256(domain || prev_hash || length-prefixed fields)`, every field
/// length-prefixed so the encoding is injective: no two distinct rows can
/// hash the same whatever their contents.
fn hash_row(
    prev_hash: &[u8],
    seq: i64,
    ts: &str,
    subject: &str,
    action: &str,
    blob_id: &str,
    version: u32,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"FZ-SEALED-AUDIT-v1");
    hasher.update(prev_hash);
    push(&mut hasher, &seq.to_le_bytes());
    push(&mut hasher, ts.as_bytes());
    push(&mut hasher, subject.as_bytes());
    push(&mut hasher, action.as_bytes());
    push(&mut hasher, blob_id.as_bytes());
    push(&mut hasher, &version.to_le_bytes());
    hasher.finalize().to_vec()
}

/// How many times an append re-reads the chain head and retries after the
/// insert is refused. Two writers that read the same head race for one `seq`;
/// the primary key refuses the loser, which tries again on the new head.
const APPEND_RETRIES: usize = 4;

/// The chain's last `seq` and hash, or the genesis link for an empty chain.
async fn chain_head(db: &dyn Database) -> Result<(i64, Vec<u8>), SealedError> {
    let rows = db
        .query(&Statement::new(
            "SELECT seq, hash FROM sealed_audit ORDER BY seq DESC LIMIT 1",
        ))
        .await?;
    rows.first()
        .map(|row| {
            Ok((
                row.get::<i64>("seq")
                    .ok_or_else(|| SealedError::Internal("an audit row has no seq".into()))?,
                row.get::<Vec<u8>>("hash")
                    .ok_or_else(|| SealedError::Internal("an audit row has no hash".into()))?,
            ))
        })
        .transpose()
        .map(|head| head.unwrap_or((0, GENESIS.to_vec())))
}

/// Appends one row to the chain: the next `seq`, the previous row's hash,
/// and the hash over both.
///
/// # Errors
///
/// `SealedError::Internal` when a statement fails. Two writers racing for
/// one `seq` cannot both link to the same predecessor — the primary key
/// refuses the loser, which re-reads the head and retries, a bounded number
/// of attempts. The remaining guarantee: under sustained contention an
/// append can still exhaust its retries and fail, in which case the caller
/// refuses the request rather than commit an unrecorded mutation — and a
/// read is always audited before it is served, so a served read is always on
/// the chain.
pub async fn append(db: &dyn Database, ts: &str, event: &Event<'_>) -> Result<(), SealedError> {
    for _ in 0..APPEND_RETRIES {
        let (seq, prev_hash) = chain_head(db).await?;
        let seq = seq.saturating_add(1);
        let hash = hash_row(
            &prev_hash,
            seq,
            ts,
            event.subject,
            event.action.as_str(),
            event.blob_id,
            event.version,
        );
        let insert = Statement::with_values(
            "INSERT INTO sealed_audit (seq, ts, subject, action, blob_id, version, prev_hash, hash) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                SeaValue::BigInt(Some(seq)),
                text(ts),
                text(event.subject),
                text(event.action.as_str()),
                text(event.blob_id),
                SeaValue::BigInt(Some(i64::from(event.version))),
                SeaValue::Bytes(Some(Box::new(prev_hash))),
                SeaValue::Bytes(Some(Box::new(hash))),
            ],
        );
        match db.execute(&insert).await {
            Ok(_) => return Ok(()),
            Err(err) => {
                tracing::warn!(error = %err, "sealed: audit append raced; retrying on the new head");
            }
        }
    }
    Err(SealedError::Internal(
        "the audit chain stayed contended; the append was not recorded".into(),
    ))
}

/// Walks the chain and returns its [`Anchor`].
///
/// # Errors
///
/// [`SealedError::ChainBroken`] naming the first row whose `seq` is not the
/// next one (a removed row) or whose hash does not follow from its
/// predecessor (an altered row).
pub async fn verify(db: &dyn Database) -> Result<Anchor, SealedError> {
    let rows = db
        .query(&Statement::new(
            "SELECT seq, ts, subject, action, blob_id, version, prev_hash, hash \
             FROM sealed_audit ORDER BY seq ASC",
        ))
        .await?;
    let mut prev_hash = GENESIS.to_vec();
    let mut expected: i64 = 1;
    for row in &rows.rows {
        let seq = row
            .get::<i64>("seq")
            .ok_or_else(|| broken(expected, "a row has no seq"))?;
        if seq != expected {
            return Err(broken(
                expected,
                "expected this seq: a row is missing or out of order",
            ));
        }
        let recorded_prev = row
            .get::<Vec<u8>>("prev_hash")
            .ok_or_else(|| broken(seq, "a row has no prev_hash"))?;
        if recorded_prev != prev_hash {
            return Err(broken(seq, "its prev_hash is not the previous row's hash"));
        }
        let ts = text_of(row, "ts", seq)?;
        let subject = text_of(row, "subject", seq)?;
        let action = text_of(row, "action", seq)?;
        if Action::parse(&action).is_none() {
            return Err(broken(seq, &format!("unknown action `{action}`")));
        }
        let blob_id = text_of(row, "blob_id", seq)?;
        let version = row
            .get::<i64>("version")
            .ok_or_else(|| broken(seq, "a row has no version"))?;
        let version =
            u32::try_from(version).map_err(|_| broken(seq, "its version is out of range"))?;
        let recorded_hash = row
            .get::<Vec<u8>>("hash")
            .ok_or_else(|| broken(seq, "a row has no hash"))?;
        let computed = hash_row(&prev_hash, seq, &ts, &subject, &action, &blob_id, version);
        if computed != recorded_hash {
            return Err(broken(
                seq,
                "its hash does not match its contents: the row was altered",
            ));
        }
        prev_hash = recorded_hash;
        expected = seq.saturating_add(1);
    }
    Ok(Anchor {
        seq: expected - 1,
        hash: hex(&prev_hash),
    })
}

fn push(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn text_of(row: &Row, column: &str, seq: i64) -> Result<String, SealedError> {
    row.get::<String>(column)
        .ok_or_else(|| broken(seq, &format!("a row has no {column}")))
}

fn broken(seq: i64, detail: &str) -> SealedError {
    SealedError::ChainBroken(format!("sealed_audit row {seq} is broken: {detail}"))
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
