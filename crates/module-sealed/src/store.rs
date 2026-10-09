//! The sealed store's tables, read and written in the portable SQL subset
//! (ADR 0004). Every query is bounded by the subject the caller's verified
//! credential resolved to — a blob id alone names nothing.
//!
//! The layout is the crypto-shred: the body exists in exactly one place
//! (inline in `sealed_blobs.outer_ct`, or the blob-store object `object_key`
//! names) and the only key that opens it is the row in `sealed_deks`.

use sea_query::Value as SeaValue;
use serde_json::json;

use cratefield_core::{Database, DbError, Row, Statement};
use cratefield_kms::{Dek, Kms};

use crate::SealedError;
use crate::outer;
use crate::record::{CreateBlob, Wrap, b64url_decode, b64url_encode};

/// Bodies at or below this many (outer-wrapped) bytes live inline in
/// `sealed_blobs.outer_ct`; larger ones go to the blob store. Below the
/// harness's 64 KiB request ceiling so the inline path stays exercisable.
pub const INLINE_BODY_MAX_BYTES: usize = 32 * 1024;

/// Why a store call refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// The blob id is already this subject's.
    Taken,
    /// No such blob for this subject.
    NotFound,
    /// The record changed since the caller last read it: its revision no
    /// longer matches the `ETag` the request carried.
    Stale,
    /// The database refused the statement.
    Db(DbError),
    /// The KMS could not open a wrapped DEK.
    Kms(cratefield_kms::KmsError),
    /// An outer ciphertext did not authenticate.
    Tampered(String),
    /// Something that should be unreachable: a row is malformed, the RNG
    /// failed. Logged, never described to a caller.
    Internal(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Taken => f.write_str("that blob_id is already stored"),
            Self::NotFound => f.write_str("no such blob"),
            Self::Stale => f.write_str("the record changed since the caller last read it"),
            Self::Db(err) => write!(f, "{err}"),
            Self::Kms(err) => write!(f, "{err}"),
            Self::Tampered(what) => write!(f, "the stored body failed authentication: {what}"),
            Self::Internal(what) => write!(f, "{what}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<DbError> for StoreError {
    fn from(err: DbError) -> Self {
        Self::Db(err)
    }
}

impl From<cratefield_kms::KmsError> for StoreError {
    fn from(err: cratefield_kms::KmsError) -> Self {
        Self::Kms(err)
    }
}

impl From<SealedError> for StoreError {
    fn from(err: SealedError) -> Self {
        match err {
            SealedError::Tampered(what) => Self::Tampered(what),
            other => Self::Internal(other.to_string()),
        }
    }
}

impl From<cratefield_core::BlobError> for StoreError {
    fn from(err: cratefield_core::BlobError) -> Self {
        Self::Internal(format!("the blob store refused: {err}"))
    }
}

/// One stored blob: the metadata the wire record carries, plus where the
/// body lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRow {
    pub blob_id: String,
    pub version: u32,
    pub purpose: String,
    pub alg: String,
    /// The wraps, as the canonical JSON array the client sent.
    pub wraps: String,
    pub created_by_credential: String,
    /// The decoded client ciphertext's size in bytes.
    pub ciphertext_len: i64,
    /// The outer-wrapped body when inline; `None` when it is in the blob
    /// store under `object_key`.
    pub outer_ct: Option<Vec<u8>>,
    pub object_key: Option<String>,
    /// The server-side validator behind the `ETag`: replaced with a fresh
    /// value by every mutation, and the value a guarded mutation's `WHERE`
    /// clause must match. `version` cannot serve this: it is the client's,
    /// and the client payload's AAD binds it, so a wrap edit must leave it
    /// alone.
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

fn bytes(value: &[u8]) -> SeaValue {
    SeaValue::Bytes(Some(Box::new(value.to_vec())))
}

fn row_text(row: &Row, column: &str) -> Option<String> {
    row.get::<Option<String>>(column).flatten()
}

const ROW_COLUMNS: &str = "blob_id, version, purpose, alg, wraps, created_by_credential, \
     ciphertext_len, outer_ct, object_key, revision, created_at, updated_at";

fn from_row(row: &Row) -> BlobRow {
    BlobRow {
        blob_id: row.get::<String>("blob_id").unwrap_or_default(),
        version: u32::try_from(row.get::<i64>("version").unwrap_or_default()).unwrap_or_default(),
        purpose: row_text(row, "purpose").unwrap_or_default(),
        alg: row_text(row, "alg").unwrap_or_default(),
        wraps: row_text(row, "wraps").unwrap_or_default(),
        created_by_credential: row_text(row, "created_by_credential").unwrap_or_default(),
        ciphertext_len: row.get::<i64>("ciphertext_len").unwrap_or_default(),
        outer_ct: match row.get::<SeaValue>("outer_ct") {
            Some(SeaValue::Bytes(Some(bytes))) => Some(bytes.as_ref().clone()),
            _ => None,
        },
        object_key: row_text(row, "object_key"),
        revision: row.get::<i64>("revision").unwrap_or_default(),
        created_at: row_text(row, "created_at").unwrap_or_default(),
        updated_at: row_text(row, "updated_at").unwrap_or_default(),
    }
}

/// The blob-store key for one parked body: the subject is only ever a hashed
/// slug (the key never embeds a subject id or a guessable name), but the
/// suffix is **fresh per write** — version plus random bytes. Uniqueness is
/// what makes rotation safe: a new body never lands on the key the live body
/// occupies, so superseding one key after the commit cannot destroy the
/// record, and unparking a refused request's key cannot touch anyone else's.
fn object_key(subject: &str, blob_id: &str, version: u32) -> Result<String, StoreError> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(format!("{subject}/{blob_id}").as_bytes());
    let mut slug = String::with_capacity(48);
    for byte in digest.iter().take(16) {
        let _ = write!(slug, "{byte:02x}");
    }
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|err| StoreError::Internal(err.to_string()))?;
    let _ = write!(slug, "-v{version}-");
    for byte in suffix {
        let _ = write!(slug, "{byte:02x}");
    }
    // Module-relative: the Blob port arrives scoped to this module's
    // `sealed/` prefix (`Ports::view_for`), so the object lands at
    // `sealed/blobs/{slug}.outer` in the store.
    Ok(format!("blobs/{slug}.outer"))
}

/// Whether the outer-wrapped body at this size goes inline.
pub(crate) fn is_inline(outer_ct_len: usize) -> bool {
    outer_ct_len <= INLINE_BODY_MAX_BYTES
}

/// A fresh validator value for one guarded write. The mutation sets
/// `revision` to *this* value under a `WHERE revision = expected` guard, so
/// the read-back after the batch can tell "the row now carries my write"
/// from "somebody else had already moved it" — a mere bump by one cannot
/// make that distinction, because the winner moves it by one too.
fn fresh_revision() -> Result<i64, StoreError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|err| StoreError::Internal(err.to_string()))?;
    Ok(i64::from_be_bytes(bytes) & i64::MAX)
}

/// Seals `body` (the client's decoded ciphertext bytes) under a fresh DEK
/// and returns everything a row needs: the wrapped DEK, the outer body and —
/// when the body is too big for the row — the blob-store key to park it at.
pub struct SealedBody {
    pub wrapped_dek: Vec<u8>,
    pub provider: &'static str,
    pub key_ref: String,
    pub outer_ct: Vec<u8>,
    /// The client ciphertext's own size in bytes (before the outer wrap).
    pub ciphertext_len: usize,
    /// `Some` when the body goes to the blob store; `None` when it is inline.
    pub object_key: Option<String>,
}

/// Wraps a fresh per-blob DEK through `kms` and seals `body` with it.
///
/// # Errors
///
/// [`StoreError::Kms`] when the KMS refuses, [`StoreError::Internal`] when
/// the RNG or the cipher fails.
pub async fn seal_body(
    kms: &dyn Kms,
    body: &[u8],
    subject: &str,
    blob_id: &str,
    version: u32,
) -> Result<SealedBody, StoreError> {
    let dek = Dek::generate().map_err(|err| StoreError::Internal(err.to_string()))?;
    let wrapped_dek = kms.wrap(&dek).await?;
    let outer_ct = outer::seal(&dek, body, subject, blob_id, version)?;
    let inline = is_inline(outer_ct.len());
    let object_key = match (!inline).then(|| object_key(subject, blob_id, version)) {
        Some(key) => Some(key?),
        None => None,
    };
    Ok(SealedBody {
        wrapped_dek,
        provider: kms.provider(),
        key_ref: kms.key_ref().to_owned(),
        ciphertext_len: body.len(),
        object_key,
        outer_ct,
    })
}

/// Opens a row's body: unwraps the DEK through `kms`, fetches the outer
/// ciphertext from the row or the blob store, and returns the client's
/// ciphertext bytes (not the client plaintext — no code path reaches that).
///
/// # Errors
///
/// [`StoreError::NotFound`] without a row, [`StoreError::Tampered`] when the
/// outer layer does not authenticate, [`StoreError::Kms`] when the KMS
/// refuses, and blob-store failures as [`StoreError::Db`]-shaped internals.
pub async fn open_body(
    kms: &dyn Kms,
    blob: Option<&dyn cratefield_core::Blob>,
    db: &dyn Database,
    subject: &str,
    row: &BlobRow,
) -> Result<Vec<u8>, StoreError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT wrapped_dek FROM sealed_deks WHERE subject = ? AND blob_id = ?",
            vec![text(subject), text(&row.blob_id)],
        ))
        .await?;
    let wrapped_dek = rows
        .first()
        .and_then(|r| r.get::<Vec<u8>>("wrapped_dek"))
        .ok_or(StoreError::NotFound)?;
    let dek = kms.unwrap(&wrapped_dek).await?;
    let outer_ct = match (&row.outer_ct, &row.object_key) {
        (Some(inline), _) => inline.clone(),
        (None, Some(key)) => {
            let store = blob.ok_or_else(|| {
                StoreError::Internal("no Blob port is mounted, but the body lives in one".into())
            })?;
            store
                .get(key)
                .await?
                .map(|object| object.bytes)
                .ok_or(StoreError::NotFound)?
        }
        (None, None) => {
            return Err(StoreError::Internal(
                "a blob row names neither an inline body nor an object key".into(),
            ));
        }
    };
    Ok(outer::open(
        &dek,
        &outer_ct,
        subject,
        &row.blob_id,
        row.version,
    )?)
}

/// The wire record a row serves, rebuilt from the stored metadata and the
/// client ciphertext `open_body` recovered. The base64url fields round-trip
/// byte-identically because the validators only ever accepted the canonical
/// encoding.
///
/// # Errors
///
/// [`StoreError::Internal`] when the stored ciphertext does not decode or
/// the stored wraps do not parse — a row only the routes write cannot be
/// either, so this is the "someone else's writer" arm.
pub fn wire_record(
    row: &BlobRow,
    subject: &str,
    ciphertext: &[u8],
) -> Result<serde_json::Value, StoreError> {
    let wraps: Vec<Wrap> = serde_json::from_str(&row.wraps).map_err(|err| {
        StoreError::Internal(format!("a stored wraps column does not parse: {err}"))
    })?;
    Ok(json!({
        "blob_id": row.blob_id,
        "version": row.version,
        "purpose": row.purpose,
        "alg": row.alg,
        "ciphertext": b64url_encode(ciphertext),
        "wraps": wraps,
        "created_by_credential": row.created_by_credential,
        "subject": subject,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }))
}

/// The decoded client ciphertext a create or rotation carries.
///
/// # Errors
///
/// [`StoreError::Internal`] — unreachable for a body `validate_create`
/// accepted; the arm exists so a caller that skips validation cannot write
/// garbage.
pub fn decode_body(blob: &CreateBlob) -> Result<Vec<u8>, StoreError> {
    b64url_decode(&blob.ciphertext)
        .ok_or_else(|| StoreError::Internal("a validated ciphertext failed to decode".into()))
}

/// Inserts the blob row and its DEK row together, refusing a blob id this
/// subject already holds. The two statements are one atomic batch: a row
/// whose key never landed would be unopenable, and a key without a row would
/// be an unshreddable orphan.
///
/// # Errors
///
/// [`StoreError::Taken`] when `(subject, blob_id)` exists;
/// [`StoreError::Db`] otherwise.
pub async fn insert(
    db: &dyn Database,
    subject: &str,
    blob: &CreateBlob,
    sealed: &SealedBody,
    ts: &str,
) -> Result<(), StoreError> {
    let existing = db
        .query(&Statement::with_values(
            "SELECT blob_id FROM sealed_blobs WHERE subject = ? AND blob_id = ?",
            vec![text(subject), text(&blob.blob_id)],
        ))
        .await?;
    if !existing.is_empty() {
        return Err(StoreError::Taken);
    }
    let (outer_ct, object_key): (SeaValue, SeaValue) = match &sealed.object_key {
        None => (bytes(&sealed.outer_ct), SeaValue::String(None)),
        Some(key) => (SeaValue::Bytes(None), text(key)),
    };
    db.batch_atomic(&[
        Statement::with_values(
            "INSERT INTO sealed_blobs (subject, blob_id, version, purpose, alg, wraps, \
             created_by_credential, ciphertext_len, outer_ct, object_key, revision, \
             created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            vec![
                text(subject),
                text(&blob.blob_id),
                SeaValue::BigInt(Some(i64::from(blob.version))),
                text(&blob.purpose),
                text(&blob.alg),
                text(&wraps_json(&blob.wraps)?),
                text(&blob.created_by_credential),
                big(sealed.ciphertext_len),
                outer_ct,
                object_key,
                text(ts),
                text(ts),
            ],
        ),
        Statement::with_values(
            "INSERT INTO sealed_deks (subject, blob_id, kms_provider, kms_key_ref, wrapped_dek, \
             revision) VALUES (?, ?, ?, ?, ?, 1)",
            vec![
                text(subject),
                text(&blob.blob_id),
                text(sealed.provider),
                text(&sealed.key_ref),
                bytes(&sealed.wrapped_dek),
            ],
        ),
    ])
    .await?;
    Ok(())
}

/// The wraps, as the canonical JSON string the row stores and the wire
/// record re-parses.
fn wraps_json(wraps: &[Wrap]) -> Result<String, StoreError> {
    serde_json::to_string(wraps).map_err(|err| {
        StoreError::Internal(format!("a validated wrap set does not serialise: {err}"))
    })
}

/// A count that started life as a `usize` column value.
fn big(len: usize) -> SeaValue {
    SeaValue::BigInt(Some(i64::try_from(len).unwrap_or(i64::MAX)))
}

/// The row for `(subject, blob_id)`, or `None`.
///
/// # Errors
///
/// [`StoreError::Db`].
pub async fn load(
    db: &dyn Database,
    subject: &str,
    blob_id: &str,
) -> Result<Option<BlobRow>, StoreError> {
    let rows = db
        .query(&Statement::with_values(
            format!("SELECT {ROW_COLUMNS} FROM sealed_blobs WHERE subject = ? AND blob_id = ?"),
            vec![text(subject), text(blob_id)],
        ))
        .await?;
    Ok(rows.first().map(from_row))
}

/// The subject's rows, newest first: metadata only, no bodies.
///
/// # Errors
///
/// [`StoreError::Db`].
pub async fn list(db: &dyn Database, subject: &str) -> Result<Vec<BlobRow>, StoreError> {
    let rows = db
        .query(&Statement::with_values(
            format!(
                "SELECT {ROW_COLUMNS} FROM sealed_blobs WHERE subject = ? ORDER BY created_at DESC"
            ),
            vec![text(subject)],
        ))
        .await?;
    Ok(rows.rows.iter().map(from_row).collect())
}

/// Replaces the wrap set under an optimistic-concurrency check on the row's
/// [`BlobRow::revision`] (the `ETag`): the batch writes only where the row
/// still carries `expected_revision`, and writes a **fresh** validator value
/// there — so the read-back after the batch can attribute the row's state to
/// this request alone, and a lost race surfaces as [`StoreError::Stale`]
/// instead of a silent overwrite. Two edits sent from the same `ETag` cannot
/// both land. The payload — the outer ciphertext, the DEK material, the
/// version itself — is untouched; the DEK row's validator moves with the
/// blob row's, so the next rotation can guard both with the one `ETag` the
/// caller holds.
///
/// # Errors
///
/// [`StoreError::NotFound`], [`StoreError::Stale`] when the row's revision is
/// not `expected_revision`, [`StoreError::Db`], [`StoreError::Internal`]
/// when the RNG fails.
pub async fn replace_wraps(
    db: &dyn Database,
    subject: &str,
    blob_id: &str,
    expected_revision: i64,
    wraps: &str,
    ts: &str,
) -> Result<(), StoreError> {
    let mut fresh = fresh_revision()?;
    if fresh == expected_revision {
        fresh ^= 1;
    }
    let expected = SeaValue::BigInt(Some(expected_revision));
    let written = SeaValue::BigInt(Some(fresh));
    db.batch_atomic(&[
        Statement::with_values(
            "UPDATE sealed_blobs SET wraps = ?, updated_at = ?, revision = ? \
             WHERE subject = ? AND blob_id = ? AND revision = ?",
            vec![
                text(wraps),
                text(ts),
                written.clone(),
                text(subject),
                text(blob_id),
                expected,
            ],
        ),
        Statement::with_values(
            "UPDATE sealed_deks SET revision = ? \
             WHERE subject = ? AND blob_id = ? AND revision = ?",
            vec![
                written,
                text(subject),
                text(blob_id),
                SeaValue::BigInt(Some(expected_revision)),
            ],
        ),
    ])
    .await?;
    // `batch_atomic` reports no per-statement row counts, so the read-back is
    // the verdict: the row carries `fresh` only if this request wrote it.
    match load(db, subject, blob_id).await? {
        Some(row) if row.revision == fresh => Ok(()),
        Some(_) => Err(StoreError::Stale),
        None => Err(StoreError::NotFound),
    }
}

/// A rotation: the new payload, wraps, version and a **fresh** DEK land
/// together, writing a **fresh** validator (see `replace_wraps`). Both
/// statements are guarded by `expected_revision` (the `ETag`), so of two
/// concurrent rotations at most one matches; the loser writes nothing — in
/// particular it can never pair its new ciphertext with the winner's DEK —
/// and the read-back reports [`StoreError::Stale`]. Only the winner goes on
/// to free the object key the previous body occupied; keys name exactly one
/// parked body, so that delete cannot touch the new one.
///
/// # Errors
///
/// [`StoreError::NotFound`], [`StoreError::Stale`] when the row's revision is
/// not `expected_revision` or its version is not the body's `version - 1`,
/// [`StoreError::Db`], [`StoreError::Internal`] when the RNG fails.
pub async fn rotate(
    db: &dyn Database,
    subject: &str,
    blob: &CreateBlob,
    sealed: &SealedBody,
    ts: &str,
    expected_revision: i64,
    store: Option<&dyn cratefield_core::Blob>,
) -> Result<(), StoreError> {
    let old_key = load(db, subject, &blob.blob_id)
        .await?
        .ok_or(StoreError::NotFound)?
        .object_key;
    let previous_version = blob.version.saturating_sub(1);
    let mut fresh = fresh_revision()?;
    if fresh == expected_revision {
        fresh ^= 1;
    }
    let expected = SeaValue::BigInt(Some(expected_revision));
    let written = SeaValue::BigInt(Some(fresh));
    let (outer_ct, new_key): (SeaValue, SeaValue) = match &sealed.object_key {
        None => (bytes(&sealed.outer_ct), SeaValue::String(None)),
        Some(key) => (SeaValue::Bytes(None), text(key)),
    };
    db.batch_atomic(&[
        Statement::with_values(
            "UPDATE sealed_blobs SET version = ?, wraps = ?, ciphertext_len = ?, outer_ct = ?, \
             object_key = ?, updated_at = ?, revision = ? \
             WHERE subject = ? AND blob_id = ? AND version = ? AND revision = ?",
            vec![
                SeaValue::BigInt(Some(i64::from(blob.version))),
                text(&wraps_json(&blob.wraps)?),
                big(sealed.ciphertext_len),
                outer_ct,
                new_key,
                text(ts),
                written.clone(),
                text(subject),
                text(&blob.blob_id),
                SeaValue::BigInt(Some(i64::from(previous_version))),
                expected.clone(),
            ],
        ),
        Statement::with_values(
            "UPDATE sealed_deks SET kms_provider = ?, kms_key_ref = ?, wrapped_dek = ?, \
             revision = ? WHERE subject = ? AND blob_id = ? AND revision = ?",
            vec![
                text(sealed.provider),
                text(&sealed.key_ref),
                bytes(&sealed.wrapped_dek),
                written,
                text(subject),
                text(&blob.blob_id),
                expected,
            ],
        ),
    ])
    .await?;
    // The read-back is the verdict (see `replace_wraps`): the row carries
    // this request's validator only if this request won.
    match load(db, subject, &blob.blob_id).await? {
        Some(row) if row.revision == fresh => {}
        Some(_) => return Err(StoreError::Stale),
        None => return Err(StoreError::NotFound),
    }
    // An object the previous version parked in the blob store is superseded
    // by this one; removing it here (after the commit names the new key)
    // keeps exactly one live body per row. Best effort: a failure leaves an
    // unopenable orphan, never a live one.
    if let (Some(old_key), Some(store)) = (old_key, store)
        && let Err(err) = store.delete(&old_key).await
    {
        tracing::warn!(error = %err, "sealed: the previous body object could not be removed");
    }
    Ok(())
}

/// The crypto-shred: the DEK row goes first, then the blob row, in one
/// atomic batch. Returns the blob-store object key to remove afterwards —
/// from the moment this returns, every remaining copy of the body anywhere
/// is inert.
///
/// # Errors
///
/// [`StoreError::NotFound`], [`StoreError::Db`].
pub async fn erase(
    db: &dyn Database,
    subject: &str,
    blob_id: &str,
) -> Result<Option<String>, StoreError> {
    let row = load(db, subject, blob_id)
        .await?
        .ok_or(StoreError::NotFound)?;
    db.batch_atomic(&[
        Statement::with_values(
            "DELETE FROM sealed_deks WHERE subject = ? AND blob_id = ?",
            vec![text(subject), text(blob_id)],
        ),
        Statement::with_values(
            "DELETE FROM sealed_blobs WHERE subject = ? AND blob_id = ?",
            vec![text(subject), text(blob_id)],
        ),
    ])
    .await?;
    Ok(row.object_key)
}
