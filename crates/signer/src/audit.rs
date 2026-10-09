//! The audit seam and its reference implementation. Every sign attempt —
//! allowed, denied, or unhashable — is one linked record: subject, key
//! reference, payload hash, decoded intent, the policy decision, and the
//! outcome. [`MemorySignAudit`] chains the records with sha256 the way
//! `cratefield-secrets`' own audit chain does, and `verify` names the
//! first entry whose hash does not follow from its predecessor.
//!
//! Audit failure fails closed: a [`SignAudit`] that cannot record has
//! the same effect as a deny, because an unrecorded signature is an
//! unauditable one.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::keys::{KeyRef, Subject};
use crate::payload::Intent;
use crate::port::SignerError;

/// What the policy decided, as the record stores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecisionRecord {
    /// The guardrails allowed it.
    Allow,
    /// The guardrails refused, with the reason.
    Deny {
        /// Why.
        reason: String,
    },
}

impl From<&crate::guardrails::PolicyDecision> for PolicyDecisionRecord {
    fn from(decision: &crate::guardrails::PolicyDecision) -> Self {
        match decision {
            crate::guardrails::PolicyDecision::Allow => Self::Allow,
            crate::guardrails::PolicyDecision::Deny { reason } => Self::Deny {
                reason: reason.clone(),
            },
        }
    }
}

/// How the attempt ended. The pairing is the invariant: a `NotAttempted`
/// under an `Allow` record is the decision written before the provider
/// ran, and the outcome arrives as its own linked record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SignOutcome {
    /// The provider signed.
    Signed,
    /// The provider was called and refused; its own words, for the
    /// record.
    ProviderError {
        /// The provider's error, as text.
        error: String,
    },
    /// The provider was never called.
    NotAttempted,
}

/// One linked record of one sign attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignAuditRecord {
    /// Who asked.
    pub subject: Subject,
    /// Which key would have signed.
    pub key_ref: KeyRef,
    /// The payload's signing digest, `0x`-hex; all-zero when the
    /// payload could not be hashed at all.
    pub payload_hash: String,
    /// The decoded intent, `None` when the payload did not decode.
    pub intent: Option<Intent>,
    /// What the policy decided.
    pub decision: PolicyDecisionRecord,
    /// How the attempt ended.
    pub outcome: SignOutcome,
    /// When the attempt was recorded, RFC 3339.
    pub at: String,
}

/// The audit seam. Implementations append; nothing here may edit or
/// delete.
#[async_trait]
pub trait SignAudit: Send + Sync {
    /// Records one attempt.
    ///
    /// # Errors
    ///
    /// When the record cannot be written. The caller fails closed: an
    /// [`GuardedSigner`](crate::GuardedSigner) returns
    /// [`SignerError::Audit`] and never returns a signature whose record
    /// is missing.
    async fn record(&self, record: &SignAuditRecord) -> Result<(), SignerError>;
}

#[async_trait]
impl<A: SignAudit + ?Sized> SignAudit for &A {
    async fn record(&self, record: &SignAuditRecord) -> Result<(), SignerError> {
        (**self).record(record).await
    }
}

/// Where the chain stands after a `verify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditAnchor {
    /// How many entries the chain holds.
    pub entries: u64,
    /// The head hash, hex — the value the next entry chains from.
    pub head_hash: String,
}

const GENESIS: [u8; 32] = [0_u8; 32];
const CHAIN_TAG: &[u8] = b"CRATEFIELD-SIGN-AUDIT-v1";

/// One stored link: the record, its predecessor's hash, its own.
#[derive(Debug, Clone)]
struct Stored {
    seq: u64,
    prev_hash: [u8; 32],
    hash: [u8; 32],
    record: SignAuditRecord,
}

/// The reference [`SignAudit`]: every record in memory, chained by
/// sha256 over the chain tag, the previous hash, and the length-prefixed
/// sequence number and serialised record — the same construction as
/// `cratefield-secrets`' audit chain, so one `verify` mental model
/// covers both.
///
/// The `std::sync::Mutex` is the workspace's allowed exception with a
/// justification on the field: this is a test and local-development
/// sink guarding its own append vector, not request state.
#[derive(Default)]
pub struct MemorySignAudit {
    // Appends to an audit chain are interior state of the sink itself,
    // not ambient request state (ADR 0007); the clippy.toml ban is for
    // per-request context, which this is not.
    #[allow(clippy::disallowed_types)]
    entries: std::sync::Mutex<Vec<Stored>>,
}

impl MemorySignAudit {
    /// An empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Copies of the records so far, in order — for inspection; the
    /// chain itself is not handed out.
    /// # Panics
    ///
    /// If the audit mutex is poisoned — a writer panicked mid-record.
    #[must_use]
    pub fn records(&self) -> Vec<SignAuditRecord> {
        self.entries
            .lock()
            .expect("an audit sink is never poisoned into use")
            .iter()
            .map(|stored| stored.record.clone())
            .collect()
    }

    /// A copy of entry `seq`, if the chain holds it.
    /// # Panics
    ///
    /// If the audit mutex is poisoned — a writer panicked mid-record.
    #[must_use]
    pub fn record_at(&self, seq: u64) -> Option<SignAuditRecord> {
        self.entries
            .lock()
            .expect("an audit sink is never poisoned into use")
            .get(usize::try_from(seq).ok()?)
            .map(|stored| stored.record.clone())
    }

    /// The link hash of entry `seq`: seq 0 is the first record, and
    /// `None` past the end.
    /// # Panics
    ///
    /// If the audit mutex is poisoned — a writer panicked mid-record.
    #[must_use]
    pub fn hash_at(&self, seq: u64) -> Option<[u8; 32]> {
        self.entries
            .lock()
            .expect("an audit sink is never poisoned into use")
            .get(usize::try_from(seq).ok()?)
            .map(|stored| stored.hash)
    }

    fn hash(seq: u64, prev_hash: &[u8; 32], record: &SignAuditRecord) -> [u8; 32] {
        let serialised = serde_json::to_vec(record).unwrap_or_else(|_| {
            // Every field is owned data — strings, arrays, decimals — so
            // serialisation cannot fail; the fallback keeps the hash
            // total anyway.
            Vec::new()
        });
        let seq_bytes = seq.to_be_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(CHAIN_TAG);
        hasher.update(prev_hash);
        hasher.update(
            u32::try_from(seq_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        hasher.update(seq_bytes);
        hasher.update(
            u32::try_from(serialised.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        hasher.update(&serialised);
        hasher.finalize().into()
    }
}

#[async_trait]
impl SignAudit for MemorySignAudit {
    async fn record(&self, record: &SignAuditRecord) -> Result<(), SignerError> {
        let mut entries = self
            .entries
            .lock()
            .expect("an audit sink is never poisoned into use");
        let seq = entries.len() as u64;
        let prev_hash = entries.last().map_or(GENESIS, |last| last.hash);
        let hash = Self::hash(seq, &prev_hash, record);
        entries.push(Stored {
            seq,
            prev_hash,
            hash,
            record: record.clone(),
        });
        Ok(())
    }
}

impl MemorySignAudit {
    /// Walks the chain and returns where it stands. An entry whose hash
    /// does not follow from its predecessor — because a record was
    /// edited, an entry dropped, or the head rewritten — is an
    /// [`SignerError::Audit`] naming the first broken `seq`.
    ///
    /// # Errors
    ///
    /// [`SignerError::Audit`] naming the first broken entry.
    ///
    /// # Panics
    ///
    /// If the audit mutex is poisoned — a writer panicked mid-record.
    pub fn verify(&self) -> Result<AuditAnchor, SignerError> {
        let entries = self
            .entries
            .lock()
            .expect("an audit sink is never poisoned into use");
        let mut prev_hash = GENESIS;
        for stored in entries.iter() {
            let expected = Self::hash(stored.seq, &prev_hash, &stored.record);
            if stored.prev_hash != prev_hash || stored.hash != expected {
                return Err(SignerError::Audit(format!(
                    "the audit chain breaks at entry {}: the hash does not follow from its \
                     predecessor",
                    stored.seq
                )));
            }
            prev_hash = stored.hash;
        }
        Ok(AuditAnchor {
            entries: entries.len() as u64,
            head_hash: hex::encode(prev_hash),
        })
    }
}

/// An RFC 3339 timestamp, the same way `cratefield-secrets` stamps its
/// rows.
pub(crate) fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(value: &str) -> SignAuditRecord {
        SignAuditRecord {
            subject: Subject::new("acme", None).expect("a venture"),
            key_ref: KeyRef::new("session/secp256k1/acme/ops/0102030405060708")
                .expect("a reference"),
            payload_hash: format!("0x{}", hex::encode([0xab; 32])),
            intent: None,
            decision: PolicyDecisionRecord::Allow,
            outcome: SignOutcome::Signed,
            at: value.to_owned(),
        }
    }

    #[test]
    fn chain_verifies() {
        let audit = MemorySignAudit::new();
        for at in ["t1", "t2", "t3"] {
            pollster::block_on(audit.record(&record(at))).expect("records");
        }
        let anchor = audit.verify().expect("the chain holds");
        assert_eq!(anchor.entries, 3);
        // Each link chains from its predecessor's hash, not from genesis.
        assert_ne!(
            audit.hash_at(0),
            audit.hash_at(1),
            "distinct records must hash distinctly"
        );
    }

    #[test]
    fn verify_names_the_first_broken_entry() {
        // A chain of three, then the internals used to edit entry 1 in
        // place — the write an attacker who can reach the sink would
        // make. verify() must name entry 1, not entry 2.
        let audit = MemorySignAudit::new();
        for at in ["t1", "t2", "t3"] {
            pollster::block_on(audit.record(&record(at))).expect("records");
        }
        #[allow(clippy::disallowed_types)]
        {
            let mut entries = audit.entries.lock().expect("uncontended");
            entries[1].record.at = "EDITED".to_owned();
        }
        let err = audit.verify().expect_err("the edit breaks the chain");
        assert!(
            err.to_string().contains("entry 1"),
            "the error should name the first broken entry, got: {err}"
        );
        // The untouched first link still follows from genesis.
        assert_eq!(
            audit.hash_at(0),
            Some(MemorySignAudit::hash(
                0,
                &GENESIS,
                &audit.record_at(0).expect("entry 0")
            ))
        );
    }

    #[test]
    fn an_empty_chain_verifies_at_genesis() {
        let audit = MemorySignAudit::new();
        let anchor = audit.verify().expect("an empty chain holds");
        assert_eq!(anchor.entries, 0);
        assert_eq!(anchor.head_hash, hex::encode(GENESIS));
    }

    #[test]
    fn records_round_trip_through_json() {
        let audit = MemorySignAudit::new();
        pollster::block_on(audit.record(&record("t1"))).expect("records");
        let seen = audit.records();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].at, "t1");
        // The bytes the hash covered are the bytes JSON gives back, so a
        // record moved between sinks — or languages — chains the same.
        let json = serde_json::to_string(&seen[0]).expect("serialises");
        let back: SignAuditRecord = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, seen[0]);
    }
}
