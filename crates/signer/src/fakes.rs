//! The in-memory [`KeySigner`] for tests: deterministic keys from
//! fixed-seed derivation, no secrets store, no I/O. A fake's value is
//! reproducibility — the same key reference signs the same way on every
//! run, so conformance failures read as failures and not as flaky
//! entropy.
//!
//! It still obeys the port's one hard rule: keys go in, signatures and
//! public descriptions come out, and nothing hands a caller the seed.

use std::collections::{BTreeMap, VecDeque};

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::audit::{SignAudit, SignAuditRecord};
use crate::crypto;
use crate::guardrails::{Guardrails, PolicyDecision, SignContext};
use crate::keys::{KeyInfo, KeyRef, KeyRole, Scheme, Signature, Subject};
use crate::payload::Payload;
use crate::port::KeySigner;
use crate::port::SignerError;

/// A deterministic in-memory signer. Keys are derived by hashing a seed
/// phrase with the subject, scheme and label and a per-signer counter,
/// so `create_key` twice with the same arguments gives two distinct
/// keys, and the same arguments on a fresh signer give the same ones.
pub struct FakeSigner {
    fixed_seed: Option<[u8; 32]>,
    // A test fake's key ring is the fake's own state, not request state
    // (ADR 0007); the clippy.toml ban is for per-request context.
    #[allow(clippy::disallowed_types)]
    keys: std::sync::Mutex<BTreeMap<String, Key>>,
    #[allow(clippy::disallowed_types)]
    counter: std::sync::Mutex<u64>,
}

impl Default for FakeSigner {
    // The constructor expressions are the same fixture state the field
    // allows above; the lint fires here because the type is named.
    #[allow(clippy::disallowed_types)]
    fn default() -> Self {
        Self {
            fixed_seed: None,
            keys: std::sync::Mutex::new(BTreeMap::new()),
            counter: std::sync::Mutex::new(0),
        }
    }
}

struct Key {
    info: KeyInfo,
    seed: Zeroizing<[u8; 32]>,
}

impl FakeSigner {
    /// An empty ring.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A fake whose keys all sign with exactly `seed` — the published
    /// test vectors a known-answer test pins, passed in code and
    /// nowhere else. Production providers never offer this.
    #[must_use]
    pub fn with_fixed_seed(seed: [u8; 32]) -> Self {
        Self {
            fixed_seed: Some(seed),
            ..Self::default()
        }
    }

    /// Signs directly against a seed — the seam the fake exposes
    /// instead of key material.
    fn sign_seed(
        seed: &[u8; 32],
        scheme: Scheme,
        payload: &Payload,
    ) -> Result<Signature, SignerError> {
        match scheme {
            Scheme::Secp256k1 => {
                if payload.scheme() != Scheme::Secp256k1 {
                    return Err(SignerError::Unsupported {
                        reason: format!(
                            "a secp256k1 key cannot sign {} payloads",
                            payload.scheme()
                        ),
                    });
                }
                let (signature, recovery_id) =
                    crypto::sign_secp256k1(seed, &payload.payload_hash()?)?;
                let (r, s) = crypto::split(signature);
                Ok(Signature::Secp256k1 {
                    r,
                    s,
                    v: crypto::v_of(recovery_id),
                })
            }
            Scheme::Ed25519 => {
                let Payload::SolanaMessage(message) = payload else {
                    return Err(SignerError::Unsupported {
                        reason: "an ed25519 key signs Solana messages here".to_owned(),
                    });
                };
                Ok(Signature::Ed25519 {
                    bytes: crypto::sign_ed25519(seed, &message.0),
                })
            }
        }
    }
}

#[async_trait]
impl KeySigner for FakeSigner {
    async fn create_key(
        &self,
        subject: &Subject,
        scheme: Scheme,
        label: &str,
    ) -> Result<KeyInfo, SignerError> {
        let mut counter = self.counter.lock().expect("uncontended");
        *counter += 1;
        let seed = self
            .fixed_seed
            .unwrap_or_else(|| derive_seed(subject, scheme, label, *counter));
        let identity = match scheme {
            Scheme::Secp256k1 => crypto::secp256k1_address(&seed)?,
            Scheme::Ed25519 => crypto::ed25519_pubkey(&seed),
        };
        let info = KeyInfo {
            key_ref: KeyRef::new(format!("fake-{scheme}-{}", *counter))?,
            scheme,
            role: KeyRole::Session,
            label: label.to_owned(),
            subject: subject.clone(),
            identity,
        };
        self.keys.lock().expect("uncontended").insert(
            info.key_ref.as_str().to_owned(),
            Key {
                info: info.clone(),
                seed: Zeroizing::new(seed),
            },
        );
        Ok(info)
    }

    async fn key(&self, key_ref: &KeyRef) -> Result<KeyInfo, SignerError> {
        self.keys
            .lock()
            .expect("uncontended")
            .get(key_ref.as_str())
            .map(|key| key.info.clone())
            .ok_or_else(|| SignerError::UnknownKey {
                key_ref: key_ref.to_string(),
            })
    }

    async fn sign(&self, key_ref: &KeyRef, payload: &Payload) -> Result<Signature, SignerError> {
        let key = self
            .keys
            .lock()
            .expect("uncontended")
            .get(key_ref.as_str())
            .map(|key| (key.info.scheme, key.seed.clone()))
            .ok_or_else(|| SignerError::UnknownKey {
                key_ref: key_ref.to_string(),
            })?;
        let (scheme, seed) = key;
        if payload.scheme() != scheme {
            return Err(SignerError::Unsupported {
                reason: format!(
                    "the key `{key_ref}` is a {scheme} key, and cannot sign {} payloads",
                    payload.scheme()
                ),
            });
        }
        Self::sign_seed(&seed, scheme, payload)
    }
}

/// The fake's key seed: sha256 over a fixed domain tag, the subject,
/// the scheme, the label and the counter. Deterministic on purpose —
/// every run derives the same key for the same arguments.
fn derive_seed(subject: &Subject, scheme: Scheme, label: &str, counter: u64) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"cratefield-signer/fake-key/v1");
    hasher.update(subject.venture.as_bytes());
    if let Some(user) = &subject.user {
        hasher.update([0_u8]);
        hasher.update(user.as_bytes());
    } else {
        hasher.update([1_u8]);
    }
    hasher.update(scheme.to_string().as_bytes());
    hasher.update(label.as_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.finalize().into()
}

/// A [`Guardrails`] fake that answers with scripted outcomes, one per
/// `check`, in order. A script that runs dry denies — a fake that
/// answers an unscripted allow lets a test pass by accident.
pub struct FakeGuardrails {
    // The script is the fake's own fixture state, not request state
    // (ADR 0007); the clippy.toml ban is for per-request context.
    #[allow(clippy::disallowed_types)]
    outcomes: std::sync::Mutex<VecDeque<Result<PolicyDecision, SignerError>>>,
}

impl FakeGuardrails {
    /// A fake scripted with `outcomes`, answered first in, first out.
    // The constructor expression is the same fixture state the field
    // allows above; the lint fires here because the type is named.
    #[allow(clippy::disallowed_types)]
    #[must_use]
    pub fn new(outcomes: impl IntoIterator<Item = Result<PolicyDecision, SignerError>>) -> Self {
        Self {
            outcomes: std::sync::Mutex::new(outcomes.into_iter().collect()),
        }
    }
}

#[async_trait]
impl Guardrails for FakeGuardrails {
    async fn check(&self, _context: &SignContext) -> Result<PolicyDecision, SignerError> {
        match self.outcomes.lock().expect("uncontended").pop_front() {
            Some(outcome) => outcome,
            None => Ok(PolicyDecision::Deny {
                reason: "the scripted guardrails have no outcome left".to_owned(),
            }),
        }
    }
}

/// A [`SignAudit`] that refuses every record — the fail-closed seam,
/// for proving a sink that cannot write stops the signature.
pub struct RefusingAudit {
    reason: String,
}

impl RefusingAudit {
    /// An audit sink that refuses every record, citing `reason`.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl SignAudit for RefusingAudit {
    async fn record(&self, _record: &SignAuditRecord) -> Result<(), SignerError> {
        Err(SignerError::Audit(self.reason.clone()))
    }
}
