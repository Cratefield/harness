//! `WorkerSecretKms` — the production provider for the Cloudflare path
//! (issue #535, ADR 0103).
//!
//! A Worker has no filesystem for a [`LocalFileKms`] key file, and the
//! managed vendor providers are still unwritten, so the KEK lives in the
//! Worker's secret store as a small numbered set: `HARNESS_KEK_CURRENT`
//! holds the decimal version that wraps, and `HARNESS_KEK_V1`,
//! `HARNESS_KEK_V2`, … hold the key material, standard base64 of 32
//! bytes. Everything is read once at construction — one lookup per
//! version, never one per request.
//!
//! It takes no environment argument and does not refuse production,
//! because it *is* the production provider. That is defensible there:
//! the KEK lives in the platform's secret store, encrypted at rest,
//! never on a host disk and never in D1 next to the wrapped DEKs. What
//! it is not is a managed HSM KMS: the Worker isolate can read the KEK
//! material, and a wrap carries no per-call IAM or audit at the key. The
//! [`Kms`] seam stays, so an HSM-backed provider, if one arrives, is a
//! re-wrap rather than a redesign.
//!
//! The lookup is a plain closure so this crate needs no `worker`
//! dependency; the runtime adapts its bindings as
//! `|name| env.secret(name).ok().map(|s| s.to_string())`. The blob is
//! `version: u32 big-endian || nonce(24) || XChaCha20-Poly1305`, with
//! the version inside the AAD, so the header an unwrap dispatches on is
//! authenticated like the rest of it.
//!
//! [`LocalFileKms`]: crate::LocalFileKms

use std::collections::BTreeMap;

use base64::Engine as _;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};

use crate::{Dek, Kms, KmsError};

/// Domain separation, so a blob produced here can never be mistaken for
/// a secret ciphertext from the envelope layer even under the same key.
/// The four version bytes follow it, so the header is authenticated.
const WRAP_AAD: &[u8] = b"FZ-KMS-WORKER-SECRET-WRAP-v1";
const NONCE_LEN: usize = 24;
/// The blob opens with the KEK version, big-endian.
const VERSION_LEN: usize = 4;
/// The secret holding the decimal number of the version that wraps.
const CURRENT_SECRET: &str = "HARNESS_KEK_CURRENT";
/// The highest version `HARNESS_KEK_CURRENT` may name, so a typo fails
/// at construction instead of chasing thousands of missing secrets.
const MAX_VERSION: u32 = 1024;

/// A KEK held in Worker secrets, read once at construction. See the
/// module docs for why it does not refuse production.
pub struct WorkerSecretKms {
    /// The version new wraps use; `HARNESS_KEK_CURRENT` named it.
    current: u32,
    /// Every version this deployment holds, from 1 through `current`
    /// minus the ones an operator deleted after a re-wrap.
    keys: BTreeMap<u32, Dek>,
    key_ref: String,
}

impl std::fmt::Debug for WorkerSecretKms {
    /// Names the current version, never any key's contents. Written by
    /// hand rather than derived so it cannot start printing key material
    /// because a field was added.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerSecretKms")
            .field("provider", &"worker-secret")
            .field("key_ref", &self.key_ref)
            .finish_non_exhaustive()
    }
}

impl WorkerSecretKms {
    /// Reads the whole key ring once: `HARNESS_KEK_CURRENT` (a decimal
    /// version `n`, 1 to 1024) and then `HARNESS_KEK_V1` through
    /// `HARNESS_KEK_V<n>`. The current version must be present; older
    /// ones are optional, because only blobs still wrapped under them
    /// need them back. Each value is standard base64 of exactly 32
    /// bytes, and an error names the secret and the fix, never the
    /// material.
    ///
    /// # Errors
    ///
    /// [`KmsError::Invalid`] for every malformation: `HARNESS_KEK_CURRENT`
    /// missing, non-numeric, zero or over the bound; the current
    /// version's secret missing; any present secret not base64, or not
    /// 32 bytes once decoded.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, KmsError> {
        let named = lookup(CURRENT_SECRET).ok_or_else(|| {
            KmsError::Invalid(format!(
                "{CURRENT_SECRET} is not set: it holds the decimal number of the KEK version \
                 new wraps use, e.g. 1, set with `wrangler secret put {CURRENT_SECRET}`"
            ))
        })?;
        let current = parse_version(&named)?;
        let mut keys = BTreeMap::new();
        for version in 1..=current {
            let name = secret_name(version);
            let Some(text) = lookup(&name) else {
                if version == current {
                    return Err(KmsError::Invalid(format!(
                        "{CURRENT_SECRET} says {current}, but {name} is not set; put the key \
                         with `wrangler secret put {name}`"
                    )));
                }
                // Deleted after a re-wrap, which the runbook says to do:
                // only a blob still wrapped under it would need it.
                continue;
            };
            keys.insert(version, decode_key(&name, &text)?);
        }
        let key_ref = format!("worker-secret:{}", secret_name(current));
        Ok(Self {
            current,
            keys,
            key_ref,
        })
    }

    fn cipher(key: &Dek) -> Result<chacha20poly1305::XChaCha20Poly1305, KmsError> {
        chacha20poly1305::XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| KmsError::Invalid("a KEK is not 32 bytes".to_owned()))
    }
}

/// `HARNESS_KEK_V<n>` — the secret holding version `n`'s key material.
fn secret_name(version: u32) -> String {
    format!("HARNESS_KEK_V{version}")
}

/// The decimal `HARNESS_KEK_CURRENT`, trimmed of the whitespace a shell
/// round trip leaves behind, bounded so a typo cannot loop through a
/// thousand missing lookups.
fn parse_version(text: &str) -> Result<u32, KmsError> {
    let text = text.trim();
    // Digits only: `u32`'s own parser accepts a leading `+`, and a
    // version count has no sign.
    let invalid = || {
        KmsError::Invalid(format!(
            "{CURRENT_SECRET} is not a version number: it must be a decimal count like 1, \
             set with `wrangler secret put {CURRENT_SECRET}`"
        ))
    };
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let version: u32 = text.parse().map_err(|_| invalid())?;
    if version == 0 {
        return Err(KmsError::Invalid(format!(
            "{CURRENT_SECRET} is 0: versions start at 1, so put 1 with \
             `wrangler secret put {CURRENT_SECRET}`"
        )));
    }
    if version > MAX_VERSION {
        return Err(KmsError::Invalid(format!(
            "{CURRENT_SECRET} is {version}, over the bound of {MAX_VERSION}: check for a \
             typo and put the right number with `wrangler secret put {CURRENT_SECRET}`; \
             if the key ring is genuinely that deep, the bound in \
             crates/kms/src/worker_secret.rs moves deliberately"
        )));
    }
    Ok(version)
}

/// Standard base64 of exactly 32 bytes. The error is a reason, never
/// the value, and [`Dek::from_bytes`] zeroises a wrong length.
fn decode_key(name: &str, text: &str) -> Result<Dek, KmsError> {
    let invalid = |reason: &str| {
        KmsError::Invalid(format!(
            "{name} {reason}: the value is 32 key bytes, standard base64, set with \
             `wrangler secret put {name}`"
        ))
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim().as_bytes())
        .map_err(|_| invalid("is not standard base64"))?;
    Dek::from_bytes(bytes).map_err(|_| invalid("does not decode to exactly 32 bytes"))
}

/// The AAD: the domain constant, then the version bytes, so a blob
/// cannot be moved between versions or have its header edited.
fn aad(version: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WRAP_AAD.len() + VERSION_LEN);
    aad.extend_from_slice(WRAP_AAD);
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

#[async_trait]
impl Kms for WorkerSecretKms {
    fn provider(&self) -> &'static str {
        "worker-secret"
    }

    fn key_ref(&self) -> &str {
        &self.key_ref
    }

    async fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, KmsError> {
        let key = self.keys.get(&self.current).ok_or_else(|| {
            KmsError::Unavailable(format!(
                "{} is {}, which this deployment no longer holds; restore the secret",
                CURRENT_SECRET, self.current
            ))
        })?;
        let cipher = Self::cipher(key)?;
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|err| KmsError::Unavailable(format!("the OS random source failed: {err}")))?;
        let sealed = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: dek.expose(),
                    aad: &aad(self.current),
                },
            )
            .map_err(|_| KmsError::Invalid("the data key could not be wrapped".to_owned()))?;
        let mut out = Vec::with_capacity(VERSION_LEN + NONCE_LEN + sealed.len());
        out.extend_from_slice(&self.current.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    async fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, KmsError> {
        if wrapped.len() <= VERSION_LEN + NONCE_LEN {
            return Err(KmsError::Tampered(
                "the wrapped key is too short to contain a version, a nonce and a tag".to_owned(),
            ));
        }
        let (header, rest) = wrapped.split_at(VERSION_LEN);
        let version = u32::from_be_bytes(header.try_into().expect("split at VERSION_LEN"));
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");
        let Some(key) = self.keys.get(&version) else {
            return Err(KmsError::Tampered(format!(
                "wrapped under {}, which this deployment does not hold ({} is {}); restore \
                 the secret or re-wrap",
                secret_name(version),
                CURRENT_SECRET,
                self.current
            )));
        };
        let opened = Self::cipher(key)?
            .decrypt(
                nonce.into(),
                Payload {
                    msg: sealed,
                    aad: &aad(version),
                },
            )
            .map_err(|_| {
                KmsError::Tampered(format!(
                    "the wrapped key did not authenticate under {}",
                    secret_name(version)
                ))
            })?;
        Dek::from_bytes(opened)
    }
}
