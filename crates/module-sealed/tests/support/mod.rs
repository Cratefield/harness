//! Shared fixtures for the `cratefield-module-sealed` tests: a KMS fake the
//! tests hold the master key of (so the shred test can prove nothing left on
//! the server opens a snapshot), a bearer-is-the-subject auth fake that can
//! carry a verified address, and builders for wire-valid records.

// A test-support module, included with `mod support;` into each test binary
// in this crate. `pub` is how a helper reads here, and the lints are right
// that nothing outside can reach it and that not every binary uses every
// helper. Saying so once beats `pub(crate)` on every helper.
#![allow(unreachable_pub)]
#![allow(dead_code)]

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce};
use async_trait::async_trait;
use base64::Engine as _;
use cratefield_core::{Auth, AuthError, Caller, Subject};
use cratefield_kms::{Dek, Kms, KmsError};
// Re-exported: the route tests build records against this type.
pub use cratefield_module_sealed::record::CreateBlob;
use cratefield_module_sealed::record::{PRF_WRAP_ALG, RECOVERY_WRAP_ALG, RecoveryParams, Wrap};

/// The same `http` types the `Auth` trait names (`axum` re-exports them).
use axum::http::HeaderMap;

/// The master key every [`FakeKms`] wraps under. Fixed, so a test can unwrap
/// what the module stored and prove what it likes about the bytes.
pub const MASTER_KEY: [u8; 32] = [42_u8; 32];

/// The subject the shared client fixture was generated for.
pub const SUBJECT_ID: &str = "user_fixture";

/// A KMS that wraps data keys under a fixed in-test master key
/// (AES-256-GCM, `nonce || ciphertext || tag`, AAD `fake-kms-v1`). Honest
/// about the two answers that matter: `Tampered` for bytes that do not
/// authenticate, and the recovered [`Dek`] otherwise.
#[derive(Clone)]
pub struct FakeKms;

impl FakeKms {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn cipher() -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&MASTER_KEY).expect("the master key is 32 bytes")
    }
}

impl Default for FakeKms {
    fn default() -> Self {
        Self::new()
    }
}

fn fake_nonce(bytes: &[u8]) -> Nonce<Aes256Gcm> {
    nonce(bytes)
}

/// A GCM nonce built from the first 12 bytes of `bytes`.
#[must_use]
pub fn nonce(bytes: &[u8]) -> Nonce<Aes256Gcm> {
    let mut nonce = <Nonce<Aes256Gcm>>::default();
    nonce.copy_from_slice(bytes);
    nonce
}

/// Fresh random bytes, for test payloads.
pub fn fill(bytes: &mut [u8]) {
    getrandom::fill(bytes).expect("the OS RNG answers");
}

#[async_trait]
impl Kms for FakeKms {
    fn provider(&self) -> &'static str {
        "fake-master"
    }

    fn key_ref(&self) -> &'static str {
        "test/master-0"
    }

    async fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, KmsError> {
        let mut nonce = vec![0_u8; 12];
        getrandom::fill(&mut nonce).map_err(|err| KmsError::Unavailable(err.to_string()))?;
        let mut body = dek.expose().to_vec();
        FakeKms::cipher()
            .encrypt_in_place(&fake_nonce(&nonce), b"fake-kms-v1", &mut body)
            .map_err(|err| KmsError::Refused(err.to_string()))?;
        let mut out = nonce;
        out.extend_from_slice(&body);
        Ok(out)
    }

    async fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, KmsError> {
        if wrapped.len() < 12 + 16 {
            return Err(KmsError::Tampered(
                "a wrapped key is shorter than its own framing".into(),
            ));
        }
        // The buffer is `ciphertext || tag`; `decrypt_in_place` verifies and
        // strips the tag itself.
        let mut body = wrapped[12..].to_vec();
        FakeKms::cipher()
            .decrypt_in_place(&fake_nonce(&wrapped[..12]), b"fake-kms-v1", &mut body)
            .map_err(|_| KmsError::Tampered("the wrapped key failed authentication".into()))?;
        Dek::from_bytes(body)
    }
}

/// A verifier whose bearer token **is** the subject id — like the kit's
/// `FakeAuth::subjects()` — but one that can carry a verified address, which
/// the unlock-notice test needs.
#[derive(Clone)]
pub struct FixedAuth {
    email: Option<String>,
}

impl FixedAuth {
    #[must_use]
    pub fn with_email(email: &str) -> Self {
        Self {
            email: Some(email.to_owned()),
        }
    }
}

#[async_trait]
impl Auth for FixedAuth {
    async fn identify(&self, headers: &HeaderMap) -> Result<Caller, AuthError> {
        let token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        match token {
            None => Ok(Caller::Anonymous),
            Some(id) => Ok(Caller::Subject(
                Subject::new(id)
                    .session("test-session")
                    .email(self.email.clone()),
            )),
        }
    }
}

/// Unpadded base64url, the wire encoding.
#[must_use]
pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A wire-valid prf wrap: 32-byte salt, 40-byte AES-KW output.
#[must_use]
pub fn prf_wrap(id: &str) -> Wrap {
    Wrap {
        id: id.to_owned(),
        kind: "prf".to_owned(),
        alg: PRF_WRAP_ALG.to_owned(),
        params: None,
        salt: b64(&[7_u8; 32]),
        wrapped_key: b64(&[9_u8; 40]),
    }
}

/// A wire-valid recovery wrap at the accepted Argon2id floor.
#[must_use]
pub fn recovery_wrap(id: &str) -> Wrap {
    Wrap {
        id: id.to_owned(),
        kind: "recovery".to_owned(),
        alg: RECOVERY_WRAP_ALG.to_owned(),
        params: Some(RecoveryParams {
            m_kib: 65536,
            t: 3,
            p: 1,
        }),
        salt: b64(&[5_u8; 16]),
        wrapped_key: b64(&[11_u8; 40]),
    }
}

/// A record the validators accept: fresh random payload bytes, one wrap per
/// unlock kind.
#[must_use]
pub fn record(blob_id: &str, version: u32, purpose: &str) -> CreateBlob {
    let mut payload = vec![0_u8; 64];
    getrandom::fill(&mut payload).expect("the OS RNG answers");
    CreateBlob {
        blob_id: blob_id.to_owned(),
        version,
        purpose: purpose.to_owned(),
        alg: "A256GCM".to_owned(),
        ciphertext: b64(&payload),
        wraps: vec![prf_wrap("passkey-1"), recovery_wrap("recovery-1")],
        created_by_credential: "test-credential-1".to_owned(),
    }
}
