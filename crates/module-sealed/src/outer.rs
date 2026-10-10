//! The outer wrap: what the server adds on top of what the client sent.
//!
//! The client's ciphertext body is sealed under a per-blob data key
//! (AES-256-GCM) whose wrapped form lives in `sealed_deks` and opens only
//! through the [`Kms`](cratefield_kms::Kms) port. This is defence in depth —
//! a database dump is ciphertext over ciphertext — and **not** a decryption
//! service: nothing here, and nothing in this crate, opens the client layer.
//! There is no server-side recovery path.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce};
use cratefield_kms::Dek;

use crate::SealedError;

/// AES-GCM nonce length, the 96 bits NIST recommends for random nonces.
const NONCE_LEN: usize = 12;
/// AES-GCM tag length.
const TAG_LEN: usize = 16;

/// Binds an outer ciphertext to exactly one (subject, blob, version) row, the
/// way the client's AAD binds its payload to one record. The domain prefix
/// keeps a server AAD from ever being mistaken for a client one.
fn aad(subject: &str, blob_id: &str, version: u32) -> Vec<u8> {
    format!("cratefield-sealed-outer-v1|{subject}|{blob_id}|{version}").into_bytes()
}

/// Draws `len` fresh bytes from the OS RNG.
pub(crate) fn random(len: usize) -> Result<Vec<u8>, SealedError> {
    let mut bytes = vec![0_u8; len];
    getrandom::fill(&mut bytes)
        .map_err(|err| SealedError::Internal(format!("the OS random source failed: {err}")))?;
    Ok(bytes)
}

fn cipher(dek: &Dek) -> Result<Aes256Gcm, SealedError> {
    Aes256Gcm::new_from_slice(dek.expose())
        .map_err(|err| SealedError::Internal(format!("the outer cipher refused the key: {err}")))
}

fn nonce_of(bytes: &[u8]) -> Nonce<Aes256Gcm> {
    let mut nonce = <Nonce<Aes256Gcm>>::default();
    nonce.copy_from_slice(bytes);
    nonce
}

/// Seals `plaintext` under `dek`, with the row's AAD bound, returning
/// `nonce || ciphertext || tag` (the tag postfix, as AES-GCM frames it).
///
/// # Errors
///
/// [`SealedError::Internal`] when the RNG fails or the cipher refuses —
/// neither is reachable with a well-formed [`Dek`] and this framing.
pub(crate) fn seal(
    dek: &Dek,
    plaintext: &[u8],
    subject: &str,
    blob_id: &str,
    version: u32,
) -> Result<Vec<u8>, SealedError> {
    let cipher = cipher(dek)?;
    let nonce = random(NONCE_LEN)?;
    let mut body = plaintext.to_vec();
    cipher
        .encrypt_in_place(
            &nonce_of(&nonce),
            &aad(subject, blob_id, version),
            &mut body,
        )
        .map_err(|err| SealedError::Internal(format!("the outer seal failed: {err}")))?;
    let mut out = nonce;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens what [`seal`] produced, verifying the row's AAD.
///
/// # Errors
///
/// [`SealedError::Tampered`] when the bytes do not authenticate — wrong key,
/// wrong row, a flipped bit — never a partial or garbage plaintext.
pub(crate) fn open(
    dek: &Dek,
    sealed: &[u8],
    subject: &str,
    blob_id: &str,
    version: u32,
) -> Result<Vec<u8>, SealedError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(SealedError::Tampered(
            "an outer ciphertext is shorter than its own framing".into(),
        ));
    }
    let mut body = sealed[NONCE_LEN..].to_vec();
    cipher(dek)?
        .decrypt_in_place(
            &nonce_of(&sealed[..NONCE_LEN]),
            &aad(subject, blob_id, version),
            &mut body,
        )
        .map_err(|_| {
            SealedError::Tampered(format!(
                "the outer wrap failed authentication for `{blob_id}` v{version}"
            ))
        })?;
    Ok(body)
}
