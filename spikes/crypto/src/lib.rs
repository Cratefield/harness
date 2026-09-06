//! # Crypto crate spike (#38)
//!
//! Implements the encrypt/decrypt path of the secrets design (#37,
//! `docs/SECRETS-DESIGN.md`) against each candidate AEAD implementation:
//!
//! | feature         | candidate                                          |
//! |-----------------|----------------------------------------------------|
//! | `aws-lc-backend`| `aws-lc-rs` (ring-compatible API over aws-lc)      |
//! | `ring-backend`  | `ring` 0.17                                        |
//! | `rustcrypto`    | `chacha20poly1305` (XChaCha20-Poly1305) + `aes-gcm`|
//! | `age-backend`   | `age` (expected elimination; scored once)          |
//!
//! The pieces of the design exercised here:
//!
//! - **Context binding.** [`SecretContext::aad`] computes the additional
//!   authenticated data — `store_id || secret_name || version || key_id`,
//!   length-prefixed — that binds every ciphertext to the row and store it
//!   belongs to. [`EnvelopeAead::seal`]/[`EnvelopeAead::open`] pass it as
//!   the AEAD's AAD, so a row copied between databases or renamed fails to
//!   decrypt (proven per candidate in `tests/roundtrip.rs`).
//! - **Envelope path.** [`store`] generates a 256-bit DEK from the OS RNG,
//!   wraps it under a KMS-held master key, caches the unwrapped DEK with a
//!   TTL and zeroisation, and seals secret values with a random nonce.
//!
//! The `store` module (OS RNG, `std::time`) is native-only and cfg-gated
//! off `wasm32`; the AEAD backends and context binding are pure and build
//! everywhere. That split mirrors production: the stores are native-only
//! (ADR 0008) while anything module-visible through a port must stay
//! wasm-clean.

pub mod backends;
#[cfg(not(target_arch = "wasm32"))]
pub mod store;

use zeroize::Zeroizing;

/// DEK length: 256-bit data keys (design, "Key hierarchy").
pub const DEK_LEN: usize = 32;

/// A data encryption key. Zeroised on drop.
pub type Dek = Zeroizing<[u8; DEK_LEN]>;

/// Generate a fresh 256-bit key from the OS RNG (native only — the store
/// path; wasm builds cfg this out).
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_key() -> Dek {
    let mut key = Dek::new([0u8; DEK_LEN]);
    getrandom::fill(key.as_mut()).expect("OS RNG");
    key
}

/// Generate `n` random bytes from the OS RNG (nonce generation).
#[cfg(not(target_arch = "wasm32"))]
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("OS RNG");
    buf
}

/// Everything a ciphertext is bound to (design, "Context binding").
/// For a tenant store `store_id` is the tenant id; the global store uses
/// the fixed label `"global"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretContext {
    pub store_id: String,
    pub secret_name: String,
    pub version: u32,
    pub key_id: String,
}

impl SecretContext {
    /// Canonical AAD: a domain-separation prefix, then every field with an
    /// explicit little-endian length prefix, so the encoding is injective —
    /// no two distinct contexts share an AAD, whatever the character sets.
    pub fn aad(&self) -> Vec<u8> {
        fn push(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"FZ-SECRETS-AAD-v1");
        push(&mut out, self.store_id.as_bytes());
        push(&mut out, self.secret_name.as_bytes());
        push(&mut out, &self.version.to_le_bytes());
        push(&mut out, self.key_id.as_bytes());
        out
    }
}

/// One stored secret version: which DEK encrypted it, the nonce, and the
/// ciphertext with the authentication tag appended. Stored in the secret's
/// row; the wrapped DEK lives in the same database's key table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// AEAD failure: authentication or parameter error. Deliberately opaque —
/// callers must not branch on the failure kind.
#[derive(Debug)]
pub struct AeadError;

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AEAD operation failed")
    }
}

impl std::error::Error for AeadError {}

/// The backend-neutral AEAD interface the design needs: seal and open with
/// caller-supplied key, nonce and AAD. Nonce handling stays with the caller
/// so the nonce strategy is one visible, scoreable decision per candidate.
pub trait EnvelopeAead: Send + Sync {
    /// Human-readable backend + algorithm name (for tests and size probe).
    fn name(&self) -> &'static str;
    fn nonce_len(&self) -> usize;
    /// `seal` returns ciphertext with the tag appended.
    fn seal(
        &self,
        key: &Dek,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError>;
    fn open(
        &self,
        key: &Dek,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError>;
}
