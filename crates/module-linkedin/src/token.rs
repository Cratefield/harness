//! Sealing OAuth tokens at rest (issue #8).
//!
//! The harness secrets layer (Cratefield/harness #24) does not exist yet, so
//! the module seals its own tokens with the primitive that layer already chose
//! in ADR 0102: XChaCha20-Poly1305, a fresh 24-byte random nonce per
//! encryption, `zeroize` on the key material. When the port lands this file
//! becomes a thin call onto it and the stored format is what has to migrate,
//! which is why the blob carries a version and a key id.
//!
//! The AAD binds a ciphertext to the row and the column it belongs to, so an
//! access-token ciphertext cannot be moved into the refresh-token column, and
//! a blob from one account cannot be replayed into another.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{Key, KeyInit as _, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Blob layout version. Bumped only if the layout changes; the key id
/// handles ordinary rotation.
const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
pub(crate) const KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SealError {
    /// The configured key is not 32 bytes of base64.
    Key,
    /// The OS refused randomness. Never seal without a fresh nonce.
    Random,
    /// The stored blob is truncated, not base64, or a version we do not know.
    Malformed,
    /// The blob was sealed under a different key id than the one configured.
    UnknownKeyId(u8),
    /// Authentication failed: wrong key, wrong AAD, or tampering.
    Authentication,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::Key => write!(f, "LINKEDIN_TOKEN_KEY is not 32 bytes of base64"),
            SealError::Random => write!(f, "no randomness available for a nonce"),
            SealError::Malformed => write!(f, "sealed value is malformed"),
            SealError::UnknownKeyId(id) => write!(f, "sealed under unknown key id {id}"),
            SealError::Authentication => write!(f, "sealed value failed authentication"),
        }
    }
}

/// The module's data key, zeroized on drop.
pub(crate) struct SealKey {
    id: u8,
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

impl SealKey {
    /// Parses `LINKEDIN_TOKEN_KEY` (standard or URL-safe base64, padded or
    /// not) and the optional `LINKEDIN_TOKEN_KEY_ID`.
    pub(crate) fn from_config(encoded: &str, id: u8) -> Result<Self, SealError> {
        let raw = decode_key(encoded).ok_or(SealError::Key)?;
        let bytes: [u8; KEY_LEN] = raw.as_slice().try_into().map_err(|_| SealError::Key)?;
        Ok(Self {
            id,
            bytes: Zeroizing::new(bytes),
        })
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let key = Key::try_from(self.bytes.as_slice()).expect("key is 32 bytes by construction");
        XChaCha20Poly1305::new(&key)
    }
}

/// Accepts either base64 alphabet, with or without padding, so an operator
/// pasting from `openssl rand -base64 32` or from `head -c 32 | base64url`
/// gets the same key rather than a confusing config error.
/// One base64 alphabet's decoder.
type Decoder = dyn Fn(&str) -> Option<Vec<u8>>;

fn decode_key(encoded: &str) -> Option<Vec<u8>> {
    let trimmed = encoded.trim();
    let engines: [&Decoder; 4] = [
        &|s| base64::engine::general_purpose::STANDARD.decode(s).ok(),
        &|s| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(s)
                .ok()
        },
        &|s| base64::engine::general_purpose::URL_SAFE.decode(s).ok(),
        &|s| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .ok()
        },
    ];
    engines.iter().find_map(|decode| decode(trimmed))
}

/// The AAD for one column of one row: `linkedin/<table>/<row id>/<column>`.
pub(crate) fn context(table: &str, row_id: &str, column: &str) -> String {
    format!("linkedin/{table}/{row_id}/{column}")
}

/// Seals `plaintext`, returning `base64url(version || key id || nonce || ct)`.
pub(crate) fn seal(key: &SealKey, aad: &str, plaintext: &str) -> Result<String, SealError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| SealError::Random)?;
    let nonce = XNonce::try_from(&nonce_bytes[..]).map_err(|_| SealError::Random)?;
    let ciphertext = key
        .cipher()
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| SealError::Authentication)?;

    let mut blob = Vec::with_capacity(2 + NONCE_LEN + ciphertext.len());
    blob.push(VERSION);
    blob.push(key.id);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob))
}

/// Opens a sealed value. The plaintext is zeroized when dropped, so callers
/// hold it for exactly as long as the request needs it.
pub(crate) fn open(key: &SealKey, aad: &str, sealed: &str) -> Result<Zeroizing<String>, SealError> {
    let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sealed.trim())
        .map_err(|_| SealError::Malformed)?;
    if blob.len() < 2 + NONCE_LEN + 16 {
        return Err(SealError::Malformed);
    }
    if blob[0] != VERSION {
        return Err(SealError::Malformed);
    }
    if blob[1] != key.id {
        return Err(SealError::UnknownKeyId(blob[1]));
    }
    let nonce = XNonce::try_from(&blob[2..2 + NONCE_LEN]).map_err(|_| SealError::Malformed)?;
    let plaintext = key
        .cipher()
        .decrypt(
            &nonce,
            Payload {
                msg: &blob[2 + NONCE_LEN..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| SealError::Authentication)?;
    let text = String::from_utf8(plaintext).map_err(|_| SealError::Malformed)?;
    Ok(Zeroizing::new(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    fn key(id: u8) -> SealKey {
        SealKey::from_config(KEY, id).expect("32-byte key")
    }

    #[test]
    fn round_trips() {
        let key = key(1);
        let aad = context("linkedin_accounts", "acc_1", "access_token");
        let sealed = seal(&key, &aad, "AQXNnd2kXITHELmWblJigb").expect("seals");
        assert_eq!(
            &*open(&key, &aad, &sealed).expect("opens"),
            "AQXNnd2kXITHELmWblJigb"
        );
    }

    #[test]
    fn a_ciphertext_cannot_move_between_columns_or_rows() {
        let key = key(1);
        let access = context("linkedin_accounts", "acc_1", "access_token");
        let refresh = context("linkedin_accounts", "acc_1", "refresh_token");
        let other_row = context("linkedin_accounts", "acc_2", "access_token");
        let sealed = seal(&key, &access, "secret").expect("seals");
        assert_eq!(
            open(&key, &refresh, &sealed),
            Err(SealError::Authentication)
        );
        assert_eq!(
            open(&key, &other_row, &sealed),
            Err(SealError::Authentication)
        );
    }

    #[test]
    fn tampering_is_caught() {
        let key = key(1);
        let aad = context("linkedin_accounts", "acc_1", "access_token");
        let sealed = seal(&key, &aad, "secret").expect("seals");
        let mut blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&sealed)
            .expect("base64");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let tampered = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob);
        assert_eq!(open(&key, &aad, &tampered), Err(SealError::Authentication));
    }

    #[test]
    fn a_blob_from_another_key_id_is_named_not_guessed() {
        let aad = context("linkedin_accounts", "acc_1", "access_token");
        let sealed = seal(&key(1), &aad, "secret").expect("seals");
        assert_eq!(
            open(&key(2), &aad, &sealed),
            Err(SealError::UnknownKeyId(1))
        );
    }

    #[test]
    fn nonces_are_never_reused() {
        let key = key(1);
        let aad = context("linkedin_accounts", "acc_1", "access_token");
        let first = seal(&key, &aad, "secret").expect("seals");
        let second = seal(&key, &aad, "secret").expect("seals");
        assert_ne!(first, second, "same plaintext sealed to the same bytes");
    }

    #[test]
    fn malformed_input_never_panics() {
        let key = key(1);
        let aad = context("linkedin_accounts", "acc_1", "access_token");
        for bad in ["", "!!!!", "AAAA", &"A".repeat(200)] {
            assert!(open(&key, &aad, bad).is_err());
        }
    }

    #[test]
    fn key_accepts_either_base64_alphabet() {
        assert!(SealKey::from_config(KEY, 1).is_ok());
        assert!(SealKey::from_config(KEY.trim_end_matches('='), 1).is_ok());
        assert!(SealKey::from_config("too short", 1).is_err());
        assert!(SealKey::from_config("", 1).is_err());
    }
}
