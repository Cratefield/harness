//! Sealing OAuth tokens at rest.
//!
//! [`TokenSealer`] is the seam: a module seals with the implementation it is
//! handed, so moving storage to the secrets store (Cratefield/harness #24)
//! later is a swap of implementations, not a rewrite. [`XChaChaSealer`] is
//! what the harness already chose (ADR 0102): XChaCha20-Poly1305, a fresh
//! 24-byte random nonce per encryption, `zeroize` on the key material.
//!
//! The AAD ([`SealContext`]) binds a ciphertext to the row and the column it
//! belongs to, so an access-token ciphertext cannot be moved into the
//! refresh-token column, and a blob from one account cannot be replayed into
//! another. The blob carries a version and a key id, because the stored
//! format is what has to migrate: the key id handles ordinary rotation, the
//! version only ever a layout change.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{Key, KeyInit as _, XChaCha20Poly1305, XNonce};
use thiserror::Error;
use zeroize::Zeroizing;

/// The length in bytes of the key [`XChaChaSealer`] takes. Exported so a
/// caller's config validation can name it.
pub const KEY_LEN: usize = 32;

/// Blob layout version. Bumped only if the layout changes; the key id
/// handles ordinary rotation.
const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// Where a sealed value belongs: one column of one row of one namespace.
/// Rendered to the additional authenticated data as
/// `"{namespace}/{table}/{row_id}/{column}"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealContext<'a> {
    /// Who is sealing: a module, an adapter, the secrets store itself.
    pub namespace: &'a str,
    /// The table the value belongs to.
    pub table: &'a str,
    /// The row the value belongs to.
    pub row_id: &'a str,
    /// The column the value belongs to.
    pub column: &'a str,
}

impl SealContext<'_> {
    /// The additional authenticated data the ciphertext is bound to. A blob
    /// sealed for one context opens nowhere else — that is the point of it.
    #[must_use]
    pub fn aad(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.namespace, self.table, self.row_id, self.column
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SealError {
    /// The configured key is not [`KEY_LEN`] bytes of base64.
    #[error("the seal key is not 32 bytes of base64")]
    Key,
    /// The OS refused randomness. Never seal without a fresh nonce.
    #[error("no randomness available for a nonce")]
    Random,
    /// The stored blob is truncated, not base64, or a version we do not know.
    #[error("sealed value is malformed")]
    Malformed,
    /// The blob was sealed under a different key id than the one configured.
    #[error("sealed under unknown key id {0}")]
    UnknownKeyId(u8),
    /// Authentication failed: wrong key, wrong AAD, or tampering.
    #[error("sealed value failed authentication")]
    Authentication,
}

/// Stores OAuth tokens as opaque strings. Whatever the implementation, the
/// ciphertext is bound to the [`SealContext`] it was sealed for.
pub trait TokenSealer: Send + Sync {
    /// Seals `plaintext` for `context`, into an opaque stored form.
    ///
    /// # Errors
    ///
    /// Implementation-specific: no randomness, an unusable key.
    fn seal(&self, plaintext: &str, context: &SealContext<'_>) -> Result<String, SealError>;

    /// Opens a stored form sealed for `context`.
    ///
    /// # Errors
    ///
    /// Implementation-specific: malformed blob, unknown key id, failed
    /// authentication (wrong key, wrong context, tampering).
    fn open(&self, sealed: &str, context: &SealContext<'_>)
    -> Result<Zeroizing<String>, SealError>;
}

/// The default [`TokenSealer`]: XChaCha20-Poly1305 under one key, writing
/// `base64url(version || key id || nonce || ciphertext)`.
pub struct XChaChaSealer {
    id: u8,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl XChaChaSealer {
    /// Parses an encoded key (standard or URL-safe base64, padded or not, so
    /// an operator pasting from `openssl rand -base64 32` or from
    /// `head -c 32 | base64url` gets the same key) and its id.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Key`] when `encoded` is not [`KEY_LEN`] bytes of
    /// base64.
    pub fn from_base64_key(encoded: &str, id: u8) -> Result<Self, SealError> {
        let trimmed = encoded.trim();
        let raw = [
            base64::engine::general_purpose::STANDARD,
            base64::engine::general_purpose::STANDARD_NO_PAD,
            base64::engine::general_purpose::URL_SAFE,
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ]
        .iter()
        .find_map(|engine| engine.decode(trimmed).ok())
        .ok_or(SealError::Key)?;
        let key: [u8; KEY_LEN] = raw.as_slice().try_into().map_err(|_| SealError::Key)?;
        Ok(Self {
            id,
            key: Zeroizing::new(key),
        })
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let key = Key::try_from(self.key.as_slice()).expect("key is 32 bytes by construction");
        XChaCha20Poly1305::new(&key)
    }
}

impl TokenSealer for XChaChaSealer {
    fn seal(&self, plaintext: &str, context: &SealContext<'_>) -> Result<String, SealError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|_| SealError::Random)?;
        let nonce = XNonce::try_from(&nonce_bytes[..]).map_err(|_| SealError::Random)?;
        let aad = context.aad();
        let ciphertext = self
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
        blob.push(self.id);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob))
    }

    fn open(
        &self,
        sealed: &str,
        context: &SealContext<'_>,
    ) -> Result<Zeroizing<String>, SealError> {
        let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sealed.trim())
            .map_err(|_| SealError::Malformed)?;
        if blob.len() < 2 + NONCE_LEN + TAG_LEN {
            return Err(SealError::Malformed);
        }
        if blob[0] != VERSION {
            return Err(SealError::Malformed);
        }
        if blob[1] != self.id {
            return Err(SealError::UnknownKeyId(blob[1]));
        }
        let nonce = XNonce::try_from(&blob[2..2 + NONCE_LEN]).map_err(|_| SealError::Malformed)?;
        let aad = context.aad();
        let plaintext = self
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    const AAD: SealContext<'static> = SealContext {
        namespace: "linkedin",
        table: "linkedin_accounts",
        row_id: "acc_1",
        column: "access_token",
    };

    fn key(id: u8) -> XChaChaSealer {
        XChaChaSealer::from_base64_key(KEY, id).expect("32-byte key")
    }

    #[test]
    fn round_trips() {
        let key = key(1);
        let stored = key.seal("AQXNnd2kXITHELmWblJigb", &AAD).expect("seals");
        assert_eq!(
            &*key.open(&stored, &AAD).expect("opens"),
            "AQXNnd2kXITHELmWblJigb"
        );
    }

    #[test]
    fn a_ciphertext_cannot_move_between_columns_or_rows() {
        let key = key(1);
        let stored = key.seal("secret", &AAD).expect("seals");
        let refresh_column = SealContext {
            column: "refresh_token",
            ..AAD
        };
        let other_row = SealContext {
            row_id: "acc_2",
            ..AAD
        };
        assert_eq!(
            key.open(&stored, &refresh_column),
            Err(SealError::Authentication)
        );
        assert_eq!(
            key.open(&stored, &other_row),
            Err(SealError::Authentication)
        );
    }

    #[test]
    fn tampering_is_caught() {
        let key = key(1);
        let stored = key.seal("secret", &AAD).expect("seals");
        let mut blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&stored)
            .expect("base64");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let tampered = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob);
        assert_eq!(key.open(&tampered, &AAD), Err(SealError::Authentication));
    }

    #[test]
    fn a_blob_from_another_key_id_is_named_not_guessed() {
        let stored = key(1).seal("secret", &AAD).expect("seals");
        assert_eq!(key(2).open(&stored, &AAD), Err(SealError::UnknownKeyId(1)));
    }

    /// The stored format, pinned: `version(1) || key id || nonce(24) || ct`,
    /// base64url. Everything downstream of a key rotation reads bytes this
    /// test would have caught.
    #[test]
    fn the_blob_layout_is_version_keyid_nonce_ciphertext() {
        let key = key(7);
        let stored = key.seal("secret", &AAD).expect("seals");
        let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&stored)
            .expect("base64");
        assert_eq!(blob[0], 1, "version");
        assert_eq!(blob[1], 7, "key id");
        assert_eq!(blob.len(), 2 + NONCE_LEN + "secret".len() + TAG_LEN);
        assert_eq!(&*key.open(&stored, &AAD).expect("opens"), "secret");
    }

    #[test]
    fn nonces_are_never_reused() {
        let sealer = key(1);
        let first = sealer.seal("secret", &AAD).expect("seals");
        let second = sealer.seal("secret", &AAD).expect("seals");
        assert_ne!(first, second, "same plaintext sealed to the same bytes");
    }

    #[test]
    fn malformed_input_never_panics() {
        let sealer = key(1);
        for bad in ["", "!!!!", "AAAA", &"A".repeat(200)] {
            assert_eq!(sealer.open(bad, &AAD), Err(SealError::Malformed));
        }
    }

    #[test]
    fn keys_are_accepted_in_either_base64_alphabet() {
        assert!(XChaChaSealer::from_base64_key(KEY, 1).is_ok());
        assert!(XChaChaSealer::from_base64_key(KEY.trim_end_matches('='), 1).is_ok());
        assert!(XChaChaSealer::from_base64_key("too short", 1).is_err());
        assert!(XChaChaSealer::from_base64_key("", 1).is_err());
    }

    /// The AAD is what makes a blob immovable, so its rendering is pinned:
    /// existing sealed rows were sealed against exactly this string.
    #[test]
    fn the_aad_renders_namespace_table_row_column() {
        assert_eq!(AAD.aad(), "linkedin/linkedin_accounts/acc_1/access_token");
    }
}
