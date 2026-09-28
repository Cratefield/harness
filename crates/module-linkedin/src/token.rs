//! Sealing OAuth tokens at rest (issue #8), over `cratefield-oauth-client`
//! (issue #531).
//!
//! The sealer is the crate's [`XChaChaSealer`], the primitive ADR 0102
//! chose: XChaCha20-Poly1305, a fresh 24-byte random nonce per encryption,
//! `zeroize` on the key material. What stays here is the module's own
//! configuration — the key from `LINKEDIN_TOKEN_KEY`, and the `linkedin`
//! namespace — because the AAD binds every ciphertext to this module's row
//! and column, and the sealed rows already in the database were sealed
//! under exactly that string.

use cratefield_oauth_client::{SealContext, SealError, TokenSealer as _, XChaChaSealer};
use zeroize::Zeroizing;

pub(crate) const KEY_LEN: usize = cratefield_oauth_client::KEY_LEN;

/// The AAD namespace every blob this module writes carries.
const NAMESPACE: &str = "linkedin";

/// The module's data key, zeroized on drop.
pub(crate) struct SealKey {
    inner: XChaChaSealer,
}

impl SealKey {
    /// Parses `LINKEDIN_TOKEN_KEY` (standard or URL-safe base64, padded or
    /// not) and the optional `LINKEDIN_TOKEN_KEY_ID`. The error names the
    /// variable an operator sets, not the crate's generic shape complaint.
    pub(crate) fn from_config(encoded: &str, id: u8) -> Result<Self, String> {
        XChaChaSealer::from_base64_key(encoded, id)
            .map(|inner| Self { inner })
            .map_err(|error| match error {
                SealError::Key => {
                    format!("LINKEDIN_TOKEN_KEY is not {KEY_LEN} bytes of base64")
                }
                other => other.to_string(),
            })
    }
}

/// The AAD for one column of one row: `linkedin/<table>/<row id>/<column>`.
pub(crate) fn context<'a>(table: &'a str, row_id: &'a str, column: &'a str) -> SealContext<'a> {
    SealContext {
        namespace: NAMESPACE,
        table,
        row_id,
        column,
    }
}

/// Seals `plaintext`, returning `base64url(version || key id || nonce || ct)`.
pub(crate) fn seal(
    key: &SealKey,
    aad: &SealContext<'_>,
    plaintext: &str,
) -> Result<String, SealError> {
    key.inner.seal(plaintext, aad)
}

/// Opens a sealed value. The plaintext is zeroized when dropped, so callers
/// hold it for exactly as long as the request needs it.
pub(crate) fn open(
    key: &SealKey,
    aad: &SealContext<'_>,
    sealed: &str,
) -> Result<Zeroizing<String>, SealError> {
    key.inner.open(sealed, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    /// The wiring this wrapper exists for: the crate's sealer under the
    /// module's key and namespace, round-tripping a token the way the store
    /// reads and writes them.
    #[test]
    fn round_trips_through_the_crate_sealer() {
        let key = SealKey::from_config(KEY, 1).expect("32-byte key");
        let aad = context("linkedin_accounts", "acc_1", "access_token");
        let sealed = seal(&key, &aad, "AQXNnd2kXITHELmWblJigb").expect("seals");
        assert_eq!(
            &*open(&key, &aad, &sealed).expect("opens"),
            "AQXNnd2kXITHELmWblJigb"
        );
        // A blob from another key id is named, not guessed.
        let other = SealKey::from_config(KEY, 2).expect("32-byte key");
        assert_eq!(open(&other, &aad, &sealed), Err(SealError::UnknownKeyId(1)));
    }

    /// The message an operator sees when the configured key does not parse
    /// names the variable they set.
    #[test]
    fn a_bad_key_is_named_for_the_operator() {
        // `expect_err` would need `SealKey: Debug`, which a key holder
        // should never have.
        let Err(error) = SealKey::from_config("too short", 1) else {
            panic!("a short key must not parse");
        };
        assert_eq!(
            error,
            format!("LINKEDIN_TOKEN_KEY is not {KEY_LEN} bytes of base64")
        );
    }
}
