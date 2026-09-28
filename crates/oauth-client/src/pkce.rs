//! PKCE (RFC 7636) and the `state` parameter: the two single-use values an
//! authorization request carries, and the two things that must be fresh
//! every time.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// The OS refused randomness. A verifier or a state that is not fresh is
/// worth exactly nothing, so this is an error and never a fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("no randomness available")]
pub struct RandomError;

/// An S256 proof-key pair (RFC 7636 §4): a verifier kept for the token
/// exchange and the challenge derived from it for the authorize URL.
///
/// The verifier is base64url of 32 random bytes — 43 characters, the
/// length RFC 7636 §4.1 sets as the floor — and is zeroized when dropped.
pub struct Pkce {
    verifier: Zeroizing<String>,
    challenge: String,
}

impl Pkce {
    /// A fresh pair. Fails only when randomness does.
    ///
    /// # Errors
    ///
    /// Returns [`RandomError`] when the platform cannot provide randomness,
    /// which on wasm means the JS backend was wired wrong: refuse rather
    /// than authorize with a predictable verifier.
    pub fn new() -> Result<Self, RandomError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| RandomError)?;
        let verifier =
            Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
        Ok(Self {
            challenge: challenge_of(&verifier),
            verifier,
        })
    }

    /// The secret half, sent to the token endpoint with the code.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The public half, sent on the authorize URL.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

/// The S256 challenge for a verifier (RFC 7636 §4.2): base64url of the
/// SHA-256 of the verifier, no padding.
fn challenge_of(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A fresh opaque `state` (RFC 6749 §10.12): base64url of 16 random bytes.
/// Whatever else a caller binds to the state — a signed token, a database
/// row — freshness starts here.
///
/// # Errors
///
/// Returns [`RandomError`] when randomness is unavailable.
pub fn random_state() -> Result<String, RandomError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| RandomError)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B, the one worked vector the RFC ships: 32 octets,
    /// their base64url verifier, and the challenge the RFC names for it.
    #[test]
    fn the_s256_challenge_matches_rfc_7636_appendix_b() {
        // [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216,
        //  173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5,
        //  88, 83, 132, 141, 121]
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge_of(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_fresh_pair_has_the_minimum_length_and_matches_itself() {
        let pkce = Pkce::new().expect("randomness");
        assert_eq!(pkce.verifier().len(), 43, "32 bytes of base64url");
        assert_eq!(challenge_of(pkce.verifier()), pkce.challenge());
    }

    #[test]
    fn pairs_are_never_reused() {
        let first = Pkce::new().expect("randomness");
        let second = Pkce::new().expect("randomness");
        assert_ne!(first.verifier(), second.verifier());
    }

    #[test]
    fn states_are_fresh_too() {
        assert_ne!(
            random_state().expect("randomness"),
            random_state().expect("randomness")
        );
        assert_eq!(
            random_state().expect("randomness").len(),
            22,
            "16 bytes of base64url"
        );
    }
}
