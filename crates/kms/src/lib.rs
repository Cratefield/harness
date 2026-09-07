//! `factory0-kms` — the KMS port (issue #40, ADR 0102,
//! `docs/SECRETS-DESIGN.md`).
//!
//! Wrapping and unwrapping a data key is the **only** thing the KMS does
//! for us, so it is the only thing this trait can ask. Everything else —
//! which cipher seals a secret, what binds a ciphertext to its row, where
//! the wrapped key is stored — belongs to the envelope layer (#39) and to
//! the database, never to the vendor.
//!
//! The provider name and key reference travel with every wrapped key, so
//! changing vendor is a re-wrap job rather than a schema change.
//!
//! ```no_run
//! # use factory0_kms::{Kms, LocalFileKms, Dek};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let kms = LocalFileKms::open("/run/secrets/fz-kek", "development")?;
//! let dek = Dek::generate()?;
//! let wrapped = kms.wrap(&dek).await?;
//! let same = kms.unwrap(&wrapped).await?;
//! assert_eq!(dek.expose(), same.expose());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod local;

use async_trait::async_trait;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub use local::LocalFileKms;

/// A 256-bit data key. Zeroised on drop, never `Debug`-printed, never
/// `Clone`d: a key that can be copied is a key that can be left behind.
pub struct Dek(Zeroizing<Vec<u8>>);

/// The only size this port deals in (ADR 0102).
pub const DEK_LEN: usize = 32;

impl Dek {
    /// A fresh key from the OS RNG.
    ///
    /// # Errors
    ///
    /// [`KmsError::Unavailable`] when the OS RNG will not answer, which
    /// is not a condition worth continuing through.
    pub fn generate() -> Result<Self, KmsError> {
        let mut bytes = vec![0_u8; DEK_LEN];
        getrandom::fill(&mut bytes).map_err(|err| {
            bytes.zeroize();
            KmsError::Unavailable(format!("the OS random source failed: {err}"))
        })?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Adopts key material the caller already holds (an unwrap result, a
    /// key read from a file).
    ///
    /// # Errors
    ///
    /// [`KmsError::Invalid`] unless the material is exactly [`DEK_LEN`].
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, KmsError> {
        if bytes.len() != DEK_LEN {
            let mut bytes = bytes;
            bytes.zeroize();
            return Err(KmsError::Invalid(format!("a data key is {DEK_LEN} bytes")));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// The key material. Named `expose` so a reader has to notice.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek([redacted])")
    }
}

/// Why a wrap or unwrap did not happen. The split that matters
/// operationally is **unavailable** (retry, alarm on duration) against
/// **denied** (do not retry, alarm immediately): they want different
/// alarms and different retry behaviour, and a single opaque error makes
/// a permissions mistake look like an outage for as long as it takes
/// someone to read the logs.
#[derive(Debug, Error)]
pub enum KmsError {
    /// The KMS could not be reached, or answered that it is unwell.
    /// Retryable.
    #[error("the KMS is unavailable: {0}")]
    Unavailable(String),
    /// The KMS was reached and refused: no permission on the key, or the
    /// key is disabled. Not retryable; a human has to change something.
    #[error("the KMS denied the request: {0}")]
    Denied(String),
    /// The wrapped key did not authenticate: it was truncated, altered,
    /// or wrapped under a different master key. Never retryable, and
    /// never a reason to fall back to anything.
    #[error("the wrapped key failed authentication: {0}")]
    Tampered(String),
    /// The caller passed something this port cannot accept.
    #[error("invalid input: {0}")]
    Invalid(String),
    /// The provider refuses to run in this configuration.
    #[error("{0}")]
    Refused(String),
}

impl KmsError {
    /// Whether a retry could plausibly succeed without anyone
    /// intervening. Retry policy lives with the caller; this is the fact
    /// it needs.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, KmsError::Unavailable(_))
    }
}

/// Wrap and unwrap a data key under a master key that never leaves the
/// KMS.
///
/// Implementations must not log key material, must not fall back to any
/// other key on failure, and must map vendor errors onto
/// [`KmsError::Unavailable`] and [`KmsError::Denied`] rather than
/// collapsing them.
#[async_trait]
pub trait Kms: Send + Sync {
    /// Stored with every wrapped key: `"local-file"`, `"aws-kms"`,
    /// `"gcp-kms"`.
    fn provider(&self) -> &'static str;

    /// The master key this instance wraps under, as the vendor names it.
    /// Stored with every wrapped key so a re-wrap knows what it is
    /// moving from.
    fn key_ref(&self) -> &str;

    /// Wraps a data key. The result is opaque to the caller and is what
    /// goes in the database (`docs/SECRETS-DESIGN.md` §3).
    ///
    /// # Errors
    ///
    /// [`KmsError`], with `Unavailable` and `Denied` distinguished.
    async fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, KmsError>;

    /// Unwraps what [`Kms::wrap`] produced.
    ///
    /// # Errors
    ///
    /// [`KmsError::Tampered`] when the wrapped key does not
    /// authenticate, and otherwise as [`Kms::wrap`].
    async fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, KmsError>;
}

/// The conformance every provider passes (issue #40). Kept in the crate
/// rather than in one provider's tests so a new vendor is one call away
/// from being held to the same behaviour.
///
/// Checks the round trip, that two wraps of one key differ (a fresh
/// nonce per wrap, so a wrapped blob is not a stable identifier), that
/// every single-bit change to the wrapped blob is refused as
/// [`KmsError::Tampered`], and that a truncated or empty blob is refused
/// rather than panicking.
///
/// # Panics
///
/// With a message naming the property that failed.
pub async fn conformance(kms: &dyn Kms) {
    assert!(
        !kms.provider().is_empty(),
        "a provider name is stored with every wrapped key; it cannot be empty"
    );
    assert!(!kms.key_ref().is_empty(), "a key reference cannot be empty");

    let dek = Dek::generate().expect("the OS RNG answers");
    let wrapped = kms.wrap(&dek).await.expect("wrap succeeds");
    let recovered = kms.unwrap(&wrapped).await.expect("unwrap succeeds");
    assert_eq!(
        dek.expose(),
        recovered.expose(),
        "unwrap must return the key that was wrapped"
    );

    let again = kms.wrap(&dek).await.expect("wrap succeeds twice");
    assert_ne!(
        wrapped, again,
        "each wrap uses a fresh nonce, so a wrapped key is not a stable identifier"
    );
    let recovered = kms.unwrap(&again).await.expect("the second wrap unwraps");
    assert_eq!(dek.expose(), recovered.expose());

    // Every byte is covered by the tag, including whatever framing the
    // provider adds. A provider that authenticates only part of its blob
    // fails here rather than in production.
    for index in 0..wrapped.len() {
        let mut altered = wrapped.clone();
        altered[index] ^= 0b0000_0001;
        match kms.unwrap(&altered).await {
            Err(KmsError::Tampered(_)) => {}
            Err(other) => panic!("a flipped bit at {index} must be Tampered, got {other}"),
            Ok(_) => panic!("a flipped bit at {index} was accepted"),
        }
    }

    for (what, blob) in [
        ("empty", Vec::new()),
        ("truncated", wrapped[..wrapped.len() / 2].to_vec()),
        ("one byte", vec![0]),
    ] {
        match kms.unwrap(&blob).await {
            Err(KmsError::Tampered(_) | KmsError::Invalid(_)) => {}
            Err(other) => panic!("a {what} blob must be refused cleanly, got {other}"),
            Ok(_) => panic!("a {what} blob was accepted"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dek_does_not_print_its_material() {
        let dek = Dek::from_bytes(vec![7; DEK_LEN]).expect("32 bytes");
        let shown = format!("{dek:?}");
        assert_eq!(shown, "Dek([redacted])");
        assert!(!shown.contains('7'), "{shown}");
    }

    #[test]
    fn a_dek_is_exactly_32_bytes() {
        assert!(Dek::from_bytes(vec![0; 31]).is_err());
        assert!(Dek::from_bytes(vec![0; 33]).is_err());
        assert!(Dek::from_bytes(vec![0; DEK_LEN]).is_ok());
        assert_eq!(Dek::generate().expect("rng").expose().len(), DEK_LEN);
    }

    #[test]
    fn only_unavailable_is_retryable() {
        assert!(KmsError::Unavailable("x".into()).is_retryable());
        for error in [
            KmsError::Denied("x".into()),
            KmsError::Tampered("x".into()),
            KmsError::Invalid("x".into()),
            KmsError::Refused("x".into()),
        ] {
            assert!(!error.is_retryable(), "{error} must not be retried");
        }
    }
}
