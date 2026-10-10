//! The `KeySigner` port: create a key, describe it, sign with it. The
//! trait's shape is the no-export guarantee — there is no method that
//! can return private key material, so no implementation reachable
//! through this trait can be asked for one.

use async_trait::async_trait;
use thiserror::Error;

use crate::keys::{KeyInfo, KeyRef, Scheme, Signature, Subject};
use crate::payload::Payload;

/// Signs by key reference. Implementations mint keys and keep them; the
/// caller only ever holds a [`KeyRef`] and a public [`KeyInfo`].
///
/// All three methods are async, `Send + Sync` and object-safe, so a
/// provider travels as `Arc<dyn KeySigner>` the way every port in this
/// workspace does.
#[async_trait]
pub trait KeySigner: Send + Sync {
    /// Mints a fresh key for `subject` on `scheme`, labelled `label`,
    /// and returns its public description. The label is what shows up in
    /// listings; the reference is the provider's.
    ///
    /// # Errors
    ///
    /// [`SignerError`] — [`Invalid`](SignerError::Invalid) for names a
    /// provider refuses, [`Provider`](SignerError::Provider) when the
    /// key cannot be minted or stored.
    async fn create_key(
        &self,
        subject: &Subject,
        scheme: Scheme,
        label: &str,
    ) -> Result<KeyInfo, SignerError>;

    /// The public description of `key_ref`.
    ///
    /// # Errors
    ///
    /// [`SignerError::UnknownKey`] when the reference names nothing.
    async fn key(&self, key_ref: &KeyRef) -> Result<KeyInfo, SignerError>;

    /// Signs `payload` with `key_ref`. Which digest the signature is
    /// over is the payload's business — the implementation calls
    /// [`Payload::payload_hash`], it does not trust a caller-supplied
    /// digest.
    ///
    /// # Errors
    ///
    /// [`SignerError::UnknownKey`] when the reference names nothing,
    /// [`SignerError::Unsupported`] when the key's scheme cannot sign
    /// this payload kind, [`SignerError::Payload`] when the payload does
    /// not hash.
    async fn sign(&self, key_ref: &KeyRef, payload: &Payload) -> Result<Signature, SignerError>;
}

#[async_trait]
impl<T: KeySigner + ?Sized> KeySigner for &T {
    async fn create_key(
        &self,
        subject: &Subject,
        scheme: Scheme,
        label: &str,
    ) -> Result<KeyInfo, SignerError> {
        (**self).create_key(subject, scheme, label).await
    }

    async fn key(&self, key_ref: &KeyRef) -> Result<KeyInfo, SignerError> {
        (**self).key(key_ref).await
    }

    async fn sign(&self, key_ref: &KeyRef, payload: &Payload) -> Result<Signature, SignerError> {
        (**self).sign(key_ref, payload).await
    }
}

/// What signing can go wrong with. The variants are the vocabulary the
/// audit chain and the guardrails reason about, which is why `Denied`
/// and `UnknownKey` carry structured fields instead of prose.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignerError {
    /// The policy said no, and said why.
    #[error("the policy denied this signature: {reason}")]
    Denied {
        /// What the guardrails were unwilling to allow.
        reason: String,
    },
    /// The key reference names nothing this provider holds.
    #[error("unknown key `{key_ref}`")]
    UnknownKey {
        /// The reference that named nothing.
        key_ref: String,
    },
    /// The key and the payload do not fit each other (an ed25519 key
    /// asked to sign an EVM transaction), or the provider cannot serve
    /// this payload kind at all.
    #[error("unsupported: {reason}")]
    Unsupported {
        /// What does not fit.
        reason: String,
    },
    /// A name, address or reference was malformed on its face.
    #[error("invalid input: {0}")]
    Invalid(String),
    /// The payload could not be hashed or decoded into an intent.
    #[error("the payload could not be processed: {0}")]
    Payload(String),
    /// The provider itself failed — storage refused, the curve
    /// rejected a signature request.
    #[error("the signer provider failed: {0}")]
    Provider(String),
    /// The audit trail refused the record, so the signature did not
    /// happen: this crate fails closed (issue #761).
    #[error("the audit trail refused, so the signature did not happen: {0}")]
    Audit(String),
}
