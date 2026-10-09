//! The `SecretsSigner`: a [`KeySigner`] that keeps its keys in the
//! Secrets port. A key is 32 random bytes, sealed into the subject's
//! tenant store under a name that is also its [`KeyRef`]; `sign` is the
//! only place that unseals one, into a `Zeroizing` buffer that never
//! leaves the call.
//!
//! **Session keys only.** This provider mints keys from the OS RNG and
//! has no import API: an owner key — the key that controls a wallet —
//! has no business living in a tenant database, and there is no way to
//! put one here. [`KeyRole::Session`] is on
//! every `KeyInfo` this returns, and deleting the secret behind a
//! reference revokes the key.

use std::sync::Arc;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::crypto;
use crate::keys::{KeyInfo, KeyRef, KeyRole, Scheme, Signature, Subject};
use crate::payload::Payload;
use crate::port::KeySigner;
use crate::port::SignerError;

/// Signs with keys held behind [`SecretStore`](cratefield_secrets::SecretStore).
/// One instance serves one store (one tenant).
pub struct SecretsSigner {
    store: Arc<cratefield_secrets::SecretStore>,
    actor: cratefield_secrets::Actor,
}

impl SecretsSigner {
    /// Signs against `store`, attributing every secret access to
    /// `actor` — the Secrets port has no anonymous access, and neither
    /// does signing through it.
    #[must_use]
    pub fn new(
        store: Arc<cratefield_secrets::SecretStore>,
        actor: cratefield_secrets::Actor,
    ) -> Self {
        Self { store, actor }
    }

    /// The store name a key lives under: `session/{scheme}/{venture}
    /// [/{user}]/{label}/{suffix}` — provider-scoped by its first
    /// component, self-describing by scheme, unique by an eight-byte
    /// suffix derived from the key itself.
    fn name_for(
        subject: &Subject,
        scheme: Scheme,
        label: &str,
        suffix: &str,
    ) -> Result<String, SignerError> {
        crypto::valid_component(&subject.venture)?;
        crypto::valid_component(label)?;
        crypto::valid_component(suffix)?;
        let venture = &subject.venture;
        let head = match &subject.user {
            Some(user) => {
                crypto::valid_component(user)?;
                format!("session/{scheme}/{venture}/{user}/{label}")
            }
            None => format!("session/{scheme}/{venture}/{label}"),
        };
        Ok(format!("{head}/{suffix}"))
    }

    /// Unseals the 32 bytes behind `key_ref`. This is the only place in
    /// the crate a private key spends time in memory.
    async fn unseal(&self, key_ref: &KeyRef) -> Result<Zeroizing<[u8; 32]>, SignerError> {
        let sealed = self
            .store
            .get(key_ref.as_str(), &self.actor)
            .await
            .map_err(|err| SignerError::Provider(format!("the secrets store refused: {err}")))?
            .ok_or_else(|| SignerError::UnknownKey {
                key_ref: key_ref.to_string(),
            })?;
        let seed = Zeroizing::new(<[u8; 32]>::try_from(sealed.expose()).map_err(|_| {
            SignerError::Provider(format!(
                "the key behind `{key_ref}` is {} bytes, not the 32 this provider stores",
                sealed.expose().len()
            ))
        })?);
        Ok(seed)
    }

    fn scheme_of_seed(seed: &[u8; 32], scheme: Scheme) -> Result<String, SignerError> {
        match scheme {
            Scheme::Secp256k1 => crypto::secp256k1_address(seed),
            Scheme::Ed25519 => Ok(crypto::ed25519_pubkey(seed)),
        }
    }

    /// Signs, with the scheme/payload pairing already checked by `sign`.
    fn sign_with_scheme(
        seed: &[u8; 32],
        scheme: Scheme,
        payload: &Payload,
    ) -> Result<Signature, SignerError> {
        match (scheme, payload) {
            (Scheme::Secp256k1, payload) => {
                let prehash = payload.payload_hash()?;
                let (signature, recovery_id) = crypto::sign_secp256k1(seed, &prehash)?;
                let (r, s) = crypto::split(signature);
                Ok(Signature::Secp256k1 {
                    r,
                    s,
                    v: crypto::v_of(recovery_id),
                })
            }
            (Scheme::Ed25519, Payload::SolanaMessage(message)) => Ok(Signature::Ed25519 {
                bytes: crypto::sign_ed25519(seed, &message.0),
            }),
            (Scheme::Ed25519, _) => Err(SignerError::Unsupported {
                reason: "an ed25519 session key signs Solana messages here".to_owned(),
            }),
        }
    }
}

#[async_trait]
impl KeySigner for SecretsSigner {
    async fn create_key(
        &self,
        subject: &Subject,
        scheme: Scheme,
        label: &str,
    ) -> Result<KeyInfo, SignerError> {
        // The seed is the key. It exists in the clear exactly once, in
        // this zeroising buffer, on the way into the store.
        let seed = crypto::random_seed()?;
        let mut suffix_material = Zeroizing::new([0_u8; 39]);
        suffix_material[..32].copy_from_slice(seed.as_ref());
        suffix_material[32..].copy_from_slice(b"key-ref");
        let suffix_seed = crypto::sha256(suffix_material.as_ref());
        let suffix = hex::encode(&suffix_seed[..8]);

        let name = Self::name_for(subject, scheme, label, &suffix)?;
        self.store
            .put(
                &name,
                &cratefield_secrets::SecretBytes::new(seed.to_vec()),
                &self.actor,
            )
            .await
            .map_err(|err| SignerError::Provider(format!("the secrets store refused: {err}")))?;

        let info = KeyInfo {
            key_ref: KeyRef::new(name)?,
            scheme,
            role: KeyRole::Session,
            label: label.to_owned(),
            subject: subject.clone(),
            identity: Self::scheme_of_seed(&seed, scheme)?,
        };
        Ok(info)
    }

    async fn key(&self, key_ref: &KeyRef) -> Result<KeyInfo, SignerError> {
        // The store holds only ciphertext; the public half is derived
        // from the seed on the way out, and the seed goes with the call.
        let name = key_ref.as_str();
        let (scheme, label) = parse_name(name)?;
        let seed = self.unseal(key_ref).await?;
        Ok(KeyInfo {
            key_ref: key_ref.clone(),
            scheme,
            role: KeyRole::Session,
            label,
            subject: subject_from_name(name)?,
            identity: Self::scheme_of_seed(&seed, scheme)?,
        })
    }

    async fn sign(&self, key_ref: &KeyRef, payload: &Payload) -> Result<Signature, SignerError> {
        let name = key_ref.as_str();
        let (scheme, _) = parse_name(name)?;
        let seed = self.unseal(key_ref).await?;
        if payload.scheme() != scheme {
            return Err(SignerError::Unsupported {
                reason: format!(
                    "the key behind `{key_ref}` is a {scheme} key, and cannot sign {} payloads",
                    payload.scheme()
                ),
            });
        }
        Self::sign_with_scheme(&seed, scheme, payload)
    }
}

/// The scheme and label from a store name. The name is the key
/// reference, and it carries the scheme so a payload/key mismatch is
/// known before anything is unsealed.
fn parse_name(name: &str) -> Result<(Scheme, String), SignerError> {
    let parts: Vec<&str> = name.split('/').collect();
    match parts.as_slice() {
        [prefix, scheme, _venture, label, _suffix]
        | [prefix, scheme, _venture, _, label, _suffix]
            if *prefix == "session" =>
        {
            let scheme = match *scheme {
                "secp256k1" => Scheme::Secp256k1,
                "ed25519" => Scheme::Ed25519,
                other => {
                    return Err(SignerError::UnknownKey {
                        key_ref: format!("{name} (unknown scheme `{other}`)"),
                    });
                }
            };
            Ok((scheme, (*label).to_owned()))
        }
        _ => Err(SignerError::UnknownKey {
            key_ref: name.to_owned(),
        }),
    }
}

/// The subject from a store name — the identity the audit record needs,
/// carried in the reference itself.
fn subject_from_name(name: &str) -> Result<Subject, SignerError> {
    let parts: Vec<&str> = name.split('/').collect();
    match parts.as_slice() {
        ["session", _scheme, venture, _label, _suffix] => Subject::new((*venture).to_owned(), None),
        ["session", _scheme, venture, user, _label, _suffix] => {
            Subject::new((*venture).to_owned(), Some((*user).to_owned()))
        }
        _ => Err(SignerError::UnknownKey {
            key_ref: name.to_owned(),
        }),
    }
}
