//! The [`KeySigner`] port, over Turnkey: signing by key reference —
//! `turnkey/{venture}/{sub-organization}/{scheme}/{address}` — where the
//! address is the sub-organization wallet's account the payload belongs
//! to. The reference carries everything a signature needs, the way a
//! [`SecretsSigner`](cratefield_signer::SecretsSigner) store name does,
//! so `key()` is a parse, not a round trip.
//!
//! Two port realities this provider is explicit about:
//!
//! - `create_key` is [`SignerError::Unsupported`]. A Turnkey key is
//!   born with its owner's passkey at sub-organization creation, and
//!   the port's `create_key(subject, scheme, label)` cannot carry a
//!   passkey attestation; use
//!   [`create_sub_organization`](crate::TurnkeySigner::create_sub_organization)
//!   then [`key_ref`].
//! - No method wraps an export activity. Turnkey has
//!   `EXPORT_WALLET`/`EXPORT_PRIVATE_KEY`; nothing here constructs
//!   them — the port's shape is the guarantee, as in the port crate.
//!
//! An answer only becomes a [`Signature`] once it verifies against the
//! key reference's identity: a secp256k1 answer must recover to the
//! identity address over the digest we asked Turnkey to sign, and an
//! ed25519 answer must verify against the identity pubkey over the
//! exact message. An answer minted by another key, or over other
//! bytes, is a [`SignerError::Provider`] — never a signature.

use async_trait::async_trait;
use cratefield_signer::keys::{KeyInfo, KeyRef, KeyRole, Scheme, Signature, Subject};
use cratefield_signer::payload::Payload;
use cratefield_signer::port::{KeySigner, SignerError};

use crate::api::TurnkeySigner;

/// The reference prefix every key this provider names carries.
const REF_PREFIX: &str = "turnkey";

/// The `TRANSACTION_TYPE_ETHEREUM` value `sign_transaction` asks for.
const TRANSACTION_TYPE_ETHEREUM: &str = "TRANSACTION_TYPE_ETHEREUM";

/// Builds the [`KeyRef`] naming `sub_organization`'s wallet account
/// `identity` (a lowercase `0x` address or a base58 pubkey, per
/// `scheme`), for `venture`'s audit trail.
///
/// # Errors
///
/// [`SignerError::Invalid`] when the venture, sub-organization id or
/// identity does not carry its strict shape.
pub fn key_ref(
    venture: &str,
    sub_organization_id: &str,
    scheme: Scheme,
    identity: &str,
) -> Result<KeyRef, SignerError> {
    if venture.is_empty() || venture.len() > 64 {
        return Err(SignerError::Invalid("a venture is 1..=64 bytes".to_owned()));
    }
    crate::policy::validate_turnkey_id(sub_organization_id)?;
    let identity = match scheme {
        Scheme::Secp256k1 => crate::policy::validate_address(identity)?,
        Scheme::Ed25519 => crate::policy::validate_program_key(identity)?,
    };
    KeyRef::new(format!(
        "{REF_PREFIX}/{venture}/{sub_organization_id}/{scheme}/{identity}"
    ))
}

/// Splits a reference back into its parts. Anything not carrying the
/// exact shape — a `SecretsSigner` store name, a fake's reference, a
/// truncated path — is an [`SignerError::UnknownKey`]: this provider
/// does not hold it.
fn parse_key_ref(key_ref: &KeyRef) -> Result<(String, String, Scheme, String), SignerError> {
    let unknown = || SignerError::UnknownKey {
        key_ref: key_ref.to_string(),
    };
    let parts: Vec<&str> = key_ref.as_str().split('/').collect();
    let [prefix, venture, sub_organization_id, scheme, identity] = parts.as_slice() else {
        return Err(unknown());
    };
    if *prefix != REF_PREFIX {
        return Err(unknown());
    }
    let scheme = match *scheme {
        "secp256k1" => Scheme::Secp256k1,
        "ed25519" => Scheme::Ed25519,
        _ => return Err(unknown()),
    };
    Ok((
        (*venture).to_owned(),
        (*sub_organization_id).to_owned(),
        scheme,
        (*identity).to_owned(),
    ))
}

#[async_trait]
impl KeySigner for TurnkeySigner {
    async fn create_key(
        &self,
        _subject: &Subject,
        _scheme: Scheme,
        _label: &str,
    ) -> Result<KeyInfo, SignerError> {
        Err(SignerError::Unsupported {
            reason: "a Turnkey key is born with its user's passkey at sub-organization creation; \
                     use create_sub_organization and TurnkeySigner::key_ref"
                .to_owned(),
        })
    }

    async fn key(&self, key_ref: &KeyRef) -> Result<KeyInfo, SignerError> {
        let (venture, _sub_organization_id, scheme, identity) = parse_key_ref(key_ref)?;
        Ok(KeyInfo {
            key_ref: key_ref.clone(),
            scheme,
            role: KeyRole::Session,
            // The address is the human-facing name this key has.
            label: identity.clone(),
            subject: Subject::new(venture, None)?,
            identity,
        })
    }

    async fn sign(&self, key_ref: &KeyRef, payload: &Payload) -> Result<Signature, SignerError> {
        let (_venture, sub_organization_id, scheme, identity) = parse_key_ref(key_ref)?;
        if payload.scheme() != scheme {
            return Err(SignerError::Unsupported {
                reason: format!(
                    "the key behind `{key_ref}` is a {scheme} key, and cannot sign {} payloads",
                    payload.scheme()
                ),
            });
        }
        match payload {
            // A full transaction goes out as one: Turnkey parses it, and
            // `eth.tx.*` policies only bind on this activity.
            Payload::EvmTransaction(tx) => {
                let unsigned = crate::evm::unsigned_transaction(tx)?;
                let digest = payload.payload_hash()?;
                let signed = self
                    .sign_transaction(
                        &sub_organization_id,
                        &identity,
                        &format!("0x{}", hex::encode(&unsigned)),
                        TRANSACTION_TYPE_ETHEREUM,
                    )
                    .await?;
                let (r, s, v) = crate::evm::decode_signed(&signed)?;
                verify_secp256k1(&identity, &digest, &r, &s, v)?;
                Ok(Signature::Secp256k1 { r, s, v })
            }
            // A pre-hashed digest: no-op hash function, Turnkey signs
            // the 32 bytes as they are.
            Payload::UserOperation(_) | Payload::Eip712(_) => {
                let digest = payload.payload_hash()?;
                let (r, s, v) = self
                    .sign_raw_payload(
                        &sub_organization_id,
                        &identity,
                        &format!("0x{}", hex::encode(digest)),
                        "HASH_FUNCTION_NO_OP",
                    )
                    .await?;
                let (r, s, v) = raw_secp256k1(&r, &s, &v)?;
                verify_secp256k1(&identity, &digest, &r, &s, v)?;
                Ok(Signature::Secp256k1 { r, s, v })
            }
            // ed25519 hashes internally; RFC 8032 allows nothing else.
            Payload::SolanaMessage(message) => {
                let (r, s, _v) = self
                    .sign_raw_payload(
                        &sub_organization_id,
                        &identity,
                        &format!("0x{}", hex::encode(&message.0)),
                        "HASH_FUNCTION_NOT_APPLICABLE",
                    )
                    .await?;
                let mut bytes = [0_u8; 64];
                bytes[..32].copy_from_slice(&hex_word(&r, "r")?);
                bytes[32..].copy_from_slice(&hex_word(&s, "s")?);
                verify_ed25519(&identity, &message.0, &bytes)?;
                Ok(Signature::Ed25519 { bytes })
            }
        }
    }
}

/// Recovers the address `(r, s, v)` was minted by over `prehash` — the
/// digest this crate itself computed, so the check binds the answer to
/// both the payload and the key — and refuses it unless that address is
/// `identity` (a lowercase `0x` word from the key reference). `v` is 27
/// plus the recovery id.
fn verify_secp256k1(
    identity: &str,
    prehash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    v: u8,
) -> Result<(), SignerError> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::Digest as _;
    let not_a_recovery_id = || SignerError::Provider(format!("turnkey's `v` is {v}"));
    let recovery_id = RecoveryId::from_byte(v.checked_sub(27).ok_or_else(not_a_recovery_id)?)
        .ok_or_else(not_a_recovery_id)?;
    let signature = Signature::from_slice(&[*r, *s].concat())
        .map_err(|err| SignerError::Provider(format!("turnkey's signature is malformed: {err}")))?;
    let recovered =
        VerifyingKey::recover_from_prehash(prehash, &signature, recovery_id).map_err(|err| {
            SignerError::Provider(format!("turnkey's signature does not recover: {err}"))
        })?;
    let point = recovered.to_encoded_point(false);
    let digest: [u8; 32] = sha3::Keccak256::digest(&point.as_bytes()[1..]).into();
    let address = format!("0x{}", hex::encode(&digest[12..]));
    if !address.eq_ignore_ascii_case(identity) {
        return Err(SignerError::Provider(format!(
            "turnkey's signature recovers to {address}, not the key's identity `{identity}` — it \
             was minted by another key or over other bytes"
        )));
    }
    Ok(())
}

/// Verifies an ed25519 answer over `message` against the identity
/// pubkey (base58, from the key reference) — the same check the signer
/// port's conformance suite runs on its providers.
fn verify_ed25519(identity: &str, message: &[u8], bytes: &[u8; 64]) -> Result<(), SignerError> {
    use ed25519_dalek::Verifier as _;
    let pubkey = crate::policy::validate_program_key(identity)?;
    let pubkey: [u8; 32] = bs58::decode(pubkey)
        .into_vec()
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            SignerError::Provider(format!(
                "the key's identity `{identity}` is not a 32-byte pubkey"
            ))
        })?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
        .map_err(|err| SignerError::Provider(format!("bad identity pubkey: {err}")))?;
    verifying
        .verify(message, &ed25519_dalek::Signature::from_bytes(bytes))
        .map_err(|_| {
            SignerError::Provider(
                "turnkey's ed25519 answer does not verify against the key's identity — it was \
                 minted by another key or over other bytes"
                    .to_owned(),
            )
        })
}

/// `(r, s, v)` hex off the raw-payload answer: `v` arrives as the
/// recovery id in hex (`"00"`/`"01"`), the port carries 27 plus it.
fn raw_secp256k1(r: &str, s: &str, v: &str) -> Result<([u8; 32], [u8; 32], u8), SignerError> {
    let v_hex = hex::decode(v)
        .ok()
        .filter(|bytes| bytes.len() == 1)
        .ok_or_else(|| SignerError::Provider(format!("turnkey's `v` is not one hex byte: {v}")))?;
    let recovery_id = v_hex[0];
    if recovery_id > 1 {
        return Err(SignerError::Provider(format!(
            "turnkey's `v` is not a recovery id: {recovery_id}"
        )));
    }
    Ok((hex_word(r, "r")?, hex_word(s, "s")?, 27 + recovery_id))
}

/// One 0x-hex 32-byte signature component.
fn hex_word(text: &str, field: &str) -> Result<[u8; 32], SignerError> {
    let bytes = text
        .strip_prefix("0x")
        .and_then(|part| hex::decode(part).ok())
        .ok_or_else(|| {
            SignerError::Provider(format!("turnkey's `{field}` is not 0x-hex: {text}"))
        })?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| SignerError::Provider(format!("turnkey's `{field}` is {len} bytes, not 32")))
}
