//! Keys and their public face: the reference, the scheme, the identity a
//! signature must verify against, and the signature itself. Nothing in
//! this module — or this crate — can hand a caller private key material;
//! `KeyInfo` is deliberately all-public-fields *public* data.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::port::SignerError;

/// Which curve a key lives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    /// secp256k1: EVM transactions, ERC-4337 `UserOperations`, EIP-712.
    Secp256k1,
    /// ed25519: Solana messages.
    Ed25519,
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Secp256k1 => "secp256k1",
            Self::Ed25519 => "ed25519",
        })
    }
}

/// What a key is for. This crate mints session keys and nothing else:
/// an owner key belongs in a hardware wallet or a KMS, never in a
/// tenant secrets store, and there is no import API to sneak one in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// A key a venture mints for automated signing, scoped to one
    /// subject, revocable by deleting the secret it lives behind.
    Session,
}

/// An opaque, provider-scoped key reference. The provider that mints the
/// key assigns it; callers only carry it and hand it back. For
/// [`SecretsSigner`](crate::SecretsSigner) the reference is the secret's
/// store name, which is as much as anyone learns from holding one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyRef(String);

impl KeyRef {
    /// Names a key. Providers assign these; empty or over-long
    /// references are refused so a misrouted empty string cannot become
    /// a key.
    ///
    /// # Errors
    ///
    /// [`SignerError::Invalid`] when empty or over 256 bytes.
    pub fn new(key_ref: impl Into<String>) -> Result<Self, SignerError> {
        let key_ref = key_ref.into();
        if key_ref.is_empty() || key_ref.len() > 256 {
            return Err(SignerError::Invalid(
                "a key reference is 1..=256 bytes".to_owned(),
            ));
        }
        Ok(Self(key_ref))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who is signing: the venture the bill goes to, and optionally the user
/// on whose behalf a session key acts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Subject {
    /// The venture (tenant) that owns the key.
    pub venture: String,
    /// The user the key acts for, when the key is scoped to one.
    pub user: Option<String>,
}

impl Subject {
    /// Names a subject.
    ///
    /// # Errors
    ///
    /// [`SignerError::Invalid`] when the venture is empty or over 64
    /// bytes: an audit record without a venture answers nothing.
    pub fn new(venture: impl Into<String>, user: Option<String>) -> Result<Self, SignerError> {
        let venture = venture.into();
        if venture.is_empty() || venture.len() > 64 {
            return Err(SignerError::Invalid("a venture is 1..=64 bytes".to_owned()));
        }
        Ok(Self { venture, user })
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.user {
            Some(user) => write!(f, "{}/{user}", self.venture),
            None => f.write_str(&self.venture),
        }
    }
}

/// The public description of a key: what a caller holds, displays, and
/// verifies signatures against. No private material, and no field that
/// could smuggle any in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    /// The reference to hand back to `sign`.
    pub key_ref: KeyRef,
    /// Which curve the key lives on.
    pub scheme: Scheme,
    /// Always [`KeyRole::Session`] from this crate.
    pub role: KeyRole,
    /// The caller-supplied label.
    pub label: String,
    /// Who the key signs for.
    pub subject: Subject,
    /// The public identity: an EIP-55 checksummed address (secp256k1)
    /// or a base58 pubkey (ed25519). A signature from this key must
    /// verify against it.
    pub identity: String,
}

impl KeyInfo {
    /// The reference to hand back to `sign`.
    #[must_use]
    pub fn key_ref(&self) -> &KeyRef {
        &self.key_ref
    }
}

/// A signature over one payload's signing hash. Exactly one of the
/// variants, sized as the chain expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// secp256k1 `(r, s, v)`; `v` is 27 plus the recovery id. EIP-155
    /// replay protection is not applied: the crate signs a plain 32-byte
    /// digest, and a caller replay-protects the payload itself (an
    /// EIP-1559 signing hash already commits the chain id).
    Secp256k1 {
        /// 32 bytes.
        r: [u8; 32],
        /// 32 bytes.
        s: [u8; 32],
        /// 27 or 28.
        v: u8,
    },
    /// ed25519: the 64-byte signature over the raw message.
    Ed25519 {
        /// 64 bytes.
        bytes: [u8; 64],
    },
}

impl Signature {
    /// The scheme the signature belongs to.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        match self {
            Self::Secp256k1 { .. } => Scheme::Secp256k1,
            Self::Ed25519 { .. } => Scheme::Ed25519,
        }
    }
}

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        match self {
            Self::Secp256k1 { r, s, v } => {
                let mut out = serializer.serialize_struct("Signature", 4)?;
                out.serialize_field("scheme", "secp256k1")?;
                out.serialize_field("r", &format!("0x{}", hex::encode(r)))?;
                out.serialize_field("s", &format!("0x{}", hex::encode(s)))?;
                out.serialize_field("v", v)?;
                out.end()
            }
            Self::Ed25519 { bytes } => {
                let mut out = serializer.serialize_struct("Signature", 2)?;
                out.serialize_field("scheme", "ed25519")?;
                out.serialize_field("bytes", &bs58::encode(bytes).into_string())?;
                out.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "scheme", rename_all = "snake_case")]
        enum Wire {
            Secp256k1 { r: String, s: String, v: u8 },
            Ed25519 { bytes: String },
        }

        let wire = Wire::deserialize(deserializer)?;
        match wire {
            Wire::Secp256k1 { r, s, v } => Ok(Self::Secp256k1 {
                r: hex_word(&r, "r")?,
                s: hex_word(&s, "s")?,
                v,
            }),
            Wire::Ed25519 { bytes } => Ok(Self::Ed25519 {
                bytes: base58_64(&bytes)?,
            }),
        }
    }
}

/// One 0x-hex 32-byte signature component, with an error that names the
/// field.
fn hex_word<E: serde::de::Error>(text: &str, field: &str) -> Result<[u8; 32], E> {
    let bytes = text
        .strip_prefix("0x")
        .and_then(|part| hex::decode(part).ok())
        .ok_or_else(|| E::custom(format!("signature field `{field}` is not 0x-hex")))?;
    bytes
        .try_into()
        .map_err(|_| E::custom(format!("signature field `{field}` is not 32 bytes")))
}

/// The 64-byte ed25519 signature, base58 (Solana's habit), with an error
/// that says so.
fn base58_64<E: serde::de::Error>(text: &str) -> Result<[u8; 64], E> {
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|_| E::custom("signature field `bytes` is not base58"))?;
    bytes
        .try_into()
        .map_err(|_| E::custom("signature field `bytes` is not 64 bytes"))
}
