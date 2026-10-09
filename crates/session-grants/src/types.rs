//! Chain-literal types, the owner credential and the EIP-7702
//! authorization, with the one hard refusal the whole crate is built
//! around: an authorization for `chain_id = 0`.

use std::fmt;

use serde::{Deserialize, Serialize};

/// An EVM address: `0x` plus 40 hex digits, stored lowercased and
/// compared case-insensitively — a checksummed literal and its
/// lowercase spelling are the same address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(String);

/// The four-byte EVM function selector a call policy names: `0x` plus
/// 8 hex digits, stored lowercased.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Selector(String);

/// A Solana public key: base58, 32 bytes when decoded (so 32–44
/// characters). Only the alphabet is checked — the crate has no
/// curve code, and the on-chain program is the real validator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pubkey(String);

/// The base58 alphabet, for [`Pubkey`] validation: no `0`, `O`, `I`, `l`.
const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Why a chain literal was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LiteralError {
    /// The string was empty or not the fixed length the type demands.
    #[error("expected {expected} characters, got {got}: {value:?}")]
    Length {
        /// The length the type demands, including the `0x` prefix.
        expected: usize,
        /// The length that was offered.
        got: usize,
        /// The offered string, for the operator's log.
        value: String,
    },
    /// A character was outside the literal's alphabet.
    #[error("invalid character {ch:?} in {value:?}")]
    Alphabet {
        /// The offending character.
        ch: char,
        /// The offered string.
        value: String,
    },
}

impl Address {
    /// Parses and normalizes an EVM address.
    ///
    /// # Errors
    /// [`LiteralError::Length`] or [`LiteralError::Alphabet`] when the
    /// string is not `0x` + 40 hex digits.
    pub fn parse(value: &str) -> Result<Self, LiteralError> {
        Ok(Self(hex_literal(value, 40)?))
    }

    /// The normalized (lowercase) spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Selector {
    /// Parses and normalizes a selector.
    ///
    /// # Errors
    /// [`LiteralError::Length`] or [`LiteralError::Alphabet`] when the
    /// string is not `0x` + 8 hex digits.
    pub fn parse(value: &str) -> Result<Self, LiteralError> {
        Ok(Self(hex_literal(value, 8)?))
    }

    /// The normalized (lowercase) spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Pubkey {
    /// Checks the base58 alphabet and length; stores the literal as given
    /// (Solana display is case-sensitive).
    ///
    /// # Errors
    /// [`LiteralError::Length`] or [`LiteralError::Alphabet`] when the
    /// string is not 32–44 base58 characters.
    pub fn parse(value: &str) -> Result<Self, LiteralError> {
        if value.len() < 32 || value.len() > 44 {
            return Err(LiteralError::Length {
                expected: 32,
                got: value.len(),
                value: value.to_owned(),
            });
        }
        let bad = value.chars().find(|ch| !BASE58.contains(*ch));
        match bad {
            None => Ok(Self(value.to_owned())),
            Some(ch) => Err(LiteralError::Alphabet {
                ch,
                value: value.to_owned(),
            }),
        }
    }

    /// The literal as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl Serialize for Selector {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl Serialize for Pubkey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

macro_rules! literal_from_string {
    ($ty:ty) => {
        impl TryFrom<String> for $ty {
            type Error = LiteralError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(&value)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                <$ty as TryFrom<String>>::try_from(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

literal_from_string!(Address);
literal_from_string!(Selector);
// Deserialization validates too, so a grant arriving as JSON cannot carry a
// pubkey the port would refuse later.
literal_from_string!(Pubkey);

/// Validates `0x` + `digits` hex digits; returns the lowercased literal.
fn hex_literal(value: &str, digits: usize) -> Result<String, LiteralError> {
    let expected = digits + 2;
    if value.len() != expected || !value.starts_with("0x") {
        return Err(LiteralError::Length {
            expected,
            got: value.len(),
            value: value.to_owned(),
        });
    }
    if !value[2..]
        .chars()
        .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch) || ('A'..='F').contains(&ch))
    {
        return Err(LiteralError::Alphabet {
            ch: value
                .chars()
                .find(|ch| !ch.is_ascii_hexdigit())
                .unwrap_or_default(),
            value: value.to_owned(),
        });
    }
    Ok(value.to_ascii_lowercase())
}

/// How the owner of the account proves the grant — signed once, at grant
/// time; the server never holds the private material behind either arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnerCredential {
    /// A WebAuthn passkey behind a Kernel WebAuthn validator: the private
    /// key never leaves the authenticator, so the server cannot export it
    /// and must ask the owner to sign each new grant.
    Passkey {
        /// The WebAuthn credential id, opaque to this crate.
        credential_id: String,
    },
    /// An EOA that delegated to the smart account with EIP-7702. Every
    /// authorization it signs names exactly one chain id (see
    /// [`Eip7702Authorization`]).
    Eip7702 {
        /// The EOA's address.
        address: Address,
    },
}

impl fmt::Display for OwnerCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passkey { credential_id } => write!(f, "passkey {credential_id}"),
            Self::Eip7702 { address } => write!(f, "eip-7702 eoa {address}"),
        }
    }
}

/// The owner's signature over one grant, carried into the port calls that
/// put it on chain — so the *user* signs the grant and the revoke, and the
/// server can only act inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnerSignature {
    /// A WebAuthn assertion from the passkey over the grant digest.
    PasskeyAssertion {
        /// Raw authenticator data, hex.
        authenticator_data: String,
        /// The client data JSON the authenticator signed over.
        client_data_json: String,
        /// The assertion signature, hex.
        signature: String,
    },
    /// The signed EIP-7702 authorization the EOA produced.
    Authorization(SignedAuthorization),
}

/// One signed EIP-7702 authorization (EIP-7702 §"`authorization_list`").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAuthorization {
    /// The authorization proper: delegation target, chain id, nonce.
    pub authorization: Eip7702Authorization,
    /// The recovery id of the signature.
    pub y_parity: bool,
    /// The signature's `r` scalar, hex.
    pub r: String,
    /// The signature's `s` scalar, hex.
    pub s: String,
}

/// An EIP-7702 authorization: "please let `address`'s code run as this
/// EOA's code from nonce `nonce` on, on chain `chain_id`".
///
/// `chain_id = 0` means "every chain" per the EIP. A session grant is an
/// automation key with a spend cap, so it must never be chain-agnostic:
/// a grant valid on all chains outlives every per-chain limit this crate
/// enforces. Construction and deserialization therefore both refuse
/// `chain_id = 0` — [`AuthorizationError::ChainIdZero`] — and the ports refuse a
/// spec carrying one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip7702Authorization {
    chain_id: u64,
    /// The contract the EOA delegates its code to.
    pub delegate: Address,
    /// The EOA nonce the authorization is valid at.
    pub nonce: u64,
}

/// Why an EIP-7702 authorization was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthorizationError {
    /// `chain_id = 0` means "any chain" (EIP-7702) and this crate refuses
    /// chain-agnostic automation keys: a grant that outlives one chain
    /// outlives the per-chain limits it was signed under. The owner must
    /// name the one chain the grant lives on.
    #[error(
        "chain_id = 0 authorizations are refused: an EIP-7702 authorization must name the one chain the grant lives on"
    )]
    ChainIdZero,
}

impl Eip7702Authorization {
    /// Builds an authorization for exactly one chain.
    ///
    /// # Errors
    /// [`AuthorizationError::ChainIdZero`] when `chain_id` is 0.
    pub fn new(chain_id: u64, delegate: Address, nonce: u64) -> Result<Self, AuthorizationError> {
        if chain_id == 0 {
            return Err(AuthorizationError::ChainIdZero);
        }
        Ok(Self {
            chain_id,
            delegate,
            nonce,
        })
    }

    /// The one chain this authorization is valid on. Never 0 for a value
    /// that exists: construction and deserialization both refuse it.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

impl fmt::Display for Eip7702Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "eip-7702 authorization for {} on {}",
            self.delegate, self.chain_id
        )
    }
}

impl serde::Serialize for Eip7702Authorization {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(serde::Serialize)]
        struct Wire<'a> {
            chain_id: u64,
            delegate: &'a Address,
            nonce: u64,
        }
        Wire {
            chain_id: self.chain_id,
            delegate: &self.delegate,
            nonce: self.nonce,
        }
        .serialize(serializer)
    }
}

// Deserialized through the constructor, so a `chain_id = 0` authorization is
// unrepresentable from the wire too — not only in Rust code.
impl<'de> Deserialize<'de> for Eip7702Authorization {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Wire {
            chain_id: u64,
            delegate: Address,
            nonce: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.chain_id, wire.delegate, wire.nonce).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789";

    #[test]
    fn addresses_are_normalized_and_case_insensitive() {
        let mixed = Address::parse("0x5FF137D4B0FDCD49DCA30C7CF57E578A026D2789").expect("parses");
        assert_eq!(mixed, Address::parse(ADDR).expect("parses"));
        assert_eq!(mixed.as_str(), ADDR);
    }

    #[test]
    fn bad_literals_are_refused() {
        assert!(matches!(
            Address::parse("5ff137d4b0fdcd49dca30c7cf57e578a026d2789"),
            Err(LiteralError::Length { .. })
        ));
        assert!(matches!(
            Address::parse("0x5ff137d4b0fdcd49dca30c7cf57e578a026zzzzz"),
            Err(LiteralError::Alphabet { .. })
        ));
        assert!(matches!(
            Selector::parse("0xfff"),
            Err(LiteralError::Length { .. })
        ));
        assert!(matches!(
            Pubkey::parse("0OIl000000000000000000000000000000000000000"),
            Err(LiteralError::Alphabet { .. })
        ));
    }

    #[test]
    fn chain_id_zero_is_refused_by_the_constructor() {
        let delegate = Address::parse(ADDR).expect("parses");
        assert_eq!(
            Eip7702Authorization::new(0, delegate.clone(), 7)
                .expect_err("chain id zero is refused"),
            AuthorizationError::ChainIdZero
        );
        let ok = Eip7702Authorization::new(8453, delegate, 7).expect("a named chain");
        assert_eq!(ok.chain_id(), 8453);
    }

    #[test]
    fn chain_id_zero_is_refused_from_the_wire() {
        let text = format!(r#"{{"chain_id":0,"delegate":"{ADDR}","nonce":7}}"#);
        let error = serde_json::from_str::<Eip7702Authorization>(&text)
            .expect_err("chain id zero does not deserialize");
        assert!(error.to_string().contains("chain_id = 0"));
    }
}
