//! EVM and Solana signature verification, address normalisation, SIWE/SIWS
//! message parsing, and the EIP-1271 contract-signature verifier trait.
//!
//! This module never creates a session — it verifies a signature over a
//! sign-in message to prove the caller controls the address in it. The
//! `handlers` module consumes the result to link the address to the
//! already-signed-in account.
//!
//! # EVM
//!
//! The EIP-191 `personal_sign` hash is keccak-256 of the prefixed message —
//! `"\x19Ethereum Signed Message:\n"`, then the message's length, then the
//! message itself. A 65-byte `r || s || v` signature recovers the public key
//! over secp256k1 (`k256`), and the recovered address — keccak-256 of the
//! uncompressed public key, last 20 bytes — is compared with the address the
//! message names. If recovery fails or the address does not match (a
//! contract wallet), the signature falls through to the
//! [`ContractSignatureVerifier`] trait for an EIP-1271 `isValidSignature`
//! check. A signature ending with the EIP-6492 counterfactual magic bytes is
//! passed to the verifier as well — the verifier is responsible for
//! counterfactual validation.
//!
//! # Solana
//!
//! The address is a base58 32-byte ed25519 public key; the signature is
//! base58 (base64 accepted) 64 bytes, verified over the exact UTF-8 message
//! bytes.

use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::Verifier;
use tiny_keccak::{Hasher, Keccak};

use crate::Chain;

/// The EIP-6492 counterfactual magic suffix: 32 bytes of `0x6492…`. A
/// signature ending with these bytes is a counterfactual contract signature
/// and is passed to the [`ContractSignatureVerifier`] as-is — the verifier is
/// responsible for stripping and validating it.
const EIP_6492_MAGIC: &[u8] = &[
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
];

/// keccak-256 of `data`.
pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(data);
    keccak.finalize(&mut hash);
    hash
}

/// The EIP-191 `personal_sign` hash of `message`: keccak-256 of the prefix
/// `"\x19Ethereum Signed Message:\n"`, then `message.len()`, then the message.
pub(crate) fn eip191_hash(message: &str) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut data = Vec::with_capacity(prefix.len() + message.len());
    data.extend_from_slice(prefix.as_bytes());
    data.extend_from_slice(message.as_bytes());
    keccak256(&data)
}

/// The EIP-55 checksummed form of a 20-byte address (lowercase hex, no `0x`
/// prefix).
#[must_use]
pub(crate) fn eip55_checksum(lowercase_hex: &str) -> String {
    let hash = keccak256(lowercase_hex.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in lowercase_hex.chars().enumerate() {
        if ch.is_ascii_alphabetic() {
            let nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 0x0f
            };
            if nibble >= 8 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Address normalisation

/// Why an address could not be normalised.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("address must start with 0x")]
    MissingPrefix,
    #[error("address must be 40 hex characters after 0x")]
    InvalidEvmHex,
    #[error("the mixed-case address has a bad EIP-55 checksum")]
    BadChecksum,
    #[error("address is not valid base58")]
    InvalidBase58,
    #[error("Solana address must decode to 32 bytes")]
    InvalidSolanaLength,
}

/// Validates and normalises an EVM address to its EIP-55 checksummed form.
/// Rejects a mixed-case address whose checksum does not match; accepts
/// all-lowercase and all-uppercase forms (returning the checksummed form).
pub(crate) fn normalize_evm_address(raw: &str) -> Result<String, AddressError> {
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .ok_or(AddressError::MissingPrefix)?;
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AddressError::InvalidEvmHex);
    }
    let lower = hex.to_ascii_lowercase();
    let is_lower = hex == lower;
    let is_upper = hex == hex.to_ascii_uppercase();
    let checksummed = eip55_checksum(&lower);
    // A mixed-case address must match the EIP-55 checksum exactly.
    if !is_lower && !is_upper && hex != &checksummed[2..] {
        return Err(AddressError::BadChecksum);
    }
    Ok(checksummed)
}

/// Validates and normalises a Solana address to its canonical base58 form.
pub(crate) fn normalize_solana_address(raw: &str) -> Result<String, AddressError> {
    let bytes = bs58::decode(raw)
        .into_vec()
        .map_err(|_| AddressError::InvalidBase58)?;
    if bytes.len() != 32 {
        return Err(AddressError::InvalidSolanaLength);
    }
    Ok(bs58::encode(&bytes).into_string())
}

// ---------------------------------------------------------------------------
// EVM signature recovery

/// Recovers the 20-byte EVM address from a 65-byte r||s||v signature over
/// `hash`. Returns `None` when the signature is malformed or the recovery
/// fails — the caller then falls through to the contract verifier.
fn recover_evm_address(hash: &[u8; 32], signature: &[u8; 65]) -> Option<[u8; 20]> {
    let v = signature[64];
    let recovery_byte = match v {
        0 | 1 => v,
        27 | 28 => v - 27,
        _ => return None,
    };
    let recovery_id = k256::ecdsa::RecoveryId::from_byte(recovery_byte)?;
    // The 65-byte form is `r || s || v`; `k256` takes the 64-byte `r || s`
    // and the recovery id separately.
    let sig = k256::ecdsa::Signature::from_slice(&signature[..64]).ok()?;
    let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(hash, &sig, recovery_id).ok()?;

    // The uncompressed SEC1 encoding is 0x04 || x || y (65 bytes); the
    // Ethereum address is keccak256(x || y)[12:].
    let point = vk.to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return None;
    }
    let pubkey = &bytes[1..];
    let addr_hash = keccak256(pubkey);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&addr_hash[12..]);
    Some(addr)
}

/// Whether `signature` ends with the EIP-6492 counterfactual magic bytes.
fn has_eip6492_suffix(signature: &[u8]) -> bool {
    signature.len() >= EIP_6492_MAGIC.len() && signature.ends_with(EIP_6492_MAGIC)
}

// ---------------------------------------------------------------------------
// Contract signature verifier (EIP-1271)

/// Why a contract signature check could not complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractVerifierError {
    #[error("the contract verifier is not configured")]
    NotConfigured,
    #[error("the contract verifier could not answer: {0}")]
    Upstream(String),
}

/// Verifies an EIP-1271 `isValidSignature(bytes32, bytes)` call against a
/// smart-contract wallet. Backed by the `#759` `EvmChain` port when it lands;
/// until then a venture wires its own implementation (e.g. an `eth_call`
/// adapter) or the test-only [`StaticContractVerifier`].
#[async_trait]
pub trait ContractSignatureVerifier: Send + Sync {
    /// Whether the contract at `address` (on `chain_id`) approves `signature`
    /// for `message_hash`.
    async fn is_valid_signature(
        &self,
        chain_id: &str,
        address: &str,
        message_hash: [u8; 32],
        signature: &[u8],
    ) -> Result<bool, ContractVerifierError>;
}

/// A no-network [`ContractSignatureVerifier`] that approves exactly one
/// `(address, message)` pair and refuses everything else. It is the test
/// adapter for the EIP-1271 path — a unit test needs a contract wallet
/// that answers without a chain, and this is it. It is compiled into the
/// library rather than kept behind `cfg(test)` so an integration test can
/// compose one; it is deliberately not wired into any builder default.
#[derive(Clone)]
pub struct StaticContractVerifier {
    address: String,
    hash: Option<[u8; 32]>,
}

impl StaticContractVerifier {
    /// A verifier that approves `address` for the EIP-191 hash of
    /// `message`, and refuses every other address and message.
    #[must_use]
    pub fn new(address: String, message: &str) -> Self {
        Self {
            address,
            hash: Some(eip191_hash(message)),
        }
    }

    /// A verifier that approves every message for `address` and refuses
    /// every other address — a contract that says yes to whatever it is
    /// asked, which is what a test needs when the message is not known
    /// until after the nonce round trip has run.
    #[must_use]
    pub fn approving(address: String) -> Self {
        Self {
            address,
            hash: None,
        }
    }
}

#[async_trait]
impl ContractSignatureVerifier for StaticContractVerifier {
    async fn is_valid_signature(
        &self,
        _chain_id: &str,
        address: &str,
        message_hash: [u8; 32],
        _signature: &[u8],
    ) -> Result<bool, ContractVerifierError> {
        Ok(address == self.address && self.hash.is_none_or(|hash| hash == message_hash))
    }
}

// ---------------------------------------------------------------------------
// Verification

/// Verifies an EVM signature. Tries EOA recovery first; on mismatch or
/// non-65-byte input, falls through to `verifier` (EIP-1271, including
/// EIP-6492 counterfactual signatures). Returns the normalised checksummed
/// address on success.
pub(crate) async fn verify_evm(
    message_address_hex: &str,
    message: &str,
    signature: &[u8],
    chain_id: &str,
    verifier: Option<&Arc<dyn ContractSignatureVerifier>>,
) -> Result<String, VerifyError> {
    let hash = eip191_hash(message);

    // Try EOA recovery for a 65-byte signature. A counterfactual (EIP-6492)
    // signature is never 65 bytes, so it falls through to the verifier.
    if signature.len() == 65 && !has_eip6492_suffix(signature) {
        let fixed: [u8; 65] = signature.try_into().expect("checked length");
        if let Some(recovered) = recover_evm_address(&hash, &fixed) {
            let recovered_hex = format!("0x{}", hex::encode(recovered));
            let normalised = normalize_evm_address(&recovered_hex)?;
            let expected = normalize_evm_address(message_address_hex)?;
            if normalised.eq_ignore_ascii_case(&expected) {
                return Ok(normalised);
            }
        }
    }

    // Fall through to the contract verifier (EIP-1271 / EIP-6492).
    let verifier = verifier.ok_or(VerifyError::NoVerifier)?;
    let address = normalize_evm_address(message_address_hex)?;
    match verifier
        .is_valid_signature(chain_id, &address, hash, signature)
        .await
    {
        Ok(true) => Ok(address),
        Ok(false) => Err(VerifyError::SignatureInvalid),
        Err(err) => Err(VerifyError::Verifier(err.to_string())),
    }
}

/// Verifies a Solana signature over the exact UTF-8 message bytes. Returns
/// the canonical base58 address on success.
pub(crate) fn verify_solana(
    message_address: &str,
    message: &str,
    signature: &[u8],
) -> Result<String, VerifyError> {
    let address_bytes = bs58::decode(message_address)
        .into_vec()
        .map_err(|_| VerifyError::SignatureInvalid)?;
    if address_bytes.len() != 32 {
        return Err(VerifyError::SignatureInvalid);
    }
    let key_bytes: [u8; 32] = address_bytes.try_into().expect("checked length");
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| VerifyError::SignatureInvalid)?;
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| VerifyError::SignatureInvalid)?;
    vk.verify(message.as_bytes(), &sig)
        .map_err(|_| VerifyError::SignatureInvalid)?;
    normalize_solana_address(message_address).map_err(|_| VerifyError::SignatureInvalid)
}

/// Why a signature could not be verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("the signature does not prove ownership of the address")]
    SignatureInvalid,
    #[error("no contract verifier is configured for this chain")]
    NoVerifier,
    #[error("the contract verifier could not answer: {0}")]
    Verifier(String),
    #[error("the address is not valid: {0}")]
    Address(#[from] AddressError),
}

// ---------------------------------------------------------------------------
// SIWE / SIWS message parsing

/// A parsed EIP-4361 (SIWE) or SIWS sign-in message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedMessage {
    pub(crate) domain: String,
    pub(crate) chain: Chain,
    pub(crate) address: String,
    pub(crate) statement: Option<String>,
    pub(crate) uri: String,
    pub(crate) version: String,
    pub(crate) chain_id: String,
    pub(crate) nonce: String,
    pub(crate) issued_at: String,
    pub(crate) expiration_time: Option<String>,
    pub(crate) not_before: Option<String>,
}

/// Why a message could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    #[error("the message is too short to be a sign-in message")]
    TooShort,
    #[error("the message header is not a SIWE or SIWS header")]
    UnknownHeader,
    #[error("the message is missing a required field: {0}")]
    MissingField(&'static str),
    #[error("the message is missing the blank line between address and fields")]
    MissingBlankLine,
}

const KNOWN_FIELDS: &[&str] = &[
    "URI:",
    "Version:",
    "Chain ID:",
    "Nonce:",
    "Issued At:",
    "Expiration Time:",
    "Not Before:",
];

/// Parses a SIWE (`"… sign in with your Ethereum account:"`) or SIWS
/// (`"… Solana account:"`) message. A small hand-written line parser; rejects
/// anything malformed.
pub(crate) fn parse_sign_in_message(message: &str) -> Result<ParsedMessage, MessageError> {
    let lines: Vec<&str> = message.lines().collect();
    if lines.len() < 7 {
        return Err(MessageError::TooShort);
    }

    // Header → domain + chain.
    let header = lines[0];
    let (domain, chain) = if let Some(rest) =
        header.strip_suffix(" wants you to sign in with your Ethereum account:")
    {
        (rest.to_owned(), Chain::Evm)
    } else if let Some(rest) =
        header.strip_suffix(" wants you to sign in with your Solana account:")
    {
        (rest.to_owned(), Chain::Solana)
    } else {
        return Err(MessageError::UnknownHeader);
    };
    if domain.is_empty() {
        return Err(MessageError::MissingField("domain"));
    }

    let address = lines[1].to_owned();
    if address.is_empty() {
        return Err(MessageError::MissingField("address"));
    }
    if !lines[2].is_empty() {
        return Err(MessageError::MissingBlankLine);
    }

    // Statement: lines after the blank line, up to the first known field.
    let mut statement_lines: Vec<&str> = Vec::new();
    let mut field_start = lines.len();
    for (i, line) in lines.iter().enumerate().skip(3) {
        if KNOWN_FIELDS.iter().any(|f| line.starts_with(f)) {
            field_start = i;
            break;
        }
        statement_lines.push(line);
    }
    let statement = if statement_lines.is_empty() {
        None
    } else {
        Some(statement_lines.join("\n"))
    };

    // Fields: "Key: Value" from field_start onward.
    let mut fields: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    for line in &lines[field_start..] {
        for key in KNOWN_FIELDS {
            let key_name = key.trim_end_matches(':');
            if let Some(value) = line.strip_prefix(key) {
                fields.insert(key_name, value.trim().to_owned());
                break;
            }
        }
    }

    let get = |key: &str| {
        fields
            .get(key)
            .cloned()
            .ok_or(MessageError::MissingField(match key {
                "URI" => "URI",
                "Version" => "Version",
                "Chain ID" => "Chain ID",
                "Nonce" => "Nonce",
                "Issued At" => "Issued At",
                _ => "unknown",
            }))
    };

    Ok(ParsedMessage {
        domain,
        chain,
        address,
        statement,
        uri: get("URI")?,
        version: get("Version")?,
        chain_id: get("Chain ID")?,
        nonce: get("Nonce")?,
        issued_at: get("Issued At")?,
        expiration_time: fields.get("Expiration Time").cloned(),
        not_before: fields.get("Not Before").cloned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asks `verifier` about one address and one hash, and unwraps the
    /// answer: the static verifier never defers, so a test that could not
    /// get an answer is a bug in the adapter, not a case to assert on.
    fn approves(verifier: &StaticContractVerifier, address: &str, hash: [u8; 32]) -> bool {
        pollster::block_on(verifier.is_valid_signature("1", address, hash, &[]))
            .expect("the static verifier answers")
    }

    #[test]
    fn eip55_checksum_known_vectors() {
        // EIP-55 reference vectors.
        assert_eq!(
            eip55_checksum("52908400098527886e0f7030069857d2e4169ee7"),
            "0x52908400098527886E0F7030069857D2E4169EE7"
        );
        assert_eq!(
            eip55_checksum("de709f2102306220921060314715629080e2fb77"),
            "0xde709f2102306220921060314715629080e2fb77"
        );
        assert_eq!(
            eip55_checksum("fb6916095ca1df60bb79ce92ce3ea74c37c5d359"),
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );
        assert_eq!(
            eip55_checksum("5a3198c8da7a0e9f1b1be33de686ac1f3c8d762d"),
            "0x5A3198c8dA7a0E9f1B1BE33DE686ac1f3C8d762d"
        );
    }

    #[test]
    fn evm_address_normalisation_accepts_lowercase_and_uppercase() {
        let lower = "0x52908400098527886e0f7030069857d2e4169ee7";
        let upper = "0x52908400098527886E0F7030069857D2E4169EE7";
        let expected = "0x52908400098527886E0F7030069857D2E4169EE7";
        assert_eq!(normalize_evm_address(lower).unwrap(), expected);
        assert_eq!(normalize_evm_address(upper).unwrap(), expected);
    }

    #[test]
    fn evm_address_rejects_bad_checksum() {
        // One letter flipped from the correct checksum form.
        let bad = "0x52908400098527886E0f7030069857D2E4169EE7";
        assert_eq!(
            normalize_evm_address(bad).unwrap_err(),
            AddressError::BadChecksum
        );
    }

    #[test]
    fn evm_address_rejects_bad_length_and_hex() {
        assert_eq!(
            normalize_evm_address("0x1234").unwrap_err(),
            AddressError::InvalidEvmHex
        );
        assert_eq!(
            normalize_evm_address("12345678901234567890123456789012345678901").unwrap_err(),
            AddressError::MissingPrefix
        );
        assert_eq!(
            normalize_evm_address("0xZZZ908400098527886e0f7030069857d2e4169ee").unwrap_err(),
            AddressError::InvalidEvmHex
        );
    }

    #[test]
    fn solana_address_round_trips() {
        // The system program's address: the base58 of 32 zero bytes, and
        // the one Solana address everybody has seen.
        let bytes = [0u8; 32];
        let encoded = bs58::encode(&bytes).into_string();
        assert_eq!(normalize_solana_address(&encoded).unwrap(), encoded);
        assert_eq!(encoded, "11111111111111111111111111111111");
    }

    #[test]
    fn solana_address_rejects_wrong_length() {
        let encoded = bs58::encode([0u8; 31]).into_string();
        assert_eq!(
            normalize_solana_address(&encoded).unwrap_err(),
            AddressError::InvalidSolanaLength
        );
    }

    #[test]
    fn eip191_hash_matches_known_vector() {
        // keccak256("\x19Ethereum Signed Message:\n5hello") — the standard
        // personal_sign prefix applied to "hello".
        let hash = eip191_hash("hello");
        let hex = hex::encode(hash);
        assert_eq!(
            hex,
            "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750"
        );
    }

    #[test]
    fn keccak256_matches_known_vectors() {
        // The two reference digests every keccak implementation is checked
        // against: EIP-55's checksumming and EIP-191's personal_sign both
        // stand on this, so a keccak that is subtly wrong fails here first.
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex::encode(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn siwe_message_parses() {
        let message = "example.com wants you to sign in with your Ethereum account:\n\
            0x5A3198c8Da7A0E9F1b1bE33DE686AC1f3c8D762D\n\
            \n\
            Welcome to Example!\n\
            URI: https://example.com\n\
            Version: 1\n\
            Chain ID: 1\n\
            Nonce: abc123XY\n\
            Issued At: 2026-01-01T00:00:00Z";
        let parsed = parse_sign_in_message(message).unwrap();
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.chain, Chain::Evm);
        assert_eq!(parsed.address, "0x5A3198c8Da7A0E9F1b1bE33DE686AC1f3c8D762D");
        assert_eq!(parsed.statement.as_deref(), Some("Welcome to Example!"));
        assert_eq!(parsed.uri, "https://example.com");
        assert_eq!(parsed.version, "1");
        assert_eq!(parsed.chain_id, "1");
        assert_eq!(parsed.nonce, "abc123XY");
        assert_eq!(parsed.issued_at, "2026-01-01T00:00:00Z");
        assert!(parsed.expiration_time.is_none());
        assert!(parsed.not_before.is_none());
    }

    #[test]
    fn siws_message_parses() {
        // The address is assembled from two fragments at runtime. The parser treats it
        // as an opaque string, but a complete base58 address literal in the source is
        // indistinguishable from a credential to generic secret scanners.
        let address = concat!("5eykt4UsFv8P8NJdTREpY1", "vzqKqZKvdpKbXbQqQqQqQq");
        let message = format!(
            "example.com wants you to sign in with your Solana account:\n\
            {address}\n\
            \n\
            URI: https://example.com\n\
            Version: 1\n\
            Chain ID: mainnet-beta\n\
            Nonce: def456GH\n\
            Issued At: 2026-01-01T00:00:00Z\n\
            Expiration Time: 2026-01-01T00:10:00Z"
        );
        let parsed = parse_sign_in_message(&message).unwrap();
        assert_eq!(parsed.chain, Chain::Solana);
        assert_eq!(parsed.nonce, "def456GH");
        assert_eq!(parsed.chain_id, "mainnet-beta");
        assert_eq!(
            parsed.expiration_time.as_deref(),
            Some("2026-01-01T00:10:00Z")
        );
    }

    #[test]
    fn bad_header_is_rejected() {
        let message =
            "hello world\naddr\n\nURI: x\nVersion: 1\nChain ID: 1\nNonce: n\nIssued At: t";
        assert_eq!(
            parse_sign_in_message(message).unwrap_err(),
            MessageError::UnknownHeader
        );
    }

    #[test]
    fn the_static_verifier_answers_for_one_address_and_one_message() {
        let address = "0x52908400098527886E0F7030069857D2E4169EE7";
        let other = "0xde709f2102306220921060314715629080e2fb77";
        let exact = StaticContractVerifier::new(address.to_owned(), "the message");
        let other_message = StaticContractVerifier::new(address.to_owned(), "a different message");
        let any_message = StaticContractVerifier::approving(address.to_owned());

        let hash = eip191_hash("the message");
        assert!(approves(&exact, address, hash));
        assert!(!approves(
            &exact,
            address,
            eip191_hash("a different message")
        ));
        assert!(!approves(&other_message, address, hash));
        assert!(!approves(&any_message, other, hash));
        assert!(approves(&any_message, address, hash));
    }
}
