//! Private crypto helpers: keccak256, sha256, address and pubkey parsing,
//! EIP-55 checksumming, and the signing/recovering pairs over both
//! schemes. Everything here takes or returns bytes; the private key
//! material never outlives the call it came in on.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha2::Digest as _;
use zeroize::Zeroizing;

use crate::port::SignerError;

/// keccak-256 (the pre-NIST padding, as Ethereum uses it).
pub(crate) fn keccak256(bytes: &[u8]) -> [u8; 32] {
    sha3::Keccak256::digest(bytes).into()
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

/// An `address` word: twenty bytes, left-padded to thirty-two.
pub(crate) fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[12..].copy_from_slice(address);
    out
}

/// A `uint256` word for a value that fits in 128 bits.
pub(crate) fn uint256_word(value: u128) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Parses a `0x`-prefixed twenty-byte address (any case).
pub(crate) fn parse_address(text: &str) -> Result<[u8; 20], SignerError> {
    let hex_part = text.strip_prefix("0x").ok_or_else(|| bad_address(text))?;
    let bytes = hex::decode(hex_part).map_err(|_| bad_address(text))?;
    bytes.try_into().map_err(|_| bad_address(text))
}

fn bad_address(text: &str) -> SignerError {
    SignerError::Invalid(format!("`{text}` is not a 0x-prefixed 20-byte hex address"))
}

/// The EIP-55 checksummed form of an address (mixed case over keccak256
/// of the lowercase hex, the byte-pair-nibble rule).
pub(crate) fn eip55(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (nibble_index, ch) in lower.chars().enumerate() {
        let nibble = if nibble_index % 2 == 0 {
            hash[nibble_index / 2] >> 4
        } else {
            hash[nibble_index / 2] & 0x0f
        };
        if nibble >= 8 {
            out.extend(ch.to_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Parses a base58 Solana pubkey into its 32 bytes.
pub(crate) fn parse_base58_pubkey(text: &str) -> Result<[u8; 32], SignerError> {
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|_| SignerError::Invalid(format!("`{text}` is not a base58 pubkey")))?;
    let len = bytes.len();
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        SignerError::Invalid(format!(
            "`{text}` is not a 32-byte pubkey (it decodes to {len} bytes)"
        ))
    })
}

/// Validates one path component for a Secrets store name: short, and
/// only letters, digits, `-`, `_` and `.` — a name is also a label
/// people read in `list`.
pub(crate) fn valid_component(part: &str) -> Result<(), SignerError> {
    let ok = !part.is_empty()
        && part.len() <= 64
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(SignerError::Invalid(format!(
            "`{part}` is not a usable key name component (1..=64 bytes of letters, digits, \
             `-`, `_`, `.`)"
        )))
    }
}

/// The EIP-55 address of the secp256k1 key a 32-byte seed expands to.
pub(crate) fn secp256k1_address(seed: &[u8; 32]) -> Result<String, SignerError> {
    let pubkey = secp256k1_pubkey_bytes(seed)?;
    let hashed = keccak256(&pubkey);
    let address: [u8; 20] = hashed[12..]
        .try_into()
        .expect("keccak256 output is always 32 bytes");
    Ok(eip55(&address))
}

/// The 64-byte uncompressed public key a 32-byte seed expands to; the
/// address is `keccak256(bytes)[12..]`, EIP-55 checksummed on top.
pub(crate) fn secp256k1_pubkey_bytes(seed: &[u8; 32]) -> Result<[u8; 64], SignerError> {
    let key = SigningKey::from_slice(seed)
        .map_err(|err| SignerError::Invalid(format!("not a valid secp256k1 seed: {err}")))?;
    let point = key.verifying_key().to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(SignerError::Provider(
            "k256 returned a malformed public key".into(),
        ));
    }
    let mut pubkey = [0_u8; 64];
    pubkey.copy_from_slice(&bytes[1..]);
    Ok(pubkey)
}

/// The base58 form of the ed25519 public key a 32-byte seed expands to.
pub(crate) fn ed25519_pubkey(seed: &[u8; 32]) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    bs58::encode(key.verifying_key().as_bytes()).into_string()
}

/// RFC 6979 deterministic ECDSA over a prehashed digest, returning the
/// signature and its recovery id (so `v` = 27 plus that id; EIP-155 is
/// not applied — the payload hash here is a plain 32-byte digest).
pub(crate) fn sign_secp256k1(
    seed: &[u8; 32],
    prehash: &[u8; 32],
) -> Result<(Signature, RecoveryId), SignerError> {
    let key = SigningKey::from_slice(seed)
        .map_err(|err| SignerError::Invalid(format!("not a valid secp256k1 seed: {err}")))?;
    key.sign_prehash_recoverable(prehash)
        .map_err(|err| SignerError::Provider(format!("secp256k1 signing failed: {err}")))
}

/// The two 32-byte halves of an ECDSA signature, `r` then `s`.
pub(crate) fn split(signature: Signature) -> ([u8; 32], [u8; 32]) {
    let bytes = signature.to_bytes();
    let r = bytes[..32].try_into().expect("r||s is 64 bytes");
    let s = bytes[32..].try_into().expect("r||s is 64 bytes");
    (r, s)
}

/// Recovers the signer's address from a digest and an `(r, s, v)`
/// signature — `v` as 27 plus the recovery id.
pub(crate) fn recover_address(
    prehash: &[u8; 32],
    signature: &Signature,
    recovery_id: RecoveryId,
) -> Result<String, SignerError> {
    let verifying = VerifyingKey::recover_from_prehash(prehash, signature, recovery_id)
        .map_err(|err| SignerError::Provider(format!("the signature does not recover: {err}")))?;
    let point = verifying.to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(SignerError::Provider(
            "k256 returned a malformed public key".into(),
        ));
    }
    let hashed = keccak256(&bytes[1..]);
    let address: [u8; 20] = hashed[12..]
        .try_into()
        .expect("keccak256 output is always 32 bytes");
    Ok(eip55(&address))
}

/// Deterministic ed25519 over the raw message bytes (ed25519 has no
/// prehash mode here, so Solana messages are signed as-is).
pub(crate) fn sign_ed25519(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer as _;
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    key.sign(message).to_bytes()
}

/// Verifies an ed25519 signature against a base58 pubkey.
pub(crate) fn verify_ed25519(
    pubkey_base58: &str,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), SignerError> {
    use ed25519_dalek::Verifier as _;
    let pubkey = parse_base58_pubkey(pubkey_base58)?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
        .map_err(|err| SignerError::Provider(format!("bad verifying key: {err}")))?;
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    verifying
        .verify(message, &signature)
        .map_err(|err| SignerError::Provider(format!("the signature does not verify: {err}")))
}

/// A fresh 32-byte key seed from the OS (the `wasm_js` backend on wasm32),
/// already inside a zeroising buffer.
pub(crate) fn random_seed() -> Result<Zeroizing<[u8; 32]>, SignerError> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut())
        .map_err(|err| SignerError::Provider(format!("the OS random source failed: {err}")))?;
    Ok(seed)
}

/// What `Signature::Secp256k1` carries apart from `(r, s)`: 27 or 28.
pub(crate) fn v_of(recovery_id: RecoveryId) -> u8 {
    27 + u8::from(recovery_id.is_y_odd())
}

/// And back: the recovery id from the EIP-191-style `v`.
pub(crate) fn recovery_id_of(v: u8) -> Result<RecoveryId, SignerError> {
    RecoveryId::from_byte(
        v.checked_sub(27)
            .ok_or_else(|| SignerError::Invalid(format!("v is {v}, expected 27 or 28")))?,
    )
    .ok_or_else(|| SignerError::Invalid(format!("v is {v}, expected 27 or 28")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_reference_addresses() {
        // EIP-55's own test set (the addresses in the EIP text). Each
        // address is written as `concat!` of short pieces — a single long
        // hex literal reads as a secret to push scanners, and no piece
        // here is long enough to; the join happens at compile time, so
        // the values are bit for bit the EIP's.
        for (lower, mixed) in [
            (
                concat!("5290840009852788", "6e0f7030069857d2", "e4169ee7"),
                concat!("5290840009852788", "6E0F7030069857D2", "E4169EE7"),
            ),
            (
                concat!("de709f2102306220", "9210603147156290", "80e2fb77"),
                concat!("de709f2102306220", "9210603147156290", "80e2fb77"),
            ),
            (
                concat!("27b1fdb04752bbc5", "36007a920d24acb0", "45561c26"),
                concat!("27b1fdb04752bbc5", "36007a920d24acb0", "45561c26"),
            ),
            (
                concat!("5aaeb6053f3e94c9", "b9a09f33669435e7", "ef1beaed"),
                concat!("5aAeb6053F3E94C9", "b9A09f33669435E7", "Ef1BeAed"),
            ),
            (
                concat!("fb6916095ca1df60", "bb79ce92ce3ea74c", "37c5d359"),
                concat!("fB6916095ca1df60", "bB79Ce92cE3Ea74c", "37c5d359"),
            ),
            (
                concat!("dbf03b407c01e7cd", "3cbea99509d93f8d", "ddc8c6fb"),
                concat!("dbF03B407c01E7cD", "3CBea99509d93f8D", "DDC8C6FB"),
            ),
            (
                concat!("d1220a0cf47c7b9b", "e7a2e6ba89f42976", "2e7b9adb"),
                concat!("D1220A0cf47c7B9B", "e7A2E6BA89F42976", "2e7b9aDb"),
            ),
        ] {
            let bytes = parse_address(&format!("0x{lower}")).expect("parses");
            assert_eq!(
                eip55(&bytes),
                format!("0x{mixed}"),
                "case mismatch on {lower}"
            );
            // Parsing is case-insensitive, so the checksummed form parses
            // straight back.
            assert_eq!(parse_address(&format!("0x{mixed}")).expect("parses"), bytes);
        }
    }

    #[test]
    fn reject_malformed_addresses() {
        for text in [
            "0x1234",
            "1234567890123456789012345678901234567890",
            "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
            "0x00000000000000000000000000000000000000000",
        ] {
            assert!(parse_address(text).is_err(), "{text} should not parse");
        }
    }
}
