//! The `X-Stamp`: Turnkey's API-key authentication header. A stamp is
//! base64url of a JSON object naming the signer's compressed P-256 public
//! key (hex), a DER ECDSA signature over the **exact** request body
//! (hex), and the scheme `SIGNATURE_SCHEME_TK_API_P256` — Turnkey
//! verifies the signature against the body as it received it, so the
//! stamp is the last thing built before the request is sent.
//!
//! The signing key is the venture's Turnkey API key, a 32-byte P-256
//! scalar that lives in the Secrets port. It is unsealed only inside
//! [`stamp_with_key`], into buffers that zeroise, and signing is
//! deterministic (RFC 6979): no RNG anywhere on this path, which is what
//! lets it run unchanged on wasm32.

use cratefield_signer::SignerError;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};

/// The only stamp scheme this crate produces: an ECDSA signature from a
/// P-256 key over SHA-256 of the request body.
pub const SCHEME_TK_API_P256: &str = "SIGNATURE_SCHEME_TK_API_P256";

/// Builds the `X-Stamp` header value for `body`, signing with `key`.
///
/// The signature is over `body` exactly as sent — build the stamp after
/// the body's final serialisation, never on a re-encoding of it.
#[must_use]
pub fn stamp_with_key(body: &[u8], key: &SigningKey) -> String {
    let signature: DerSignature = key.sign(body);
    let stamp = format!(
        "{{\"publicKey\":\"{}\",\"signature\":\"{}\",\"scheme\":\"{SCHEME_TK_API_P256}\"}}",
        compressed_public_key_hex(key),
        hex::encode(signature.to_bytes()),
    );
    base64_url(&stamp)
}

/// The key's compressed public point, hex — the `publicKey` a stamp
/// carries, and the value Turnkey registers for the delegated access
/// user's API key.
#[must_use]
pub fn compressed_public_key_hex(key: &SigningKey) -> String {
    let encoded = key.verifying_key().to_encoded_point(true);
    hex::encode(encoded.as_bytes())
}

/// Restores the [`SigningKey`] behind a 32-byte P-256 secret scalar —
/// the form the Secrets port stores. The caller hands over the unsealed
/// bytes; they must already be in a zeroising buffer of the caller's.
///
/// # Errors
///
/// [`SignerError::Provider`] when the stored bytes are not exactly 32 or
/// are not a scalar on the curve.
pub fn signing_key(exposed: &[u8]) -> Result<SigningKey, SignerError> {
    let Ok(bytes) = <&[u8; 32]>::try_from(exposed) else {
        return Err(SignerError::Provider(format!(
            "the Turnkey API key is {} bytes; this provider stores the 32-byte P-256 scalar",
            exposed.len()
        )));
    };
    let secret = p256::SecretKey::from_slice(bytes).map_err(|err| {
        SignerError::Provider(format!("the Turnkey API key is not a P-256 scalar: {err}"))
    })?;
    Ok(SigningKey::from(&secret))
}

/// base64url, no padding — the stamp's envelope encoding.
fn base64_url(text: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// `keccak256("cow")` is the EIP-712 example key; the stamp test key
    /// here is derived, not imported, so nothing credential-shaped is
    /// ever copied into the tree.
    fn test_key() -> SigningKey {
        let mut seed = [0_u8; 32];
        for (byte, tag) in seed
            .iter_mut()
            .zip(b"cratefield-adapter-turnkey/stamp-test")
        {
            *byte = *tag;
        }
        signing_key(&seed).expect("a valid scalar")
    }

    #[test]
    fn the_stamp_carries_the_documented_fields() {
        let key = test_key();
        let body = br#"{"type":"ACTIVITY_TYPE_SIGN_TRANSACTION_V2"}"#;
        let stamp = stamp_with_key(body, &key);

        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&stamp)
            .expect("base64url round-trips");
        let text = String::from_utf8(decoded).expect("utf8");
        assert!(
            text.starts_with("{\"publicKey\":\""),
            "publicKey is the first field: {text}"
        );
        assert!(
            text.contains(&format!("\"scheme\":\"{SCHEME_TK_API_P256}\"")),
            "the scheme names P-256: {text}"
        );
        // The public key is the compressed point, hex: one prefix byte
        // (`02` or `03`) plus the 32-byte x coordinate.
        let public_key = compressed_public_key_hex(&key);
        assert_eq!(public_key.len(), 66);
        assert!(
            public_key.starts_with("02") || public_key.starts_with("03"),
            "compressed points start 02 or 03: {public_key}"
        );
    }

    #[test]
    fn the_stamp_signature_verifies_over_the_exact_body() {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};

        let key = test_key();
        let body = b"the exact serialized body it receives";
        let stamp = stamp_with_key(body, &key);

        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&stamp)
            .expect("base64url round-trips");
        let text = String::from_utf8(decoded).expect("utf8");
        let signature_hex = text
            .split("\"signature\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("a signature field");
        let signature =
            Signature::from_der(&hex::decode(signature_hex).expect("hex DER")).expect("DER");
        VerifyingKey::from(&key)
            .verify(body, &signature)
            .expect("the stamp verifies over the exact body");
    }

    #[test]
    fn a_non_scalar_is_refused() {
        let err = signing_key(&[0_u8; 31]).expect_err("31 bytes are not a scalar");
        assert!(matches!(err, SignerError::Provider(_)), "got: {err:?}");
    }
}
