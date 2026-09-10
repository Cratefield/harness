//! ES256 (ECDSA P-256 + SHA-256) provider JWTs: APNs today, VAPID next.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::DecodePrivateKey as _;
use serde_json::Value;

use crate::{KeyError, signing_input};

/// Signs ES256 JWTs with a P-256 private key.
///
/// The nonce is RFC 6979 deterministic, so the same key over the same input
/// always yields the same token — which is what lets the APNs adapter's
/// cache be a plain "same token until it ages out", and lets a test assert
/// an exact token string.
pub struct Es256Signer {
    key: SigningKey,
}

impl Es256Signer {
    /// Parses a PKCS#8 PEM P-256 private key.
    ///
    /// # Errors
    ///
    /// [`KeyError::Parse`] if the PEM is not a PKCS#8 P-256 private key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, KeyError> {
        SigningKey::from_pkcs8_pem(pem)
            .map(|key| Self { key })
            .map_err(|err| KeyError::parse("ES256", err))
    }

    /// Apple's name for the same thing: the `.p8` downloaded from the
    /// developer portal is a PKCS#8 PEM.
    ///
    /// # Errors
    ///
    /// [`KeyError::Parse`] if the `.p8` is not a PKCS#8 P-256 private key.
    pub fn from_p8_pem(pem: &str) -> Result<Self, KeyError> {
        Self::from_pkcs8_pem(pem)
    }

    /// The bare 32-byte P-256 private scalar, with no PKCS#8 wrapper around
    /// it — which is how a VAPID key is usually handed over (issue #180).
    /// Every generator in that ecosystem prints the scalar base64url and
    /// calls it `VAPID_PRIVATE_KEY`; the caller decodes it and passes the
    /// bytes.
    ///
    /// # Errors
    ///
    /// [`KeyError::Parse`] if the scalar is zero or not below the curve
    /// order, neither of which is a usable private key.
    pub fn from_scalar(scalar: &[u8; 32]) -> Result<Self, KeyError> {
        SigningKey::from_slice(scalar)
            .map(|key| Self { key })
            .map_err(|err| KeyError::parse("ES256", err))
    }

    /// Signs `header`/`claims` into a compact JWS.
    ///
    /// The caller owns the claims because they differ per provider: APNs
    /// wants `iss`/`iat`, VAPID wants `aud`/`sub`/`exp`. `alg` and `kid`
    /// belong in `header`.
    #[must_use]
    pub fn sign_jwt(&self, header: &Value, claims: &Value) -> String {
        let input = signing_input(header, claims);
        // ES256 is a fixed 64-byte r||s signature — exactly JWS's encoding,
        // so there is no DER to unwrap.
        let signature: p256::ecdsa::Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    /// The public key as an uncompressed SEC1 point (`0x04 || x || y`), the
    /// form VAPID sends as `k=` and a JWKS splits into `x`/`y`.
    #[must_use]
    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        let point = self.key.verifying_key().to_encoded_point(false);
        let mut out = [0u8; 65];
        // An uncompressed P-256 point is always 65 bytes.
        out.copy_from_slice(point.as_bytes());
        out
    }
}

impl std::fmt::Debug for Es256Signer {
    /// Never prints the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Es256Signer { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;
    use serde_json::json;

    // A throwaway P-256 key, generated for these tests only — NOT an Apple
    // key. The same one `crates/adapter-apns/tests/apns.rs` uses, so the two
    // suites assert the same bytes.
    const TEST_P8: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcXMgRpW+eLn7ZvCx\nIuTdd8csWMZ69azlRzS0dy2FN6GhRANCAATJ6GazR2lhWcC3JYsazLR0uWOyDKrC\nmeP4HPWghRmfoa4z3Ux7mG3Ylz+auRaBukKGicSdSvVG+jGeQwr3fNag\n-----END PRIVATE KEY-----";

    #[test]
    fn rejects_a_pem_that_is_not_a_key() {
        let error = Es256Signer::from_p8_pem("not a key").unwrap_err();
        assert!(error.to_string().contains("ES256"), "{error}");
    }

    #[test]
    fn signs_a_verifiable_jwt() {
        let signer = Es256Signer::from_p8_pem(TEST_P8).unwrap();
        let jwt = signer.sign_jwt(
            &json!({ "alg": "ES256", "kid": "ABC1234567" }),
            &json!({ "iss": "TEAM987654", "iat": 1_700_000_000 }),
        );

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "header.claims.signature");

        // The signature verifies against the key's own public half.
        let verifying = signer.key.verifying_key();
        let signature = p256::ecdsa::Signature::from_slice(
            &URL_SAFE_NO_PAD.decode(parts[2]).expect("base64url"),
        )
        .expect("64-byte r||s");
        let input = format!("{}.{}", parts[0], parts[1]);
        verifying
            .verify(input.as_bytes(), &signature)
            .expect("the JWT verifies under its own key");
    }

    /// RFC 6979 makes ES256 deterministic here, so the token is a fixed
    /// string — the strongest form of "this did not silently change".
    #[test]
    fn the_token_is_a_fixed_string_for_a_fixed_key_and_claims() {
        let signer = Es256Signer::from_p8_pem(TEST_P8).unwrap();
        let jwt = signer.sign_jwt(
            &json!({ "alg": "ES256", "kid": "ABC1234567" }),
            &json!({ "iss": "TEAM987654", "iat": 1_700_000_000 }),
        );
        assert_eq!(
            jwt,
            "eyJhbGciOiJFUzI1NiIsImtpZCI6IkFCQzEyMzQ1NjcifQ.\
             eyJpc3MiOiJURUFNOTg3NjU0IiwiaWF0IjoxNzAwMDAwMDAwfQ.\
             FLaMDTVoUcLQhdV3iub8kZEpb2FRTQcrjNgvBvt8mIdsVi6hnRSrdAgbM06sQEsGKInnfX_M1sknBYJIsrAH0Q"
        );
    }

    /// The PKCS#8 wrapper carries the same scalar, so a signer built from
    /// the bare scalar must be the *same* signer — that is what lets a VAPID
    /// key be configured in either form (issue #180).
    #[test]
    fn a_bare_scalar_and_its_pkcs8_wrapper_are_the_same_key() {
        let from_pem = Es256Signer::from_p8_pem(TEST_P8).unwrap();
        let scalar: [u8; 32] = from_pem.key.to_bytes().into();
        let from_scalar = Es256Signer::from_scalar(&scalar).unwrap();

        assert_eq!(
            from_scalar.public_key_uncompressed(),
            from_pem.public_key_uncompressed()
        );
        let header = json!({ "alg": "ES256" });
        let claims = json!({ "sub": "mailto:ops@example.test" });
        assert_eq!(
            from_scalar.sign_jwt(&header, &claims),
            from_pem.sign_jwt(&header, &claims)
        );
    }

    #[test]
    fn a_scalar_that_is_not_a_private_key_is_refused() {
        // Zero is not a valid P-256 scalar, and neither is the curve order
        // itself (n, from FIPS 186-4 D.1.2.3) or anything above it.
        let error = Es256Signer::from_scalar(&[0u8; 32]).unwrap_err();
        assert!(error.to_string().contains("ES256"), "{error}");
        let order = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        assert!(Es256Signer::from_scalar(&order).is_err());
    }

    #[test]
    fn the_public_key_is_an_uncompressed_sec1_point() {
        let signer = Es256Signer::from_p8_pem(TEST_P8).unwrap();
        let point = signer.public_key_uncompressed();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04, "uncompressed marker");
        // It is the public half of this key: signing with the private key
        // verifies under a key rebuilt from these bytes.
        let verifying =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("valid SEC1 point");
        assert_eq!(&verifying, signer.key.verifying_key());
    }
}
