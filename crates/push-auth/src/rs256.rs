//! RS256 (RSASSA-PKCS1-v1_5 + SHA-256) service-account JWTs: Google's
//! OAuth 2.0 server-to-server flow, which FCM v1 needs for its bearer token.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use serde_json::Value;

use crate::{KeyError, signing_input};

/// Signs RS256 JWTs with an RSA private key.
///
/// Google's service-account JSON ships its key as PKCS#8
/// (`-----BEGIN PRIVATE KEY-----`); older exports and other providers use the
/// legacy PKCS#1 form (`-----BEGIN RSA PRIVATE KEY-----`). [`Self::from_pem`]
/// takes either, so a venture never has to know which it was handed.
///
/// PKCS#1 v1.5 signing is deterministic and takes no RNG, which is what lets
/// this run on a Workers isolate.
pub struct Rs256Signer {
    key: SigningKey<Sha256>,
}

impl Rs256Signer {
    /// Parses a PKCS#8 PEM RSA private key — the form Google's
    /// service-account JSON carries in `private_key`.
    ///
    /// # Errors
    ///
    /// [`KeyError::Parse`] if the PEM is not a PKCS#8 RSA private key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, KeyError> {
        rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .map(|key| Self {
                key: SigningKey::new(key),
            })
            .map_err(|err| KeyError::parse("RS256", err))
    }

    /// Parses the legacy PKCS#1 PEM form
    /// (`-----BEGIN RSA PRIVATE KEY-----`).
    ///
    /// # Errors
    ///
    /// [`KeyError::Parse`] if the PEM is not a PKCS#1 RSA private key.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, KeyError> {
        rsa::RsaPrivateKey::from_pkcs1_pem(pem)
            .map(|key| Self {
                key: SigningKey::new(key),
            })
            .map_err(|err| KeyError::parse("RS256", err))
    }

    /// Parses either PEM form, choosing by the label so the error a caller
    /// sees names the format they actually supplied.
    ///
    /// # Errors
    ///
    /// [`KeyError::Parse`] if the PEM is neither a PKCS#8 nor a PKCS#1 RSA
    /// private key.
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        if pem.contains("BEGIN RSA PRIVATE KEY") {
            Self::from_pkcs1_pem(pem)
        } else {
            Self::from_pkcs8_pem(pem)
        }
    }

    /// Signs `header`/`claims` into a compact JWS.
    #[must_use]
    pub fn sign_jwt(&self, header: &Value, claims: &Value) -> String {
        let input = signing_input(header, claims);
        let signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

impl std::fmt::Debug for Rs256Signer {
    /// Never prints the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rs256Signer { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::sha2::Digest as _;
    use rsa::traits::PublicKeyParts as _;
    use serde_json::json;

    // Throwaway 2048-bit RSA keys, generated for these tests only. The two
    // PEMs are the SAME key in the two encodings Google and its older
    // exports use, so `from_pem` can be asserted to reach one signer.
    const TEST_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCgQ/qAORkSKZjW
xMCbrhGXqbVCHpslcKpb3Ew/5qpRclIDXmJcaXehqY4swKuYdyqcQloRH5inZ/6U
DR/p72s+6Gu5ExAje64hw2AChozIdmKA/xZYxPjQ5AtFXLofTglg1VeudH+6/bDw
sXKGsaqRPWghb0lc1cai0ETHZDfP9frfJKjJRm2HlZqp8CKwwl1Jy6CQOGrjKlQX
ThV07JKPpRPTZFscZTMzjG9fIfYCcxWt7c7HcPN4G7QUrx4oEX/jkuJcA2zgQ0WL
0gJ4IKUc1BiNDP67UniFq8bxlcqePQc8MN3bBDrPKktX24u9ZJJZjx6otgBIWCaB
nIKyuyfzAgMBAAECggEAS0Af+tzUfMazUQSJO4/8Cq5QwX8Fcgr4srE5zDdOeXeo
MpS6spGC7pFihHjjGW+6viwZhjjDwLb/vhx7g6g7Pwp6qifdSAvms0u9ZPIwYF/V
2KPtpji2a77n2+WyLsjBdoo15WAmKXK9BgcLs1rwr8mZfzl1xPVLk18fLFBONIKY
ySiiGRQC2NZXfAEZF/pDMaBT5+my7hjZkw07XMrV//DnR71Gre2IPj0SNPWjS+Fd
qMQq5UvxaJxLP6dDswYqXNvoWC7YAlsnf9ySD3ykLThATh4yUCL6y97wvKEdU9yb
1mruLpOGNCnjCDqx+spY49qt+3uWBcj2BXjAPUlQoQKBgQDPOLZSz772jquTiyk0
4OiUkCofmhLdpKU/vJW6TWGjGWv3MSUvi1wA5q/AByljCtr+/lwzkj1c9/6Hzo0N
zv0kagaVRmb5INhTEu+1957lBP/WucHOvKPhiUvLjiH0YTqFSl+uB5ZbzbIxMOko
T86cq9/qFkOl3BhR8CFoRWwbbwKBgQDF/avnjCFOEVzluU+FnNepR36mZWlhQPNt
xT/wlavbPVQbIYbUJ4vKaU2OjIRE0fPJiC/XXEdD74LeX3gfoufau/M3hSmUDLoq
DZCng5zGKtOlPMLQkf0Q2xVesM5eCJ2dPWZDR8jgkoXaLRa1YIFUofl24AkeabqO
u56pgEwJvQKBgAaN+65o5dh0sNas6zPB/XldigeP3xLlt1hpxa6r7e+zySd7hXqY
hON+aIbBczyvxjeUoiP7dzdunL18+hc6ueUh+W1VWcJ9mHogOjbeS0dhPhpzq763
VtO2fRBGQaqyPKCktpwRn17uBbnqmyVsSNPJ1/5Wj/M6IAbPeq8Kqx2/AoGAPy6u
lxu+3RzpWl4CpI7iu6CXKB6gvGpvxI3305zP1Q0DNA1E65sbHyLvnxf0dcnSVHPj
YISQMXvTdYdd3Cqudr0X5pXWKOrO1fCyQuLbOtob5FU5jjmoWqKvdSJTGOsC8VTQ
t5PG5POdR3ywDH2ZiBqQc4EXJ99xq27wOQM6QLkCgYB9f9GrE+DQIYBzb7hf1SMz
ELvz+3ijy43njvIg4CihiUAzIuc0VJaVCKZcxIMZxLoDB6roeLoYBS+GhVrMoHUj
mbv4voW/HXdaIlZUbMa0y9q0cg3Q8oaw5bwSzrSZxEkadudn4+MFKbLRvmYFX7We
6OmL9MfIa/kocbiIIu0TSA==
-----END PRIVATE KEY-----";

    const TEST_PKCS1: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAoEP6gDkZEimY1sTAm64Rl6m1Qh6bJXCqW9xMP+aqUXJSA15i
XGl3oamOLMCrmHcqnEJaER+Yp2f+lA0f6e9rPuhruRMQI3uuIcNgAoaMyHZigP8W
WMT40OQLRVy6H04JYNVXrnR/uv2w8LFyhrGqkT1oIW9JXNXGotBEx2Q3z/X63ySo
yUZth5WaqfAisMJdScugkDhq4ypUF04VdOySj6UT02RbHGUzM4xvXyH2AnMVre3O
x3DzeBu0FK8eKBF/45LiXANs4ENFi9ICeCClHNQYjQz+u1J4havG8ZXKnj0HPDDd
2wQ6zypLV9uLvWSSWY8eqLYASFgmgZyCsrsn8wIDAQABAoIBAEtAH/rc1HzGs1EE
iTuP/AquUMF/BXIK+LKxOcw3Tnl3qDKUurKRgu6RYoR44xlvur4sGYY4w8C2/74c
e4OoOz8Keqon3UgL5rNLvWTyMGBf1dij7aY4tmu+59vlsi7IwXaKNeVgJilyvQYH
C7Na8K/JmX85dcT1S5NfHyxQTjSCmMkoohkUAtjWV3wBGRf6QzGgU+fpsu4Y2ZMN
O1zK1f/w50e9Rq3tiD49EjT1o0vhXajEKuVL8WicSz+nQ7MGKlzb6Fgu2AJbJ3/c
kg98pC04QE4eMlAi+sve8LyhHVPcm9Zq7i6ThjQp4wg6sfrKWOParft7lgXI9gV4
wD1JUKECgYEAzzi2Us++9o6rk4spNODolJAqH5oS3aSlP7yVuk1hoxlr9zElL4tc
AOavwAcpYwra/v5cM5I9XPf+h86NDc79JGoGlUZm+SDYUxLvtfee5QT/1rnBzryj
4YlLy44h9GE6hUpfrgeWW82yMTDpKE/OnKvf6hZDpdwYUfAhaEVsG28CgYEAxf2r
54whThFc5blPhZzXqUd+pmVpYUDzbcU/8JWr2z1UGyGG1CeLymlNjoyERNHzyYgv
11xHQ++C3l94H6Ln2rvzN4UplAy6Kg2Qp4OcxirTpTzC0JH9ENsVXrDOXgidnT1m
Q0fI4JKF2i0WtWCBVKH5duAJHmm6jrueqYBMCb0CgYAGjfuuaOXYdLDWrOszwf15
XYoHj98S5bdYacWuq+3vs8kne4V6mITjfmiGwXM8r8Y3lKIj+3c3bpy9fPoXOrnl
IfltVVnCfZh6IDo23ktHYT4ac6u+t1bTtn0QRkGqsjygpLacEZ9e7gW56pslbEjT
ydf+Vo/zOiAGz3qvCqsdvwKBgD8urpcbvt0c6VpeAqSO4ruglygeoLxqb8SN99Oc
z9UNAzQNROubGx8i758X9HXJ0lRz42CEkDF703WHXdwqrna9F+aV1ijqztXwskLi
2zraG+RVOY45qFqir3UiUxjrAvFU0LeTxuTznUd8sAx9mYgakHOBFyffcatu8DkD
OkC5AoGAfX/RqxPg0CGAc2+4X9UjMxC78/t4o8uN547yIOAooYlAMyLnNFSWlQim
XMSDGcS6Aweq6Hi6GAUvhoVazKB1I5m7+L6Fvx13WiJWVGzGtMvatHIN0PKGsOW8
Es60mcRJGnbnZ+PjBSmy0b5mBV+1nujpi/THyGv5KHG4iCLtE0g=
-----END RSA PRIVATE KEY-----";

    fn claims() -> (Value, Value) {
        (
            json!({ "alg": "RS256", "typ": "JWT" }),
            json!({
                "iss": "svc@project.iam.gserviceaccount.com",
                "scope": "https://www.googleapis.com/auth/firebase.messaging",
                "aud": "https://oauth2.googleapis.com/token",
                "iat": 1_700_000_000,
                "exp": 1_700_003_600,
            }),
        )
    }

    #[test]
    fn signs_a_jwt_that_verifies_under_pkcs1v15() {
        let signer = Rs256Signer::from_pkcs8_pem(TEST_PKCS8).unwrap();
        let (header, payload) = claims();
        let jwt = signer.sign_jwt(&header, &payload);

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "header.claims.signature");
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).expect("base64url");
        let public = rsa::RsaPublicKey::from(signer.key.as_ref());
        assert_eq!(signature.len(), public.size(), "a full-width RSA signature");

        // Verified the long way round — `Pkcs1v15Sign` over the SHA-256
        // digest of the signing input — so the test does not just re-run the
        // code it is testing.
        let digest = rsa::sha2::Sha256::digest(format!("{}.{}", parts[0], parts[1]).as_bytes());
        public
            .verify(
                rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
                &digest,
                &signature,
            )
            .expect("the JWT verifies under the matching public key");
    }

    #[test]
    fn both_pem_encodings_parse_to_the_same_key() {
        let (header, payload) = claims();
        let from_pkcs8 = Rs256Signer::from_pem(TEST_PKCS8).unwrap();
        let from_pkcs1 = Rs256Signer::from_pem(TEST_PKCS1).unwrap();
        // PKCS#1 v1.5 is deterministic, so the same key over the same input
        // is the same token, byte for byte.
        assert_eq!(
            from_pkcs8.sign_jwt(&header, &payload),
            from_pkcs1.sign_jwt(&header, &payload)
        );
    }

    #[test]
    fn rejects_a_pem_that_is_not_a_key() {
        let error = Rs256Signer::from_pem(
            "-----BEGIN RSA PRIVATE KEY-----\nnope\n-----END RSA PRIVATE KEY-----",
        )
        .unwrap_err();
        assert!(error.to_string().contains("RS256"), "{error}");
        let error = Rs256Signer::from_pem("not a key at all").unwrap_err();
        assert!(error.to_string().contains("RS256"), "{error}");
    }
}
