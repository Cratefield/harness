//! One [`EnvelopeAead`] implementation per candidate (#38), plus the
//! `age` demo. Each backend wraps ONLY the AEAD operation — the envelope
//! path, AAD computation and caching live in [`crate::store`] and are
//! shared, so the candidates are scored on exactly the same usage.

use crate::{AeadError, Dek, EnvelopeAead};

// ---------------------------------------------------------------------------
// aws-lc-rs — ring-compatible API over AWS's aws-lc (BoringSSL fork).
// C code via aws-lc-sys (cmake + C compiler). Optional FIPS build.
// ---------------------------------------------------------------------------
#[cfg(feature = "aws-lc-backend")]
pub mod aws_lc {
    use super::*;

    /// Generic adapter over aws-lc-rs's ring-style API.
    pub struct AwsLcAead {
        alg: &'static aws_lc_rs::aead::Algorithm,
        name: &'static str,
    }

    impl AwsLcAead {
        pub const fn aes_256_gcm() -> Self {
            Self {
                alg: &aws_lc_rs::aead::AES_256_GCM,
                name: "aws-lc-rs AES-256-GCM",
            }
        }
        pub const fn chacha20_poly1305() -> Self {
            Self {
                alg: &aws_lc_rs::aead::CHACHA20_POLY1305,
                name: "aws-lc-rs ChaCha20-Poly1305",
            }
        }

        fn key(&self, key: &Dek) -> Result<aws_lc_rs::aead::LessSafeKey, AeadError> {
            let unbound = aws_lc_rs::aead::UnboundKey::new(self.alg, key.as_slice())
                .map_err(|_| AeadError)?;
            Ok(aws_lc_rs::aead::LessSafeKey::new(unbound))
        }
    }

    impl EnvelopeAead for AwsLcAead {
        fn name(&self) -> &'static str {
            self.name
        }

        fn nonce_len(&self) -> usize {
            self.alg.nonce_len()
        }

        fn seal(
            &self,
            key: &Dek,
            nonce: &[u8],
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, AeadError> {
            if nonce.len() != self.nonce_len() {
                return Err(AeadError);
            }
            let key = self.key(key)?;
            let nonce =
                aws_lc_rs::aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| AeadError)?;
            let mut in_out = plaintext.to_vec();
            let tag = key
                .seal_in_place_separate_tag(nonce, aws_lc_rs::aead::Aad::from(aad), &mut in_out)
                .map_err(|_| AeadError)?;
            in_out.extend_from_slice(tag.as_ref());
            Ok(in_out)
        }

        fn open(
            &self,
            key: &Dek,
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, AeadError> {
            if nonce.len() != self.nonce_len() {
                return Err(AeadError);
            }
            let key = self.key(key)?;
            let nonce =
                aws_lc_rs::aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| AeadError)?;
            let mut in_out = ciphertext.to_vec();
            let plaintext = key
                .open_in_place(nonce, aws_lc_rs::aead::Aad::from(aad), &mut in_out)
                .map_err(|_| AeadError)?;
            Ok(plaintext.to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// ring 0.17 — the API aws-lc-rs mirrors. No XChaCha20-Poly1305 algorithm,
// no zeroisation of key material on drop (scored in ADR 0102).
// ---------------------------------------------------------------------------
#[cfg(feature = "ring-backend")]
pub mod ring_backend {
    use super::*;

    pub struct RingAead {
        alg: &'static ring::aead::Algorithm,
        name: &'static str,
    }

    impl RingAead {
        pub const fn aes_256_gcm() -> Self {
            Self {
                alg: &ring::aead::AES_256_GCM,
                name: "ring AES-256-GCM",
            }
        }
        pub const fn chacha20_poly1305() -> Self {
            Self {
                alg: &ring::aead::CHACHA20_POLY1305,
                name: "ring ChaCha20-Poly1305",
            }
        }

        fn key(&self, key: &Dek) -> Result<ring::aead::LessSafeKey, AeadError> {
            let unbound =
                ring::aead::UnboundKey::new(self.alg, key.as_slice()).map_err(|_| AeadError)?;
            Ok(ring::aead::LessSafeKey::new(unbound))
        }
    }

    impl EnvelopeAead for RingAead {
        fn name(&self) -> &'static str {
            self.name
        }

        fn nonce_len(&self) -> usize {
            self.alg.nonce_len()
        }

        fn seal(
            &self,
            key: &Dek,
            nonce: &[u8],
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, AeadError> {
            if nonce.len() != self.nonce_len() {
                return Err(AeadError);
            }
            let key = self.key(key)?;
            let nonce =
                ring::aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| AeadError)?;
            let mut in_out = plaintext.to_vec();
            let tag = key
                .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(aad), &mut in_out)
                .map_err(|_| AeadError)?;
            in_out.extend_from_slice(tag.as_ref());
            Ok(in_out)
        }

        fn open(
            &self,
            key: &Dek,
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, AeadError> {
            if nonce.len() != self.nonce_len() {
                return Err(AeadError);
            }
            let key = self.key(key)?;
            let nonce =
                ring::aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| AeadError)?;
            let mut in_out = ciphertext.to_vec();
            let plaintext = key
                .open_in_place(nonce, ring::aead::Aad::from(aad), &mut in_out)
                .map_err(|_| AeadError)?;
            Ok(plaintext.to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// RustCrypto: chacha20poly1305 (XChaCha20-Poly1305) and aes-gcm
// (AES-256-GCM). Pure Rust; `zeroize` feature zeroes key material on drop.
// ---------------------------------------------------------------------------
#[cfg(feature = "rustcrypto")]
pub mod rustcrypto {
    use super::*;
    use aes_gcm::KeyInit as _;
    use aes_gcm::aead::Aead as _;

    /// XChaCha20-Poly1305 — 192-bit nonce.
    pub struct XChaCha20Poly1305Aead;

    impl EnvelopeAead for XChaCha20Poly1305Aead {
        fn name(&self) -> &'static str {
            "RustCrypto XChaCha20-Poly1305"
        }

        fn nonce_len(&self) -> usize {
            24
        }

        fn seal(
            &self,
            key: &Dek,
            nonce: &[u8],
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, AeadError> {
            if nonce.len() != 24 {
                return Err(AeadError);
            }
            let cipher = chacha20poly1305::XChaCha20Poly1305::new(
                &chacha20poly1305::Key::try_from(key.as_slice()).map_err(|_| AeadError)?,
            );
            let nonce = chacha20poly1305::XNonce::try_from(nonce).map_err(|_| AeadError)?;
            cipher
                .encrypt(
                    &nonce,
                    chacha20poly1305::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| AeadError)
        }

        fn open(
            &self,
            key: &Dek,
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, AeadError> {
            if nonce.len() != 24 {
                return Err(AeadError);
            }
            let cipher = chacha20poly1305::XChaCha20Poly1305::new(
                &chacha20poly1305::Key::try_from(key.as_slice()).map_err(|_| AeadError)?,
            );
            let nonce = chacha20poly1305::XNonce::try_from(nonce).map_err(|_| AeadError)?;
            cipher
                .decrypt(
                    &nonce,
                    chacha20poly1305::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| AeadError)
        }
    }

    /// AES-256-GCM — 96-bit nonce.
    pub struct Aes256GcmAead;

    impl EnvelopeAead for Aes256GcmAead {
        fn name(&self) -> &'static str {
            "RustCrypto AES-256-GCM"
        }

        fn nonce_len(&self) -> usize {
            12
        }

        fn seal(
            &self,
            key: &Dek,
            nonce: &[u8],
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, AeadError> {
            if nonce.len() != 12 {
                return Err(AeadError);
            }
            let cipher = aes_gcm::Aes256Gcm::new(
                &aes_gcm::Key::<aes_gcm::Aes256Gcm>::try_from(key.as_slice())
                    .map_err(|_| AeadError)?,
            );
            let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| AeadError)?;
            cipher
                .encrypt(
                    &nonce,
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| AeadError)
        }

        fn open(
            &self,
            key: &Dek,
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, AeadError> {
            if nonce.len() != 12 {
                return Err(AeadError);
            }
            let cipher = aes_gcm::Aes256Gcm::new(
                &aes_gcm::Key::<aes_gcm::Aes256Gcm>::try_from(key.as_slice())
                    .map_err(|_| AeadError)?,
            );
            let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| AeadError)?;
            cipher
                .decrypt(
                    &nonce,
                    aes_gcm::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| AeadError)
        }
    }
}

// ---------------------------------------------------------------------------
// age — scored once, expected elimination. It is a file-encryption FORMAT
// built on X25519 recipients (encrypt-to-person), not a symmetric envelope
// primitive:
//
//   * seal/open are keyed by an X25519 recipient/identity pair, not by the
//     DEK the envelope design wraps;
//   * there is NO caller-supplied AAD — the authenticated header is the
//     age header itself, so a ciphertext carries no binding to store,
//     name, version or key id (proven in tests/roundtrip.rs: context swap
//     does NOT fail decryption);
//   * the payload is a streaming format (header + 64 KiB chunks), not a
//     single sealed box.
// ---------------------------------------------------------------------------
#[cfg(feature = "age-backend")]
pub mod age_backend {
    use std::io::{Read, Write};

    /// Demo-only pairing of a generated X25519 recipient and identity. A
    /// real envelope has no such pairing — this exists to run the design's
    /// round trip against age and record where the model breaks.
    pub struct AgeDemo {
        recipient: age::x25519::Recipient,
        identity: age::x25519::Identity,
    }

    impl AgeDemo {
        pub fn generate() -> Self {
            let identity = age::x25519::Identity::generate();
            let recipient = identity.to_public();
            Self {
                recipient,
                identity,
            }
        }

        /// "Encrypt": seal to the recipient. No AAD parameter exists.
        pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
            let encryptor = age::Encryptor::with_recipients(std::iter::once(
                &self.recipient as &dyn age::Recipient,
            ))
            .expect("age encryptor");
            let mut out = Vec::new();
            let mut writer = encryptor.wrap_output(&mut out).expect("age header");
            writer.write_all(plaintext).expect("age write");
            writer.finish().expect("age finish");
            out
        }

        /// "Decrypt": open with the identity. `aad` is accepted and
        /// IGNORED — age has no AAD, which is the elimination point.
        pub fn open(&self, ciphertext: &[u8], _aad: &[u8]) -> Vec<u8> {
            let decryptor = age::Decryptor::new(ciphertext).expect("age decryptor");
            let mut reader = decryptor
                .decrypt(std::iter::once(&self.identity as &dyn age::Identity))
                .expect("age decrypt");
            let mut plaintext = Vec::new();
            reader.read_to_end(&mut plaintext).expect("age read");
            plaintext
        }
    }
}
