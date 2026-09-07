//! `LocalFileKms` — the provider for development and tests (issue #40).
//!
//! It wraps data keys under a master key read from a file, with the same
//! AEAD the envelope layer uses (XChaCha20-Poly1305, ADR 0102). That is
//! a real cipher, but a master key on a local disk is not a managed KMS:
//! it can be read, copied and backed up by anything that can read the
//! file, which is the property a KMS exists to remove. So it **refuses
//! to construct in production**.

use std::path::Path;

use base64::Engine as _;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use zeroize::Zeroize;

use crate::{DEK_LEN, Dek, Kms, KmsError};

/// Domain separation, so a blob produced here can never be mistaken for
/// a secret ciphertext from the envelope layer even under the same key.
const WRAP_AAD: &[u8] = b"FZ-KMS-LOCAL-WRAP-v1";
const NONCE_LEN: usize = 24;

/// A KEK read from a file. See the module docs for why it refuses
/// production.
pub struct LocalFileKms {
    kek: Dek,
    key_ref: String,
}

impl std::fmt::Debug for LocalFileKms {
    /// Names the key file, never its contents. Written by hand rather
    /// than derived so it cannot start printing key material because a
    /// field was added.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalFileKms")
            .field("provider", &"local-file")
            .field("key_ref", &self.key_ref)
            .finish_non_exhaustive()
    }
}

impl LocalFileKms {
    /// Reads the master key from `path`.
    ///
    /// `env` is the deployment environment, as
    /// `cratefield_core::VentureEnv` spells it: anything equal to
    /// `"production"` (case-insensitively) is refused. The environment
    /// is a parameter rather than read from the process here, so the
    /// refusal cannot be sidestepped by unsetting a variable, and so the
    /// caller passes the same value it validated everything else with.
    ///
    /// The file holds 32 raw bytes, or their hex or base64 encoding on
    /// one line; a trailing newline is ignored, because the difference
    /// between `printf` and `echo` should not be a cryptographic event.
    ///
    /// # Errors
    ///
    /// [`KmsError::Refused`] in production, [`KmsError::Unavailable`]
    /// when the file cannot be read, [`KmsError::Invalid`] when its
    /// contents are not a 32-byte key.
    pub fn open(path: impl AsRef<Path>, env: &str) -> Result<Self, KmsError> {
        if env.eq_ignore_ascii_case("production") {
            return Err(KmsError::Refused(
                "LocalFileKms holds its master key on local disk, where anything that can read \
                 the file can read the key. It is for development and tests. Configure a managed \
                 KMS provider for production"
                    .to_owned(),
            ));
        }
        let path = path.as_ref();
        let raw = std::fs::read(path).map_err(|err| {
            KmsError::Unavailable(format!(
                "cannot read the master key at {}: {err}",
                path.display()
            ))
        })?;
        let kek = parse_key(raw).map_err(|err| {
            KmsError::Invalid(format!("the master key at {}: {err}", path.display()))
        })?;
        Ok(Self {
            kek,
            key_ref: path.display().to_string(),
        })
    }

    /// A KEK the caller already holds, for tests that do not want a
    /// file. Refuses production for the same reason.
    ///
    /// # Errors
    ///
    /// [`KmsError::Refused`] in production.
    pub fn from_key(kek: Dek, key_ref: impl Into<String>, env: &str) -> Result<Self, KmsError> {
        if env.eq_ignore_ascii_case("production") {
            return Err(KmsError::Refused(
                "LocalFileKms is for development and tests".to_owned(),
            ));
        }
        Ok(Self {
            kek,
            key_ref: key_ref.into(),
        })
    }

    /// Writes a fresh master key to `path` for a development
    /// environment. Refuses to overwrite: losing a KEK means losing
    /// every secret wrapped under it, so the destructive version of this
    /// is a human deleting the file on purpose.
    ///
    /// # Errors
    ///
    /// [`KmsError::Refused`] when the file exists,
    /// [`KmsError::Unavailable`] when it cannot be written.
    pub fn create(path: impl AsRef<Path>) -> Result<(), KmsError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(KmsError::Refused(format!(
                "{} exists; every secret wrapped under it would become unreadable. Delete it \
                 deliberately if that is what you mean",
                path.display()
            )));
        }
        let dek = Dek::generate()?;
        let mut hex = String::with_capacity(DEK_LEN * 2);
        for byte in dek.expose() {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        let result = std::fs::write(path, format!("{hex}\n")).map_err(|err| {
            KmsError::Unavailable(format!("cannot write {}: {err}", path.display()))
        });
        hex.zeroize();
        result
    }
}

/// 32 raw bytes, or hex, or base64, with surrounding whitespace ignored.
fn parse_key(raw: Vec<u8>) -> Result<Dek, String> {
    if raw.len() == DEK_LEN {
        return Dek::from_bytes(raw).map_err(|err| err.to_string());
    }
    let text = String::from_utf8(raw)
        .map_err(|_| format!("is not {DEK_LEN} raw bytes and not valid text"))?;
    let text = text.trim();
    if text.len() == DEK_LEN * 2
        && let Ok(bytes) = decode_hex(text)
    {
        return Dek::from_bytes(bytes).map_err(|err| err.to_string());
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(text.as_bytes())
        && bytes.len() == DEK_LEN
    {
        return Dek::from_bytes(bytes).map_err(|err| err.to_string());
    }
    Err(format!(
        "is not a {DEK_LEN}-byte key: expected {DEK_LEN} raw bytes, {} hex characters, or base64",
        DEK_LEN * 2
    ))
}

fn decode_hex(text: &str) -> Result<Vec<u8>, ()> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(());
    }
    let mut out = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let hi = (pair[0] as char).to_digit(16).ok_or(())?;
        let lo = (pair[1] as char).to_digit(16).ok_or(())?;
        out.push(u8::try_from(hi * 16 + lo).map_err(|_| ())?);
    }
    Ok(out)
}

#[async_trait]
impl Kms for LocalFileKms {
    fn provider(&self) -> &'static str {
        "local-file"
    }

    fn key_ref(&self) -> &str {
        &self.key_ref
    }

    async fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, KmsError> {
        let cipher = self.cipher()?;
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|err| KmsError::Unavailable(format!("the OS random source failed: {err}")))?;
        let sealed = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: dek.expose(),
                    aad: WRAP_AAD,
                },
            )
            .map_err(|_| KmsError::Invalid("the data key could not be wrapped".to_owned()))?;
        let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    async fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, KmsError> {
        if wrapped.len() <= NONCE_LEN {
            return Err(KmsError::Tampered(
                "the wrapped key is too short to contain a nonce and a tag".to_owned(),
            ));
        }
        let (nonce, sealed) = wrapped.split_at(NONCE_LEN);
        let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");
        let opened = self
            .cipher()?
            .decrypt(
                nonce.into(),
                Payload {
                    msg: sealed,
                    aad: WRAP_AAD,
                },
            )
            .map_err(|_| {
                KmsError::Tampered(
                    "the wrapped key did not authenticate under this master key".to_owned(),
                )
            })?;
        Dek::from_bytes(opened)
    }
}

impl LocalFileKms {
    fn cipher(&self) -> Result<chacha20poly1305::XChaCha20Poly1305, KmsError> {
        chacha20poly1305::XChaCha20Poly1305::new_from_slice(self.kek.expose())
            .map_err(|_| KmsError::Invalid("the master key is not 32 bytes".to_owned()))
    }
}
