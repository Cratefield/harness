//! The wire record, and the validation the server does on the way in.
//!
//! Kept in lockstep with `packages/sealed/src` (`types.ts`, `aad.ts`,
//! `keys.ts`), which is the contract: `snake_case` JSON, unpadded base64url
//! for every binary field, and the same grammars for `blob_id`, `purpose`
//! and `version`. The server treats `ciphertext` and every `wrapped_key` as
//! opaque — validated for shape, never opened.

use serde::{Deserialize, Serialize};

use crate::SealedError;

/// The one payload algorithm this version of the store accepts.
pub const PAYLOAD_ALG: &str = "A256GCM";
/// A passkey-PRF wrap's KEK derivation.
pub const PRF_WRAP_ALG: &str = "HKDF-SHA256+A256KW";
/// A recovery-code wrap's KEK derivation.
pub const RECOVERY_WRAP_ALG: &str = "ARGON2ID+A256KW";

/// AES-KW output for a 256-bit key — the wire invariant on `wrapped_key`.
pub const WRAPPED_KEY_LEN: usize = 40;
/// A PRF evaluation input (`eval.first`), 32 bytes by WebAuthn convention.
pub const PRF_SALT_LEN: usize = 32;
/// An Argon2id salt, per wrap.
pub const RECOVERY_SALT_LEN: usize = 16;

/// An AES-GCM wire `ciphertext` is `nonce(12) || ciphertext || tag(16)`; it
/// can never be shorter than the framing.
pub const CIPHERTEXT_FLOOR: usize = 28;

/// The lowest Argon2id cost a recovery wrap may carry. Below it the wrap is
/// a downgrade — a record a thief could brute-force offline — and the whole
/// record is refused, exactly as the client refuses it.
pub const RECOVERY_FLOOR: RecoveryParams = RecoveryParams {
    m_kib: 65536,
    t: 3,
    p: 1,
};

/// Argon2id parameters for a recovery wrap (`m_kib` in KiB, `t` rounds, `p`
/// lanes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// One key wrap: the content key encrypted under one unlock's KEK. Opaque to
/// the server; `params` is present only on recovery wraps, and must be
/// absent (not `null`) on prf wraps, so it serialises away when `None`.
/// Unknown fields are refused: the wire format is closed, and a wrap the
/// server round-trips must be one it understood.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wrap {
    pub id: String,
    pub kind: String,
    pub alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<RecoveryParams>,
    pub salt: String,
    pub wrapped_key: String,
}

/// The body of `POST /blobs`, `PUT /blobs/{id}` (rotation) and the record a
/// read returns (plus subject and timestamps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateBlob {
    pub blob_id: String,
    pub version: u32,
    pub purpose: String,
    pub alg: String,
    pub ciphertext: String,
    pub wraps: Vec<Wrap>,
    pub created_by_credential: String,
}

/// `PUT /blobs/{id}/wraps`: wrap edits that never touch the payload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WrapEdit {
    pub version: u32,
    pub wraps: Vec<Wrap>,
}

/// Unpadded base64url, as the wire format defines it. Decoding is
/// *canonical*: the input must re-encode to itself, so a padded or
/// mixed-alphabet value is refused rather than silently rewritten — the
/// server returns stored fields byte-identically, which only holds when
/// what it stored is the canonical encoding.
pub fn b64url_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()?;
    let mut canonical = String::with_capacity(value.len());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(&decoded, &mut canonical);
    (canonical == value).then_some(decoded)
}

/// Unpadded base64url, the direction responses go.
#[must_use]
pub fn b64url_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `1..=64` of `[A-Za-z0-9_-]` — the grammar `aad.ts` enforces on both ends.
#[must_use]
pub fn is_blob_id(blob_id: &str) -> bool {
    (1..=64).contains(&blob_id.len())
        && blob_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `1..=64` of `[a-z0-9._-]`.
#[must_use]
pub fn is_purpose(purpose: &str) -> bool {
    (1..=64).contains(&purpose.len())
        && purpose.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        })
}

/// Validates one wrap against the wire invariants `keys.ts::assertWrapShape`
/// enforces: a known kind, the matching alg, canonical base64url fields of
/// the right lengths, and — for recovery — the Argon2id cost floor.
///
/// # Errors
///
/// [`SealedError::BadWrap`] for a shape violation, [`SealedError::WeakParams`]
/// for a below-floor recovery wrap.
pub fn validate_wrap(wrap: &Wrap) -> Result<(), SealedError> {
    let fail = |what: &str| SealedError::BadWrap(format!("wrap `{}`: {what}", wrap.id));
    let wrapped = b64url_decode(&wrap.wrapped_key)
        .ok_or_else(|| fail("wrapped_key is not canonical base64url"))?;
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err(fail(&format!(
            "wrapped_key must be {WRAPPED_KEY_LEN} bytes, got {}",
            wrapped.len()
        )));
    }
    match wrap.kind.as_str() {
        "prf" => {
            if wrap.alg != PRF_WRAP_ALG {
                return Err(fail(&format!(
                    "alg must be {PRF_WRAP_ALG}, got {}",
                    wrap.alg
                )));
            }
            if wrap.params.is_some() {
                return Err(fail("prf wraps carry no params"));
            }
            let salt =
                b64url_decode(&wrap.salt).ok_or_else(|| fail("salt is not canonical base64url"))?;
            if salt.len() != PRF_SALT_LEN {
                return Err(fail(&format!(
                    "salt must be {PRF_SALT_LEN} bytes, got {}",
                    salt.len()
                )));
            }
            Ok(())
        }
        "recovery" => {
            if wrap.alg != RECOVERY_WRAP_ALG {
                return Err(fail(&format!(
                    "alg must be {RECOVERY_WRAP_ALG}, got {}",
                    wrap.alg
                )));
            }
            let salt =
                b64url_decode(&wrap.salt).ok_or_else(|| fail("salt is not canonical base64url"))?;
            if salt.len() != RECOVERY_SALT_LEN {
                return Err(fail(&format!(
                    "salt must be {RECOVERY_SALT_LEN} bytes, got {}",
                    salt.len()
                )));
            }
            let params = wrap
                .params
                .ok_or_else(|| fail("recovery wrap is missing its params"))?;
            if params.m_kib < RECOVERY_FLOOR.m_kib
                || params.t < RECOVERY_FLOOR.t
                || params.p < RECOVERY_FLOOR.p
            {
                return Err(SealedError::WeakParams(format!(
                    "wrap `{}`: params m_kib={} t={} p={} are below the accepted floor \
                     m_kib>={} t>={} p>={} — refusing (downgrade protection)",
                    wrap.id,
                    params.m_kib,
                    params.t,
                    params.p,
                    RECOVERY_FLOOR.m_kib,
                    RECOVERY_FLOOR.t,
                    RECOVERY_FLOOR.p
                )));
            }
            Ok(())
        }
        other => Err(fail(&format!("unknown kind `{other}`"))),
    }
}

/// Validates a wrap set: at least two wraps (the store's own invariant — a
/// record below it is a bug or an attack, never something to serve), with
/// distinct ids, every one of them well-formed.
///
/// # Errors
///
/// [`SealedError::BadInput`] when the set is too small or an id repeats;
/// whatever [`validate_wrap`] answers for the first bad wrap.
pub fn validate_wraps(wraps: &[Wrap]) -> Result<(), SealedError> {
    if wraps.len() < 2 {
        return Err(SealedError::BadInput(format!(
            "a record carries at least 2 wraps, got {}",
            wraps.len()
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for wrap in wraps {
        if !seen.insert(wrap.id.as_str()) {
            return Err(SealedError::BadInput(format!(
                "duplicate wrap id `{}`",
                wrap.id
            )));
        }
        validate_wrap(wrap)?;
    }
    Ok(())
}

/// Validates a whole create/rotate body: the field grammars `aad.ts` enforces,
/// the one known payload alg, and a decodable payload. Everything is checked
/// before any row is written.
///
/// # Errors
///
/// [`SealedError::BadInput`] naming the first field that failed.
pub fn validate_create(blob: &CreateBlob) -> Result<(), SealedError> {
    if !is_blob_id(&blob.blob_id) {
        return Err(SealedError::BadInput(
            "blob_id must be 1-64 chars of [A-Za-z0-9_-]".into(),
        ));
    }
    if !is_purpose(&blob.purpose) {
        return Err(SealedError::BadInput(
            "purpose must be 1-64 chars of [a-z0-9._-]".into(),
        ));
    }
    if blob.version < 1 {
        return Err(SealedError::BadInput("version must be a u32 >= 1".into()));
    }
    if blob.alg != PAYLOAD_ALG {
        return Err(SealedError::BadInput(format!(
            "alg must be {PAYLOAD_ALG}, got {}",
            blob.alg
        )));
    }
    if blob.created_by_credential.is_empty() {
        return Err(SealedError::BadInput(
            "created_by_credential must be non-empty".into(),
        ));
    }
    validate_wraps(&blob.wraps)?;
    let ciphertext = b64url_decode(&blob.ciphertext)
        .ok_or_else(|| SealedError::BadInput("ciphertext is not canonical base64url".into()))?;
    if ciphertext.len() < CIPHERTEXT_FLOOR {
        return Err(SealedError::BadInput(format!(
            "ciphertext must be at least {CIPHERTEXT_FLOOR} bytes (nonce + tag), got {}",
            ciphertext.len()
        )));
    }
    Ok(())
}
