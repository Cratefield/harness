//! The HMAC-SHA256 reference `Signer` (ADR 0006, issue #3).
//!
//! Token format: `base64url(json).base64url(mac)` where the MAC is
//! computed over the **encoded** payload string — the exact bytes between
//! the dots — so a token has exactly one valid encoding. Key rotation:
//! `HARNESS_SECRET` plus optional `HARNESS_SECRET_PREVIOUS`; tokens name
//! their `kid`, verification tries the named key then the other, and MAC
//! comparison is constant-time (`subtle`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::ports::signer::{Kid, Payload, Signer};

type HmacSha256 = Hmac<Sha256>;

/// Minimum secret length. `HARNESS_SECRET` must be at least 32 bytes.
pub const MIN_SECRET_BYTES: usize = 32;

/// Errors from constructing an [`HmacSigner`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    #[error("harness secret must be at least {MIN_SECRET_BYTES} bytes")]
    SecretTooShort,
}

#[derive(Serialize, Deserialize)]
struct PayloadJson {
    purpose: String,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    exp: Option<u64>,
    kid: String,
}

/// HMAC-SHA256 signer over `HARNESS_SECRET` (+ optional previous).
#[derive(Debug, Clone)]
pub struct HmacSigner {
    cur: Vec<u8>,
    prev: Option<Vec<u8>>,
}

impl HmacSigner {
    /// # Errors
    ///
    /// [`SignerError::SecretTooShort`] when the current secret is shorter
    /// than [`MIN_SECRET_BYTES`].
    pub fn new(
        current_secret: impl Into<String>,
        previous_secret: Option<String>,
    ) -> Result<Self, SignerError> {
        let cur: Vec<u8> = current_secret.into().into_bytes();
        if cur.len() < MIN_SECRET_BYTES {
            return Err(SignerError::SecretTooShort);
        }
        Ok(Self {
            cur,
            prev: previous_secret.map(String::into_bytes),
        })
    }

    fn mac(key: &[u8], encoded_payload: &str) -> [u8; 32] {
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(encoded_payload.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        out
    }

    fn key_for(&self, kid: Kid) -> (&[u8], Option<Kid>) {
        match (kid, self.prev.as_deref()) {
            (Kid::Cur, Some(_)) => (&self.cur, Some(Kid::Prev)),
            (Kid::Prev, Some(prev)) => (prev, Some(Kid::Cur)),
            (Kid::Cur | Kid::Prev, None) => (&self.cur, None),
        }
    }
}

impl Signer for HmacSigner {
    fn sign(&self, payload: &Payload) -> String {
        // `Kid::Prev` without a configured previous secret signs with the
        // current key and is labelled `cur`.
        let (kid, key) = match (payload.kid, self.prev.as_deref()) {
            (Kid::Prev, Some(prev)) => (Kid::Prev, prev),
            _ => (Kid::Cur, &self.cur[..]),
        };
        let json = PayloadJson {
            purpose: payload.purpose.clone(),
            subject: payload.subject.clone(),
            exp: payload.exp,
            kid: kid_name(kid).to_string(),
        };
        let encoded =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&json).expect("payload serializes"));
        let mac = Self::mac(key, &encoded);
        format!("{encoded}.{}", URL_SAFE_NO_PAD.encode(mac))
    }

    fn verify(&self, token: &str, expected_purpose: &str) -> Option<Payload> {
        let (encoded_payload, encoded_mac) = token.split_once('.')?;
        if encoded_payload.is_empty() || encoded_mac.is_empty() {
            return None;
        }
        if token.matches('.').count() != 1 {
            return None;
        }

        let mac: [u8; 32] = URL_SAFE_NO_PAD.decode(encoded_mac).ok()?.try_into().ok()?;
        let json = URL_SAFE_NO_PAD
            .decode(encoded_payload)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())?;
        let payload: PayloadJson = serde_json::from_str(&json).ok()?;
        let kid = parse_kid(&payload.kid)?;

        // MAC over the encoded payload string (ADR 0006): the exact bytes
        // of `encoded_payload`, so a re-encoded (e.g. padded) payload
        // cannot reuse a MAC.
        let (named_key, fallback_kid) = self.key_for(kid);
        let named_ok = bool::from(mac.ct_eq(&Self::mac(named_key, encoded_payload)));
        let verified = named_ok
            || match fallback_kid {
                Some(other) => {
                    let (other_key, _) = self.key_for(other);
                    bool::from(mac.ct_eq(&Self::mac(other_key, encoded_payload)))
                }
                None => false,
            };
        if !verified {
            return None;
        }

        if payload.purpose != expected_purpose {
            return None;
        }
        if let Some(exp) = payload.exp {
            let now = time::OffsetDateTime::now_utc()
                .unix_timestamp()
                .max(0)
                .cast_unsigned();
            if now >= exp {
                return None;
            }
        }
        Some(Payload {
            purpose: payload.purpose,
            subject: payload.subject,
            exp: payload.exp,
            kid,
        })
    }
}

fn kid_name(kid: Kid) -> &'static str {
    match kid {
        Kid::Cur => "cur",
        Kid::Prev => "prev",
    }
}

fn parse_kid(name: &str) -> Option<Kid> {
    match name {
        "cur" => Some(Kid::Cur),
        "prev" => Some(Kid::Prev),
        _ => None,
    }
}
