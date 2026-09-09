//! `cratefield-push-auth`: the provider tokens the push adapters present
//! (issue #178).
//!
//! APNs signs an ES256 JWT with the `.p8` key from the Apple developer
//! portal. VAPID (RFC 8292) is the *same* construction with different claims
//! — `aud` is the push-service origin, `sub` a `mailto:`, `exp` at most 24
//! hours out — and the public key travels alongside it as `k=`. Google's
//! service-account flow signs an **RS256** JWT and trades it for a bearer
//! token. Three adapters, one signer, one cache; extracted here so the next
//! two adapters do not each grow their own copy of
//! `base64url(header).base64url(claims).base64url(sig)`.
//!
//! Everything is pure Rust and builds for `wasm32-unknown-unknown`: no
//! `jsonwebtoken`, no `ring`, no OpenSSL. Both signatures are deterministic
//! (RFC 6979 for ES256, PKCS#1 v1.5 for RS256), so no RNG is needed on a
//! Workers isolate.
//!
//! Verifying tokens is deliberately absent — that is the auth service's job.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod cache;
mod es256;
mod rs256;

pub use cache::CachedToken;
pub use es256::Es256Signer;
pub use rs256::Rs256Signer;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

/// A private key did not parse.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The PEM was not the expected kind of private key. The detail is the
    /// underlying parser's message; it never contains key material.
    #[error("invalid {kind} private key: {detail}")]
    Parse {
        /// `ES256` or `RS256` — which signer refused it.
        kind: &'static str,
        detail: String,
    },
}

impl KeyError {
    fn parse(kind: &'static str, detail: impl std::fmt::Display) -> Self {
        KeyError::Parse {
            kind,
            detail: detail.to_string(),
        }
    }
}

/// The JWS signing input: `base64url(header) "." base64url(claims)`
/// (RFC 7515 §5.1). Compact serialisation, so the exact bytes signed are the
/// exact bytes sent.
fn signing_input(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string()),
    )
}
