//! The `Signer` port and the signed-token payload (ADR 0006). The HMAC
//! reference implementation lives in `factory0-core::signer` (issue #3).

use thiserror::Error;

/// Which secret a token was signed with. Tokens name their key so rotation
/// never breaks links in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kid {
    Cur,
    Prev,
}

/// The signed payload: `{ purpose, subject, exp?, kid }`.
///
/// `purpose` scopes a token to one use (`confirm`, `unsubscribe`, ...), so a
/// confirm link can never be replayed as an unsubscribe. `exp` is a Unix
/// timestamp in seconds; confirm tokens expire (7-day default), unsubscribe
/// tokens do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub purpose: String,
    pub subject: String,
    pub exp: Option<u64>,
    pub kid: Kid,
}

/// Failures surfaced by `verify` beyond "the token is simply invalid",
/// which is reported as `None`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignatureError {
    #[error("token payload is not valid UTF-8/JSON")]
    Malformed,
    #[error("token is expired")]
    Expired,
    #[error("token purpose {actual:?} does not match expected {expected:?}")]
    WrongPurpose { actual: String, expected: String },
}

/// Produces and verifies `base64url(json).base64url(mac)` tokens where the
/// MAC is computed over the **encoded** payload string, so a token has
/// exactly one valid encoding (ADR 0006).
pub trait Signer: Send + Sync {
    fn sign(&self, payload: &Payload) -> String;
    /// `None` for malformed input, tampering, expiry or wrong purpose;
    /// never panics on malformed input.
    fn verify(&self, token: &str, expected_purpose: &str) -> Option<Payload>;
}
