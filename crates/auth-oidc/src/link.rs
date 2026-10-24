//! The signed state of a venture link request (venture linking).
//!
//! When `/factory-zero/start?intent=link` arrives without a venture session,
//! the person is shown the venture's sign-in and the link is resumed after
//! it. The resume carries a token this module seals: it names a
//! `link_intent` row in auth-core, the provider it was issued for, and when
//! it lapses. The row is what makes the token single use; the seal is what
//! stops anyone else from minting one.
//!
//! The expiry is inside the signed payload and checked against the `Clock`
//! port, for the same reason [`crate::flow`] does it: the signer's own `exp`
//! reads the wall clock.

use cratefield_core::{Clock, Kid, Payload, Signer};
use serde::{Deserialize, Serialize};

/// The payload's purpose (ADR 0006): a link token can never be replayed as a
/// flow cookie, or any other signed token this service issues.
pub(crate) const PURPOSE: &str = "auth-oidc.link-intent";

/// The `intent` query value that asks for a link.
pub(crate) const INTENT_LINK: &str = "link";

/// How long the sign-in-then-resume may take. The auth-core row carries the
/// same lifetime; this copy lets the token refuse on its own terms.
pub(crate) const TTL_SECS: i64 = cratefield_auth_core::link_intent::LINK_INTENT_TTL_SECS;

#[derive(Debug, Serialize, Deserialize)]
struct Sealed {
    /// The `link_intent` row this token spends.
    id: String,
    /// The provider slug the link is for. Checked on resume.
    provider: String,
    /// Unix seconds.
    expires_at: i64,
}

/// Seals a link token for `id`, naming `provider`.
pub(crate) fn seal(signer: &dyn Signer, id: &str, provider: &str, now: i64) -> String {
    let payload = serde_json::to_string(&Sealed {
        id: id.to_owned(),
        provider: provider.to_owned(),
        expires_at: now + TTL_SECS,
    })
    .unwrap_or_default();
    signer.sign(&Payload {
        purpose: PURPOSE.to_owned(),
        subject: payload,
        exp: None,
        kid: Kid::Cur,
    })
}

/// The `link_intent` id a token names, or `None` for anything that is not a
/// live token for `provider`: unsigned, tampered, malformed, expired, or for
/// another provider. Spending the id is a separate, single-use step.
pub(crate) fn open(
    signer: &dyn Signer,
    clock: &dyn Clock,
    provider: &str,
    token: &str,
) -> Option<String> {
    let payload = signer.verify(token, PURPOSE)?;
    let sealed: Sealed = serde_json::from_str(&payload.subject).ok()?;
    if sealed.provider != provider || sealed.expires_at <= clock.now().unix_timestamp() {
        return None;
    }
    Some(sealed.id)
}
