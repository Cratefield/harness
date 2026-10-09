//! The step-up seam: proof that a request carries a **fresh** passkey
//! ceremony, beyond being signed in at all.
//!
//! Being signed in is not the same as being present. A session token
//! lives for hours on whatever device minted it; a consent button that
//! moves value must not take the token's word for it. The [`StepUp`]
//! trait is the module's seam for the difference — the web app's
//! `/confirm` route refuses to approve a value-moving action unless a
//! configured `StepUp` says this very request proved one. With none
//! configured the route answers `403` for everyone: fail closed, never
//! open.
//!
//! # What an implementation must prove
//!
//! A passkey assertion — a WebAuthn ceremony — completed **for this
//! subject** within this request, or within a freshness window the
//! implementation names. Not merely a passkey-born session:
//!
//! the auth service stores the login's methods in the session's `amr`
//! and copies them into **every** access token it mints for that
//! session, stamping each mint with a fresh `iat` — the refresh grant
//! included (`cratefield-auth-core`'s `minted_response` reads `amr` off
//! the session row; `mint_access_token` takes `iat` from the clock). A
//! token refreshed hours after a passkey login therefore carries
//! `amr: ["…", "passkey"]` and an `iat` seconds old while proving
//! nothing about the last minutes. No claim on an access token
//! (`amr`, `iat`, `sid` — there is no `auth_time`) distinguishes a
//! fresh ceremony from a passkey-born session, so **a verifier that
//! reads them off the bearer token is unsound and must not be
//! written**. The proof has to come from a ceremony the implementation
//! itself observes: a WebAuthn assertion in the request body checked
//! against the subject's registered credentials, or a service-side
//! record of one of equal strength, both bound to the subject.

use async_trait::async_trait;
use http::HeaderMap;

/// Proves, or refuses to prove, that a request carries a fresh passkey
/// ceremony for `subject`.
///
/// Implemented by the venture and injected with `Telegram::step_up`.
/// `headers` are the confirm request's own headers — the credentials the
/// request itself presented; `subject` is the account the action belongs
/// to, which the proof must be about — a ceremony by a colleague is not
/// a ceremony by you.
///
/// The contract, in one sentence: return `true` only when you watched a
/// passkey assertion for `subject` complete within this request or
/// within your own freshness window; every doubt returns `false`, and
/// the route answers `403` without touching the action.
#[async_trait]
pub trait StepUp: Send + Sync {
    /// `true` only when this request proves a fresh passkey ceremony for
    /// `subject`. Never asked twice for one action: the conditional
    /// update behind it is single-use.
    async fn passkey_verified(&self, headers: &HeaderMap, subject: &str) -> bool;
}
