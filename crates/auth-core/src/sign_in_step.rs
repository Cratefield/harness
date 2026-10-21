//! A step a just-signed-in browser may be sent through before the
//! authorization code is minted.
//!
//! `/authorize` is where every sign-in ends up: the magic link or password
//! confirm redirects back to it, and it mints the code. A module that wants
//! a page in between — the passkey offer is the first — implements
//! [`SignInStep`] and is attached to [`AuthCore`](crate::AuthCore) at
//! composition. `auth-core` does not know what the step decides; it only
//! decides *when* a step may run, and that only for a sign-in that is
//! really a sign-in:
//!
//! - the session was created at most two minutes ago (the same window a
//!   fresh ceremony is judged by), so a long-lived session that merely
//!   visits another client is never interrupted;
//! - the request is not a step-up (`prompt=login`, `max_age`, or a step-up
//!   transaction), so a sensitive action is never interrupted;
//! - the request is not silent (`prompt=none`) and the client wants a page
//!   (`Accept: text/html`), so an API client never gets HTML back.
//!
//! When a step answers `Some(location)` the browser is redirected there
//! instead, and the step owns the way back: it must return the browser to
//! the `continue_to` request unchanged.
//!
//! [`AuthCore`]: crate::AuthCore

use std::fmt::Debug;

use cratefield_core::{BoxFuture, ModuleContext, Problem};

/// The marker a step sets when the browser has answered it for this sign-in
/// and must not be asked again: `__Host-sign-in-step=<session id>`. A step
/// that sends a browser on without an answer (no WebAuthn, say) sets it, and
/// `/authorize` then passes the request through, so the step cannot loop.
/// It names the session, so a marker from an earlier sign-in never counts.
pub const MARKER_COOKIE: &str = "__Host-sign-in-step";

/// One sign-in the step is asked about.
#[derive(Debug, Clone, Copy)]
pub struct SignIn<'a> {
    /// The account that just signed in.
    pub user_id: &'a str,
    /// The session the sign-in created.
    pub session_id: &'a str,
    /// The methods the session was signed in by (`email`, `pwd`,
    /// `passkey`, …), as the session records them.
    pub amr: &'a [String],
    /// The authorization request as it came in, path and query, exactly
    /// as the client sent it. A step that diverts must hand this back
    /// unchanged, so the code is minted for the same `state`, PKCE
    /// challenge and `redirect_uri`.
    pub continue_to: &'a str,
}

/// A page a just-signed-in browser is sent to before its code is minted.
///
/// Implementations must be cheap when they have nothing to say: the step
/// runs on every qualifying `/authorize`.
pub trait SignInStep: Debug + Send + Sync + 'static {
    /// `Some(location)` diverts the browser to `location` instead of
    /// minting a code. `None` lets the request continue.
    ///
    /// A failed read should answer `None` (and log), not an error: a
    /// missing nudge must never stop a person signing in.
    fn divert<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        sign_in: SignIn<'a>,
    ) -> BoxFuture<'a, Result<Option<String>, Problem>>;
}
