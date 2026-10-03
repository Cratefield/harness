//! Every deployment-specific literal this Worker bakes in, in one table
//! (issue #646).
//!
//! Nothing outside this file may name the venture: [`crate::config`] reads
//! these as the fallback for an unset variable, and
//! `tests/literal_scope.rs` fails the build if the marker escapes here.
//! A wrapper venture that composes [`crate::AuthWorker`] supplies its own
//! [`crate::AuthWorkerConfig`] and never touches this module.

/// `AUTH_VENTURE_NAME` fallback: the kebab-case venture name.
pub const VENTURE_NAME: &str = "factory0-auth";

/// `AUTH_PUBLIC_URL` fallback: the absolute origin the API is served on.
/// The venture domain, the Turnstile hostname and the default `MAIL_FROM`
/// host all derive from it.
pub const PUBLIC_URL: &str = "https://auth.factory0.ventures";

/// `AUTH_CORS_ORIGINS` fallback: the first-party browser origins allowed to
/// call the discovery/JWKS documents cross-origin.
pub const CORS_ORIGINS: &[&str] = &[
    "https://app.cratefield.com",
    "https://cratefield.com",
    "https://yoginini.us",
];
