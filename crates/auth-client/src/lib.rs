//! Verify Factory Zero auth tokens in a consuming app (issue #11).
//!
//! Six ventures each writing their own JWT validation is six chances to
//! forget the audience check. This crate does it once.
//!
//! ```ignore
//! let auth = AuthClient::new(http, clock, "https://auth.factory0.ventures", "client-kontinuum");
//! async fn handler(Authenticated(claims): Authenticated) -> String { claims.sub }
//! ```
//!
//! **What it checks, in this order**: the header names `ES256` and a
//! `kid` we hold; the signature verifies against that key; `iss` equals
//! the configured issuer; `aud` equals *this* client's id; `exp` has not
//! passed and `nbf`/`iat` are not implausibly far in the future. Every
//! one of those is a way a token from somewhere else gets accepted if it
//! is skipped, so none of them is optional and none is configurable.
//!
//! **Algorithm confusion is refused structurally.** The header's `alg`
//! must be exactly `ES256`. `none` and the HMAC families are rejected
//! before any key is looked up, so a token asking to be verified with
//! the public key as an HMAC secret never reaches verification.
//!
//! **wasm-safe.** Time comes from the harness `Clock` port and HTTP from
//! its `HttpClient` port, so this compiles for `wasm32-unknown-unknown`
//! where `std::time` and `chrono::Utc::now` both panic.

#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod extractor;
mod jwks;
mod verify;

pub use extractor::{AuthState, Authenticated, UNAUTHENTICATED};
pub use jwks::{AuthClient, JwksCache};
pub use verify::{Claims, VerifyError, token_fingerprint};

/// The only signature algorithm this client accepts.
pub const ALGORITHM: &str = "ES256";

/// How long a fetched key set is trusted before it is refetched.
pub const JWKS_TTL_SECS: i64 = 3600;

/// The shortest gap between two forced refetches triggered by an unknown
/// `kid`. Without it, a stream of tokens naming keys that do not exist
/// would let anyone drive unbounded traffic at the auth service.
pub const JWKS_MIN_REFETCH_SECS: i64 = 60;

/// Clock skew tolerated on `exp`, `nbf` and `iat`.
pub const LEEWAY_SECS: i64 = 60;
