//! OAuth 2.0 for the harness's modules and adapters (issue #531).
//!
//! Three-legged OAuth is the same shape everywhere and is still easy to get
//! wrong in ways that matter: a scope list that is not encoded, a refresh
//! that loops, a token pasted into a log. This crate speaks the protocol
//! once, over the [`HttpClient`](cratefield_core::HttpClient) port, so the
//! code runs unchanged on Workers and native, and the provider is
//! configuration ([`ProviderConfig`]) rather than a client type per brand.
//!
//! Sealing what comes back is a trait, [`TokenSealer`], so moving storage to
//! the secrets store later is a swap of implementations, not a rewrite of
//! every module: `fz-module-linkedin` seals today with [`XChaChaSealer`]
//! (ADR 0102), and the blob format it writes is the one that has to keep
//! opening.
//!
//! **wasm-safe.** No `std::net`, no wall clock, no threads: HTTP goes
//! through the `HttpClient` port and randomness through `getrandom`, whose
//! wasm backend the manifest enables on `wasm32`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod client;
mod config;
mod pkce;
mod refresh;
mod seal;

pub use client::{OAuthClient, OAuthError, ProviderError, TokenResponse};
pub use config::{ClientAuth, ProviderConfig, authorize_url};
pub use pkce::{Pkce, RandomError, random_state};
pub use refresh::{SendWithRefreshError, send_with_refresh};
pub use seal::{KEY_LEN, SealContext, SealError, TokenSealer, XChaChaSealer};
