//! `cratefield` is the harness as one dependency: a facade that re-exports
//! `cratefield-core` at the root and every other crate behind a feature of
//! its own. It contains no code, so `cratefield::Harness` and
//! `cratefield_core::Harness` are one type and a venture can move between
//! the facade and the parts freely.
//!
//! There is no default feature: a runtime is a decision, not a default.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub use cratefield_core::*;

#[cfg(feature = "cloudflare")]
pub use cratefield_runtime_cloudflare as cloudflare;

#[cfg(feature = "native")]
pub use cratefield_runtime_native as native;

#[cfg(feature = "sqlite")]
pub use cratefield_adapter_sqlite as sqlite;

#[cfg(feature = "postgres")]
pub use cratefield_adapter_postgres as postgres;

#[cfg(feature = "resend")]
pub use cratefield_adapter_resend as resend;

#[cfg(feature = "turnstile")]
pub use cratefield_adapter_turnstile as turnstile;

#[cfg(feature = "apns")]
pub use cratefield_adapter_apns as apns;

#[cfg(feature = "fcm")]
pub use cratefield_adapter_fcm as fcm;

#[cfg(feature = "push-auth")]
pub use cratefield_push_auth as push_auth;

#[cfg(feature = "stripe")]
pub use cratefield_adapter_stripe as stripe;

#[cfg(feature = "ui")]
pub use cratefield_ui as ui;

#[cfg(feature = "secrets")]
pub use cratefield_secrets as secrets;

#[cfg(feature = "kms")]
pub use cratefield_kms as kms;

#[cfg(feature = "email-signup")]
pub use cratefield_module_email_signup as email_signup;

#[cfg(feature = "waitlist")]
pub use cratefield_module_waitlist as waitlist;

#[cfg(feature = "cms")]
pub use cratefield_module_cms as cms;

#[cfg(feature = "testing")]
pub use cratefield_testing as testing;
