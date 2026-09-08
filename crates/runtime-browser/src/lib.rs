//! `cratefield-runtime-browser` runs a Factory Zero [`Harness`](cratefield_core::Harness) entirely in a
//! browser tab (Fable's "compose" engine): the same modules and axum router
//! that ship to Cloudflare, over ports backed by browser primitives instead of
//! Worker bindings.
//!
//! - `Database` -> `cratefield-adapter-sqlite-wasm` (sqlite-wasm on OPFS)
//! - `Signer` -> `HARNESS_SECRET` handed in from JS
//! - `HttpClient` -> `fetch`
//! - `Clock` -> `Date` (via `time`'s `wasm-bindgen` feature)
//! - `IdGen` -> `UlidIdGen`
//! - `Defer` -> `spawn_local`
//!
//! A venture's browser entry is a small `cdylib` that builds a `Harness` with
//! `.runtime(Browser::new())` and, from a `#[wasm_bindgen]` `handle`, calls
//! `serve`. A Service Worker turns `fetch` of `/api/*` into those calls; the
//! same venture manifest promotes to Cloudflare + D1 with no recompilation.
//! See `web/` and `crates/runtime-browser-demo` for the worked example.
//!
//! The runtime is only meaningful on `wasm32`; the [`Browser`] builder and its
//! [`Runtime`] declaration compile everywhere so the crate is testable on the
//! host (see `tests/migration_portability.rs`).

#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::sync::Arc;

use cratefield_core::{Captcha, Config, Mailer, Port, Runtime};

/// Config handed in from JS at boot: `HARNESS_SECRET` plus any module keys.
#[derive(Debug, Default, Clone)]
pub struct BrowserConfig {
    values: HashMap<String, String>,
}

impl BrowserConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets one key (e.g. `HARNESS_SECRET`, `WAITLIST_CONFIRM_TTL_DAYS`).
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.values.insert(key.into(), value.into());
        self
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values.insert(key.into(), value.into());
    }
}

impl Config for BrowserConfig {
    fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }
}

/// The browser runtime. Like the `Cloudflare` runtime it
/// carries adapter instances built from the venture's secrets (`mailer`,
/// `captcha`); the database, signer, clock, id generator, defer and HTTP
/// client are resolved from browser primitives at `Browser::ports` time.
#[derive(Clone, Default)]
pub struct Browser {
    config: Arc<BrowserConfig>,
    mailer: Option<Arc<dyn Mailer>>,
    captcha: Option<Arc<dyn Captcha>>,
}

impl Browser {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The config (including `HARNESS_SECRET`) this runtime resolves ports
    /// from. Typically parsed from a JS object at boot.
    #[must_use]
    pub fn config(mut self, config: BrowserConfig) -> Self {
        self.config = Arc::new(config);
        self
    }

    #[must_use]
    pub fn mailer_arc(mut self, mailer: Arc<dyn Mailer>) -> Self {
        self.mailer = Some(mailer);
        self
    }

    #[must_use]
    pub fn captcha_arc(mut self, captcha: Arc<dyn Captcha>) -> Self {
        self.captcha = Some(captcha);
        self
    }
}

impl Runtime for Browser {
    /// The static set used by `Harness::build`. `Db`/`Signer`/`HttpClient`/
    /// `Clock`/`IdGen`/`Defer` are always available in the browser; `Signer`'s
    /// actual presence depends on a valid `HARNESS_SECRET` (checked at
    /// `ports()` time, mirroring the other runtimes).
    fn provides(&self) -> Vec<Port> {
        let mut provided = vec![
            Port::Db,
            Port::Signer,
            Port::HttpClient,
            Port::Clock,
            Port::IdGen,
            Port::Defer,
        ];
        if self.mailer.is_some() {
            provided.push(Port::Mailer);
        }
        if self.captcha.is_some() {
            provided.push(Port::Captcha);
        }
        provided
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_arch = "wasm32")]
pub use wasm::serve;
