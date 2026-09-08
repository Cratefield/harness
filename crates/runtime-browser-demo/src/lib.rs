//! A worked browser-runtime venture: the three built-in modules
//! (`waitlist`, `email-signup`, `cms`) composed into one `Harness` over
//! `cratefield-runtime-browser`, exported to JS as `init` + `handle`.
//!
//! Build with `wasm-pack build --target web` (needs `wasm-bindgen`), then open
//! `crates/runtime-browser/web/index.html`. See that crate's `web/README.md`.
//!
//! This is the browser counterpart of a venture's Cloudflare Worker: the same
//! modules, the same router; only the runtime differs.

#![cfg(target_arch = "wasm32")]

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use cratefield_adapter_sqlite_wasm::SqliteWasmDatabase;
use cratefield_core::{Harness, MailError, Mailer, Message, Module, SendOutcome, Venture};
use cratefield_runtime_browser::{Browser, BrowserConfig, serve};
use wasm_bindgen::prelude::*;

/// Capture-only mailer: modules that send mail (waitlist, email-signup) still
/// create their rows in the browser demo; real delivery is a promoted concern.
struct NoopMailer;

#[async_trait]
impl Mailer for NoopMailer {
    async fn send(&self, _message: Message) -> Result<SendOutcome, MailError> {
        Ok(SendOutcome::Sent {
            id: "browser-noop".to_owned(),
        })
    }
}

static INSTANCE: OnceLock<(Harness, Browser)> = OnceLock::new();

fn build(secret: &str, admin_token: &str) -> (Harness, Browser) {
    let config = BrowserConfig::new()
        .with("HARNESS_SECRET", secret)
        .with("ADMIN_TOKEN", admin_token);
    let runtime = Browser::new()
        .config(config)
        .mailer_arc(Arc::new(NoopMailer));

    let harness = Harness::builder()
        .venture(
            Venture::new("browser-demo", "demo.cratefield.app").public_url("http://localhost:8000"),
        )
        .templates(cratefield_module_waitlist::default_templates())
        .templates(cratefield_module_email_signup::default_templates())
        .module(cratefield_module_waitlist::Waitlist::default())
        .module(cratefield_module_email_signup::EmailSignup::default())
        .module(cratefield_module_cms::Cms::default())
        .runtime(runtime.clone())
        .build()
        .expect("the browser-demo venture is a valid harness");

    (harness, runtime)
}

/// Initialises the venture with the `HARNESS_SECRET` and `ADMIN_TOKEN` handed
/// in from JS. Idempotent; the first call wins.
// wasm-bindgen exports must take owned `String`s.
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
pub fn init(secret: String, admin_token: String) {
    let _ = INSTANCE.set(build(&secret, &admin_token));
}

/// Applies every built-in module's migrations to the OPFS-backed sqlite-wasm
/// database. Idempotent — safe to call on every load; the second run is a
/// no-op via the `harness_migrations` ledger (which persists in OPFS).
///
/// # Errors
///
/// Returns the migration error (as a JS string) if any module's SQL fails to
/// apply against sqlite-wasm.
#[wasm_bindgen]
pub async fn migrate() -> Result<(), JsValue> {
    let db = SqliteWasmDatabase::new();
    let modules: [Box<dyn Module>; 3] = [
        Box::new(cratefield_module_waitlist::Waitlist::default()),
        Box::new(cratefield_module_email_signup::EmailSignup::default()),
        Box::new(cratefield_module_cms::Cms::default()),
    ];
    for module in &modules {
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .await
            .map_err(|err| JsValue::from_str(&err.to_string()))?;
    }
    Ok(())
}

/// Serves one request. `headers_json` is `[[name, value], ...]`; returns the
/// JSON envelope `{ status, headers, body }` (body base64) for the caller to
/// turn into a `Response`. Call [`init`] first.
// wasm-bindgen exports must take owned arguments.
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
pub async fn handle(method: String, url: String, headers_json: String, body: Vec<u8>) -> String {
    let Some((harness, runtime)) = INSTANCE.get() else {
        return String::from(
            r#"{"status":503,"headers":[["content-type","text/plain"]],"body":"aW5pdCgpIG5vdCBjYWxsZWQ="}"#,
        );
    };
    serve(harness, runtime, &method, &url, &headers_json, body).await
}
