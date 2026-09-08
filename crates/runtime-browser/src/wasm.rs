//! The wasm32 implementation: browser-backed ports and the request bridge.
//! Split out so the crate builds (and is testable) on the host.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use cratefield_adapter_sqlite_wasm::SqliteWasmDatabase;
use cratefield_core::{
    Clock, Config, Defer, Harness, HarnessConfig, HttpClient, HttpError, Ports, UlidIdGen,
};
use futures_core::future::BoxFuture;
use js_sys::Promise;
use send_wrapper::SendWrapper;
use serde_json::Value as Json;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};

use crate::Browser;

/// Responses are JSON/HTML (small); 4 MiB is a generous ceiling.
const MAX_RESPONSE_BUFFER: usize = 4 * 1024 * 1024;

impl Browser {
    /// Resolves the `Ports` from browser primitives and the boot config.
    /// A missing/short `HARNESS_SECRET` leaves `Signer` unset, exactly like
    /// the Cloudflare and native runtimes.
    #[must_use]
    pub fn ports(&self) -> Ports {
        let config: Arc<dyn Config> = self.config.clone();
        let mut ports = Ports::with_config(Arc::clone(&config));

        ports.db = Some(Arc::new(SqliteWasmDatabase::new()));
        ports.http = Some(Arc::new(FetchClient));
        ports.clock = Some(Arc::new(BrowserClock));
        ports.id_gen = Some(Arc::new(UlidIdGen));
        ports.defer = Some(Arc::new(SpawnLocalDefer));

        if let Ok(parsed) = HarnessConfig::from_config(&*config) {
            // Key logged email pseudonyms from the harness secret (#135).
            cratefield_core::set_log_pseudonym_key(parsed.harness_secret.as_bytes());
            ports.signer = Some(Arc::new(parsed.signer()));
        }
        ports.mailer.clone_from(&self.mailer);
        ports.captcha.clone_from(&self.captcha);
        ports
    }
}

/// Serves one request through the harness router and returns a JSON envelope
/// `{ status, headers: [[name, value]], body: <base64> }` for JS to turn into
/// a `Response`. `headers_json` is `[[name, value], ...]`.
///
/// This is the browser counterpart of `cratefield_runtime_cloudflare::serve`.
pub async fn serve(
    harness: &Harness,
    runtime: &Browser,
    method: &str,
    url: &str,
    headers_json: &str,
    body: Vec<u8>,
) -> String {
    use tower::ServiceExt as _;

    let ports = runtime.ports();
    let router = harness.router(ports);

    let mut builder = http::Request::builder().method(method).uri(url);
    if let Ok(headers) = serde_json::from_str::<Vec<(String, String)>>(headers_json) {
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
    }
    let request = match builder.body(axum::body::Body::from(body)) {
        Ok(request) => request,
        Err(err) => return error_envelope(&format!("bad request: {err}")),
    };

    // The axum router's error type is `Infallible`.
    let Ok(response) = router.oneshot(request).await;

    let (response_parts, response_body) = response.into_parts();
    let bytes = axum::body::to_bytes(response_body, MAX_RESPONSE_BUFFER)
        .await
        .unwrap_or_default();
    let headers: Vec<(String, String)> = response_parts
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    serde_json::json!({
        "status": response_parts.status.as_u16(),
        "headers": headers,
        "body": BASE64.encode(&bytes),
    })
    .to_string()
}

fn error_envelope(message: &str) -> String {
    serde_json::json!({
        "status": 500u16,
        "headers": [["content-type", "text/plain"]],
        "body": BASE64.encode(message.as_bytes()),
    })
    .to_string()
}

/// `Clock` over `Date` (`time`'s `wasm-bindgen` feature). The default
/// `timeout_any` (run to completion) is used for now; a real `setTimeout`
/// race is a follow-up.
struct BrowserClock;

#[async_trait]
impl Clock for BrowserClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }
}

/// `Defer` over `spawn_local`: continues work after the response, the browser
/// counterpart of `Context::wait_until`.
struct SpawnLocalDefer;

impl Defer for SpawnLocalDefer {
    fn wait_until(&self, fut: BoxFuture<'static, ()>) {
        spawn_local(fut);
    }
}

// ---- HttpClient over fetch ----

#[wasm_bindgen(inline_js = r#"
export async function __cf_fetch(method, url, headers, body_b64) {
    const init = { method, headers: JSON.parse(headers) };
    if (body_b64) {
        const bin = atob(body_b64);
        const a = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) { a[i] = bin.charCodeAt(i); }
        init.body = a;
    }
    const r = await fetch(url, init);
    const buf = new Uint8Array(await r.arrayBuffer());
    let s = "";
    for (const b of buf) { s += String.fromCharCode(b); }
    const h = [];
    r.headers.forEach((v, k) => h.push([k, v]));
    return JSON.stringify({ status: r.status, headers: h, body: btoa(s) });
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = __cf_fetch)]
    fn js_fetch(method: &str, url: &str, headers: &str, body_b64: &str) -> Promise;
}

struct FetchClient;

#[async_trait]
impl HttpClient for FetchClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        let headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let headers_json = serde_json::to_string(&headers).unwrap_or_else(|_| "[]".to_owned());
        let promise = js_fetch(
            parts.method.as_str(),
            &parts.uri.to_string(),
            &headers_json,
            &BASE64.encode(&body),
        );
        let out = SendWrapper::new(JsFuture::from(promise))
            .await
            .map_err(|err| HttpError::Transport(js_error(&err)))?;
        let json = out
            .as_string()
            .ok_or_else(|| HttpError::Transport("fetch bridge returned a non-string".to_owned()))?;
        let value: Json =
            serde_json::from_str(&json).map_err(|err| HttpError::Transport(err.to_string()))?;

        let status = value
            .get("status")
            .and_then(Json::as_u64)
            .and_then(|status| u16::try_from(status).ok())
            .unwrap_or(502);
        let body_bytes = value
            .get("body")
            .and_then(Json::as_str)
            .and_then(|b64| BASE64.decode(b64).ok())
            .unwrap_or_default();

        let mut builder = http::Response::builder().status(status);
        if let Some(headers) = value.get("headers").and_then(Json::as_array) {
            for pair in headers {
                if let Some(entry) = pair.as_array()
                    && let (Some(name), Some(val)) = (
                        entry.first().and_then(Json::as_str),
                        entry.get(1).and_then(Json::as_str),
                    )
                {
                    builder = builder.header(name, val);
                }
            }
        }
        builder
            .body(Bytes::from(body_bytes))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

fn js_error(value: &JsValue) -> String {
    value
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(value, &JsValue::from_str("message"))
                .ok()
                .and_then(|message| message.as_string())
        })
        .unwrap_or_else(|| format!("{value:?}"))
}
