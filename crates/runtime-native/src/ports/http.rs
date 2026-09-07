//! `HttpClient` over `reqwest` (rustls, ring provider, webpki roots —
//! no OpenSSL, no native-tls): the native counterpart of
//! `worker::Fetch`. Adapters (Resend, Turnstile) run unchanged over
//! either.

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{HttpClient, HttpError};

/// A shared reqwest client. Built once per process (the connection pool
/// is the `Client`); the port is cheap to `Arc` and clone-free on the
/// hot path.
///
/// No default timeout — the port contract leaves timeouts to the caller
/// (the adapters bound their own calls through the `Clock` port), the
/// same trade `worker::Fetch` makes.
pub struct ReqwestClient(reqwest::Client);

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestClient {
    /// # Panics
    ///
    /// Only if the rustls backend cannot initialize, which a static
    /// webpki-roots configuration cannot do at runtime — a startup-time
    /// invariant, the same class as core's `HmacSigner::new` panic.
    pub fn new() -> Self {
        Self(
            reqwest::Client::builder()
                .build()
                .expect("reqwest initializes: rustls with webpki roots is static"),
        )
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        // reqwest re-exports the same `http` v1 types (Method, header
        // map, status), so the conversion is structural, not a rebuild.
        let (parts, body) = request.into_parts();
        let url = parts
            .uri
            .to_string()
            .parse::<reqwest::Url>()
            .map_err(|err| HttpError::Transport(format!("invalid request uri: {err}")))?;
        let mut builder = self.0.request(parts.method, url);
        for (name, value) in &parts.headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .body(body)
            .send()
            .await
            .map_err(|err| HttpError::Transport(err.to_string()))?;

        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .bytes()
            .await
            .map_err(|err| HttpError::Transport(err.to_string()))?;
        let mut rebuilt = http::Response::builder().status(status);
        if let Some(target) = rebuilt.headers_mut() {
            *target = headers;
        }
        rebuilt
            .body(bytes)
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}
