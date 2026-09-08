//! The harness `HttpClient` port, copied verbatim from
//! `Cratefield/harness` `crates/core/src/ports/http.rs` so the spike can
//! prove the wiring without pulling `cratefield-core` (and its axum tree) into
//! the wasm build. The trait is identical; when the auth modules are built on
//! the real harness crate, this file disappears.

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum HttpError {
    #[error("http request failed: {0}")]
    Transport(String),
}

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn send(&self, request: http::Request<Bytes>)
        -> Result<http::Response<Bytes>, HttpError>;
}
