//! The `HttpClient` port (architecture section 5): plain `http` types over
//! bytes, so adapters (Resend, Turnstile) run unchanged on Workers
//! (`worker::Fetch`) and native (`reqwest`, phase 3).

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
