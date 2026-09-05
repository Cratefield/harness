//! The `RateLimiter` port (architecture section 5).

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub ok: bool,
    pub retry_after: Option<Duration>,
}

#[derive(Debug, Clone, Error)]
pub enum RateLimitError {
    #[error("rate limiter transport error: {0}")]
    Transport(String),
}

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn limit(&self, key: &str) -> Result<Decision, RateLimitError>;
}
