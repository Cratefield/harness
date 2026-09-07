//! `KeyValue` over Redis, plus the shared-connection convenience both
//! Redis ports are wired through (`redis_from_env`). The honest
//! differences from a Workers KV namespace are listed on [`RedisKv`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cratefield_core::{Config, KeyValue, KvError};
use redis::aio::ConnectionManager;

use crate::ports::rate_limit::RedisRateLimiter;

/// `KeyValue` over Redis (one shared `ConnectionManager`, cloned per
/// call — a cheap channel copy, not a new connection).
///
/// # Differences from the Workers KV binding (documented, not papered
/// over)
///
/// | | Workers KV | `RedisKv` |
/// |---|---|---|
/// | Consistency | eventually consistent; a write can take up to ~60 s to propagate to other colos, and reads may hit a stale per-colo cache | strongly consistent single Redis: a read after a write sees the write |
/// | Failure mode | KV outages degrade per colo; values survive Redis-down | Redis is a single point of failure and of latency for the port |
/// | TTL | minimum 60 s | any duration, millisecond granularity (`PX`) |
/// | Value size | 25 MiB per value | 512 MiB per string, but the port is meant for small values |
/// | Key space | the binding's own namespace | one Redis database shared with the rate limiter — keys are prefixed `kv:` here to keep the two apart |
///
/// The port has no list/scan method, so KV's list operations have no
/// counterpart to mismatch.
pub struct RedisKv(ConnectionManager);

impl RedisKv {
    pub fn new(conn: ConnectionManager) -> Self {
        Self(conn)
    }
}

fn op(err: &redis::RedisError) -> KvError {
    KvError::Operation(err.to_string())
}

#[async_trait]
impl KeyValue for RedisKv {
    async fn get(&self, key: &str) -> Result<Option<String>, KvError> {
        let mut conn = self.0.clone();
        redis::cmd("GET")
            .arg(format!("kv:{key}"))
            .query_async(&mut conn)
            .await
            .map_err(|err| op(&err))
    }

    async fn put(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), KvError> {
        let mut conn = self.0.clone();
        let mut cmd = redis::cmd("SET");
        cmd.arg(format!("kv:{key}")).arg(value);
        if let Some(ttl) = ttl {
            // PX (milliseconds) rather than EX (seconds): the port takes
            // a Duration and the port's granularity survives intact.
            let millis = i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX).max(1);
            cmd.arg("PX").arg(millis);
        }
        cmd.query_async::<()>(&mut conn)
            .await
            .map_err(|err| op(&err))
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        let mut conn = self.0.clone();
        redis::cmd("DEL")
            .arg(format!("kv:{key}"))
            .query_async::<i64>(&mut conn)
            .await
            .map_err(|err| op(&err))?;
        Ok(())
    }
}

/// Both Redis ports over one shared connection, what a venture gets from
/// `REDIS_URL` when it is set.
pub struct RedisBundle {
    pub rate_limiter: Arc<RedisRateLimiter>,
    pub kv: Arc<RedisKv>,
}

#[derive(Debug, thiserror::Error)]
pub enum RedisPortError {
    /// `REDIS_URL` is not a valid Redis URL, or the manager could not
    /// establish its first connection.
    #[error("redis port setup failed: {0}")]
    Connection(String),
}

/// Wires both Redis ports from config: `REDIS_URL` opens a client and
/// one reconnecting [`ConnectionManager`] shared (cloned) by the two
/// adapters; `RATE_LIMIT_MAX` (default `100`) and
/// `RATE_LIMIT_PERIOD_SECS` (default `60`) configure the limiter's
/// window. `Ok(None)` when `REDIS_URL` is unset — the ports stay absent
/// and a module that requires one fails `Harness::build` by name.
///
/// # Errors
///
/// [`RedisPortError::Connection`] when the URL cannot be parsed or the
/// first connection fails (fail fast at startup, not on the first
/// request).
pub async fn redis_from_env(config: &dyn Config) -> Result<Option<RedisBundle>, RedisPortError> {
    let Some(url) = config.get("REDIS_URL") else {
        return Ok(None);
    };
    let client = redis::Client::open(url.as_str())
        .map_err(|err| RedisPortError::Connection(err.to_string()))?;
    let manager = client
        .get_connection_manager()
        .await
        .map_err(|err| RedisPortError::Connection(err.to_string()))?;
    let rate_limiter = Arc::new(RedisRateLimiter::from_env(manager.clone(), config));
    let kv = Arc::new(RedisKv::new(manager));
    Ok(Some(RedisBundle { rate_limiter, kv }))
}
