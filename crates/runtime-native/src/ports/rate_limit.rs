//! `RateLimiter` over Redis: a true sliding window (sorted set + one Lua
//! script), the honest differences from the Workers Rate Limiting
//! binding documented on [`RedisRateLimiter`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use factory0_core::{Config, Decision, RateLimitError, RateLimiter};
use redis::aio::ConnectionManager;

/// Default `RATE_LIMIT_MAX`: requests allowed per key per window.
const DEFAULT_LIMIT: u64 = 100;

/// Default `RATE_LIMIT_PERIOD_SECS`.
const DEFAULT_PERIOD_SECS: u64 = 60;

/// One atomic sliding-window decision. KEYS[1] is the key; ARGV holds
/// `now_ms`, `window_ms`, the limit and a caller-supplied uniqueness
/// suffix for the member id. Returns `{allowed, retry_after_ms}`.
///
/// Atomicity matters: check-then-add outside a script would let two
/// concurrent requests both pass the same full window.
const SLIDING_WINDOW: &str = r"
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', tonumber(ARGV[1]) - tonumber(ARGV[2]))
local count = redis.call('ZCARD', KEYS[1])
if count < tonumber(ARGV[3]) then
  redis.call('ZADD', KEYS[1], ARGV[1], ARGV[1] .. ':' .. ARGV[4])
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return {1, 0}
end
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local retry = tonumber(ARGV[2])
if oldest[2] then
  retry = tonumber(oldest[2]) + tonumber(ARGV[2]) - tonumber(ARGV[1])
end
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return {0, math.max(retry, 0)}
";

/// `RateLimiter` over Redis: each allowed request ZADDs `now` into the
/// key's sorted set; a request is allowed while the set holds fewer than
/// `limit` members within the trailing `window`.
///
/// # Differences from the Workers Rate Limiting binding (documented,
/// not papered over)
///
/// | | Workers Rate Limiting binding | `RedisRateLimiter` |
/// |---|---|---|
/// | Algorithm | fixed-window counter (limit + period per binding, configured in `wrangler.toml`) | sliding window: a request at the window's edge does not get a fresh full budget immediately |
/// | `retry_after` | the binding exposes none — the port's `Decision::retry_after` is always `None` on Workers | `Some`: milliseconds until the oldest counted request exits the window, so callers can send an honest `Retry-After` |
/// | Where the limit lives | the binding declaration (per Worker) | config keys `RATE_LIMIT_MAX` / `RATE_LIMIT_PERIOD_SECS`, one budget shared by every module — the same "one venture, one budget per subject" the shared binding gives |
/// | Scope | counters are per-Cloudflare-edge | one Redis: exact across every process and replica that shares it, and a single point of failure |
/// | Key space | the binding's own | `rl:`-prefixed in the database shared with [`RedisKv`](crate::RedisKv) |
///
/// `Duration`-granularity windows are kept whole: the script works in
/// milliseconds.
pub struct RedisRateLimiter {
    conn: ConnectionManager,
    script: redis::Script,
    limit: u64,
    window_ms: u64,
    nonce: AtomicU64,
}

impl RedisRateLimiter {
    pub fn new(conn: ConnectionManager, limit: u64, window: Duration) -> Self {
        Self {
            conn,
            script: redis::Script::new(SLIDING_WINDOW),
            limit,
            window_ms: u64::try_from(window.as_millis()).unwrap_or(1).max(1),
            nonce: AtomicU64::new(0),
        }
    }

    /// `RATE_LIMIT_MAX` (default `100`) and `RATE_LIMIT_PERIOD_SECS`
    /// (default `60`) from config.
    #[must_use]
    pub fn from_env(conn: ConnectionManager, config: &dyn Config) -> Self {
        let limit = config
            .get("RATE_LIMIT_MAX")
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(DEFAULT_LIMIT);
        let period_secs = config
            .get("RATE_LIMIT_PERIOD_SECS")
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(DEFAULT_PERIOD_SECS);
        Self::new(conn, limit, Duration::from_secs(period_secs))
    }
}

fn now_ms() -> u64 {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn limit(&self, key: &str) -> Result<Decision, RateLimitError> {
        let mut conn = self.conn.clone();
        let timestamp_ms = now_ms();
        // Member ids must be unique per counted request; the nonce is
        // process-local, the timestamp bounds collisions across
        // processes to the same millisecond.
        let member_nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
        let outcome: Vec<i64> = self
            .script
            .key(format!("rl:{key}"))
            .arg(timestamp_ms)
            .arg(self.window_ms)
            .arg(self.limit)
            .arg(member_nonce)
            .invoke_async(&mut conn)
            .await
            .map_err(|err| RateLimitError::Transport(err.to_string()))?;
        let (allowed, retry_ms) = (
            outcome.first().copied().unwrap_or(0),
            outcome.get(1).copied().unwrap_or(0),
        );
        Ok(Decision {
            ok: allowed == 1,
            retry_after: if retry_ms > 0 {
                Some(Duration::from_millis(retry_ms.unsigned_abs()))
            } else {
                None
            },
        })
    }
}
