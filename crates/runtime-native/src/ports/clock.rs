//! `Clock` over the system clock, `timeout_any` over `tokio::time` —
//! the native counterpart of `WorkersClock` (which races `worker::Delay`
//! because workerd has no tokio timer).

use async_trait::async_trait;
use futures_core::future::BoxFuture;
use std::any::Any;
use std::time::Duration;

/// The system clock on tokio. `now()` reads the wall clock through the
/// `time` crate (the same path core's `SystemClock` uses, never
/// `std::time` directly); `timeout_any` abandons the future with
/// `tokio::time::timeout`, which this runtime can always supply.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioClock;

#[async_trait]
impl factory0_core::Clock for TokioClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }

    async fn timeout_any(
        &self,
        fut: BoxFuture<'static, Box<dyn Any + Send>>,
        after: Duration,
    ) -> Option<Box<dyn Any + Send>> {
        tokio::time::timeout(after, fut).await.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_core::Clock as _;

    #[tokio::test]
    async fn timeout_abandons_a_slow_future() {
        let slow: BoxFuture<'static, Box<dyn Any + Send>> = Box::pin(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Box::new(()) as Box<dyn Any + Send>
        });
        let started = std::time::Instant::now();
        let out = TokioClock
            .timeout_any(slow, Duration::from_millis(20))
            .await;
        assert!(out.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "abandoned, not awaited"
        );
    }

    #[tokio::test]
    async fn timeout_returns_a_fast_future() {
        let fast: BoxFuture<'static, Box<dyn Any + Send>> =
            Box::pin(async { Box::new(7_u32) as Box<dyn Any + Send> });
        let out = TokioClock.timeout_any(fast, Duration::from_secs(5)).await;
        let value = out
            .and_then(|any| any.downcast::<u32>().ok())
            .map(|boxed| *boxed);
        assert_eq!(value, Some(7));
    }
}
