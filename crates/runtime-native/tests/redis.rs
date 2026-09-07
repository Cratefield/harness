//! Redis port tests (issue #19), gated on `FZ_TEST_REDIS_URL` exactly as
//! the Postgres adapter's tests gate on `FZ_TEST_POSTGRES_URL` (CI
//! provides a `redis` service container; unset means skipped with a
//! printed reason):
//!
//! ```sh
//! docker run --rm -p 6380:6379 redis:8-alpine
//! export FZ_TEST_REDIS_URL=redis://127.0.0.1:6380
//! cargo test -p cratefield-runtime-native --test redis
//! ```
//!
//! Sliding-window assertions use unique keys per run (ULID-prefixed) so
//! repeated runs never see each other's counters.

use std::sync::Arc;
use std::time::Duration;

use cratefield_core::{IdGen as _, KeyValue as _, RateLimiter as _, UlidIdGen};
use cratefield_runtime_native::{RedisKv, RedisRateLimiter};
use redis::aio::ConnectionManager;

fn redis_url() -> Option<String> {
    std::env::var("FZ_TEST_REDIS_URL").ok()
}

async fn manager() -> Option<ConnectionManager> {
    let url = redis_url()?;
    let client = redis::Client::open(url.as_str()).expect("test redis url parses");
    Some(
        client
            .get_connection_manager()
            .await
            .expect("test redis reachable"),
    )
}

fn unique(label: &str) -> String {
    format!("test:{label}:{}", UlidIdGen.ulid())
}

#[tokio::test]
async fn kv_round_trips_value_ttl_and_delete() {
    let Some(manager) = manager().await else {
        eprintln!("skipping: FZ_TEST_REDIS_URL is not set");
        return;
    };
    let kv = RedisKv::new(manager);
    let key = unique("kv");

    assert_eq!(kv.get(&key).await.expect("get missing"), None);
    kv.put(&key, "hello", Some(Duration::from_millis(2_000)))
        .await
        .expect("put");
    assert_eq!(kv.get(&key).await.expect("get"), Some("hello".to_owned()));

    kv.delete(&key).await.expect("delete");
    assert_eq!(kv.get(&key).await.expect("get deleted"), None);
}

#[tokio::test]
async fn kv_put_without_ttl_persists() {
    let Some(manager) = manager().await else {
        eprintln!("skipping: FZ_TEST_REDIS_URL is not set");
        return;
    };
    let kv = RedisKv::new(manager);
    let key = unique("kv-nottl");
    kv.put(&key, "stays", None).await.expect("put");
    assert_eq!(kv.get(&key).await.expect("get"), Some("stays".to_owned()));
    kv.delete(&key).await.expect("delete");
}

#[tokio::test]
async fn sliding_window_allows_limit_then_blocks_with_retry_hint() {
    let Some(manager) = manager().await else {
        eprintln!("skipping: FZ_TEST_REDIS_URL is not set");
        return;
    };
    let limiter = RedisRateLimiter::new(manager, 3, Duration::from_millis(1_500));
    let key = unique("rl");

    for attempt in 1..=3 {
        let decision = limiter.limit(&key).await.expect("limit call");
        assert!(
            decision.ok && decision.retry_after.is_none(),
            "request {attempt} within the budget should be ok without retry hint"
        );
    }

    let blocked = limiter.limit(&key).await.expect("limit call");
    assert!(!blocked.ok, "fourth request within the window is blocked");
    let retry = blocked
        .retry_after
        .expect("a blocked decision carries a retry hint");
    assert!(
        retry <= Duration::from_millis(1_500),
        "hint bounded by the window"
    );

    // The window really slides: after it empties, the same key is
    // allowed again.
    tokio::time::sleep(Duration::from_millis(1_700)).await;
    let after = limiter.limit(&key).await.expect("limit call");
    assert!(after.ok, "window slid: key allowed again");
}

#[tokio::test]
async fn keys_do_not_share_budgets() {
    let Some(manager) = manager().await else {
        eprintln!("skipping: FZ_TEST_REDIS_URL is not set");
        return;
    };
    let limiter = Arc::new(RedisRateLimiter::new(
        manager,
        1,
        Duration::from_millis(60_000),
    ));
    let a = unique("rl-a");
    let b = unique("rl-b");

    let a1 = limiter.limit(&a).await.expect("limit a");
    let b1 = limiter.limit(&b).await.expect("limit b");
    assert!(a1.ok && b1.ok, "separate keys have separate budgets");

    let a2 = limiter.limit(&a).await.expect("limit a again");
    assert!(!a2.ok, "key a exhausted its own budget only");
}
