//! The per-tenant pool cap actually bites (issue #32, TENANT-ROUTING.md §4).
//!
//! One pool per tenant with no cap is how one busy tenant takes every
//! connection on a shared cluster, so `PoolLimits` exists — and a cap that
//! is configured but not enforced is worse than no cap, because it reads
//! as protection. These tests are the difference.
//!
//! Skipped with a printed reason when `FZ_TEST_POSTGRES_URL` is unset; CI
//! provides a `postgres:16` service container.

mod common;

use common::{TempDb, base_url, skip_reason};
use cratefield_adapter_postgres::{PoolLimits, Postgres};
use cratefield_core::{Database, Statement};
use std::time::{Duration, Instant};

/// A cap of one, a checkout held, and a second query that must refuse
/// rather than wait forever.
#[tokio::test]
async fn a_checkout_past_the_cap_refuses_on_a_deadline() {
    let Some(url) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(temp) = TempDb::create(&url, "poolcap").await else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };

    let limits = PoolLimits {
        max_connections: 1,
        idle_timeout: None,
        acquire_timeout: Duration::from_millis(400),
    };
    let db = Postgres::connect_with(&temp.url, limits)
        .await
        .expect("connects within the cap");

    // Hold the single connection: `pg_sleep` keeps it checked out for
    // longer than the acquire deadline of the query racing it.
    let holder = db.clone();
    let held = tokio::spawn(async move {
        let _ = holder.query(&Statement::new("SELECT pg_sleep(2)")).await;
    });
    // Give the holder time to take the only connection.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let started = Instant::now();
    let refused = db.query(&Statement::new("SELECT 1")).await;
    let waited = started.elapsed();

    assert!(
        refused.is_err(),
        "a checkout past the cap must refuse, not queue: {refused:?}"
    );
    assert!(
        waited < Duration::from_millis(1_500),
        "and refuse on its deadline rather than waiting out the holder: {waited:?}"
    );
    let _ = held.await;
    temp.finish().await;
}

/// The other direction, without which the test above passes on a pool that
/// refuses *everything*: within the cap, queries run.
#[tokio::test]
async fn within_the_cap_queries_run_normally() {
    let Some(url) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(temp) = TempDb::create(&url, "poolok").await else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let db = Postgres::connect_with(&temp.url, PoolLimits::default())
        .await
        .expect("connects");

    for _ in 0..4 {
        db.query(&Statement::new("SELECT 1"))
            .await
            .expect("a query within the cap succeeds");
    }
    temp.finish().await;
}

/// `connect` is `connect_with(PoolLimits::default())`, so the default is
/// the thing every existing caller silently got. Pinned so a change to it
/// is a decision rather than a side effect.
#[test]
fn the_default_limits_are_the_documented_ones() {
    let limits = PoolLimits::default();
    assert_eq!(limits.max_connections, 8);
    assert_eq!(limits.idle_timeout, Some(Duration::from_secs(300)));
    assert_eq!(limits.acquire_timeout, Duration::from_secs(5));
}
