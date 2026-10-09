//! The outbound-budget conformance fns (issue #765) against real SQLite
//! **and** Postgres: the same dialect loop `usage.rs` runs for the quota
//! table `Usage` sits on. The fns create and clear their own probe tables,
//! so one throwaway database per dialect carries all four.

use std::any::Any;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use cratefield_core::Database;
use cratefield_testing::{Dialect, TestHarness};
use futures_core::future::BoxFuture;

/// SQLite always; Postgres when the kit is built with the `postgres` feature
/// and `FZ_TEST_POSTGRES_URL` names a server (a non-postgres build never
/// constructs a Postgres harness, so the skip is real).
fn dialects() -> Vec<Dialect> {
    #[cfg(feature = "postgres")]
    {
        Dialect::available()
    }
    #[cfg(not(feature = "postgres"))]
    {
        vec![Dialect::Sqlite]
    }
}

/// Runs one conformance fn against every available dialect's harness — a
/// bare database, no modules mounted, since the fns create their own probe
/// tables — naming the dialect in the failure, which the fns' own panics
/// cannot.
fn every_dialect(label: &str, assert: for<'a> fn(&'a Arc<dyn Database>) -> BoxFuture<'a, ()>) {
    for dialect in dialects() {
        let kit = TestHarness::with_database(Vec::new(), dialect);
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            pollster::block_on(assert(&kit.db));
        }));
        if let Err(err) = outcome {
            panic!("{}: {label}: {}", kit.dialect, panic_message(&err));
        }
    }
}

/// A panic payload's message, whatever shape it arrived in.
fn panic_message(err: &Box<dyn Any + Send>) -> String {
    err.downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default()
}

#[test]
fn budget_pacing_holds_on_every_dialect() {
    every_dialect("budget pacing", |db| {
        Box::pin(cratefield_testing::assert_budget_pacing(db))
    });
}

#[test]
fn budget_daily_quota_holds_on_every_dialect() {
    every_dialect("budget daily quota", |db| {
        Box::pin(cratefield_testing::assert_budget_daily_quota(db))
    });
}

#[test]
fn budget_retries_hold_on_every_dialect() {
    every_dialect("budget retries", |db| {
        Box::pin(cratefield_testing::assert_budget_retries(db))
    });
}

#[test]
fn budget_passthrough_holds_on_every_dialect() {
    every_dialect("budget passthrough", |db| {
        Box::pin(cratefield_testing::assert_budget_passthrough(db))
    });
}
