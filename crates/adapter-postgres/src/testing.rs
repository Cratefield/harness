//! Shared Postgres test infrastructure: per-test throwaway databases on
//! the server named by `FZ_TEST_POSTGRES_URL`, so tests never see each
//! other's tables (issue #18).
//!
//! Exported so `cratefield-testing`'s parity kit (issue #20) reuses the
//! exact helper this crate's own contract tests use — one
//! implementation, not two. Tests skip with a printed reason when the
//! variable is unset (CI provides a `postgres:16` service container).

use sqlx::{Executor as _, Row as _};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// The server URL from `FZ_TEST_POSTGRES_URL`, when set (trimmed and
/// non-empty).
#[must_use]
pub fn base_url() -> Option<String> {
    std::env::var("FZ_TEST_POSTGRES_URL")
        .ok()
        .map(|url| url.trim().to_owned())
        .filter(|url| !url.is_empty())
}

/// The skip reason printed when a test cannot run without a server.
#[must_use]
pub fn skip_reason() -> String {
    "FZ_TEST_POSTGRES_URL is not set — start a local postgres:16 \
     (docker run --rm -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:16) \
     and set FZ_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5433/postgres"
        .to_owned()
}

fn url_with_database(base: &str, database: &str) -> String {
    let (path, query) = match base.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (base, None),
    };
    let (prefix, _) = path
        .rsplit_once('/')
        .expect("FZ_TEST_POSTGRES_URL must name a database");
    let mut url = format!("{prefix}/{database}");
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }
    url
}

/// A fresh database named `fz_<tag>_<pid>_<n>` on the given server;
/// call [`TempDb::finish`] to drop it.
pub struct TempDb {
    /// The connection string of the throwaway database.
    pub url: String,
    admin: sqlx::PgPool,
    database: String,
}

impl TempDb {
    /// Creates a throwaway database on `base` (the value of
    /// `FZ_TEST_POSTGRES_URL`). The name is unique per process and per
    /// call, so a previous run's leaked databases (a test that panicked
    /// before `finish`) never collide.
    ///
    /// # Panics
    ///
    /// Panics when the server refuses connections or cannot create the
    /// database — callers gate on [`base_url`] so a missing server is a
    /// skip, not a panic.
    pub async fn create(base: &str, tag: &str) -> Option<Self> {
        let admin = sqlx::PgPool::connect(base)
            .await
            .expect("FZ_TEST_POSTGRES_URL server accepts connections");
        let database = format!(
            "fz_{tag}_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        admin
            .execute(format!(r#"CREATE DATABASE "{database}""#).as_str())
            .await
            .expect("can create a throwaway test database");
        Some(Self {
            url: url_with_database(base, &database),
            admin,
            database,
        })
    }

    /// Asserts the server is the major version the contract is about.
    ///
    /// # Panics
    ///
    /// Panics when the server is not Postgres 16.
    pub async fn assert_postgres_16(&self) {
        let version: String = sqlx::query("SELECT version()")
            .fetch_one(&self.admin)
            .await
            .expect("server reports its version")
            .get(0);
        assert!(
            version.starts_with("PostgreSQL 16"),
            "contract is about Postgres 16, server is: {version}"
        );
    }

    /// Drops the throwaway database.
    ///
    /// # Panics
    ///
    /// Panics when the drop fails on a server that answered `create`.
    pub async fn finish(self) {
        let Self {
            admin,
            database,
            url: _,
        } = self;
        admin.close().await;
        // A fresh pool just for the DROP (the old one may still hold
        // connections to the database being dropped).
        if let Ok(dropper) =
            sqlx::PgPool::connect(&base_url().expect("create was called with a non-empty base url"))
                .await
        {
            dropper
                .execute(
                    // WITH (FORCE): the adapter under test still holds
                    // pool sessions; Postgres 13+ terminates them.
                    format!(r#"DROP DATABASE IF EXISTS "{database}" WITH (FORCE)"#).as_str(),
                )
                .await
                .expect("drop throwaway test database");
            dropper.close().await;
        }
    }
}
