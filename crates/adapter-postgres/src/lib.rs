//! `cratefield-adapter-postgres`: the [`Database`] port over `sqlx`
//! Postgres for the native runtime (ADR 0004, issue #18). Native only —
//! it must never enter a wasm build.
//!
//! # Native-only gate
//!
//! The sqlx driver does not compile to wasm, so this crate is impossible
//! to build for a wasm target: `src/lib.rs` fails compilation with a
//! clear message on `wasm32`/`wasm64`, and the sqlx dependency itself is
//! target-gated to non-wasm builds in `Cargo.toml`. The wasm graph of
//! `examples/venture` must stay free of this crate (CI asserts it with
//! `cargo tree --target wasm32-unknown-unknown -p venture | grep -c
//! sqlx` → 0).
//!
//! # Statement pipeline
//!
//! Modules build queries with sea-query; the port's [`Statement`] carries
//! them rendered with `SqliteQueryBuilder` (the portable `?`-placeholder
//! wire form D1 and rusqlite execute directly). This adapter rewrites `?`
//! to Postgres `$n` placeholders — skipping string literals, quoted
//! identifiers and comments — and binds the sea-query values positionally
//! (`src/convert.rs`). The migration runner's own
//! bookkeeping statements are rendered by sea-query's
//! `PostgresQueryBuilder` directly.
//!
//! # The SQLite → Postgres mapping actually used
//!
//! The portable subset (ADR 0004, architecture section 7) is deliberately
//! the intersection of SQLite and Postgres, so migration files run
//! verbatim on both engines:
//!
//! | Portable concept | SQLite | Postgres | Notes |
//! |---|---|---|---|
//! | ULID ids | `TEXT PRIMARY KEY` | `TEXT PRIMARY KEY` | no `AUTOINCREMENT`/`SERIAL` anywhere |
//! | timestamps | ISO-8601 `TEXT` | ISO-8601 `TEXT` | computed in Rust, never `NOW()`/`datetime()` |
//! | counters | `INTEGER` | `INTEGER` (`int4`) | `referrals`, `position` |
//! | booleans | `INTEGER 0/1` by convention | `INTEGER 0/1` by convention | no SQL `BOOLEAN` columns; `SeaValue::Bool` binds as `SMALLINT` 0/1, and rows read back through `Row::get::<bool>` accept both |
//! | upserts | `INSERT … ON CONFLICT …` | identical syntax | rendered by sea-query for both dialects |
//! | read-back writes | `INSERT … RETURNING …` | identical syntax | rendered by sea-query for both dialects |
//!
//! `batch` runs all statements in one transaction (atomic, ADR 0004).
//!
//! ```no_run
//! # async fn demo() -> Result<(), cratefield_core::DbError> {
//! use cratefield_adapter_postgres::Postgres;
//!
//! let db = Postgres::connect("postgres://user:pass@host:5432/venture").await?;
//! // db.apply_harness_migrations(&harness).await?;   // library entry point
//! // … or through Arc<dyn Database> as with any adapter
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

// The whole crate is native-only (issue #18): fail a wasm build of this
// crate fast, with a clear message, before sqlx is even attempted.
#[cfg(any(target_arch = "wasm32", target_arch = "wasm64"))]
compile_error!(
    "cratefield-adapter-postgres is native-only: the sqlx Postgres driver does not \
     compile to wasm (issue #18, ADR 0004). A wasm target must not depend on this \
     crate — check the wasm dependency graph of the venture (modules see ports, \
     never adapters, and runtime-native is the only consumer)."
);

mod convert;
mod migrate;
mod reconcile;
mod registry;
pub mod testing;

pub use cratefield_core::TenantStatus;
pub use migrate::select_set;
pub use reconcile::{ModulePlan, TenantPlan, TenantRecord, TenantReport, tenant_lock_key};
pub use registry::{PoolRegistry, TENANT_POOL_IDLE, TENANT_POOL_TOTAL, TenantDsns};

use async_trait::async_trait;
use cratefield_core::{Database, DbError, Rows, Statement};
use sqlx::postgres::PgArguments;

/// An open Postgres connection pool (`sqlx` 0.8, `runtime-tokio`,
/// `tls-rustls`).
///
/// One pool per tenant database: ADR 0008 keeps tenants isolated at the
/// database boundary, and the native runtime (#19) holds one adapter per
/// tenant.
/// What one tenant's pool may take (TENANT-ROUTING.md §4).
///
/// The per-tenant cap is what stops one busy tenant taking every
/// connection on a shared cluster; the idle timeout is what stops a
/// replica's cost scaling with the tenant count rather than with its
/// traffic, since a pool that no request has touched should not hold
/// connections open.
///
/// `acquire_timeout` is the fail-closed half: a checkout that cannot be
/// served refuses with a deadline rather than queueing unboundedly, which
/// is the same instinct as the outbound budget in #136.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolLimits {
    /// Connections one tenant's pool may hold. Default 8.
    pub max_connections: u32,
    /// A pool with no checkout for this long closes its connections.
    /// Default 5 minutes.
    pub idle_timeout: Option<std::time::Duration>,
    /// How long a checkout waits before refusing. Default 5 seconds.
    pub acquire_timeout: std::time::Duration,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            max_connections: 8,
            idle_timeout: Some(std::time::Duration::from_secs(300)),
            acquire_timeout: std::time::Duration::from_secs(5),
        }
    }
}

#[derive(Clone)]
pub struct Postgres {
    pool: sqlx::PgPool,
}

impl Postgres {
    /// Opens a pool and establishes at least one connection, failing fast
    /// on an unreachable server or bad credentials.
    ///
    /// Uses [`PoolLimits::default`]. A multi-tenant deployment wants
    /// [`Postgres::connect_with`] instead: one pool per tenant with no cap
    /// is how one busy tenant takes every connection on a shared cluster.
    ///
    /// # Errors
    ///
    /// [`DbError::Execute`] when the pool cannot connect.
    pub async fn connect(url: &str) -> Result<Self, DbError> {
        Self::connect_with(url, PoolLimits::default()).await
    }

    /// Opens a pool with explicit limits (TENANT-ROUTING.md §4).
    ///
    /// `sqlx` caps and times out *per pool*, which is exactly the
    /// per-tenant boundary: a pool belongs to one tenant. The **total**
    /// across pools is not something `sqlx` can express, so it is not
    /// pretended to here — it needs a semaphore held by whatever owns the
    /// pools, acquired around every `execute`, `query` and `batch`. A
    /// config key that silently did nothing would be worse than its
    /// absence.
    ///
    /// # Errors
    ///
    /// [`DbError::Execute`] when the pool cannot connect.
    pub async fn connect_with(url: &str, limits: PoolLimits) -> Result<Self, DbError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(limits.max_connections)
            .idle_timeout(limits.idle_timeout)
            .acquire_timeout(limits.acquire_timeout)
            .connect(url)
            .await
            .map_err(|err| DbError::Execute(err.to_string()))?;
        Ok(Self { pool })
    }

    /// Prepares a port statement for execution: rewrites `?` placeholders
    /// to `$n` and binds the sea-query values.
    fn prepare(stmt: &Statement) -> Result<(String, PgArguments), DbError> {
        let sql = convert::rebind_placeholders(&stmt.sql);
        let mut args = PgArguments::default();
        convert::bind_values(&mut args, &stmt.values.0)?;
        Ok((sql, args))
    }

    /// Closes the pool: waits for in-flight queries, then closes every
    /// connection. Dropping the adapter eventually closes the pool too;
    /// `close` makes shutdown deterministic for the parity kit and the
    /// native runtime.
    ///
    /// # Errors
    ///
    /// [`DbError::Execute`] when the pool cannot be closed.
    pub async fn close(&self) -> Result<(), DbError> {
        self.pool.close().await;
        Ok(())
    }
}

#[async_trait]
impl Database for Postgres {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        let (sql, args) = Self::prepare(stmt)?;
        let result = sqlx::query_with(sql.as_str(), args)
            .execute(&self.pool)
            .await
            .map_err(|err| DbError::Execute(err.to_string()))?;
        Ok(result.rows_affected())
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        let (sql, args) = Self::prepare(stmt)?;
        let rows = sqlx::query_with(sql.as_str(), args)
            .fetch_all(&self.pool)
            .await
            .map_err(|err| DbError::Query(err.to_string()))?;
        Ok(Rows::new(rows.iter().map(convert::pg_row_to_row).collect()))
    }

    /// Runs all statements in one transaction (atomic on Postgres).
    async fn batch_atomic(&self, stmts: &[Statement]) -> Result<(), DbError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| DbError::Batch(err.to_string()))?;
        for stmt in stmts {
            let (sql, args) = Self::prepare(stmt)?;
            sqlx::query_with(sql.as_str(), args)
                .execute(&mut *tx)
                .await
                .map_err(|err| DbError::Batch(err.to_string()))?;
        }
        tx.commit()
            .await
            .map_err(|err| DbError::Batch(err.to_string()))?;
        Ok(())
    }
}
