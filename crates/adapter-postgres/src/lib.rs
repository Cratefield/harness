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
pub mod testing;

pub use migrate::select_set;

use async_trait::async_trait;
use cratefield_core::{Database, DbError, Rows, Statement};
use sqlx::postgres::PgArguments;

/// An open Postgres connection pool (`sqlx` 0.8, `runtime-tokio`,
/// `tls-rustls`).
///
/// One pool per tenant database: ADR 0008 keeps tenants isolated at the
/// database boundary, and the native runtime (#19) holds one adapter per
/// tenant.
pub struct Postgres {
    pool: sqlx::PgPool,
}

impl Postgres {
    /// Opens a pool and establishes at least one connection, failing fast
    /// on an unreachable server or bad credentials.
    ///
    /// # Errors
    ///
    /// [`DbError::Execute`] when the pool cannot connect.
    pub async fn connect(url: &str) -> Result<Self, DbError> {
        let pool = sqlx::PgPool::connect(url)
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
    async fn batch(&self, stmts: &[Statement]) -> Result<(), DbError> {
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
