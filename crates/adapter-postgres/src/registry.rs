//! [`PoolRegistry`]: one connection pool per tenant, opened on first use
//! and closed when idle (TENANT-ROUTING.md §4, issue #32).
//!
//! **Lazy, not eager.** Boot reconciliation already touches every tenant
//! database; holding those connections afterwards would make a replica's
//! idle cost scale with the tenant count rather than with its traffic.
//! The registry is a cache, not an inventory.
//!
//! **Two caps, because one is not enough.** `sqlx` caps *per pool*, which
//! is exactly the per-tenant boundary — a pool belongs to one tenant, and
//! that cap is what stops one busy tenant taking every connection on a
//! shared cluster. It cannot express a total across pools, which is the
//! failure the per-tenant cap does not prevent: the process taking every
//! connection on the *server*. So the total is a semaphore this registry
//! holds, acquired around every `execute`, `query` and `batch` — and for
//! a `batch` the permit spans the whole batch, because `batch` holds its
//! connection across `pool.begin()`.
//!
//! Without that semaphore `TENANT_POOL_TOTAL` would be a config key that
//! does nothing, which is worse than not having it: it reads as
//! protection.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cratefield_core::{
    Clock, Database, DbError, Rows, Statement, Tenant, TenantDatabases, TenantDbError,
};

use crate::{PoolLimits, Postgres};

/// Where a tenant's connection string comes from.
///
/// A trait rather than a hard-wired lookup, because the answer is not
/// settled: the control database's registry carries a `dsn` column, and
/// the secrets design (#39) puts it at `tenants/<id>/db_ref` behind a
/// `HarnessOnly` proof. Both are defensible and the choice is a
/// deployment's, so the registry takes whichever and never decides.
///
/// Whatever supplies it, the DSN stops here: [`PoolRegistry`] is the only
/// thing that holds one, and it maps a connect failure to
/// [`TenantDbError::Unreachable`] before the URL can reach a log line or
/// a response body.
#[async_trait]
pub trait TenantDsns: Send + Sync {
    /// The connection string for `tenant`, or `None` if it has none.
    ///
    /// # Errors
    ///
    /// Any lookup failure, as a message that must not contain the DSN.
    async fn dsn(&self, tenant: &str) -> Result<Option<String>, String>;
}

/// The default total across every tenant pool in this process.
///
/// A guess pending a measurement against a real cluster's
/// `max_connections` and the replica count — recorded as one in
/// TENANT-ROUTING.md §12 rather than presented as a finding. Note that
/// boot reconciliation runs 8 tenants concurrently and the control
/// database has its own pool; both draw on the same server limit and
/// neither is inside this cap.
pub const TENANT_POOL_TOTAL: usize = 64;

/// How long a pool with no checkout survives before it is closed.
pub const TENANT_POOL_IDLE: Duration = Duration::from_secs(300);

struct Cached {
    db: Arc<CappedDb>,
    /// Unix seconds of the last handout. Coarse on purpose: this decides
    /// eviction, not correctness.
    last_used: i64,
}

/// Pools per tenant, with both caps applied.
pub struct PoolRegistry {
    dsns: Arc<dyn TenantDsns>,
    limits: PoolLimits,
    idle: Duration,
    clock: Arc<dyn Clock>,
    total: Arc<tokio::sync::Semaphore>,
    // Not request state (ADR 0007): deployment-scoped, outlives every
    // request, and shared by all of them.
    #[allow(clippy::disallowed_types)]
    pools: std::sync::Mutex<HashMap<String, Cached>>,
}

impl PoolRegistry {
    /// A registry with the default caps.
    #[must_use]
    pub fn new(dsns: Arc<dyn TenantDsns>, clock: Arc<dyn Clock>) -> Self {
        Self::with_limits(
            dsns,
            clock,
            PoolLimits::default(),
            TENANT_POOL_TOTAL,
            TENANT_POOL_IDLE,
        )
    }

    /// A registry with explicit caps.
    // The pool map is deployment-scoped shared state that outlives every
    // request, not the ambient request state ADR 0007 bans — the same
    // category as the sidecar probe cache in core's harness.
    #[allow(clippy::disallowed_types)]
    #[must_use]
    pub fn with_limits(
        dsns: Arc<dyn TenantDsns>,
        clock: Arc<dyn Clock>,
        limits: PoolLimits,
        total: usize,
        idle: Duration,
    ) -> Self {
        Self {
            dsns,
            limits,
            idle,
            clock,
            total: Arc::new(tokio::sync::Semaphore::new(total.max(1))),
            pools: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// How many pools are open right now. For tests and `/__health`;
    /// never a correctness signal — TENANT-ROUTING.md §12 makes the
    /// *registry row* authoritative, precisely so that pool presence
    /// cannot be mistaken for tenant health.
    ///
    /// # Panics
    ///
    /// If the pool map's lock was poisoned by a panic in another thread.
    /// Poisoning here means a previous handout panicked mid-map, and
    /// continuing on a map in an unknown state is worse than stopping.
    #[must_use]
    pub fn open_pools(&self) -> usize {
        self.pools.lock().expect("pool lock").len()
    }

    /// Closes every pool whose last handout is older than the idle
    /// window. Called on each handout, so a busy deployment sweeps itself
    /// and an idle one costs nothing.
    fn evict_idle(&self, now: i64) -> Vec<Arc<CappedDb>> {
        let cutoff = now.saturating_sub(i64::try_from(self.idle.as_secs()).unwrap_or(i64::MAX));
        let mut pools = self.pools.lock().expect("pool lock");
        let stale: Vec<String> = pools
            .iter()
            .filter(|(_, cached)| cached.last_used < cutoff)
            .map(|(tenant, _)| tenant.clone())
            .collect();
        // Returned rather than closed under the lock: `close` awaits
        // in-flight queries, and holding a std Mutex across an await is
        // the deadlock this avoids by construction.
        stale
            .into_iter()
            .filter_map(|tenant| pools.remove(&tenant).map(|cached| cached.db))
            .collect()
    }

    fn now_secs(&self) -> i64 {
        self.clock.now().unix_timestamp()
    }
}

#[async_trait]
impl TenantDatabases for PoolRegistry {
    async fn database(&self, tenant: &Tenant) -> Result<Arc<dyn Database>, TenantDbError> {
        let id = tenant.id().as_str().to_owned();
        let now = self.now_secs();

        for stale in self.evict_idle(now) {
            let _ = stale.inner.close().await;
        }

        if let Some(cached) = self.pools.lock().expect("pool lock").get_mut(&id) {
            cached.last_used = now;
            return Ok(Arc::clone(&cached.db) as Arc<dyn Database>);
        }

        let unreachable = || TenantDbError::Unreachable { tenant: id.clone() };
        // The DSN exists only inside this block, and the error it could be
        // folded into is discarded rather than formatted.
        let dsn = self
            .dsns
            .dsn(&id)
            .await
            .map_err(|_| unreachable())?
            .ok_or_else(unreachable)?;
        let pool = Postgres::connect_with(&dsn, self.limits)
            .await
            .map_err(|_| unreachable())?;
        drop(dsn);

        let db = Arc::new(CappedDb {
            inner: pool,
            total: Arc::clone(&self.total),
            acquire_timeout: self.limits.acquire_timeout,
            clock: Arc::clone(&self.clock),
            tenant: id.clone(),
        });
        self.pools.lock().expect("pool lock").insert(
            id,
            Cached {
                db: Arc::clone(&db),
                last_used: now,
            },
        );
        Ok(db as Arc<dyn Database>)
    }
}

/// A tenant's pool with the process-wide total applied around every
/// operation.
struct CappedDb {
    inner: Postgres,
    total: Arc<tokio::sync::Semaphore>,
    acquire_timeout: Duration,
    clock: Arc<dyn Clock>,
    tenant: String,
}

impl CappedDb {
    /// A permit from the process-wide total, or a refusal on the deadline.
    ///
    /// Refuses rather than queues: an unbounded queue turns a connection
    /// shortage into an unbounded latency, which is the failure #136's
    /// outbound budget refuses for the same reason.
    async fn permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, DbError> {
        let total = Arc::clone(&self.total);
        let acquire = async move { total.acquire_owned().await };
        match cratefield_core::timeout(&*self.clock, acquire, self.acquire_timeout).await {
            Some(Ok(permit)) => Ok(permit),
            // The semaphore is never closed, so `Err` is unreachable; it
            // is mapped rather than unwrapped because an unreachable
            // panic in a database path is not worth the line it saves.
            Some(Err(_)) | None => Err(DbError::Execute(format!(
                "tenant `{}` waited out the connection budget",
                self.tenant
            ))),
        }
    }
}

#[async_trait]
impl Database for CappedDb {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        let _permit = self.permit().await?;
        self.inner.execute(stmt).await
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        let _permit = self.permit().await?;
        self.inner.query(stmt).await
    }

    async fn batch(&self, stmts: &[Statement]) -> Result<(), DbError> {
        // One permit for the whole batch: `batch` holds its connection
        // across `pool.begin()`, so a per-statement permit would let the
        // total be exceeded by exactly the number of open transactions.
        let _permit = self.permit().await?;
        self.inner.batch(stmts).await
    }
}
