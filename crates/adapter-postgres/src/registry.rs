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

/// Why a keyed pool could not be produced. Internal: every variant is a
/// [`TenantDbError::Unreachable`] to a caller, but which one it was is
/// worth having in a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolError {
    /// The source has no connection string under that key.
    NoDsn,
    /// The source itself failed.
    Lookup,
    /// The server refused or did not answer.
    Connect,
}

impl PoolRegistry {
    /// The pool for `key`, opened on first use and reused after.
    ///
    /// **Keyed, not tenanted.** Lazy open, idle eviction and both caps are
    /// pool bookkeeping and have nothing to do with tenancy, so they live
    /// here and are tested by string. What makes a key a *tenant* is the
    /// [`TenantDatabases`] impl below, which is short enough to be correct
    /// by inspection — the split is deliberate, so that the part with the
    /// interesting behaviour does not need a `Tenant` to test and core's
    /// private constructor can stay private.
    pub(crate) async fn pool_for(&self, key: &str) -> Result<Arc<CappedDb>, PoolError> {
        let now = self.now_secs();

        for stale in self.evict_idle(now) {
            let _ = stale.inner.close().await;
        }

        if let Some(cached) = self.pools.lock().expect("pool lock").get_mut(key) {
            cached.last_used = now;
            return Ok(Arc::clone(&cached.db));
        }

        // The DSN exists only inside this block, and the error it could be
        // folded into is discarded rather than formatted.
        let dsn = self
            .dsns
            .dsn(key)
            .await
            .map_err(|_| PoolError::Lookup)?
            .ok_or(PoolError::NoDsn)?;
        let pool = Postgres::connect_with(&dsn, self.limits)
            .await
            .map_err(|_| PoolError::Connect)?;
        drop(dsn);

        let db = Arc::new(CappedDb {
            inner: pool,
            total: Arc::clone(&self.total),
            acquire_timeout: self.limits.acquire_timeout,
            clock: Arc::clone(&self.clock),
            key: key.to_owned(),
        });
        self.pools.lock().expect("pool lock").insert(
            key.to_owned(),
            Cached {
                db: Arc::clone(&db),
                last_used: now,
            },
        );
        Ok(db)
    }
}

#[async_trait]
impl TenantDatabases for PoolRegistry {
    /// The tenant half, and all of it: a tenant's key is its id.
    ///
    /// Every way the lookup can miss is one answer to the caller — the
    /// tenant's database is unreachable — because the distinction between
    /// "no DSN
    /// recorded" and "the server refused" is an operator's question, not
    /// the caller's, and answering it in a response body would describe
    /// the deployment to a stranger.
    async fn database(&self, tenant: &Tenant) -> Result<Arc<dyn Database>, TenantDbError> {
        match self.pool_for(tenant.id().as_str()).await {
            Ok(db) => Ok(db as Arc<dyn Database>),
            Err(why) => {
                tracing::warn!(tenant = %tenant.id(), reason = ?why, "no pool for tenant");
                Err(TenantDbError::Unreachable {
                    tenant: tenant.id().to_string(),
                })
            }
        }
    }
}

/// A tenant's pool with the process-wide total applied around every
/// operation.
pub(crate) struct CappedDb {
    inner: Postgres,
    total: Arc<tokio::sync::Semaphore>,
    acquire_timeout: Duration,
    clock: Arc<dyn Clock>,
    key: String,
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
                "`{}` waited out the connection budget",
                self.key
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

#[cfg(test)]
#[allow(clippy::disallowed_types)] // recording fakes, not request state
mod tests {
    use super::*;
    use crate::testing::{TempDb, base_url, skip_reason};
    use cratefield_core::Statement;

    /// A clock the test moves, so idle eviction is deterministic rather
    /// than a sleep.
    struct StepClock {
        offset: std::sync::atomic::AtomicI64,
    }

    impl StepClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                offset: std::sync::atomic::AtomicI64::new(0),
            })
        }

        fn advance(&self, secs: i64) {
            self.offset
                .fetch_add(secs, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl Clock for StepClock {
        fn now(&self) -> time::OffsetDateTime {
            time::OffsetDateTime::now_utc()
                + time::Duration::seconds(self.offset.load(std::sync::atomic::Ordering::SeqCst))
        }

        async fn timeout_any(
            &self,
            fut: cratefield_core::BoxFuture<'static, Box<dyn std::any::Any + Send>>,
            after: Duration,
        ) -> Option<Box<dyn std::any::Any + Send>> {
            tokio::time::timeout(after, fut).await.ok()
        }
    }

    /// Hands out one DSN for the keys it knows, and records every lookup
    /// so a test can prove a pool opened once rather than per request.
    struct Dsns {
        url: String,
        known: Vec<String>,
        lookups: std::sync::Mutex<Vec<String>>,
    }

    impl Dsns {
        fn new(url: &str, known: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                url: url.to_owned(),
                known: known.iter().map(|k| (*k).to_owned()).collect(),
                lookups: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn lookups(&self) -> Vec<String> {
            self.lookups.lock().expect("lookup lock").clone()
        }
    }

    #[async_trait]
    impl TenantDsns for Dsns {
        async fn dsn(&self, key: &str) -> Result<Option<String>, String> {
            self.lookups
                .lock()
                .expect("lookup lock")
                .push(key.to_owned());
            Ok(self
                .known
                .iter()
                .any(|known| known == key)
                .then(|| self.url.clone()))
        }
    }

    #[tokio::test]
    async fn a_pool_opens_on_first_use_and_is_reused() {
        let Some(url) = base_url() else {
            eprintln!("SKIPPED: {}", skip_reason());
            return;
        };
        let Some(temp) = TempDb::create(&url, "reglazy").await else {
            eprintln!("SKIPPED: {}", skip_reason());
            return;
        };
        let dsns = Dsns::new(&temp.url, &["a"]);
        let registry =
            PoolRegistry::new(Arc::clone(&dsns) as Arc<dyn TenantDsns>, StepClock::new());

        assert_eq!(registry.open_pools(), 0, "nothing opens at construction");
        for _ in 0..3 {
            let db = registry.pool_for("a").await.expect("opens");
            db.query(&Statement::new("SELECT 1"))
                .await
                .expect("queries");
        }

        assert_eq!(registry.open_pools(), 1);
        assert_eq!(
            dsns.lookups(),
            vec!["a".to_owned()],
            "the DSN is read once, not per request"
        );
        temp.finish().await;
    }

    #[tokio::test]
    async fn an_idle_pool_is_closed_and_reopens_on_the_next_request() {
        let Some(url) = base_url() else {
            eprintln!("SKIPPED: {}", skip_reason());
            return;
        };
        let Some(temp) = TempDb::create(&url, "regidle").await else {
            eprintln!("SKIPPED: {}", skip_reason());
            return;
        };
        let dsns = Dsns::new(&temp.url, &["a"]);
        let clock = StepClock::new();
        let registry = PoolRegistry::with_limits(
            Arc::clone(&dsns) as Arc<dyn TenantDsns>,
            Arc::clone(&clock) as Arc<dyn Clock>,
            PoolLimits::default(),
            8,
            Duration::from_secs(60),
        );

        registry.pool_for("a").await.expect("opens");
        assert_eq!(registry.open_pools(), 1);

        clock.advance(120);
        registry.pool_for("a").await.expect("reopens");
        assert_eq!(registry.open_pools(), 1, "reopened, not accumulated");
        assert_eq!(
            dsns.lookups().len(),
            2,
            "a reopen reads the DSN again, which is what makes eviction real"
        );
        temp.finish().await;
    }

    #[tokio::test]
    async fn one_key_cannot_starve_the_others_of_the_total() {
        // #32's starvation criterion, in the terms it actually lives in:
        // the total is one, held by A, so B must refuse on its deadline
        // rather than queue behind A.
        let Some(url) = base_url() else {
            eprintln!("SKIPPED: {}", skip_reason());
            return;
        };
        let Some(temp) = TempDb::create(&url, "regstarve").await else {
            eprintln!("SKIPPED: {}", skip_reason());
            return;
        };
        let dsns = Dsns::new(&temp.url, &["a", "b"]);
        let registry = Arc::new(PoolRegistry::with_limits(
            Arc::clone(&dsns) as Arc<dyn TenantDsns>,
            StepClock::new(),
            PoolLimits {
                max_connections: 4,
                idle_timeout: None,
                acquire_timeout: Duration::from_millis(400),
            },
            1,
            Duration::from_secs(300),
        ));

        let a = registry.pool_for("a").await.expect("a opens");
        let b = registry.pool_for("b").await.expect("b opens");

        let hold = tokio::spawn(async move {
            let _ = a.query(&Statement::new("SELECT pg_sleep(2)")).await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let started = std::time::Instant::now();
        let refused = b.query(&Statement::new("SELECT 1")).await;
        let waited = started.elapsed();

        assert!(
            refused.is_err(),
            "B must be refused rather than queued behind A: {refused:?}"
        );
        assert!(
            waited < Duration::from_millis(1_500),
            "and refused on its own deadline, not after A finished: {waited:?}"
        );
        let _ = hold.await;

        // A refusal is backpressure, not a broken pool.
        b.query(&Statement::new("SELECT 1"))
            .await
            .expect("B recovers once the budget frees");
        temp.finish().await;
    }

    #[tokio::test]
    async fn an_unknown_key_opens_nothing_and_says_which_kind_of_miss() {
        let Some(url) = base_url() else {
            eprintln!("SKIPPED: {}", skip_reason());
            return;
        };
        let Some(temp) = TempDb::create(&url, "regmissing").await else {
            eprintln!("SKIPPED: {}", skip_reason());
            return;
        };
        let dsns = Dsns::new(&temp.url, &["a"]);
        let registry =
            PoolRegistry::new(Arc::clone(&dsns) as Arc<dyn TenantDsns>, StepClock::new());

        assert_eq!(
            registry.pool_for("nobody").await.err(),
            Some(PoolError::NoDsn)
        );
        assert_eq!(registry.open_pools(), 0, "and opened nothing");
        temp.finish().await;
    }
}
