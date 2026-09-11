//! The pool registry (issue #32, TENANT-ROUTING.md §4): lazy, evicted
//! when idle, and capped both per tenant and in total.
//!
//! Skipped with a printed reason when `FZ_TEST_POSTGRES_URL` is unset; CI
//! provides a `postgres:16` service container.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use common::{TempDb, base_url, skip_reason};
use cratefield_adapter_postgres::{PoolLimits, PoolRegistry, TenantDsns};
use cratefield_core::{Clock, Database, Statement, Tenant, TenantDatabases, TenantStatus};

/// A clock whose `now` the test moves, so idle eviction is deterministic
/// rather than a sleep.
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

/// Hands out one DSN for every tenant it knows, and records every lookup
/// so a test can prove a pool was opened once rather than per request.
struct Dsns {
    url: String,
    known: Vec<String>,
    lookups: std::sync::Mutex<Vec<String>>,
}

impl Dsns {
    fn lookups(&self) -> Vec<String> {
        self.lookups.lock().expect("lookup lock").clone()
    }
}

#[async_trait]
impl TenantDsns for Dsns {
    async fn dsn(&self, tenant: &str) -> Result<Option<String>, String> {
        self.lookups
            .lock()
            .expect("lookup lock")
            .push(tenant.to_owned());
        Ok(self
            .known
            .iter()
            .any(|known| known == tenant)
            .then(|| self.url.clone()))
    }
}

/// Core mints a `Tenant`; a test cannot. Resolution is the only route, so
/// a test goes through it too — which is the boundary working.
fn tenant(id: &str) -> Tenant {
    Tenant::for_test(id, TenantStatus::Active)
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
    let dsns = Arc::new(Dsns {
        url: temp.url.clone(),
        known: vec!["a".to_owned()],
        lookups: std::sync::Mutex::new(Vec::new()),
    });
    let registry = PoolRegistry::new(Arc::clone(&dsns) as Arc<dyn TenantDsns>, StepClock::new());

    assert_eq!(registry.open_pools(), 0, "nothing opens at construction");

    for _ in 0..3 {
        let db = registry.database(&tenant("a")).await.expect("opens");
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
    let dsns = Arc::new(Dsns {
        url: temp.url.clone(),
        known: vec!["a".to_owned()],
        lookups: std::sync::Mutex::new(Vec::new()),
    });
    let clock = StepClock::new();
    let registry = PoolRegistry::with_limits(
        Arc::clone(&dsns) as Arc<dyn TenantDsns>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        PoolLimits::default(),
        8,
        Duration::from_secs(60),
    );

    registry.database(&tenant("a")).await.expect("opens");
    assert_eq!(registry.open_pools(), 1);

    // Past the idle window, the next handout sweeps it.
    clock.advance(120);
    registry.database(&tenant("a")).await.expect("reopens");
    assert_eq!(registry.open_pools(), 1, "reopened, not accumulated");
    assert_eq!(
        dsns.lookups().len(),
        2,
        "a reopen reads the DSN again, which is what makes eviction real"
    );
    temp.finish().await;
}

#[tokio::test]
async fn one_tenant_cannot_starve_the_others_of_the_total() {
    // #32's starvation criterion. The total is one, held by A, so B's
    // checkout must refuse on its deadline rather than wait for A.
    let Some(url) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(temp) = TempDb::create(&url, "regstarve").await else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let dsns = Arc::new(Dsns {
        url: temp.url.clone(),
        known: vec!["a".to_owned(), "b".to_owned()],
        lookups: std::sync::Mutex::new(Vec::new()),
    });
    let registry = Arc::new(PoolRegistry::with_limits(
        Arc::clone(&dsns) as Arc<dyn TenantDsns>,
        StepClock::new(),
        PoolLimits {
            max_connections: 4,
            idle_timeout: None,
            acquire_timeout: Duration::from_millis(400),
        },
        1, // the whole process may hold one connection at a time
        Duration::from_secs(300),
    ));

    let a = registry.database(&tenant("a")).await.expect("a opens");
    let b = registry.database(&tenant("b")).await.expect("b opens");

    // A holds the only permit for two seconds.
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

    // And once A is done, B works again — a refusal is backpressure, not
    // a broken pool.
    b.query(&Statement::new("SELECT 1"))
        .await
        .expect("B recovers once the budget frees");
    temp.finish().await;
}

#[tokio::test]
async fn a_tenant_with_no_dsn_is_unreachable_and_names_no_url() {
    let Some(url) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(temp) = TempDb::create(&url, "regmissing").await else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let dsns = Arc::new(Dsns {
        url: temp.url.clone(),
        known: vec!["a".to_owned()],
        lookups: std::sync::Mutex::new(Vec::new()),
    });
    let registry = PoolRegistry::new(Arc::clone(&dsns) as Arc<dyn TenantDsns>, StepClock::new());

    // `dyn Database` is not `Debug`, so the Ok arm cannot be unwrapped
    // into a message; match instead.
    let err = match registry.database(&tenant("nobody")).await {
        Ok(_) => panic!("an unknown tenant must not get a handle"),
        Err(err) => err,
    };
    let rendered = format!("{err}");
    assert!(rendered.contains("nobody"), "names the tenant: {rendered}");
    assert!(
        !rendered.contains("postgres://") && !rendered.contains('@'),
        "and never the connection string: {rendered}"
    );
    assert_eq!(registry.open_pools(), 0, "and opened nothing");
    temp.finish().await;
}
