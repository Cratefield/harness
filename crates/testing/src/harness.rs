//! [`TestHarness`]: a built harness over fakes with an in-memory SQLite
//! database whose migrations are applied per module at creation
//! (issue #9).

use factory0_adapter_sqlite::SqliteDatabase;
use factory0_core::{
    Harness, HmacSigner, MapConfig, Module, Port, Ports, Runtime, UlidIdGen, Venture,
};
use std::sync::Arc;

use crate::fakes::{
    FakeCaptcha, FakeDefer, FakeHttpClient, FakeMailer, FakeRateLimiter, FixedClock, MemoryKeyValue,
};

struct TestRuntime;

impl Runtime for TestRuntime {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

/// A harness with every port faked and an in-memory SQLite database,
/// migrations applied per module on creation. The same database handle is
/// wired into the router and exposed for assertions.
pub struct TestHarness {
    /// The assembled router: hand it to [`crate::request`].
    pub router: axum::Router,
    pub harness: Harness,
    pub mailer: FakeMailer,
    pub captcha: FakeCaptcha,
    pub rate_limiter: FakeRateLimiter,
    pub clock: FixedClock,
    pub kv: MemoryKeyValue,
    pub http: FakeHttpClient,
    pub defer: FakeDefer,
    pub signer: Arc<HmacSigner>,
    /// The in-memory SQLite database backing the `Database` port (shared
    /// with the router — assertions see module writes).
    pub db: Arc<SqliteDatabase>,
    /// The modules passed in (for conformance access).
    pub modules: Vec<Arc<dyn Module>>,
}

impl TestHarness {
    /// Builds the harness (venture `test-venture.test`), applies every
    /// module's sqlite migrations to a fresh in-memory database, and
    /// assembles the router.
    ///
    /// # Panics
    ///
    /// Panics when the harness cannot build (invalid module set) or a
    /// migration fails — exactly what a module test should surface.
    #[must_use]
    pub fn new(modules: Vec<Box<dyn Module>>) -> Self {
        let shared: Vec<Arc<dyn Module>> = modules.into_iter().map(Arc::from).collect();
        let mut builder = Harness::builder().venture(
            Venture::new("test-venture", "test.example").cors_origins(["https://test.example"]),
        );
        for module in &shared {
            builder = builder.module_arc(Arc::clone(module));
        }
        let harness = builder
            .runtime(TestRuntime)
            .build()
            .expect("test harness builds");

        let db = Arc::new(SqliteDatabase::in_memory().expect("in-memory sqlite"));
        for module in &shared {
            db.apply_migrations(module.name(), module.migrations().sqlite)
                .unwrap_or_else(|err| panic!("migration for {}: {err}", module.name()));
        }

        let mailer = FakeMailer::new(crate::fakes::MailerMode::SendOk);
        let captcha = FakeCaptcha::allow_all();
        let rate_limiter = FakeRateLimiter::always_allow();
        let clock = FixedClock(
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed epoch"),
        );
        let kv = MemoryKeyValue::new();
        let http = FakeHttpClient::ok_json("{}");
        let defer = FakeDefer::new();
        let signer = Arc::new(
            HmacSigner::new(crate::TEST_HARNESS_SECRET, None).expect("test secret is long enough"),
        );

        let mut ports = Ports::with_config(Arc::new(MapConfig::default()));
        ports.db = Some(db.clone());
        ports.mailer = Some(Arc::new(mailer.clone()));
        ports.captcha = Some(Arc::new(captcha.clone()));
        ports.rate_limiter = Some(Arc::new(rate_limiter.clone()));
        ports.signer = Some(signer.clone());
        ports.kv = Some(Arc::new(kv.clone()));
        ports.http = Some(Arc::new(http.clone()));
        ports.clock = Some(Arc::new(clock.clone()));
        ports.id_gen = Some(Arc::new(UlidIdGen));
        ports.defer = Some(Arc::new(defer.clone()));

        let router = harness.router(ports);
        Self {
            router,
            harness,
            mailer,
            captcha,
            rate_limiter,
            clock,
            kv,
            http,
            defer,
            signer,
            db,
            modules: shared,
        }
    }
}
