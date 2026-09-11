//! Contract test (issue #30): boot-time reconciliation on Postgres 16 —
//! the tenant registry, the advisory-lock serialisation, idempotent
//! re-runs, plan mode, and the degraded-tenant behaviour
//! (RECONCILIATION.md). Skipped with a printed reason when
//! `FZ_TEST_POSTGRES_URL` is unset; CI provides a `postgres:16` service
//! container.

mod common;

use common::{TempDb, base_url, skip_reason};
use cratefield_adapter_postgres::{Postgres, TenantStatus};
use cratefield_core::{
    Database as _, Harness, Migrations, Module, ModuleContext, Port, Runtime, SqlMigration, Venture,
};

struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

/// A two-module harness with a real `depends_on` edge, so the contract
/// also sees the dependency order the runner must respect.
struct Base;

impl Module for Base {
    fn name(&self) -> &'static str {
        "recon-base"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }
    fn depends_on(&self) -> &'static [&'static str] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [SqlMigration::new(
            "0001",
            "init",
            "CREATE TABLE recon_base (id TEXT PRIMARY KEY);",
        )];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }
    fn validate_config(
        &self,
        _: &dyn cratefield_core::Config,
    ) -> Result<(), cratefield_core::ConfigError> {
        Ok(())
    }
    fn router(&self, _: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

struct Dependant;

impl Module for Dependant {
    fn name(&self) -> &'static str {
        "recon-dependant"
    }
    fn version(&self) -> &'static str {
        "0.1.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }
    fn depends_on(&self) -> &'static [&'static str] {
        &["recon-base"]
    }
    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [SqlMigration::new(
            "0001",
            "init",
            "CREATE TABLE recon_dependant (base_id TEXT REFERENCES recon_base (id));",
        )];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }
    fn validate_config(
        &self,
        _: &dyn cratefield_core::Config,
    ) -> Result<(), cratefield_core::ConfigError> {
        Ok(())
    }
    fn router(&self, _: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

fn harness() -> Harness {
    Harness::builder()
        .venture(Venture::new("recon", "recon.example").cors_origins(["https://recon.example"]))
        .module(Dependant) // listed first: the depends_on edge must reorder
        .module(Base)
        .runtime(AllPorts)
        .build()
        .expect("harness builds")
}

#[tokio::test]
async fn registry_bootstraps_and_reconcile_applies_idempotently() {
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(control_db) = TempDb::create(&base, "reconctl").await else {
        panic!("throwaway database creation failed");
    };
    let Some(tenant_db) = TempDb::create(&base, "recon").await else {
        panic!("throwaway database creation failed");
    };
    control_db.assert_postgres_16().await;

    let control = Postgres::connect(&control_db.url)
        .await
        .expect("connect to the control database");
    control
        .bootstrap_registry()
        .await
        .expect("registry bootstraps");
    control
        .bootstrap_registry()
        .await
        .expect("bootstrap is idempotent");
    control
        .register_tenant("factory0", &tenant_db.url)
        .await
        .expect("tenant registers as provisioning");
    let records = control.tenants().await.expect("registry readable");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].tenant, "factory0");
    assert_eq!(records[0].status, TenantStatus::Provisioning);

    let harness = harness();
    let report = control
        .reconcile_tenant(&records[0], &harness)
        .await
        .expect("first reconciliation succeeds");
    assert_eq!(report.status, TenantStatus::Active);
    assert_eq!(report.applied, 2, "one migration per module");
    assert_eq!(report.skipped, 0);
    // Promotion is recorded: provisioning -> active.
    assert_eq!(
        control.tenants().await.expect("registry")[0].status,
        TenantStatus::Active
    );

    // A second replica booting reconciles to the same state and applies
    // nothing — the whole point of the lock and the checksums.
    let again = control
        .reconcile_tenant(&records[0], &harness)
        .await
        .expect("reconciliation is idempotent");
    assert_eq!(again.status, TenantStatus::Active);
    assert_eq!(again.applied, 0, "nothing left to apply");
    assert_eq!(again.skipped, 2);

    // Plan mode after everything is applied says so, applying nothing.
    let plan = control
        .reconcile_plan(&records[0], &harness)
        .await
        .expect("plan computes");
    assert!(plan.modules.is_empty(), "nothing pending: {plan:?}");

    // The foreign key proves the dependency order: dependant after base.
    let tenant = Postgres::connect(&tenant_db.url)
        .await
        .expect("connect to the tenant database");
    tenant
        .execute(&cratefield_core::Statement::new(
            "INSERT INTO recon_base (id) VALUES ('b1')".to_owned(),
        ))
        .await
        .expect("base table exists");
    tenant
        .execute(&cratefield_core::Statement::new(
            "INSERT INTO recon_dependant (base_id) VALUES ('b1')".to_owned(),
        ))
        .await
        .expect("dependant table exists with its reference");

    control_db.finish().await;
    tenant_db.finish().await;
}

#[tokio::test]
async fn a_degraded_tenant_is_marked_and_skipped_by_the_fleet() {
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(control_db) = TempDb::create(&base, "reconctl2").await else {
        panic!("throwaway database creation failed");
    };
    control_db.assert_postgres_16().await;
    let control = Postgres::connect(&control_db.url).await.expect("connect");

    // A tenant whose DSN points nowhere: reconciliation must mark it
    // degraded and let the fleet move on, never abort.
    control
        .bootstrap_registry()
        .await
        .expect("registry bootstraps");
    control
        .register_tenant("ghost", "postgres://nobody:nope@127.0.0.1:1/ghost")
        .await
        .expect("registers");

    let harness = std::sync::Arc::new(harness());
    let reports = control
        .reconcile_fleet(&harness, 8)
        .await
        .expect("the fleet never aborts on one tenant");
    assert_eq!(reports.len(), 1, "the ghost tenant is reported");
    assert_eq!(reports[0].status, TenantStatus::Degraded);
    assert!(
        reports[0]
            .error
            .as_deref()
            .is_some_and(|err| !err.is_empty()),
        "the degradation says why"
    );
    assert!(
        !reports[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("nope"),
        "the DSN never appears in an error: {:?}",
        reports[0].error
    );
    assert_eq!(
        control.tenants().await.expect("registry")[0].status,
        TenantStatus::Degraded,
        "the registry records the degradation"
    );

    // The next boot skips a degraded tenant (retry timer's job, §6).
    control
        .set_tenant_status("ghost", TenantStatus::Degraded)
        .await;
    let skipped = control
        .reconcile_fleet(&harness, 8)
        .await
        .expect("fleet runs");
    assert!(skipped.is_empty(), "degraded tenants are not re-flown");

    // One healthy tenant among the wreckage: the healthy tenant serves.
    let Some(tenant_db) = TempDb::create(&base, "reconok").await else {
        panic!("throwaway database creation failed");
    };
    control
        .register_tenant("healthy", &tenant_db.url)
        .await
        .expect("registers");
    let reports = control
        .reconcile_fleet(&harness, 8)
        .await
        .expect("fleet runs");
    assert_eq!(reports.len(), 1, "only the non-degraded tenant is flown");
    assert_eq!(reports[0].tenant, "healthy");
    assert_eq!(reports[0].status, TenantStatus::Active);
    assert_eq!(reports[0].applied, 2);

    control_db.finish().await;
    tenant_db.finish().await;
}
