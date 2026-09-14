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

/// A status this binary has never heard of, written straight into the
/// registry the way a newer binary would.
async fn store_unknown_status(control: &Postgres, tenant: &str) {
    use cratefield_core::Database as _;
    control
        .execute(&cratefield_core::Statement::with_values(
            "UPDATE harness_tenants SET status = ? WHERE tenant = ?".to_owned(),
            vec!["suspended".to_owned().into(), tenant.to_owned().into()],
        ))
        .await
        .expect("the registry takes any text");
}

/// Asserts the registry refuses every move back out of `offboarding`.
///
/// The fleet skipping an offboarding tenant is one guard; this is the
/// other, because the reconciler is not the only writer of a status, and
/// the tenant being shredded is the one that must not come back.
async fn refuses_every_revival(control: &Postgres, tenant: &str) {
    for revival in [
        TenantStatus::Active,
        TenantStatus::Degraded,
        TenantStatus::Provisioning,
    ] {
        assert!(
            !control.set_tenant_status(tenant, revival).await,
            "the registry took {revival} for a tenant being shredded"
        );
        assert_eq!(
            control.tenants().await.expect("registry")[0].status,
            TenantStatus::Offboarding,
            "and it moved the row"
        );
    }
}

#[tokio::test]
async fn a_retired_tenant_cannot_be_resurrected_or_re_flown() {
    // #336 gave the lifecycle an end (`offboarding`, `archived`). This is
    // the registry half of that: once a tenant is archived its database is
    // dropped and its data keys are destroyed, so a row that comes back to
    // life would name a tenant nothing can reconstitute.
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(control_db) = TempDb::create(&base, "reconctl3").await else {
        panic!("throwaway database creation failed");
    };
    let control = Postgres::connect(&control_db.url).await.expect("connect");
    control
        .bootstrap_registry()
        .await
        .expect("registry bootstraps");

    let Some(tenant_db) = TempDb::create(&base, "reconretire").await else {
        panic!("throwaway database creation failed");
    };
    control
        .register_tenant("retiree", &tenant_db.url)
        .await
        .expect("registers");

    // Offboarding: stopped serving, not yet shredded. The fleet must not
    // fly it — reconnecting mid-shred and flipping it back to `active` is
    // the failure this guards.
    let harness = std::sync::Arc::new(harness());
    assert!(
        control
            .set_tenant_status("retiree", TenantStatus::Offboarding)
            .await,
        "retirement starts from active"
    );

    refuses_every_revival(&control, "retiree").await;
    let reports = control
        .reconcile_fleet(&harness, 8)
        .await
        .expect("fleet runs");
    assert!(reports.is_empty(), "an offboarding tenant was flown");
    assert_eq!(
        control.tenants().await.expect("registry")[0].status,
        TenantStatus::Offboarding,
        "the fleet moved a tenant it should not have touched"
    );

    // The shred completes.
    assert!(
        control
            .set_tenant_status("retiree", TenantStatus::Archived)
            .await,
        "the only way out of offboarding"
    );

    // Terminal: no status write moves it back.
    for attempt in [
        TenantStatus::Active,
        TenantStatus::Provisioning,
        TenantStatus::Degraded,
        TenantStatus::Offboarding,
    ] {
        assert!(
            !control.set_tenant_status("retiree", attempt).await,
            "the registry reported taking {attempt} for an archived tenant"
        );
        assert_eq!(
            control.tenants().await.expect("registry")[0].status,
            TenantStatus::Archived,
            "a status write moved an archived tenant to {attempt}"
        );
    }
    // Including a repeat of `archived` itself: the row is the record that
    // the keys were destroyed, and rewriting it would move its timestamp
    // and lose when the shred actually happened.
    assert!(
        !control
            .set_tenant_status("retiree", TenantStatus::Archived)
            .await,
        "the record of an irreversible act was rewritten"
    );

    // Terminal: re-registering the id is refused, and says so. The
    // database still exists here, so nothing but the guard stops it.
    let refused = control
        .register_tenant("retiree", &tenant_db.url)
        .await
        .expect_err("an archived tenant must not re-register");
    assert!(
        refused.to_string().contains("retiree"),
        "the refusal names the tenant: {refused}"
    );
    assert_eq!(
        control.tenants().await.expect("registry")[0].status,
        TenantStatus::Archived,
    );

    // And it is still not flown.
    let reports = control
        .reconcile_fleet(&harness, 8)
        .await
        .expect("fleet runs");
    assert!(reports.is_empty(), "an archived tenant was flown");

    // A different id provisions normally: the guard is about this row,
    // not about the registry having seen an archived tenant.
    control
        .register_tenant("successor", &tenant_db.url)
        .await
        .expect("a fresh id registers");
    let reports = control
        .reconcile_fleet(&harness, 8)
        .await
        .expect("fleet runs");
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].tenant, "successor");
    assert_eq!(reports[0].status, TenantStatus::Active);

    control_db.finish().await;
    tenant_db.finish().await;
}

#[tokio::test]
async fn a_status_this_binary_does_not_know_is_not_overwritten_by_it() {
    // Mixed-version deploys are the normal case during a rollout. A newer
    // binary writes a status this one has never heard of; this one must
    // leave it alone rather than deciding it is `degraded` — which is how
    // `TenantStatus::parse` reads it — and writing `active` over it.
    //
    // Two guards happen to cover this and only one is deliberate. The
    // fleet skips it, because an unknown status parses as `degraded` and
    // `is_reconciled` is false there. The one that matters is the
    // registry's: `set_tenant_status` compares the *stored text* against
    // `TenantStatus::admits`, and a word not in that list matches nothing.
    // Had the guard been written against the parsed value it would have
    // seen `degraded`, found it admitted, and clobbered the row.
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let Some(control_db) = TempDb::create(&base, "reconctl4").await else {
        panic!("throwaway database creation failed");
    };
    let control = Postgres::connect(&control_db.url).await.expect("connect");
    control
        .bootstrap_registry()
        .await
        .expect("registry bootstraps");
    let Some(tenant_db) = TempDb::create(&base, "reconfuture").await else {
        panic!("throwaway database creation failed");
    };
    control
        .register_tenant("future", &tenant_db.url)
        .await
        .expect("registers");
    store_unknown_status(&control, "future").await;

    for attempt in [
        TenantStatus::Active,
        TenantStatus::Degraded,
        TenantStatus::Offboarding,
        TenantStatus::Archived,
        TenantStatus::Provisioning,
    ] {
        assert!(
            !control.set_tenant_status("future", attempt).await,
            "the registry took {attempt} over a status it cannot read"
        );
    }
    // Still the newer binary's word, untouched, for it to act on.
    assert_eq!(
        control.tenants().await.expect("registry")[0].status,
        TenantStatus::Degraded,
        "this binary reads the unknown word as degraded"
    );

    // And it is not flown, so nothing reconciles it into a status this
    // binary does understand.
    let harness = std::sync::Arc::new(harness());
    let reports = control
        .reconcile_fleet(&harness, 8)
        .await
        .expect("fleet runs");
    assert!(
        reports.is_empty(),
        "a tenant with an unknown status was flown"
    );

    control_db.finish().await;
    tenant_db.finish().await;
}
