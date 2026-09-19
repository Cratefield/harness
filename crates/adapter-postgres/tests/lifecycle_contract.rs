//! Contract test (issue #154): the `TenantLifecycle` port over the
//! `harness_tenants` registry on Postgres 16 — the runtime-neutral
//! write half of the tenant registry that `docs/TENANT-ONBOARDING.md` §4
//! says was Postgres-only before. Every assertion goes through the
//! trait, never the adapter's inherent registry methods, which is what
//! makes this a port contract rather than a repeat of
//! `reconcile_contract.rs`. Skipped with a printed reason when
//! `FZ_TEST_POSTGRES_URL` is unset; CI provides a `postgres:16` service
//! container.

mod common;

use common::{TempDb, base_url, skip_reason};
use cratefield_adapter_postgres::Postgres;
use cratefield_core::{TenantLifecycle, TenantLifecycleError, TenantStatus};

/// A DSN for a database that does not exist. The registry write never
/// connects to it — registration is a row, not a connection — and a
/// secret-shaped string is the point: the listing test proves it never
/// comes back out.
const DSN: &str = "postgres://tenant:s3cret-pw@127.0.0.1:1/no_such_database";

/// A throwaway control database with the registry bootstrapped, and the
/// adapter over it.
async fn bootstrapped_control(base: &str, tag: &str) -> (TempDb, Postgres) {
    let Some(db) = TempDb::create(base, tag).await else {
        panic!("throwaway database creation failed");
    };
    db.assert_postgres_16().await;
    let control = Postgres::connect(&db.url)
        .await
        .expect("connect to the control database");
    control
        .bootstrap_registry()
        .await
        .expect("registry bootstraps");
    (db, control)
}

#[tokio::test]
async fn a_tenant_walks_the_whole_lifecycle_through_the_port() {
    // The runbook of `docs/TENANT-ONBOARDING.md` §1 then §2, as one
    // port-level walk: register as provisioning, promote to active,
    // stop serving (offboarding, with the remaining steps handed back),
    // archive. If the port cannot express the whole path, the CLI that
    // stands on it (#36) cannot either.
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let (control_db, control) = bootstrapped_control(&base, "lcctl1").await;

    control
        .create("walker", DSN)
        .await
        .expect("a fresh id registers");
    assert_eq!(
        control.status("walker").await.expect("registered"),
        TenantStatus::Provisioning,
        "a tenant registers as provisioning, before reconciliation runs"
    );

    control
        .set_status("walker", TenantStatus::Active)
        .await
        .expect("provisioning becomes active once reconciliation succeeds");
    assert_eq!(
        control.status("walker").await.expect("registered"),
        TenantStatus::Active,
    );

    let steps = control
        .begin_erasure("walker")
        .await
        .expect("a serving tenant can be retired");
    assert_eq!(
        steps,
        cratefield_core::remaining_erasure(TenantStatus::Offboarding).to_vec(),
        "begin_erasure returns the §2 steps still outstanding, in order"
    );
    assert_eq!(
        steps.first(),
        Some(&cratefield_core::ErasureStep::ExportData),
        "the stop already happened, so the export is the first step left"
    );
    assert_eq!(
        control.status("walker").await.expect("registered"),
        TenantStatus::Offboarding,
        "begin_erasure stopped the tenant serving by moving the row"
    );

    control
        .complete_erasure("walker")
        .await
        .expect("archived is the only way out of offboarding");
    assert_eq!(
        control.status("walker").await.expect("registered"),
        TenantStatus::Archived,
        "complete_erasure records the terminal status"
    );

    control_db.finish().await;
}

#[tokio::test]
async fn an_offboarding_tenant_refuses_every_revival_with_the_move_it_refused() {
    // The typed-error payoff over the old `bool`: the port does not just
    // say no, it says from where. `TenantStatus::admits` allows nothing
    // back out of `offboarding`, so a reviving writer — a reconciler, a
    // stale CLI — gets the row's real status and its own ask back.
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let (control_db, control) = bootstrapped_control(&base, "lcctl2").await;
    control.create("retiree", DSN).await.expect("registers");
    control
        .begin_erasure("retiree")
        .await
        .expect("retirement starts from active");

    for revival in [
        TenantStatus::Active,
        TenantStatus::Provisioning,
        TenantStatus::Degraded,
    ] {
        assert_eq!(
            control.set_status("retiree", revival).await,
            Err(TenantLifecycleError::Refused {
                tenant: "retiree".to_owned(),
                from: TenantStatus::Offboarding,
                to: revival,
            }),
            "{revival} must be refused naming the offboarding row and the ask"
        );
        assert_eq!(
            control.status("retiree").await.expect("registered"),
            TenantStatus::Offboarding,
            "a refused revival must not have moved the row"
        );
    }

    control_db.finish().await;
}

#[tokio::test]
async fn an_archived_tenant_refuses_recreation_and_the_refusal_names_the_tenant() {
    // Archiving destroyed the data keys, so a resurrected row would name
    // a tenant nothing can reconstitute. The port refuses the re-create
    // as a typed `Refused` from `archived` — the string the old
    // `DbError` carried, now a variant — and still says who it was about.
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let (control_db, control) = bootstrapped_control(&base, "lcctl3").await;
    control.create("refusee", DSN).await.expect("registers");
    control
        .begin_erasure("refusee")
        .await
        .expect("retirement starts");
    control
        .complete_erasure("refusee")
        .await
        .expect("the shred completes");

    let refused = control
        .create("refusee", DSN)
        .await
        .expect_err("an archived id must not re-register");
    assert_eq!(
        refused,
        TenantLifecycleError::Refused {
            tenant: "refusee".to_owned(),
            from: TenantStatus::Archived,
            to: TenantStatus::Provisioning,
        },
        "re-creating an archived id is a refusal from archived, not a backend fault"
    );
    assert!(
        refused.to_string().contains("refusee"),
        "the rendered refusal names the tenant: {refused}"
    );
    assert_eq!(
        control.status("refusee").await.expect("registered"),
        TenantStatus::Archived,
        "the refused create did not touch the row"
    );

    control_db.finish().await;
}

#[tokio::test]
async fn an_unregistered_tenant_is_unknown_to_reads_and_writes() {
    // `Unknown` is its own answer, not a refusal and not a backend
    // fault: an operator typo in a tenant id must look different from a
    // lifecycle rule and from a database outage.
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let (control_db, control) = bootstrapped_control(&base, "lcctl4").await;

    assert_eq!(
        control.status("never-registered").await,
        Err(TenantLifecycleError::Unknown {
            tenant: "never-registered".to_owned(),
        }),
        "reading a tenant with no row is Unknown"
    );
    assert_eq!(
        control
            .set_status("never-registered", TenantStatus::Active)
            .await,
        Err(TenantLifecycleError::Unknown {
            tenant: "never-registered".to_owned(),
        }),
        "moving a tenant with no row is Unknown, not a refusal"
    );

    control_db.finish().await;
}

#[tokio::test]
async fn tenants_through_the_port_lists_rows_without_a_dsn() {
    // The registry stores DSNs and the port must drop them: ADR 0008
    // makes a tenant DSN a global secret, and a listing is the thing
    // most likely to be logged. This calls the trait's `tenants`
    // explicitly — `Postgres` also has an inherent `tenants` that
    // returns records *with* DSNs, and method syntax would silently
    // pick that one; the explicit form is also the guard against the
    // impl delegating to itself, which would hang this test.
    let Some(base) = base_url() else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let (control_db, control) = bootstrapped_control(&base, "lcctl5").await;
    control.create("lister", DSN).await.expect("registers");
    control
        .set_status("lister", TenantStatus::Active)
        .await
        .expect("promotes to active");

    let summaries = TenantLifecycle::tenants(&control)
        .await
        .expect("the registry is readable through the port");
    assert_eq!(summaries.len(), 1, "the registered tenant is listed");
    assert_eq!(summaries[0].tenant, "lister");
    assert_eq!(
        summaries[0].status,
        TenantStatus::Active,
        "the listing carries the row's status"
    );
    let rendered = format!("{summaries:?}");
    assert!(
        !rendered.contains("postgres://"),
        "a listing through the port leaked a connect string: {rendered}"
    );
    assert!(
        !rendered.contains("s3cret-pw"),
        "a listing through the port leaked the DSN's secret: {rendered}"
    );

    control_db.finish().await;
}
