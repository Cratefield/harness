//! Boot-time reconciliation (RECONCILIATION.md, issue #30): the one
//! operation that touches every tenant database on every boot of every
//! native replica.
//!
//! The flow on boot: connect to the **control database** (this `Postgres`
//! instance), bootstrap its `harness_tenants` registry, then for every
//! tenant whose status is `active` or `provisioning` apply the harness's
//! module migrations to that tenant's own database, concurrently but
//! bounded (default 8). A tenant that fails is marked `degraded` in the
//! registry and every other tenant serves; only a control-database
//! failure aborts the boot.
//!
//! # Locking
//!
//! Before reading what is missing, the reconciler takes a Postgres
//! **advisory lock inside the tenant's own database**, keyed on a hash of
//! the tenant id, held for the duration of that tenant's reconciliation
//! on a dedicated connection. The lock lives in the tenant database so
//! one tenant's reconciliation can never block another's, and it is
//! released automatically when the connection dies — a replica that
//! crashes holding one does not wedge the fleet.
//!
//! This is a **session-level** lock (`pg_advisory_lock`) rather than the
//! `pg_advisory_xact_lock` RECONCILIATION.md §3 proposes: the design's
//! one lock transaction cannot also hold the non-transactional
//! migrations that must run in autocommit (`CREATE INDEX CONCURRENTLY`
//! refuses a transaction block). The semantics the design wants — lock
//! before reading, released on crash — are identical.
//!
//! # Ordering and checksums
//!
//! Modules apply in the harness's `depends_on` order ([`Harness::modules`]
//! is already dependency-resolved), each set by zero-padded migration id;
//! a recorded checksum that differs is fatal for that tenant and never
//! auto-repaired. Both are the adapters' existing behaviour; the
//! reconciler adds only the fleet behaviour around them.

use crate::migrate::{first_error_line, select_set};
use crate::{Postgres, Statement};
use cratefield_core::{Database as _, DbError, Harness, TenantStatus};

/// The advisory-lock key for a tenant: the first 60 bits of the sha256
/// of its id, as [`i64`]. Stable across versions (it is a hash of the
/// id, not of Rust's `DefaultHasher`) and never zero for a non-empty id.
#[must_use]
pub fn tenant_lock_key(tenant: &str) -> i64 {
    let hex = cratefield_core::migration_checksum(tenant);
    i64::from_str_radix(&hex[..15], 16).unwrap_or(1)
}

impl Postgres {
    /// Creates the `harness_tenants` registry on the control database,
    /// idempotently. Boot calls this first; a failure here aborts the
    /// boot (there is no registry to read, no DSN to resolve).
    ///
    /// # Errors
    ///
    /// [`DbError`] when the DDL fails.
    pub async fn bootstrap_registry(&self) -> Result<(), DbError> {
        self.execute(&Statement::new(
            "CREATE TABLE IF NOT EXISTS harness_tenants (
                 tenant TEXT PRIMARY KEY,
                 dsn    TEXT NOT NULL,
                 status TEXT NOT NULL
             );"
            .to_owned(),
        ))
        .await?;
        Ok(())
    }

    /// Registers (or re-points) a tenant: upsert the DSN and reset the
    /// status to `provisioning` — the next boot's reconciliation is what
    /// promotes it to `active`.
    ///
    /// **An archived tenant is never re-registered.** Archiving means the
    /// database was dropped and the data keys destroyed
    /// (`docs/TENANT-ONBOARDING.md` §2); re-registering the same id would
    /// mint a tenant that the registry says is the old one and that no
    /// export can reconstitute. The guard is the `WHERE` on the conflict
    /// branch, so it is decided by the database and not by a read the
    /// caller might race.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the write fails, and [`DbError::Execute`] naming
    /// the tenant when the row is archived.
    pub async fn register_tenant(&self, tenant: &str, dsn: &str) -> Result<(), DbError> {
        // 0 rows affected means the conflict branch was filtered out:
        // the row exists and is archived. An insert or a permitted update
        // both report 1.
        let affected = self
            .execute(&Statement::with_values(
                "INSERT INTO harness_tenants (tenant, dsn, status) VALUES (?, ?, 'provisioning') \
                 ON CONFLICT (tenant) DO UPDATE SET dsn = excluded.dsn, status = 'provisioning' \
                 WHERE harness_tenants.status <> 'archived'"
                    .to_owned(),
                vec![tenant.to_owned().into(), dsn.to_owned().into()],
            ))
            .await?;
        if affected == 0 {
            return Err(DbError::Execute(format!(
                "tenant {tenant} is archived and cannot be re-registered"
            )));
        }
        Ok(())
    }

    /// Every tenant in the registry, newest DSN wins. The values come
    /// from the control database and include the DSN: callers log or
    /// serve with them, never print them.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the read fails.
    pub async fn tenants(&self) -> Result<Vec<TenantRecord>, DbError> {
        let rows = self
            .query(&Statement::new(
                "SELECT tenant, dsn, status FROM harness_tenants ORDER BY tenant".to_owned(),
            ))
            .await?;
        Ok(rows
            .rows
            .iter()
            .filter_map(|row| {
                Some(TenantRecord {
                    tenant: row.get::<String>("tenant")?,
                    dsn: row.get::<String>("dsn")?,
                    status: TenantStatus::parse(&row.get::<String>("status")?),
                })
            })
            .collect())
    }

    /// Records a tenant's status, if the lifecycle allows the move.
    ///
    /// Answers whether the row changed. Best-effort by design
    /// (RECONCILIATION.md §6): a write that fails mid-boot still leaves
    /// the tenant refused at request time, because its pool was never
    /// registered. The answer is for the caller that wants to say so —
    /// `false` covers both "the database would not take it" and "the
    /// lifecycle does not allow it", which are the same thing to a
    /// caller: the tenant is not in the status it just asked for.
    ///
    /// The legal previous statuses are [`TenantStatus::admits`], so
    /// `archived` stays terminal (it admits nothing, itself included) and
    /// an `offboarding` tenant cannot be flipped back to `active` by a
    /// reconciler while its keys are being shredded.
    pub async fn set_tenant_status(&self, tenant: &str, status: TenantStatus) -> bool {
        // The legal previous values are part of the `WHERE`, not a read
        // before the write: two writers moving one tenant at once would
        // both read a legal status and both write, and the loser's
        // transition would be checked against a state that no longer
        // existed. `TenantStatus::admits` is the one place the rule
        // lives — the reconciler, the offboarding tooling and #154's
        // lifecycle API all move a tenant, and a rule written into this
        // clause alone would be a rule the others did not have.
        let admits = status.admits();
        let placeholders = std::iter::repeat_n("?", admits.len())
            .collect::<Vec<_>>()
            .join(", ");
        let mut values: Vec<sea_query::Value> = vec![status.as_str().to_owned().into()];
        values.push(tenant.to_owned().into());
        values.extend(
            admits
                .iter()
                .map(|previous| previous.as_str().to_owned().into()),
        );
        let applied = self
            .execute(&Statement::with_values(
                format!(
                    "UPDATE harness_tenants SET status = ? WHERE tenant = ? AND status IN \
                     ({placeholders})"
                ),
                values,
            ))
            .await;
        match applied {
            Ok(rows) => rows > 0,
            Err(error) => {
                tracing::warn!(
                    tenant = %tenant,
                    status = status.as_str(),
                    %error,
                    "could not write the tenant status"
                );
                false
            }
        }
    }

    /// Reconciles one tenant: take the advisory lock, then apply every
    /// module's migrations to the tenant's database in `depends_on`
    /// order. On any failure the tenant is marked `degraded` in the
    /// control database (best-effort) and the error is returned; the
    /// caller decides whether that aborts the boot (`strict`).
    ///
    /// The tenant DSN is never part of any error message: connection
    /// strings carry credentials.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the tenant's database is unreachable or a
    /// migration fails.
    pub async fn reconcile_tenant(
        &self,
        record: &TenantRecord,
        harness: &Harness,
    ) -> Result<TenantReport, DbError> {
        let started = std::time::Instant::now();
        let mut report = TenantReport {
            tenant: record.tenant.clone(),
            status: TenantStatus::Active,
            applied: 0,
            skipped: 0,
            error: None,
        };
        let outcome = self
            .reconcile_tenant_inner(record, harness, &mut report)
            .await;
        if outcome.is_err() {
            report.status = TenantStatus::Degraded;
        }
        if !self.set_tenant_status(&record.tenant, report.status).await {
            // Not a boot failure: the pool is registered or it is not,
            // and that is what serves requests. But a status the registry
            // would not take means the tenant moved underneath this
            // reconciliation — being offboarded, most likely — and a
            // silent miss here is how a fleet and its registry drift.
            tracing::warn!(
                tenant = %record.tenant,
                status = report.status.as_str(),
                "the registry did not take the reconciled status; the tenant moved underneath it"
            );
        }
        tracing::info!(
            tenant = %record.tenant,
            status = report.status.as_str(),
            applied = report.applied,
            skipped = report.skipped,
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "tenant reconciliation finished"
        );
        outcome.map(|()| report)
    }

    async fn reconcile_tenant_inner(
        &self,
        record: &TenantRecord,
        harness: &Harness,
        report: &mut TenantReport,
    ) -> Result<(), DbError> {
        // A dedicated connection holds the advisory lock for the whole
        // reconciliation; the migration runner runs over its own pool.
        let mut lock = <sqlx::PgConnection as sqlx::Connection>::connect(&record.dsn)
            .await
            .map_err(|err| {
                DbError::Batch(format!(
                    "tenant {} database unreachable: {}",
                    record.tenant,
                    first_error_line(&err.to_string())
                ))
            })?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(tenant_lock_key(&record.tenant))
            .execute(&mut lock)
            .await
            .map_err(|err| DbError::Batch(err.to_string()))?;

        let tenant = Postgres::connect(&record.dsn).await?;
        // Bootstrap the tracking table before anything reads it: a fresh
        // tenant database has none, and "what is missing" needs the read
        // to succeed (the lock is already held, so this is safe).
        tenant
            .execute(&crate::migrate::tracking_table_ddl())
            .await?;
        tenant
            .execute(&crate::migrate::tracking_table_backfill_ddl())
            .await?;
        for module in harness.modules() {
            let set = select_set(&module.migrations())
                .map_err(|reason| DbError::Batch(format!("module {}: {reason}", module.name())))?;
            let before = tenant.applied_keys(module.name()).await?;
            tenant.apply_migrations(module.name(), set).await?;
            let after = tenant.applied_keys(module.name()).await?;
            let applied = after.len() - after.intersection(&before).count();
            report.applied += applied;
            report.skipped += before.intersection(&after).count();
            if applied > 0 {
                tracing::info!(
                    tenant = %record.tenant,
                    module = module.name(),
                    applied,
                    "migrations applied"
                );
            }
        }
        Ok(())
    }

    /// Reconciles every tenant in the registry whose status is `active`
    /// or `provisioning`, at most `parallelism` at a time (default 8;
    /// #30 §10 keeps the right number a measured question). A `degraded`
    /// tenant is left for the retry timer, not re-flown this boot; an
    /// `offboarding` or `archived` one is never flown again at all.
    ///
    /// This is what boot calls. The control database drives everything:
    /// if it cannot be bootstrapped or read, the error returns and the
    /// boot aborts — there is nothing useful to serve without a registry.
    /// A tenant that fails is marked `degraded` and every other tenant
    /// serves; the same with `strict` semantics is the caller's
    /// decision (any `Degraded` in the reports).
    ///
    /// # Errors
    ///
    /// [`DbError`] when the control database cannot be bootstrapped or
    /// read. Per-tenant failures never abort the fleet.
    pub async fn reconcile_fleet(
        &self,
        harness: &Harness,
        parallelism: usize,
    ) -> Result<Vec<TenantReport>, DbError> {
        self.bootstrap_registry().await?;
        // Positive filter, not `!= Degraded`: see
        // `TenantStatus::is_reconciled`. The negation was correct only
        // while three statuses existed, and flying an offboarding or
        // archived tenant would reconnect to a database that is being
        // shredded and flip it back to `active`.
        let records: Vec<TenantRecord> = self
            .tenants()
            .await?
            .into_iter()
            .filter(|record| record.status.is_reconciled())
            .collect();
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(parallelism.max(1)));
        // One task, many in-flight futures: the per-tenant work is
        // I/O-bound sqlx calls, and a semaphore future per tenant bounds
        // the fan-out without `spawn`'s `Send` + `'static` requirements
        // on the harness's module trait objects.
        let plans: Vec<_> = records
            .into_iter()
            .map(|record| {
                let db = self.clone();
                let semaphore = std::sync::Arc::clone(&semaphore);
                async move {
                    let _permit = semaphore.acquire_owned().await;
                    db.reconcile_tenant(&record, harness)
                        .await
                        .unwrap_or_else(|err| TenantReport {
                            tenant: record.tenant,
                            status: TenantStatus::Degraded,
                            applied: 0,
                            skipped: 0,
                            error: Some(err.to_string()),
                        })
                }
            })
            .collect();
        let mut reports = futures_util::future::join_all(plans).await;
        reports.sort_by(|a, b| a.tenant.cmp(&b.tenant));
        let degraded = reports
            .iter()
            .filter(|report| report.status == TenantStatus::Degraded)
            .count();
        tracing::info!(
            tenants = reports.len(),
            degraded,
            "fleet reconciliation finished"
        );
        Ok(reports)
    }

    /// What *would* be applied, per module, for one tenant. Takes the
    /// same advisory lock, so the answer is not a guess about a moving
    /// target (RECONCILIATION.md §8), and applies nothing.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the tenant's database is unreachable.
    pub async fn reconcile_plan(
        &self,
        record: &TenantRecord,
        harness: &Harness,
    ) -> Result<TenantPlan, DbError> {
        let mut lock = <sqlx::PgConnection as sqlx::Connection>::connect(&record.dsn)
            .await
            .map_err(|err| DbError::Batch(err.to_string()))?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(tenant_lock_key(&record.tenant))
            .execute(&mut lock)
            .await
            .map_err(|err| DbError::Batch(err.to_string()))?;
        let tenant = Postgres::connect(&record.dsn).await?;

        let mut plan = TenantPlan {
            tenant: record.tenant.clone(),
            modules: Vec::new(),
        };
        for module in harness.modules() {
            let set = select_set(&module.migrations())
                .map_err(|reason| DbError::Batch(format!("module {}: {reason}", module.name())))?;
            let applied = tenant.applied_keys(module.name()).await?;
            let pending: Vec<String> = set
                .iter()
                .map(|migration| migration.id)
                .filter(|id| !applied.contains(&format!("{}/{}", module.name(), id)))
                .map(ToOwned::to_owned)
                .collect();
            if !pending.is_empty() {
                plan.modules.push(ModulePlan {
                    module: module.name().to_owned(),
                    migrations: pending,
                });
            }
        }
        Ok(plan)
    }

    async fn applied_keys(
        &self,
        module: &str,
    ) -> Result<std::collections::HashSet<String>, DbError> {
        let prefix = format!("{module}/");
        let rows = self
            .query(&Statement::with_values(
                "SELECT id FROM harness_migrations WHERE id LIKE ?".to_owned(),
                vec![format!("{prefix}%").into()],
            ))
            .await?;
        Ok(rows
            .rows
            .iter()
            .filter_map(|row| row.get::<String>("id"))
            .filter(|id| id.starts_with(&prefix))
            .collect())
    }
}

/// One tenant in the control database's registry.
#[derive(Debug, Clone)]
pub struct TenantRecord {
    /// The tenant id, e.g. `factory0`.
    pub tenant: String,
    /// The tenant database's connection string. Never log it.
    pub dsn: String,
    /// The status reconciliation last recorded.
    pub status: TenantStatus,
}

/// The outcome of reconciling one tenant.
#[derive(Debug, Clone)]
pub struct TenantReport {
    pub tenant: String,
    pub status: TenantStatus,
    /// Migrations applied this boot.
    pub applied: usize,
    /// Migrations already recorded, skipped.
    pub skipped: usize,
    /// Why the tenant went `degraded`, when it did. Names the migration
    /// or the failure, never the DSN.
    pub error: Option<String>,
}

/// What [`Postgres::reconcile_plan`] would apply for one tenant.
#[derive(Debug, Clone)]
pub struct TenantPlan {
    pub tenant: String,
    /// Only modules with something pending; a module fully applied is
    /// not listed at all.
    pub modules: Vec<ModulePlan>,
}

/// One module's pending migration ids, in apply order.
#[derive(Debug, Clone)]
pub struct ModulePlan {
    pub module: String,
    /// Zero-padded ids, e.g. `["0003", "0004"]`.
    pub migrations: Vec<String>,
}
