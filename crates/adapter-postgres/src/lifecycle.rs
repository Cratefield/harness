//! The Postgres side of core's [`TenantLifecycle`] port (issue #154):
//! the runtime-neutral write half of the `harness_tenants` registry.
//!
//! The registry's write path already existed here —
//! [`Postgres::register_tenant`] and [`Postgres::set_tenant_status`] —
//! but it answered in strings and booleans: a refused move and a failed
//! write were the same `false`, and refusing an archived id was a
//! `DbError` whose reason lived in prose. This file does not add a
//! second writer; it is the classification layer that turns those
//! answers into the port's typed errors, so a caller above the adapter
//! can tell "the lifecycle says no" from "the database is down" without
//! parsing driver text. The lifecycle rule itself stays in
//! `TenantStatus::admits` — this file only asks it.
//!
//! Deliberately a separate module from `reconcile.rs` rather than more
//! methods there: reconciliation owns the boot-time fleet behaviour, and
//! this owns the registry's port surface. Both call the same two
//! registry primitives, and neither re-implements the rule.

use async_trait::async_trait;

use crate::Postgres;
use crate::reconcile::TenantRecord;
use cratefield_core::Database as _;
use cratefield_core::{
    DbError, Statement, TenantLifecycle, TenantLifecycleError, TenantStatus, TenantSummary,
};

impl Postgres {
    /// The status the registry records for `tenant`, or `None` when
    /// there is no row.
    ///
    /// A status this binary does not know reads as
    /// [`TenantStatus::Degraded`] here: `TenantStatus::parse` is
    /// fail-closed on purpose, and this read inherits that — an
    /// unknown word is a refusal at request time, not a guess.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the read fails (including when the registry has
    /// not been bootstrapped yet).
    pub async fn tenant_status(&self, tenant: &str) -> Result<Option<TenantStatus>, DbError> {
        let rows = self
            .query(&Statement::with_values(
                "SELECT status FROM harness_tenants WHERE tenant = ?".to_owned(),
                vec![tenant.to_owned().into()],
            ))
            .await?;
        Ok(rows.rows.iter().find_map(|row| {
            row.get::<String>("status")
                .map(|status| TenantStatus::parse(&status))
        }))
    }
}

#[async_trait]
impl TenantLifecycle for Postgres {
    async fn create(&self, tenant: &str, dsn: &str) -> Result<(), TenantLifecycleError> {
        if let Err(error) = self.register_tenant(tenant, dsn).await {
            // `register_tenant` reports an archived id as a 0-rows
            // upsert, which reaches here as a `DbError::Execute` naming
            // the tenant in prose. Classify it: a follow-up read that
            // finds `archived` turns the string into the typed refusal,
            // and any other answer falls back to the write's own error,
            // already scrubbed by `Display for DbError`.
            let archived = matches!(
                self.tenant_status(tenant).await,
                Ok(Some(TenantStatus::Archived))
            );
            return if archived {
                Err(TenantLifecycleError::Refused {
                    tenant: tenant.to_owned(),
                    from: TenantStatus::Archived,
                    to: TenantStatus::Provisioning,
                })
            } else {
                Err(TenantLifecycleError::Backend {
                    tenant: tenant.to_owned(),
                    message: error.to_string(),
                })
            };
        }
        Ok(())
    }

    async fn status(&self, tenant: &str) -> Result<TenantStatus, TenantLifecycleError> {
        match self.tenant_status(tenant).await {
            Ok(Some(status)) => Ok(status),
            Ok(None) => Err(TenantLifecycleError::Unknown {
                tenant: tenant.to_owned(),
            }),
            Err(error) => Err(TenantLifecycleError::Backend {
                tenant: tenant.to_owned(),
                message: error.to_string(),
            }),
        }
    }

    async fn tenants(&self) -> Result<Vec<TenantSummary>, TenantLifecycleError> {
        // The inherent method, called explicitly: the trait method has
        // the same name, and a bare `self.tenants()` here would dispatch
        // to the trait — this impl — and recurse forever. Naming the
        // type is what keeps this a delegation instead of a loop; the
        // contract test `tenants_through_the_port_lists_rows_without_a_dsn`
        // would hang if it ever regressed.
        let records: Vec<TenantRecord> = Postgres::tenants(self).await.map_err(|error| {
            // A listing reads the whole registry: there is no single
            // tenant to name, so the field stays empty rather than
            // blaming a row that had nothing to do with the failure.
            TenantLifecycleError::Backend {
                tenant: String::new(),
                message: error.to_string(),
            }
        })?;
        // The DSN is dropped here, not scrubbed: the summary type has no
        // field for it, so the secret cannot reach a log or a dashboard
        // through this port at all.
        Ok(records
            .into_iter()
            .map(|record| TenantSummary {
                tenant: record.tenant,
                status: record.status,
            })
            .collect())
    }

    async fn set_status(
        &self,
        tenant: &str,
        next: TenantStatus,
    ) -> Result<(), TenantLifecycleError> {
        if self.set_tenant_status(tenant, next).await {
            return Ok(());
        }
        // KNOWN IMPRECISION, stated rather than papered over:
        // `set_tenant_status` answers `false` both for "the lifecycle
        // does not allow the move" and for "the write itself failed" —
        // it logs and swallows the error (see its doc). A backend fault
        // is therefore reported here as `Refused` (or `Unknown`),
        // classified by this follow-up read, unless the read fails too —
        // only that surfaces as `Backend`. Fixing it means changing the
        // primitive's best-effort contract, which reconciliation also
        // depends on; not done in this issue.
        match self.tenant_status(tenant).await {
            Ok(None) => Err(TenantLifecycleError::Unknown {
                tenant: tenant.to_owned(),
            }),
            Ok(Some(current)) => Err(TenantLifecycleError::Refused {
                tenant: tenant.to_owned(),
                from: current,
                to: next,
            }),
            Err(error) => Err(TenantLifecycleError::Backend {
                tenant: tenant.to_owned(),
                message: error.to_string(),
            }),
        }
    }
}
