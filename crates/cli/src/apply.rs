//! `fz migrations apply` (issue #18): applies the harness's module
//! migrations directly to a Postgres database — the native counterpart of
//! `wrangler d1 migrations apply`. With `--plan` / `--tenant` / `--strict`
//! it becomes the boot-time reconciliation the native runtime runs
//! (RECONCILIATION.md, issue #30), driven by hand against the control
//! database. Requires building `fz` with cratefield-cli's `postgres`
//! feature so sqlx and tokio stay out of the default (wasm-safe)
//! dependency graph.

use cratefield_core::Harness;

#[cfg(feature = "postgres")]
/// Default per-boot fan-out to tenant databases (RECONCILIATION.md §2:
/// "something small like 8"; #30 §10 keeps it a measured question).
#[cfg(feature = "postgres")]
const FLEET_PARALLELISM: usize = 8;

/// Applies the harness's migrations to the database at `url`, or — when
/// `plan` or `tenant` is given — reconciles against the control database
/// at `url`.
///
/// # Errors
///
/// A human-readable message when the dialect is unsupported, the binary
/// lacks the `postgres` feature, the server is unreachable, or a
/// migration fails. In strict mode any degraded tenant is one.
pub fn apply(
    harness: &Harness,
    dialect: &str,
    url: &str,
    plan: bool,
    tenant: Option<&str>,
    strict: bool,
) -> Result<(), String> {
    if dialect != "postgres" {
        return Err(format!(
            "dialect {dialect:?} is not supported for apply (only postgres, issue #18)"
        ));
    }
    if tenant.is_some() && !plan {
        return Err(
            "--tenant only means something with --plan today: fleet apply is the runtime \
             reconciler's job, and one tenant cannot be applied without its neighbours' \
             registry being read anyway"
                .to_owned(),
        );
    }
    #[cfg(not(feature = "postgres"))]
    {
        let _ = (harness, url, plan, tenant, strict);
        Err(
            "this fz binary was built without cratefield-cli's `postgres` feature — \
             rebuild the fz bin with `--features cratefield-cli/postgres` to apply \
             migrations to Postgres (sqlite/D1 migrations run through \
             `wrangler d1 migrations apply`)"
                .to_owned(),
        )
    }
    #[cfg(feature = "postgres")]
    {
        if plan {
            apply_plan(harness, url, tenant)
        } else {
            apply_postgres(harness, url, strict)
        }
    }
}

#[cfg(feature = "postgres")]
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("cannot start the async runtime: {err}"))
}

#[cfg(feature = "postgres")]
fn apply_postgres(harness: &Harness, url: &str, strict: bool) -> Result<(), String> {
    runtime()?.block_on(async {
        let db = cratefield_adapter_postgres::Postgres::connect(url)
            .await
            .map_err(|err| format!("cannot connect (check --url): {err}"))?;
        let reports = db
            .reconcile_fleet(harness, FLEET_PARALLELISM)
            .await
            .map_err(|err| format!("reconciliation failed: {err}"))?;
        let degraded: Vec<&cratefield_adapter_postgres::TenantReport> = reports
            .iter()
            .filter(|report| report.status == cratefield_adapter_postgres::TenantStatus::Degraded)
            .collect();
        for report in &reports {
            println!(
                "tenant {}: {} applied, {} skipped, {}{}",
                report.tenant,
                report.applied,
                report.skipped,
                report.status,
                report
                    .error
                    .as_deref()
                    .map(|err| format!(" — {err}"))
                    .unwrap_or_default()
            );
        }
        if degraded.is_empty() {
            Ok(())
        } else if strict {
            Err(format!(
                "{} tenant(s) degraded ({}): boot would abort in strict mode",
                degraded.len(),
                degraded
                    .iter()
                    .map(|report| report.tenant.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        } else {
            println!(
                "{} tenant(s) degraded; every other tenant serves (re-run with --strict \
                 to make this a failure)",
                degraded.len()
            );
            Ok(())
        }
    })
}

/// `--plan`: what would be applied, per tenant and per module, applied
/// nowhere. Locks are taken so the answer is not a guess about a moving
/// target (RECONCILIATION.md §8).
#[cfg(feature = "postgres")]
fn apply_plan(harness: &Harness, url: &str, tenant: Option<&str>) -> Result<(), String> {
    runtime()?.block_on(async {
        let control = cratefield_adapter_postgres::Postgres::connect(url)
            .await
            .map_err(|err| {
                format!("cannot connect to the control database (check --url): {err}")
            })?;
        control
            .bootstrap_registry()
            .await
            .map_err(|err| format!("cannot bootstrap the registry: {err}"))?;
        let records = control
            .tenants()
            .await
            .map_err(|err| format!("cannot read the tenant registry: {err}"))?;
        let records: Vec<_> = match tenant {
            Some(name) => {
                let found: Vec<_> = records
                    .iter()
                    .filter(|record| record.tenant == name)
                    .collect();
                if found.is_empty() {
                    return Err(format!("tenant {name:?} is not in the registry"));
                }
                found
            }
            None => records.iter().collect(),
        };
        if records.is_empty() {
            println!("no tenants registered");
            return Ok(());
        }
        for record in records {
            match control.reconcile_plan(record, harness).await {
                Ok(plan) => {
                    if plan.modules.is_empty() {
                        println!("tenant {}: nothing to apply", plan.tenant);
                    } else {
                        println!("tenant {}:", plan.tenant);
                        for module in &plan.modules {
                            println!("  {}: {}", module.module, module.migrations.join(", "));
                        }
                    }
                }
                Err(err) => println!("tenant {}: unreachable — {err}", record.tenant),
            }
        }
        Ok(())
    })
}
