//! `fz tables drift` — what a database differs from the manifest by.
//!
//! Both halves of this landed without a way to run one against the other:
//! a manifest can declare `[tables]` (#354) and
//! `cratefield_introspect::drift` can compare a declaration against a
//! live catalog (#353). This is the command that makes the pair reachable
//! by a person, which is the only form in which either is worth anything.
//!
//! Read-only, always. It opens the database, reads its catalog and prints;
//! there is no `--fix`, because what a drift costs is the author's
//! decision and three of the four answers are not "apply this".

use std::path::Path;

#[cfg(feature = "postgres")]
use cratefield_introspect::{drift as catalog_drift, unseen};
#[cfg(feature = "postgres")]
use cratefield_tables::Step;

/// `fz tables drift`: report, then fail when there was anything to
/// report.
///
/// Drift is the finding, so it is also the exit code — a CI job asking
/// "does this database still match the manifest?" needs an answer it can
/// branch on rather than a paragraph it has to read.
///
/// # Errors
///
/// Anything [`drift_report`] cannot do, and a summary line when the
/// report was not empty.
pub fn drift(manifest_path: &Path, dialect: &str, url: &str) -> Result<(), String> {
    match drift_report(manifest_path, dialect, url)? {
        0 => Ok(()),
        count => Err(format!(
            "{count} difference(s) between the declaration and the database (above)"
        )),
    }
}

/// Reports drift between the manifest at `manifest_path` and the database
/// `url` names, and answers **how many differences there were**.
///
/// The count is the point: a command that only printed would be a
/// command no test could tell the two answers apart with, and no CI job
/// could act on. The caller turns a non-zero count into a non-zero exit.
///
/// # Errors
///
/// A message for the operator when the manifest cannot be read, the
/// dialect is unsupported, the database cannot be reached, or its catalog
/// cannot be read.
pub fn drift_report(manifest_path: &Path, dialect: &str, url: &str) -> Result<usize, String> {
    // Same gate `fz migrations apply` carries, for the same reason: the
    // Postgres adapter pulls sqlx and tokio, and the default `fz`
    // dependency graph stays free of both.
    #[cfg(not(feature = "postgres"))]
    {
        let _ = (manifest_path, url);
        Err(format!(
            "dialect {dialect:?} needs an `fz` built with the `postgres` feature              (cargo install cratefield-cli --features postgres)"
        ))
    }
    #[cfg(feature = "postgres")]
    {
        report(manifest_path, dialect, url)
    }
}

#[cfg(feature = "postgres")]
fn report(manifest_path: &Path, dialect: &str, url: &str) -> Result<usize, String> {
    if dialect != "postgres" {
        return Err(format!(
            "dialect {dialect:?} cannot be reached from here (a D1 database is read through \
             wrangler, not a connection string); `--dialect postgres --url ...` is the \
             direct-connection flow, the same one `fz migrations apply` uses"
        ));
    }
    let raw = std::fs::read_to_string(manifest_path)
        .map_err(|err| format!("cannot read {}: {err}", manifest_path.display()))?;
    let manifest = crate::build::parse(manifest_path, &raw)?;
    manifest.validate().map_err(|err| err.to_string())?;

    if manifest.tables.is_empty() {
        println!("{} declares no tables of its own.", manifest_path.display());
        return Ok(0);
    }

    let changes = pollster::block_on(async {
        let db = cratefield_adapter_postgres::Postgres::connect(url)
            .await
            // The URL carries credentials; the adapter's own errors are
            // already sanitised, and this adds nothing that is not.
            .map_err(|err| format!("cannot reach the database: {err}"))?;
        let report = catalog_drift(&db, &manifest.tables)
            .await
            .map_err(|err| format!("cannot read the catalog: {err}"));
        db.close().await.ok();
        report
    })?;

    if changes.is_empty() {
        println!(
            "No drift: the database matches all {} declared table(s).",
            manifest.tables.tables.len()
        );
    } else {
        println!(
            "{} difference(s) between the declaration and the database:\n",
            changes.len()
        );
        for change in &changes {
            println!("  [{}] {}", change.step, change.line());
        }
        println!();
        for step in [Step::Expand, Step::Contract, Step::Rewrite] {
            let count = changes.iter().filter(|change| change.step == step).count();
            if count > 0 {
                println!("  {count} {step}");
            }
        }
    }
    // Printed either way, because "no drift" is an answer about the
    // things that were compared and a reader has no way to know which
    // those were.
    println!("\n{}", unseen());
    Ok(changes.len())
}
