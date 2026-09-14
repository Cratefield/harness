//! `fz tables diff` and `fz tables drift` — what a declaration change
//! costs, and what a database differs from the declaration by.
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
use cratefield_tables::Step;

/// `fz tables diff`: what changed between two versions of a manifest's
/// declaration, and what each change costs.
///
/// The counterpart of `drift`, and the reason both exist: this is the
/// question before a deploy — *"I edited the declaration; can I ship
/// it?"* — and drift is the question after one. Neither answers the
/// other, and a database is only involved in the second.
///
/// Exits non-zero when anything changed, for the same reason `drift`
/// does: the finding is the point, and a CI job comparing a branch's
/// manifest against `main`'s needs something to branch on.
///
/// # Errors
///
/// A message when either manifest cannot be read or is not valid, and a
/// summary line when the report was not empty.
pub fn diff(previous: &Path, current: &Path) -> Result<(), String> {
    match diff_report(previous, current)? {
        0 => Ok(()),
        count => Err(format!("{count} change(s) to the declaration (above)")),
    }
}

/// Reports the differences and answers how many there were.
///
/// # Errors
///
/// A message when either manifest cannot be read or is not valid.
pub fn diff_report(previous: &Path, current: &Path) -> Result<usize, String> {
    let before = load(previous)?;
    let after = load(current)?;
    let changes = cratefield_tables::diff(&before.tables, &after.tables);
    // The schema is not the whole declaration. Flipping one table from
    // `owner` to `public-read` changes no column, so the schema diff is
    // empty — and this command answered "No change" and exited zero for
    // an edit that publishes every subject's private rows.
    let declared = cratefield_manifest::declaration_diff(
        &before.table_access,
        &after.table_access,
        &before.table_privacy,
        &after.table_privacy,
    );

    if changes.is_empty() && declared.is_empty() {
        println!(
            "No change: both declare the same {} table(s), with the same access and privacy.",
            after.tables.tables.len()
        );
        return Ok(0);
    }
    if !declared.is_empty() {
        // First, and not under the expand/contract/rewrite heading: those
        // three words are about what a change costs to *apply*, and these
        // changes cost nothing to apply and can still be the most
        // consequential line in the diff.
        println!(
            "{} change(s) to who may reach these tables and what they hold:\n",
            declared.len()
        );
        for change in &declared {
            println!("  {}", change.line());
        }
        let widened = declared
            .iter()
            .filter(|change| {
                matches!(
                    change,
                    cratefield_manifest::DeclarationChange::Access {
                        direction: cratefield_manifest::Move::Widens,
                        ..
                    }
                )
            })
            .count();
        if widened > 0 {
            println!("\n  {widened} of them widen reach. Read those before shipping.");
        }
        println!();
    }
    if changes.is_empty() {
        return Ok(declared.len());
    }
    println!("{} change(s) to the declaration:\n", changes.len());
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
    // The vocabulary is `docs/ROLLBACK.md` section 5's, and a reader who
    // has not met it needs the line saying what the three words cost.
    println!(
        "\n  expand: additive, a rollback stays free\n           contract: safe once nothing deployed reads it\n           rewrite: cannot be applied forward-only to rows that already exist"
    );
    Ok(changes.len() + declared.len())
}

/// Reads and validates one manifest. Validated on purpose: comparing two
/// declarations where one is not legal reports differences against
/// something that could never be deployed.
fn load(path: &Path) -> Result<cratefield_manifest::VentureManifest, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let manifest = crate::build::parse(path, &raw)?;
    manifest
        .validate()
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(manifest)
}

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
