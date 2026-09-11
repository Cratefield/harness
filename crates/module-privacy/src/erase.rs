//! Erasure: the destructive half, in two steps with a receipt.
//!
//! **Why two steps.** Erasure cannot be undone and the request that starts it
//! is one HTTP call. A single endpoint means a mistyped subject id, a retried
//! request or a curl in the wrong terminal removes somebody's practice history
//! with no moment in between. So the first call reads and promises, the second
//! acts: `POST /v1/privacy/erase` answers with exactly what it *would* do, per
//! table, with row counts and a short-lived signed token; nothing is written.
//! `POST /v1/privacy/erase/confirm` takes that token and does it.
//!
//! The preview is the point rather than ceremony. An operator about to erase
//! reads that `practice_sessions` loses 412 rows while `invoices` keeps 9
//! because tax law requires them, and can tell before acting whether the id
//! they typed is the person they meant.
//!
//! **Why one batch.** Every statement goes through [`Database::batch_atomic`], which
//! is all-or-nothing on every engine. A half-erased subject —
//! sessions gone, account row left — is worse than a failed erasure, because
//! the failure can be retried and the half cannot be found again.
//!
//! **Why it verifies afterwards.** The receipt says rows were removed because
//! the module went back and counted, not because a statement returned without
//! an error. `Erase` sets are re-counted after the batch and a non-zero count
//! fails the request: an erasure that reports success it did not achieve is
//! the one failure mode nobody would catch until it mattered.

use crate::handlers::subject_predicate;
use cratefield_core::{
    CatalogEntry, Database, Disposition, Kid, Payload, Problem, Signer, Statement,
    is_plain_identifier,
};
use serde_json::{Value, json};
use std::sync::Arc;

/// The signed purpose. A token minted for anything else cannot confirm an
/// erasure, and this one cannot be replayed against another route.
pub(crate) const PURPOSE_ERASE: &str = "privacy-erase";

/// How long a confirmation token lives.
///
/// Long enough to read the preview and decide, short enough that a token left
/// in a shell history or a ticket comment is inert by the time anybody finds
/// it. Erasure is not a task somebody resumes tomorrow.
pub(crate) const CONFIRM_TTL_SECS: u64 = 15 * 60;

/// What erasure would do, or did, to one declared set.
pub(crate) struct Planned {
    pub(crate) entry: CatalogEntry,
    pub(crate) rows: u64,
}

/// Counts the rows each declaration matches for this subject.
///
/// Counted per table rather than estimated, because the number is shown to a
/// person deciding whether to go ahead. `Retain` sets are counted too: "9 rows
/// will be kept, because tax law requires them" is the part of the answer a
/// subject is least likely to expect and most entitled to.
pub(crate) async fn plan(
    db: &Arc<dyn Database>,
    catalog: &cratefield_core::PersonalDataCatalog,
    subject: &str,
) -> Result<Vec<Planned>, String> {
    let mut planned = Vec::new();
    for entry in catalog.subject_sets() {
        if !is_plain_identifier(entry.set.table) || !is_plain_identifier(entry.set.subject) {
            return Err(format!(
                "declaration for `{}` is not queryable",
                entry.set.table
            ));
        }
        let predicate = subject_predicate(&entry.set)
            .ok_or_else(|| format!("declaration for `{}` is not queryable", entry.set.table))?;
        let statement = Statement::with_values(
            format!(
                "SELECT COUNT(*) AS n FROM {} WHERE {predicate}",
                entry.set.table
            ),
            vec![subject.into()],
        );
        let rows = db
            .query(&statement)
            .await
            .map_err(|err| format!("counting `{}` failed: {err}", entry.set.table))?;
        let count: i64 = rows.first().and_then(|row| row.get("n")).unwrap_or(0);
        planned.push(Planned {
            entry: *entry,
            rows: count.max(0).unsigned_abs(),
        });
    }
    Ok(planned)
}

/// The statements that carry out a plan, in reverse catalog order.
///
/// The catalog is composed in dependency order, so a table appears before the
/// tables that point at it. Erasing in that order would delete a parent while
/// a child still references it; reversed, the references go first and a
/// foreign key never has to be deferred.
pub(crate) fn statements(planned: &[Planned], subject: &str) -> Vec<Statement> {
    let mut out = Vec::new();
    for step in planned.iter().rev() {
        let set = step.entry.set;
        // The same predicate plan counted with: a declaration reached through
        // a join is deleted through it too, so the receipt never promises a
        // row the statements cannot find (issue #281).
        let Some(predicate) = subject_predicate(&set) else {
            // Unreachable through `HarnessBuilder::build`, which validates the
            // names. Kept explicit so a skipped declaration is a smaller
            // statement list, never a wrong one.
            continue;
        };
        match set.disposition {
            Disposition::Erase => out.push(Statement::with_values(
                format!("DELETE FROM {} WHERE {predicate}", set.table),
                vec![subject.into()],
            )),
            Disposition::Anonymise(columns) => {
                // Every column was checked to be a plain identifier at build.
                let assignments = columns
                    .iter()
                    .map(|column| format!("{column} = NULL"))
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push(Statement::with_values(
                    format!("UPDATE {} SET {assignments} WHERE {predicate}", set.table),
                    vec![subject.into()],
                ));
            }
            // Retained rows are the one case that writes nothing. They are
            // still in the receipt, with the reason, because silence here
            // would read as "we deleted everything" — which is exactly the
            // claim a retention obligation makes untrue.
            _ => {}
        }
    }
    out
}

/// Re-counts what should now be gone.
///
/// Returns the tables that still hold rows for this subject. A statement that
/// returned without an error has not proved anything: the receipt says the data
/// is gone because this went back and looked.
pub(crate) async fn verify(
    db: &Arc<dyn Database>,
    planned: &[Planned],
    subject: &str,
) -> Result<Vec<String>, String> {
    let mut remaining = Vec::new();
    for step in planned {
        if !matches!(step.entry.set.disposition, Disposition::Erase) {
            continue;
        }
        let set = step.entry.set;
        let predicate = subject_predicate(&set)
            .ok_or_else(|| format!("declaration for `{}` is not queryable", set.table))?;
        let statement = Statement::with_values(
            format!("SELECT COUNT(*) AS n FROM {} WHERE {predicate}", set.table),
            vec![subject.into()],
        );
        let rows = db
            .query(&statement)
            .await
            .map_err(|err| format!("verifying `{}` failed: {err}", set.table))?;
        let count: i64 = rows.first().and_then(|row| row.get("n")).unwrap_or(0);
        if count > 0 {
            remaining.push(set.table.to_owned());
        }
    }
    Ok(remaining)
}

/// One line per declaration, for the preview and the receipt alike. The two
/// answer the same question in different tenses, so they are rendered by the
/// same code: a preview that could describe something the receipt would not is
/// a promise the system does not keep.
pub(crate) fn render(planned: &[Planned]) -> Vec<Value> {
    planned
        .iter()
        .map(|step| {
            let set = step.entry.set;
            let mut row = json!({
                "module": step.entry.module,
                "table": set.table,
                "kind": set.kind.as_str(),
                "rows": step.rows,
            });
            let object = row.as_object_mut().expect("object");
            match set.disposition {
                Disposition::Erase => {
                    object.insert("action".into(), json!("erase"));
                }
                Disposition::Anonymise(columns) => {
                    object.insert("action".into(), json!("anonymise"));
                    object.insert("columns".into(), json!(columns));
                }
                Disposition::Retain(reason) => {
                    object.insert("action".into(), json!("retain"));
                    object.insert("reason".into(), json!(reason));
                }
                _ => {
                    object.insert("action".into(), json!("unknown"));
                }
            }
            row
        })
        .collect()
}

/// Mints the token that confirms this subject's erasure.
pub(crate) fn mint(signer: &Arc<dyn Signer>, subject: &str, now: u64) -> String {
    signer.sign(&Payload {
        purpose: PURPOSE_ERASE.to_owned(),
        subject: subject.to_owned(),
        exp: Some(now.saturating_add(CONFIRM_TTL_SECS)),
        kid: Kid::Cur,
    })
}

/// The subject a token confirms, or `None` when it is not a valid erase token.
pub(crate) fn subject_of(signer: &Arc<dyn Signer>, token: &str) -> Option<String> {
    signer.verify(token, PURPOSE_ERASE).map(|p| p.subject)
}

/// The problem returned when erasure ran but did not achieve what it claimed.
pub(crate) fn not_verified(tables: &[String]) -> Problem {
    Problem::internal().with_detail(format!(
        "erasure completed without error but {} still holds rows for this subject",
        tables.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::{DataKind, PersonalDataSet, SubjectVia};

    fn planned(sets: &'static [PersonalDataSet]) -> Vec<Planned> {
        sets.iter()
            .map(|set| Planned {
                entry: CatalogEntry {
                    module: "fixture",
                    set: *set,
                },
                rows: 1,
            })
            .collect()
    }

    const PARENT: PersonalDataSet = PersonalDataSet {
        table: "accounts",
        subject: "id",
        kind: DataKind::Identifier,
        disposition: Disposition::Erase,
        description: "The account.",
        redacted: &[],
        subject_via: None,
    };
    const CHILD: PersonalDataSet = PersonalDataSet {
        table: "practice_sessions",
        subject: "account_id",
        kind: DataKind::Fitness,
        disposition: Disposition::Erase,
        description: "Practices.",
        redacted: &[],
        subject_via: None,
    };

    /// The catalog is composed in dependency order, so a parent appears before
    /// the tables pointing at it. Erasing in that order deletes the parent
    /// while a child still references it.
    ///
    /// Asserted on the emitted statements rather than through a foreign key,
    /// because SQLite enforces one only with `PRAGMA foreign_keys = ON` — the
    /// invariant would then hold or not depending on a pragma, and the test
    /// would pass on a dialect that was not checking.
    #[test]
    fn children_are_erased_before_their_parents() {
        const SETS: &[PersonalDataSet] = &[PARENT, CHILD];
        let statements = statements(&planned(SETS), "acct-1");
        assert_eq!(statements.len(), 2);
        assert!(
            statements[0].sql.contains("practice_sessions"),
            "the parent was deleted first: {}",
            statements[0].sql
        );
        assert!(
            statements[1].sql.contains("accounts"),
            "{}",
            statements[1].sql
        );
    }

    #[test]
    fn a_retained_set_emits_no_statement() {
        const SETS: &[PersonalDataSet] = &[PersonalDataSet {
            table: "invoices",
            subject: "account_id",
            kind: DataKind::Financial,
            disposition: Disposition::Retain("Tax law requires seven years."),
            description: "Invoices.",
            redacted: &[],
            subject_via: None,
        }];
        assert!(statements(&planned(SETS), "acct-1").is_empty());
    }

    #[test]
    fn an_anonymised_set_updates_rather_than_deletes() {
        const SETS: &[PersonalDataSet] = &[PersonalDataSet {
            table: "commission_ledger",
            subject: "account_id",
            kind: DataKind::Financial,
            disposition: Disposition::Anonymise(&["name", "email"]),
            description: "Commission entries.",
            redacted: &[],
            subject_via: None,
        }];
        let statements = statements(&planned(SETS), "acct-1");
        assert_eq!(statements.len(), 1);
        let sql = &statements[0].sql;
        assert!(sql.starts_with("UPDATE commission_ledger SET "), "{sql}");
        assert!(sql.contains("name = NULL"), "{sql}");
        assert!(sql.contains("email = NULL"), "{sql}");
        // The row survives: an aggregate that loses rows loses its totals.
        assert!(!sql.contains("DELETE"), "{sql}");
    }

    #[test]
    fn a_set_reached_through_a_join_is_deleted_through_it_too() {
        // The same predicate plan counted with, or the receipt promises a
        // row the DELETE cannot find (issue #281).
        const SETS: &[PersonalDataSet] = &[PersonalDataSet {
            table: "deletion_jobs",
            subject: "provider_subject",
            kind: DataKind::Identifier,
            disposition: Disposition::Erase,
            description: "Deletion requests.",
            redacted: &[],
            subject_via: Some(SubjectVia {
                table: "identities",
                subject: "user_id",
                key: "provider_subject",
            }),
        }];
        let statements = statements(&planned(SETS), "acct-1");
        assert_eq!(statements.len(), 1);
        let sql = &statements[0].sql;
        assert!(
            sql.contains(
                "WHERE provider_subject IN (SELECT provider_subject FROM identities \
                          WHERE user_id = ?)"
            ),
            "{sql}"
        );
    }
}

#[cfg(test)]
mod verification_tests {
    use super::*;
    use cratefield_core::{DataKind, PersonalDataSet};
    use cratefield_testing::TestHarness;

    /// The join reaches `verify` too, and a miss here is silently
    /// permissive (issue #281).
    ///
    /// `verify` only re-counts `Erase` sets, and the one set in the
    /// workspace that declares a join — `auth-core.deletion_jobs` — is
    /// `Retain`. So nothing in the real catalogue exercises this path, and
    /// a `verify` that matched the subject directly would find zero rows
    /// through the join it ignored and write a receipt saying the erasure
    /// completed. That is the same failure the issue is about, in the one
    /// builder where it would not be noticed.
    #[pollster::test]
    async fn verification_follows_a_declared_join() {
        const JOINED: PersonalDataSet = PersonalDataSet {
            table: "jobs",
            subject: "provider_subject",
            kind: DataKind::Identifier,
            disposition: Disposition::Erase,
            description: "Rows keyed on the provider's id for a person.",
            redacted: &[],
            subject_via: Some(cratefield_core::SubjectVia {
                table: "identities",
                subject: "user_id",
                key: "provider_subject",
            }),
        };

        for kit in TestHarness::all_dialects(Vec::new) {
            kit.db
                .execute(&Statement::new(
                    "CREATE TABLE identities (user_id TEXT NOT NULL, provider_subject TEXT NOT NULL)",
                ))
                .await
                .expect("create identities");
            kit.db
                .execute(&Statement::new(
                    "CREATE TABLE jobs (id TEXT PRIMARY KEY, provider_subject TEXT NOT NULL)",
                ))
                .await
                .expect("create jobs");
            kit.db
                .execute(&Statement::with_values(
                    "INSERT INTO identities (user_id, provider_subject) VALUES (?, ?)",
                    vec!["acct-1".into(), "sub-9".into()],
                ))
                .await
                .expect("insert identity");
            kit.db
                .execute(&Statement::with_values(
                    "INSERT INTO jobs (id, provider_subject) VALUES (?, ?)",
                    vec!["j1".into(), "sub-9".into()],
                ))
                .await
                .expect("insert job");

            let planned = vec![Planned {
                entry: CatalogEntry {
                    module: "fixture",
                    set: JOINED,
                },
                rows: 1,
            }];

            // The subject is the account id. Nothing in `jobs` holds it —
            // only `identities` does — so a verify that matched directly
            // would count zero and call this erased.
            let remaining = verify(&kit.db, &planned, "acct-1").await.expect("verify");
            assert_eq!(
                remaining,
                vec!["jobs".to_owned()],
                "verification did not follow the join, so a surviving row read as erased"
            );

            kit.db
                .execute(&Statement::with_values(
                    "DELETE FROM jobs WHERE provider_subject = ?",
                    vec!["sub-9".into()],
                ))
                .await
                .expect("delete");
            let remaining = verify(&kit.db, &planned, "acct-1").await.expect("verify");
            assert!(
                remaining.is_empty(),
                "verification named a table it no longer holds rows for: {remaining:?}"
            );
        }
    }

    const SET: PersonalDataSet = PersonalDataSet {
        table: "leftovers",
        subject: "account_id",
        kind: DataKind::Usage,
        disposition: Disposition::Erase,
        description: "Rows that should not survive an erasure.",
        redacted: &[],
        subject_via: None,
    };

    fn planned() -> Vec<Planned> {
        vec![Planned {
            entry: CatalogEntry {
                module: "fixture",
                set: SET,
            },
            rows: 1,
        }]
    }

    /// Verification has to be able to report a failure, or it is decoration.
    ///
    /// The case it exists for cannot be reached through the routes — a batch
    /// that returns without an error and changes nothing needs a broken
    /// engine — so it is exercised directly: rows present, nothing deleted,
    /// and the table named as still holding them. Without this, a `verify`
    /// that always reported success would pass every other test here, which
    /// is exactly what it did before this test was written.
    #[pollster::test]
    async fn verification_names_a_table_that_still_holds_rows() {
        for kit in TestHarness::all_dialects(Vec::new) {
            kit.db
                .execute(&Statement::new(
                    "CREATE TABLE leftovers (id TEXT PRIMARY KEY, account_id TEXT NOT NULL)",
                ))
                .await
                .expect("create");
            kit.db
                .execute(&Statement::with_values(
                    "INSERT INTO leftovers (id, account_id) VALUES (?, ?)",
                    vec!["l1".into(), "acct-1".into()],
                ))
                .await
                .expect("insert");

            let remaining = verify(&kit.db, &planned(), "acct-1").await.expect("verify");
            assert_eq!(
                remaining,
                vec!["leftovers".to_owned()],
                "verification reported a clean erasure over surviving rows"
            );

            kit.db
                .execute(&Statement::with_values(
                    "DELETE FROM leftovers WHERE account_id = ?",
                    vec!["acct-1".into()],
                ))
                .await
                .expect("delete");
            let remaining = verify(&kit.db, &planned(), "acct-1").await.expect("verify");
            assert!(remaining.is_empty(), "{remaining:?}");
        }
    }
}
