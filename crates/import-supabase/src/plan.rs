//! The migration plan: what the importer will do, tied to the inspection it
//! was written from (ADR 0026, Decision 3; issue #728).
//!
//! `fz import supabase` runs [`crate::inspect`], reads the target Postgres
//! read-only ([`read_target`]) and builds a [`Plan`] with [`build_plan`].
//! The plan carries [`inspection_hash`] — a sha256 over the report's
//! canonical JSON with the fields that vary between two inspections of an
//! unchanged source removed — so [`check_drift`] can refuse to apply a plan
//! whose source has changed since it was written.
//!
//! Nothing here writes. The plan is a document; `--apply` only re-checks
//! it (the auth-users and data phases land with #659/#660).

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::report::{ExtensionSupport, Report, Tool};
use crate::secret::Secret;
use crate::session::{InspectError, ReadOnlySession};

/// The version of the plan's JSON shape. A reader refuses one it does not
/// know; adding a field does not change it.
pub const PLAN_VERSION: u32 = 1;

/// The plan `fz import supabase` writes and `--apply` reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    /// [`PLAN_VERSION`] at the time this plan was written.
    pub plan_version: u32,
    /// Which tool wrote it.
    pub tool: Tool,
    /// The project, by ref.
    pub project: PlanProject,
    /// The inspection the plan was written from, as
    /// `sha256:<hex>` over the report's canonical JSON.
    pub inspection_hash: String,
    /// Where each source schema lands, e.g. `public` -> `app`.
    pub schema_mapping: Vec<SchemaMapping>,
    /// The phases, in order.
    pub phases: Vec<PlanPhase>,
    /// The target, `null` when it was not checked.
    pub target: Option<PlanTarget>,
    /// Every source extension, with what the target can do with it.
    pub extensions: Vec<PlanExtension>,
    /// What stops the plan: an unread target, a missing or older
    /// extension, an extension installed in `public` on the source.
    pub blockers: Vec<PlanBlocker>,
}

/// The project a plan applies to, by ref alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanProject {
    /// The Supabase project ref.
    #[serde(rename = "ref")]
    pub project_ref: String,
}

/// One source schema and where it lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMapping {
    /// The source schema.
    pub from: String,
    /// The target schema.
    pub to: String,
}

/// One importer phase and what it does, in one line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanPhase {
    /// `auth_users`, `schema`, `data`, `storage` or `verify`.
    pub phase: String,
    /// What the phase does.
    pub does: String,
}

/// The target, once it was checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanTarget {
    /// `server_version` as the target reports it.
    pub server_version: String,
}

/// A source extension and the target's facts about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanExtension {
    /// Its name.
    pub name: String,
    /// The version installed on the source.
    pub source_version: String,
    /// The schema it is installed in on the source.
    pub source_schema: String,
    /// What the harness can do with it.
    pub support: ExtensionSupport,
    /// The target has the extension available (`pg_available_extensions`).
    pub available: bool,
    /// The version installed on the target, if any.
    pub installed_version: Option<String>,
    /// The schema it is installed in on the target, if any.
    pub installed_schema: Option<String>,
    /// The target's `default_version`, if available.
    pub default_version: Option<String>,
    /// The newest version the target can provide, if available.
    pub max_version: Option<String>,
}

/// One reason the plan cannot be applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanBlocker {
    /// A stable code: `target_not_checked`, `extension_missing`,
    /// `extension_older` or `extension_in_public`.
    pub code: String,
    /// What it is about: the extension name, or the project ref.
    pub subject: String,
    /// What to do about it.
    pub message: String,
}

/// A fresh inspection of the source no longer matches the plan.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the source changed since the plan was written (plan {planned}, now {fresh}); re-plan with \
     `fz import supabase plan` and apply the new plan"
)]
pub struct PlanDrift {
    /// The hash the plan carries.
    pub planned: String,
    /// The hash of the fresh inspection.
    pub fresh: String,
}

impl Plan {
    /// The plan as pretty-printed JSON, with a trailing newline.
    ///
    /// # Panics
    ///
    /// Never: every field serializes.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = serde_json::to_string_pretty(self).expect("a plan always serializes");
        out.push('\n');
        out
    }
}

/// The target Postgres, as far as the plan needs it: the server version and
/// what each available extension offers. Read from `pg_available_extensions`,
/// `pg_available_extension_versions` and `pg_extension`; no user table is
/// touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetFacts {
    /// `server_version` as the target reports it.
    pub server_version: String,
    /// Every extension the target could install, by name.
    pub extensions: Vec<TargetExtension>,
}

/// What the target knows about one extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetExtension {
    /// Its name.
    pub name: String,
    /// The version installed, if it is.
    pub installed_version: Option<String>,
    /// The schema it is installed in, if it is.
    pub installed_schema: Option<String>,
    /// The target's `default_version`.
    pub default_version: Option<String>,
    /// The newest version the target can provide, by `compare_versions`.
    pub max_version: Option<String>,
}

/// Reads the target's server version and available extensions, read-only.
///
/// # Errors
///
/// [`InspectError`] when the target cannot be reached or read, or a write
/// was somehow attempted (it never is: the session is read-only).
pub async fn read_target(url: &Secret) -> Result<TargetFacts, InspectError> {
    let mut session = ReadOnlySession::open(url).await?;
    let server_version: String = sqlx::query_scalar("SELECT current_setting('server_version')")
        .fetch_one(&mut session.conn)
        .await
        .map_err(|error| session.error(&error))?;
    let rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Vec<String>,
        ),
    >(
        "SELECT ae.name::text, ae.default_version::text, e.extversion::text, n.nspname::text, \
         COALESCE((SELECT array_agg(v.version ORDER BY v.version) FROM \
         pg_available_extension_versions v WHERE v.name = ae.name), ARRAY[]::text[]) \
         FROM pg_available_extensions ae \
         LEFT JOIN pg_extension e ON e.extname = ae.name \
         LEFT JOIN pg_namespace n ON n.oid = e.extnamespace \
         ORDER BY ae.name",
    )
    .fetch_all(&mut session.conn)
    .await
    .map_err(|error| session.error(&error))?;
    let _ = session.finish().await?;
    Ok(TargetFacts {
        server_version,
        extensions: rows
            .into_iter()
            .map(
                |(name, default_version, installed_version, installed_schema, versions)| {
                    let max_version = versions.into_iter().max_by(|a, b| compare_versions(a, b));
                    TargetExtension {
                        name,
                        installed_version,
                        installed_schema,
                        default_version,
                        max_version,
                    }
                },
            )
            .collect(),
    })
}

/// Builds the plan. Pure: no database, so every blocker is decided here and
/// tested without one.
#[must_use]
pub fn build_plan(report: &Report, target: Option<&TargetFacts>) -> Plan {
    Plan {
        plan_version: PLAN_VERSION,
        tool: report.tool.clone(),
        project: PlanProject {
            project_ref: report.project.project_ref.clone(),
        },
        inspection_hash: inspection_hash(report),
        schema_mapping: report
            .schemas
            .iter()
            .filter_map(|schema| {
                schema.target.as_ref().map(|to| SchemaMapping {
                    from: schema.name.clone(),
                    to: to.clone(),
                })
            })
            .collect(),
        phases: phases(report),
        target: target.map(|facts| PlanTarget {
            server_version: facts.server_version.clone(),
        }),
        extensions: plan_extensions(report, target),
        blockers: blockers(report, target),
    }
}

/// Every blocker the plan carries, in report order.
fn blockers(report: &Report, target: Option<&TargetFacts>) -> Vec<PlanBlocker> {
    let mut out = Vec::new();
    if target.is_none() {
        out.push(PlanBlocker {
            code: "target_not_checked".to_owned(),
            subject: report.project.project_ref.clone(),
            message: "the target Postgres was not checked, so extension availability is unknown: \
                      set the variable named by --target-env (default DATABASE_URL) to the \
                      target's URL, or pass it by name, and run again"
                .to_owned(),
        });
    }
    for extension in &report.extensions {
        if extension.schema == "public" {
            out.push(PlanBlocker {
                code: "extension_in_public".to_owned(),
                subject: extension.name.clone(),
                message: format!(
                    "extension {} is installed in schema public on the source; imported objects \
                     move public->app and functions are pinned to search_path = app, extensions, \
                     so install it in the extensions schema on the target and remap the column \
                     types it defines (public.{} types)",
                    extension.name, extension.name
                ),
            });
        }
        // The importer skips Supabase platform extensions, and plpgsql is
        // always present; neither needs a target check.
        if extension.support == ExtensionSupport::SupabasePlatform || extension.name == "plpgsql" {
            continue;
        }
        let Some(facts) = target else { continue };
        match facts
            .extensions
            .iter()
            .find(|known| known.name == extension.name)
        {
            None => out.push(PlanBlocker {
                code: "extension_missing".to_owned(),
                subject: extension.name.clone(),
                message: format!(
                    "{} {} is not available on the target; install it before the schema phase",
                    extension.name, extension.version
                ),
            }),
            Some(known) => {
                let best = known
                    .installed_version
                    .clone()
                    .or_else(|| known.max_version.clone());
                if let Some(best) = best
                    && compare_versions(&best, &extension.version) == Ordering::Less
                {
                    out.push(PlanBlocker {
                        code: "extension_older".to_owned(),
                        subject: extension.name.clone(),
                        message: format!(
                            "the target's {} is {}, older than the source's {}; upgrade the \
                             target Postgres or the extension before the schema phase",
                            extension.name, best, extension.version
                        ),
                    });
                }
            }
        }
    }
    out
}

/// Every source extension, with the target's facts where it has any.
fn plan_extensions(report: &Report, target: Option<&TargetFacts>) -> Vec<PlanExtension> {
    report
        .extensions
        .iter()
        .map(|extension| {
            let known = target.and_then(|facts| {
                facts
                    .extensions
                    .iter()
                    .find(|known| known.name == extension.name)
            });
            PlanExtension {
                name: extension.name.clone(),
                source_version: extension.version.clone(),
                source_schema: extension.schema.clone(),
                support: extension.support,
                available: known.is_some(),
                installed_version: known.and_then(|known| known.installed_version.clone()),
                installed_schema: known.and_then(|known| known.installed_schema.clone()),
                default_version: known.and_then(|known| known.default_version.clone()),
                max_version: known.and_then(|known| known.max_version.clone()),
            }
        })
        .collect()
}

/// The phases, in the ADR's order, each with a one-line description built
/// from the report's counts.
fn phases(report: &Report) -> Vec<PlanPhase> {
    let schemas: Vec<String> = report
        .schemas
        .iter()
        .filter_map(|schema| {
            schema.target.as_ref().map(|to| {
                format!(
                    "create schema {to} (from {}) with {} tables",
                    schema.name, schema.tables
                )
            })
        })
        .collect();
    vec![
        PlanPhase {
            phase: "auth_users".to_owned(),
            does: report.auth.users.map_or_else(
                || {
                    "copy the auth users with their password hashes and identities (count not \
                     visible to the inspecting role)"
                        .to_owned()
                },
                |users| {
                    format!("copy {users} auth users with their password hashes and identities")
                },
            ),
        },
        PlanPhase {
            phase: "schema".to_owned(),
            does: if schemas.is_empty() {
                "no user schemas to create".to_owned()
            } else {
                schemas.join("; ")
            },
        },
        PlanPhase {
            phase: "data".to_owned(),
            does: format!(
                "copy an estimated {} rows across {} tables",
                report.summary.estimated_rows, report.summary.tables
            ),
        },
        PlanPhase {
            phase: "storage".to_owned(),
            does: match (report.summary.storage_objects, report.summary.storage_bytes) {
                (Some(objects), Some(bytes)) => {
                    format!("copy {objects} storage objects ({bytes} bytes) into R2")
                }
                _ => "copy the storage objects into R2 (count and size not visible to the \
                      inspecting role)"
                    .to_owned(),
            },
        },
        PlanPhase {
            phase: "verify".to_owned(),
            does: "compare per-table row counts and checksums against the source".to_owned(),
        },
    ]
}

/// `sha256:<hex>` over the report's canonical JSON with the fields that vary
/// between two inspections of an unchanged source removed.
///
/// Removed, because they measure *how much* or *where*, not *what* the
/// source is: the connection's host, port and database; the `read_only`
/// evidence, which describes the session, not the source; every byte size,
/// row estimate, object count and transfer estimate; and the warnings.
/// A column add, drop or retype changes it.
///
/// # Panics
///
/// Never: every field serializes.
#[must_use]
pub fn inspection_hash(report: &Report) -> String {
    let mut canonical = report.clone();
    canonical.project.host.clear();
    canonical.project.port = 0;
    canonical.project.database.clear();
    canonical.read_only = crate::report::ReadOnlyEvidence {
        transaction_read_only: true,
        session_read_only: true,
        no_transaction_id_assigned: true,
        role: String::new(),
        role_is_superuser: false,
        role_can_write: false,
    };
    canonical.summary.estimated_rows = 0;
    canonical.summary.data_bytes = 0;
    canonical.summary.index_bytes = 0;
    canonical.summary.storage_objects = canonical.summary.storage_objects.map(|_| 0);
    canonical.summary.storage_bytes = canonical.summary.storage_bytes.map(|_| 0);
    canonical.summary.transfer_assumed_mbps = 0;
    canonical.summary.estimated_transfer_seconds = 0;
    for table in &mut canonical.tables {
        table.estimated_rows = None;
        table.data_bytes = 0;
        table.index_bytes = 0;
    }
    canonical.auth.users = canonical.auth.users.map(|_| 0);
    canonical.auth.users_without_password = canonical.auth.users_without_password.map(|_| 0);
    canonical.auth.users_unconfirmed = canonical.auth.users_unconfirmed.map(|_| 0);
    canonical.auth.anonymous_users = canonical.auth.anonymous_users.map(|_| 0);
    canonical.auth.mfa_factors = canonical.auth.mfa_factors.map(|_| 0);
    canonical.auth.sso_providers = canonical.auth.sso_providers.map(|_| 0);
    for provider in canonical.auth.identities_by_provider.iter_mut().flatten() {
        provider.identities = 0;
    }
    // A count the role cannot see stays `None`: visibility is part of the
    // shape, only the volatile numbers are zeroed.
    for bucket in canonical.storage.buckets.iter_mut().flatten() {
        bucket.objects = bucket.objects.map(|_| 0);
        bucket.bytes = bucket.bytes.map(|_| 0);
        bucket.objects_over_blob_cap = bucket.objects_over_blob_cap.map(|_| 0);
    }
    canonical.warnings.clear();
    let json = serde_json::to_vec(&canonical).expect("a report always serializes");
    format!("sha256:{}", hex::encode(Sha256::digest(&json)))
}

/// Checks a fresh inspection against the plan's hash.
///
/// # Errors
///
/// [`PlanDrift`] when the source changed since the plan was written; its
/// message names both hashes and says to re-plan.
pub fn check_drift(plan: &Plan, fresh: &Report) -> Result<(), PlanDrift> {
    let fresh = inspection_hash(fresh);
    if fresh == plan.inspection_hash {
        Ok(())
    } else {
        Err(PlanDrift {
            planned: plan.inspection_hash.clone(),
            fresh,
        })
    }
}

/// Compares two versions the way a person reads them: numeric runs
/// numerically (`3.3.7` < `3.4.0`), and a shorter version is older
/// (`1.3` < `1.3.1`).
fn compare_versions(a: &str, b: &str) -> Ordering {
    let pa = segments(a);
    let pb = segments(b);
    for index in 0..pa.len().max(pb.len()) {
        match (pa.get(index), pb.get(index)) {
            (Some(x), Some(y)) => {
                let order = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(left), Ok(right)) => left.cmp(&right),
                    _ => x.cmp(y),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => break,
        }
    }
    Ordering::Equal
}

/// Splits a version into runs of digits and runs of letters, dropping the
/// separators: `3.3.7` -> `["3", "3", "7"]`.
fn segments(version: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut last_was_digit = None;
    for character in version.chars() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            last_was_digit = None;
            continue;
        }
        let digit = character.is_ascii_digit();
        if last_was_digit.is_some_and(|previous| previous != digit) {
            out.push(std::mem::take(&mut current));
        }
        current.push(character);
        last_was_digit = Some(digit);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::ExtensionSupport;
    use serde_json::{Value, json};

    fn extension(name: &str, version: &str, schema: &str, support: &str) -> Value {
        json!({"name": name, "version": version, "schema": schema, "support": support})
    }

    /// A minimal report built through serde, so it does not need `Default`
    /// on forty report types.
    fn report(extensions: &[Value], tables: &[Value]) -> Report {
        serde_json::from_value(json!({
            "report_version": 1,
            "tool": {"name": "cratefield-import-supabase", "version": "0.1.0"},
            "project": {"ref": "abcdefghijklmnopqrst", "host": "db.test", "port": 5432,
                        "database": "postgres", "server_version": "16.4"},
            "read_only": {"transaction_read_only": true, "session_read_only": true,
                          "no_transaction_id_assigned": true, "role": "postgres",
                          "role_is_superuser": false, "role_can_write": false},
            "coverage": {"database": "inspected", "management_api": "not_inspected",
                         "policy_classifier": "not_inspected", "sections": []},
            "summary": {"automatic": 0, "needs_work": 0, "blockers": 0, "decided": 0,
                        "undecided": 0, "ready": true, "tables": 1,
                        "estimated_rows": 4, "data_bytes": 8192, "index_bytes": 4096,
                        "storage_objects": 3, "storage_bytes": 20000, "transfer_assumed_mbps": 100,
                        "estimated_transfer_seconds": 1},
            "dispositions": {"by_kind": [], "decided": [], "stale": []},
            "schemas": [], "tables": tables, "views": [], "sequences": [], "enums": [],
            "extensions": extensions, "functions": [], "triggers": [], "policies": [],
            "managed_policies": [], "api_role_grants": [],
            "auth": {"present": true, "users": 3, "users_without_password": 2,
                     "users_unconfirmed": 1, "anonymous_users": 0, "identities_by_provider": [],
                     "mfa_factors": 1, "sso_providers": 0, "enabled_providers": null,
                     "enabled_mfa": null},
            "storage": {"present": true, "buckets": [],
                        "unattached_policies": []},
            "edge_functions": {"status": "not_inspected", "functions": []},
            "realtime": {"publications": []}, "cron_jobs": [], "findings": [], "warnings": []
        }))
        .expect("a minimal report deserializes")
    }

    fn column(name: &str, data_type: &str) -> Value {
        json!({"name": name, "data_type": data_type, "nullable": true, "default": null,
               "identity": null, "generated": null})
    }

    fn table(columns: &[Value]) -> Value {
        json!({"schema": "app", "name": "widgets", "kind": "table", "estimated_rows": 4,
               "data_bytes": 8192, "index_bytes": 4096, "rls_enabled": false, "rls_forced": false,
               "primary_key": ["id"], "columns": columns, "constraints": [], "indexes": []})
    }

    fn target(extensions: Vec<TargetExtension>) -> TargetFacts {
        TargetFacts {
            server_version: "16.4".to_owned(),
            extensions,
        }
    }

    fn target_extension(name: &str, installed: Option<&str>, max: Option<&str>) -> TargetExtension {
        TargetExtension {
            name: name.to_owned(),
            installed_version: installed.map(str::to_owned),
            installed_schema: installed.map(|_| "extensions".to_owned()),
            default_version: max.map(str::to_owned),
            max_version: max.map(str::to_owned),
        }
    }

    fn blocker<'a>(plan: &'a Plan, code: &str) -> &'a PlanBlocker {
        plan.blockers
            .iter()
            .find(|blocker| blocker.code == code)
            .unwrap_or_else(|| panic!("no {code} blocker in {:?}", plan.blockers))
    }

    #[test]
    fn versions_compare_numerically_and_shorter_is_older() {
        assert_eq!(compare_versions("3.3.7", "3.4.0"), Ordering::Less);
        assert_eq!(compare_versions("1.3", "1.3.1"), Ordering::Less);
        assert_eq!(compare_versions("1.3.1", "1.3"), Ordering::Greater);
        assert_eq!(compare_versions("3.3.7", "3.3.7"), Ordering::Equal);
        assert_eq!(compare_versions("1.10", "1.9"), Ordering::Greater);
        assert_eq!(compare_versions("0.35.0", "1.0.0"), Ordering::Less);
    }

    #[test]
    fn an_unchecked_target_is_a_blocker_not_an_error() {
        let report = report(
            &[extension("postgis", "3.3.7", "extensions", "supported")],
            &[],
        );
        let plan = build_plan(&report, None);
        assert_eq!(plan.target, None);
        assert_eq!(plan.blockers.len(), 1);
        assert_eq!(plan.blockers[0].code, "target_not_checked");
        assert!(plan.blockers[0].message.contains("DATABASE_URL"));
    }

    #[test]
    fn a_missing_extension_names_it_and_its_version() {
        let report = report(
            &[extension("postgis", "3.3.7", "extensions", "supported")],
            &[],
        );
        let plan = build_plan(&report, Some(&target(vec![])));
        let blocker = blocker(&plan, "extension_missing");
        assert_eq!(blocker.subject, "postgis");
        assert!(blocker.message.contains("postgis"), "{blocker:?}");
        assert!(blocker.message.contains("3.3.7"), "{blocker:?}");
    }

    #[test]
    fn an_older_target_extension_names_both_versions() {
        let report = report(
            &[extension("postgis", "3.3.7", "extensions", "supported")],
            &[],
        );
        let facts = target(vec![target_extension(
            "postgis",
            Some("3.2.0"),
            Some("3.3.7"),
        )]);
        let plan = build_plan(&report, Some(&facts));
        let blocker = blocker(&plan, "extension_older");
        assert!(blocker.message.contains("3.2.0"), "{blocker:?}");
        assert!(blocker.message.contains("3.3.7"), "{blocker:?}");
    }

    #[test]
    fn a_new_enough_target_extension_has_no_blocker() {
        let report = report(
            &[extension("postgis", "3.3.7", "extensions", "supported")],
            &[],
        );
        let facts = target(vec![target_extension(
            "postgis",
            Some("3.3.7"),
            Some("3.3.7"),
        )]);
        let plan = build_plan(&report, Some(&facts));
        assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
        let extension = &plan.extensions[0];
        assert!(extension.available);
        assert_eq!(extension.installed_version.as_deref(), Some("3.3.7"));
        assert_eq!(extension.installed_schema.as_deref(), Some("extensions"));
    }

    #[test]
    fn an_extension_installed_in_public_is_a_blocker() {
        let report = report(&[extension("postgis", "3.3.7", "public", "supported")], &[]);
        let facts = target(vec![target_extension(
            "postgis",
            Some("3.3.7"),
            Some("3.3.7"),
        )]);
        let plan = build_plan(&report, Some(&facts));
        let blocker = blocker(&plan, "extension_in_public");
        assert_eq!(blocker.subject, "postgis");
        assert!(blocker.message.contains("public"), "{blocker:?}");
        assert!(blocker.message.contains("extensions"), "{blocker:?}");
    }

    #[test]
    fn a_platform_extension_and_plpgsql_are_not_checked_against_the_target() {
        let report = report(
            &[
                extension("pg_net", "0.7.1", "extensions", "supabase_platform"),
                extension("plpgsql", "1.0", "pg_catalog", "supported"),
            ],
            &[],
        );
        let plan = build_plan(&report, Some(&target(vec![])));
        assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    }

    #[test]
    fn the_hash_is_stable_and_changes_when_a_column_changes() {
        let tables = vec![table(&[column("id", "integer"), column("name", "text")])];
        let report = report(&[], &tables);
        assert_eq!(inspection_hash(&report), inspection_hash(&report.clone()));

        // An unchanged source inspected twice: same bytes, same hash even
        // though the volatile fields differ.
        let mut other = report.clone();
        other.project.host = "elsewhere.test".to_owned();
        other.project.port = 6543;
        other.summary.data_bytes = 999_999;
        other.tables[0].data_bytes = 999_999;
        other.tables[0].estimated_rows = Some(500);
        other.auth.users = Some(42);
        other.warnings.push("a warning".to_owned());
        assert_eq!(inspection_hash(&report), inspection_hash(&other));

        // A changed column does change it.
        let mut dropped = report.clone();
        dropped.tables[0].columns.pop();
        assert_ne!(inspection_hash(&report), inspection_hash(&dropped));
        let mut retyped = report.clone();
        retyped.tables[0].columns[1].data_type = "varchar(20)".to_owned();
        assert_ne!(inspection_hash(&report), inspection_hash(&retyped));
    }

    #[test]
    fn drift_reports_both_hashes() {
        let report = report(&[], &[table(&[column("id", "integer")])]);
        let plan = build_plan(&report, None);
        check_drift(&plan, &report.clone()).expect("an unchanged source does not drift");

        let mut changed = report.clone();
        let extra: crate::report::Column =
            serde_json::from_value(column("extra", "text")).expect("a column");
        changed.tables[0].columns.push(extra);
        let error = check_drift(&plan, &changed).expect_err("a new column drifts");
        assert!(
            error.to_string().contains("changed since the plan"),
            "{error}"
        );
        assert!(error.to_string().contains(&plan.inspection_hash), "{error}");
        assert!(
            error.to_string().contains(&inspection_hash(&changed)),
            "{error}"
        );
    }

    #[test]
    fn the_plan_json_round_trips() {
        let report = report(
            &[extension("postgis", "3.3.7", "extensions", "supported")],
            &[],
        );
        let plan = build_plan(&report, Some(&target(vec![])));
        let json = plan.to_json();
        assert!(json.ends_with('\n'));
        let parsed: Plan = serde_json::from_str(&json).expect("a plan parses back");
        assert_eq!(parsed, plan);
        assert_eq!(
            plan.phases
                .iter()
                .map(|phase| phase.phase.as_str())
                .collect::<Vec<_>>(),
            ["auth_users", "schema", "data", "storage", "verify"]
        );
    }

    #[test]
    fn a_supabase_platform_extension_keeps_its_support_status() {
        let report = report(
            &[extension(
                "pg_net",
                "0.7.1",
                "extensions",
                "supabase_platform",
            )],
            &[],
        );
        let plan = build_plan(&report, None);
        assert_eq!(
            plan.extensions[0].support,
            ExtensionSupport::SupabasePlatform
        );
        assert!(!plan.extensions[0].available);
    }
}
