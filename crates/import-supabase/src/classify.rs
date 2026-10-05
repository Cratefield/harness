//! Turns what was read into findings: every item automatic, needs work, or
//! a blocker, with a reason and its Cratefield equivalent.
//!
//! The split is ADR 0026's Decision 5. Automatic: tables, columns,
//! constraints, indexes, sequences, enums and supported extensions into the
//! venture's `app` schema; functions, triggers and views verbatim where they
//! do not reach into `auth`/`storage`; auth users; storage objects into R2.
//! Reported (needs work): every RLS policy, `auth.*` usage, SECURITY
//! DEFINER, grants to the API roles, Edge Functions, Realtime, cron jobs,
//! Supabase-only extensions and foreign keys into `auth.users`. A blocker is
//! what stops a later step outright: an extension with no harness form, a
//! foreign key into a Supabase table no phase recreates, a schema name the
//! target already uses.

use std::collections::{BTreeMap, BTreeSet};

use crate::collect::{Catalog, names_schema};
use crate::extensions;
use crate::report::{
    Auth, BucketPolicy, Classification, EdgeFunctions, ExtensionSupport, Finding, Policy,
    SourceStatus, Storage,
};

use Classification::{Automatic, Blocker, NeedsWork};

/// Platform extensions with nothing to carry and nothing depending on them
/// that a venture would notice.
const INERT_PLATFORM: &[&str] = &[
    "hypopg",
    "index_advisor",
    "pg_stat_monitor",
    "pg_stat_statements",
    "plpgsql_check",
];

/// Where a user schema lands on the target.
#[must_use]
pub(crate) fn target_schema(schema: &str) -> String {
    if schema == "public" {
        "app".to_owned()
    } else {
        schema.to_owned()
    }
}

struct Findings(Vec<Finding>);

impl Findings {
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        kind: &str,
        object: impl Into<String>,
        classification: Classification,
        phase: &str,
        reason: impl Into<String>,
        equivalent: impl Into<String>,
    ) {
        let object = object.into();
        self.0.push(Finding {
            id: format!("{kind}:{object}"),
            kind: kind.to_owned(),
            object,
            classification,
            phase: phase.to_owned(),
            reason: reason.into(),
            cratefield_equivalent: equivalent.into(),
        });
    }
}

/// Every finding, sorted by id.
#[must_use]
#[allow(clippy::too_many_lines)] // one block per section, in report order
pub(crate) fn findings(
    catalog: &Catalog,
    policies: &[Policy],
    storage: &Storage,
    auth: &Auth,
    edge: &EdgeFunctions,
) -> Vec<Finding> {
    let mut out = Findings(Vec::new());
    // Every `schema.table` that has at least one policy, so a table with RLS
    // enabled and none can be told apart from one that has them.
    let policed: BTreeSet<(&str, &str)> = catalog
        .policies
        .iter()
        .map(|policy| (policy.schema.as_str(), policy.table.as_str()))
        .collect();
    let user_schemas: Vec<&str> = catalog
        .schemas
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| !crate::collect::MANAGED_SCHEMAS.contains(name))
        .collect();

    for schema in &user_schemas {
        let target = target_schema(schema);
        if *schema == "app" && user_schemas.contains(&"public") {
            out.push(
                "schema",
                *schema,
                Blocker,
                "schema",
                "`public` is imported as `app`, and this project already has an `app` schema",
                "choose a new name for one of them before the schema phase",
            );
        } else {
            out.push(
                "schema",
                *schema,
                Automatic,
                "schema",
                "a user schema; owned by the venture, not tracked by harness migrations",
                format!("the Postgres schema `{target}` in the venture's database"),
            );
        }
    }

    for table in &catalog.tables {
        let object = format!("{}.{}", table.schema, table.name);
        let target = format!("{}.{}", target_schema(&table.schema), table.name);
        if table.primary_key.is_empty() {
            out.push(
                "table",
                &object,
                NeedsWork,
                "data",
                "no primary key: copied in one piece and checksummed over its sorted rows, so \
                 an interrupted copy restarts the table; add a key for chunked, resumable copy",
                target,
            );
        } else {
            out.push(
                "table",
                &object,
                Automatic,
                "data",
                "columns, constraints and indexes recreated; rows copied with COPY and verified \
                 by count and checksum",
                target,
            );
        }
        // RLS on with no policy denies every client by default. Nothing to
        // port: an informational fact, so it does not inflate needs work.
        if table.rls_enabled && !policed.contains(&(table.schema.as_str(), table.name.as_str())) {
            out.push(
                "rls_no_policy",
                &object,
                Automatic,
                "code",
                "RLS is enabled with no policy on the table, so every client request is denied; \
                 nothing reaches it but the server side",
                "service_role_only: only server-side module code touches it, expose no route",
            );
        }
        for constraint in &table.constraints {
            let Some(references) = &constraint.references else {
                continue;
            };
            let fk = format!("{object}.{}", constraint.name);
            if references == "auth.users" {
                out.push(
                    "foreign_key",
                    fk,
                    NeedsWork,
                    "schema",
                    "points into auth.users: dropped on load, its values kept and checked \
                     against the imported users in verify",
                    "the imported user's id, mapped through the auth-users step's id table",
                );
            } else if names_schema(references, "auth") || names_schema(references, "storage") {
                out.push(
                    "foreign_key",
                    fk,
                    Blocker,
                    "schema",
                    format!(
                        "points into {references}, which no phase recreates as a table (storage \
                         objects become R2 keys, auth rows become harness users)"
                    ),
                    "drop the constraint on the source or decide what the column holds after \
                     the move (an object key, a user id) before the schema phase",
                );
            }
        }
    }

    for view in &catalog.views {
        let object = format!("{}.{}", view.schema, view.name);
        let kind = if view.materialized {
            "materialized_view"
        } else {
            "view"
        };
        if view.references_auth || view.references_storage {
            out.push(
                kind,
                object,
                NeedsWork,
                "code",
                "reads auth.* or storage.*, which do not exist on the target; not copied",
                "a module query that takes the request's subject as a parameter",
            );
        } else {
            out.push(
                kind,
                &object,
                Automatic,
                "schema",
                "copied verbatim",
                format!("{}.{}", target_schema(&view.schema), view.name),
            );
        }
    }

    for sequence in &catalog.sequences {
        out.push(
            "sequence",
            format!("{}.{}", sequence.schema, sequence.name),
            Automatic,
            "schema",
            "recreated, and set to at least the source's value in verify",
            format!("{}.{}", target_schema(&sequence.schema), sequence.name),
        );
    }
    for enum_type in &catalog.enums {
        out.push(
            "enum",
            format!("{}.{}", enum_type.schema, enum_type.name),
            Automatic,
            "schema",
            "recreated with the same labels in the same order",
            format!("{}.{}", target_schema(&enum_type.schema), enum_type.name),
        );
    }

    for (name, _, _) in &catalog.extensions {
        let (support, why) = extensions::support(name);
        let (classification, equivalent) = match support {
            ExtensionSupport::Supported => (Automatic, "created on the target"),
            ExtensionSupport::SupabasePlatform if INERT_PLATFORM.contains(&name.as_str()) => {
                (Automatic, "nothing; not carried")
            }
            ExtensionSupport::SupabasePlatform => (NeedsWork, "not carried; see the reason"),
            ExtensionSupport::Unsupported => (Blocker, "none"),
            ExtensionSupport::Unknown => (NeedsWork, "the same extension, if the target has it"),
        };
        out.push("extension", name, classification, "schema", why, equivalent);
    }

    let mut function_by_name: BTreeMap<String, &crate::report::Function> = BTreeMap::new();
    for function in &catalog.functions {
        let object = format!(
            "{}.{}({})",
            function.schema, function.name, function.arguments
        );
        function_by_name.insert(format!("{}.{}", function.schema, function.name), function);
        let mut reasons = Vec::new();
        if function.references_auth {
            reasons.push("reads auth.* (auth.uid(), auth.jwt(), auth.users)");
        }
        if function.references_storage {
            reasons.push("reads storage.*");
        }
        if function.references_net {
            reasons.push("calls pg_net");
        }
        if function.security_definer {
            reasons.push("SECURITY DEFINER: it bypasses the caller's privileges");
        }
        if reasons.is_empty() {
            out.push(
                "function",
                object,
                Automatic,
                "schema",
                "copied verbatim, its search_path pinned to the target schema",
                format!("{}.{}", target_schema(&function.schema), function.name),
            );
        } else {
            out.push(
                "function",
                object,
                NeedsWork,
                "code",
                reasons.join("; "),
                "module code over the request's subject (and the `HttpClient` port for HTTP); \
                 or copy it once it no longer reaches into Supabase",
            );
        }
    }

    for trigger in &catalog.triggers {
        let object = format!("{}.{}.{}", trigger.schema, trigger.table, trigger.name);
        let on_supabase = matches!(trigger.schema.as_str(), "auth" | "storage");
        let webhook = trigger.function.starts_with("supabase_functions.");
        let reaches = function_by_name
            .get(&trigger.function)
            .is_some_and(|function| {
                function.references_auth || function.references_storage || function.references_net
            });
        if on_supabase {
            out.push(
                "trigger",
                object,
                NeedsWork,
                "code",
                format!(
                    "fires on {}.{}, which the harness replaces: it will never fire",
                    trigger.schema, trigger.table
                ),
                if trigger.schema == "auth" {
                    "a module reacting to the harness's account events (sign-up, deletion)"
                } else {
                    "a module route that writes the object through the Blob port and does the \
                     rest itself"
                },
            );
        } else if webhook {
            out.push(
                "trigger",
                object,
                NeedsWork,
                "code",
                "a Supabase database webhook",
                "an event from the module that owns the table, delivered by module-webhooks",
            );
        } else if reaches {
            out.push(
                "trigger",
                object,
                NeedsWork,
                "code",
                format!("its function {} reaches into Supabase", trigger.function),
                "rewrite the function first (see its finding), then the trigger copies",
            );
        } else {
            out.push(
                "trigger",
                object,
                Automatic,
                "schema",
                "copied verbatim with its function",
                format!("on {}.{}", target_schema(&trigger.schema), trigger.table),
            );
        }
    }

    for policy in policies {
        out.push(
            "policy",
            format!("{}.{}.{}", policy.schema, policy.table, policy.name),
            NeedsWork,
            "code",
            format!(
                "RLS is neither copied nor translated (ADR 0026); {} by {} at confidence {:.2}; \
                 needs a covered or waived disposition before cutover",
                serde_json::to_value(policy.pattern)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                match policy.source {
                    crate::report::PolicySource::Rule => "rule",
                    crate::report::PolicySource::Classifier => "classifier",
                },
                policy.confidence,
            ),
            policy.suggested_equivalent.clone(),
        );
    }

    for grants in &catalog.grants {
        let (classification, reason, equivalent) = if grants.role == "service_role" {
            (
                Automatic,
                "the server-side role; module code has the same reach",
                "module code",
            )
        } else {
            (
                NeedsWork,
                "a PostgREST role: the harness exposes no table directly, so what this role \
                 could reach is reachable only through a route someone writes",
                "a route per access path, with its check",
            )
        };
        out.push(
            "grant",
            format!("{} ({} tables)", grants.role, grants.tables.len()),
            classification,
            "code",
            reason,
            equivalent,
        );
    }

    auth_findings(&mut out, auth);

    storage_policy_findings(&mut out, storage);

    for bucket in &storage.buckets {
        let target = if bucket.public {
            "R2 under the same keys, served by a public route"
        } else {
            "R2 under the same keys"
        };
        if bucket.objects_over_blob_cap > 0 {
            out.push(
                "bucket",
                &bucket.id,
                NeedsWork,
                "storage",
                format!(
                    "{} object(s) over the Blob port's 10 MiB put cap: copied and readable, but \
                     module code cannot replace them through the port",
                    bucket.objects_over_blob_cap
                ),
                target,
            );
        } else {
            out.push(
                "bucket",
                &bucket.id,
                Automatic,
                "storage",
                "objects copied through the Storage API and verified by count, size and \
                 checksum",
                target,
            );
        }
    }

    match edge.status {
        SourceStatus::Inspected => {
            for function in &edge.functions {
                out.push(
                    "edge_function",
                    &function.slug,
                    NeedsWork,
                    "code",
                    "Deno code that runs on Supabase; not moved",
                    "a Worker route in a module",
                );
            }
        }
        SourceStatus::NotInspected | SourceStatus::Failed => out.push(
            "edge_function",
            "unknown",
            NeedsWork,
            "code",
            "Edge Functions are only visible through the Management API, which was not read: \
             unknown, not none",
            "re-run with a Management API token",
        ),
    }

    for publication in &catalog.publications {
        let realtime = publication.name == "supabase_realtime";
        if realtime && !publication.all_tables && publication.tables.is_empty() {
            out.push(
                "publication",
                &publication.name,
                Automatic,
                "code",
                "Realtime's publication, with no table in it: nothing to replace",
                "nothing",
            );
        } else if realtime {
            out.push(
                "publication",
                &publication.name,
                NeedsWork,
                "code",
                "Realtime streams changes to these tables to clients",
                "the `Realtime` port: a room the owning module broadcasts to after each write",
            );
        } else {
            out.push(
                "publication",
                &publication.name,
                NeedsWork,
                "code",
                "a logical-replication publication: its subscribers read the Supabase database",
                "repoint or retire its subscribers; the importer creates no publication",
            );
        }
    }

    for job in &catalog.cron_jobs {
        out.push(
            "cron_job",
            &job.name,
            NeedsWork,
            "code",
            format!("pg_cron job on `{}`", job.schedule),
            "a module's scheduled handler (ADR 0023)",
        );
    }

    let mut findings = out.0;
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings
}

/// One finding per storage policy, however many buckets it landed on. The
/// policy itself is on the bucket (`report.storage.buckets[].policies`) or,
/// with no buckets at all, in `report.storage.unattached_policies`.
fn storage_policy_findings(out: &mut Findings, storage: &Storage) {
    // Per policy: the bucket ids it landed on, whether it applies to all
    // buckets, and its suggested check.
    type Scope = (Vec<String>, bool, String);
    let mut groups: BTreeMap<(String, String), Scope> = BTreeMap::new();
    for bucket in &storage.buckets {
        for policy in &bucket.policies {
            record(&mut groups, policy, Some(&bucket.id));
        }
    }
    for policy in &storage.unattached_policies {
        record(&mut groups, policy, None);
    }

    for ((table, name), (mut buckets, all_buckets, suggested)) in groups {
        buckets.sort();
        buckets.dedup();
        let scope = if buckets.is_empty() {
            "no bucket exists in the project".to_owned()
        } else if all_buckets {
            "every bucket".to_owned()
        } else {
            format!(
                "bucket(s) {}",
                buckets
                    .iter()
                    .map(|id| format!("`{id}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        out.push(
            "storage_policy",
            format!("{table}.{name}"),
            NeedsWork,
            "storage",
            format!(
                "RLS is neither copied nor translated (ADR 0026); this policy applies to {scope} \
                 and needs a covered or waived disposition before cutover"
            ),
            suggested,
        );
    }
}

/// Folds one bucket's copy of a policy (or an unattached one) into the
/// per-policy group `groups`.
fn record(
    groups: &mut BTreeMap<(String, String), (Vec<String>, bool, String)>,
    policy: &BucketPolicy,
    bucket: Option<&str>,
) {
    let entry = groups
        .entry((policy.table.clone(), policy.name.clone()))
        .or_insert_with(|| (Vec::new(), false, policy.suggested_equivalent.clone()));
    if let Some(bucket) = bucket
        && !entry.0.iter().any(|id| id == bucket)
    {
        entry.0.push(bucket.to_owned());
    }
    entry.1 |= policy.all_buckets;
}

fn auth_findings(out: &mut Findings, auth: &Auth) {
    if !auth.present {
        return;
    }
    out.push(
        "auth",
        "users",
        Automatic,
        "auth",
        format!(
            "{} user(s): email, verified flag, bcrypt hash and created_at move through the \
             harness's user import; passwords keep working",
            auth.users
        ),
        "harness users (auth-password, auth-magic-link)",
    );
    let mut providers: Vec<String> = auth
        .identities_by_provider
        .iter()
        .map(|count| count.provider.clone())
        .collect();
    if let Some(enabled) = &auth.enabled_providers {
        providers.extend(enabled.iter().cloned());
    }
    providers.sort();
    providers.dedup();
    for provider in providers {
        let (classification, reason, equivalent) = match provider.as_str() {
            "email" => (
                Automatic,
                "email and password, or magic link".to_owned(),
                "auth-password and auth-magic-link".to_owned(),
            ),
            "google" | "apple" => (
                NeedsWork,
                format!("{provider} sign-in: identities map once the provider is configured"),
                format!("auth-oidc's `{provider}` provider"),
            ),
            "facebook" => (
                NeedsWork,
                "Facebook sign-in: identities map once the provider is configured".to_owned(),
                "auth-meta".to_owned(),
            ),
            "phone" => (
                NeedsWork,
                "phone (SMS) sign-in has no harness method".to_owned(),
                "magic link by email, or a new method".to_owned(),
            ),
            "saml" => (
                NeedsWork,
                "SAML SSO has no harness method".to_owned(),
                "an OIDC provider in front of the identity provider".to_owned(),
            ),
            other => (
                NeedsWork,
                format!("{other} sign-in has no harness provider"),
                "its users sign in by magic link until a provider is added".to_owned(),
            ),
        };
        out.push(
            "auth_provider",
            provider,
            classification,
            "auth",
            reason,
            equivalent,
        );
    }
    for (count, object, reason, equivalent) in [
        (
            auth.anonymous_users,
            "anonymous_users",
            "anonymous users have no email to sign back in with",
            "drop them, or keep their data under a placeholder account",
        ),
        (
            auth.mfa_factors,
            "mfa_factors",
            "MFA factors are not imported; enrolled users lose their second factor",
            "re-enrolment (passkeys, auth-passkeys) after the move",
        ),
        (
            auth.sso_providers,
            "sso_providers",
            "SSO providers are not imported",
            "an OIDC provider per identity provider",
        ),
    ] {
        if count > 0 {
            out.push("auth", object, NeedsWork, "auth", reason, equivalent);
        }
    }
}
