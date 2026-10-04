//! `cratefield-import-supabase`: step one of moving a Supabase project onto
//! the harness (ADR 0026, issue #658). [`inspect`] connects read-only to the
//! project's Postgres — plus, optionally, the Supabase Management API for
//! what Postgres cannot see — and returns a [`Report`]: every schema object,
//! RLS policy, auth provider, storage bucket, Edge Function and Realtime
//! publication, each classified as automatic, needs work or a blocker, with
//! a size and transfer-time estimate.
//!
//! It never writes. The later steps (auth users, schema and data, storage,
//! cutover) read the report's JSON; `docs/import/supabase-report.md`
//! documents it.
//!
//! Step two (issue #659) is [`read_users`]: the same read-only snapshot,
//! but rows — the auth users as the admin import contract, plus the map
//! [`record_mapping`] writes so the data step can rewrite their references.
//!
//! ```no_run
//! # async fn demo() -> Result<(), cratefield_import_supabase::InspectError> {
//! use cratefield_import_supabase::{InspectOptions, Secret, inspect};
//!
//! let options = InspectOptions::new("abcdefghijklmnopqrst", Secret::new(std::env::var("SUPABASE_DB_URL").unwrap()));
//! let report = inspect(&options).await?;
//! println!("{}", report.to_markdown());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

// Native only: the sqlx driver does not compile to wasm, and an importer is
// an operator's command, never something a Worker serves.
// `no_wasm_package_can_reach_a_native_only_crate` in
// `crates/cli-acceptance/tests/native_only_off_wasm.rs` finds this crate by
// the guard below.
#[cfg(any(target_arch = "wasm32", target_arch = "wasm64"))]
compile_error!(
    "cratefield-import-supabase is native-only: it reads Postgres through sqlx, which does not \
     compile to wasm (ADR 0026). Run it from the fz CLI, never from a Worker."
);

mod classify;
mod collect;
pub mod dispositions;
pub mod extensions;
pub mod management;
mod markdown;
pub mod plan;
pub mod policy;
pub mod report;
mod secret;
mod session;
mod storage_policy;
mod visibility;
mod users;

use std::sync::Arc;

use cratefield_core::Classifier;

pub use dispositions::{
    DispositionsError, DispositionsFile, apply as apply_dispositions, skeleton,
};
pub use management::{AuthConfig, DEFAULT_API_BASE, ManagementApi, ManagementError};
pub use plan::{
    PLAN_VERSION, Plan, PlanBlocker, PlanDrift, TargetFacts, build_plan, check_drift,
    inspection_hash, read_target,
};
pub use report::*;
pub use secret::{Secret, SourceName, source_name};
pub use session::{InspectError, ReadOnlySession};
pub use users::{
    DEFAULT_BATCH_SIZE, EXTERNAL_PROVIDER, ImportIdentity, ImportPlan, ImportRecord, MappedUser,
    MappingCounts, MappingError, SkipReason, SkippedUser, UnmappedProvider, UserMetadata,
    UsersOptions, connect_mapping, read_users, record_mapping,
};

/// The throughput the transfer estimate assumes when none is given, in
/// megabits per second.
pub const DEFAULT_TRANSFER_MBPS: u32 = 100;

/// What [`inspect`] needs.
pub struct InspectOptions {
    /// The Supabase project ref.
    pub project_ref: String,
    /// The database URL, ideally for the read-only role.
    pub db_url: Secret,
    /// The Management API, when a token was given.
    pub management: Option<ManagementApi>,
    /// The classifier asked about policies no rule placed. `None` leaves
    /// them `needs_review`.
    pub classifier: Option<Arc<dyn Classifier>>,
    /// The confidence a classifier answer needs (per adapter; see
    /// [`policy`]).
    pub classify_threshold: f32,
    /// The transfer estimate's throughput.
    pub transfer_mbps: u32,
}

impl InspectOptions {
    /// Options with no Management API, no classifier, the default
    /// threshold and throughput.
    #[must_use]
    pub fn new(project_ref: impl Into<String>, db_url: Secret) -> Self {
        Self {
            project_ref: project_ref.into(),
            db_url,
            management: None,
            classifier: None,
            classify_threshold: policy::DEFAULT_THRESHOLD,
            transfer_mbps: DEFAULT_TRANSFER_MBPS,
        }
    }
}

/// A project ref is lower-case letters and digits: it goes into a URL path.
///
/// # Errors
///
/// The refusal, when it is not one.
pub fn validate_project_ref(project_ref: &str) -> Result<(), String> {
    let ok = !project_ref.is_empty()
        && project_ref.len() <= 64
        && project_ref
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{project_ref:?} is not a Supabase project ref (lower-case letters and digits, as in \
             the project URL https://<ref>.supabase.co)"
        ))
    }
}

/// Inspects the project. Read-only throughout; see [`ReadOnlySession`].
///
/// # Errors
///
/// [`InspectError`] when the database cannot be reached or read, or the
/// Management API refuses the token. A blocker is never an error: it is in
/// the report.
#[allow(clippy::too_many_lines)] // the report, assembled in field order
pub async fn inspect(options: &InspectOptions) -> Result<Report, InspectError> {
    validate_project_ref(&options.project_ref).map_err(InspectError::InvalidInput)?;
    let source = source_name(&options.db_url).map_err(InspectError::InvalidInput)?;
    if !(0.0..=1.0).contains(&options.classify_threshold) {
        return Err(InspectError::InvalidInput(
            "the classifier threshold must be between 0 and 1".to_owned(),
        ));
    }

    let mut session = ReadOnlySession::open(&options.db_url).await?;
    let catalog = collect::read(&mut session).await?;
    let no_transaction_id_assigned = session.finish().await?;
    let mut warnings = catalog.warnings.clone();

    // The Management API, for what Postgres cannot see.
    let mut auth = catalog.auth.clone();
    let mut edge = EdgeFunctions {
        status: SourceStatus::NotInspected,
        functions: Vec::new(),
    };
    let mut management_status = SourceStatus::NotInspected;
    if let Some(api) = &options.management {
        management_status = SourceStatus::Inspected;
        match api.edge_functions(&options.project_ref).await {
            Ok(functions) => {
                edge = EdgeFunctions {
                    status: SourceStatus::Inspected,
                    functions,
                };
            }
            Err(ManagementError::Unauthorized(status)) => {
                return Err(InspectError::ManagementUnauthorized(
                    ManagementError::Unauthorized(status).to_string(),
                ));
            }
            Err(error) => {
                management_status = SourceStatus::Failed;
                edge.status = SourceStatus::Failed;
                warnings.push(format!("Edge Functions not listed: {error}"));
            }
        }
        match api.auth_config(&options.project_ref).await {
            Ok(config) => {
                auth.enabled_providers = Some(config.providers);
                auth.enabled_mfa = Some(config.mfa);
            }
            Err(ManagementError::Unauthorized(status)) => {
                return Err(InspectError::ManagementUnauthorized(
                    ManagementError::Unauthorized(status).to_string(),
                ));
            }
            Err(error) => {
                management_status = SourceStatus::Failed;
                warnings.push(format!("auth configuration not read: {error}"));
            }
        }
    }

    // Policies: rules, then the classifier for the rest.
    let mut classifier = options.classifier.as_deref();
    let mut classifier_status = if classifier.is_some() {
        SourceStatus::Inspected
    } else {
        SourceStatus::NotInspected
    };
    let mut policies = Vec::with_capacity(catalog.policies.len());
    let mut managed_policies: Vec<ManagedPolicy> = Vec::new();
    let mut storage_policies: Vec<collect::RawPolicy> = Vec::new();
    for raw in &catalog.policies {
        // Policies on Supabase-managed schemas are the platform's, not the
        // venture's: listed for audit, never classified, never a finding.
        // The two storage tables are handled by the storage phase instead.
        if collect::MANAGED_SCHEMAS.contains(&raw.schema.as_str()) {
            if storage_policy::is_bucket_table(&raw.schema, &raw.table) {
                storage_policies.push(raw.clone());
            } else {
                managed_policies.push(ManagedPolicy {
                    schema: raw.schema.clone(),
                    table: raw.table.clone(),
                    name: raw.name.clone(),
                    command: raw.command.clone(),
                    roles: raw.roles.clone(),
                    using: raw.using.clone(),
                    with_check: raw.with_check.clone(),
                });
            }
            continue;
        }
        let table = format!("{}.{}", raw.schema, raw.table);
        let input = policy::PolicyInput {
            table: &table,
            columns: &raw.columns,
            command: &raw.command,
            roles: &raw.roles,
            permissive: raw.permissive,
            using: raw.using.as_deref(),
            with_check: raw.with_check.as_deref(),
        };
        let placement = match policy::place(&input, classifier, options.classify_threshold).await {
            Ok(placement) => placement,
            Err(error) => {
                // One failure ends the classifier's part: the rest of the
                // policies are placed by rule alone.
                warnings.push(format!(
                    "the policy classifier failed, so unplaced policies stay needs_review: \
                     {error}"
                ));
                classifier = None;
                classifier_status = SourceStatus::Failed;
                policy::place(&input, None, options.classify_threshold)
                    .await
                    .unwrap_or_else(|_| unreachable!("rules alone never fail"))
            }
        };
        let test_stub = policy::test_stub(&input, &raw.name, &placement.suggested_equivalent);
        policies.push(Policy {
            schema: raw.schema.clone(),
            table: raw.table.clone(),
            name: raw.name.clone(),
            command: raw.command.clone(),
            permissive: raw.permissive,
            roles: raw.roles.clone(),
            using: raw.using.clone(),
            with_check: raw.with_check.clone(),
            pattern: placement.pattern,
            confidence: placement.confidence,
            source: placement.source,
            classifier_label: placement.classifier_label,
            suggested_equivalent: placement.suggested_equivalent,
            test_stub,
            disposition: Disposition::Undecided,
        });
    }

    // Storage policies on `storage.objects`/`storage.buckets` go with the
    // bucket they name; ones on any other `storage` table stayed managed.
    let mut storage = catalog.storage.clone();
    storage_policy::attach(&mut storage, &storage_policies);

    let role_can_write = catalog.role_can_write;
    if catalog.role_is_superuser {
        warnings.push(format!(
            "inspected as the superuser `{}`: the session was read-only, but use the read-only \
             role from docs/import/supabase.md for the real run",
            catalog.role
        ));
    } else if role_can_write {
        warnings.push(format!(
            "the role `{}` holds write privileges: the session was read-only, but a role that \
             cannot write is the second guard (docs/import/supabase.md)",
            catalog.role
        ));
    }

    let findings = classify::findings(&catalog, &policies, &storage, &auth, &edge);
    let count = |class: Classification| {
        findings
            .iter()
            .filter(|finding| finding.classification == class)
            .count()
    };
    let data_bytes: u64 = catalog.tables.iter().map(|table| table.data_bytes).sum();
    // `None` when the storage section is not visible: a sum over hidden
    // buckets would be a wrong fact, not a small one.
    let storage_objects: Option<u64> = storage
        .buckets
        .as_ref()
        .and_then(|buckets| buckets.iter().map(|bucket| bucket.objects).sum());
    let storage_bytes: Option<u64> = storage
        .buckets
        .as_ref()
        .and_then(|buckets| buckets.iter().map(|bucket| bucket.bytes).sum());
    let mbps = u64::from(options.transfer_mbps.max(1));
    // The estimate is data-only when storage is not visible: adding a zero
    // would silently understate it, so the Markdown says so instead (the
    // JSON keeps its shape).
    let bits = (data_bytes + storage_bytes.unwrap_or(0)).saturating_mul(8);
    let summary = Summary {
        automatic: count(Classification::Automatic),
        needs_work: count(Classification::NeedsWork),
        blockers: count(Classification::Blocker),
        // Both counts are set by `dispositions::apply` below.
        decided: 0,
        undecided: 0,
        ready: count(Classification::Blocker) == 0,
        tables: catalog.tables.len(),
        estimated_rows: catalog
            .tables
            .iter()
            .filter_map(|table| table.estimated_rows)
            .sum(),
        data_bytes,
        index_bytes: catalog.tables.iter().map(|table| table.index_bytes).sum(),
        storage_objects,
        storage_bytes,
        transfer_assumed_mbps: options.transfer_mbps.max(1),
        estimated_transfer_seconds: bits.div_ceil(mbps * 1_000_000),
    };

    let schemas = catalog
        .schemas
        .iter()
        .map(|(name, tables)| {
            let managed = collect::MANAGED_SCHEMAS.contains(&name.as_str());
            Schema {
                name: name.clone(),
                kind: if managed {
                    SchemaKind::SupabaseManaged
                } else {
                    SchemaKind::User
                },
                target: (!managed).then(|| classify::target_schema(name)),
                tables: *tables,
            }
        })
        .collect();

    warnings.sort();
    warnings.dedup();
    let mut report = Report {
        report_version: REPORT_VERSION,
        tool: Tool {
            name: env!("CARGO_PKG_NAME").to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        project: Project {
            project_ref: options.project_ref.clone(),
            host: source.host,
            port: source.port,
            database: source.database,
            server_version: catalog.server_version.clone(),
        },
        read_only: ReadOnlyEvidence {
            transaction_read_only: catalog.transaction_read_only,
            session_read_only: catalog.session_read_only,
            no_transaction_id_assigned,
            role: catalog.role.clone(),
            role_is_superuser: catalog.role_is_superuser,
            role_can_write,
        },
        coverage: Coverage {
            database: SourceStatus::Inspected,
            management_api: management_status,
            policy_classifier: classifier_status,
            sections: catalog.visibility.sections.clone(),
        },
        summary,
        // Set just below, with an empty file: without a dispositions file
        // every needs-work and blocker item is undecided.
        dispositions: DispositionsReport::default(),
        schemas,
        tables: catalog.tables.clone(),
        views: catalog.views.clone(),
        sequences: catalog.sequences.clone(),
        enums: catalog.enums.clone(),
        extensions: catalog
            .extensions
            .iter()
            .map(|(name, version, schema)| Extension {
                support: extensions::support(name).0,
                name: name.clone(),
                version: version.clone(),
                schema: schema.clone(),
            })
            .collect(),
        functions: catalog.functions.clone(),
        triggers: catalog.triggers.clone(),
        policies,
        managed_policies,
        api_role_grants: catalog.grants.clone(),
        auth,
        storage,
        edge_functions: edge,
        realtime: Realtime {
            publications: catalog.publications.clone(),
        },
        cron_jobs: catalog.cron_jobs.clone(),
        findings,
        warnings,
    };
    dispositions::apply(&mut report, &DispositionsFile::default());
    Ok(report)
}
