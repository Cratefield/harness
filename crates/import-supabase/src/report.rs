//! The migration report: what inspect saw, and what each item needs.
//!
//! The JSON rendering of [`Report`] is the contract the later importer
//! steps (#659, #660, #661) and the dashboard read, documented field by
//! field in `docs/import/supabase-report.md`. Its rules:
//!
//! - [`REPORT_VERSION`] changes whenever a field is removed, renamed or
//!   changes meaning. Adding a field does not change it; a reader ignores
//!   fields it does not know.
//! - Every list is sorted (by schema, then name, then whatever else makes
//!   the key unique), so two inspections of the same project render the
//!   same bytes. There is no timestamp in the report.
//! - Nothing secret is in it: no credential, no password hash, no email,
//!   no row data. The connection is named by host, port and database only,
//!   and every free-text SQL fragment has passed through `scrub_text`.

use serde::{Deserialize, Serialize};

/// The version of the report's JSON shape. See the module docs for when it
/// changes.
pub const REPORT_VERSION: u32 = 1;

/// The whole report. Field order is the JSON's key order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// [`REPORT_VERSION`] at the time this report was written.
    pub report_version: u32,
    /// Which tool wrote it.
    pub tool: Tool,
    /// The project, named without credentials.
    pub project: Project,
    /// The evidence that the inspection could not write.
    pub read_only: ReadOnlyEvidence,
    /// What was inspected and what could not be.
    pub coverage: Coverage,
    /// Totals, counts per classification and the transfer estimate.
    pub summary: Summary,
    /// Every non-system schema, Supabase-managed ones included.
    pub schemas: Vec<Schema>,
    /// Tables in the user schemas (never `auth`, `storage` or another
    /// Supabase-managed schema: those have their own sections).
    pub tables: Vec<Table>,
    /// Views and materialized views in the user schemas.
    pub views: Vec<View>,
    /// Sequences in the user schemas.
    pub sequences: Vec<Sequence>,
    /// Enum types in the user schemas.
    pub enums: Vec<EnumType>,
    /// Every installed extension, with its support status.
    pub extensions: Vec<Extension>,
    /// Functions in the user schemas, excluding extension members.
    pub functions: Vec<Function>,
    /// Triggers on user tables, and user-defined triggers on `auth` and
    /// `storage` tables.
    pub triggers: Vec<Trigger>,
    /// Every row-level-security policy outside the system catalogs.
    pub policies: Vec<Policy>,
    /// Table grants to Supabase's API roles, one entry per role.
    pub api_role_grants: Vec<RoleGrants>,
    /// Supabase Auth: counts and providers, never a user.
    pub auth: Auth,
    /// Supabase Storage buckets.
    pub storage: Storage,
    /// Edge Functions (Management API only).
    pub edge_functions: EdgeFunctions,
    /// Logical-replication publications, which is what Realtime reads.
    pub realtime: Realtime,
    /// `pg_cron` jobs.
    pub cron_jobs: Vec<CronJob>,
    /// Every item classified: automatic, needs work, or a blocker.
    pub findings: Vec<Finding>,
    /// Things the reader should know that are not findings: a role that
    /// could write, counts RLS may have hidden, a Management API call that
    /// failed.
    pub warnings: Vec<String>,
}

/// The tool that wrote a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    /// The crate name.
    pub name: String,
    /// The crate version.
    pub version: String,
}

/// The project, named without credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    /// The Supabase project ref.
    #[serde(rename = "ref")]
    pub project_ref: String,
    /// The database host. Never a user name or password.
    pub host: String,
    /// The database port.
    pub port: u16,
    /// The database name.
    pub database: String,
    /// `server_version` as the server reports it.
    pub server_version: String,
}

/// How the inspection was kept from writing, as observed — not as
/// intended.
// Independent observations, each its own yes or no in the JSON.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadOnlyEvidence {
    /// The reads ran in a `READ ONLY` transaction
    /// (`transaction_read_only` read back inside it).
    pub transaction_read_only: bool,
    /// The session default was read-only too
    /// (`default_transaction_read_only`).
    pub session_read_only: bool,
    /// No transaction id was ever assigned (`txid_current_if_assigned()`
    /// was null at the end), which a write would have forced.
    pub no_transaction_id_assigned: bool,
    /// The role inspect connected as.
    pub role: String,
    /// The role is a superuser.
    pub role_is_superuser: bool,
    /// The role holds a write privilege — `INSERT`, `UPDATE`, `DELETE`,
    /// `TRUNCATE` on a user table, or `CREATE` on a user schema. The
    /// documented read-only role has none.
    pub role_can_write: bool,
}

/// What each source of facts contributed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Always `inspected`: without the database there is no report.
    pub database: SourceStatus,
    /// The Supabase Management API: `not_inspected` without a token.
    pub management_api: SourceStatus,
    /// The RLS classifier: `not_inspected` unless one was configured.
    pub policy_classifier: SourceStatus,
}

/// Whether a source was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    /// Read in full.
    Inspected,
    /// Not read, because nothing to read it with was given. Absence of
    /// data from it means "unknown", never "none".
    NotInspected,
    /// Tried and failed; the warnings say why.
    Failed,
}

/// Totals and the rough transfer estimate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    /// Findings classified automatic.
    pub automatic: usize,
    /// Findings classified needs work.
    pub needs_work: usize,
    /// Findings classified blocker.
    pub blockers: usize,
    /// No blockers: the later steps can run once the needs-work items have
    /// a disposition.
    pub ready: bool,
    /// User tables.
    pub tables: usize,
    /// Sum of the tables' planner row estimates.
    pub estimated_rows: u64,
    /// Heap and TOAST bytes of the user tables — what the data phase moves.
    pub data_bytes: u64,
    /// Index bytes of the user tables, rebuilt on the target rather than
    /// moved.
    pub index_bytes: u64,
    /// Storage objects.
    pub storage_objects: u64,
    /// Storage bytes, from each object's recorded size.
    pub storage_bytes: u64,
    /// The throughput the estimate assumes, in megabits per second.
    pub transfer_assumed_mbps: u32,
    /// `(data_bytes + storage_bytes)` at that throughput, rounded up, plus
    /// nothing else: index builds, validation and verification are not in
    /// it. A rough guide, not a promise.
    pub estimated_transfer_seconds: u64,
}

/// A schema and whether it is the user's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    /// The schema name.
    pub name: String,
    /// `user` or `supabase_managed`.
    pub kind: SchemaKind,
    /// Where the importer puts it: `app` for `public`, the same name for
    /// another user schema, `null` for a Supabase-managed one.
    pub target: Option<String>,
    /// Ordinary and partitioned tables in it.
    pub tables: usize,
}

/// Whose schema it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaKind {
    /// The project's own; copied.
    User,
    /// Supabase's (auth, storage, realtime, extensions, …); never copied
    /// as a schema.
    SupabaseManaged,
}

/// A user table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    /// Its schema.
    pub schema: String,
    /// Its name.
    pub name: String,
    /// `table` or `partitioned_table`.
    pub kind: String,
    /// The planner's estimate (`pg_class.reltuples`); `null` when the
    /// table has never been analyzed.
    pub estimated_rows: Option<u64>,
    /// Heap and TOAST bytes.
    pub data_bytes: u64,
    /// Index bytes.
    pub index_bytes: u64,
    /// Row-level security is enabled.
    pub rls_enabled: bool,
    /// Row-level security is forced on the owner too.
    pub rls_forced: bool,
    /// The primary key's columns, in key order; empty when it has none.
    pub primary_key: Vec<String>,
    /// Columns in ordinal order.
    pub columns: Vec<Column>,
    /// Constraints, by name.
    pub constraints: Vec<Constraint>,
    /// Indexes, by name.
    pub indexes: Vec<Index>,
}

/// A column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Column {
    /// Its name.
    pub name: String,
    /// `format_type` of its type.
    pub data_type: String,
    /// It accepts null.
    pub nullable: bool,
    /// Its default expression, scrubbed.
    pub default: Option<String>,
    /// `always` or `by_default` for an identity column.
    pub identity: Option<String>,
    /// The expression of a stored generated column, scrubbed.
    pub generated: Option<String>,
}

/// A table constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    /// Its name.
    pub name: String,
    /// `primary_key`, `foreign_key`, `unique`, `check`, `exclusion` or
    /// `trigger`.
    pub kind: String,
    /// `pg_get_constraintdef`, scrubbed.
    pub definition: String,
    /// The referenced table of a foreign key, as `schema.table`.
    pub references: Option<String>,
}

/// An index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    /// Its name.
    pub name: String,
    /// It is unique.
    pub unique: bool,
    /// It backs the primary key.
    pub primary: bool,
    /// `pg_get_indexdef`.
    pub definition: String,
}

/// A view or materialized view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct View {
    /// Its schema.
    pub schema: String,
    /// Its name.
    pub name: String,
    /// It is a materialized view.
    pub materialized: bool,
    /// Its definition names `auth.`.
    pub references_auth: bool,
    /// Its definition names `storage.`.
    pub references_storage: bool,
}

/// A sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sequence {
    /// Its schema.
    pub schema: String,
    /// Its name.
    pub name: String,
    /// `table.column` of the column that owns it, if one does.
    pub owned_by: Option<String>,
    /// Its data type.
    pub data_type: String,
}

/// An enum type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumType {
    /// Its schema.
    pub schema: String,
    /// Its name.
    pub name: String,
    /// Its labels, in sort order.
    pub labels: Vec<String>,
}

/// An installed extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    /// Its name.
    pub name: String,
    /// The installed version.
    pub version: String,
    /// The schema it is installed in.
    pub schema: String,
    /// What the harness can do with it.
    pub support: ExtensionSupport,
}

/// What the harness Postgres target can do with an extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionSupport {
    /// Created on the target before the schema; nothing to do.
    Supported,
    /// Part of the Supabase platform; not carried over. What used it
    /// needs a harness equivalent.
    SupabasePlatform,
    /// No harness equivalent and no way to carry it: a blocker.
    Unsupported,
    /// Not on the support list: the target may or may not have it.
    Unknown,
}

/// A user function.
// Independent facts about one function, each its own field in the JSON.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Function {
    /// Its schema.
    pub schema: String,
    /// Its name.
    pub name: String,
    /// `pg_get_function_identity_arguments`.
    pub arguments: String,
    /// `function`, `procedure`, `aggregate` or `window`.
    pub kind: String,
    /// Its language.
    pub language: String,
    /// Its result type.
    pub returns: String,
    /// It runs as its owner.
    pub security_definer: bool,
    /// Its body names `auth.`.
    pub references_auth: bool,
    /// Its body names `storage.`.
    pub references_storage: bool,
    /// Its body calls `pg_net` (`net.http_…`).
    pub references_net: bool,
}

/// A trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trigger {
    /// The schema of its table.
    pub schema: String,
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// The function it runs, as `schema.name`.
    pub function: String,
    /// `pg_get_triggerdef`.
    pub definition: String,
    /// It is enabled.
    pub enabled: bool,
}

/// A row-level-security policy, with what inspect made of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// The schema of its table.
    pub schema: String,
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// `ALL`, `SELECT`, `INSERT`, `UPDATE` or `DELETE`.
    pub command: String,
    /// Permissive (true) or restrictive.
    pub permissive: bool,
    /// The roles it applies to, sorted.
    pub roles: Vec<String>,
    /// The `USING` expression, scrubbed.
    pub using: Option<String>,
    /// The `WITH CHECK` expression, scrubbed.
    pub with_check: Option<String>,
    /// What the policy amounts to.
    pub pattern: PolicyPattern,
    /// How sure: 1.0 for a rule match, the classifier's confidence for a
    /// classifier answer, 0.0 for an unplaced policy.
    pub confidence: f32,
    /// Who placed it.
    pub source: PolicySource,
    /// The label the classifier answered when it was below the threshold
    /// (the policy is then `needs_review`); `null` otherwise.
    pub classifier_label: Option<String>,
    /// The check to write in code, as advice: ADR 0026 rejects
    /// translating RLS automatically, so this is never enforcement code.
    pub suggested_equivalent: String,
    /// A failing (`todo!()`) Rust test stub naming the policy and its
    /// expression, for the venture to turn into the test that proves its
    /// replacement check. Written into the run directory, never into the
    /// venture's source tree.
    pub test_stub: String,
    /// Always `undecided` in an inspect report: before cutover each
    /// policy needs its own `covered` (with a reference to the code or
    /// test) or `waived` (with a reason) — never in bulk (ADR 0026,
    /// Decision 5).
    pub disposition: Disposition,
}

/// The decision a reported item needs before cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Nobody has decided yet: cutover refuses.
    Undecided,
    /// Code and a test now do what the item did.
    Covered,
    /// Deliberately not replaced, with a reason.
    Waived,
}

/// The access pattern a policy expresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPattern {
    /// A row belongs to one user: `auth.uid() = owner_column`.
    OwnerOnly,
    /// A row belongs to a team, organisation or tenant the user is a
    /// member of, through a membership lookup.
    TenantScoped,
    /// Everyone may read: `USING (true)` on a read.
    PublicRead,
    /// Everyone may write: `true` on a write.
    PublicWrite,
    /// A role or JWT claim decides: `auth.role()`, `auth.jwt()`, or `true`
    /// for `authenticated` only.
    RoleBased,
    /// Only the service role: no client ever passes it.
    ServiceRoleOnly,
    /// The classifier judged it bespoke logic.
    CustomLogic,
    /// Not placed by a rule, and either no classifier was configured or
    /// its answer was below the threshold. A person reads it.
    NeedsReview,
}

/// Who placed a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySource {
    /// A deterministic rule (or no rule matched and no classifier ran).
    Rule,
    /// The configured `Classifier`.
    Classifier,
}

/// Table privileges granted to one of Supabase's API roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleGrants {
    /// `anon`, `authenticated` or `service_role`.
    pub role: String,
    /// `schema.table` of every user table it holds a privilege on.
    pub tables: Vec<String>,
}

/// Supabase Auth, as counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auth {
    /// The `auth` schema exists.
    pub present: bool,
    /// Rows in `auth.users`.
    pub users: u64,
    /// Users with no password (OAuth, magic link or phone only).
    pub users_without_password: u64,
    /// Users whose email is not confirmed.
    pub users_unconfirmed: u64,
    /// Anonymous users (`is_anonymous`), when the column exists.
    pub anonymous_users: u64,
    /// `auth.identities` rows per provider, sorted by provider.
    pub identities_by_provider: Vec<ProviderCount>,
    /// MFA factors enrolled (`auth.mfa_factors`), when the table exists.
    pub mfa_factors: u64,
    /// SSO providers (`auth.sso_providers`), when the table exists.
    pub sso_providers: u64,
    /// The providers the project's auth configuration enables, from the
    /// Management API. `null` when it was not inspected.
    pub enabled_providers: Option<Vec<String>>,
    /// MFA methods the configuration enables, from the Management API.
    /// `null` when it was not inspected.
    pub enabled_mfa: Option<Vec<String>>,
}

/// Identities of one provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCount {
    /// The provider name (`email`, `google`, `github`, …).
    pub provider: String,
    /// Identities with it.
    pub identities: u64,
}

/// Supabase Storage.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Storage {
    /// The `storage` schema exists.
    pub present: bool,
    /// The object counts are exact: false when `storage.objects` has RLS
    /// and the inspecting role cannot bypass it, so a count may be low.
    pub counts_exact: bool,
    /// Buckets, by id.
    pub buckets: Vec<Bucket>,
}

/// A bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    /// Its id.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Objects are readable without a token.
    pub public: bool,
    /// The per-object size limit, in bytes.
    pub file_size_limit: Option<u64>,
    /// The allowed MIME types, sorted.
    pub allowed_mime_types: Vec<String>,
    /// Objects in it.
    pub objects: u64,
    /// The sum of their recorded sizes.
    pub bytes: u64,
    /// Objects over the Blob port's 10 MiB put cap.
    pub objects_over_blob_cap: u64,
}

/// Edge Functions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeFunctions {
    /// Whether the list was read; `not_inspected` means "unknown", never
    /// "none".
    pub status: SourceStatus,
    /// The functions, by slug.
    pub functions: Vec<EdgeFunction>,
}

/// An Edge Function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeFunction {
    /// Its slug.
    pub slug: String,
    /// Its name.
    pub name: String,
    /// `ACTIVE`, `REMOVED` or `THROTTLED`.
    pub status: String,
    /// It requires a Supabase JWT.
    pub verify_jwt: Option<bool>,
}

/// Realtime publications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Realtime {
    /// Publications, by name.
    pub publications: Vec<Publication>,
}

/// A publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Publication {
    /// Its name (`supabase_realtime` is Realtime's).
    pub name: String,
    /// It publishes every table.
    pub all_tables: bool,
    /// The operations it publishes, sorted.
    pub operations: Vec<String>,
    /// `schema.table` of every table it publishes, sorted.
    pub tables: Vec<String>,
}

/// A `pg_cron` job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronJob {
    /// Its name, or `job-<id>` when it has none.
    pub name: String,
    /// Its cron schedule.
    pub schedule: String,
    /// Its command, scrubbed.
    pub command: String,
    /// It is active.
    pub active: bool,
}

/// One classified item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// A stable id: `<kind>:<qualified name>`. Sorting is by this id.
    pub id: String,
    /// What kind of object it is (`table`, `policy`, `extension`, …).
    pub kind: String,
    /// The object's qualified name.
    pub object: String,
    /// What the importer can do with it.
    pub classification: Classification,
    /// The importer phase that handles it (`schema`, `data`, `auth`,
    /// `storage`) or `code` when the venture's own code has to.
    pub phase: String,
    /// Why it is classified so.
    pub reason: String,
    /// What it becomes on Cratefield.
    pub cratefield_equivalent: String,
}

/// What the importer can do with an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Moved by the importer with nothing to decide.
    Automatic,
    /// Moved or reported, but the venture has to write or decide
    /// something: each needs a disposition before cutover (ADR 0026,
    /// Decision 5).
    NeedsWork,
    /// The importer cannot proceed until it is resolved.
    Blocker,
}

impl Classification {
    /// The label the Markdown report uses.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::NeedsWork => "needs work",
            Self::Blocker => "blocker",
        }
    }
}

impl Report {
    /// The report as pretty-printed JSON, with a trailing newline.
    ///
    /// # Panics
    ///
    /// Never: every field serializes.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = serde_json::to_string_pretty(self).expect("a report always serializes");
        out.push('\n');
        out
    }
}
