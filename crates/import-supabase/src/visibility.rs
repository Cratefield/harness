//! The privilege preflight: what the inspecting role can actually see.
//!
//! Inspect reads rows through `count(*)` and `sum(...)` (issue #723). A role
//! that lacks `USAGE` or `SELECT`, or is stopped by row-level security, used
//! to report the resulting zero as a fact or abort on `permission denied`.
//! So this module asks the catalogs by OID (never by name: no `to_regclass`)
//! before any row is read, and reports what the role cannot see as
//! `not_visible` (unknown, never zero) with the SQL that fixes it; the
//! collector skips that read. [`rows_visible`] is pure, tested without a
//! database.

use std::collections::{BTreeMap, BTreeSet};

use crate::report::{SectionCoverage, SourceStatus};
use crate::session::{InspectError, ReadOnlySession};

/// The `(schema, table)` pairs inspect reads rows from, as the query scope.
const ROW_READ_PAIRS: &str = "('auth', 'users'), ('auth', 'identities'), ('auth', 'mfa_factors'), \
     ('auth', 'sso_providers'), ('storage', 'buckets'), ('storage', 'objects'), ('cron', 'job')";

/// The row-read tables behind each fixed section.
const AUTH_TABLES: &[(&str, &str)] = &[
    ("auth", "users"),
    ("auth", "identities"),
    ("auth", "mfa_factors"),
    ("auth", "sso_providers"),
];
const STORAGE_BUCKETS: &[(&str, &str)] = &[("storage", "buckets")];
const STORAGE_OBJECTS: &[(&str, &str)] = &[("storage", "objects")];
const CRON_JOBS: &[(&str, &str)] = &[("cron", "job")];

/// How much the inspecting role may bypass row-level security.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RoleFlags {
    /// `pg_roles.rolsuper`.
    pub(crate) superuser: bool,
    /// `pg_roles.rolbypassrls`.
    pub(crate) bypassrls: bool,
}

/// Everything the preflight read about one table; one flag per fact, as
/// elsewhere in the crate.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TableAccess {
    /// The relation exists (ordinary or partitioned table).
    pub(crate) exists: bool,
    /// `has_schema_privilege(..., 'USAGE')` on its schema.
    pub(crate) schema_usage: bool,
    /// `has_table_privilege(..., 'SELECT')`.
    pub(crate) select: bool,
    /// `pg_class.relrowsecurity`.
    pub(crate) rls: bool,
    /// `pg_class.relforcerowsecurity`.
    pub(crate) force_rls: bool,
    /// The role owns the table (`relowner = current role`).
    pub(crate) is_owner: bool,
    /// An applicable permissive `SELECT`/`ALL` policy uses `USING (true)`.
    pub(crate) permissive_true_policy: bool,
    /// An applicable restrictive policy narrows the permissive ones.
    pub(crate) restrictive_blocks: bool,
}

/// Whether the role gets past RLS: superuser, `BYPASSRLS`, ownership (unless
/// forced), or a permissive `USING (true)` with no restrictive policy.
fn bypasses_rls(access: TableAccess, role: RoleFlags) -> bool {
    role.superuser
        || role.bypassrls
        || (access.is_owner && !access.force_rls)
        || (access.permissive_true_policy && !access.restrictive_blocks)
}

/// Whether every row of a table is visible: `USAGE` and `SELECT` on it, and
/// either no RLS or a way past it; the preflight and its test share it.
#[must_use]
pub(crate) fn rows_visible(access: TableAccess, role: RoleFlags) -> bool {
    access.schema_usage && access.select && (!access.rls || bypasses_rls(access, role))
}

/// Whether RLS, and nothing else, is what hides a table's rows.
fn rls_blocks(access: TableAccess, role: RoleFlags) -> bool {
    access.rls && !bypasses_rls(access, role)
}

/// Everything the preflight learned: the sections carry their reason and fix.
#[derive(Debug, Default)]
pub(crate) struct Visibility {
    /// One entry per section, sorted by section name.
    pub(crate) sections: Vec<SectionCoverage>,
    tables: BTreeMap<(String, String), TableAccess>,
}

impl Visibility {
    /// The access the preflight read for one table.
    pub(crate) fn table(&self, schema: &str, table: &str) -> TableAccess {
        self.tables
            .get(&(schema.to_owned(), table.to_owned()))
            .copied()
            .unwrap_or_default()
    }

    /// The table exists.
    pub(crate) fn exists(&self, schema: &str, table: &str) -> bool {
        self.table(schema, table).exists
    }

    /// A named section was fully visible; unknown sections read as visible.
    /// Derived from [`sections`](Self::sections): gating follows coverage.
    pub(crate) fn section(&self, section: &str) -> bool {
        self.sections
            .iter()
            .find(|entry| entry.section == section)
            .is_none_or(|entry| entry.coverage != SourceStatus::NotVisible)
    }
}

/// Builds one section's reason and fix lines, then deduplicates them.
#[derive(Debug, Default)]
struct SectionBuilder {
    reasons: Vec<String>,
    fixes: Vec<String>,
}

impl SectionBuilder {
    /// `pg_read_all_data` is the one-line fix; the narrower grant, the
    /// alternative. `grant` is `USAGE ON SCHEMA` or `SELECT ON ALL TABLES …`.
    fn grant_fix(&mut self, role: &str, schema: &str, grant: &str) {
        let (schema, role) = (quote_ident(schema), quote_ident(role));
        self.fixes
            .push(format!("GRANT pg_read_all_data TO {role};"));
        self.fixes
            .push(format!("-- or: GRANT {grant} {schema} TO {role};"));
    }

    /// Adds only what is wrong, with the real role flags.
    fn problem_with(
        &mut self,
        access: TableAccess,
        role: &str,
        flags: RoleFlags,
        schema: &str,
        table: &str,
    ) {
        if !access.schema_usage {
            self.reasons
                .push(format!("`{role}` has no USAGE on schema `{schema}`"));
            self.grant_fix(role, schema, "USAGE ON SCHEMA");
        }
        if !access.select {
            self.reasons
                .push(format!("`{role}` has no SELECT on `{schema}.{table}`"));
            self.grant_fix(role, schema, "SELECT ON ALL TABLES IN SCHEMA");
        }
        if access.schema_usage && access.select && rls_blocks(access, flags) {
            self.reasons.push(format!(
                "row-level security on `{schema}.{table}` hides its rows from `{role}`"
            ));
            self.fixes
                .push(format!("ALTER ROLE {} BYPASSRLS;", quote_ident(role)));
            self.fixes.push(format!(
                "-- or, as the table owner: CREATE POLICY cratefield_inspect_read ON {}.{} FOR \
                 SELECT TO {} USING (true);",
                quote_ident(schema),
                quote_ident(table),
                quote_ident(role)
            ));
        }
    }

    /// A user schema's own problem: no USAGE, or SELECT missing on tables.
    fn schema_problem(&mut self, role: &str, schema: &str, usage: bool, missing_select: i64) {
        if !usage {
            self.reasons.push(format!(
                "`{role}` has no USAGE on schema `{schema}`: the import can list its tables but \
                 not read their rows"
            ));
            self.grant_fix(role, schema, "USAGE ON SCHEMA");
        }
        if missing_select > 0 {
            self.reasons.push(format!(
                "`{role}` lacks SELECT on {missing_select} table(s) in `{schema}`: the import can \
                 list them but not read their rows"
            ));
            self.grant_fix(role, schema, "SELECT ON ALL TABLES IN SCHEMA");
        }
    }

    /// The section: `not_visible` when anything was wrong, else `inspected`.
    fn finish(mut self, section: &str) -> SectionCoverage {
        self.reasons = dedup_in_order(self.reasons);
        self.fixes = dedup_in_order(self.fixes);
        SectionCoverage {
            section: section.to_owned(),
            coverage: if self.reasons.is_empty() {
                SourceStatus::Inspected
            } else {
                SourceStatus::NotVisible
            },
            reason: self.reasons.join("; "),
            fix: self.fixes.join("\n"),
        }
    }
}

/// Keeps the first occurrence of each line, in order: overlapping fixes
/// (`GRANT pg_read_all_data`) print once.
fn dedup_in_order(items: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(item.clone()))
        .collect()
}

/// One section of row-read tables: a problem per table whose rows are hidden.
fn row_section(
    vis: &Visibility,
    role: &str,
    flags: RoleFlags,
    section: &str,
    tables: &[(&str, &str)],
) -> SectionCoverage {
    let mut builder = SectionBuilder::default();
    for (schema, table) in tables {
        let access = vis.table(schema, table);
        if access.exists && !rows_visible(access, flags) {
            builder.problem_with(access, role, flags, schema, table);
        }
    }
    builder.finish(section)
}

/// Reads the preflight for `user_schemas` (the collector's non-managed
/// schemas): what the role can see.
///
/// # Errors
///
/// [`InspectError`] only for a read that fails for any reason other than a
/// missing privilege.
#[allow(clippy::too_many_lines)] // one catalog read per fact, in order
pub(crate) async fn preflight(
    session: &mut ReadOnlySession,
    user_schemas: &[String],
) -> Result<Visibility, InspectError> {
    let mut vis = Visibility::default();

    let (role, superuser, bypassrls): (String, bool, bool) = sqlx::query_as(
        "SELECT current_user::text, r.rolsuper, r.rolbypassrls FROM pg_roles r WHERE r.rolname = \
         current_user",
    )
    .fetch_one(&mut session.conn)
    .await
    .map_err(|error| session.error(&error))?;
    let flags = RoleFlags {
        superuser,
        bypassrls,
    };

    // Table access, by OID, joined on names as text: USAGE comes from the
    // schema's OID, so a name that cannot be resolved never errors.
    let tables: Vec<(String, String, bool, bool, bool, bool, bool)> = sqlx::query_as(&format!(
        "SELECT n.nspname::text, c.relname::text, has_schema_privilege(n.oid, 'USAGE'), \
         has_table_privilege(c.oid, 'SELECT'), c.relrowsecurity, c.relforcerowsecurity, \
         c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'p') AND \
         (n.nspname, c.relname) IN (VALUES {ROW_READ_PAIRS})"
    ))
    .fetch_all(&mut session.conn)
    .await
    .map_err(|error| session.error(&error))?;
    for (schema, table, schema_usage, select, rls, force_rls, is_owner) in tables {
        vis.tables.insert(
            (schema, table),
            TableAccess {
                exists: true,
                schema_usage,
                select,
                rls,
                force_rls,
                is_owner,
                ..TableAccess::default()
            },
        );
    }

    // The SELECT/ALL policies that apply to the role (directly, through
    // inheritance, or as PUBLIC). A permissive `USING (true)` lets every
    // row through; any restrictive policy whose `USING` is not `true`
    // narrows what it allows, so the rows stay hidden.
    let policies: Vec<(String, String, Option<bool>, Option<bool>)> = sqlx::query_as(&format!(
        "SELECT n.nspname::text, c.relname::text, bool_or(p.polpermissive AND \
         pg_get_expr(p.polqual, p.polrelid) = 'true'), bool_or(NOT p.polpermissive AND \
         pg_get_expr(p.polqual, p.polrelid) IS DISTINCT FROM 'true') FROM pg_policy p JOIN \
         pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE \
         p.polcmd IN ('r', '*') AND (0 = ANY(p.polroles) OR EXISTS (SELECT 1 FROM \
         unnest(p.polroles) AS o(ro_id) WHERE pg_has_role(o.ro_id, 'USAGE'))) AND (n.nspname, \
         c.relname) IN (VALUES {ROW_READ_PAIRS}) GROUP BY 1, 2"
    ))
    .fetch_all(&mut session.conn)
    .await
    .map_err(|error| session.error(&error))?;
    for (schema, table, permissive, restrictive) in policies {
        if let Some(access) = vis.tables.get_mut(&(schema, table)) {
            access.permissive_true_policy = permissive.unwrap_or(false);
            access.restrictive_blocks = restrictive.unwrap_or(false);
        }
    }

    // Per user schema: USAGE, and how many of its tables cannot be read.
    let user_select: BTreeMap<String, (bool, i64)> = if user_schemas.is_empty() {
        BTreeMap::new()
    } else {
        sqlx::query_as::<_, (String, bool, i64)>(
            "SELECT n.nspname::text, has_schema_privilege(n.oid, 'USAGE'), (SELECT count(*) FROM \
             pg_class c WHERE c.relnamespace = n.oid AND c.relkind IN ('r', 'p') AND NOT \
             has_table_privilege(c.oid, 'SELECT'))::bigint FROM pg_namespace n WHERE n.nspname = \
             ANY($1)",
        )
        .bind(user_schemas.to_vec())
        .fetch_all(&mut session.conn)
        .await
        .map_err(|error| session.error(&error))?
        .into_iter()
        .map(|(schema, usage, missing)| (schema, (usage, missing)))
        .collect()
    };

    let mut sections = vec![
        row_section(&vis, &role, flags, "auth", AUTH_TABLES),
        row_section(&vis, &role, flags, "storage.buckets", STORAGE_BUCKETS),
        row_section(&vis, &role, flags, "storage.objects", STORAGE_OBJECTS),
    ];
    // cron, only when cron.job exists.
    if vis.exists("cron", "job") {
        sections.push(row_section(&vis, &role, flags, "cron", CRON_JOBS));
    }
    // One section per user schema; its tables list regardless of SELECT.
    for schema in user_schemas {
        let (usage, missing) = user_select.get(schema).copied().unwrap_or_default();
        let mut builder = SectionBuilder::default();
        builder.schema_problem(&role, schema, usage, missing);
        sections.push(builder.finish(&format!("schema:{schema}")));
    }

    sections.sort_by(|a, b| a.section.cmp(&b.section));
    vis.sections = sections;
    Ok(vis)
}

/// Always double-quotes, doubling any `"`. The generated SQL never depends
/// on a keyword list (never complete) or on a name's case.
#[must_use]
pub(crate) fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    // The decision has many booleans by nature; the helpers mirror it 1:1.
    #![allow(clippy::fn_params_excessive_bools, clippy::field_reassign_with_default)]

    use super::*;

    fn access() -> TableAccess {
        let mut access = TableAccess::default();
        access.exists = true;
        access.schema_usage = true;
        access.select = true;
        access
    }

    fn role_flags(superuser: bool, bypassrls: bool) -> RoleFlags {
        RoleFlags {
            superuser,
            bypassrls,
        }
    }

    /// `access()` with the grants and flags given.
    fn visible_as(select: bool, usage: bool, superuser: bool, bypassrls: bool) -> bool {
        let mut access = access();
        access.select = select;
        access.schema_usage = usage;
        rows_visible(access, role_flags(superuser, bypassrls))
    }

    /// RLS on, the two policy facts given.
    fn rls_visible(permissive: bool, restrictive: bool) -> bool {
        let mut access = access();
        access.rls = true;
        access.permissive_true_policy = permissive;
        access.restrictive_blocks = restrictive;
        rows_visible(access, RoleFlags::default())
    }

    /// RLS on, ownership/force and the role flags given.
    fn rls_as(owner: bool, forced: bool, superuser: bool, bypassrls: bool) -> bool {
        let mut access = access();
        access.rls = true;
        access.is_owner = owner;
        access.force_rls = forced;
        rows_visible(access, role_flags(superuser, bypassrls))
    }

    #[test]
    fn usage_and_select_are_both_required() {
        assert!(rows_visible(access(), RoleFlags::default()));
        assert!(!visible_as(false, true, false, false));
        assert!(!visible_as(true, false, false, false));
    }

    #[test]
    fn rls_hides_rows_unless_something_bypasses_it() {
        assert!(!rls_visible(false, false));
        // Superuser and BYPASSRLS get past it.
        assert!(rls_as(false, false, true, false));
        assert!(rls_as(false, false, false, true));
        // The owner is exempt unless RLS is forced.
        assert!(rls_as(true, false, false, false));
        assert!(!rls_as(true, true, false, false));
        // A permissive USING (true) policy opens it, unless an applicable
        // restrictive policy narrows it; restrictive alone opens nothing.
        assert!(rls_visible(true, false));
        assert!(!rls_visible(true, true));
        assert!(!rls_visible(false, true));
    }

    #[test]
    fn superuser_and_bypassrls_do_not_override_a_missing_grant() {
        assert!(!visible_as(false, true, true, false));
        assert!(!visible_as(true, false, false, true));
    }

    #[test]
    fn identifiers_are_always_quoted() {
        assert_eq!(quote_ident("public"), "\"public\"");
        assert_eq!(quote_ident("fz_inspect_1"), "\"fz_inspect_1\"");
        assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
    }
}
