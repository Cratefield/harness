//! The catalog reads. Every one runs inside the [`ReadOnlySession`]'s
//! transaction, reads the system catalogs or aggregates (counts and sums),
//! and never a row of user data.

use std::collections::BTreeMap;

use cratefield_core::scrub_text;

use crate::report::{
    Auth, Bucket, Column, Constraint, CronJob, EnumType, Function, Index, ProviderCount,
    Publication, RoleGrants, Sequence, Storage, Table, Trigger, View,
};
use crate::session::{InspectError, ReadOnlySession};
use crate::visibility::{self, Visibility};

/// Supabase-managed schemas: never copied as schemas (ADR 0026, Decision
/// 3). `auth` and `storage` have their own phases.
pub(crate) const MANAGED_SCHEMAS: &[&str] = &[
    "_analytics",
    "_realtime",
    "_supavisor",
    "auth",
    "cron",
    "extensions",
    "graphql",
    "graphql_public",
    "net",
    "pgbouncer",
    "pgsodium",
    "pgsodium_masks",
    "pgtle",
    "realtime",
    "storage",
    "supabase_functions",
    "supabase_migrations",
    "tiger",
    "tiger_data",
    "topology",
    "vault",
];

/// The Blob port's put cap (`crates/core/src/ports/blob.rs`): an object
/// over it is copied but cannot be replaced through the port.
pub(crate) const BLOB_CAP_BYTES: i64 = 10 * 1024 * 1024;

/// The roles Supabase's REST layer runs requests as.
pub(crate) const API_ROLES: &[&str] = &["anon", "authenticated", "service_role"];

/// The text names `schema.` as a qualifier (`auth.uid()`, `storage.objects`),
/// not as the tail of another identifier (`oauth.x`).
#[must_use]
pub(crate) fn names_schema(text: &str, schema: &str) -> bool {
    let lower = text.to_lowercase();
    let needle = format!("{schema}.");
    lower.match_indices(&needle).any(|(at, _)| {
        let before = lower[..at].chars().next_back();
        !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    })
}

/// Everything read from the database.
// Facts read off the catalog, one flag per fact; not a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
pub(crate) struct Catalog {
    pub(crate) server_version: String,
    pub(crate) role: String,
    pub(crate) role_is_superuser: bool,
    pub(crate) role_can_write: bool,
    pub(crate) transaction_read_only: bool,
    pub(crate) session_read_only: bool,
    pub(crate) schemas: Vec<(String, usize)>,
    pub(crate) tables: Vec<Table>,
    pub(crate) views: Vec<View>,
    pub(crate) sequences: Vec<Sequence>,
    pub(crate) enums: Vec<EnumType>,
    pub(crate) extensions: Vec<(String, String, String)>,
    pub(crate) functions: Vec<Function>,
    pub(crate) triggers: Vec<Trigger>,
    pub(crate) policies: Vec<RawPolicy>,
    pub(crate) grants: Vec<RoleGrants>,
    pub(crate) auth: Auth,
    pub(crate) storage: Storage,
    pub(crate) publications: Vec<Publication>,
    pub(crate) cron_jobs: Option<Vec<CronJob>>,
    pub(crate) warnings: Vec<String>,
    /// What the role could see, read before anything that needs a row.
    pub(crate) visibility: Visibility,
}

/// A policy as read, before it is placed.
#[derive(Debug, Clone)]
pub(crate) struct RawPolicy {
    pub(crate) schema: String,
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) command: String,
    pub(crate) permissive: bool,
    pub(crate) roles: Vec<String>,
    pub(crate) using: Option<String>,
    pub(crate) with_check: Option<String>,
    pub(crate) columns: Vec<String>,
}

/// `$1` in the queries below: the user schemas.
const NOT_EXTENSION_MEMBER: &str = "NOT EXISTS (SELECT 1 FROM pg_depend d \
     WHERE d.objid = c.oid AND d.classid = 'pg_class'::regclass AND d.deptype = 'e')";

macro_rules! fetch {
    ($session:expr, $ty:ty, $sql:expr $(, $bind:expr)*) => {{
        let session: &mut ReadOnlySession = $session;
        let result = sqlx::query_as::<_, $ty>($sql)
            $(.bind($bind))*
            .fetch_all(&mut session.conn)
            .await;
        result.map_err(|error| session.error(&error))
    }};
}

fn clamp(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// Reads the catalog.
///
/// # Errors
///
/// [`InspectError::Permission`] when the role cannot read something inspect
/// needs; [`InspectError::Query`] for anything else.
#[allow(clippy::too_many_lines)] // one read per section, in report order
pub(crate) async fn read(session: &mut ReadOnlySession) -> Result<Catalog, InspectError> {
    let mut catalog = Catalog::default();

    let (version, read_only, default_read_only, role, superuser): (
        String,
        String,
        String,
        String,
        bool,
    ) = fetch!(
        session,
        (String, String, String, String, bool),
        "SELECT current_setting('server_version'), current_setting('transaction_read_only'), \
             current_setting('default_transaction_read_only'), current_user::text, \
             coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false)"
    )?
    .remove(0);
    catalog.server_version = version;
    catalog.transaction_read_only = read_only == "on";
    catalog.session_read_only = default_read_only == "on";
    catalog.role = role;
    catalog.role_is_superuser = superuser;

    // Schemas.
    catalog.schemas = fetch!(
        session,
        (String, i64),
        "SELECT n.nspname::text, (SELECT count(*) FROM pg_class c WHERE c.relnamespace = n.oid \
         AND c.relkind IN ('r', 'p') AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = \
         c.oid AND d.classid = 'pg_class'::regclass AND d.deptype = 'e')) \
         FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> \
         'information_schema' ORDER BY 1"
    )?
    .into_iter()
    .map(|(name, tables)| (name, usize::try_from(tables).unwrap_or(0)))
    .collect();
    let user: Vec<String> = catalog
        .schemas
        .iter()
        .map(|(name, _)| name.clone())
        .filter(|name| !MANAGED_SCHEMAS.contains(&name.as_str()))
        .collect();
    let mut writable_scope = user.clone();
    writable_scope.extend(["auth".to_owned(), "storage".to_owned()]);

    // The privilege preflight: catalog-only, before any row read. It is
    // what keeps a schema without USAGE (or RLS) from aborting the run or
    // reporting a hidden zero as a fact.
    let visibility = visibility::preflight(session, &user).await?;

    catalog.role_can_write = fetch!(
        session,
        (bool,),
        "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relkind IN ('r', 'p') AND n.nspname = ANY($1) AND (has_table_privilege(c.oid, \
         'INSERT') OR has_table_privilege(c.oid, 'UPDATE') OR has_table_privilege(c.oid, \
         'DELETE') OR has_table_privilege(c.oid, 'TRUNCATE'))) OR EXISTS (SELECT 1 FROM \
         pg_namespace n WHERE n.nspname = ANY($1) AND has_schema_privilege(n.oid, 'CREATE'))",
        &writable_scope
    )?
    .remove(0)
    .0;

    // Tables, then their columns, constraints and indexes.
    let tables = fetch!(
        session,
        (String, String, String, f64, i64, i64, bool, bool),
        &format!(
            "SELECT n.nspname::text, c.relname::text, CASE c.relkind WHEN 'p' THEN \
             'partitioned_table' ELSE 'table' END, c.reltuples::float8, pg_table_size(c.oid), \
             pg_indexes_size(c.oid), c.relrowsecurity, c.relforcerowsecurity FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'p') AND \
             n.nspname = ANY($1) AND {NOT_EXTENSION_MEMBER} ORDER BY 1, 2"
        ),
        &user
    )?;
    let mut by_key: BTreeMap<(String, String), Table> = BTreeMap::new();
    for (schema, name, kind, rows, data, index, rls, forced) in tables {
        // `reltuples` is -1 for a table never vacuumed or analyzed.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let estimated_rows = (rows >= 0.0).then(|| rows.round() as u64);
        by_key.insert(
            (schema.clone(), name.clone()),
            Table {
                schema,
                name,
                kind,
                estimated_rows,
                data_bytes: clamp(data),
                index_bytes: clamp(index),
                rls_enabled: rls,
                rls_forced: forced,
                primary_key: Vec::new(),
                columns: Vec::new(),
                constraints: Vec::new(),
                indexes: Vec::new(),
            },
        );
    }
    let columns = fetch!(
        session,
        (
            String,
            String,
            String,
            String,
            bool,
            Option<String>,
            String,
            String
        ),
        "SELECT n.nspname::text, c.relname::text, a.attname::text, format_type(a.atttypid, \
         a.atttypmod), NOT a.attnotnull, pg_get_expr(d.adbin, d.adrelid), a.attidentity::text, \
         a.attgenerated::text FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN \
         pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid = \
         a.attrelid AND d.adnum = a.attnum WHERE a.attnum > 0 AND NOT a.attisdropped AND \
         c.relkind IN ('r', 'p') AND n.nspname = ANY($1) ORDER BY 1, 2, a.attnum",
        &user
    )?;
    for (schema, table, name, data_type, nullable, expr, identity, generated) in columns {
        let Some(entry) = by_key.get_mut(&(schema, table)) else {
            continue;
        };
        let expr = expr.map(|expr| scrub_text(&expr));
        let is_generated = generated == "s";
        entry.columns.push(Column {
            name,
            data_type,
            nullable,
            default: if is_generated { None } else { expr.clone() },
            identity: match identity.as_str() {
                "a" => Some("always".to_owned()),
                "d" => Some("by_default".to_owned()),
                _ => None,
            },
            generated: if is_generated { expr } else { None },
        });
    }
    let constraints = fetch!(
        session,
        (String, String, String, String, String, Option<String>),
        "SELECT n.nspname::text, cl.relname::text, con.conname::text, con.contype::text, \
         pg_get_constraintdef(con.oid), CASE WHEN con.contype = 'f' THEN fn.nspname || '.' || \
         fc.relname END FROM pg_constraint con JOIN pg_class cl ON cl.oid = con.conrelid JOIN \
         pg_namespace n ON n.oid = cl.relnamespace LEFT JOIN pg_class fc ON fc.oid = \
         con.confrelid LEFT JOIN pg_namespace fn ON fn.oid = fc.relnamespace WHERE n.nspname = \
         ANY($1) ORDER BY 1, 2, 3",
        &user
    )?;
    for (schema, table, name, kind, definition, references) in constraints {
        let Some(entry) = by_key.get_mut(&(schema, table)) else {
            continue;
        };
        entry.constraints.push(Constraint {
            name,
            kind: match kind.as_str() {
                "p" => "primary_key",
                "f" => "foreign_key",
                "u" => "unique",
                "c" => "check",
                "x" => "exclusion",
                "t" => "trigger",
                _ => "other",
            }
            .to_owned(),
            definition: scrub_text(&definition),
            references,
        });
    }
    let indexes = fetch!(
        session,
        (String, String, String, bool, bool, String, Vec<String>),
        "SELECT n.nspname::text, t.relname::text, ic.relname::text, i.indisunique, \
         i.indisprimary, pg_get_indexdef(i.indexrelid), CASE WHEN i.indisprimary THEN \
         array(SELECT a.attname::text FROM unnest(i.indkey::int2[]) WITH ORDINALITY k(attnum, \
         ord) JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum ORDER BY \
         k.ord) ELSE '{}'::text[] END FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid \
         JOIN pg_class t ON t.oid = i.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace \
         WHERE n.nspname = ANY($1) ORDER BY 1, 2, 3",
        &user
    )?;
    for (schema, table, name, unique, primary, definition, key) in indexes {
        let Some(entry) = by_key.get_mut(&(schema, table)) else {
            continue;
        };
        if primary {
            entry.primary_key = key;
        }
        entry.indexes.push(Index {
            name,
            unique,
            primary,
            definition,
        });
    }
    catalog.tables = by_key.into_values().collect();

    catalog.views = fetch!(
        session,
        (String, String, bool, String),
        &format!(
            "SELECT n.nspname::text, c.relname::text, c.relkind = 'm', pg_get_viewdef(c.oid) \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN \
             ('v', 'm') AND n.nspname = ANY($1) AND {NOT_EXTENSION_MEMBER} ORDER BY 1, 2"
        ),
        &user
    )?
    .into_iter()
    .map(|(schema, name, materialized, definition)| View {
        references_auth: names_schema(&definition, "auth"),
        references_storage: names_schema(&definition, "storage"),
        schema,
        name,
        materialized,
    })
    .collect();

    catalog.sequences = fetch!(
        session,
        (String, String, String, Option<String>),
        &format!(
            "SELECT n.nspname::text, c.relname::text, format_type(s.seqtypid, NULL), (SELECT \
             t.relname || '.' || a.attname FROM pg_depend d JOIN pg_class t ON t.oid = \
             d.refobjid JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = \
             d.refobjsubid WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND \
             d.refobjsubid > 0 AND d.deptype IN ('a', 'i') LIMIT 1) FROM pg_sequence s JOIN \
             pg_class c ON c.oid = s.seqrelid JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = ANY($1) AND {NOT_EXTENSION_MEMBER} ORDER BY 1, 2"
        ),
        &user
    )?
    .into_iter()
    .map(|(schema, name, data_type, owned_by)| Sequence {
        schema,
        name,
        owned_by,
        data_type,
    })
    .collect();

    catalog.enums = fetch!(
        session,
        (String, String, Vec<String>),
        "SELECT n.nspname::text, t.typname::text, array_agg(e.enumlabel::text ORDER BY \
         e.enumsortorder) FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid JOIN pg_namespace \
         n ON n.oid = t.typnamespace WHERE n.nspname = ANY($1) AND NOT EXISTS (SELECT 1 FROM \
         pg_depend d WHERE d.objid = t.oid AND d.classid = 'pg_type'::regclass AND d.deptype = \
         'e') GROUP BY 1, 2 ORDER BY 1, 2",
        &user
    )?
    .into_iter()
    .map(|(schema, name, labels)| EnumType {
        schema,
        name,
        labels,
    })
    .collect();

    catalog.extensions = fetch!(
        session,
        (String, String, String),
        "SELECT e.extname::text, e.extversion, n.nspname::text FROM pg_extension e JOIN \
         pg_namespace n ON n.oid = e.extnamespace ORDER BY 1"
    )?;

    catalog.functions = fetch!(
        session,
        (String, String, String, String, String, String, bool, String),
        "SELECT n.nspname::text, p.proname::text, pg_get_function_identity_arguments(p.oid), \
         CASE p.prokind WHEN 'p' THEN 'procedure' WHEN 'a' THEN 'aggregate' WHEN 'w' THEN \
         'window' ELSE 'function' END, l.lanname::text, coalesce(pg_get_function_result(p.oid), \
         ''), p.prosecdef, coalesce(p.prosrc, '') FROM pg_proc p JOIN pg_namespace n ON n.oid = \
         p.pronamespace JOIN pg_language l ON l.oid = p.prolang WHERE n.nspname = ANY($1) AND \
         NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.classid = \
         'pg_proc'::regclass AND d.deptype = 'e') ORDER BY 1, 2, 3",
        &user
    )?
    .into_iter()
    .map(
        |(schema, name, arguments, kind, language, returns, security_definer, body)| Function {
            references_auth: names_schema(&body, "auth"),
            references_storage: names_schema(&body, "storage"),
            references_net: names_schema(&body, "net"),
            schema,
            name,
            arguments,
            kind,
            language,
            returns,
            security_definer,
        },
    )
    .collect();

    catalog.triggers = fetch!(
        session,
        (String, String, String, String, String, bool),
        "SELECT n.nspname::text, c.relname::text, t.tgname::text, pn.nspname || '.' || \
         p.proname, pg_get_triggerdef(t.oid), t.tgenabled <> 'D' FROM pg_trigger t JOIN \
         pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace JOIN \
         pg_proc p ON p.oid = t.tgfoid JOIN pg_namespace pn ON pn.oid = p.pronamespace WHERE \
         NOT t.tgisinternal AND (n.nspname = ANY($1) OR (n.nspname IN ('auth', 'storage') AND \
         pn.nspname = ANY($1))) ORDER BY 1, 2, 3",
        &user
    )?
    .into_iter()
    .map(
        |(schema, table, name, function, definition, enabled)| Trigger {
            schema,
            table,
            name,
            function,
            definition,
            enabled,
        },
    )
    .collect();

    catalog.policies = fetch!(
        session,
        (
            String,
            String,
            String,
            String,
            bool,
            Vec<String>,
            Option<String>,
            Option<String>,
            Vec<String>
        ),
        // The relation comes from `pg_policy.polrelid`, never from casting
        // `schemaname.tablename`: that resolves the name, which needs USAGE
        // the role may not have (issue #723). Same for the policy's
        // columns.
        "SELECT n.nspname::text, c.relname::text, p.polname::text, CASE p.polcmd WHEN 'r' THEN \
         'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' ELSE \
         'ALL' END, p.polpermissive, CASE WHEN p.polroles = '{0}'::oid[] THEN \
         ARRAY['public']::text[] ELSE array(SELECT ro.rolname::text FROM unnest(p.polroles) AS \
         o(ro_id) JOIN pg_roles ro ON ro.oid = o.ro_id ORDER BY 1) END, \
         pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid), \
         array(SELECT a.attname::text FROM pg_attribute a WHERE a.attrelid = p.polrelid AND \
         a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum) FROM pg_policy p JOIN pg_class c \
         ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT \
         IN ('pg_catalog', 'information_schema') ORDER BY 1, 2, 3"
    )?
    .into_iter()
    .map(
        |(schema, table, name, command, permissive, mut roles, using, with_check, columns)| {
            roles.sort();
            RawPolicy {
                schema,
                table,
                name,
                command,
                permissive,
                roles,
                using: using.map(|expr| scrub_text(&expr)),
                with_check: with_check.map(|expr| scrub_text(&expr)),
                columns,
            }
        },
    )
    .collect();

    let grants = fetch!(
        session,
        (String, String),
        "SELECT DISTINCT r.rolname::text, n.nspname || '.' || c.relname FROM pg_class c JOIN \
         pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a \
         JOIN pg_roles r ON r.oid = a.grantee WHERE c.relkind IN ('r', 'p', 'v', 'm') AND \
         n.nspname = ANY($1) AND r.rolname = ANY($2) ORDER BY 1, 2",
        &user,
        API_ROLES
    )?;
    let mut by_role: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (role, table) in grants {
        by_role.entry(role).or_default().push(table);
    }
    catalog.grants = by_role
        .into_iter()
        .map(|(role, tables)| RoleGrants { role, tables })
        .collect();

    read_auth(session, &mut catalog, &visibility).await?;
    read_storage(session, &mut catalog, &visibility).await?;

    catalog.publications = fetch!(
        session,
        (String, bool, bool, bool, bool, bool, Vec<String>),
        "SELECT p.pubname::text, p.puballtables, p.pubinsert, p.pubupdate, p.pubdelete, \
         p.pubtruncate, array(SELECT pt.schemaname || '.' || pt.tablename FROM \
         pg_publication_tables pt WHERE pt.pubname = p.pubname ORDER BY 1) FROM pg_publication \
         p ORDER BY 1"
    )?
    .into_iter()
    .map(
        |(name, all_tables, insert, update, delete, truncate, tables)| Publication {
            name,
            all_tables,
            operations: [
                ("delete", delete),
                ("insert", insert),
                ("truncate", truncate),
                ("update", update),
            ]
            .into_iter()
            .filter(|(_, on)| *on)
            .map(|(op, _)| op.to_owned())
            .collect(),
            tables,
        },
    )
    .collect();

    if visibility.exists("cron", "job") {
        if visibility.section("cron") {
            catalog.cron_jobs = Some(
                fetch!(
                    session,
                    (i64, Option<String>, String, String, bool),
                    "SELECT jobid, jobname::text, schedule, command, active FROM cron.job ORDER \
                     BY coalesce(jobname, ''), jobid"
                )?
                .into_iter()
                .map(|(id, name, schedule, command, active)| CronJob {
                    name: name
                        .filter(|name| !name.is_empty())
                        .unwrap_or_else(|| format!("job-{id}")),
                    schedule,
                    command: scrub_text(&command),
                    active,
                })
                .collect(),
            );
        } else {
            // Not visible: unknown, never "no jobs". The section's blocker
            // finding carries the fix; no row query runs, so no permission
            // error and no savepoint to recover from one.
            catalog.cron_jobs = None;
        }
    } else {
        catalog.cron_jobs = Some(Vec::new());
    }

    catalog.visibility = visibility;
    Ok(catalog)
}

/// Whether a relation exists, by `to_regclass`. Only `fz import supabase
/// users` uses it, on `auth` tables its role must already be able to read;
/// `inspect` checks visibility by catalog OID instead (issue #723).
pub(crate) async fn relation_exists(
    session: &mut ReadOnlySession,
    name: &str,
) -> Result<bool, InspectError> {
    Ok(
        fetch!(session, (bool,), "SELECT to_regclass($1) IS NOT NULL", name)?
            .remove(0)
            .0,
    )
}

/// Whether a table has a column, by catalog lookup (`pg_attribute` joined
/// to `pg_class`/`pg_namespace` on the name text): never `to_regclass` on a
/// name, which resolves it and can error without USAGE on its schema.
pub(crate) async fn column_exists(
    session: &mut ReadOnlySession,
    schema: &str,
    table: &str,
    column: &str,
) -> Result<bool, InspectError> {
    Ok(fetch!(
        session,
        (bool,),
        "SELECT EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN \
         pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2 AND \
         a.attname = $3 AND a.attnum > 0 AND NOT a.attisdropped)",
        schema,
        table,
        column
    )?
    .remove(0)
    .0)
}

async fn read_auth(
    session: &mut ReadOnlySession,
    catalog: &mut Catalog,
    visibility: &Visibility,
) -> Result<(), InspectError> {
    if !visibility.exists("auth", "users") {
        return Ok(());
    }
    catalog.auth.present = true;
    if !visibility.section("auth") {
        // Not visible: every count stays null (unknown, never zero). The
        // preflight already recorded why and the fix; no row is read, so
        // there is no permission error to recover from.
        return Ok(());
    }
    let anonymous = if column_exists(session, "auth", "users", "is_anonymous").await? {
        "count(*) FILTER (WHERE is_anonymous)"
    } else {
        "0::bigint"
    };
    // A user is confirmed when either address is: a phone-only user has no
    // `email_confirmed_at`, and `phone_confirmed_at` is not on every stack.
    let confirmed = if column_exists(session, "auth", "users", "phone_confirmed_at").await? {
        "(email_confirmed_at IS NOT NULL OR phone_confirmed_at IS NOT NULL)"
    } else {
        "email_confirmed_at IS NOT NULL"
    };
    let (users, without_password, unconfirmed, anonymous): (i64, i64, i64, i64) = fetch!(
        session,
        (i64, i64, i64, i64),
        &format!(
            "SELECT count(*), count(*) FILTER (WHERE encrypted_password IS NULL OR \
             encrypted_password = ''), count(*) FILTER (WHERE NOT {confirmed}), \
             {anonymous} FROM auth.users"
        )
    )?
    .remove(0);
    catalog.auth.users = Some(clamp(users));
    catalog.auth.users_without_password = Some(clamp(without_password));
    catalog.auth.users_unconfirmed = Some(clamp(unconfirmed));
    catalog.auth.anonymous_users = Some(clamp(anonymous));
    catalog.auth.identities_by_provider = Some(if visibility.exists("auth", "identities") {
        fetch!(
            session,
            (String, i64),
            "SELECT provider, count(*) FROM auth.identities GROUP BY 1 ORDER BY 1"
        )?
        .into_iter()
        .map(|(provider, identities)| ProviderCount {
            provider,
            identities: clamp(identities),
        })
        .collect()
    } else {
        Vec::new()
    });
    for (table, field) in [
        ("mfa_factors", &mut catalog.auth.mfa_factors),
        ("sso_providers", &mut catalog.auth.sso_providers),
    ] {
        // Absent table (visible section): none of them, so zero, matching
        // `identities_by_provider`. `None` only when the section is
        // not visible, which returned above.
        *field = Some(if visibility.exists("auth", table) {
            clamp(
                fetch!(
                    session,
                    (i64,),
                    &format!("SELECT count(*) FROM auth.{table}")
                )?
                .remove(0)
                .0,
            )
        } else {
            0
        });
    }
    Ok(())
}

async fn read_storage(
    session: &mut ReadOnlySession,
    catalog: &mut Catalog,
    visibility: &Visibility,
) -> Result<(), InspectError> {
    if !visibility.exists("storage", "buckets") {
        catalog.storage = Storage {
            present: false,
            buckets: None,
            unattached_policies: Vec::new(),
        };
        return Ok(());
    }
    catalog.storage.present = true;
    if !visibility.section("storage.buckets") {
        // Not visible: null, not []. No row read, so no permission error.
        catalog.storage.buckets = None;
        return Ok(());
    }
    let mime = if column_exists(session, "storage", "buckets", "allowed_mime_types").await? {
        "coalesce(allowed_mime_types, '{}'::text[])"
    } else {
        "'{}'::text[]"
    };
    let limit = if column_exists(session, "storage", "buckets", "file_size_limit").await? {
        "file_size_limit::bigint"
    } else {
        "NULL::bigint"
    };
    let buckets = fetch!(
        session,
        (String, String, bool, Option<i64>, Vec<String>),
        &format!(
            "SELECT id::text, name::text, coalesce(public, false), {limit}, {mime} FROM \
             storage.buckets ORDER BY 1"
        )
    )?;
    // `None` when storage.objects is not visible: the per-bucket counts are
    // then unknown, not zero. `Some(empty)` when the table is simply absent.
    let objects: Option<BTreeMap<String, (i64, i64, i64)>> = if !visibility
        .exists("storage", "objects")
    {
        Some(BTreeMap::new())
    } else if visibility.section("storage.objects") {
        let size = "CASE WHEN metadata->>'size' ~ '^[0-9]+$' THEN (metadata->>'size')::bigint END";
        let mut map = BTreeMap::new();
        for (bucket, count, bytes, over) in fetch!(
            session,
            (String, i64, i64, i64),
            &format!(
                "SELECT bucket_id::text, count(*), coalesce(sum({size}), 0)::bigint, count(*) \
                     FILTER (WHERE {size} > {BLOB_CAP_BYTES}) FROM storage.objects GROUP BY 1"
            )
        )? {
            map.insert(bucket, (count, bytes, over));
        }
        Some(map)
    } else {
        None
    };
    catalog.storage.buckets = Some(
        buckets
            .into_iter()
            .map(
                |(id, name, public, file_size_limit, mut allowed_mime_types)| {
                    allowed_mime_types.sort();
                    let counts = objects
                        .as_ref()
                        .map(|map| map.get(&id).copied().unwrap_or_default());
                    Bucket {
                        id,
                        name,
                        public,
                        file_size_limit: file_size_limit.map(clamp),
                        allowed_mime_types,
                        objects: counts.map(|(count, _, _)| clamp(count)),
                        bytes: counts.map(|(_, bytes, _)| clamp(bytes)),
                        objects_over_blob_cap: counts.map(|(_, _, over)| clamp(over)),
                        // Filled by `storage_policy::attach` once every
                        // policy has been read.
                        policies: Vec::new(),
                    }
                },
            )
            .collect(),
    );
    Ok(())
}
