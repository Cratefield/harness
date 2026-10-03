//! What the harness Postgres target can do with each extension a Supabase
//! project may have installed.
//!
//! The list is the decision, in one place: an extension not on it is
//! [`ExtensionSupport::Unknown`], which is reported as needing work (the
//! target may or may not have it), never guessed to be fine.

use crate::report::ExtensionSupport;

/// Extensions created on the target before the schema (ADR 0026, Decision
/// 5): the ones a stock Postgres 16 ships, plus `PostGIS` and `pgvector`, which
/// the target installs. `plpgsql` is always there.
const SUPPORTED: &[&str] = &[
    "btree_gin",
    "btree_gist",
    "citext",
    "cube",
    "earthdistance",
    "fuzzystrmatch",
    "hstore",
    "intarray",
    "isn",
    "ltree",
    "moddatetime",
    "pg_trgm",
    "pgcrypto",
    "plpgsql",
    "postgis",
    "postgis_raster",
    "postgis_topology",
    "seg",
    "tablefunc",
    "unaccent",
    "uuid-ossp",
    "vector",
];

/// Supabase platform extensions: not carried over. What used one needs a
/// harness equivalent, and the reason says which.
const PLATFORM: &[(&str, &str)] = &[
    (
        "http",
        "outbound HTTP from SQL; move the call into a module through the `HttpClient` port",
    ),
    (
        "hypopg",
        "a query-planning aid; nothing to carry, run it on the target if wanted",
    ),
    (
        "index_advisor",
        "a query-planning aid; nothing to carry, run it on the target if wanted",
    ),
    (
        "pg_cron",
        "scheduled SQL; each job becomes a scheduled handler in a module (see the cron findings)",
    ),
    (
        "pg_graphql",
        "Supabase's GraphQL endpoint; the harness exposes no table directly, so a client that \
         queried it needs a module route",
    ),
    (
        "pg_jsonschema",
        "JSON-schema CHECK constraints; validate in the module before the write instead",
    ),
    (
        "pg_net",
        "async HTTP from SQL (database webhooks); move it into a module through the `HttpClient` \
         port or module-webhooks",
    ),
    (
        "pg_stat_monitor",
        "monitoring; the target has its own, nothing to carry",
    ),
    (
        "pg_stat_statements",
        "monitoring; the target has its own, nothing to carry",
    ),
    (
        "pgaudit",
        "audit logging; the harness records audit events through module code",
    ),
    (
        "pgjwt",
        "JWT signing in SQL; the harness signs tokens in auth code (`Signer` port)",
    ),
    (
        "pgsodium",
        "column encryption keyed by Supabase; decrypt on the source and seal with the harness \
         secret store instead",
    ),
    (
        "pgtap",
        "database unit tests; they run against Supabase's schema, not the harness",
    ),
    ("plpgsql_check", "a function linter; nothing to carry"),
    (
        "supabase_vault",
        "Supabase Vault; move each secret to the harness secret store",
    ),
    (
        "wrappers",
        "foreign data wrappers to third-party APIs; replace with module code over the \
         `HttpClient` port",
    ),
];

/// Extensions with no harness equivalent that cannot be carried: each is a
/// blocker until the project stops depending on it.
const UNSUPPORTED: &[(&str, &str)] = &[
    (
        "dblink",
        "cross-database queries: the harness is one database per tenant (ADR 0008) and reaches \
         other systems through ports, not through SQL",
    ),
    (
        "file_fdw",
        "reads files on the database server, which the harness target does not expose",
    ),
    (
        "pljava",
        "functions in Java: the target runs no JVM in the database",
    ),
    (
        "plv8",
        "functions in JavaScript, deprecated on Supabase itself: rewrite them in SQL/plpgsql or \
         move the logic into a module",
    ),
    (
        "postgres_fdw",
        "cross-database queries: the harness is one database per tenant (ADR 0008) and reaches \
         other systems through ports, not through SQL",
    ),
    (
        "timescaledb",
        "deprecated on Supabase and not on the harness target: hypertables have to become \
         plain (or partitioned) tables first",
    ),
];

/// The support status of `name`, and the reason a finding quotes.
#[must_use]
pub fn support(name: &str) -> (ExtensionSupport, &'static str) {
    if SUPPORTED.contains(&name) {
        return (
            ExtensionSupport::Supported,
            "created on the target before the schema",
        );
    }
    if let Some((_, why)) = PLATFORM.iter().find(|(known, _)| *known == name) {
        return (ExtensionSupport::SupabasePlatform, why);
    }
    if let Some((_, why)) = UNSUPPORTED.iter().find(|(known, _)| *known == name) {
        return (ExtensionSupport::Unsupported, why);
    }
    (
        ExtensionSupport::Unknown,
        "not on the support list: confirm the target Postgres provides it before the schema phase",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lists_are_sorted_and_disjoint() {
        let platform: Vec<_> = PLATFORM.iter().map(|(name, _)| *name).collect();
        let unsupported: Vec<_> = UNSUPPORTED.iter().map(|(name, _)| *name).collect();
        for list in [SUPPORTED, platform.as_slice(), unsupported.as_slice()] {
            assert!(list.is_sorted(), "{list:?}");
        }
        for name in SUPPORTED {
            assert!(
                !platform.contains(name) && !unsupported.contains(name),
                "{name}"
            );
        }
        for name in &platform {
            assert!(!unsupported.contains(name), "{name}");
        }
    }

    #[test]
    fn statuses() {
        assert_eq!(support("pgcrypto").0, ExtensionSupport::Supported);
        assert_eq!(support("pg_net").0, ExtensionSupport::SupabasePlatform);
        assert_eq!(support("dblink").0, ExtensionSupport::Unsupported);
        assert_eq!(support("some_new_thing").0, ExtensionSupport::Unknown);
    }
}
