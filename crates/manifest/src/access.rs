//! Who may read and write a declared table (issue #153).
//!
//! A small fixed vocabulary, evaluated in Rust, and **it stays a
//! vocabulary**. The issue is explicit that it must not grow into a
//! policy language, and the reason is worth restating where someone will
//! be tempted: a policy language is a second program, written in a
//! manifest, with no type checker and no tests, deciding who sees what.
//! Four words that the harness evaluates are four things that can be
//! reviewed.
//!
//! Required per table, with no default, for the reason
//! [`crate::privacy`] gives at more length: both available defaults are
//! wrong. `public-read` by default publishes a venture's tables the day
//! the CRUD layer lands, and `admin` by default makes every declared
//! table useless until somebody notices.
//!
//! Nothing serves these yet — the CRUD routes are not built. Declaring
//! first is deliberate: when the routes arrive, no table can be served
//! without an author having said who may see it, and no existing
//! manifest needs migrating to a rule it was written before.

use serde::{Deserialize, Serialize};

/// Who may reach a declared table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
// The set is meant to stay this size; a new variant is a decision about
// the product, not a convenience. `#[non_exhaustive]` so adding one is
// not a breaking change for every downstream `match` on the day it is.
#[non_exhaustive]
pub enum Access {
    /// Anyone may read; nobody may write through the table API.
    ///
    /// For reference data a venture publishes — plan tiers, categories,
    /// a public catalogue.
    PublicRead,
    /// A signed-in caller reads and writes their own rows, and no
    /// others.
    ///
    /// "Their own" is the table's subject column, the one its privacy
    /// declaration names. A table with no subject has nothing to match
    /// the caller against, which is why declaring `owner` on one is a
    /// manifest error rather than a runtime surprise.
    Owner,
    /// Any caller the deployment's verifier accepts reads and writes
    /// every row.
    ///
    /// Named for what it is *for* and not for what it checks, and the
    /// difference matters: the harness has no membership fact. A
    /// `Subject` is an id, a session and an address, and `Ports::tenants`
    /// is deliberately invisible to a module, so nothing in the decision
    /// can ask which tenant a caller belongs to.
    ///
    /// On a deployment without a tenant registry — every venture `fz
    /// build` generates — the two are the same set: there is one tenant,
    /// so every subject the verifier accepts is a member of it. On a
    /// deployment with a registry they are not, and a subject of one
    /// tenant reaches another's rows by sending the same credential to
    /// its host. Issue #385 carries the analysis and the options.
    TenantMembers,
    /// Only an admin token, the same one `require_admin` checks.
    Admin,
}

impl Access {
    /// The wire name, kebab-case like the manifest writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicRead => "public-read",
            Self::Owner => "owner",
            Self::TenantMembers => "tenant-members",
            Self::Admin => "admin",
        }
    }

    /// Whether this level needs the table to name whose each row is.
    #[must_use]
    pub const fn needs_a_subject(self) -> bool {
        match self {
            Self::Owner => true,
            Self::PublicRead | Self::TenantMembers | Self::Admin => false,
        }
    }
}

impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every declared table's access level, keyed by table name.
pub type AccessMap = std::collections::BTreeMap<String, Access>;

/// The four, for an error message that lists them.
pub const LEVELS: &[&str] = &["public-read", "owner", "tenant-members", "admin"];

/// Checks every declared table has a level, and that the level is one the
/// table can actually enforce.
pub(crate) fn validate(
    tables: &cratefield_tables::Schema,
    access: &AccessMap,
    privacy: &crate::privacy::TablePrivacyMap,
    problems: &mut Vec<String>,
) {
    for table in &tables.tables {
        let Some(level) = access.get(&table.name) else {
            problems.push(format!(
                "table `{}` does not say who may reach it; add `access` to \
                 [tables.{}] — one of {}",
                table.name,
                table.name,
                LEVELS.join(", ")
            ));
            continue;
        };
        if level.needs_a_subject() {
            // `owner` matches the caller against the column the privacy
            // declaration names. Without one there is nothing to match,
            // and a route that fell back to "everyone" or "nobody" would
            // be deciding that here, silently.
            let names_a_subject = matches!(
                privacy.get(&table.name),
                Some(crate::privacy::TablePrivacy::Personal { .. })
            );
            if !names_a_subject {
                problems.push(format!(
                    "table `{}`: `access = \"{level}\"` needs the table to say whose each row \
                     is, and its privacy block says it holds nothing personal — there is no \
                     column to match a caller against",
                    table.name
                ));
            }
        }
    }
    for name in access.keys() {
        if tables.table(name).is_none() {
            problems.push(format!(
                "access is declared for `{name}`, which is not a declared table"
            ));
        }
    }
}
