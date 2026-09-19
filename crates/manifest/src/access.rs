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
    /// so every subject the verifier accepts is a member of it, and the
    /// level serves as named. On a deployment with a registry they are
    /// not, and the serving layer refuses the level outright rather than
    /// guess who is a member: `500 no-membership-fact`, at every host,
    /// the caller's own included.
    ///
    /// This crate sees none of that. A manifest does not name the
    /// deployment's tenancy, so `validate` cannot reject the level the
    /// way it rejects `owner` on a table with no subject — whether the
    /// level can be honoured is a fact about the deployment, not the
    /// manifest — and the refusal can only happen at request time.
    /// Issue #385 stays open for the real answer: a tenant claim on
    /// `Subject`, populated by the verifier and checked against the
    /// tenant the request resolved to.
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

/// Declares [`LEVELS`] and, from the same list, a match that has to be
/// exhaustive.
///
/// `LEVELS` is the menu an author is offered when they leave `access`
/// out. A level missing from it is one the harness enforces and the
/// error message never mentions, which is the worst way to learn a
/// vocabulary — so the list and the type come from one place.
macro_rules! levels {
    ($($variant:ident => $wire:literal),+ $(,)?) => {
        /// Every level, for an error message that lists them.
        pub const LEVELS: &[&str] = &[$($wire),+];

        /// Never called. It exists so that a variant absent from the list
        /// above is a compile error here, and so that the wire name in it
        /// is the one [`Access::as_str`] answers.
        #[expect(dead_code, reason = "its only job is to be exhaustive")]
        fn every_level_is_listed(access: Access) -> &'static str {
            match access {
                $(Access::$variant => {
                    debug_assert_eq!(Access::$variant.as_str(), $wire);
                    $wire
                }),+
                // No wildcard. `Access` is `#[non_exhaustive]`, which
                // does not make an in-crate match non-exhaustive — one
                // here would be unreachable and would quietly take away
                // the only thing this function does.
            }
        }
    };
}

levels!(
    PublicRead => "public-read",
    Owner => "owner",
    TenantMembers => "tenant-members",
    Admin => "admin",
);

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
