//! What changed about who may reach a declared table, and what it holds
//! (issue #153).
//!
//! `cratefield_tables::diff` answers the schema question — what does this
//! edit cost to apply to a database. It is the wrong question on its own.
//! Flipping one table from `access = "owner"` to `access = "public-read"`
//! changes no column, so the schema diff reports nothing, and
//! `fz tables diff` said *"No change: both declare the same 1 table(s)"*
//! and exited zero — for an edit that publishes every subject's private
//! rows.
//!
//! So this is the other half: the declaration diff. It compares the
//! access levels and the privacy blocks, which are the two parts of a
//! `[tables]` section that decide who sees what rather than what the
//! database holds.
//!
//! # The rank, and what it is not
//!
//! [`Move`] says whether an access change widens or narrows reach, from a
//! rank over the four levels:
//!
//! | rank | level | who reaches which rows |
//! |---|---|---|
//! | 0 | `admin` | operators, every row |
//! | 1 | `owner` | every signed-in caller, their own rows |
//! | 2 | `tenant-members` | every signed-in caller, every row |
//! | 3 | `public-read` | everybody, every row |
//!
//! It is a rank for choosing a word in a report, not a lattice. `admin`
//! sits at the bottom because moving off it is the moment somebody who is
//! not an operator can reach the table at all — which is the thing a
//! reviewer is looking for — even though an admin sees more rows than an
//! owner does.
//!
//! The rank reads the level off the manifest, and the manifest does not
//! know the deployment's tenancy: `owner` → `tenant-members` reports
//! [`Move::Widens`] even on a deployment whose tenants come from a
//! registry, where the serving layer refuses the level for everybody
//! (issue #385). The word describes the direction of the edit, not the
//! rows anyone will get.

use crate::access::{Access, AccessMap};
use crate::privacy::{TablePrivacy, TablePrivacyMap};

/// Which way an access change moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Move {
    /// More people reach the table, or the same people reach more rows.
    /// The direction worth stopping on.
    Widens,
    /// Fewer people, or fewer rows. Safe for the data and a breaking
    /// change for whatever was reading it.
    Narrows,
}

impl Move {
    /// The word a report prints.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Widens => "widens",
            Self::Narrows => "narrows",
        }
    }
}

impl std::fmt::Display for Move {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One difference between two versions of a `[tables]` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// A table's access level changed.
    Access {
        /// The table.
        table: String,
        /// What it was.
        from: Access,
        /// What it is now.
        to: Access,
        /// Which way reach moved.
        direction: Move,
    },
    /// A table's privacy declaration changed.
    Privacy {
        /// The table.
        table: String,
        /// What changed, in a sentence for a reviewer.
        detail: String,
    },
}

impl Change {
    /// The table this is about.
    #[must_use]
    pub fn table(&self) -> &str {
        match self {
            Self::Access { table, .. } | Self::Privacy { table, .. } => table,
        }
    }

    /// A line for a report.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Self::Access {
                table,
                from,
                to,
                direction,
            } => format!("`{table}`: access {from} -> {to} ({direction} reach)"),
            Self::Privacy { table, detail } => format!("`{table}`: {detail}"),
        }
    }
}

/// Where a level sits on the reach rank. See the module docs.
///
/// No wildcard arm. `Access` is `#[non_exhaustive]`, which stops *other*
/// crates from matching exhaustively but not this one — it is declared
/// here. So a level added later fails to compile until somebody decides
/// where it sits, which is the right place for that decision: a default
/// would silently call a move onto an unranked level safe.
const fn rank(access: Access) -> u8 {
    match access {
        Access::Admin => 0,
        Access::Owner => 1,
        Access::TenantMembers => 2,
        Access::PublicRead => 3,
    }
}

/// Every difference in access and privacy between two declarations.
///
/// Tables added or removed are not reported here: the schema diff already
/// says a table arrived or left, and repeating it would double every such
/// line in a report that prints both.
#[must_use]
pub fn diff(
    previous_access: &AccessMap,
    current_access: &AccessMap,
    previous_privacy: &TablePrivacyMap,
    current_privacy: &TablePrivacyMap,
) -> Vec<Change> {
    let mut changes = Vec::new();
    for (table, to) in current_access {
        let Some(from) = previous_access.get(table) else {
            continue;
        };
        if from != to {
            changes.push(Change::Access {
                table: table.clone(),
                from: *from,
                to: *to,
                direction: if rank(*to) > rank(*from) {
                    Move::Widens
                } else {
                    Move::Narrows
                },
            });
        }
    }
    for (table, to) in current_privacy {
        let Some(from) = previous_privacy.get(table) else {
            continue;
        };
        for detail in privacy_details(from, to) {
            changes.push(Change::Privacy {
                table: table.clone(),
                detail,
            });
        }
    }
    changes.sort_by(|a, b| a.table().cmp(b.table()));
    changes
}

/// What changed between two privacy declarations, one sentence each.
fn privacy_details(from: &TablePrivacy, to: &TablePrivacy) -> Vec<String> {
    match (from, to) {
        (TablePrivacy::Nothing { reason: was }, TablePrivacy::Nothing { reason })
            if was != reason =>
        {
            vec![format!(
                "the reason it holds nothing changed to {reason:?} — that sentence is what tells a \
             reader this table was considered rather than overlooked"
            )]
        }
        (TablePrivacy::Nothing { .. }, TablePrivacy::Nothing { .. }) => Vec::new(),
        // The two that change what erasure and export do to the table.
        (TablePrivacy::Nothing { .. }, TablePrivacy::Personal { subject, .. }) => vec![format!(
            "now holds personal data, subject column `{subject}` — it enters export and erasure"
        )],
        (TablePrivacy::Personal { .. }, TablePrivacy::Nothing { reason }) => vec![format!(
            "no longer declares personal data ({reason:?}) — it leaves export and erasure, and \
             an erasure that would have cleared it will not"
        )],
        (
            TablePrivacy::Personal {
                subject: was_subject,
                kind: was_kind,
                disposition: was_disposition,
                description: was_description,
                redacted: was_redacted,
            },
            TablePrivacy::Personal {
                subject,
                kind,
                disposition,
                description,
                redacted,
            },
        ) => {
            let mut details = Vec::new();
            if was_subject != subject {
                details.push(format!(
                    "the subject column changed from `{was_subject}` to `{subject}` — every row's \
                     owner is decided by a different column, and `access = \"owner\"` matches on it"
                ));
            }
            if was_kind != kind {
                details.push(format!("the data kind changed from {was_kind} to {kind}"));
            }
            if was_disposition != disposition {
                details.push(format!(
                    "what erasure does changed from {was_disposition:?} to {disposition:?}"
                ));
            }
            if was_description != description {
                details.push(
                    "the description changed — it is published verbatim to the person asking"
                        .to_owned(),
                );
            }
            if was_redacted != redacted {
                details.push(format!(
                    "the redacted columns changed from {was_redacted:?} to {redacted:?}"
                ));
            }
            details
        }
    }
}
