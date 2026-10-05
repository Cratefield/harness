//! Dispositions: the per-item decision every needs-work and blocker item
//! needs before cutover (ADR 0026, Decision 5).
//!
//! An inspect report is complete but undecided: each item that is not
//! automatic needs its own entry saying it is *covered* (with a `ref` to the
//! code or test that replaces it) or *waived* (with a `reason`). The file is
//! TOML, keyed by the finding `id` from the report verbatim:
//!
//! ```toml
//! [items."policy:public.posts.Anyone can read posts"]
//! status = "waived"
//! reason = "public feed by design"
//!
//! [items."function:public.handle_new_user()"]
//! status = "covered"
//! ref = "src/auth/hooks.rs#on_signup"
//! ```
//!
//! Never in bulk: an entry key with a glob wildcard (`*`) is refused, because
//! each policy is its own line (ADR 0026, Decision 5); a `?` is a literal, as
//! it can appear in a policy name. [`skeleton`] writes one placeholder block
//! per undecided item to fill in.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::report::{
    Classification, DecidedItem, Disposition, DispositionsReport, KindDispositions, Report,
};

/// The dispositions file: one `[items."<finding id>"]` table per item.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispositionsFile {
    /// Every entry, keyed by the finding `id` verbatim.
    #[serde(default)]
    pub items: BTreeMap<String, Entry>,
}

/// One item's disposition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// `covered`, `waived` or `undecided` (the skeleton's placeholder).
    pub status: Status,
    /// The code or test that covers it; required for `covered`.
    #[serde(default, rename = "ref")]
    pub reference: String,
    /// Why it is waived; required for `waived`.
    #[serde(default)]
    pub reason: String,
}

/// What an entry decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Code and a test now do what the item did.
    Covered,
    /// Deliberately not replaced, with a reason.
    Waived,
    /// A placeholder: still to be decided.
    Undecided,
}

/// Why a dispositions file was refused.
#[derive(Debug, thiserror::Error)]
pub enum DispositionsError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The path that could not be read.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The text is not TOML, or has a field the format does not know. The
    /// message is the TOML parser's.
    #[error("{path} is not a dispositions file: {message}")]
    Parse {
        /// Where the text came from (a path, or "the dispositions file").
        path: String,
        /// The TOML error's own text.
        message: String,
    },
    /// A key is a glob wildcard, which ADR 0026 forbids.
    #[error(
        "{id:?} uses a wildcard: each item needs its own disposition, never in bulk (ADR 0026, \
         Decision 5)"
    )]
    Wildcard {
        /// The offending key.
        id: String,
    },
    /// A key is not a finding id.
    #[error(
        "{id:?} is not a finding id: use the report's `id` field, as in \
         `policy:public.posts.Anyone can read posts`"
    )]
    NotAnId {
        /// The offending key.
        id: String,
    },
    /// A waived entry has no reason.
    #[error("{id:?} is waived without a reason")]
    WaivedWithoutReason {
        /// The offending key.
        id: String,
    },
    /// A covered entry has no reference.
    #[error("{id:?} is covered without a `ref`")]
    CoveredWithoutRef {
        /// The offending key.
        id: String,
    },
}

impl DispositionsFile {
    /// Parses and validates the file's text.
    ///
    /// # Errors
    ///
    /// [`DispositionsError`]: a TOML error, or a refusal naming the entry
    /// (a wildcard key, a key that is not a finding id, a waived entry with
    /// no reason, a covered entry with no `ref`).
    pub fn parse(text: &str) -> Result<Self, DispositionsError> {
        Self::from_text(text, "the dispositions file")
    }

    /// Reads, parses and validates the file at `path`.
    ///
    /// # Errors
    ///
    /// [`DispositionsError`] as for [`parse`](Self::parse), or a read error.
    pub fn load(path: &Path) -> Result<Self, DispositionsError> {
        let text = std::fs::read_to_string(path).map_err(|source| DispositionsError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_text(&text, &path.display().to_string())
    }

    fn from_text(text: &str, path: &str) -> Result<Self, DispositionsError> {
        let file: Self = toml::from_str(text).map_err(|error| DispositionsError::Parse {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
        file.validate()?;
        Ok(file)
    }

    fn validate(&self) -> Result<(), DispositionsError> {
        for (id, entry) in &self.items {
            if id.contains('*') {
                return Err(DispositionsError::Wildcard { id: id.clone() });
            }
            if !id.contains(':') {
                return Err(DispositionsError::NotAnId { id: id.clone() });
            }
            match entry.status {
                Status::Waived if entry.reason.trim().is_empty() => {
                    return Err(DispositionsError::WaivedWithoutReason { id: id.clone() });
                }
                Status::Covered if entry.reference.trim().is_empty() => {
                    return Err(DispositionsError::CoveredWithoutRef { id: id.clone() });
                }
                Status::Covered | Status::Waived | Status::Undecided => {}
            }
        }
        Ok(())
    }
}

/// Applies a file to a report: sets each needs-work and blocker finding's
/// decision, each policy's own `disposition`, the summary's `decided` and
/// `undecided` counts, and the report's `dispositions` section.
///
/// An item with no entry (or an `undecided` one) is undecided; an entry that
/// matches no item that needs a disposition is stale. Applying an empty file
/// is how a report with no file at all still carries the section.
pub fn apply(report: &mut Report, file: &DispositionsFile) {
    let mut by_kind: BTreeMap<String, KindDispositions> = BTreeMap::new();
    let mut decided = Vec::new();
    let mut decided_status: BTreeMap<String, Disposition> = BTreeMap::new();
    let mut needed: BTreeSet<String> = BTreeSet::new();
    let mut undecided = 0;

    for finding in &report.findings {
        if finding.classification == Classification::Automatic {
            continue;
        }
        needed.insert(finding.id.clone());
        let disposition = file
            .items
            .get(&finding.id)
            .map_or(Disposition::Undecided, |entry| match entry.status {
                Status::Covered => Disposition::Covered,
                Status::Waived => Disposition::Waived,
                Status::Undecided => Disposition::Undecided,
            });
        let counts = by_kind
            .entry(finding.kind.clone())
            .or_insert_with(|| KindDispositions {
                kind: finding.kind.clone(),
                covered: 0,
                waived: 0,
                undecided: 0,
            });
        match disposition {
            Disposition::Covered => counts.covered += 1,
            Disposition::Waived => counts.waived += 1,
            Disposition::Undecided => {
                counts.undecided += 1;
                undecided += 1;
            }
        }
        if disposition != Disposition::Undecided {
            let entry = &file.items[&finding.id];
            decided_status.insert(finding.id.clone(), disposition);
            // Only the field the status uses: `ref` for covered, `reason` for
            // waived. The other is left absent.
            let (reference, reason) = match disposition {
                Disposition::Covered => (non_blank(&entry.reference), None),
                Disposition::Waived | Disposition::Undecided => (None, non_blank(&entry.reason)),
            };
            decided.push(DecidedItem {
                id: finding.id.clone(),
                status: disposition,
                reference,
                reason,
            });
        }
    }
    decided.sort_by(|a, b| a.id.cmp(&b.id));

    // The policy list carries the same decision in its own field.
    for policy in &mut report.policies {
        let id = format!("policy:{}.{}.{}", policy.schema, policy.table, policy.name);
        policy.disposition = decided_status
            .get(&id)
            .copied()
            .unwrap_or(Disposition::Undecided);
    }

    report.summary.decided = decided.len();
    report.summary.undecided = undecided;
    report.dispositions = DispositionsReport {
        by_kind: by_kind.into_values().collect(),
        decided,
        stale: file
            .items
            .keys()
            .filter(|id| !needed.contains(*id))
            .cloned()
            .collect(),
    };
}

/// A skeleton file: a short header and one placeholder `[items."<id>"]`
/// block per item still to decide. It parses with
/// [`DispositionsFile::parse`] and, applied, leaves everything undecided.
#[must_use]
pub fn skeleton(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(
        "# Dispositions for the Supabase import (ADR 0026, Decision 5).\n\
         #\n\
         # One entry per item that needs work or is a blocker, keyed by the finding\n\
         # id from the report. `covered` needs a `ref` to the code or test that\n\
         # covers it; `waived` needs a `reason`. No wildcards: each item is its\n\
         # own line. See docs/import/supabase.md.\n",
    );
    for finding in &report.findings {
        if finding.classification == Classification::Automatic {
            continue;
        }
        if report
            .dispositions
            .decided
            .iter()
            .any(|decided| decided.id == finding.id)
        {
            continue;
        }
        let _ = write!(
            out,
            "\n# {} ({}): {}\n[items.{}]\nstatus = \"undecided\"\nref = \"\"\nreason = \"\"\n",
            finding.kind,
            finding.classification.label(),
            one_line(&finding.reason),
            quoted(&finding.id),
        );
    }
    out
}

/// A single-line TOML basic string, quoted, for a key or a value alike.
///
/// `\\`, `"` and the control characters are escaped, so the result is always
/// one line and can never become a multi-line string (`"""…"""`) or break out
/// of a `[items.<key>]` header.
fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            // Other C0 controls and DEL, which TOML forbids unescaped.
            character if character.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(character));
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

/// One comment line: no newline can break out of it.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn non_blank(text: &str) -> Option<String> {
    (!text.trim().is_empty()).then(|| text.to_owned())
}
