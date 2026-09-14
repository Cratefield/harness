//! What a declared table holds, said by the author who declared it
//! (issue #153).
//!
//! Every table a module owns carries a
//! `cratefield_core::PersonalDataSet`: whose the rows
//! are, what erasure does to them, and a sentence published verbatim to
//! the person asking. A table a *venture* declares in its `[tables]`
//! section has no module to carry one, and the harness has no way to
//! guess — so this is where the author says.
//!
//! **It is required, and there is no default.** The two defaults on offer
//! were both wrong:
//!
//! - *"Nothing personal unless you say otherwise"* puts a venture's own
//!   tables outside `fz data export`, outside subject access and outside
//!   erasure, silently. That is the exact hole `auth-core`'s
//!   `deletion_jobs` sat in (#272), and it was found by someone reading
//!   the list rather than by anything failing.
//! - *"Personal unless you say otherwise"* makes an erasure delete a
//!   venture's reference data the first time somebody asks.
//!
//! So a `[tables.x]` section without a `[tables.x.privacy]` block is a
//! manifest error. Saying a table holds nothing is one line, and it is a
//! decision rather than a silence.
//!
//! The vocabulary mirrors `cratefield_core`'s, because that is what the
//! generated module will emit and a second vocabulary would be a second
//! thing to keep in step. The owned `String`s here become `&'static str`
//! literals in generated source, which is why this can mirror a type
//! whose fields are all `'static`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What one declared table holds.
///
/// Internally tagged on `holds`, so a typo in a key is an error about
/// that key rather than a silent fall through to the other shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "holds", rename_all = "snake_case", deny_unknown_fields)]
pub enum TablePrivacy {
    /// Nothing about anybody, and the reason.
    ///
    /// The reason is the point: "no declaration" and "nothing personal
    /// here" look identical in a manifest, and only one of them is a
    /// decision.
    Nothing {
        /// Why nobody is in it. Published, so write it for a reader.
        reason: String,
    },
    /// Somebody's, with the column that says whose and what erasure does.
    Personal {
        /// The column holding the subject's id — the value export and
        /// erasure match on.
        subject: String,
        /// `contact`, `identifier`, `fitness`, `usage`, `content` or
        /// `financial`, the vocabulary `cratefield_core`'s `DataKind` uses.
        kind: String,
        /// `erase`, `{ anonymise = ["col", ...] }` or
        /// `{ retain = "why" }`.
        disposition: Disposition,
        /// One sentence, published verbatim to the person asking. Write
        /// it for them rather than for a colleague.
        description: String,
        /// Columns an export names but never copies, because the value
        /// is credential material.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        redacted: Vec<String>,
    },
}

/// What erasure does to the rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// The rows go. The ordinary case.
    Erase,
    /// The rows stay and the named columns are overwritten, because
    /// removing them would break an aggregate.
    Anonymise(Vec<String>),
    /// The rows stay whole, and this says why in a sentence a regulator
    /// could read.
    Retain(String),
}

/// Every declared table's privacy declaration, keyed by table name.
pub type TablePrivacyMap = BTreeMap<String, TablePrivacy>;

/// The `kind` values [`TablePrivacy::Personal`] accepts, matching
/// `cratefield_core`'s `DataKind` wire names.
pub const KINDS: &[&str] = &[
    "contact",
    "identifier",
    "fitness",
    "usage",
    "content",
    "financial",
];

/// Checks the declarations against the tables they describe, collecting
/// every problem the way the rest of the manifest does.
///
/// The rules, and each is a promise the declaration makes about a column
/// that has to exist for the promise to mean anything:
///
/// - every declared table has a declaration, and every declaration names
///   a declared table;
/// - `subject` names a field of that table;
/// - the columns `anonymise` names are fields of that table, and each is
///   optional or defaulted — overwriting a `NOT NULL` column with nothing
///   is not a thing a database will do;
/// - `redacted` names fields of that table;
/// - `kind` is one of [`KINDS`];
/// - the sentences are not empty, because an empty one is published to
///   the person asking.
pub(crate) fn validate(
    tables: &cratefield_tables::Schema,
    privacy: &TablePrivacyMap,
    problems: &mut Vec<String>,
) {
    for table in &tables.tables {
        let Some(declaration) = privacy.get(&table.name) else {
            problems.push(format!(
                "table `{}` does not say what it holds; add a [tables.{}.privacy] block \
                 (`holds = \"nothing\"` with a reason, or `holds = \"personal\"` with a \
                 subject column)",
                table.name, table.name
            ));
            continue;
        };
        check_one(table, declaration, problems);
    }
    for name in privacy.keys() {
        if tables.table(name).is_none() {
            problems.push(format!(
                "privacy is declared for `{name}`, which is not a declared table"
            ));
        }
    }
}

fn check_one(
    table: &cratefield_tables::TableDef,
    declaration: &TablePrivacy,
    problems: &mut Vec<String>,
) {
    let has = |name: &str| table.fields.iter().any(|field| field.name == name);
    let at = &table.name;
    match declaration {
        TablePrivacy::Nothing { reason } => {
            plain_prose(at, "reason", reason, problems);
            if reason.trim().is_empty() {
                problems.push(format!(
                    "table `{at}`: `holds = \"nothing\"` needs a reason — the reason is what \
                     makes it a decision rather than a silence"
                ));
            }
        }
        TablePrivacy::Personal {
            subject,
            kind,
            disposition,
            description,
            redacted,
        } => {
            match table.fields.iter().find(|field| &field.name == subject) {
                None => problems.push(format!(
                    "table `{at}`: the subject column `{subject}` is not a field of it"
                )),
                // A subject is a caller's id, which is a string out of a
                // verified credential. A column that cannot hold one
                // makes every scoped read fail while the statement is
                // built — a 400 blaming the caller for a filter they did
                // not send, and naming the table's subject column in the
                // detail — rather than failing here, where the mistake
                // is.
                Some(field) if !field.kind.can_hold_a_subject() => problems.push(format!(
                    "table `{at}`: the subject column `{subject}` is {}, which cannot hold a \
                     caller's id — a subject column is `text` or `uuid`",
                    field.kind.as_str()
                )),
                Some(_holds_a_subject) => {}
            }
            if !KINDS.contains(&kind.as_str()) {
                problems.push(format!(
                    "table `{at}`: `{kind}` is not a data kind; it is one of {}",
                    KINDS.join(", ")
                ));
            }
            plain_prose(at, "description", description, problems);
            if description.trim().is_empty() {
                problems.push(format!(
                    "table `{at}`: the description is published to the person asking and must \
                     not be empty"
                ));
            }
            for column in redacted {
                if !has(column) {
                    problems.push(format!(
                        "table `{at}`: `redacted` names `{column}`, which is not a field of it"
                    ));
                }
            }
            check_disposition(table, disposition, problems);
        }
    }
}

/// Prose an author writes that is both published to a person and
/// embedded in generated Rust source.
///
/// Two characters in it stop `fz build` working, and the failure lands
/// as a rustc error inside a file whose first line says not to edit it
/// by hand, with nothing pointing back at the manifest:
///
/// - a lone carriage return is `error: bare CR not allowed in raw
///   string` (CRLF compiles; the rule that allows one and not the other
///   is not one anybody can hold, so both are refused — a JSON string
///   cannot hold a real newline, so every `\r` in one was typed on
///   purpose and `\n` is what was meant);
/// - a codepoint that changes text direction is `error: unicode
///   codepoint changing visible direction of text present in literal`,
///   which rustc denies by default.
///
/// The second matters after the build too. This sentence is published
/// verbatim to the person asking what a venture holds about them, and a
/// direction override makes published text read as something other than
/// what it says — which is the whole of the Trojan Source class, pointed
/// at a privacy notice.
///
/// `\n` and `\t` are left alone: prose is allowed to have shape.
fn plain_prose(at: &str, field: &str, text: &str, problems: &mut Vec<String>) {
    for character in text.chars() {
        let why = match character {
            '\n' | '\t' => continue,
            '\r' => "a carriage return; write `\\n`",
            // U+200E/U+200F and the two embedding/override families.
            '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {
                "a codepoint that changes which direction text reads in"
            }
            other if other.is_control() => "a control character",
            _printable => continue,
        };
        problems.push(format!(
            "table `{at}`: the {field} contains U+{:04X}, {why} — it is published to the person \
             asking and written into generated source, so it is plain text",
            character as u32
        ));
        return;
    }
}

fn check_disposition(
    table: &cratefield_tables::TableDef,
    disposition: &Disposition,
    problems: &mut Vec<String>,
) {
    let at = &table.name;
    match disposition {
        Disposition::Erase => {}
        Disposition::Retain(reason) => {
            plain_prose(at, "retain reason", reason, problems);
            if reason.trim().is_empty() {
                problems.push(format!(
                    "table `{at}`: `retain` needs the reason the rows stay — it is the argument \
                     a regulator reads"
                ));
            }
        }
        Disposition::Anonymise(columns) => {
            if columns.is_empty() {
                problems.push(format!(
                    "table `{at}`: `anonymise` with no columns erases nothing; use `erase`, or \
                     name the columns that are overwritten"
                ));
            }
            for column in columns {
                let Some(field) = table.fields.iter().find(|field| &field.name == column) else {
                    problems.push(format!(
                        "table `{at}`: `anonymise` names `{column}`, which is not a field of it"
                    ));
                    continue;
                };
                // The same check `cratefield-module-privacy` makes
                // against the applied schema rather than trusting: a
                // column that is `NOT NULL` with no default cannot be
                // overwritten with nothing.
                if field.required && field.default.is_none() {
                    problems.push(format!(
                        "table `{at}`: `anonymise` names `{column}`, which is required and has \
                         no default — there is nothing to overwrite it with"
                    ));
                }
                if table.primary_key.iter().any(|key| key == column) {
                    problems.push(format!(
                        "table `{at}`: `anonymise` names `{column}`, which is part of the \
                         primary key"
                    ));
                }
            }
        }
    }
}
