//! What changed between two versions of a declaration, and what each
//! change costs (issue #153).
//!
//! Everything this crate renders only creates. That is the right default
//! — a generated `ALTER` is a generated guess about data nobody here can
//! see — but it leaves the author of a `[tables]` section with no answer
//! to the question they actually have, which is *"can I ship this?"*
//!
//! `docs/ROLLBACK.md` §5 already decides the vocabulary, so this speaks
//! it rather than inventing one:
//!
//! - **Expand** — the change is additive. The old code keeps working
//!   against the new schema, and a rollback stays free.
//! - **Contract** — the change removes something. It is safe only once no
//!   deployed build reads it, and after it a rollback past the switch is
//!   not available. That is the trade, and it is the author's to accept.
//! - **Rewrite** — the change cannot be expressed forward-only against
//!   rows that already exist. Adding a `NOT NULL` column with no default
//!   to a table with rows in it does not fail *later*, it fails; so does
//!   narrowing a bound that existing rows already violate.
//!
//! **Nothing here refuses anything.** A diff is a report: the declaration
//! rules in `Schema::validate` say what is legal, and this says what it
//! costs. Refusing a contract would make the tool wrong for the case the
//! discipline exists to serve — dropping a column on purpose, in its own
//! migration, once nothing reads it.

use std::collections::BTreeMap;

use crate::schema::{FieldDef, FieldKind, ForeignKey, Schema, TableDef};

/// What a change costs, in `docs/ROLLBACK.md` §5's vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
// The set will grow — a move between tables is neither of the three — and
// a new variant in an exhaustive public enum is a breaking change for
// every downstream `match`.
#[non_exhaustive]
pub enum Step {
    /// Additive. The old build keeps working; a rollback stays free.
    Expand,
    /// Removes something. Safe once nothing deployed reads it, and a
    /// rollback past the switch is gone afterwards.
    Contract,
    /// Cannot be applied forward-only to rows that already exist.
    Rewrite,
}

impl Step {
    /// The wire form, lowercase and stable.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Expand => "expand",
            Self::Contract => "contract",
            Self::Rewrite => "rewrite",
        }
    }
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One difference between two declarations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Change {
    /// The table it happened to.
    pub table: String,
    /// The field, when the change is a field's.
    pub field: Option<String>,
    pub step: Step,
    /// One line for the person deciding whether to ship it. Written for
    /// them, so it says what will happen rather than naming a rule.
    pub detail: String,
}

impl Change {
    fn table(table: &str, step: Step, detail: impl Into<String>) -> Self {
        Self {
            table: table.to_owned(),
            field: None,
            step,
            detail: detail.into(),
        }
    }

    fn field(table: &str, field: &str, step: Step, detail: impl Into<String>) -> Self {
        Self {
            table: table.to_owned(),
            field: Some(field.to_owned()),
            step,
            detail: detail.into(),
        }
    }

    /// `table.field: detail`, or `table: detail` for a whole table.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.field {
            Some(field) => format!("{}.{field}: {}", self.table, self.detail),
            None => format!("{}: {}", self.table, self.detail),
        }
    }
}

/// Every difference from `previous` to `current`, tables in name order and
/// fields in the order the new declaration lists them.
///
/// Deterministic: the same pair always produces the same list, so a drift
/// check can compare two runs.
#[must_use]
pub fn diff(previous: &Schema, current: &Schema) -> Vec<Change> {
    let before: BTreeMap<&str, &TableDef> = previous
        .tables
        .iter()
        .map(|table| (table.name.as_str(), table))
        .collect();
    let after: BTreeMap<&str, &TableDef> = current
        .tables
        .iter()
        .map(|table| (table.name.as_str(), table))
        .collect();

    let mut changes = Vec::new();
    for (name, table) in &after {
        match before.get(name) {
            None => changes.push(Change::table(
                name,
                Step::Expand,
                format!("new table with {} fields", table.fields.len()),
            )),
            Some(old) => table_changes(old, table, &mut changes),
        }
    }
    for name in before.keys() {
        if !after.contains_key(name) {
            changes.push(Change::table(
                name,
                Step::Contract,
                "table is gone; every row in it goes with it",
            ));
        }
    }
    changes.sort_by(|a, b| (&a.table, &a.field).cmp(&(&b.table, &b.field)));
    changes
}

fn table_changes(old: &TableDef, new: &TableDef, out: &mut Vec<Change>) {
    if old.primary_key != new.primary_key {
        out.push(Change::table(
            &new.name,
            Step::Rewrite,
            format!(
                "primary key changes from ({}) to ({}); no engine alters one in place",
                old.primary_key.join(", "),
                new.primary_key.join(", ")
            ),
        ));
    }
    foreign_key_changes(old, new, out);

    let before: BTreeMap<&str, &FieldDef> = old
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field))
        .collect();
    for field in &new.fields {
        match before.get(field.name.as_str()) {
            None => out.push(added_field(&new.name, field)),
            Some(old_field) => field_changes(&new.name, old_field, field, out),
        }
    }
    for field in &old.fields {
        if !new.fields.iter().any(|kept| kept.name == field.name) {
            out.push(Change::field(
                &new.name,
                &field.name,
                Step::Contract,
                "column is gone; the values in it go with it",
            ));
        }
    }
}

/// A new column is additive **unless the database would have to invent a
/// value for the rows already there.** `NOT NULL` with no default is
/// exactly that case, and it is the one an author hits first.
fn added_field(table: &str, field: &FieldDef) -> Change {
    if field.required && field.default.is_none() {
        return Change::field(
            table,
            &field.name,
            Step::Rewrite,
            "new required column with no default; every existing row would need a value",
        );
    }
    if field.unique {
        return Change::field(
            table,
            &field.name,
            Step::Rewrite,
            "new unique column; existing rows would all take the same value and collide",
        );
    }
    Change::field(table, &field.name, Step::Expand, "new optional column")
}

fn field_changes(table: &str, old: &FieldDef, new: &FieldDef, out: &mut Vec<Change>) {
    if std::mem::discriminant(&old.kind) == std::mem::discriminant(&new.kind) {
        kind_changes(table, &old.kind, &new.kind, &new.name, out);
    } else {
        out.push(Change::field(
            table,
            &new.name,
            Step::Rewrite,
            format!(
                "type changes from {} to {}; the values already stored are the old type",
                old.kind.as_str(),
                new.kind.as_str()
            ),
        ));
    }

    match (old.required, new.required) {
        (false, true) => out.push(Change::field(
            table,
            &new.name,
            Step::Rewrite,
            "column becomes required; rows that left it empty have nothing to put there",
        )),
        (true, false) => out.push(Change::field(
            table,
            &new.name,
            Step::Expand,
            "column becomes optional",
        )),
        _ => {}
    }

    match (old.unique, new.unique) {
        (false, true) => out.push(Change::field(
            table,
            &new.name,
            Step::Rewrite,
            "column becomes unique; the rows already there may hold duplicates",
        )),
        (true, false) => out.push(Change::field(
            table,
            &new.name,
            Step::Expand,
            "column stops being unique",
        )),
        _ => {}
    }

    if old.indexed != new.indexed {
        // An index is the one thing here that costs nothing either way:
        // it holds no data and both engines build and drop them online.
        let detail = if new.indexed {
            "indexed"
        } else {
            "no longer indexed"
        };
        out.push(Change::field(table, &new.name, Step::Expand, detail));
    }

    if old.default != new.default {
        // A default is read when a write omits the column, so it reaches
        // new rows only. The rows already there keep what they have,
        // which is why this is additive and why it is worth saying.
        out.push(Change::field(
            table,
            &new.name,
            Step::Expand,
            "default changes; rows already written keep the value they have",
        ));
    }
}

/// Bounds and enum members: widening is additive, narrowing is not,
/// because the rows already stored were written under the old rule.
fn kind_changes(table: &str, old: &FieldKind, new: &FieldKind, field: &str, out: &mut Vec<Change>) {
    match (old, new) {
        (
            FieldKind::Text {
                min_len: old_min,
                max_len: old_max,
                format: old_format,
            },
            FieldKind::Text {
                min_len: new_min,
                max_len: new_max,
                format: new_format,
            },
        ) => {
            bounds(
                table, field, *old_min, *new_min, *old_max, *new_max, "length ", out,
            );
            if old_format != new_format {
                // A format is checked on write, so requiring one leaves
                // stored values that were never checked against it.
                let (step, detail) = if new_format.is_some() {
                    (
                        Step::Rewrite,
                        "a format is required now; stored values were not checked against it",
                    )
                } else {
                    (Step::Expand, "the format requirement is gone")
                };
                out.push(Change::field(table, field, step, detail));
            }
        }
        (
            FieldKind::Integer {
                min: old_min,
                max: old_max,
            },
            FieldKind::Integer {
                min: new_min,
                max: new_max,
            },
        ) => bounds(
            table, field, *old_min, *new_min, *old_max, *new_max, "", out,
        ),
        (
            FieldKind::Real {
                min: old_min,
                max: old_max,
            },
            FieldKind::Real {
                min: new_min,
                max: new_max,
            },
        ) => bounds(
            table, field, *old_min, *new_min, *old_max, *new_max, "", out,
        ),
        (FieldKind::Enum { values: old_values }, FieldKind::Enum { values: new_values }) => {
            enum_changes(table, field, old_values, new_values, out);
        }
        // Every other kind carries nothing to widen or narrow.
        _ => {}
    }
}

/// One report for a pair of bounds. Narrowing either end is a rewrite,
/// because a row written under the old rule may already sit outside the
/// new one; widening is additive and worth saying so.
#[allow(clippy::too_many_arguments)]
fn bounds<T: PartialOrd + Copy>(
    table: &str,
    field: &str,
    old_min: Option<T>,
    new_min: Option<T>,
    old_max: Option<T>,
    new_max: Option<T>,
    what: &str,
    out: &mut Vec<Change>,
) {
    if narrows(old_min, new_min, Bound::Lower) || narrows(old_max, new_max, Bound::Upper) {
        out.push(Change::field(
            table,
            field,
            Step::Rewrite,
            format!("{what}bounds narrow; stored values may already be outside them"),
        ));
    } else if !same(old_min, new_min) || !same(old_max, new_max) {
        out.push(Change::field(
            table,
            field,
            Step::Expand,
            format!("{what}bounds widen"),
        ));
    }
}

/// `Real`'s bounds are floats, so this compares with `PartialOrd` rather
/// than `PartialEq` on `Option` — a `f64` is not `Eq`.
fn same<T: PartialOrd>(a: Option<T>, b: Option<T>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn enum_changes(
    table: &str,
    field: &str,
    old_values: &[String],
    new_values: &[String],
    out: &mut Vec<Change>,
) {
    let removed: Vec<&String> = old_values
        .iter()
        .filter(|value| !new_values.contains(value))
        .collect();
    if !removed.is_empty() {
        out.push(Change::field(
            table,
            field,
            Step::Rewrite,
            format!(
                "enum drops {}; rows already holding one would fail the new CHECK",
                removed
                    .iter()
                    .map(|value| format!("`{value}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    let added = new_values
        .iter()
        .filter(|value| !old_values.contains(value))
        .count();
    if added > 0 {
        out.push(Change::field(
            table,
            field,
            Step::Expand,
            format!("enum gains {added} value(s)"),
        ));
    }
}

#[derive(Clone, Copy)]
enum Bound {
    Lower,
    Upper,
}

/// Whether a bound got stricter. Adding a bound where there was none is
/// always stricter: `None` admits everything.
fn narrows<T: PartialOrd>(old: Option<T>, new: Option<T>, which: Bound) -> bool {
    match (old, new) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(old), Some(new)) => match which {
            Bound::Lower => new > old,
            Bound::Upper => new < old,
        },
    }
}

fn foreign_key_changes(old: &TableDef, new: &TableDef, out: &mut Vec<Change>) {
    let same = |a: &ForeignKey, b: &ForeignKey| a.field == b.field && a.references == b.references;
    for key in &new.foreign_keys {
        if !old.foreign_keys.iter().any(|had| same(had, key)) {
            out.push(Change::field(
                &new.name,
                &key.field,
                Step::Rewrite,
                format!(
                    "new reference to `{}`; rows already there may point at nothing",
                    key.references
                ),
            ));
        }
    }
    for key in &old.foreign_keys {
        if !new.foreign_keys.iter().any(|kept| same(kept, key)) {
            out.push(Change::field(
                &new.name,
                &key.field,
                Step::Expand,
                format!("reference to `{}` is gone", key.references),
            ));
        }
    }
}
