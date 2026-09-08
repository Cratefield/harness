//! Row validation: one `serde_json` object against one [`TableDef`].
//!
//! The answer is a structured list, and the list renders into the
//! harness's existing RFC 9457 problem+json error rather than a new error
//! style: [`RowErrors`] converts to a
//! [`cratefield_core::Problem`] carrying the `validation-failed` slug
//! core already publishes, so a declared table's 400 looks exactly like a
//! module's.
//!
//! # The rules
//!
//! - **A row is a JSON object.** An array, a string or a number is one
//!   error against the row itself, reported with an empty field name,
//!   which is the RFC 6901 pointer to the whole document.
//! - **`null` is absence.** `{"note": null}` and `{}` are the same
//!   verdict, always. A field that must be present is missing in both;
//!   an optional field is satisfied by both. Nothing else in the crate
//!   distinguishes them, and a second implementation must not either.
//! - **A default satisfies `required`.** A write only has to carry a
//!   field that is required *and* has no default, because otherwise the
//!   database supplies the value.
//! - **An unknown key is an error.** A misspelled column that is silently
//!   dropped is a write that looks like it worked.
//! - **Nothing is coerced, nothing is trimmed, and length is counted in
//!   Unicode characters.** The full value rules are in
//!   [`check_value`](crate::check_value).
//! - **Uniqueness is not checked here.** It reads other rows, so it is
//!   the database's job. Foreign keys are the same.
//!
//! Errors come out in a fixed order: declared fields in declaration
//! order, then unknown keys sorted by name. A caller can compare two runs
//! and a second implementation can compare against the corpus.

use cratefield_core::Problem;
use serde_json::Value;
use std::fmt::Write as _;

use crate::schema::TableDef;
use crate::value::{ErrorCode, check_value};

/// The largest number of errors a problem `detail` spells out before it
/// summarises the rest. The structured list is never truncated.
pub const MAX_DETAIL_ERRORS: usize = 10;

/// One rejected field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowError {
    /// The declared field name, or an empty string for the row itself.
    pub field: String,
    /// The stable code a conformance case is matched on.
    pub code: ErrorCode,
    /// A line for a person, phrased to follow the field name.
    pub message: String,
}

impl RowError {
    fn new(field: impl Into<String>, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            code,
            message: message.into(),
        }
    }

    /// `field: message`, or just the message for the row itself.
    #[must_use]
    pub fn line(&self) -> String {
        if self.field.is_empty() {
            self.message.clone()
        } else {
            format!("{} {}", self.field, self.message)
        }
    }
}

/// Every reason a row was rejected, in a fixed order. Never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowErrors {
    errors: Vec<RowError>,
}

impl RowErrors {
    /// The rejections, declared fields in declaration order and then
    /// unknown keys sorted by name.
    #[must_use]
    pub fn errors(&self) -> &[RowError] {
        &self.errors
    }

    /// The problem `detail`: at most [`MAX_DETAIL_ERRORS`] lines joined
    /// with `; `, then a count of what was left out. The structured list
    /// keeps everything.
    #[must_use]
    pub fn detail(&self) -> String {
        let shown: Vec<String> = self
            .errors
            .iter()
            .take(MAX_DETAIL_ERRORS)
            .map(RowError::line)
            .collect();
        let mut detail = shown.join("; ");
        if self.errors.len() > MAX_DETAIL_ERRORS {
            let hidden = self.errors.len() - MAX_DETAIL_ERRORS;
            let _ = write!(detail, " (and {hidden} more)");
        }
        detail
    }

    /// The `400 validation-failed` problem core already publishes. No new
    /// slug: a declared table's rejection reads like a module's.
    #[must_use]
    pub fn problem(&self) -> Problem {
        Problem::validation_failed(self.detail())
    }
}

impl From<RowErrors> for Problem {
    fn from(errors: RowErrors) -> Self {
        errors.problem()
    }
}

impl std::fmt::Display for RowErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail())
    }
}

impl std::error::Error for RowErrors {}

/// Checks `row` against `table`.
///
/// # Errors
///
/// Every rejection, in the fixed order described on this module.
pub fn validate_row(table: &TableDef, row: &Value) -> Result<(), RowErrors> {
    let Some(object) = row.as_object() else {
        return Err(RowErrors {
            errors: vec![RowError::new(
                "",
                ErrorCode::NotAnObject,
                format!("the row must be a JSON object, not {}", type_name(row)),
            )],
        });
    };

    let mut errors = Vec::new();

    for field in &table.fields {
        // A missing key and a JSON null are the same thing: no value.
        match object.get(&field.name) {
            None | Some(Value::Null) => {
                if field.must_be_present() {
                    errors.push(RowError::new(
                        &field.name,
                        ErrorCode::Required,
                        "is required",
                    ));
                }
            }
            Some(value) => {
                if let Err(error) = check_value(&field.kind, value) {
                    errors.push(RowError::new(&field.name, error.code, error.message));
                }
            }
        }
    }

    let mut unknown: Vec<&String> = object
        .keys()
        .filter(|key| table.field(key).is_none())
        .collect();
    unknown.sort();
    for key in unknown {
        errors.push(RowError::new(
            key,
            ErrorCode::UnknownField,
            format!("is not a declared field of `{}`", table.name),
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(RowErrors { errors })
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}
