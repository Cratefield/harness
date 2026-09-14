//! The declared tables, as a venture's generated module carries them
//! (issue #153).
//!
//! `TableApi` is a runtime value with `String`s and `Vec`s in it, so a
//! generated module cannot hold one in a `const`. It holds the
//! declaration as JSON text instead and parses it once at boot.
//!
//! # Why text rather than emitted Rust
//!
//! Emitting `TableDef` literals would make a malformed declaration a
//! compile error instead of a boot-time one, which is strictly better.
//! It is also a great deal of generated code — every `FieldKind`'s
//! bounds, every foreign key — and the text comes from the same manifest
//! `fz build` has already validated, so the failure it would catch is a
//! bug in the generator rather than anything an author can write.
//!
//! The cost is that the failure surfaces at boot. So it surfaces in
//! `validate_config`, which the harness calls while composing: a
//! deployment whose declaration will not parse refuses to start rather
//! than starting and serving an empty table list.

use cratefield_manifest::{AccessMap, TablePrivacy, TablePrivacyMap};
use cratefield_tables::Schema;
use serde::{Deserialize, Serialize};

use crate::access::TableApi;

/// A venture's `[tables]` section, in the three parts the API needs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Declared {
    /// The tables themselves.
    pub tables: Schema,
    /// Who may reach each one.
    pub access: AccessMap,
    /// What each one holds — read for the subject column, which is what
    /// `owner` matches a caller against.
    pub privacy: TablePrivacyMap,
}

impl Declared {
    /// The declared tables, ready to serve.
    ///
    /// A table with no access level is **left out** rather than given
    /// one. `fz build` refuses a manifest that omits one (#359), so this
    /// cannot happen from a generated module; if it somehow does, a table
    /// nobody can reach is the only safe answer, and a `404` is what a
    /// caller gets. Defaulting to `public-read` here would publish it and
    /// defaulting to `admin` would hide a real bug behind a plausible
    /// refusal.
    #[must_use]
    pub fn into_apis(self) -> Vec<TableApi> {
        let Self {
            tables,
            access,
            privacy,
        } = self;
        tables
            .tables
            .into_iter()
            .filter_map(|table| {
                let level = *access.get(&table.name)?;
                let subject = match privacy.get(&table.name) {
                    Some(TablePrivacy::Personal { subject, .. }) => Some(subject.clone()),
                    _ => None,
                };
                Some(TableApi {
                    table,
                    access: level,
                    subject,
                })
            })
            .collect()
    }
}

/// Parses the JSON a generated module carries.
///
/// # Errors
///
/// A message naming what could not be read. It is for an operator: this
/// text is generated, so a failure is a bug in the generator and the
/// message has to be enough to find it.
pub fn parse(json: &str) -> Result<Vec<TableApi>, String> {
    serde_json::from_str::<Declared>(json)
        .map(Declared::into_apis)
        .map_err(|err| format!("the generated table declaration could not be read: {err}"))
}
