//! What a live database differs from a declaration by (issue #153).
//!
//! `cratefield_tables::diff` compares two declarations. This compares a
//! declaration against a database that already exists, which is a
//! different question with two traps in it — both of which produce
//! *false* reports, and a false "rewrite" is worse than no report at all
//! because it teaches an operator to skip the next one.
//!
//! # A database holds more than one declaration's tables
//!
//! [`schema`](crate::schema) reads the whole catalog. A venture's
//! `[tables]` section is a subset of it: the module crates own tables
//! too, and so does anything an operator made by hand. Diffing the two
//! whole schemas would report every module table as *"table is gone"* —
//! alarming, and wrong. **A table the declaration does not name is not
//! the declaration's to remove**, so drift narrows the live side to the
//! tables the declaration actually names.
//!
//! # A catalog cannot see most of a declaration
//!
//! A column's storage type is not its declared kind. `text`, `uuid`,
//! `json`, `enum` and `timestamp` are all `TEXT`, and `boolean` is
//! `INTEGER` on SQLite — so reading the catalog back gives `text` for
//! five kinds and `integer` for two. Comparing that against the
//! declaration directly reports a type rewrite for every uuid, json, enum
//! and timestamp column in the venture.
//!
//! The same applies to everything the declaration knows and the catalog
//! does not: length and numeric bounds, formats, enum members, defaults.
//! A declared `max_len = 200` against a catalog that reports no bound
//! reads as *"bounds narrow"* — a rewrite, for a column that is exactly
//! what was asked for.
//!
//! So drift does not compare against the declaration. It compares against
//! a **projection** of it: the declaration reduced to what a catalog read
//! could show. Everything the projection drops is something this
//! comparison cannot speak about, and [`unseen`] says what that is in one
//! place rather than leaving it to be discovered.
//!
//! The cost of the projection is stated rather than hidden: a change from
//! `text` to `uuid` is **invisible** here, because both are `TEXT` and the
//! database genuinely does not know the difference. `cratefield_tables::diff`
//! between two declarations does see it; this cannot, and saying "no
//! drift" about it is the honest answer to the question actually asked.

use cratefield_core::{Database, DbError};
use cratefield_tables::{Change, FieldDef, FieldKind, Schema, TableDef, diff};

/// What a comparison against a live catalog cannot see, for a caller that
/// wants to say so alongside the report.
///
/// Each of these is a property the declaration carries and the database
/// does not record in a form this crate reads. They are not "no drift" —
/// they are "not asked".
pub const UNSEEN: &[&str] = &[
    "which of text, uuid, json, enum and timestamp a TEXT column was declared as",
    "length and numeric bounds",
    "text formats (email, url)",
    "enum members",
    "column defaults",
];

/// The same list as a sentence, for a report's footer.
#[must_use]
pub fn unseen() -> String {
    format!(
        "not compared, because a catalog does not record it: {}",
        UNSEEN.join("; ")
    )
}

/// Every difference between `declared` and the database behind `db`, in
/// `cratefield_tables`' expand/contract/rewrite vocabulary.
///
/// Only the tables `declared` names are looked at, and only the
/// properties a catalog records are compared — see the module docs and
/// [`unseen`].
///
/// # Errors
///
/// [`DbError`] when the catalog cannot be read.
pub async fn drift(db: &dyn Database, declared: &Schema) -> Result<Vec<Change>, DbError> {
    let live = crate::schema(db).await?;
    Ok(compare(&live, declared))
}

/// The comparison itself, separated from the read so it can be driven
/// over a catalog captured earlier — and so the two traps above are
/// testable without a database.
#[must_use]
pub fn compare(live: &Schema, declared: &Schema) -> Vec<Change> {
    let narrowed = Schema::new(
        live.tables
            .iter()
            .filter(|table| declared.table(&table.name).is_some())
            .cloned()
            .collect(),
    );
    // Both sides through the same projection. The live side is already
    // storage-shaped — it came out of a catalog — with one exception:
    // Postgres records a real `BOOLEAN`, and the projection maps that to
    // `integer` exactly as it maps a declared `boolean`. Projecting only
    // the declaration would report a type change on every boolean column
    // in every Postgres venture, which is the same false rewrite this
    // module exists to avoid, pointing the other way.
    diff(&project(&narrowed), &project(declared))
}

/// The declaration reduced to what a catalog read could show.
///
/// Everything dropped here is in [`UNSEEN`]. Keeping the two in step is
/// the point of `the_projection_drops_exactly_what_unseen_lists`.
fn project(declared: &Schema) -> Schema {
    Schema::new(
        declared
            .tables
            .iter()
            .map(|table| TableDef {
                name: table.name.clone(),
                primary_key: table.primary_key.clone(),
                foreign_keys: table.foreign_keys.clone(),
                fields: table.fields.iter().map(project_field).collect(),
            })
            .collect(),
    )
}

fn project_field(field: &FieldDef) -> FieldDef {
    FieldDef {
        name: field.name.clone(),
        kind: stored_as(&field.kind),
        required: field.required,
        unique: field.unique,
        indexed: field.indexed,
        // A default lives in the DDL, and the catalog readers here do not
        // select it. Carrying the declared one would report a change on
        // every column that has one.
        default: None,
    }
}

/// The kind a declared field reads back as, once it has been through a
/// database's own catalog.
///
/// Derived from the column types `cratefield-tables` renders and the
/// types [`schema`](crate::schema) maps them back to. Where the two
/// engines disagree — `boolean` is `INTEGER` on SQLite and `BOOLEAN` on
/// Postgres — this answers with the *lossy* one, because reporting no
/// drift on a real difference is the failure this whole module is
/// avoiding, and the alternative is a false rewrite on every boolean
/// column in every SQLite venture.
fn stored_as(kind: &FieldKind) -> FieldKind {
    match kind {
        // All five render as TEXT.
        FieldKind::Text { .. }
        | FieldKind::Uuid
        | FieldKind::Json
        | FieldKind::Enum { .. }
        | FieldKind::Timestamp => FieldKind::text(),
        // `integer` twice, and deliberately: a declared `integer` stores
        // as INTEGER/BIGINT, and a declared `boolean` stores as INTEGER
        // on SQLite. They collapse to the same catalog answer, which is
        // the whole reason this function exists — merging the arms would
        // read as tidier and lose the fact that they arrive here for
        // different reasons.
        FieldKind::Integer { .. } | FieldKind::Boolean => FieldKind::integer(),
        FieldKind::Real { .. } => FieldKind::real(),
    }
}
