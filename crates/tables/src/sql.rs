//! The statements that read and write a declared table's rows
//! (issue #153).
//!
//! A `[tables]` declaration already becomes DDL, a module, a privacy
//! declaration and an access level. This is the layer underneath the CRUD
//! routes: given a [`TableDef`] and a row, the five statements that put a
//! row in a database and get it back out, built with sea-query and
//! rendered through the `Database` port like every other module's SQL
//! (ADR 0004).
//!
//! # Where the injection boundary is
//!
//! A declared table's column names come from a manifest, and a row's keys
//! come from an HTTP request. Only the first may become an identifier.
//! Every builder here walks `table.fields` and never the row's keys: a
//! key the table does not declare cannot reach the SQL at all, whatever
//! it contains, because nothing iterates over it. Values are bound
//! positionally by the adapter and are never rendered into the text.
//!
//! That is a property worth stating rather than assuming, so
//! `a_row_key_cannot_become_an_identifier` asserts it directly.
//!
//! # Why decoding can fail
//!
//! A column that does not come back as its declared kind is an error, not
//! a `null`. The declaration says a database has a `TEXT` column named
//! `body`; a row answering with an integer means the database no longer
//! matches the manifest, which is a finding — `fz tables drift` is the
//! command that reports it — and turning it into a silent `null` would
//! publish wrong data through the same API that promises the declared
//! JSON Schema.

use cratefield_core::{Row, Statement};
use sea_query::{Alias, Cond, Expr, Order, Query, SimpleExpr, Value as SeaValue};
use serde_json::{Map, Value};

use crate::schema::{FieldDef, FieldKind, TableDef};
use crate::validate::{RowErrors, validate_row};
use crate::value::ErrorCode;

/// A column that did not come back as the declaration says it is.
///
/// Carries the table and column so the operator knows where to look, and
/// a detail that describes the shape rather than quoting the value —
/// these rows are a venture's data and this message goes to a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    /// The declared table the row belongs to.
    pub table: String,
    /// The declared column that could not be read.
    pub column: String,
    /// What was wrong, in terms of kinds and never of values.
    pub detail: String,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "table `{}`, column `{}`: {}",
            self.table, self.column, self.detail
        )
    }
}

impl std::error::Error for DecodeError {}

/// A JSON value for one declared field, as a bound parameter, or `None`
/// when the value is not the kind the column is declared as.
///
/// A `null` — or an absent field — becomes a **typed** null matching the
/// column, not an untyped one. Postgres binds parameters by type and
/// cannot infer one for a bare null, so an untyped null is an error there
/// and a silent success on SQLite: exactly the asymmetry that passes
/// every local test and fails in production.
///
/// A value of the wrong kind is `None` rather than that same typed null,
/// which is the whole reason this answers an `Option`. A `42` for a
/// `uuid` column silently becoming `NULL` makes `WHERE id = NULL` — never
/// true — so a delete would remove nothing and report success.
#[must_use]
pub fn to_sql(field: &FieldDef, value: Option<&Value>) -> Option<SeaValue> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Some(null_for(&field.kind));
    };
    match &field.kind {
        FieldKind::Boolean => value.as_bool().map(|flag| SeaValue::Bool(Some(flag))),
        FieldKind::Integer { .. } => {
            crate::value::integral(value).map(|n| SeaValue::BigInt(Some(n)))
        }
        FieldKind::Real { .. } => value.as_f64().map(|n| SeaValue::Double(Some(n))),
        // Stored as TEXT, so what goes in is the serialization and what
        // comes back is parsed. `to_string` rather than the raw request
        // bytes: the value has been through `serde_json`, so the stored
        // text is canonical JSON rather than whatever spacing was sent.
        // Any JSON value is a legal one, which is why this cannot fail.
        FieldKind::Json => Some(SeaValue::String(Some(Box::new(value.to_string())))),
        FieldKind::Text { .. }
        | FieldKind::Timestamp
        | FieldKind::Uuid
        | FieldKind::Enum { .. } => value
            .as_str()
            .map(|text| SeaValue::String(Some(Box::new(text.to_owned())))),
    }
}

/// [`to_sql`], with the mismatch turned into the row error it is.
///
/// Reachable only past [`validate_row`], which refuses a wrong-typed
/// value first — so this is the second line rather than the first, and it
/// exists because "the caller validated" is the assumption that stops
/// being true the day somebody adds a second caller.
fn bound(field: &FieldDef, value: Option<&Value>) -> Result<SeaValue, RowErrors> {
    to_sql(field, value).ok_or_else(|| {
        RowErrors::one(
            &field.name,
            ErrorCode::WrongType,
            format!("must be {}", field.kind.as_str()),
        )
    })
}

/// The typed null for a column of this kind.
fn null_for(kind: &FieldKind) -> SeaValue {
    match kind {
        FieldKind::Boolean => SeaValue::Bool(None),
        FieldKind::Integer { .. } => SeaValue::BigInt(None),
        FieldKind::Real { .. } => SeaValue::Double(None),
        FieldKind::Text { .. }
        | FieldKind::Timestamp
        | FieldKind::Uuid
        | FieldKind::Json
        | FieldKind::Enum { .. } => SeaValue::String(None),
    }
}

/// One column of a returned row, as the JSON the declaration promises.
///
/// # Errors
///
/// When the value is not the declared kind — which means the database no
/// longer matches the declaration.
pub fn from_sql(table: &str, field: &FieldDef, value: &SeaValue) -> Result<Value, DecodeError> {
    let wrong = |detail: &str| DecodeError {
        table: table.to_owned(),
        column: field.name.clone(),
        detail: detail.to_owned(),
    };
    // SQLite has no typed nulls: its adapter maps every `NULL` to
    // `SeaValue::String(None)` whatever the column is declared as,
    // because the value carries no type to map from. So a null in an
    // `integer`, `real` or `boolean` column arrives here looking like a
    // text null, and reading that as a wrong kind answers 500 for a row
    // that is exactly what the declaration says it is.
    //
    // Only the *null* case widens. A text value in an integer column is
    // still an error, which is the part worth keeping: that one means the
    // database has drifted from the declaration.
    if matches!(value, SeaValue::String(None)) {
        return Ok(Value::Null);
    }
    match &field.kind {
        FieldKind::Boolean => match value {
            SeaValue::Bool(None) | SeaValue::Int(None) | SeaValue::BigInt(None) => Ok(Value::Null),
            SeaValue::Bool(Some(flag)) => Ok(Value::Bool(*flag)),
            // SQLite has no boolean type and the DDL renders the column
            // as INTEGER there, so a `true` comes back as 1. Postgres
            // answers with a real boolean. Both are the declared kind.
            SeaValue::Int(Some(n)) => Ok(Value::Bool(*n != 0)),
            SeaValue::BigInt(Some(n)) => Ok(Value::Bool(*n != 0)),
            _ => Err(wrong(
                "declared boolean, and the database did not answer with one",
            )),
        },
        FieldKind::Integer { .. } => match integer(value) {
            Integral::Whole(n) => Ok(Value::from(n)),
            Integral::Null => Ok(Value::Null),
            Integral::Other => Err(wrong(
                "declared integer, and the database did not answer with one",
            )),
        },
        FieldKind::Real { .. } => match value {
            SeaValue::Double(None) | SeaValue::Float(None) => Ok(Value::Null),
            SeaValue::Double(Some(n)) => Ok(number(*n).ok_or_else(|| {
                wrong("declared real, and the database answered with a value JSON cannot hold")
            })?),
            SeaValue::Float(Some(n)) => Ok(number(f64::from(*n)).ok_or_else(|| {
                wrong("declared real, and the database answered with a value JSON cannot hold")
            })?),
            // SQLite's column affinity stores a whole number in a REAL
            // column as an integer and answers with one.
            _ => match integer(value) {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "a REAL column's value was written as an f64; coming back through \
                              SQLite's integer affinity, f64 is the kind it is declared as"
                )]
                Integral::Whole(n) => {
                    Ok(number(n as f64).ok_or_else(|| wrong("not a JSON number"))?)
                }
                Integral::Null => Ok(Value::Null),
                Integral::Other => Err(wrong(
                    "declared real, and the database did not answer with a number",
                )),
            },
        },
        FieldKind::Json => match value {
            SeaValue::String(None) => Ok(Value::Null),
            SeaValue::String(Some(text)) => serde_json::from_str(text).map_err(|_ignored| {
                // The message says the shape, never the text: a `json`
                // column holds whatever the venture put in it.
                wrong("declared json, and the stored text is not JSON")
            }),
            _ => Err(wrong(
                "declared json, and the database did not answer with text",
            )),
        },
        FieldKind::Text { .. }
        | FieldKind::Timestamp
        | FieldKind::Uuid
        | FieldKind::Enum { .. } => match value {
            SeaValue::String(None) => Ok(Value::Null),
            SeaValue::String(Some(text)) => Ok(Value::String((**text).clone())),
            _ => Err(wrong(
                "declared text, and the database did not answer with text",
            )),
        },
    }
}

/// What a value is, when the declaration says the column holds a whole
/// number. Three cases rather than a nested `Option`, because "a null
/// integer" and "not an integer at all" become different answers — one is
/// a JSON `null` and the other is a [`DecodeError`].
enum Integral {
    /// A whole number, in any of the widths an engine may answer with.
    Whole(i64),
    /// SQL `NULL` in an integer column.
    Null,
    /// Not an integer at all.
    Other,
}

fn integer(value: &SeaValue) -> Integral {
    let inner = match value {
        SeaValue::TinyInt(inner) => inner.map(i64::from),
        SeaValue::SmallInt(inner) => inner.map(i64::from),
        SeaValue::Int(inner) => inner.map(i64::from),
        SeaValue::BigInt(inner) => *inner,
        _ => return Integral::Other,
    };
    inner.map_or(Integral::Null, Integral::Whole)
}

/// A finite `f64` as a JSON number. NaN and the infinities have no JSON
/// form, and `serde_json` renders them as `null` rather than refusing.
fn number(n: f64) -> Option<Value> {
    serde_json::Number::from_f64(n).map(Value::Number)
}

/// A returned row as the JSON the declaration promises.
///
/// Every declared field is a key, in declaration order, whether or not
/// the database answered with one — a missing column is an error for the
/// reason a mistyped one is.
///
/// # Errors
///
/// When a column is absent or is not the declared kind.
pub fn row_json(table: &TableDef, row: &Row) -> Result<Value, DecodeError> {
    let mut out = Map::new();
    for field in &table.fields {
        let value = row
            .get::<SeaValue>(&field.name)
            .ok_or_else(|| DecodeError {
                table: table.name.clone(),
                column: field.name.clone(),
                detail: "declared, and the row does not have it".to_owned(),
            })?;
        out.insert(field.name.clone(), from_sql(&table.name, field, &value)?);
    }
    Ok(Value::Object(out))
}

/// `INSERT` for one row.
///
/// The row is validated here rather than trusted: a statement built from
/// a row that would not pass [`validate_row`] is a statement that reaches
/// the database to be refused by a constraint, in a message written for a
/// DBA rather than for the caller.
///
/// # Errors
///
/// The row's own validation errors, as the problem+json body describes.
pub fn insert(table: &TableDef, row: &Value) -> Result<Statement, RowErrors> {
    validate_row(table, row)?;
    let object = row.as_object().cloned().unwrap_or_default();
    // Declared fields the row leaves out are left out of the statement
    // too, so the column's DDL default applies. Binding an explicit null
    // instead would overwrite a default with nothing.
    let present: Vec<&FieldDef> = table
        .fields
        .iter()
        .filter(|field| object.contains_key(&field.name))
        .collect();

    let mut values = Vec::with_capacity(present.len());
    for field in &present {
        values.push(bound(field, object.get(&field.name))?.into());
    }

    let mut insert = Query::insert();
    insert
        .into_table(Alias::new(&table.name))
        .columns(present.iter().map(|field| Alias::new(&field.name)))
        .values_panic(values);
    Ok(Statement::render(&insert))
}

/// Rows belonging to one subject: the condition an `owner` table's
/// access level puts on every read.
///
/// A parameter rather than something the caller applies afterwards. The
/// condition joins the same `WHERE` as the key and the cursor, because a
/// filter applied to rows already fetched turns a `LIMIT 20` into a page
/// of however many survived — and the shortfall is a count of the rows
/// the caller was not allowed to see.
#[derive(Debug, Clone, Copy)]
pub struct Owned<'a> {
    /// The table's subject column.
    pub column: &'a str,
    /// The caller's own id.
    pub subject: &'a Value,
}

/// `SELECT` of one row by primary key, optionally scoped to one subject.
///
/// With `owned`, a row belonging to somebody else does not match — so the
/// caller is answered "not found" rather than "forbidden", which is an
/// answer about a row they were never in a position to learn exists.
///
/// # Errors
///
/// When `key` does not carry every primary-key column the table declares
/// — half a composite key selects an arbitrary row — or when the subject
/// column is not a field of the table.
pub fn select_one(
    table: &TableDef,
    key: &Value,
    owned: Option<Owned<'_>>,
) -> Result<Statement, DecodeError> {
    let mut select = Query::select();
    select
        .columns(table.fields.iter().map(|field| Alias::new(&field.name)))
        .from(Alias::new(&table.name))
        .cond_where(key_predicate(table, key)?.add_option(owned_predicate(table, owned)?))
        .limit(1);
    Ok(Statement::render(&select))
}

/// `subject_column = ?`, when the read is scoped to one subject.
fn owned_predicate(
    table: &TableDef,
    owned: Option<Owned<'_>>,
) -> Result<Option<sea_query::SimpleExpr>, DecodeError> {
    let Some(owned) = owned else {
        return Ok(None);
    };
    let field = table
        .fields
        .iter()
        .find(|field| field.name == owned.column)
        .ok_or_else(|| DecodeError {
            table: table.name.clone(),
            column: owned.column.to_owned(),
            detail: "the subject column this read is scoped to is not a field of the table"
                .to_owned(),
        })?;
    let value = to_sql(field, Some(owned.subject)).ok_or_else(|| DecodeError {
        table: table.name.clone(),
        column: owned.column.to_owned(),
        detail: format!(
            "the subject this read is scoped to is not {}",
            field.kind.as_str()
        ),
    })?;
    Ok(Some(Expr::col(Alias::new(owned.column)).eq(value)))
}

/// One equality condition on a declared column.
///
/// Equality, and nothing else. #153's own rule bounds the declaration
/// surface — *anything referencing another row or another request is a
/// function, not a field* — and the same instinct bounds what a caller
/// may ask of one: ranges, prefixes and `LIKE` are queries a module
/// writes, not vocabulary a manifest grows into.
#[derive(Debug, Clone)]
pub struct Filter {
    /// The declared column.
    pub column: String,
    /// What it must equal, as JSON.
    pub value: Value,
}

/// What a page asks for.
///
/// A struct rather than five positional arguments: the last two are both
/// optional and both about *which rows*, and a call site that swapped
/// them would compile.
#[derive(Debug, Clone, Copy)]
pub struct Page<'a> {
    /// The most rows to return.
    pub limit: u64,
    /// The key of the last row of the previous page.
    pub after: Option<&'a Value>,
    /// The subject scope an `owner` table's access level decided.
    pub owned: Option<Owned<'a>>,
    /// What the caller asked to narrow by.
    pub filters: &'a [Filter],
}

/// `SELECT` of a page, ordered by primary key, optionally after a cursor.
///
/// Ordered by the primary key because a page has to be stable: a `LIMIT`
/// with no `ORDER BY` is whatever the engine felt like, and two requests
/// for "the first ten" may then share rows or skip them.
///
/// # Errors
///
/// When `after` is given and does not carry every primary-key column.
pub fn select_page(table: &TableDef, page: Page<'_>) -> Result<Statement, DecodeError> {
    let mut select = Query::select();
    select
        .columns(table.fields.iter().map(|field| Alias::new(&field.name)))
        .from(Alias::new(&table.name))
        .limit(page.limit);
    for column in &table.primary_key {
        select.order_by(Alias::new(column), Order::Asc);
    }
    // Every condition `AND`ed: the cursor is where the page starts, the
    // scope is which rows the caller may see, and the filters are which
    // of those they asked for. Applying any of them afterwards would page
    // through rows that are then discarded and hand back short pages that
    // count them.
    //
    // The scope goes in first and is never replaced by a filter — a
    // caller filtering on the subject column narrows their own rows and
    // cannot reach anybody else's, because both conditions stand.
    let mut all = Cond::all().add_option(owned_predicate(table, page.owned)?);
    if let Some(after) = page.after {
        all = all.add(after_predicate(table, after)?);
    }
    for filter in page.filters {
        all = all.add(filter_predicate(table, filter)?);
    }
    select.cond_where(all);
    Ok(Statement::render(&select))
}

/// `column = ?`, for one caller-supplied filter.
///
/// The column must be a declared field and the value must be its kind.
/// Neither is ignored: a filter that is silently dropped answers a
/// question the caller did not ask, with more rows than they asked for.
fn filter_predicate(table: &TableDef, filter: &Filter) -> Result<SimpleExpr, DecodeError> {
    let field = table
        .fields
        .iter()
        .find(|field| field.name == filter.column)
        .ok_or_else(|| DecodeError {
            table: table.name.clone(),
            column: filter.column.clone(),
            detail: "is not a field of this table".to_owned(),
        })?;
    let value = to_sql(field, Some(&filter.value)).ok_or_else(|| DecodeError {
        table: table.name.clone(),
        column: filter.column.clone(),
        detail: format!("is {} and the value given is not", field.kind.as_str()),
    })?;
    Ok(Expr::col(Alias::new(&filter.column)).eq(value))
}

/// `UPDATE` of one row by primary key, replacing every declared
/// non-key field, optionally scoped to one subject.
///
/// With `owned`, a row belonging to somebody else matches nothing, so the
/// caller is told no row was changed rather than being refused — the same
/// answer a read gives, for the same reason.
///
/// A replacement rather than a merge: the caller sends the row it wants
/// to exist. A merge would make "unset this field" unexpressible, because
/// an absent key and a `null` one would both mean "leave it".
///
/// # Errors
///
/// The row's validation errors, or a key that is not complete.
pub fn update(
    table: &TableDef,
    key: &Value,
    row: &Value,
    owned: Option<Owned<'_>>,
) -> Result<Statement, UpdateError> {
    validate_row(table, row).map_err(UpdateError::Row)?;
    let object = row.as_object().cloned().unwrap_or_default();
    let predicate = key_predicate(table, key)
        .map_err(UpdateError::Key)?
        .add_option(owned_predicate(table, owned).map_err(UpdateError::Key)?);

    let mut update = Query::update();
    update.table(Alias::new(&table.name));
    for field in &table.fields {
        if table.primary_key.contains(&field.name) {
            // Changing a row's identity is a delete and an insert, not an
            // update: rows referencing it by foreign key would follow the
            // value or be orphaned depending on the constraint, which is
            // not a decision an edit should make silently.
            continue;
        }
        update.value(
            Alias::new(&field.name),
            bound(field, object.get(&field.name)).map_err(UpdateError::Row)?,
        );
    }
    update.cond_where(predicate);
    Ok(Statement::render(&update))
}

/// What an `UPDATE` can be refused for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateError {
    /// The new row is not a legal row for this table.
    Row(RowErrors),
    /// The key does not name the row to change.
    Key(DecodeError),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Row(errors) => write!(f, "{errors}"),
            Self::Key(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for UpdateError {}

/// `DELETE` of one row by primary key, optionally scoped to one subject.
///
/// The scope is the difference between a caller deleting their own row
/// and a caller deleting any row whose key they can guess.
///
/// # Errors
///
/// When `key` does not carry every primary-key column — a partial key
/// would delete every row that matches the half it names.
pub fn delete(
    table: &TableDef,
    key: &Value,
    owned: Option<Owned<'_>>,
) -> Result<Statement, DecodeError> {
    let mut delete = Query::delete();
    delete
        .from_table(Alias::new(&table.name))
        .cond_where(key_predicate(table, key)?.add_option(owned_predicate(table, owned)?));
    Ok(Statement::render(&delete))
}

/// `pk_a = ? AND pk_b = ?`, refusing a key that is not complete.
fn key_predicate(table: &TableDef, key: &Value) -> Result<Cond, DecodeError> {
    let mut all = Cond::all();
    for column in &table.primary_key {
        all = all.add(Expr::col(Alias::new(column)).eq(key_part(table, key, column)?));
    }
    Ok(all)
}

/// Lexicographic "after this key", as an OR of ANDs.
///
/// `(a > x) OR (a = x AND b > y)` rather than a row-value comparison:
/// `(a, b) > (x, y)` is standard SQL that SQLite does not have, and a
/// cursor that worked on Postgres and not on D1 would be a difference
/// between two deployments of the same declaration.
fn after_predicate(table: &TableDef, after: &Value) -> Result<Cond, DecodeError> {
    let mut any = Cond::any();
    for (at, column) in table.primary_key.iter().enumerate() {
        let mut branch = Cond::all();
        for earlier in &table.primary_key[..at] {
            branch =
                branch.add(Expr::col(Alias::new(earlier)).eq(key_part(table, after, earlier)?));
        }
        branch = branch.add(Expr::col(Alias::new(column)).gt(key_part(table, after, column)?));
        any = any.add(branch);
    }
    Ok(any)
}

/// The bound value for one key column, refusing anything that would not
/// actually identify a row.
///
/// A value of the wrong kind is refused rather than bound as a null: the
/// null would make `WHERE id = NULL`, which is never true, so the
/// statement would match nothing and report success.
fn key_part(table: &TableDef, key: &Value, column: &str) -> Result<SeaValue, DecodeError> {
    let missing = |detail: &str| DecodeError {
        table: table.name.clone(),
        column: column.to_owned(),
        detail: detail.to_owned(),
    };
    let field = table
        .fields
        .iter()
        .find(|field| field.name == column)
        .ok_or_else(|| missing("a primary-key column that is not a declared field"))?;
    let value = key
        .get(column)
        .filter(|value| !value.is_null())
        .ok_or_else(|| missing("part of the primary key, and the key does not give it"))?;
    to_sql(field, Some(value)).ok_or_else(|| {
        missing(&format!(
            "part of the primary key, and the value given is not {}",
            field.kind.as_str()
        ))
    })
}
