//! Reads the `tables` module's entry out of a `/__surface` document into
//! the small model the emitter renders.
//!
//! The reading is deliberately literal: the routes, the audience and the
//! schema are taken from the actions as the contract publishes them, not
//! reconstructed from what the Tables module happens to serve today. That
//! is what makes the compile-time absence work — a table the contract
//! publishes no `delete` for gets no `delete` method, because the client
//! never asked the contract for one.

use serde_json::Value;

use cratefield_core::{Audience, SurfaceDocument};

use crate::GenerateError;

/// The module whose contract the client speaks: the Tables module's mount
/// name (`crates/manifest/src/generate_tables.rs`, `MODULE_NAME`).
pub const TABLES_MODULE: &str = "tables";

/// One of the five verbs the Tables module publishes, as the action names
/// spell them (`list-note`, `delete-note`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verb {
    /// `list-{t}` — the page.
    List,
    /// `read-{t}` — one row by key.
    Read,
    /// `create-{t}` — a write.
    Create,
    /// `replace-{t}` — a write that names a row.
    Replace,
    /// `delete-{t}` — a write that names a row.
    Delete,
}

impl Verb {
    /// The method the verb is served by, so a drifted contract is caught
    /// rather than silently mis-typed.
    fn method(self) -> &'static str {
        match self {
            Verb::List | Verb::Read => "GET",
            Verb::Create => "POST",
            Verb::Replace => "PUT",
            Verb::Delete => "DELETE",
        }
    }
}

/// One column's type, normalized from the JSON Schema shape the Tables
/// module publishes for it (`crates/tables/src/json_schema.rs`). The
/// shapes are closed: the module emits exactly these, so anything else
/// reads as [`ColumnKind::Opaque`] rather than as a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnKind {
    /// `{"type": "string"}` — with optional `minLength`/`maxLength`, an
    /// optional `format` of `"email"` or `"uri"`, and the `not`/`pattern`
    /// ban on U+0000. A `timestamp` (`format: "date-time"`) and a `uuid`
    /// (`format: "uuid"`) normalize here too: the wire type is a string
    /// either way.
    Text,
    /// `{"type": "integer"}`, with optional `minimum`/`maximum`.
    Integer,
    /// `{"type": "number"}`, with optional `minimum`/`maximum`.
    Real,
    /// `{"type": "boolean"}`.
    Boolean,
    /// A closed list of literals (`"enum"`), their JSON text forms, with
    /// the `null` member left out — nullability lives on
    /// [`ColumnModel::nullable`].
    Enum(Vec<String>),
    /// The schema names no type at all: the `json` column's own shape
    /// ("any JSON value", nothing to narrow), or a shape this generator
    /// cannot read. TypeScript gets `unknown`, and the wire gets no
    /// filter, because equality on the incomparable is a lie.
    Opaque,
}

/// One column of a declared table, as the contract's row schema
/// describes it.
// Five flags, and each one is read straight off the schema as a
// separate fact of it (nullability, `required`, the primary-key
// marker, filter-ability, sort-ability); no enum can carry the five
// at once, which is why the model stays a flag set.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnModel {
    /// The wire key, as the schema spells it.
    pub name: String,
    /// The normalized type, from the schema's `type`/`enum` shape.
    pub kind: ColumnKind,
    /// Whether the schema says the column can hold `null`: a `type`
    /// array carrying `"null"`, or an `enum` listing it.
    pub nullable: bool,
    /// Whether the schema lists the column under `required`.
    pub required: bool,
    /// Whether the schema marks the column as the table's primary key —
    /// by a `description` that begins with the words `Primary key of`
    /// followed by the table's name, the one way
    /// `cratefield_tables::json_schema` marks it.
    pub is_primary_key: bool,
    /// Whether the page's query accepts an equality filter on the
    /// column: every kind but [`ColumnKind::Opaque`].
    pub filterable: bool,
    /// Whether the page may be sorted by the column: the schema-required
    /// columns and the primary key.
    pub sortable: bool,
}

/// One declared table, as the contract publishes it.
// Five flags, each an independent fact of the contract: whether a row
// schema travelled at all, and which of the four non-page verbs the
// entry publishes. Every combination is legal wire shape, so an enum
// could not say it without lying about one.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct TableModel {
    /// The table's name, from the actions that name it.
    pub name: String,
    /// The audience every action of the table is served to. A surface
    /// says a credential is needed and nothing more — `owner` and
    /// `tenant-members` both publish as `Subject`.
    pub audience: Audience,
    /// The page's path as published (`/note`).
    pub list_path: Option<String>,
    /// The single-row path as published (`/note/{key}`); `None` exactly
    /// when the contract publishes no single-row action, which is a
    /// composite-key table.
    pub key_path: Option<String>,
    /// The row schema the contract carries on `create-{t}` (falling back
    /// to `replace-{t}`'s). `None` when the contract publishes none — a
    /// read-only table's entry carries no schema anywhere, which is the
    /// known gap.
    pub schema: Option<Value>,
    /// The row's columns, read out of [`TableModel::schema`], in the
    /// order the schema lists them — the declaration's order. Empty
    /// whenever the contract carries no schema, which is a fact about
    /// the contract, not an error.
    pub columns: Vec<ColumnModel>,
    /// The column the schema marks as the single primary key — the one
    /// a single-row path substitutes. `None` when the contract carries
    /// no schema (a read-only table's known gap), when the schema marks
    /// several columns (a composite key, which cannot travel one path
    /// segment), or when the table has no single-row routes to substitute
    /// it into.
    pub primary_key: Option<ColumnModel>,
    /// Whether the contract says anything at all about the row's shape:
    /// `true` exactly when a schema travelled. A read-only table
    /// publishes `list` and `read` and no write, and the write is where
    /// a row schema travels — so its shape is unknown and the generated
    /// client says so rather than guessing.
    pub row_shape_known: bool,
    pub has_read: bool,
    pub has_create: bool,
    pub has_replace: bool,
    pub has_delete: bool,
}

/// The Tables contract, extracted.
#[derive(Debug, Clone)]
pub struct Contract {
    /// The venture the client speaks for.
    pub venture: String,
    /// Where the Tables module is mounted (`/v1/tables`): every action
    /// path is relative to this.
    pub mount: String,
    /// The tables, in the order the contract introduces them.
    pub tables: Vec<TableModel>,
}

/// Whether a table name is safe to interpolate into generated TypeScript:
/// lowercase snake-case — `[a-z][a-z0-9_]*`, no double or trailing
/// underscore. Duplicated from `cratefield_tables::schema::is_identifier`
/// (`crates/tables/src/schema.rs:894`), the source of truth a venture's
/// declaration is held to, so a name the Tables module serves always
/// passes and anything else in a `/__surface` document is a forgery or a
/// drift. Not depended on: `cratefield-tables` pulls `sea-query` for its
/// DDL, and this crate stays serde-only so it stays wasm-clean — the
/// integration test pins the two rules to the same verdicts instead.
fn is_table_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    if name.ends_with('_') || name.contains("__") {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Splits an action name into its verb and table (`list-note`).
fn split_action(name: &str) -> Option<(Verb, &str)> {
    let (verb, table) = name.split_once('-')?;
    let verb = match verb {
        "list" => Verb::List,
        "read" => Verb::Read,
        "create" => Verb::Create,
        "replace" => Verb::Replace,
        "delete" => Verb::Delete,
        _ => return None,
    };
    if table.is_empty() {
        return None;
    }
    Some((verb, table))
}

/// The single-row path of one action: `{table}/{placeholder}`, where the
/// placeholder is the one segment the key is substituted into. Checked
/// rather than assumed — a client that pastes a drifted path into its own
/// URL would answer 404s the contract never promised.
fn key_path_of(table: &str, path: &str, action: &str) -> Result<String, GenerateError> {
    let prefix = format!("/{table}/");
    let placeholder =
        path.strip_prefix(prefix.as_str())
            .ok_or_else(|| GenerateError::UnreadableAction {
                action: action.to_owned(),
                why: format!("its single-row path `{path}` must start with `{prefix}`"),
            })?;
    let one_segment = !placeholder.is_empty()
        && !placeholder.contains('/')
        && placeholder.starts_with('{')
        && placeholder.ends_with('}');
    if !one_segment {
        return Err(GenerateError::UnreadableAction {
            action: action.to_owned(),
            why: format!(
                "its single-row path `{path}` must end with one `{{key}}` placeholder \
                 segment after `{table}`"
            ),
        });
    }
    Ok(path.to_owned())
}

/// The page path of one action: `/{table}`, and nothing else.
fn list_path_of(table: &str, path: &str, action: &str) -> Result<String, GenerateError> {
    if path != format!("/{table}") {
        return Err(GenerateError::UnreadableAction {
            action: action.to_owned(),
            why: format!("its page path `{path}` must be exactly `/{table}`"),
        });
    }
    Ok(path.to_owned())
}

/// How the Tables module marks a primary-key column in the schema it
/// publishes (`crates/tables/src/json_schema.rs`): a `description` of
/// the form ``Primary key of `{table}`.``, the table's own name spelled
/// inside the backticks. Matched by prefix rather than as a whole
/// sentence, so the marker survives a table name this generator never
/// guessed.
const PK_MARKER: &str = "Primary key of `";

/// Whether the schema marks this column as the table's primary key.
/// Shared with the emitter (`crate::emitter`), which reads the same
/// marker — one check, so the two readers cannot drift.
pub(crate) fn is_primary_key_marker(column_schema: &Value) -> bool {
    column_schema
        .get("description")
        .and_then(Value::as_str)
        .is_some_and(|description| description.starts_with(PK_MARKER))
}

/// Whether the schema says the column can hold `null`: a type array
/// carrying `"null"`, or an `enum` listing it. A column with no `type`
/// at all (a `json` column) carries no nullability either — a null and
/// a missing key are the same absence to the validator.
///
/// Shared with the emitter (`crate::emitter`): the one reader of
/// nullability, so the row types and the sort union cannot disagree with
/// the model about a nullable enum.
pub(crate) fn column_nullable(column_schema: &Value) -> bool {
    let type_nullable = match column_schema.get("type") {
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind == "null"),
        Some(Value::String(kind)) => kind == "null",
        _ => false,
    };
    // An `enum` lists its own null too: the Tables module publishes a
    // nullable enum as `{"type": "string", "enum": [..., null]}`, so the
    // enum is checked even where a `type` travels alongside it.
    type_nullable
        || column_schema
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|members| members.iter().any(Value::is_null))
}

/// The base type one JSON Schema `type` value names.
fn scalar_kind(kind: &str) -> ColumnKind {
    match kind {
        "string" => ColumnKind::Text,
        "integer" => ColumnKind::Integer,
        "number" => ColumnKind::Real,
        "boolean" => ColumnKind::Boolean,
        _ => ColumnKind::Opaque,
    }
}

/// Removes duplicates keeping the first occurrence, in order.
/// `Vec::dedup` only removes *adjacent* duplicates, so a non-adjacent
/// repeat would reach a generated union twice; and the order is part of
/// the deterministic output, so no sorting either.
pub(crate) fn dedup_keep_first<T: Clone + PartialEq>(values: Vec<T>) -> Vec<T> {
    let mut kept: Vec<T> = Vec::with_capacity(values.len());
    for value in values {
        if !kept.contains(&value) {
            kept.push(value);
        }
    }
    kept
}

/// A column's kind: its `enum` as a literal list when there is one, its
/// `type` otherwise, and [`ColumnKind::Opaque`] when the schema names
/// neither — a `json` column, deliberately, and anything else this
/// generator cannot narrow.
fn column_kind_of(column_schema: &Value) -> ColumnKind {
    if let Some(members) = column_schema.get("enum").and_then(Value::as_array) {
        let literals: Vec<String> = members
            .iter()
            .filter(|member| !member.is_null())
            .map(|member| match member {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            })
            .collect();
        return ColumnKind::Enum(dedup_keep_first(literals));
    }
    match column_schema.get("type") {
        Some(Value::String(kind)) => scalar_kind(kind),
        Some(Value::Array(kinds)) => kinds
            .iter()
            .filter_map(Value::as_str)
            .find(|kind| *kind != "null")
            .map_or(ColumnKind::Opaque, scalar_kind),
        // A non-string, non-array `type` (or no `type` at all) names
        // nothing this generator narrows: `Opaque`, not a guess.
        _ => ColumnKind::Opaque,
    }
}

/// One column, normalized from its schema shape and the table's
/// `required` list.
fn column_of(name: &str, column_schema: &Value, required: bool) -> ColumnModel {
    let kind = column_kind_of(column_schema);
    let is_primary_key = is_primary_key_marker(column_schema);
    let filterable = !matches!(kind, ColumnKind::Opaque);
    ColumnModel {
        name: name.to_owned(),
        kind,
        nullable: column_nullable(column_schema),
        required,
        is_primary_key,
        filterable,
        sortable: required || is_primary_key,
    }
}

/// Reads the row shape out of the schema the write actions carry, into
/// [`TableModel::columns`] and [`TableModel::primary_key`]. A table the
/// contract carries no schema for keeps an empty column list and
/// `row_shape_known: false` — the read-only table's known gap, recorded
/// rather than errored on.
fn normalize(table: &mut TableModel) {
    let Some(schema) = table.schema.as_ref() else {
        return;
    };
    table.row_shape_known = true;
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return;
    };
    table.columns = properties
        .iter()
        .map(|(name, column_schema)| {
            column_of(name, column_schema, required.contains(&name.as_str()))
        })
        .collect();
    // The single-row routes are exactly where a key is substituted, and
    // one path segment holds one column's value: a composite key cannot
    // travel it, so the contract publishes no `read`/`replace`/`delete`
    // and the model carries no key either. One marked column with the
    // routes present is the key; anything else is none.
    let mut marked = table.columns.iter().filter(|c| c.is_primary_key);
    let key = match (marked.next(), marked.next()) {
        (Some(single), None) => Some(single.clone()),
        _ => None,
    };
    if table.key_path.is_some() {
        table.primary_key = key;
    }
}

/// Extracts the Tables contract from a `/__surface` document.
///
/// # Errors
///
/// [`GenerateError::UnsupportedSurfaceApi`] when the document speaks a
/// different contract version, [`GenerateError::NoTablesModule`] when the
/// document declares no `tables` module,
/// [`GenerateError::UnknownAction`] / [`GenerateError::UnreadableAction`]
/// when a Tables action falls outside the verb vocabulary, and
/// [`GenerateError::UnsupportedTableName`] when a table's name is not a
/// safe identifier.
///
/// # Panics
///
/// Never on any input: the one `expect` guards a lookup that the line
/// above it just satisfied (a table pushed when no action had named it
/// yet), so it is unreachable for every document.
pub fn extract(document: &SurfaceDocument) -> Result<Contract, GenerateError> {
    if document.surface_api != cratefield_core::SURFACE_API {
        return Err(GenerateError::UnsupportedSurfaceApi {
            found: document.surface_api,
            expected: cratefield_core::SURFACE_API,
        });
    }
    let module = document
        .modules
        .iter()
        .find(|module| module.name == TABLES_MODULE)
        .ok_or_else(|| GenerateError::NoTablesModule {
            modules: document
                .modules
                .iter()
                .map(|module| module.name.clone())
                .collect(),
        })?;

    let mut tables: Vec<TableModel> = Vec::new();
    for action in &module.surface.actions {
        let (verb, table_name) =
            split_action(&action.name).ok_or_else(|| GenerateError::UnknownAction {
                action: action.name.clone(),
            })?;
        // The name reaches the generated TypeScript as a property name and
        // inside doc comments, and the document is untrusted input, so it
        // is held to the declaration rule before anything else reads it.
        if !is_table_name(table_name) {
            return Err(GenerateError::UnsupportedTableName {
                table: table_name.to_owned(),
            });
        }
        // The audience is a fact about the table and every action of one
        // table carries the same one, so the action that first names the
        // table decides what the generated doc comments say.
        if tables.iter_mut().all(|table| table.name != table_name) {
            tables.push(TableModel {
                name: table_name.to_owned(),
                audience: action.audience,
                list_path: None,
                key_path: None,
                schema: None,
                columns: Vec::new(),
                primary_key: None,
                row_shape_known: false,
                has_read: false,
                has_create: false,
                has_replace: false,
                has_delete: false,
            });
        }
        let table = tables
            .iter_mut()
            .find(|table| table.name == table_name)
            .expect("the table was pushed on the line above when it was missing");

        let method = action.method.as_str();
        if method != verb.method() {
            return Err(GenerateError::UnreadableAction {
                action: action.name.clone(),
                why: format!(
                    "its verb is served by `{}`, and the contract carries `{}`",
                    verb.method(),
                    method
                ),
            });
        }
        match verb {
            Verb::List => {
                table.list_path = Some(list_path_of(table_name, &action.path, &action.name)?);
            }
            Verb::Read => {
                table.key_path = Some(key_path_of(table_name, &action.path, &action.name)?);
                table.has_read = true;
            }
            Verb::Create => {
                table.has_create = true;
                // The create body is the row schema — the contract's own
                // words for what a row is. `replace` carries the same
                // one; take whichever arrives, create first.
                if let Some(schema) = &action.input {
                    table.schema = Some(schema.as_value().clone());
                }
            }
            Verb::Replace => {
                table.has_replace = true;
                if table.schema.is_none()
                    && let Some(schema) = &action.input
                {
                    table.schema = Some(schema.as_value().clone());
                }
            }
            Verb::Delete => table.has_delete = true,
        }
    }

    for table in &mut tables {
        normalize(table);
    }

    Ok(Contract {
        venture: document.venture.name.clone(),
        mount: format!("/v1/{}", module.name),
        tables,
    })
}
