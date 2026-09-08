//! The schema type: what a venture declares, and the rules the
//! declaration itself must satisfy.
//!
//! This is a small purpose-built enum, not JSON Schema. JSON Schema is
//! sprawling and says nothing about the SQLite and Postgres DDL mapping,
//! so it is emitted as a derived view instead.
//!
//! The bound on what a field can express: a declaration covers required,
//! length, range, format, enum, uniqueness, foreign keys, defaults and
//! indexes. Anything that has to read another row or another request is a
//! function, not a field. Overlap checks, state machines and side effects
//! belong in a module or a sidecar.

use cratefield_core::ConfigError;
use serde_json::Value;

/// The longest identifier both dialects accept without truncation.
/// Postgres cuts identifiers at 63 bytes; the rule keeps a declared name
/// meaning the same thing on both engines.
pub const MAX_IDENTIFIER_CHARS: usize = 63;

/// Name prefixes the harness keeps for itself. A declared table or field
/// may not start with one, so a venture can never shadow the migration
/// bookkeeping or an engine catalogue.
pub const RESERVED_PREFIXES: &[&str] = &["harness_", "sqlite_", "pg_", "cf_"];

/// Every word either engine treats as a keyword in a table or column
/// position, plus the Postgres system column names. A declared name is
/// rejected rather than quoted, which is why the generated DDL needs no
/// quoting at all.
///
/// Sorted, deduplicated, and merged from four lists:
///
/// - PostgreSQL's `reserved` category, the `reserved_keyword` production
///   in its grammar, listed in Appendix C of the manual. These can never
///   be a table or column name unquoted.
/// - PostgreSQL's `type_func_name_keyword` category, Appendix C's
///   "reserved (can be function or type name)". A column named `binary`
///   or `similar` is a syntax error the same way.
/// - SQLite's keyword list, <https://sqlite.org/lang_keywords.html>.
///   SQLite accepts most of these in some positions and rejects them in
///   others, so the whole list is rejected rather than the subset that
///   happens to break today.
/// - The Postgres system column names, which every table has whether or
///   not they are declared: `tableoid`, `xmin`, `cmin`, `xmax`, `cmax`
///   and `ctid`. A declared column of one of those names is refused at
///   `CREATE TABLE`.
///
/// Two entries are a version ahead of the engines the review ran
/// against: `system_user` became reserved in PostgreSQL 16, and `xmax`
/// is a system column the review's list did not spell out.
pub const RESERVED_WORDS: &[&str] = &[
    "abort",
    "action",
    "add",
    "after",
    "all",
    "alter",
    "always",
    "analyse",
    "analyze",
    "and",
    "any",
    "array",
    "as",
    "asc",
    "asymmetric",
    "attach",
    "authorization",
    "autoincrement",
    "before",
    "begin",
    "between",
    "binary",
    "both",
    "by",
    "cascade",
    "case",
    "cast",
    "check",
    "cmax",
    "cmin",
    "collate",
    "collation",
    "column",
    "commit",
    "concurrently",
    "conflict",
    "constraint",
    "create",
    "cross",
    "ctid",
    "current",
    "current_catalog",
    "current_date",
    "current_role",
    "current_schema",
    "current_time",
    "current_timestamp",
    "current_user",
    "database",
    "default",
    "deferrable",
    "deferred",
    "delete",
    "desc",
    "detach",
    "distinct",
    "do",
    "drop",
    "each",
    "else",
    "end",
    "escape",
    "except",
    "exclude",
    "exclusive",
    "exists",
    "explain",
    "fail",
    "false",
    "fetch",
    "filter",
    "first",
    "following",
    "for",
    "foreign",
    "freeze",
    "from",
    "full",
    "generated",
    "glob",
    "grant",
    "group",
    "groups",
    "having",
    "if",
    "ignore",
    "ilike",
    "immediate",
    "in",
    "index",
    "indexed",
    "initially",
    "inner",
    "insert",
    "instead",
    "intersect",
    "into",
    "is",
    "isnull",
    "join",
    "key",
    "last",
    "lateral",
    "leading",
    "left",
    "like",
    "limit",
    "localtime",
    "localtimestamp",
    "match",
    "materialized",
    "natural",
    "no",
    "not",
    "nothing",
    "notnull",
    "null",
    "nulls",
    "of",
    "offset",
    "on",
    "only",
    "or",
    "order",
    "others",
    "outer",
    "over",
    "overlaps",
    "partition",
    "placing",
    "plan",
    "pragma",
    "preceding",
    "primary",
    "query",
    "raise",
    "range",
    "recursive",
    "references",
    "regexp",
    "reindex",
    "release",
    "rename",
    "replace",
    "restrict",
    "returning",
    "right",
    "rollback",
    "row",
    "rows",
    "savepoint",
    "select",
    "session_user",
    "set",
    "similar",
    "some",
    "symmetric",
    "system_user",
    "table",
    "tableoid",
    "tablesample",
    "temp",
    "temporary",
    "then",
    "ties",
    "to",
    "trailing",
    "transaction",
    "trigger",
    "true",
    "unbounded",
    "union",
    "unique",
    "update",
    "user",
    "using",
    "vacuum",
    "values",
    "variadic",
    "verbose",
    "view",
    "virtual",
    "when",
    "where",
    "window",
    "with",
    "without",
    "xmax",
    "xmin",
];

/// A text field's declared format. The row validator asserts these; JSON
/// Schema only annotates them, which is one of the reasons the JSON
/// Schema rendering is a view and not the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFormat {
    /// The address rule `cratefield-core` already applies everywhere it
    /// stores one, reused here so a declared table and a module cannot
    /// disagree about what an address is.
    Email,
    /// An absolute `http` or `https` URL with a non-empty host and no
    /// whitespace.
    Url,
}

impl TextFormat {
    /// The wire name, as written in the manifest.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TextFormat::Email => "email",
            TextFormat::Url => "url",
        }
    }
}

/// What one column holds. Deliberately small: every variant maps to a
/// column type in both dialects and to one rule in the row validator.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    /// A Unicode string. `min_len` and `max_len` count Unicode scalar
    /// values, never bytes and never UTF-16 code units.
    Text {
        min_len: Option<u32>,
        max_len: Option<u32>,
        format: Option<TextFormat>,
    },
    /// A whole number. Bounds are inclusive.
    Integer { min: Option<i64>, max: Option<i64> },
    /// A floating-point number. Bounds are inclusive.
    Real { min: Option<f64>, max: Option<f64> },
    /// `true` or `false`, never `0`, `1` or `"true"`.
    Boolean,
    /// An RFC 3339 timestamp, stored as ISO-8601 text. That is the
    /// portable subset every module migration already uses.
    Timestamp,
    /// A hyphenated 8-4-4-4-12 UUID string, stored as text.
    Uuid,
    /// Any JSON value, stored as text.
    Json,
    /// One of a fixed list of strings, compared case-sensitively.
    Enum { values: Vec<String> },
}

impl FieldKind {
    /// The wire name, as written in the manifest's `kind` key.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            FieldKind::Text { .. } => "text",
            FieldKind::Integer { .. } => "integer",
            FieldKind::Real { .. } => "real",
            FieldKind::Boolean => "boolean",
            FieldKind::Timestamp => "timestamp",
            FieldKind::Uuid => "uuid",
            FieldKind::Json => "json",
            FieldKind::Enum { .. } => "enum",
        }
    }

    /// A plain text field with no length bounds and no format.
    #[must_use]
    pub fn text() -> Self {
        FieldKind::Text {
            min_len: None,
            max_len: None,
            format: None,
        }
    }

    /// An integer field with no bounds.
    #[must_use]
    pub fn integer() -> Self {
        FieldKind::Integer {
            min: None,
            max: None,
        }
    }

    /// A real field with no bounds.
    #[must_use]
    pub fn real() -> Self {
        FieldKind::Real {
            min: None,
            max: None,
        }
    }
}

/// One declared column.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDef {
    /// Lowercase snake-case identifier, unique within the table.
    pub name: String,
    pub kind: FieldKind,
    /// `NOT NULL` in the generated DDL. A required field with a default
    /// may still be left out of a write: the database supplies the value.
    pub required: bool,
    /// `UNIQUE` in the generated DDL. Uniqueness is enforced by the
    /// database, never by the row validator, because it reads other rows.
    pub unique: bool,
    /// Gets its own `CREATE INDEX`.
    pub indexed: bool,
    /// Literal default, checked against `kind` by [`Schema::validate`].
    pub default: Option<Value>,
}

impl FieldDef {
    /// An optional field of `kind`, with no default and no index.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: FieldKind) -> Self {
        Self {
            name: name.into(),
            kind,
            required: false,
            unique: false,
            indexed: false,
            default: None,
        }
    }

    #[must_use]
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    #[must_use]
    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }

    #[must_use]
    pub fn indexed(mut self) -> Self {
        self.indexed = true;
        self
    }

    #[must_use]
    pub fn default_value(mut self, value: Value) -> Self {
        self.default = Some(value);
        self
    }

    /// Whether a write must carry this field. A default satisfies
    /// `required`, so only a required field without one has to be sent.
    #[must_use]
    pub fn must_be_present(&self) -> bool {
        self.required && self.default.is_none()
    }
}

/// A reference from one declared field to another declared table's
/// primary key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignKey {
    /// The field in this table that holds the reference.
    pub field: String,
    /// The declared table it points at. The referenced column is that
    /// table's primary key, which must be a single column.
    pub references: String,
}

impl ForeignKey {
    #[must_use]
    pub fn new(field: impl Into<String>, references: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            references: references.into(),
        }
    }
}

/// One declared table.
#[derive(Debug, Clone, PartialEq)]
pub struct TableDef {
    /// Lowercase snake-case identifier, unique within the schema.
    pub name: String,
    /// Columns, in declaration order. That order is the column order of
    /// the generated DDL and the order errors are reported in.
    pub fields: Vec<FieldDef>,
    /// One or more declared field names. Primary-key fields are `NOT
    /// NULL` whether or not they are marked required.
    pub primary_key: Vec<String>,
    pub foreign_keys: Vec<ForeignKey>,
}

impl TableDef {
    /// A table with a single-column primary key.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        primary_key: impl Into<String>,
        fields: Vec<FieldDef>,
    ) -> Self {
        Self {
            name: name.into(),
            fields,
            primary_key: vec![primary_key.into()],
            foreign_keys: Vec::new(),
        }
    }

    #[must_use]
    pub fn foreign_key(mut self, key: ForeignKey) -> Self {
        self.foreign_keys.push(key);
        self
    }

    /// The declared field called `name`, if there is one.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|field| field.name == name)
    }

    /// Whether `name` is part of the primary key.
    #[must_use]
    pub fn is_primary_key(&self, name: &str) -> bool {
        self.primary_key.iter().any(|key| key == name)
    }
}

/// Every table a venture declares, in name order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Schema {
    /// Declared tables. [`Schema::new`] and the manifest deserializer both
    /// sort by name, so the generated DDL does not depend on the order the
    /// manifest happened to list them in.
    pub tables: Vec<TableDef>,
}

impl Schema {
    /// Builds a schema, sorted by table name.
    #[must_use]
    pub fn new(tables: Vec<TableDef>) -> Self {
        let mut tables = tables;
        tables.sort_by(|a, b| a.name.cmp(&b.name));
        Self { tables }
    }

    /// The declared table called `name`, if there is one.
    #[must_use]
    pub fn table(&self, name: &str) -> Option<&TableDef> {
        self.tables.iter().find(|table| table.name == name)
    }

    /// Checks the declaration itself and reports every violation
    /// together, the way [`cratefield_core::Venture`] does.
    ///
    /// The rules: identifiers are lowercase snake-case, not reserved and
    /// not card-shaped; field and table names do not repeat; the primary
    /// key names declared fields and every one of them is required or
    /// defaulted; a foreign key points at a declared table with a
    /// single-column primary key of a matching kind, and the references
    /// hold no cycle; an enum declares at least one member; bounds are
    /// the right way round; a default matches its field's kind; and no
    /// two generated index names collide with each other or with a
    /// declared table name.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] carrying one line per violation.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = ConfigError::new();
        let mut seen_tables: Vec<String> = Vec::new();

        for table in &self.tables {
            check_identifier(&mut errors, "table", &table.name, &table.name);
            if seen_tables.iter().any(|seen| seen == &table.name) {
                errors.push(format!("table `{}`: declared twice", table.name));
            }
            seen_tables.push(table.name.clone());
            self.validate_table(&mut errors, table);
        }

        self.validate_index_names(&mut errors);
        self.validate_no_reference_cycle(&mut errors);

        errors.into_result()
    }

    /// Index names live in the same namespace as table names, in both
    /// engines, and that namespace is the whole schema rather than one
    /// table. `{table}_{field}_idx` is ambiguous because an underscore is
    /// legal in both halves, so `post.author_id` and `post_author.id`
    /// generate the same name. `CREATE INDEX IF NOT EXISTS` then leaves
    /// the second one silently absent, and a name that lands on a table
    /// loses the table instead.
    fn validate_index_names(&self, errors: &mut ConfigError) {
        let mut generated: Vec<(String, String, String)> = Vec::new();
        for table in &self.tables {
            for field in &table.fields {
                if !crate::ddl::needs_own_index(table, field) {
                    continue;
                }
                let index = crate::ddl::index_name(&table.name, &field.name);
                if let Some((_, first_table, first_field)) =
                    generated.iter().find(|(name, _, _)| name == &index)
                {
                    errors.push(format!(
                        "table `{}`, field `{}`: the generated index name `{index}` is already \
                         generated by table `{first_table}`, field `{first_field}`",
                        table.name, field.name
                    ));
                }
                if self.table(&index).is_some() {
                    errors.push(format!(
                        "table `{}`, field `{}`: the generated index name `{index}` is also a \
                         declared table name, and both engines keep indexes and tables in one \
                         namespace",
                        table.name, field.name
                    ));
                }
                generated.push((index, table.name.clone(), field.name.clone()));
            }
        }
    }

    /// A foreign key makes the referenced table a prerequisite, so a
    /// cycle has no creation order at all. Reported here rather than left
    /// for the renderer, because the script it would produce runs on
    /// neither engine.
    fn validate_no_reference_cycle(&self, errors: &mut ConfigError) {
        let (_, cyclic) = crate::ddl::creation_order(self);
        let Some(first) = cyclic.first() else {
            return;
        };
        let names: Vec<&str> = cyclic.iter().map(|table| table.name.as_str()).collect();
        let path = self.walk_cycle(&first.name, &names);
        errors.push(format!(
            "table `{}`: the foreign keys form a reference cycle, {}, so there is no order that \
             creates a table after the tables it references",
            first.name,
            path.join(" -> ")
        ));
    }

    /// Follows unresolved references from `start`, taking the
    /// alphabetically first each time, until a name repeats. Every table
    /// in `unresolved` has at least one unresolved reference, which is
    /// what left it there, so the walk always closes.
    fn walk_cycle(&self, start: &str, unresolved: &[&str]) -> Vec<String> {
        let mut path: Vec<&str> = Vec::new();
        let mut current = start;
        loop {
            if let Some(at) = path.iter().position(|name| *name == current) {
                let mut cycle: Vec<String> =
                    path[at..].iter().map(|&name| name.to_owned()).collect();
                cycle.push(current.to_owned());
                return cycle;
            }
            path.push(current);
            let next = self.table(current).and_then(|table| {
                table
                    .foreign_keys
                    .iter()
                    .map(|key| key.references.as_str())
                    .filter(|name| unresolved.contains(name))
                    .min()
            });
            match next {
                Some(next) => current = next,
                // Unreachable while `unresolved` comes from the sort, and
                // a partial path still names the table that is stuck.
                None => return path.iter().map(|&name| name.to_owned()).collect(),
            }
        }
    }

    fn validate_table(&self, errors: &mut ConfigError, table: &TableDef) {
        if table.fields.is_empty() {
            errors.push(format!("table `{}`: declares no fields", table.name));
        }

        let mut seen_fields: Vec<String> = Vec::new();
        for field in &table.fields {
            check_identifier(errors, "field", &field.name, &table.name);
            if seen_fields.iter().any(|seen| seen == &field.name) {
                errors.push(format!(
                    "table `{}`: field `{}` is declared twice",
                    table.name, field.name
                ));
            }
            seen_fields.push(field.name.clone());
            validate_field(errors, table, field);
        }

        validate_primary_key(errors, table);

        for key in &table.foreign_keys {
            self.validate_foreign_key(errors, table, key);
        }
    }

    fn validate_foreign_key(&self, errors: &mut ConfigError, table: &TableDef, key: &ForeignKey) {
        let Some(local) = table.field(&key.field) else {
            errors.push(format!(
                "table `{}`: foreign key on `{}`, which is not a declared field",
                table.name, key.field
            ));
            return;
        };
        let Some(target) = self.table(&key.references) else {
            errors.push(format!(
                "table `{}`: foreign key `{}` references table `{}`, which is not declared",
                table.name, key.field, key.references
            ));
            return;
        };
        let [target_key] = target.primary_key.as_slice() else {
            errors.push(format!(
                "table `{}`: foreign key `{}` references table `{}`, whose primary key is not a \
                 single column",
                table.name, key.field, target.name
            ));
            return;
        };
        let Some(target_field) = target.field(target_key) else {
            // The target table's own primary-key rule already reported it.
            return;
        };
        if local.kind.as_str() != target_field.kind.as_str() {
            errors.push(format!(
                "table `{}`: foreign key `{}` is {} but `{}.{}` is {}",
                table.name,
                key.field,
                local.kind.as_str(),
                target.name,
                target_field.name,
                target_field.kind.as_str()
            ));
        }
    }
}

fn validate_primary_key(errors: &mut ConfigError, table: &TableDef) {
    if table.primary_key.is_empty() {
        errors.push(format!("table `{}`: no primary key", table.name));
        return;
    }
    let mut seen: Vec<&String> = Vec::new();
    for key in &table.primary_key {
        match table.field(key) {
            None => errors.push(format!(
                "table `{}`: primary key names `{key}`, which is not a declared field",
                table.name
            )),
            // The rendered column is `NOT NULL` whether or not the field
            // says `required`, so a primary key that is neither required
            // nor defaulted is a column the row validator and the JSON
            // Schema would both let through and the insert would then
            // reject. Rejecting the declaration is what keeps the three
            // from ever disagreeing.
            Some(field) if !field.required && field.default.is_none() => errors.push(format!(
                "table `{}`: primary key `{key}` must be required or have a default, because a \
                 primary-key column is NOT NULL",
                table.name
            )),
            Some(_) => {}
        }
        if seen.contains(&key) {
            errors.push(format!(
                "table `{}`: primary key names `{key}` twice",
                table.name
            ));
        }
        seen.push(key);
    }
}

fn validate_field(errors: &mut ConfigError, table: &TableDef, field: &FieldDef) {
    let at = format!("table `{}`, field `{}`", table.name, field.name);
    match &field.kind {
        FieldKind::Text {
            min_len, max_len, ..
        } => {
            if let (Some(min), Some(max)) = (min_len, max_len)
                && min > max
            {
                errors.push(format!("{at}: min_len {min} is greater than max_len {max}"));
            }
            if *max_len == Some(0) {
                errors.push(format!("{at}: max_len 0 accepts nothing"));
            }
        }
        FieldKind::Integer { min, max } => {
            if let (Some(min), Some(max)) = (min, max)
                && min > max
            {
                errors.push(format!("{at}: min {min} is greater than max {max}"));
            }
        }
        FieldKind::Real { min, max } => {
            if let (Some(min), Some(max)) = (min, max)
                && min > max
            {
                errors.push(format!("{at}: min {min} is greater than max {max}"));
            }
            for (label, bound) in [("min", min), ("max", max)] {
                if bound.is_some_and(|value| !value.is_finite()) {
                    errors.push(format!("{at}: {label} is not a finite number"));
                }
            }
        }
        FieldKind::Enum { values } => {
            if values.is_empty() {
                errors.push(format!("{at}: an enum must declare at least one value"));
            }
            let mut seen: Vec<&String> = Vec::new();
            for value in values {
                if seen.contains(&value) {
                    errors.push(format!("{at}: enum value `{value}` is declared twice"));
                }
                seen.push(value);
            }
        }
        FieldKind::Boolean | FieldKind::Timestamp | FieldKind::Uuid | FieldKind::Json => {}
    }

    if let Some(default) = &field.default
        && let Err(error) = crate::value::check_value(&field.kind, default)
    {
        errors.push(format!("{at}: the default {default} {}", error.message));
    }

    // The generated index name has to be a legal identifier too, and it
    // is longer than either name it is built from.
    if crate::ddl::needs_own_index(table, field) {
        let index = crate::ddl::index_name(&table.name, &field.name);
        if index.chars().count() > MAX_IDENTIFIER_CHARS {
            errors.push(format!(
                "{at}: the generated index name `{index}` is longer than \
                 {MAX_IDENTIFIER_CHARS} characters"
            ));
        }
    }
}

/// Identifier rules, shared by table and field names. `what` is the noun
/// used in the message, `at` the table the name belongs to.
fn check_identifier(errors: &mut ConfigError, what: &str, name: &str, at: &str) {
    let where_ = if what == "table" {
        format!("table `{name}`")
    } else {
        format!("table `{at}`, field `{name}`")
    };

    if !is_identifier(name) {
        errors.push(format!(
            "{where_}: a {what} name must match [a-z][a-z0-9_]* and hold no double or trailing \
             underscore"
        ));
    } else if name.chars().count() > MAX_IDENTIFIER_CHARS {
        errors.push(format!(
            "{where_}: a {what} name is at most {MAX_IDENTIFIER_CHARS} characters"
        ));
    }

    if RESERVED_WORDS.contains(&name) {
        errors.push(format!("{where_}: `{name}` is a reserved SQL word"));
    }
    if let Some(prefix) = RESERVED_PREFIXES
        .iter()
        .find(|prefix| name.starts_with(*prefix))
    {
        errors.push(format!(
            "{where_}: the `{prefix}` prefix is reserved for the harness"
        ));
    }
    // The harness never stores card data (issue #44); a declared table is
    // exactly where it would otherwise appear.
    if let Some(fragment) = cratefield_core::card_data_hit(name) {
        errors.push(format!(
            "{where_}: `{fragment}` looks like card data. With a normal Stripe integration the \
             card never reaches a backend, so store only Stripe's identifiers"
        ));
    }
}

/// Lowercase snake-case: starts with a letter, then letters, digits and
/// single underscores, never ending in one. Nothing else is accepted, and
/// that is what lets the generated DDL leave identifiers unquoted.
#[must_use]
pub fn is_identifier(name: &str) -> bool {
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
