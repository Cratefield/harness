//! Renders the extracted Tables contract as the files of the generated
//! package. Same rule as every generator in this repository: the output
//! is a pure function of the input, so the same contract always generates
//! byte-identical files and the composition hash means something.
//!
//! The generated TypeScript is deliberately dependency-free beyond
//! `fetch`, and the `fetch` shape it needs is declared in the generated
//! source rather than taken from a DOM library, so the same package
//! type-checks in a browser, a Worker and Node alike.

use std::fmt::Write as _;

use cratefield_core::Audience;
use serde_json::Value;

use crate::GeneratedFile;
use crate::contract::{
    Contract, TableModel, column_nullable, dedup_keep_first, is_primary_key_marker,
};

/// The npm name every generated package carries. The venture is named
/// inside it (description, README), not in the package name: a customer's
/// imports do not change when they generate a second venture.
pub(crate) const PACKAGE_NAME: &str = "@cratefield/client";

/// One column of a typed table, as TypeScript will say it.
// Four flags, each read straight off the schema as a separate fact of it
// (`required`, the primary-key marker, filter-ability, sort-ability); no
// enum carries the four at once, which is why the model stays a flag set.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub(crate) struct TsColumn {
    /// The wire key, as the schema spells it.
    pub(crate) name: String,
    /// The type without its null arm: `"string"`, `"number"`,
    /// `"boolean"`, a string-literal union, or `"unknown"` for a `json`
    /// column (and anything the schema says that this generator cannot
    /// read — `unknown` is the honest widening).
    pub(crate) base: String,
    /// The type as a row carries it: [`Self::base`] plus `| null` when
    /// the schema says the column can be null.
    pub(crate) row_type: String,
    /// In the schema's `required`.
    pub(crate) required: bool,
    /// The primary-key column, identified the only way the contract
    /// marks one: a description beginning with the words `Primary key`
    /// of, followed by the table's name.
    pub(crate) is_pk: bool,
    /// Whether the page query may filter on it: everything but a `json`
    /// column, which has no equality on the wire.
    pub(crate) filterable: bool,
    /// Whether the page may be sorted by it: a non-nullable column that
    /// is schema-`required` or the primary key.
    pub(crate) sortable: bool,
}

/// One table, as the generated TypeScript says it.
// Five flags, each an independent fact of the contract: whether a row
// schema travelled at all, and which of the four non-page verbs the
// entry publishes. Every combination is a legal wire shape, so an enum
// could not say it without lying about one.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub(crate) struct TsTable {
    pub(crate) name: String,
    /// The accessor class (`NoteTable`).
    pub(crate) class: String,
    pub(crate) audience: Audience,
    /// The page's full path on the wire (`/v1/tables/note`).
    pub(crate) page_path: String,
    /// The single-row path (`/v1/tables/note/{key}`), when the contract
    /// publishes one.
    pub(crate) key_path: Option<String>,
    /// Whether the contract publishes a schema to type the rows from.
    /// `false` is the known gap: a read-only table's entry carries no
    /// schema anywhere.
    pub(crate) typed: bool,
    /// The primary key's TypeScript type, for `get`/`replace`/`delete`.
    pub(crate) key_type: String,
    pub(crate) columns: Vec<TsColumn>,
    pub(crate) has_read: bool,
    pub(crate) has_create: bool,
    pub(crate) has_replace: bool,
    pub(crate) has_delete: bool,
    /// `{Pascal}Row`.
    pub(crate) row: String,
    /// `New{Pascal}` — only meaningful for a table with a write.
    pub(crate) input: String,
    /// `{Pascal}Filters`.
    pub(crate) filters: String,
    /// `{Pascal}Sort`.
    pub(crate) sort: String,
}

impl TsTable {
    /// Whether the table is writable but names no single row: a
    /// composite-key table, per ADR 0018's interim.
    fn is_composite(&self) -> bool {
        self.has_create && !self.has_read
    }

    /// The `json` columns, for the doc comment that says why they take
    /// no filter.
    fn json_columns(&self) -> Vec<&str> {
        self.columns
            .iter()
            .filter(|column| column.base == "unknown")
            .map(|column| column.name.as_str())
            .collect()
    }

    /// The columns the page may be sorted by, in schema order.
    fn sortable(&self) -> Vec<&TsColumn> {
        self.columns
            .iter()
            .filter(|column| column.sortable)
            .collect()
    }
}

/// `note` to `Note`, `waitlist_send` to `WaitlistSend`.
fn pascal_case(name: &str) -> String {
    name.split(['_', '-'])
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// A TypeScript string literal, escaped the way JSON escapes one — the
/// two agree on every escape a table name, column name or enum member can
/// carry.
fn ts_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

/// One literal in a union type.
fn literal(value: &Value) -> String {
    match value {
        Value::String(text) => ts_string(text),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        _ => "unknown".to_owned(),
    }
}

/// The base type one JSON Schema `type` value names.
fn scalar(kind: &str) -> &'static str {
    match kind {
        "string" => "string",
        // An integer in draft 2020-12 is a number with a zero fractional
        // part; TypeScript has one number type for both.
        "integer" | "number" => "number",
        "boolean" => "boolean",
        _ => "unknown",
    }
}

/// A column's base type: its `enum` as a string-literal union when there
/// is one, its `type` otherwise, and `"unknown"` when the schema names
/// neither — a `json` column, deliberately, and anything else this
/// generator cannot read.
fn base_type(column_schema: &Value) -> String {
    if let Some(members) = column_schema.get("enum").and_then(Value::as_array) {
        let parts = dedup_keep_first(
            members
                .iter()
                .filter(|member| !member.is_null())
                .map(literal)
                .collect(),
        );
        if parts.is_empty() {
            return "unknown".to_owned();
        }
        return parts.join(" | ");
    }
    match column_schema.get("type") {
        Some(Value::String(kind)) => scalar(kind).to_owned(),
        Some(Value::Array(kinds)) => {
            let parts = dedup_keep_first(
                kinds
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|kind| *kind != "null")
                    .map(scalar)
                    .collect(),
            );
            if parts.is_empty() {
                "unknown".to_owned()
            } else {
                parts.join(" | ")
            }
        }
        _ => "unknown".to_owned(),
    }
}

/// The columns of one table, from the contract's own JSON Schema — the
/// one the write actions carry, which is `cratefield_tables::json_schema`'s
/// output: draft 2020-12, subschemas inlined, `additionalProperties:
/// false`. Property order is the schema's, which is the declaration's.
/// Nullability and the primary-key marker are read by `contract`'s own
/// helpers, not re-derived here: one parser, so the emitted row types and
/// sort union cannot disagree with the model.
fn columns_of(table: &TableModel) -> Vec<TsColumn> {
    let Some(schema) = &table.schema else {
        return Vec::new();
    };
    // The primary key is marked in the schema the only way the Tables
    // module marks it (`crates/tables/src/json_schema.rs`): a description
    // beginning `Primary key of \`{table}\`. Reading the marker, rather
    // than assuming the key column's name, keeps this honest against a
    // contract that renamed things.
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut columns = Vec::with_capacity(properties.len());
    for (name, column_schema) in properties {
        let base = base_type(column_schema);
        let nullable = column_nullable(column_schema);
        let required = required.contains(&name.as_str());
        let is_pk = is_primary_key_marker(column_schema);
        columns.push(TsColumn {
            name: name.clone(),
            row_type: if nullable && base != "unknown" {
                format!("{base} | null")
            } else {
                base.clone()
            },
            base,
            required,
            is_pk,
            filterable: true,
            sortable: !nullable && (required || is_pk),
        });
    }
    // A `json` column has no `type` at all in the schema (there is
    // nothing to narrow), and the wire gives equality on nothing it
    // cannot compare — so it takes no filter, and `unknown` is the mark.
    for column in &mut columns {
        if column.base == "unknown" {
            column.filterable = false;
        }
    }
    columns
}

/// The primary key's TypeScript type, from its column's own schema type:
/// an integer key arrives at `get(key: number)`, every other key is the
/// path-segment text it travels as. A table with no schema (or none
/// marked) keys on a string.
fn key_type_of(columns: &[TsColumn]) -> String {
    match columns.iter().find(|column| column.is_pk) {
        Some(pk) if pk.base == "number" => "number".to_owned(),
        _ => "string".to_owned(),
    }
}

fn render_table(contract: &Contract, table: &TableModel) -> TsTable {
    let pascal = pascal_case(&table.name);
    let columns = columns_of(table);
    let list_path = table
        .list_path
        .clone()
        .unwrap_or_else(|| format!("/{}", table.name));
    TsTable {
        class: format!("{pascal}Table"),
        page_path: format!("{}{list_path}", contract.mount),
        key_path: table
            .key_path
            .clone()
            .map(|path| format!("{}{path}", contract.mount)),
        typed: table.schema.is_some(),
        key_type: key_type_of(&columns),
        row: format!("{pascal}Row"),
        input: format!("New{pascal}"),
        filters: format!("{pascal}Filters"),
        sort: format!("{pascal}Sort"),
        name: table.name.clone(),
        audience: table.audience,
        columns,
        has_read: table.has_read,
        has_create: table.has_create,
        has_replace: table.has_replace,
        has_delete: table.has_delete,
    }
}

/// Every file of the package, in write order.
pub(crate) fn emit(contract: &Contract) -> Vec<GeneratedFile> {
    let tables: Vec<TsTable> = contract
        .tables
        .iter()
        .map(|table| render_table(contract, table))
        .collect();
    vec![
        GeneratedFile {
            path: "package.json".to_owned(),
            contents: package_json(contract),
        },
        GeneratedFile {
            path: "tsconfig.json".to_owned(),
            contents: tsconfig_json(contract),
        },
        GeneratedFile {
            path: "README.md".to_owned(),
            contents: package_readme(contract, &tables),
        },
        GeneratedFile {
            path: "src/index.ts".to_owned(),
            contents: index_ts(contract, &tables),
        },
        GeneratedFile {
            path: "src/runtime.ts".to_owned(),
            contents: runtime_ts(),
        },
        GeneratedFile {
            path: "src/types.ts".to_owned(),
            contents: types_ts(contract, &tables),
        },
    ]
}

/// The npm manifest. `dependencies` is absent on purpose: the only thing
/// the generated client runs on is `fetch`, and a package that ships
/// source under `exports` carries nothing else to resolve.
fn package_json(contract: &Contract) -> String {
    let package = serde_json::json!({
        "name": PACKAGE_NAME,
        "version": "0.1.0",
        "description": format!(
            "Typed tables client for the {} venture, generated from its /__surface contract.",
            contract.venture
        ),
        "type": "module",
        "types": "./src/index.ts",
        "exports": {
            ".": "./src/index.ts"
        },
        "files": ["src", "README.md", "tsconfig.json"],
        "scripts": {
            "check": "tsc"
        },
        "keywords": ["cratefield", "tables", "client", "typescript"],
        "license": "MIT"
    });
    let mut out = serde_json::to_string_pretty(&package).unwrap_or_else(|_| "{}".to_owned());
    out.push('\n');
    out
}

/// The compile check's configuration. `tsconfig.json` is JSONC, so the
/// reasons ride along as comments.
fn tsconfig_json(contract: &Contract) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "// GENERATED for {PACKAGE_NAME}, generated from the `{venture}` venture's",
        venture = contract.venture
    );
    out.push_str("// /__surface contract. Re-run the generator; do not edit by hand.\n");
    out.push_str("{\n");
    out.push_str("  \"compilerOptions\": {\n");
    out.push_str("    // The API's wire shape is ES2022. No DOM lib is assumed: the client\n");
    out.push_str("    // declares the `fetch` shape it needs, so the same source\n");
    out.push_str("    // type-checks in a browser, a Worker and Node alike.\n");
    out.push_str("    \"target\": \"ES2022\",\n");
    out.push_str("    \"lib\": [\"ES2022\"],\n");
    out.push_str("    \"module\": \"ESNext\",\n");
    out.push_str("    \"moduleResolution\": \"bundler\",\n");
    out.push_str("    \"strict\": true,\n");
    out.push_str("    \"isolatedModules\": true,\n");
    out.push_str("    \"skipLibCheck\": true,\n");
    out.push_str("    \"forceConsistentCasingInFileNames\": true,\n");
    out.push_str("    // The package ships source, so consumers compile it; `npm run check`\n");
    out.push_str("    // type-checks without emitting.\n");
    out.push_str("    \"noEmit\": true\n");
    out.push_str("  },\n");
    out.push_str("  \"include\": [\"src\"]\n");
    out.push_str("}\n");
    out
}

/// The audience sentence, as each table's class doc comment says it. The
/// two credential audiences get the sentence the issue asks for: an
/// `admin` table needs the deployment's admin token specifically, a
/// `subject` table needs any signed-in caller.
fn audience_doc(out: &mut String, table: &TsTable) {
    let name = &table.name;
    let line = match table.audience {
        Audience::Public => {
            format!(" * The `{name}` table. audience: `public` — no credential needed.\n")
        }
        Audience::Subject => format!(
            " * The `{name}` table. audience: `subject` — needs any signed-in caller:\n \
             * the credential decides only that you are somebody, and the table's\n \
             * access level decides which rows you see.\n"
        ),
        Audience::Admin => format!(
            " * The `{name}` table. audience: `admin` — needs the deployment's admin\n \
             * token specifically, not merely any signed-in caller.\n"
        ),
        Audience::Link => format!(
            " * The `{name}` table. audience: `link` — reached through a link the\n \
             * venture minted, so the proof travels in the link, not in a header.\n"
        ),
    };
    out.push_str(&line);
}

/// The single-row URL expression: a string key is encoded as it is, an
/// integer key has to become text first.
fn key_expression(table: &TsTable) -> &'static str {
    if table.key_type == "number" {
        "encodeURIComponent(String(key))"
    } else {
        "encodeURIComponent(key)"
    }
}

/// One typed table's accessor class.
// The five methods are one class in the emitted source, doc comments and
// all; the length is the emission, not entanglement.
#[allow(clippy::too_many_lines)]
fn typed_table_class(out: &mut String, table: &TsTable) {
    let key = key_expression(table);
    let _ = writeln!(out, "/**");
    audience_doc(out, table);
    if table.is_composite() {
        out.push_str(" *\n");
        out.push_str(" * Its primary key is more than one column, so a row cannot be named in\n");
        out.push_str(" * a path: the contract publishes the page and the create and no\n");
        out.push_str(" * single-row action — `get`, `replace` and `delete` would answer\n");
        out.push_str(" * `400 composite-key` whatever they were called with.\n");
    }
    out.push_str(" */\n");
    let _ = writeln!(out, "export class {} {{", table.class);
    out.push_str("  private readonly http: Http;\n");
    out.push('\n');
    out.push_str("  /** @internal */\n");
    let _ = writeln!(out, "  constructor(http: Http) {{");
    out.push_str("    this.http = http;\n");
    out.push_str("  }\n");
    out.push('\n');

    // The page. `list()` returns the query builder; the filters and the
    // sort are the contract's own columns.
    out.push_str("  /** The page: `GET ");
    out.push_str(&table.page_path);
    out.push_str("`. */\n");
    let _ = writeln!(
        out,
        "  list(): TableQuery<{row}, {filters}, {sort}> {{",
        row = table.row,
        filters = table.filters,
        sort = table.sort
    );
    let _ = writeln!(
        out,
        "    return new TableQuery<{row}, {filters}, {sort}>(this.http, {path}, {{",
        row = table.row,
        filters = table.filters,
        sort = table.sort,
        path = ts_string(&table.page_path)
    );
    out.push_str("      filters: [],\n");
    out.push_str("      sort: null,\n");
    out.push_str("      after: null,\n");
    out.push_str("    });\n");
    out.push_str("  }\n");
    out.push('\n');

    if table.has_read {
        let path = table.key_path.clone().unwrap_or_default();
        out.push_str("  /** One row by its primary key: `GET ");
        out.push_str(&path);
        out.push_str("`. */\n");
        let _ = writeln!(
            out,
            "  get(key: {key_type}): Promise<{row}> {{",
            key_type = table.key_type,
            row = table.row
        );
        let _ = writeln!(
            out,
            "    return this.http.request<{row}>(\"GET\", `{path}/${{{key}}}`);",
            row = table.row,
            path = ts_string(&path),
        );
        out.push_str("  }\n");
        out.push('\n');
    }

    if table.has_create {
        out.push_str("  /** Creates a row: `POST ");
        out.push_str(&table.page_path);
        out.push_str("`, answered `201` with the row as stored. */\n");
        let _ = writeln!(
            out,
            "  create(row: {input}): Promise<{row}> {{",
            input = table.input,
            row = table.row
        );
        let _ = writeln!(
            out,
            "    return this.http.request<{row}>(\"POST\", {path}, undefined, row);",
            row = table.row,
            path = ts_string(&table.page_path)
        );
        out.push_str("  }\n");
        out.push('\n');
    }

    if table.has_replace {
        let path = table.key_path.clone().unwrap_or_default();
        out.push_str("  /** Replaces a row: `PUT ");
        out.push_str(&path);
        out.push_str("`. Replace, not merge: every column is written. */\n");
        let _ = writeln!(
            out,
            "  replace(key: {key_type}, row: {input}): Promise<{row}> {{",
            key_type = table.key_type,
            input = table.input,
            row = table.row
        );
        let _ = writeln!(
            out,
            "    return this.http.request<{row}>(\"PUT\", `{path}/${{{key}}}`, undefined, row);",
            row = table.row,
            path = ts_string(&path),
        );
        out.push_str("  }\n");
        out.push('\n');
    }

    if table.has_delete {
        let path = table.key_path.clone().unwrap_or_default();
        out.push_str("  /** Deletes a row: `DELETE ");
        out.push_str(&path);
        out.push_str("`, answered `204` with no body. */\n");
        let _ = writeln!(
            out,
            "  async delete(key: {key_type}): Promise<void> {{",
            key_type = table.key_type
        );
        let _ = writeln!(
            out,
            "    await this.http.request<void>(\"DELETE\", `{path}/${{{key}}}`);",
            path = ts_string(&path),
        );
        out.push_str("  }\n");
        out.push('\n');
    }

    append_async_iterator(out, &table.row, "this.list()");
    out.push_str("}\n");
    out.push('\n');
}

/// The async-iterator tail shared by every typed table class: the rows the
/// page query reaches, walked by following `next` until it is `null`.
/// Delegation rather than a reimplementation — `TableQuery` owns the
/// paging, so `for await (const row of table)` and
/// `for await (const row of table.list().where(..))` walk the same way.
fn append_async_iterator(out: &mut String, row: &str, make: &str) {
    let _ = writeln!(
        out,
        "  /** Lets `for await (const row of table)` walk every row the caller reaches. */"
    );
    let _ = writeln!(
        out,
        "  [Symbol.asyncIterator](): AsyncGenerator<{row}, void, void> {{"
    );
    let _ = writeln!(out, "    return {make}[Symbol.asyncIterator]();");
    out.push_str("  }\n");
}

/// One untyped table's accessor class: a read-only contract entry with no
/// schema anywhere on it, so the page takes no typed filters and the rows
/// stay unknown.
fn untyped_table_class(out: &mut String, table: &TsTable) {
    let _ = writeln!(out, "/**");
    audience_doc(out, table);
    out.push_str(" *\n");
    out.push_str(" * Read-only in the contract: it publishes the page and the single row\n");
    out.push_str(" * and no write, so there is no `create`, `replace` or `delete` here.\n");
    out.push_str(" * It publishes no row schema either, so rows are `");
    out.push_str(&table.row);
    out.push_str("` and the page\n");
    out.push_str(" * takes no typed filters or sort.\n");
    out.push_str(" */\n");
    let _ = writeln!(out, "export class {} {{", table.class);
    out.push_str("  private readonly http: Http;\n");
    out.push('\n');
    out.push_str("  /** @internal */\n");
    let _ = writeln!(out, "  constructor(http: Http) {{");
    out.push_str("    this.http = http;\n");
    out.push_str("  }\n");
    out.push('\n');
    out.push_str("  /** The page: `GET ");
    out.push_str(&table.page_path);
    out.push_str("`. Pass the previous page's `next` as `after` to page\n");
    out.push_str("   * past the first 50 rows; the size is the server's. */\n");
    let _ = writeln!(
        out,
        "  list(after?: Cursor | undefined): Promise<Page<{row}>> {{",
        row = table.row
    );
    out.push_str("    const query =\n");
    out.push_str("      after === undefined\n");
    out.push_str("        ? undefined\n");
    out.push_str("        : `after=${encodeURIComponent(JSON.stringify(after))}`;\n");
    let _ = writeln!(
        out,
        "    return this.http.request<Page<{row}>>(\"GET\", {path}, query);",
        row = table.row,
        path = ts_string(&table.page_path)
    );
    out.push_str("  }\n");
    out.push('\n');
    if table.has_read {
        let path = table.key_path.clone().unwrap_or_default();
        out.push_str("  /** One row: `GET ");
        out.push_str(&path);
        out.push_str("`. The key is the raw path segment; the contract\n");
        out.push_str("   * publishes no schema to type it from. */\n");
        let _ = writeln!(
            out,
            "  get(key: string): Promise<{row}> {{",
            row = table.row
        );
        let _ = writeln!(
            out,
            "    return this.http.request<{row}>(\"GET\", `{path}/${{encodeURIComponent(key)}}`);",
            row = table.row,
            path = ts_string(&path)
        );
        out.push_str("  }\n");
        out.push('\n');
    }
    // The walk is written out here rather than delegated: `list()` takes
    // the cursor instead of returning a builder, because a table with no
    // schema has no honest filter or sort type to build one from.
    out.push_str("  /** Lets `for await (const row of table)` walk every page. */\n");
    let _ = writeln!(
        out,
        "  async *[Symbol.asyncIterator](): AsyncGenerator<{row}, void, void> {{",
        row = table.row
    );
    out.push_str("    let cursor: Cursor | null = null;\n");
    out.push_str("    for (;;) {\n");
    out.push_str("      const page = await this.list(cursor ?? undefined);\n");
    out.push_str("      for (const row of page.rows) {\n");
    out.push_str("        yield row;\n");
    out.push_str("      }\n");
    out.push_str("      if (page.next === null) {\n");
    out.push_str("        return;\n");
    out.push_str("      }\n");
    out.push_str("      cursor = page.next;\n");
    out.push_str("    }\n");
    out.push_str("  }\n");
    out.push_str("}\n");
    out.push('\n');
}

/// `src/index.ts`: the per-table classes, the two clients, the factory.
// The file is emitted as one ordered whole — imports, types, classes,
// clients, factory — and its length is that order, not tangled logic.
#[allow(clippy::too_many_lines)]
fn index_ts(contract: &Contract, tables: &[TsTable]) -> String {
    let mut out = String::new();
    out.push_str("/**\n");
    let _ = writeln!(
        out,
        " * GENERATED for the `{venture}` venture from its /__surface contract.",
        venture = contract.venture
    );
    out.push_str(" * Do not edit by hand: change the venture's declaration and regenerate.\n");
    out.push_str(" *\n");
    out.push_str(" * One accessor per table the venture declares, typed from the JSON\n");
    out.push_str(" * Schemas the contract publishes and restricted to the routes it\n");
    out.push_str(" * actually serves — a table the contract publishes no write for has no\n");
    out.push_str(" * write method here, and that absence is the point.\n");
    out.push_str(" */\n");
    out.push('\n');
    out.push_str("import { Http } from \"./runtime.js\";\n");
    // `createClient`'s signatures name these, and the factory is emitted
    // for every venture.
    out.push_str("import type { ClientOptions, TokenSource } from \"./runtime.js\";\n");
    // `TableQuery` is constructed — a value, not only a type — by every
    // typed table's `list()`; a venture whose tables are all untyped (the
    // known gap) names it nowhere.
    if tables.iter().any(|table| table.typed) {
        out.push_str("import { TableQuery } from \"./runtime.js\";\n");
    }
    if tables.iter().any(|table| !table.typed) {
        out.push_str("import type { Cursor, Page } from \"./runtime.js\";\n");
    }
    out.push_str(
        "export {\n\
         \x20 ApiError,\n\
         \x20 PROBLEM_TYPE_BASE,\n\
         \x20 type ClientOptions,\n\
         \x20 type Cursor,\n\
         \x20 type FetchLike,\n\
         \x20 type FetchResponse,\n\
         \x20 type Page,\n\
         \x20 type ProblemSlug,\n\
         \x20 type TokenSource,\n\
         } from \"./runtime.js\";\n",
    );

    // The row types, per table that has them; and the input, filter and
    // sort types, which only a typed table carries.
    let mut type_names: Vec<String> = Vec::new();
    for table in tables {
        if !table.typed {
            type_names.push(table.row.clone());
            continue;
        }
        type_names.push(table.row.clone());
        if table.has_create || table.has_replace {
            type_names.push(table.input.clone());
        }
        type_names.push(table.filters.clone());
        type_names.push(table.sort.clone());
    }
    let _ = writeln!(
        out,
        "import type {{ {names} }} from \"./types.js\";",
        names = type_names.join(", ")
    );
    let _ = writeln!(
        out,
        "export type {{ {names} }} from \"./types.js\";",
        names = type_names.join(", ")
    );
    out.push('\n');

    for table in tables {
        if table.typed {
            typed_table_class(&mut out, table);
        } else {
            untyped_table_class(&mut out, table);
        }
    }

    // The clients. `PublicClient` is the venture's public face: the
    // tables whose every action the contract marks `public`. The
    // credential audiences ride on `AuthenticatedClient`.
    out.push_str("/**\n");
    out.push_str(" * The venture's public face: the tables whose every action is\n");
    out.push_str(" * `audience: \"public\"`. No credential needed.\n");
    out.push_str(" */\n");
    let _ = writeln!(out, "export class PublicClient {{");
    out.push_str("  protected readonly http: Http;\n");
    out.push('\n');
    for table in tables
        .iter()
        .filter(|table| table.audience == Audience::Public)
    {
        let _ = writeln!(
            out,
            "  /** The `{name}` table (audience: `public`) — no credential needed. */",
            name = table.name
        );
        let _ = writeln!(
            out,
            "  readonly {name}: {class};",
            name = table.name,
            class = table.class
        );
    }
    let _ = writeln!(out, "  constructor(http: Http) {{");
    out.push_str("    this.http = http;\n");
    for table in tables
        .iter()
        .filter(|table| table.audience == Audience::Public)
    {
        let _ = writeln!(
            out,
            "    this.{name} = new {class}(http);",
            name = table.name,
            class = table.class
        );
    }
    out.push_str("  }\n");
    out.push_str("}\n");
    out.push('\n');

    let authed: Vec<&TsTable> = tables
        .iter()
        .filter(|table| table.audience != Audience::Public)
        .collect();
    out.push_str("/**\n");
    out.push_str(" * The full client: the public tables, plus the ones that need a\n");
    out.push_str(" * credential. A `subject` table needs any signed-in caller; an `admin`\n");
    out.push_str(" * table needs the deployment's admin token specifically.\n");
    out.push_str(" */\n");
    let _ = writeln!(
        out,
        "export class AuthenticatedClient extends PublicClient {{"
    );
    for table in &authed {
        let note = match table.audience {
            Audience::Admin => "needs the deployment's admin token specifically",
            Audience::Subject => "needs any signed-in caller",
            _ => "reached through a link the venture minted",
        };
        let _ = writeln!(
            out,
            "  /** The `{name}` table (audience: `{audience}`) — {note}. */",
            name = table.name,
            audience = audience_word(table.audience),
            note = note
        );
        let _ = writeln!(
            out,
            "  readonly {name}: {class};",
            name = table.name,
            class = table.class
        );
    }
    let _ = writeln!(out, "  constructor(http: Http) {{");
    out.push_str("    super(http);\n");
    for table in &authed {
        let _ = writeln!(
            out,
            "    this.{name} = new {class}(http);",
            name = table.name,
            class = table.class
        );
    }
    out.push_str("  }\n");
    out.push_str("}\n");
    out.push('\n');

    out.push_str("/**\n");
    out.push_str(" * Builds a client from options.\n");
    out.push_str(" *\n");
    out.push_str(" * With a `token` — a string, or a function returning one, possibly\n");
    out.push_str(" * asynchronously — the tables that need a credential become reachable,\n");
    out.push_str(" * and the type says so: the returned `AuthenticatedClient` has an\n");
    out.push_str(" * accessor for every table the venture publishes. Without one, only the\n");
    out.push_str(" * public tables are, and a `PublicClient` has no accessor for the rest.\n");
    out.push_str(" */\n");
    out.push_str(
        "export function createClient(\n\
         \x20 options: ClientOptions & { token: TokenSource },\n\
         ): AuthenticatedClient;\n",
    );
    out.push_str("export function createClient(options: ClientOptions): PublicClient;\n");
    out.push_str(
        "export function createClient(\n\
         \x20 options: ClientOptions & { token?: TokenSource },\n\
         ): PublicClient | AuthenticatedClient {\n",
    );
    out.push_str("  const http = new Http(options);\n");
    out.push_str("  return options.token === undefined\n");
    out.push_str("    ? new PublicClient(http)\n");
    out.push_str("    : new AuthenticatedClient(http);\n");
    out.push_str("}\n");
    out
}

/// The audience as the contract spells it on the wire.
fn audience_word(audience: Audience) -> &'static str {
    match audience {
        Audience::Public => "public",
        Audience::Subject => "subject",
        Audience::Admin => "admin",
        Audience::Link => "link",
    }
}

/// `src/types.ts`: the row, input, filter and sort types, one set per
/// table the contract publishes a schema for, and the read-only alias for
/// the tables it does not.
fn types_ts(contract: &Contract, tables: &[TsTable]) -> String {
    let mut out = String::new();
    out.push_str("/**\n");
    let _ = writeln!(
        out,
        " * GENERATED for the `{venture}` venture from its /__surface contract.",
        venture = contract.venture
    );
    out.push_str(" * The shapes are the contract's own JSON Schemas, one per table that\n");
    out.push_str(" * publishes one: required columns non-optional, optional columns\n");
    out.push_str(" * nullable (a null and a missing key are the same absence here).\n");
    out.push_str(" * Regenerate; do not edit.\n");
    out.push_str(" */\n");
    out.push('\n');

    for table in tables {
        if table.typed {
            row_interface(&mut out, table);
            input_interface(&mut out, table);
            filters_interface(&mut out, table);
            sort_type(&mut out, table);
        } else {
            readonly_alias(&mut out, table);
        }
    }
    out
}

/// The row interface: every declared column, present, null where unset —
/// which is how the API answers a read.
fn row_interface(out: &mut String, table: &TsTable) {
    let _ = writeln!(
        out,
        "/** One row of `{name}`, exactly as the API answers it: every declared",
        name = table.name
    );
    out.push_str(" * column is present, null where unset. */\n");
    let _ = writeln!(out, "export interface {row} {{", row = table.row);
    for column in &table.columns {
        column_doc(out, column);
        let _ = writeln!(
            out,
            "  {key}: {ty};",
            key = ts_property_key(&column.name),
            ty = column.row_type
        );
    }
    out.push_str("}\n");
    out.push('\n');
}

/// The create/replace input: the contract's own body schema. An absent
/// optional column is stored as null (or takes the column's default);
/// `replace` overwrites every column, it does not merge.
fn input_interface(out: &mut String, table: &TsTable) {
    if !table.has_create && !table.has_replace {
        return;
    }
    out.push_str("/**\n");
    let _ = writeln!(
        out,
        " * A row of `{name}` as `create` and `replace` take it. An absent optional",
        name = table.name
    );
    out.push_str(" * column is stored as null, or takes the column's default; `replace`\n");
    out.push_str(" * writes every column, it does not merge.\n");
    out.push_str(" */\n");
    let _ = writeln!(out, "export interface {input} {{", input = table.input);
    for column in &table.columns {
        column_doc(out, column);
        let optionality = if column.required { "" } else { "?" };
        let _ = writeln!(
            out,
            "  {key}{optionality}: {ty};",
            key = ts_property_key(&column.name),
            ty = column.row_type
        );
    }
    out.push_str("}\n");
    out.push('\n');
}

/// The equality-filter type for the page query. Everything but a `json`
/// column: the wire has no equality for one, and the server refuses a
/// parameter it does not know.
fn filters_interface(out: &mut String, table: &TsTable) {
    out.push_str("/**\n");
    let _ = writeln!(
        out,
        " * Equality filters for `{name}`, as the page query takes them.",
        name = table.name
    );
    let json = table.json_columns();
    match json.as_slice() {
        [] => out.push_str(" *\n"),
        [only] => {
            let _ = writeln!(
                out,
                " * A `json` column (`{only}`) is not filterable — the wire has no",
            );
            out.push_str(" * equality for one — so it is absent here.\n");
        }
        several => {
            let names = several
                .iter()
                .map(|name| format!("`{name}`"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                out,
                " * The `json` columns ({names}) are not filterable — the wire has no",
            );
            out.push_str(" * equality for one — so they are absent here.\n");
        }
    }
    out.push_str(" */\n");
    let _ = writeln!(
        out,
        "export interface {filters} {{",
        filters = table.filters
    );
    for column in table.columns.iter().filter(|column| column.filterable) {
        let _ = writeln!(
            out,
            "  {key}?: {ty};",
            key = ts_property_key(&column.name),
            ty = column.base
        );
    }
    out.push_str("}\n");
    out.push('\n');
}

/// The sort union: the non-nullable columns — the schema's `required`
/// plus the primary key. The server refuses the rest, because nulls order
/// differently between the two engines it runs on.
fn sort_type(out: &mut String, table: &TsTable) {
    out.push_str("/**\n");
    let _ = writeln!(
        out,
        " * What the page of `{name}` may be ordered by: `\"col\"` ascending,",
        name = table.name
    );
    out.push_str(" * `\"-col\"` descending, one column — the primary key is already the\n");
    out.push_str(" * tiebreaker. The server refuses a column whose values can be null\n");
    out.push_str(" * (`400 bad-sort`), so the union is the contract's non-nullable\n");
    out.push_str(" * columns: the schema's `required` plus the primary key.\n");
    out.push_str(" *\n");
    out.push_str(" * Slightly conservative on purpose: a column declared required with a\n");
    out.push_str(" * default sorts server-side but is absent from the schema's\n");
    out.push_str(" * `required`, so this union may refuse a sort the server would\n");
    out.push_str(" * accept.\n");
    out.push_str(" */\n");
    let arms: Vec<String> = table
        .sortable()
        .iter()
        .flat_map(|column| {
            // Both arms are string literals on the wire: `"id"` ascending,
            // `"-id"` descending — a leading minus inside the quotes, not
            // a negation of a quoted name.
            vec![
                ts_string(&column.name),
                ts_string(&format!("-{}", column.name)),
            ]
        })
        .collect();
    // A table whose schema lists no sortable column cannot happen from
    // the Tables module (the primary key is always one), but the emitter
    // stays total: `never` is a union of nothing.
    let union = if arms.is_empty() {
        "never".to_owned()
    } else {
        arms.join(" | ")
    };
    let _ = writeln!(out, "export type {} = {union};", table.sort);
    out.push('\n');
}

/// The known gap, as the generated file says it: a read-only table
/// publishes no write, the write is where a row schema travels, and so
/// there is nothing in the contract to type these rows from.
fn readonly_alias(out: &mut String, table: &TsTable) {
    out.push_str("/**\n");
    let _ = writeln!(
        out,
        " * `{name}` is published read-only: the contract serves `list-{name}` and",
        name = table.name
    );
    let _ = writeln!(
        out,
        " * `read-{name}` and no write, and the write is where a row schema",
        name = table.name
    );
    out.push_str(" * travels. No schema appears anywhere in its surface entry, so there\n");
    out.push_str(" * is nothing in the contract to type these rows from. Widen them with\n");
    out.push_str(" * the venture's own knowledge of the table rather than guessing here.\n");
    out.push_str(" */\n");
    let _ = writeln!(
        out,
        "export type {row} = Record<string, unknown>;",
        row = table.row
    );
    out.push('\n');
}

/// The doc line a column carries in a row or input interface.
fn column_doc(out: &mut String, column: &TsColumn) {
    if column.is_pk {
        let _ = writeln!(out, "  /** Primary key. */");
    } else if column.base == "unknown" {
        out.push_str("  /** Any JSON value; the contract does not narrow it. */\n");
    }
}

/// The wire key as a TypeScript property: bare when it is an identifier
/// that is not a reserved word, quoted otherwise.
fn ts_property_key(name: &str) -> String {
    const RESERVED: &[&str] = &[
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "enum",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "new",
        "null",
        "return",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "var",
        "void",
        "while",
        "with",
    ];
    let identifier = !name.is_empty()
        && name.chars().enumerate().all(|(index, character)| {
            if index == 0 {
                character.is_ascii_alphabetic() || character == '_' || character == '$'
            } else {
                character.is_ascii_alphanumeric() || character == '_' || character == '$'
            }
        });
    if identifier && !RESERVED.contains(&name) {
        name.to_owned()
    } else {
        ts_string(name)
    }
}

/// The venture-free runtime every generated package ships: the fetch
/// plumbing, the bearer token, the page and its cursor, the query
/// builder, and the problem+json error. Byte-identical for every venture,
/// which is what makes the venture-specific files the only ones worth
/// reading.
fn runtime_ts() -> String {
    let mut out = String::new();
    out.push_str("/**\n");
    out.push_str(" * GENERATED as part of the @cratefield/client package; do not edit by\n");
    out.push_str(" * hand: re-run the generator instead.\n");
    out.push_str(" *\n");
    out.push_str(" * The only runtime dependency is `fetch`. Its shape is declared here\n");
    out.push_str(" * rather than taken from a DOM library, so the same source\n");
    out.push_str(" * type-checks in a browser, a Worker and Node alike — and a host\n");
    out.push_str(" * without `fetch` on `globalThis` takes one through the options.\n");
    out.push_str(" */\n");
    out.push('\n');
    out.push_str(RUNTIME_TS);
    out
}

const RUNTIME_TS: &str = r#"/**
 * What this client needs of a response: the subset it reads. A real
 * `Response` has all of it.
 */
export interface FetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

/**
 * A `fetch` implementation: `globalThis.fetch`, or your own — a test
 * double, a Worker-bound client, an older runtime.
 */
export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  },
) => Promise<FetchResponse>;

/**
 * The credential the API's bearer checks. A literal token, or a function
 * returning one — possibly asynchronously, for a stored or refreshing
 * one. Resolved per request, so a refreshed token is picked up without
 * rebuilding the client.
 */
export type TokenSource = string | (() => string | Promise<string>);

export interface ClientOptions {
  /** The venture's origin, with or without a trailing slash. */
  baseUrl: string;
  /** A `fetch` to run requests with. Defaults to `globalThis.fetch`. */
  fetch?: FetchLike;
}

/** The `fetch` this runtime falls back to, when the host has one. */
const GLOBAL_FETCH: FetchLike | undefined = (globalThis as {
  fetch?: FetchLike;
}).fetch;

function noFetch(): Promise<FetchResponse> {
  return Promise.reject(
    new Error(
      "no fetch on globalThis in this runtime; pass one as options.fetch",
    ),
  );
}

/** The URI base every problem `type` is under. */
export const PROBLEM_TYPE_BASE = "https://factory0.ventures/problems/";

/**
 * The slugs the tables API answers with, and the status each rides on.
 * A server newer than this client may answer a slug this union does not
 * list; it still arrives, as the string the class carries.
 */
export type ProblemSlug =
  | "no-such-table" // 404
  | "no-such-row" // 404
  | "unauthenticated" // 401
  | "table-forbidden" // 403
  | "table-read-only" // 403
  | "not-yours-to-give" // 403
  | "bad-filter" // 400
  | "bad-sort" // 400
  | "bad-cursor" // 400
  | "bad-key" // 400
  | "composite-key" // 400
  | "validation-failed" // 422
  | "already-exists"; // 409

/**
 * One API error, parsed from the problem+json the tables API answers
 * with. Narrow on {@link ProblemSlug} through the `slug`: the slug is the
 * stable part, and the one a caller branches on.
 */
export class ApiError extends Error {
  /** The HTTP status the problem was answered with. */
  readonly status: number;
  /** The problem's stable human title. */
  readonly title: string;
  /** What the server said went wrong, when it said. */
  readonly detail: string | null;
  /** The request id the server attached, when it did. */
  readonly instance: string | null;
  /** The full problem `type` URI. */
  readonly type: string;
  /** The stable slug — the last path segment of `type`. */
  readonly slug: string;

  /** @internal Parses a body that was expected to be problem+json. */
  constructor(problem: unknown, status: number) {
    const body = (problem ?? {}) as {
      type?: unknown;
      title?: unknown;
      status?: unknown;
      detail?: unknown;
      instance?: unknown;
    };
    const title =
      typeof body.title === "string" ? body.title : `HTTP ${status}`;
    super(title);
    this.name = "ApiError";
    this.status = typeof body.status === "number" ? body.status : status;
    this.title = title;
    this.detail = typeof body.detail === "string" ? body.detail : null;
    this.instance = typeof body.instance === "string" ? body.instance : null;
    this.type = typeof body.type === "string" ? body.type : "";
    this.slug = this.type.startsWith(PROBLEM_TYPE_BASE)
      ? this.type.slice(PROBLEM_TYPE_BASE.length)
      : this.type;
  }
}

/**
 * A page of rows. `next` is the cursor for the page after this one, or
 * `null` when the table is exhausted. The size is the server's (50 rows);
 * there is no caller-supplied limit.
 */
export interface Page<Row> {
  rows: Row[];
  next: Cursor | null;
}

/**
 * A cursor: the primary-key columns (and the sort column, when the page
 * is sorted) of the last row on a page. Take it from `next` and hand it
 * back to `.after(...)` verbatim — it is never built by hand.
 */
export type Cursor = {
  readonly [column: string]: string | number | boolean;
};

/** The query string parts of a page request, ready to encode. */
interface QueryParts {
  filters: ReadonlyArray<readonly [column: string, value: string]>;
  sort: string | null;
  after: string | null;
}

/**
 * A page request being built. Chainable, and immutable: every method
 * returns a new query, so a partially built one can be reused as the
 * base of another.
 */
export class TableQuery<Row, Filters extends object, Sort extends string> {
  private readonly http: Http;
  private readonly path: string;
  private readonly parts: QueryParts;

  /** @internal Built by a table's `list()`. */
  constructor(http: Http, path: string, parts: QueryParts) {
    this.http = http;
    this.path = path;
    this.parts = parts;
  }

  private with(parts: QueryParts): TableQuery<Row, Filters, Sort> {
    return new TableQuery<Row, Filters, Sort>(this.http, this.path, parts);
  }

  /**
   * Narrows the page by equality on declared columns. A `json` column
   * takes no filter — the wire has no equality for one — and the server
   * refuses a parameter it does not know with `400 bad-filter`.
   */
  where(filters: Filters): TableQuery<Row, Filters, Sort> {
    const added = Object.entries(filters).map(
      ([column, value]) => [column, String(value)] as const,
    );
    return this.with({
      ...this.parts,
      filters: [...this.parts.filters, ...added],
    });
  }

  /**
   * Orders the page: `"col"` ascending, `"-col"` descending. One column —
   * the primary key is already the tiebreaker. The union is restricted to
   * the columns the contract marks non-nullable; the server refuses the
   * rest with `400 bad-sort`.
   */
  sort(by: Sort): TableQuery<Row, Filters, Sort> {
    return this.with({ ...this.parts, sort: by });
  }

  /**
   * Resumes after `cursor` — the `next` value of a previous page, sent
   * back verbatim. It travels as percent-encoded JSON; a bare value is a
   * `400 bad-cursor`.
   */
  after(cursor: Cursor): TableQuery<Row, Filters, Sort> {
    return this.with({ ...this.parts, after: JSON.stringify(cursor) });
  }

  /** The page itself. */
  async page(): Promise<Page<Row>> {
    return this.http.request<Page<Row>>(
      "GET",
      this.path,
      toQueryString(this.parts),
    );
  }

  /**
   * Every row the query reaches: follows `next` until the table is
   * exhausted, yielding each page's rows as they arrive. Prefer this to
   * paging by hand when the caller would only loop anyway.
   */
  async *items(): AsyncGenerator<Row, void, void> {
    let query: TableQuery<Row, Filters, Sort> = this;
    for (;;) {
      const page: Page<Row> = await query.page();
      for (const row of page.rows) {
        yield row;
      }
      if (page.next === null) {
        return;
      }
      query = query.after(page.next);
    }
  }

  /** Lets `for await (const row of query)` walk the table. */
  [Symbol.asyncIterator](): AsyncGenerator<Row, void, void> {
    return this.items();
  }
}

/** Percent-encodes the query; `undefined` when there is nothing to ask. */
function toQueryString(parts: QueryParts): string | undefined {
  const pieces = parts.filters.map(
    ([column, value]) =>
      `${encodeURIComponent(column)}=${encodeURIComponent(value)}`,
  );
  if (parts.sort !== null) {
    pieces.push(`sort=${encodeURIComponent(parts.sort)}`);
  }
  if (parts.after !== null) {
    // The cursor is JSON, percent-encoded; the server parses it back.
    pieces.push(`after=${encodeURIComponent(parts.after)}`);
  }
  return pieces.length === 0 ? undefined : pieces.join("&");
}

/** Resolves the token source per request. */
async function bearer(token: TokenSource): Promise<string> {
  return typeof token === "string" ? token : await token();
}

/**
 * The HTTP plumbing: base URL, optional bearer, JSON both ways, and
 * problem+json turned into an {@link ApiError}. One per client.
 *
 * @internal Not part of the generated surface; the table classes take one.
 */
export class Http {
  private readonly base: string;
  private readonly send: FetchLike;
  private readonly token: TokenSource | undefined;

  constructor(options: ClientOptions & { token?: TokenSource }) {
    const base = options.baseUrl.replace(/\/+$/, "");
    if (base === "") {
      throw new TypeError(
        "baseUrl is required: the origin the venture is served from",
      );
    }
    this.base = base;
    this.token = options.token;
    this.send = options.fetch ?? GLOBAL_FETCH ?? noFetch;
  }

  /**
   * Runs one request and unwraps the JSON. `204` has no body and comes
   * back as `undefined`; anything not `2xx` throws the problem+json as
   * an {@link ApiError}.
   *
   * @internal
   */
  async request<Body>(
    method: string,
    path: string,
    query?: string | undefined,
    body?: unknown,
  ): Promise<Body> {
    const headers: Record<string, string> = {};
    if (this.token !== undefined) {
      headers.authorization = `Bearer ${await bearer(this.token)}`;
    }
    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }
    const url =
      query === undefined || query === ""
        ? `${this.base}${path}`
        : `${this.base}${path}?${query}`;
    const response = await this.send(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 204) {
      return undefined as Body;
    }
    const payload: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      throw new ApiError(payload, response.status);
    }
    return payload as Body;
  }
}
"#;

/// The primary key's wire name, for the README example's `created.{key}`:
/// the schema-marked column, or `id` — the wire's own default — when the
/// contract marks none (a composite key, or no schema at all).
fn primary_key_name(table: &TsTable) -> String {
    table
        .columns
        .iter()
        .find(|column| column.is_pk)
        .map_or_else(|| "id".to_owned(), |column| column.name.clone())
}

/// The generated package's README: what it is, a working example, and the
/// gap the contract itself creates.
// One artifact emitted start to finish — the prose, the example and the
// gap section answer to each other, and splitting it would scatter the
// write order that the composition hash pins.
#[allow(clippy::too_many_lines)]
fn package_readme(contract: &Contract, tables: &[TsTable]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# {PACKAGE_NAME} — {venture}",
        venture = contract.venture
    );
    out.push('\n');
    out.push_str("The typed TypeScript client for the **");
    out.push_str(&contract.venture);
    out.push_str("** venture's tables API, GENERATED from the venture's\n");
    out.push_str("`/__surface` contract. Do not edit by hand: change the venture's\n");
    out.push_str("declaration and regenerate — every method here is a route the\n");
    out.push_str("contract publishes, and nothing else.\n");
    out.push('\n');
    out.push_str("## Use\n");
    out.push('\n');
    out.push_str("```ts\n");
    out.push_str("import { ApiError, createClient } from \"@cratefield/client\";\n");
    out.push('\n');
    out.push_str("// The tables the venture serves without a credential:\n");
    out.push_str("const anon = createClient({ baseUrl: \"https://venture.example\" });\n");
    if let Some(public) = tables
        .iter()
        .find(|table| table.audience == Audience::Public)
    {
        let _ = writeln!(
            out,
            "const page = await anon.{name}.list();",
            name = public.name
        );
        out.push_str("console.log(page.rows, page.next);\n");
    }
    out.push('\n');
    out.push_str("// Signed in: the `subject` and `admin` tables appear on the client.\n");
    out.push_str("// A token string, or a function returning one (possibly asynchronously):\n");
    out.push_str("const client = createClient({\n");
    out.push_str("  baseUrl: \"https://venture.example\",\n");
    out.push_str("  token: () => sessionStorage.getItem(\"token\") ?? \"\",\n");
    out.push_str("});\n");
    let writable: Vec<&TsTable> = tables
        .iter()
        .filter(|table| table.typed && table.has_create)
        .collect();
    if let Some(table) = writable.first() {
        let _ = writeln!(
            out,
            "const created = await client.{name}.create({{",
            name = table.name
        );
        for column in table.columns.iter().filter(|column| column.required) {
            let value = match column.base.as_str() {
                "number" => "0",
                "boolean" => "false",
                "unknown" => "null",
                _ => "\"...\"",
            };
            let _ = writeln!(
                out,
                "  {key}: {value},",
                key = ts_property_key(&column.name),
            );
        }
        out.push_str("});\n");
        let _ = writeln!(
            out,
            "const mine = await client.{name}.where({{ }}).sort(\"{first}\").page();",
            name = table.name,
            first = table
                .sortable()
                .first()
                .map_or_else(|| table.name.clone(), |column| column.name.clone()),
        );
        let _ = writeln!(
            out,
            "for await (const row of client.{name}) console.log(row); // walks every page",
            name = table.name
        );
        if table.has_read {
            let _ = writeln!(
                out,
                "const row = await client.{name}.get(created.{key});",
                name = table.name,
                key = ts_property_key(&primary_key_name(table)),
            );
        }
        if table.has_delete {
            let _ = writeln!(
                out,
                "await client.{name}.delete(created.{key});",
                name = table.name,
                key = ts_property_key(&primary_key_name(table)),
            );
        }
    }
    out.push('\n');
    // The error example names a table the venture actually publishes, and
    // reaches it through the client that can: `anon` for a public table,
    // `client` for a credential one.
    if let Some(example) = tables.iter().find(|table| table.has_read) {
        let accessor = if example.audience == Audience::Public {
            "anon"
        } else {
            "client"
        };
        out.push_str("try {\n");
        let _ = writeln!(
            out,
            "  await {accessor}.{name}.get(\"nope\");",
            accessor = accessor,
            name = example.name
        );
        out.push_str("} catch (err) {\n");
        out.push_str("  if (err instanceof ApiError && err.slug === \"no-such-row\") {\n");
        out.push_str("    // the stable slug is the thing to branch on\n");
        out.push_str("  }\n");
        out.push_str("}\n");
    }
    out.push_str("```\n");
    out.push('\n');
    out.push_str("## What the contract does not say\n");
    out.push('\n');
    let untyped: Vec<&TsTable> = tables.iter().filter(|table| !table.typed).collect();
    if untyped.is_empty() {
        out.push_str("Every table this venture publishes carries a schema, so every row\n");
        out.push_str("is typed. If the venture later declares a table whose access level\n");
        out.push_str("is `public-read`, its contract entry will carry no schema at all — a\n");
        out.push_str("read-only table publishes no write, and the write is where the row\n");
        out.push_str("schema travels — and that table's rows will arrive as\n");
        out.push_str("`Record<string, unknown>`.\n");
    } else {
        for table in &untyped {
            let _ = writeln!(
                out,
                "- `{name}` is read-only in the contract: it publishes no write, and",
                name = table.name
            );
            out.push_str("  the write is where a row schema travels. No schema appears\n");
            out.push_str("  anywhere in its surface entry, so its rows are `");
            out.push_str(&table.row);
            out.push_str("` —\n");
            out.push_str("  `Record<string, unknown>` — and its page takes no typed filters or\n");
            out.push_str("  sort.\n");
        }
    }
    out.push('\n');
    out.push_str("## Notes\n");
    out.push('\n');
    out.push_str("- The only runtime dependency is `fetch`. Pass `fetch` in the options\n");
    out.push_str("  to inject one (tests, Workers, older runtimes).\n");
    out.push_str("- The page size is the server's — 50 rows — and there is no\n");
    out.push_str("  caller-supplied limit. `next` is the cursor: pass it to `.after(...)`\n");
    out.push_str("  verbatim; it travels as percent-encoded JSON.\n");
    out.push_str("- The sort unions cover the contract's non-nullable columns. A column\n");
    out.push_str("  declared required with a default may sort server-side while missing\n");
    out.push_str("  from the union — slightly conservative on purpose.\n");
    out.push_str("- A `subject` table needs any signed-in caller; an `admin` table needs\n");
    out.push_str("  the deployment's admin token specifically.\n");
    out
}
