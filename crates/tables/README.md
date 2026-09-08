<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-tables"><img src="https://img.shields.io/crates/v/cratefield-tables.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-tables on crates.io"></a>
  <a href="https://docs.rs/cratefield-tables"><img src="https://img.shields.io/docsrs/cratefield-tables?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-tables documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-tables

The schema a venture declares in its manifest. One declaration, several
artifacts: the SQLite and Postgres DDL, the row validator, and a JSON
Schema view for anyone who wants one.

Pure logic. No I/O, no database driver, no clock and no randomness, so it
builds for `wasm32-unknown-unknown` alongside `cratefield-core`.

## The schema type

```rust
use cratefield_tables::{FieldDef, FieldKind, Schema, TableDef, TextFormat};

let schema = Schema::new(vec![TableDef::new(
    "subscriber",
    "id",
    vec![
        FieldDef::new("id", FieldKind::Uuid).required(),
        FieldDef::new(
            "email",
            FieldKind::Text { min_len: Some(3), max_len: Some(254), format: Some(TextFormat::Email) },
        )
        .required()
        .unique(),
        FieldDef::new("signed_up_at", FieldKind::Timestamp).required().indexed(),
    ],
)]);

schema.validate().expect("the declaration itself is valid");
```

## Rules the declaration must satisfy

`Schema::validate` reports every violation together, the way
`cratefield_core::Venture` does:

- identifiers match `[a-z][a-z0-9_]*`, hold no double or trailing
  underscore, and are at most 63 characters, which is what Postgres
  accepts without truncating;
- a name is not a reserved SQL word, does not start with a prefix the
  harness keeps (`harness_`, `sqlite_`, `pg_`, `cf_`), and is not shaped
  like card data;
- no table name repeats, and no field name repeats inside a table;
- the primary key is non-empty and names declared fields;
- a foreign key names a declared field and points at a declared table
  whose primary key is a single column of the same kind;
- an enum declares at least one value, with no duplicates;
- bounds are the right way round, and a default is a value its own field
  would accept.

Identifiers are rejected rather than quoted. That is deliberate: it is
what lets the generated DDL leave every identifier unquoted, the way the
hand-written module migrations do.

## The manifest

`[tables]` is a map keyed by table name. A field is one entry in that
table's `fields` array, flat: a `kind` and the attributes that kind
accepts. An attribute that does not apply to the kind is an error, not an
ignored key. A silently dropped `max_len` is the drift this crate exists
to prevent.

A `venture.toml` fragment, parsed here by a real TOML parser so the
example cannot drift from what the crate accepts:

```rust
use cratefield_tables::{FieldKind, Schema};

#[derive(serde::Deserialize)]
struct Manifest {
    tables: Schema,
}

let fragment = r#"
[tables.author]
primary_key = "id"

[[tables.author.fields]]
name = "id"
kind = "uuid"
required = true

[[tables.author.fields]]
name = "email"
kind = "text"
format = "email"
max_len = 254
required = true
unique = true

[tables.post]
primary_key = "id"

[[tables.post.fields]]
name = "id"
kind = "uuid"
required = true

[[tables.post.fields]]
name = "title"
kind = "text"
min_len = 1
max_len = 200
required = true

[[tables.post.fields]]
name = "status"
kind = "enum"
values = ["draft", "published"]
required = true
default = "draft"

[[tables.post.fields]]
name = "read_minutes"
kind = "integer"
min = 0
max = 600

[[tables.post.fields]]
name = "author_id"
kind = "uuid"
indexed = true

[[tables.post.foreign_keys]]
field = "author_id"
references = "author"
"#;

let manifest: Manifest = toml::from_str(fragment).expect("the fragment parses");
manifest.tables.validate().expect("the declaration is valid");

// Tables arrive in name order, whatever order the manifest listed them in.
let names: Vec<&str> = manifest.tables.tables.iter().map(|t| t.name.as_str()).collect();
assert_eq!(names, ["author", "post"]);

let status = manifest.tables.table("post").unwrap().field("status").unwrap();
assert_eq!(
    status.kind,
    FieldKind::Enum { values: vec!["draft".to_owned(), "published".to_owned()] }
);
```

Keys, and where each applies:

| Key | Applies to | Meaning |
|---|---|---|
| `name` | every field | the column name |
| `kind` | every field | `text`, `integer`, `real`, `boolean`, `timestamp`, `uuid`, `json`, `enum` |
| `required` | every field | `NOT NULL`; a field with a default may still be left out of a write |
| `unique` | every field | `UNIQUE`, enforced by the database |
| `indexed` | every field | gets its own `CREATE INDEX` |
| `default` | every field | a literal the field would itself accept |
| `min_len`, `max_len` | `text` | length in Unicode characters |
| `format` | `text` | `email` or `url` |
| `min`, `max` | `integer`, `real` | inclusive bounds |
| `values` | `enum` | the allowed strings, at least one |

`primary_key` takes a string or an array of strings and defaults to
`"id"`. `foreign_keys` entries are `{ field, references }`, where
`references` names another declared table and the referenced column is
that table's primary key.

## DDL

`Schema::ddl` renders one script per dialect. It validates first, so SQL
can never come from a definition whose identifiers were not checked.

```rust
use cratefield_tables::{Schema, SqlDialect};

#[derive(serde::Deserialize)]
struct Manifest {
    tables: Schema,
}

let manifest: Manifest = toml::from_str(r#"
[tables.post]
primary_key = "id"

[[tables.post.fields]]
name = "id"
kind = "uuid"
required = true

[[tables.post.fields]]
name = "status"
kind = "enum"
values = ["draft", "published"]
required = true
default = "draft"

[[tables.post.fields]]
name = "created_at"
kind = "timestamp"
required = true
indexed = true
"#).unwrap();

let sql = manifest.tables.ddl(SqlDialect::Sqlite).unwrap();
assert_eq!(sql, "\
-- Generated by cratefield-tables from the venture manifest.
-- Dialect: sqlite. Forward-only: this file only creates.

CREATE TABLE IF NOT EXISTS post (
    id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS post_created_at_idx ON post (created_at);
");
```

**Forward-only.** Only `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF
NOT EXISTS` are rendered, never `DROP` and never `ALTER`. The diff
between two versions of a definition is a separate problem.

**Deterministic.** The same definition always renders byte-identical SQL,
and a test asserts it: tables in name order, columns in declaration
order, every clause on a column in a fixed position, and no hash map
anywhere in the path.

**Portable.** Both dialects' output passes
`cratefield_core::lint_portable_sql`, the predicate `fz doctor` runs over
a module's hand-written migrations.

Column types per dialect:

| kind | SQLite | Postgres |
|---|---|---|
| `text`, `uuid`, `json`, `enum` | `TEXT` | `TEXT` |
| `timestamp` | `TEXT` | `TEXT` |
| `integer` | `INTEGER` | `BIGINT` |
| `real` | `REAL` | `DOUBLE PRECISION` |
| `boolean` | `INTEGER` | `BOOLEAN` |

A timestamp is text in both and a UUID is text in both, because the
harness stores ISO-8601 timestamps and text ids everywhere else. Boolean
is the one kind whose storage differs, `0` and `1` against `FALSE` and
`TRUE`, because SQLite has no boolean type.

`indexed` on a field that is already `unique` or part of the primary key
adds no second index: the constraint has one.

## Row validation

`validate_row` checks a `serde_json` object against a table and answers
with a structured list. The list renders into the harness's existing
RFC 9457 problem, `validation-failed`, so a declared table's 400 reads
like a module's. No new slug and no new error style.

```rust
use cratefield_tables::{ErrorCode, Schema, validate_row};
use serde_json::json;

#[derive(serde::Deserialize)]
struct Manifest {
    tables: Schema,
}

let manifest: Manifest = toml::from_str(r#"
[tables.post]
primary_key = "id"

[[tables.post.fields]]
name = "id"
kind = "text"
required = true

[[tables.post.fields]]
name = "title"
kind = "text"
min_len = 1
max_len = 5
required = true
"#).unwrap();

let post = manifest.tables.table("post").unwrap();

validate_row(post, &json!({"id": "x", "title": "hi"})).unwrap();

let errors = validate_row(post, &json!({"id": "x", "title": "far too long"})).unwrap_err();
assert_eq!(errors.errors()[0].code, ErrorCode::TooLong);

let problem = errors.problem();
assert_eq!(problem.slug, "validation-failed");
assert_eq!(problem.status.as_u16(), 400);
```

The rules, which are also the rules a generated client has to match:

- **A row is a JSON object.** Anything else is one error against the row
  itself, reported with an empty field name.
- **`null` is absence.** `{"note": null}` and `{}` always reach the same
  verdict.
- **A default satisfies `required`.** Only a field that is required and
  has no default has to be sent.
- **An unknown key is an error**, never a dropped key.
- **No coercion.** `"42"` is not an integer, `1` is not `true`.
- **An integer is a JSON number with no fractional part**, which is
  `Number.isInteger(v)` in JavaScript, so `42.0` is accepted.
- **Length is counted in Unicode scalar values**, so a JavaScript
  implementation counts `[...s].length` and never `s.length`. There is no
  normalisation: `e` plus a combining acute is two characters.
- **Nothing is trimmed.** Whitespace is part of the value.
- **Bounds are inclusive** at both ends.
- **Uniqueness and foreign keys are not checked here.** They read other
  rows, which makes them the database's job and marks the line between a
  field and a function.

Errors come out in a fixed order: declared fields in declaration order,
then unknown keys sorted by name.

## The conformance corpus

`corpus/rows.json` holds triples of table, input and expected verdict.
`tests/corpus.rs` runs the Rust validator over all of them, and a second
implementation in another language runs over the same file. That is what
stops this validator and a generated client disagreeing about empty
versus absent, number coercion, null versus missing, Unicode length and
whitespace. Every one of those five has cases, and a test fails if any
group loses them.

Match on the `code`, never on a message: codes are the stable vocabulary,
messages are prose. The file lists its own vocabulary, and a test fails
if that list and the crate's codes drift apart.

## The JSON Schema view

`json_schema` renders a table as a JSON Schema (draft 2020-12) object.
**It is a derived view and never the source.** Nothing here reads a JSON
Schema back. It exists so an outside tool that speaks JSON Schema can
describe a declared table, and if the two ever disagree the `TableDef` is
right.

```rust
use cratefield_tables::{Schema, json_schema};

#[derive(serde::Deserialize)]
struct Manifest {
    tables: Schema,
}

let manifest: Manifest = toml::from_str(r#"
[tables.post]
primary_key = "id"

[[tables.post.fields]]
name = "id"
kind = "uuid"
required = true

[[tables.post.fields]]
name = "title"
kind = "text"
max_len = 200
required = true

[[tables.post.fields]]
name = "note"
kind = "text"
"#).unwrap();

let view = json_schema(manifest.tables.table("post").unwrap());
assert_eq!(view["type"], "object");
assert_eq!(view["required"], serde_json::json!(["id", "title"]));
assert_eq!(view["additionalProperties"], false);
// An optional field is nullable, because null and absent are the same here.
assert_eq!(view["properties"]["note"]["type"], serde_json::json!(["string", "null"]));
```

Carries over exactly: `minLength` and `maxLength` count Unicode code
points in JSON Schema too; `type: "integer"` in draft 2020-12 is a number
with a zero fractional part, the same rule; `additionalProperties: false`
is the unknown-key rejection; `minimum` and `maximum` are inclusive.

Does not carry over: `format` is an annotation in JSON Schema and an
assertion here; a validator that distinguishes null from a missing key
will still disagree about a required field set to `null`; and
uniqueness, foreign keys, indexes and defaults do not appear at all.

## Not built here

This crate is the schema definition and nothing downstream of it. Each of
these is a follow-up:

- CRUD route handlers, the `public-read | owner | tenant-members | admin`
  access vocabulary, and the batched read endpoint.
- The migration diff between two versions of a definition. Everything
  here only creates.
- The generated `@cratefield/client` TypeScript package, and the second
  run of `corpus/rows.json` against its Zod schemas.
- Publishing declared tables on `/__surface`, and any control plane or
  manifest generator wiring.
