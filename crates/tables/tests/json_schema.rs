//! The JSON Schema view. A derived rendering for interop, never a source.

use cratefield_tables::{JSON_SCHEMA_DIALECT, Schema, json_schema};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Manifest {
    tables: Schema,
}

fn schema(fragment: &str) -> Schema {
    toml::from_str::<Manifest>(fragment)
        .expect("the fragment parses")
        .tables
}

const EVERYTHING: &str = r#"
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
name = "email"
kind = "text"
format = "email"

[[tables.post.fields]]
name = "site"
kind = "text"
format = "url"

[[tables.post.fields]]
name = "read_minutes"
kind = "integer"
min = 0
max = 600
required = true

[[tables.post.fields]]
name = "score"
kind = "real"
min = 0.0
max = 1.0

[[tables.post.fields]]
name = "featured"
kind = "boolean"
required = true
default = false

[[tables.post.fields]]
name = "created_at"
kind = "timestamp"
required = true

[[tables.post.fields]]
name = "body"
kind = "json"

[[tables.post.fields]]
name = "status"
kind = "enum"
values = ["draft", "published"]
required = true
"#;

#[test]
fn a_table_renders_as_exactly_this_json_schema() {
    let schema = schema(EVERYTHING);
    let rendered = json_schema(schema.table("post").unwrap());
    assert_eq!(
        rendered,
        json!({
            "$schema": JSON_SCHEMA_DIALECT,
            "title": "post",
            "type": "object",
            "additionalProperties": false,
            "required": ["id", "title", "read_minutes", "created_at", "status"],
            "properties": {
                "id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "Primary key of `post`."
                },
                // Every `text` property carries the NUL rule, and only
                // `text` does: a uuid, a timestamp and an enum are
                // already constrained to shapes that cannot hold one.
                "title": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 200,
                    "not": { "pattern": "\u{0}" }
                },
                "email": {
                    "type": ["string", "null"],
                    "format": "email",
                    "not": { "pattern": "\u{0}" }
                },
                "site": {
                    "type": ["string", "null"],
                    "format": "uri",
                    "not": { "pattern": "\u{0}" }
                },
                "read_minutes": { "type": "integer", "minimum": 0, "maximum": 600 },
                "score": { "type": ["number", "null"], "minimum": 0.0, "maximum": 1.0 },
                // `featured` is required but has a default, so a write need
                // not carry it and the rendering is nullable.
                "featured": { "type": ["boolean", "null"] },
                "created_at": { "type": "string", "format": "date-time" },
                "body": {},
                "status": { "type": "string", "enum": ["draft", "published"] }
            }
        })
    );
}

#[test]
fn required_lists_only_what_a_write_must_carry() {
    let schema = schema(EVERYTHING);
    let rendered = json_schema(schema.table("post").unwrap());
    let required = rendered["required"].as_array().unwrap();
    assert!(
        !required.iter().any(|name| name == "featured"),
        "a required field with a default does not have to be sent"
    );
}

#[test]
fn an_optional_enum_lists_the_null_it_accepts() {
    let schema = schema(
        r#"
[tables.post]
[[tables.post.fields]]
name = "id"
kind = "text"
required = true
[[tables.post.fields]]
name = "status"
kind = "enum"
values = ["draft", "published"]
"#,
    );
    let rendered = json_schema(schema.table("post").unwrap());
    assert_eq!(
        rendered["properties"]["status"]["enum"],
        json!(["draft", "published", null])
    );
}

#[test]
fn the_rendering_is_deterministic() {
    let schema = schema(EVERYTHING);
    let table = schema.table("post").unwrap();
    let once = json_schema(table).to_string();
    let twice = json_schema(table).to_string();
    assert_eq!(once.as_bytes(), twice.as_bytes());
}

#[test]
fn nothing_the_database_owns_leaks_into_the_view() {
    // Uniqueness, foreign keys, indexes and defaults are absent by
    // design: the first two read other rows, the last two are the
    // database's.
    let schema = schema(
        r#"
[tables.post]
[[tables.post.fields]]
name = "id"
kind = "text"
required = true
[[tables.post.fields]]
name = "slug"
kind = "text"
unique = true
indexed = true
default = "untitled"
"#,
    );
    let rendered = json_schema(schema.table("post").unwrap()).to_string();
    // An empty view leaks nothing and describes nothing. The four
    // absences below are only worth anything once the fields that carry
    // those properties are in the rendering.
    for present in ["\"id\"", "\"slug\"", "properties"] {
        assert!(
            rendered.contains(present),
            "the view does not describe {present}, so nothing below is checking anything: {rendered}"
        );
    }
    for absent in ["unique", "index", "default", "foreignKey"] {
        assert!(!rendered.contains(absent), "{absent} leaked: {rendered}");
    }
}

#[test]
fn properties_come_out_in_declaration_order_not_alphabetically() {
    // The view is a published contract, so its bytes are what a drift
    // gate compares. Declaration order holds only while
    // `serde_json/preserve_order` is on — without it a `Map` is a
    // `BTreeMap` and sorts the keys. The crate used to inherit the
    // feature from `cratefield-core`'s choice of a `schemars` feature and
    // now asks for it itself; this is what notices if that stops being
    // true.
    let schema = schema(
        r#"
[tables.post]
[[tables.post.fields]]
name = "zebra"
kind = "text"
required = true
[[tables.post.fields]]
name = "middle"
kind = "integer"
[[tables.post.fields]]
name = "alpha"
kind = "boolean"
"#,
    );
    let rendered = json_schema(schema.table("post").unwrap());
    let names: Vec<&String> = rendered["properties"]
        .as_object()
        .expect("properties is an object")
        .keys()
        .collect();
    assert_eq!(
        names,
        ["zebra", "middle", "alpha"],
        "properties were reordered; `serde_json/preserve_order` is off"
    );
}
