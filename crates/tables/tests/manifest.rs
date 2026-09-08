//! The `[tables]` section of the manifest, parsed by a real TOML parser.
//!
//! The documented fragment lives in the crate README and runs as a
//! doctest. These cases cover what the fragment cannot: the rejections.

use cratefield_tables::{FieldKind, Schema, TableDef, TextFormat};
use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    tables: Schema,
}

fn parse(fragment: &str) -> Result<Schema, toml::de::Error> {
    toml::from_str::<Manifest>(fragment).map(|manifest| manifest.tables)
}

fn error(fragment: &str) -> String {
    match parse(fragment) {
        Ok(_) => panic!("expected a parse error"),
        Err(error) => error.to_string(),
    }
}

const MINIMAL: &str = r#"
[tables.post]
primary_key = "id"

[[tables.post.fields]]
name = "id"
kind = "uuid"
required = true
"#;

#[test]
fn a_minimal_table_parses() {
    let schema = parse(MINIMAL).expect("parses");
    assert_eq!(schema.tables.len(), 1);
    let table = schema.table("post").expect("the table is there");
    assert_eq!(table.primary_key, ["id"]);
    assert_eq!(table.fields.len(), 1);
    assert_eq!(table.fields[0].kind, FieldKind::Uuid);
    assert!(table.fields[0].required);
    schema.validate().expect("valid");
}

#[test]
fn the_primary_key_defaults_to_id() {
    let schema = parse(
        r#"
[tables.post]

[[tables.post.fields]]
name = "id"
kind = "uuid"
"#,
    )
    .expect("parses");
    assert_eq!(schema.table("post").unwrap().primary_key, ["id"]);
}

#[test]
fn a_composite_primary_key_parses() {
    let schema = parse(
        r#"
[tables.item]
primary_key = ["collection", "slug"]

[[tables.item.fields]]
name = "collection"
kind = "text"

[[tables.item.fields]]
name = "slug"
kind = "text"
"#,
    )
    .expect("parses");
    assert_eq!(
        schema.table("item").unwrap().primary_key,
        ["collection", "slug"]
    );
}

#[test]
fn field_order_follows_the_manifest_and_table_order_follows_the_name() {
    let schema = parse(
        r#"
[tables.zebra]
[[tables.zebra.fields]]
name = "id"
kind = "uuid"

[tables.apple]
[[tables.apple.fields]]
name = "id"
kind = "uuid"
[[tables.apple.fields]]
name = "zzz"
kind = "text"
[[tables.apple.fields]]
name = "aaa"
kind = "text"
"#,
    )
    .expect("parses");
    let names: Vec<&str> = schema.tables.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["apple", "zebra"], "tables sort by name");
    let fields: Vec<&str> = schema
        .table("apple")
        .unwrap()
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(fields, ["id", "zzz", "aaa"], "fields keep declared order");
}

#[test]
fn every_kind_parses() {
    let schema = parse(
        r#"
[tables.everything]

[[tables.everything.fields]]
name = "id"
kind = "uuid"

[[tables.everything.fields]]
name = "label"
kind = "text"
min_len = 1
max_len = 10
format = "url"

[[tables.everything.fields]]
name = "count"
kind = "integer"
min = -5
max = 5

[[tables.everything.fields]]
name = "ratio"
kind = "real"
min = 0.0
max = 1.5

[[tables.everything.fields]]
name = "live"
kind = "boolean"

[[tables.everything.fields]]
name = "seen_at"
kind = "timestamp"

[[tables.everything.fields]]
name = "payload"
kind = "json"

[[tables.everything.fields]]
name = "state"
kind = "enum"
values = ["on", "off"]
"#,
    )
    .expect("parses");
    let table = schema.table("everything").unwrap();
    assert_eq!(
        table.field("label").unwrap().kind,
        FieldKind::Text {
            min_len: Some(1),
            max_len: Some(10),
            format: Some(TextFormat::Url)
        }
    );
    assert_eq!(
        table.field("count").unwrap().kind,
        FieldKind::Integer {
            min: Some(-5),
            max: Some(5)
        }
    );
    assert_eq!(
        table.field("ratio").unwrap().kind,
        FieldKind::Real {
            min: Some(0.0),
            max: Some(1.5)
        }
    );
    schema.validate().expect("valid");
}

#[test]
fn an_integer_bound_written_as_a_toml_integer_stays_exact() {
    // A bound routed through f64 would round; the largest safe integer
    // plus one is the cheapest case that shows it.
    let schema = parse(
        r#"
[tables.big]
[[tables.big.fields]]
name = "id"
kind = "uuid"
[[tables.big.fields]]
name = "n"
kind = "integer"
max = 9007199254740993
"#,
    )
    .expect("parses");
    assert_eq!(
        schema.table("big").unwrap().field("n").unwrap().kind,
        FieldKind::Integer {
            min: None,
            max: Some(9_007_199_254_740_993)
        }
    );
}

#[test]
fn an_attribute_that_does_not_apply_to_the_kind_is_rejected() {
    let message = error(
        r#"
[tables.post]
[[tables.post.fields]]
name = "views"
kind = "integer"
max_len = 10
"#,
    );
    assert!(
        message.contains("`max_len` does not apply to a integer field"),
        "{message}"
    );
}

#[test]
fn an_unknown_key_is_rejected() {
    let message = error(
        r#"
[tables.post]
[[tables.post.fields]]
name = "views"
kind = "integer"
maxlen = 10
"#,
    );
    assert!(message.contains("unknown field"), "{message}");
}

#[test]
fn an_unknown_kind_is_rejected() {
    let message = error(
        r#"
[tables.post]
[[tables.post.fields]]
name = "when"
kind = "date"
"#,
    );
    assert!(message.contains("unknown variant"), "{message}");
}

#[test]
fn an_unknown_format_is_rejected() {
    let message = error(
        r#"
[tables.post]
[[tables.post.fields]]
name = "handle"
kind = "text"
format = "phone"
"#,
    );
    assert!(message.contains("unknown format `phone`"), "{message}");
}

#[test]
fn an_enum_without_values_is_rejected() {
    let message = error(
        r#"
[tables.post]
[[tables.post.fields]]
name = "state"
kind = "enum"
"#,
    );
    assert!(message.contains("needs a `values` list"), "{message}");
}

#[test]
fn a_fractional_integer_bound_is_rejected() {
    let message = error(
        r#"
[tables.post]
[[tables.post.fields]]
name = "n"
kind = "integer"
min = 0.5
"#,
    );
    assert!(
        message.contains("`min` must be a whole number"),
        "{message}"
    );
}

#[test]
fn an_inner_name_must_match_the_section() {
    let message = error(
        r#"
[tables.post]
name = "article"

[[tables.post.fields]]
name = "id"
kind = "uuid"
"#,
    );
    assert!(message.contains("does not match the section"), "{message}");
}

#[test]
fn a_table_deserialized_on_its_own_needs_a_name() {
    // The conformance corpus carries one table per case, so a table has
    // to parse outside a `[tables]` map too.
    let table: TableDef = serde_json::from_value(serde_json::json!({
        "name": "post",
        "primary_key": "id",
        "fields": [{"name": "id", "kind": "uuid", "required": true}]
    }))
    .expect("parses");
    assert_eq!(table.name, "post");

    let missing = serde_json::from_value::<TableDef>(serde_json::json!({
        "fields": [{"name": "id", "kind": "uuid"}]
    }))
    .expect_err("a table on its own needs a name");
    assert!(missing.to_string().contains("needs a `name`"), "{missing}");
}

#[test]
fn the_same_shape_parses_from_json_and_from_toml() {
    // One deserializer serves the manifest and the corpus, so a corpus
    // case cannot describe a table the manifest could not declare.
    let from_toml = parse(MINIMAL).expect("toml parses");
    let from_json: Schema = serde_json::from_value(serde_json::json!({
        "post": {
            "primary_key": "id",
            "fields": [{"name": "id", "kind": "uuid", "required": true}]
        }
    }))
    .expect("json parses");
    assert_eq!(from_toml, from_json);
}
