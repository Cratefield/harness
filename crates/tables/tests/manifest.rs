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
required = true

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

#[test]
fn every_shape_the_corpus_declares_round_trips() {
    // The two directions drifting apart is the failure this crate exists
    // to prevent, and a promise that the writers mirror the readers is
    // not a check. The corpus's own `tables` section is the widest set of
    // declarations in the repository — every kind, bounds, formats, enum
    // members, defaults, flags — so it is what the round trip runs over.
    const CORPUS: &str = include_str!("../corpus/rows.json");
    let corpus: serde_json::Value = serde_json::from_str(CORPUS).expect("the corpus is JSON");
    let declared = corpus.get("tables").expect("the corpus declares tables");

    let schema: Schema = serde_json::from_value(declared.clone()).expect("reads");
    assert!(
        schema.tables.len() >= 4,
        "only {} tables — the round trip is checking almost nothing",
        schema.tables.len()
    );

    let written = serde_json::to_value(&schema).expect("writes");
    let again: Schema = serde_json::from_value(written.clone()).expect("reads what it wrote");
    assert_eq!(schema, again, "a schema changed by being written out");

    // And again, to catch a writer that is merely *stable* rather than
    // faithful — a second pass over its own output would still match.
    let twice = serde_json::to_value(&again).expect("writes");
    assert_eq!(written, twice);
}

#[test]
fn a_written_declaration_is_one_the_reader_accepts() {
    // The reader refuses an attribute that does not belong to the
    // declared kind. A writer that emitted `max_len` on a `boolean` would
    // produce a document this crate cannot read, so the round trip above
    // is the guard — this is the case that would break it first.
    let schema = parse(
        r#"
[tables.thing]
primary_key = "id"

[[tables.thing.fields]]
name = "id"
kind = "uuid"
required = true

[[tables.thing.fields]]
name = "live"
kind = "boolean"

[[tables.thing.fields]]
name = "ratio"
kind = "real"
min = 0.0
max = 1.0

[[tables.thing.fields]]
name = "slug"
kind = "text"
unique = true
max_len = 64

[[tables.thing.fields]]
name = "state"
kind = "enum"
values = ["on", "off"]
default = "off"
indexed = true
"#,
    )
    .expect("parses");
    let written = serde_json::to_string(&schema).expect("writes");
    // The property, stated about the field it is about: a boolean accepts
    // no attributes, so its entry is exactly `name` and `kind`. Asserting
    // `max_len` appears nowhere in the document was the first version of
    // this and was wrong the moment a text field carried one.
    let document: serde_json::Value = serde_json::from_str(&written).expect("valid json");
    let live = document["thing"]["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .find(|field| field["name"] == "live")
        .expect("the boolean field");
    assert_eq!(
        live.as_object()
            .expect("an object")
            .keys()
            .collect::<Vec<_>>(),
        ["name", "kind"],
        "a boolean was written with attributes its reader refuses: {live}"
    );
    let again: Schema = serde_json::from_str(&written).expect("reads what it wrote");
    assert_eq!(schema, again);
}
