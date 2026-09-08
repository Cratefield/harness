//! A JSON Schema rendering of a table, for interop.

use serde_json::{Map, Value, json};

use crate::schema::{FieldDef, FieldKind, TableDef, TextFormat};

/// The dialect the rendering declares.
pub const JSON_SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Renders `table` as a JSON Schema (draft 2020-12) object.
///
/// **This is a derived view and never the source.** The source is the
/// [`TableDef`], which is where the DDL mapping and the row rules live.
/// Nothing in this crate reads a JSON Schema back, and nothing should:
/// JSON Schema is here so an outside tool that speaks it can describe a
/// declared table, and for no other reason. If the two ever disagree, the
/// [`TableDef`] is right.
///
/// # What carries over exactly
///
/// - `minLength` and `maxLength` count Unicode code points in JSON
///   Schema, which is what the row validator counts.
/// - `type: "integer"` in draft 2020-12 is a number with a zero
///   fractional part, so `42.0` is an integer there as it is here.
/// - `additionalProperties: false` is the unknown-key rejection.
/// - `minimum` and `maximum` are inclusive in both.
///
/// # What does not
///
/// - `format` is an annotation in JSON Schema, not an assertion, and a
///   validator may ignore it. The row validator always asserts it, using
///   the harness's own address rule rather than a format registry's.
/// - `null` is absence here, so an optional field renders as a nullable
///   type. A JSON Schema validator that distinguishes a null from a
///   missing key will still disagree with this crate about a required
///   field set to `null`.
/// - Uniqueness, foreign keys, indexes and defaults do not appear.
///   The first two read other rows, and the last two are the database's.
#[must_use]
pub fn json_schema(table: &TableDef) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &table.fields {
        properties.insert(field.name.clone(), field_schema(table, field));
        if field.must_be_present() {
            required.push(Value::String(field.name.clone()));
        }
    }

    json!({
        "$schema": JSON_SCHEMA_DIALECT,
        "title": table.name,
        "type": "object",
        "properties": Value::Object(properties),
        "required": Value::Array(required),
        "additionalProperties": false,
    })
}

/// A field's schema. A field that may be absent is nullable, because a
/// `null` and a missing key are the same absence here.
fn field_schema(table: &TableDef, field: &FieldDef) -> Value {
    let nullable = !field.must_be_present();
    let mut schema = Map::new();

    let mut set_type = |name: &str| {
        schema.insert(
            "type".to_owned(),
            if nullable {
                json!([name, "null"])
            } else {
                json!(name)
            },
        );
    };

    match &field.kind {
        FieldKind::Text {
            min_len,
            max_len,
            format,
        } => {
            set_type("string");
            if let Some(min) = min_len {
                schema.insert("minLength".to_owned(), json!(min));
            }
            if let Some(max) = max_len {
                schema.insert("maxLength".to_owned(), json!(max));
            }
            if let Some(format) = format {
                let name = match format {
                    // "uri" is the registered JSON Schema format; "url"
                    // is the manifest's spelling.
                    TextFormat::Email => "email",
                    TextFormat::Url => "uri",
                };
                schema.insert("format".to_owned(), json!(name));
            }
        }
        FieldKind::Integer { min, max } => {
            set_type("integer");
            insert_bounds(&mut schema, min.map(|v| json!(v)), max.map(|v| json!(v)));
        }
        FieldKind::Real { min, max } => {
            set_type("number");
            insert_bounds(&mut schema, min.map(|v| json!(v)), max.map(|v| json!(v)));
        }
        FieldKind::Boolean => set_type("boolean"),
        FieldKind::Timestamp => {
            set_type("string");
            schema.insert("format".to_owned(), json!("date-time"));
        }
        FieldKind::Uuid => {
            set_type("string");
            schema.insert("format".to_owned(), json!("uuid"));
        }
        FieldKind::Json => {
            // Any JSON value. No `type`, because there is nothing to
            // narrow, and a nullable annotation would be noise.
        }
        FieldKind::Enum { values } => {
            set_type("string");
            let mut members: Vec<Value> = values.iter().map(|value| json!(value)).collect();
            if nullable {
                // `enum` is a closed list, so a nullable enum has to list
                // the null it accepts.
                members.push(Value::Null);
            }
            schema.insert("enum".to_owned(), Value::Array(members));
        }
    }

    if table.is_primary_key(&field.name) {
        schema.insert(
            "description".to_owned(),
            json!(format!("Primary key of `{}`.", table.name)),
        );
    }

    Value::Object(schema)
}

fn insert_bounds(schema: &mut Map<String, Value>, min: Option<Value>, max: Option<Value>) {
    if let Some(min) = min {
        schema.insert("minimum".to_owned(), min);
    }
    if let Some(max) = max {
        schema.insert("maximum".to_owned(), max);
    }
}
