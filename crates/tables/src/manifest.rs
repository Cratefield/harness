//! Deserialization of the manifest's `[tables]` section.
//!
//! The wire shape is flat on purpose: a field is one TOML table with a
//! `kind` and the attributes that kind accepts, so a venture reads its own
//! schema without learning a nesting convention. An attribute that does
//! not belong to the declared kind is an error rather than an ignored
//! key, because a silently dropped `max_len` is exactly the kind of drift
//! this crate exists to prevent. `[tables]` is a map keyed by table name,
//! so the table order of the generated DDL comes from the name and not
//! from where the author happened to put the section.
//!
//! The same shape is JSON, which is what `corpus/rows.json` uses: one
//! deserializer serves the manifest and the conformance corpus, so a case
//! in the corpus cannot describe a table the manifest could not declare.

use serde::Deserialize;
use serde::de::Error as _;
use serde_json::Value;
use std::collections::BTreeMap;

use crate::schema::{FieldDef, FieldKind, ForeignKey, Schema, TableDef, TextFormat};

/// `kind = "..."`, the one key every field declaration carries.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum KindName {
    Text,
    Integer,
    Real,
    Boolean,
    Timestamp,
    Uuid,
    Json,
    Enum,
}

impl KindName {
    fn as_str(self) -> &'static str {
        match self {
            KindName::Text => "text",
            KindName::Integer => "integer",
            KindName::Real => "real",
            KindName::Boolean => "boolean",
            KindName::Timestamp => "timestamp",
            KindName::Uuid => "uuid",
            KindName::Json => "json",
            KindName::Enum => "enum",
        }
    }
}

impl<'de> Deserialize<'de> for TextFormat {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        match name.as_str() {
            "email" => Ok(TextFormat::Email),
            "url" => Ok(TextFormat::Url),
            other => Err(D::Error::custom(format!(
                "unknown format `{other}`; the formats are email and url"
            ))),
        }
    }
}

/// `primary_key = "id"` and `primary_key = ["collection", "slug"]` both
/// parse; a single column is the common case and should not need brackets.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PrimaryKeyWire {
    One(String),
    Many(Vec<String>),
}

impl PrimaryKeyWire {
    fn into_vec(self) -> Vec<String> {
        match self {
            PrimaryKeyWire::One(one) => vec![one],
            PrimaryKeyWire::Many(many) => many,
        }
    }
}

fn default_primary_key() -> PrimaryKeyWire {
    PrimaryKeyWire::One("id".to_owned())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldWire {
    name: String,
    kind: KindName,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    unique: bool,
    #[serde(default)]
    indexed: bool,
    #[serde(default)]
    default: Option<Value>,
    #[serde(default)]
    min_len: Option<u32>,
    #[serde(default)]
    max_len: Option<u32>,
    #[serde(default)]
    format: Option<TextFormat>,
    #[serde(default)]
    min: Option<Value>,
    #[serde(default)]
    max: Option<Value>,
    #[serde(default)]
    values: Option<Vec<String>>,
}

impl FieldWire {
    /// Rejects an attribute the declared kind does not accept, so a
    /// `max_len` on an integer is an error and not a dropped key.
    fn reject_unless<E: serde::de::Error>(&self, accepted: &[&str]) -> Result<(), E> {
        let present: [(&str, bool); 6] = [
            ("min_len", self.min_len.is_some()),
            ("max_len", self.max_len.is_some()),
            ("format", self.format.is_some()),
            ("min", self.min.is_some()),
            ("max", self.max.is_some()),
            ("values", self.values.is_some()),
        ];
        for (key, is_set) in present {
            if is_set && !accepted.contains(&key) {
                return Err(E::custom(format!(
                    "field `{}`: `{key}` does not apply to a {} field",
                    self.name,
                    self.kind.as_str()
                )));
            }
        }
        Ok(())
    }

    fn bound_i64<E: serde::de::Error>(
        &self,
        key: &str,
        value: Option<&Value>,
    ) -> Result<Option<i64>, E> {
        match value {
            None => Ok(None),
            Some(value) => value.as_i64().map(Some).ok_or_else(|| {
                E::custom(format!(
                    "field `{}`: `{key}` must be a whole number, not {value}",
                    self.name
                ))
            }),
        }
    }

    fn bound_f64<E: serde::de::Error>(
        &self,
        key: &str,
        value: Option<&Value>,
    ) -> Result<Option<f64>, E> {
        match value {
            None => Ok(None),
            Some(value) => value
                .as_f64()
                .filter(|number| number.is_finite())
                .map(Some)
                .ok_or_else(|| {
                    E::custom(format!(
                        "field `{}`: `{key}` must be a finite number, not {value}",
                        self.name
                    ))
                }),
        }
    }

    fn into_field<E: serde::de::Error>(self) -> Result<FieldDef, E> {
        let kind = match self.kind {
            KindName::Text => {
                self.reject_unless(&["min_len", "max_len", "format"])?;
                FieldKind::Text {
                    min_len: self.min_len,
                    max_len: self.max_len,
                    format: self.format,
                }
            }
            KindName::Integer => {
                self.reject_unless(&["min", "max"])?;
                FieldKind::Integer {
                    min: self.bound_i64("min", self.min.as_ref())?,
                    max: self.bound_i64("max", self.max.as_ref())?,
                }
            }
            KindName::Real => {
                self.reject_unless(&["min", "max"])?;
                FieldKind::Real {
                    min: self.bound_f64("min", self.min.as_ref())?,
                    max: self.bound_f64("max", self.max.as_ref())?,
                }
            }
            KindName::Boolean => {
                self.reject_unless(&[])?;
                FieldKind::Boolean
            }
            KindName::Timestamp => {
                self.reject_unless(&[])?;
                FieldKind::Timestamp
            }
            KindName::Uuid => {
                self.reject_unless(&[])?;
                FieldKind::Uuid
            }
            KindName::Json => {
                self.reject_unless(&[])?;
                FieldKind::Json
            }
            KindName::Enum => {
                self.reject_unless(&["values"])?;
                let values = self.values.clone().ok_or_else(|| {
                    E::custom(format!(
                        "field `{}`: an enum field needs a `values` list",
                        self.name
                    ))
                })?;
                FieldKind::Enum { values }
            }
        };

        Ok(FieldDef {
            name: self.name,
            kind,
            required: self.required,
            unique: self.unique,
            indexed: self.indexed,
            default: self.default,
        })
    }
}

impl<'de> Deserialize<'de> for FieldDef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        FieldWire::deserialize(deserializer)?.into_field()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForeignKeyWire {
    field: String,
    references: String,
}

impl<'de> Deserialize<'de> for ForeignKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ForeignKeyWire::deserialize(deserializer)?;
        Ok(ForeignKey {
            field: wire.field,
            references: wire.references,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TableWire {
    /// Required when a table is deserialized on its own (the corpus does
    /// that); optional under `[tables.<name>]`, where the key is the name
    /// and an inner `name` must agree with it.
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_primary_key")]
    primary_key: PrimaryKeyWire,
    fields: Vec<FieldDef>,
    #[serde(default)]
    foreign_keys: Vec<ForeignKey>,
}

impl TableWire {
    fn into_table<E: serde::de::Error>(self, name: String) -> Result<TableDef, E> {
        if let Some(inner) = &self.name
            && inner != &name
        {
            return Err(E::custom(format!(
                "table `{name}`: the inner name `{inner}` does not match the section it is \
                 declared under"
            )));
        }
        Ok(TableDef {
            name,
            fields: self.fields,
            primary_key: self.primary_key.into_vec(),
            foreign_keys: self.foreign_keys,
        })
    }
}

impl<'de> Deserialize<'de> for TableDef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = TableWire::deserialize(deserializer)?;
        let name = wire
            .name
            .clone()
            .ok_or_else(|| D::Error::custom("a table declared on its own needs a `name`"))?;
        wire.into_table(name)
    }
}

impl<'de> Deserialize<'de> for Schema {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wires = BTreeMap::<String, TableWire>::deserialize(deserializer)?;
        let mut tables = Vec::with_capacity(wires.len());
        for (name, wire) in wires {
            tables.push(wire.into_table(name)?);
        }
        // A BTreeMap already yields its keys in order, so the table order
        // of the generated DDL is the name order and never the manifest's.
        Ok(Schema { tables })
    }
}
