//! From an action's input schema to renderable fields, and from a
//! submitted form back to the JSON the module accepts.
//!
//! The schema is whatever `schemars` derived from the handler's body type
//! (`factory0_core::schema_for`), with `x-cf-*` hints on the properties.
//! Property order is struct order (`preserve_order`), so fields render in
//! the order the module author wrote them.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// The input control a field renders as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Widget {
    Text,
    Email,
    Number,
    Select,
    Textarea,
    Checkbox,
    /// A secret typed by the visitor (the admin token); never pre-filled.
    Password,
    /// Never rendered as a control; carried as `<input type="hidden">`
    /// when the page supplies a value, omitted otherwise.
    Hidden,
}

/// One choice of a `Select`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Option_ {
    pub value: String,
    pub label: String,
}

/// One renderable field of a form.
#[derive(Debug, Clone)]
pub struct Field {
    /// The JSON property name; also the form control's `name`.
    pub name: String,
    pub label: String,
    pub widget: Widget,
    pub required: bool,
    pub placeholder: Option<String>,
    pub help: Option<String>,
    pub options: Vec<Option_>,
    /// JSON `type` the module expects (`string`, `integer`, `number`,
    /// `boolean`), used when converting the form back.
    pub json_type: JsonType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonType {
    String,
    Integer,
    Number,
    Boolean,
    /// Objects and arrays: never form-renderable, always hidden.
    Other,
}

/// Reads the fields of an object schema in property order.
#[must_use]
pub fn fields_of(schema: &Value) -> Vec<Field> {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    properties
        .iter()
        .map(|(name, property)| field_of(name, property, required.contains(&name.as_str())))
        .collect()
}

fn field_of(name: &str, property: &Value, required: bool) -> Field {
    let json_type = json_type_of(property);
    let hint = |key: &str| property.get(key);
    let hidden = hint("x-cf-hidden")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || json_type == JsonType::Other;
    let options: Vec<Option_> = hint("x-cf-options")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|item| {
                    let value = item.get("value").and_then(Value::as_str)?;
                    let label = item.get("label").and_then(Value::as_str).unwrap_or(value);
                    Some(Option_ {
                        value: value.to_owned(),
                        label: label.to_owned(),
                    })
                })
                .collect()
        })
        .or_else(|| {
            property.get("enum").and_then(Value::as_array).map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .map(|value| Option_ {
                        value: value.to_owned(),
                        label: humanize(value),
                    })
                    .collect()
            })
        })
        .unwrap_or_default();
    let widget = if hidden {
        Widget::Hidden
    } else {
        match hint("x-cf-widget").and_then(Value::as_str) {
            Some("email") => Widget::Email,
            Some("select") => Widget::Select,
            Some("textarea") => Widget::Textarea,
            Some("checkbox") => Widget::Checkbox,
            Some("number") => Widget::Number,
            Some("password") => Widget::Password,
            Some("text") => Widget::Text,
            _ if !options.is_empty() => Widget::Select,
            _ => match json_type {
                JsonType::Boolean => Widget::Checkbox,
                JsonType::Integer | JsonType::Number => Widget::Number,
                _ if property.get("format").and_then(Value::as_str) == Some("email") => {
                    Widget::Email
                }
                _ => Widget::Text,
            },
        }
    };
    let text = |key: &str| hint(key).and_then(Value::as_str).map(str::to_owned);
    Field {
        name: name.to_owned(),
        label: text("x-cf-label").unwrap_or_else(|| humanize(name)),
        widget,
        required,
        placeholder: text("x-cf-placeholder"),
        help: text("x-cf-help"),
        options,
        json_type,
    }
}

fn json_type_of(property: &Value) -> JsonType {
    let names: Vec<&str> = match property.get("type") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    let first = names.iter().find(|t| **t != "null").copied();
    match first {
        Some("string") => JsonType::String,
        Some("integer") => JsonType::Integer,
        Some("number") => JsonType::Number,
        Some("boolean") => JsonType::Boolean,
        // Objects, arrays, or no `type` at all (`serde_json::Value`):
        // anything goes, which a form cannot render.
        _ => JsonType::Other,
    }
}

/// `referral_code` -> `Referral code`, `captchaToken` -> `Captcha token`.
#[must_use]
pub fn humanize(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (i, ch) in name.chars().enumerate() {
        if ch == '_' || ch == '-' {
            out.push(' ');
        } else if ch.is_ascii_uppercase() && i > 0 {
            out.push(' ');
            out.push(ch.to_ascii_lowercase());
        } else if i == 0 {
            out.extend(ch.to_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Submitted values keyed by control name, whatever the source (form
/// body on a POST, query string on a GET that pre-fills).
pub type Values = BTreeMap<String, String>;

/// Converts a submitted form into the JSON object the module's handler
/// deserializes. Only declared fields are forwarded; an empty optional
/// string is omitted rather than sent as `""`; a checkbox is `true` when
/// present and `false` when absent; numbers that do not parse are sent as
/// the raw string so the module's own validation produces the error.
#[must_use]
pub fn form_to_json(fields: &[Field], values: &Values) -> Map<String, Value> {
    let mut object = Map::new();
    for field in fields {
        let raw = values.get(&field.name).map(String::as_str);
        match field.json_type {
            JsonType::Boolean => {
                let checked = raw.is_some_and(|v| matches!(v, "on" | "true" | "1"));
                if checked || field.required {
                    object.insert(field.name.clone(), Value::Bool(checked));
                }
            }
            JsonType::Integer => {
                if let Some(raw) = raw.filter(|v| !v.is_empty()) {
                    let value = raw
                        .parse::<i64>()
                        .map_or_else(|_| Value::String(raw.to_owned()), Value::from);
                    object.insert(field.name.clone(), value);
                }
            }
            JsonType::Number => {
                if let Some(raw) = raw.filter(|v| !v.is_empty()) {
                    let value = raw
                        .parse::<f64>()
                        .ok()
                        .and_then(serde_json::Number::from_f64)
                        .map_or_else(|| Value::String(raw.to_owned()), Value::Number);
                    object.insert(field.name.clone(), value);
                }
            }
            JsonType::String => {
                if let Some(raw) = raw
                    && (!raw.is_empty() || field.required)
                {
                    object.insert(field.name.clone(), Value::String(raw.to_owned()));
                }
            }
            JsonType::Other => {
                // Nested values only arrive as JSON text in a hidden
                // control (a page that pre-fills `answers`).
                if let Some(parsed) = raw.and_then(|v| serde_json::from_str::<Value>(v).ok()) {
                    object.insert(field.name.clone(), parsed);
                }
            }
        }
    }
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::JsonSchema;

    #[derive(JsonSchema)]
    #[allow(dead_code)]
    struct Body {
        #[schemars(extend("x-cf-label" = "Email", "x-cf-widget" = "email"))]
        email: String,
        product: String,
        count: Option<u32>,
        agree: bool,
        #[schemars(extend("x-cf-hidden" = true))]
        #[serde(rename = "captchaToken")]
        captcha_token: Option<String>,
        answers: Option<serde_json::Value>,
    }

    fn schema() -> Value {
        let mut schema = factory0_core::schema_for::<Body>();
        factory0_core::hint_field(
            &mut schema,
            "product",
            "enum",
            serde_json::json!(["a", "b-c"]),
        );
        schema.to_value()
    }

    #[test]
    fn fields_follow_struct_order_and_infer_widgets() {
        let fields = fields_of(&schema());
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "email",
                "product",
                "count",
                "agree",
                "captchaToken",
                "answers"
            ]
        );
        assert_eq!(fields[0].widget, Widget::Email);
        assert!(fields[0].required);
        assert_eq!(fields[0].label, "Email");
        assert_eq!(fields[1].widget, Widget::Select);
        assert_eq!(fields[1].options[1].label, "B c");
        assert_eq!(fields[2].widget, Widget::Number);
        assert!(!fields[2].required);
        assert_eq!(fields[3].widget, Widget::Checkbox);
        assert_eq!(fields[4].widget, Widget::Hidden);
        assert_eq!(fields[4].label, "Captcha token");
        assert_eq!(fields[5].widget, Widget::Hidden, "untyped value is hidden");
    }

    #[test]
    fn form_to_json_respects_types_and_omits_empties() {
        let fields = fields_of(&schema());
        let values: Values = [
            ("email", "a@b.co"),
            ("product", "a"),
            ("count", "3"),
            ("agree", "on"),
            ("captchaToken", ""),
            ("answers", r#"{"q":"x"}"#),
            ("unknown", "dropped"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let json = Value::Object(form_to_json(&fields, &values));
        assert_eq!(
            json,
            serde_json::json!({
                "email": "a@b.co", "product": "a", "count": 3, "agree": true,
                "answers": {"q": "x"}
            })
        );

        let empty: Values = Values::new();
        let json = Value::Object(form_to_json(&fields, &empty));
        assert_eq!(json, serde_json::json!({ "agree": false }));

        let bad: Values = [("count".to_owned(), "lots".to_owned())].into();
        let json = Value::Object(form_to_json(&fields, &bad));
        assert_eq!(json["count"], "lots", "unparsable number goes through raw");
    }

    #[test]
    fn humanize_splits_snake_kebab_and_camel() {
        assert_eq!(humanize("referral_code"), "Referral code");
        assert_eq!(humanize("captchaToken"), "Captcha token");
        assert_eq!(humanize("email-signup"), "Email signup");
        assert_eq!(humanize("join"), "Join");
    }
}
