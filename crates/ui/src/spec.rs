//! `UiSpec` (ADR 0010 §4, issue #75): everything about the UI that is
//! copy, order or theme rather than code. JSON, validated against the
//! module surface so a typo can never be silently ignored, applied by the
//! renderer, and the object a prompt produces later. The schema is
//! committed at `schemas/ui-spec-v1.schema.json` and a test keeps it in
//! step with these types.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use factory0_core::SurfaceDocument;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The spec format version this crate reads.
pub const UI_SPEC_VERSION: u32 = 1;

/// Config key the control plane sets to inject a spec per venture without
/// a rebuild (a JSON document). Invalid JSON or a spec that fails
/// validation makes every `/ui` request answer a problem naming the
/// error, never a page rendered from a half-read spec.
pub const UI_SPEC_KEY: &str = "UI_SPEC";

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UiSpec {
    /// Must be `1`.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Theme: `--cf-*` custom property values and an optional stylesheet.
    #[serde(default)]
    pub theme: Theme,
    /// Per module, by module name.
    #[serde(default)]
    pub modules: BTreeMap<String, ModuleSpec>,
}

fn default_version() -> u32 {
    UI_SPEC_VERSION
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Theme {
    /// Custom property values, keys starting with `--cf-` (`"--cf-accent":
    /// "#0a7"`). Served as `/ui/theme.css` and linked after `cf.css`.
    #[serde(default)]
    pub tokens: BTreeMap<String, String>,
    /// A stylesheet linked after the tokens: absolute `https://` URL or a
    /// path on the API origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub css_url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModuleSpec {
    /// Shown instead of the humanized module name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Per action, by action name.
    #[serde(default)]
    pub actions: BTreeMap<String, ActionSpec>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    /// Page title and heading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// A paragraph above the form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intro: Option<String>,
    /// The submit button label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit: Option<String>,
    /// The notice after an accepted submit; overrides the module's
    /// `Outcome::Accepted` message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success: Option<String>,
    /// Per field, by property name.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldSpec>,
    /// Field order; unlisted fields follow in their declared order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order: Vec<String>,
    /// Landing pages of a link action: `done`, `expired`.
    #[serde(default)]
    pub pages: BTreeMap<String, PageCopy>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Never rendered as a control (the page or the embed supplies it).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageCopy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl UiSpec {
    /// Parses JSON. Unknown keys are errors at every level.
    ///
    /// # Errors
    ///
    /// The serde message, prefixed.
    pub fn parse(json: &str) -> Result<Self, String> {
        let spec: Self = serde_json::from_str(json).map_err(|err| format!("ui spec: {err}"))?;
        if spec.version != UI_SPEC_VERSION {
            return Err(format!(
                "ui spec: version {} is not supported; this renderer reads version {UI_SPEC_VERSION}",
                spec.version
            ));
        }
        Ok(spec)
    }

    /// Checks every reference against the surface: modules, actions,
    /// fields (in `fields` and `order`), page names, theme keys and the
    /// stylesheet URL. Every problem is reported, with its JSON path.
    ///
    /// # Errors
    ///
    /// One line per problem.
    pub fn validate(&self, surface: &SurfaceDocument) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for key in self.theme.tokens.keys() {
            if !key.starts_with("--cf-") {
                errors.push(format!(
                    "theme.tokens.{key}: custom property names must start with --cf-"
                ));
            }
        }
        if let Some(url) = &self.theme.css_url
            && !(url.starts_with("https://") || url.starts_with('/'))
        {
            errors.push(format!(
                "theme.css_url: {url:?} must be an https:// URL or a path on the API origin"
            ));
        }
        for (module_name, module) in &self.modules {
            let Some(entry) = surface.modules.iter().find(|m| &m.name == module_name) else {
                errors.push(format!(
                    "modules.{module_name}: no module with that name declares a surface"
                ));
                continue;
            };
            for (action_name, action) in &module.actions {
                let path = format!("modules.{module_name}.actions.{action_name}");
                let Some(declared) = entry
                    .surface
                    .actions
                    .iter()
                    .find(|a| &a.name == action_name)
                else {
                    errors.push(format!(
                        "{path}: module `{module_name}` declares no such action"
                    ));
                    continue;
                };
                let known: Vec<String> = declared
                    .input
                    .as_ref()
                    .and_then(|s| s.as_value().get("properties"))
                    .and_then(serde_json::Value::as_object)
                    .map(|p| p.keys().cloned().collect())
                    .unwrap_or_default();
                for field in action.fields.keys() {
                    if !known.contains(field) {
                        errors.push(format!(
                            "{path}.fields.{field}: action `{action_name}` has no field with that \
                             name (it has: {})",
                            known.join(", ")
                        ));
                    }
                }
                for field in &action.order {
                    if !known.contains(field) {
                        errors.push(format!(
                            "{path}.order: `{field}` is not a field of `{action_name}`"
                        ));
                    }
                }
                for page in action.pages.keys() {
                    if !matches!(page.as_str(), "done" | "expired") {
                        errors.push(format!(
                            "{path}.pages.{page}: landing pages are `done` and `expired`"
                        ));
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// The action's copy, if any.
    #[must_use]
    pub fn action(&self, module: &str, action: &str) -> Option<&ActionSpec> {
        self.modules.get(module)?.actions.get(action)
    }

    /// `:root { --cf-…: …; }` from the theme tokens; empty when none.
    #[must_use]
    pub fn theme_css(&self) -> String {
        if self.theme.tokens.is_empty() {
            return String::new();
        }
        let mut css = String::from(":root {\n");
        for (key, value) in &self.theme.tokens {
            let value: String = value
                .chars()
                .filter(|c| !matches!(c, ';' | '{' | '}'))
                .collect();
            let _ = writeln!(css, "  {key}: {value};");
        }
        css.push_str("}\n");
        css
    }

    /// The schema this crate's tests keep committed.
    #[must_use]
    pub fn schema() -> serde_json::Value {
        let mut settings = schemars::generate::SchemaSettings::draft2020_12();
        settings.inline_subschemas = true;
        let mut schema = schemars::SchemaGenerator::new(settings)
            .into_root_schema_for::<UiSpec>()
            .to_value();
        if let Some(root) = schema.as_object_mut() {
            root.insert(
                "$id".into(),
                "https://cratefield.com/schemas/ui-spec-v1.schema.json".into(),
            );
            root.insert("title".into(), "UiSpec v1".into());
            root.insert(
                "description".into(),
                "Copy, field order, hidden fields and theme tokens for a Cratefield harness UI \
                 (ADR 0010). Everything a prompt may change; nothing that is code."
                    .into(),
            );
        }
        schema
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_unknown_keys_and_versions() {
        assert!(UiSpec::parse(r#"{"version":1}"#).is_ok());
        assert!(UiSpec::parse("{}").is_ok(), "version defaults to 1");
        let err = UiSpec::parse(r#"{"version":2}"#).unwrap_err();
        assert!(err.contains("version 2"), "{err}");
        let err = UiSpec::parse(r#"{"modules":{"x":{"colour":"red"}}}"#).unwrap_err();
        assert!(err.contains("unknown field `colour`"), "{err}");
    }

    #[test]
    fn theme_css_is_root_tokens_with_dangerous_chars_dropped() {
        let json = "{\"theme\":{\"tokens\":{\"--cf-accent\":\"#0a7\",\"--cf-radius\":\"0px;} body{display:none\"}}}";
        let spec = UiSpec::parse(json).unwrap();
        let css = spec.theme_css();
        assert_eq!(
            css,
            ":root {\n  --cf-accent: #0a7;\n  --cf-radius: 0px bodydisplay:none;\n}\n"
        );
        assert!(UiSpec::default().theme_css().is_empty());
    }
}
