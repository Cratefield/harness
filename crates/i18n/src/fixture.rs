//! A [`Catalog`](crate::Catalog) with no parser in the way, for tests.
//!
//! A module's test wants to assert that an Indonesian subscription got the
//! Indonesian string. Writing a `.ftl` to prove that puts Fluent's syntax
//! between the test and the thing it is testing: a typo in an indented
//! attribute block fails the test for a reason that has nothing to do with
//! the module.
//!
//! So this one takes the strings directly. It substitutes `{ $name }`
//! placeables and nothing else — no plural selectors, no terms, no
//! functions. A test that needs those wants
//! [`FluentCatalog`](crate::FluentCatalog), which is what production uses.

use unic_langid::LanguageIdentifier;

use crate::{Args, Catalog};

/// A catalog of literal strings.
#[derive(Debug, Clone)]
pub struct StaticCatalog {
    default: LanguageIdentifier,
    locales: Vec<LanguageIdentifier>,
    entries: Vec<Entry>,
}

#[derive(Debug, Clone)]
struct Entry {
    locale: LanguageIdentifier,
    key: String,
    attribute: String,
    template: String,
}

impl StaticCatalog {
    /// A catalog whose default locale is `default` and which holds
    /// nothing yet.
    ///
    /// # Panics
    ///
    /// If `default` is not a language tag. This is a test fixture, and a
    /// typo in a fixture should stop the test rather than change what it
    /// asserts.
    #[must_use]
    pub fn new(default: &str) -> Self {
        let default: LanguageIdentifier = crate::parse_locale(default)
            .unwrap_or_else(|| panic!("{default:?} is not a language tag"));
        Self {
            locales: vec![default.clone()],
            default,
            entries: Vec::new(),
        }
    }

    /// Adds one string.
    ///
    /// # Panics
    ///
    /// If `locale` is not a language tag, for the reason [`Self::new`]
    /// gives.
    #[must_use]
    pub fn with(
        mut self,
        locale: &str,
        key: &str,
        attribute: &str,
        template: impl Into<String>,
    ) -> Self {
        let locale: LanguageIdentifier = crate::parse_locale(locale)
            .unwrap_or_else(|| panic!("{locale:?} is not a language tag"));
        if !self.locales.contains(&locale) {
            self.locales.push(locale.clone());
        }
        self.entries.push(Entry {
            locale,
            key: key.to_owned(),
            attribute: attribute.to_owned(),
            template: template.into(),
        });
        self
    }
}

impl Catalog for StaticCatalog {
    fn locales(&self) -> &[LanguageIdentifier] {
        &self.locales
    }

    fn default_locale(&self) -> &LanguageIdentifier {
        &self.default
    }

    fn render(
        &self,
        locale: &LanguageIdentifier,
        key: &str,
        attribute: &str,
        args: &Args,
    ) -> Option<String> {
        let entry = self.entries.iter().find(|entry| {
            entry.locale == *locale && entry.key == key && entry.attribute == attribute
        })?;
        Some(substitute(&entry.template, args))
    }
}

/// Replaces every `{ $name }` in `template` with the argument's value.
///
/// Whitespace inside the braces is optional, which is what makes a
/// fixture readable next to the Fluent it stands in for. An argument
/// nobody supplied is left as it was written, so a test that forgot one
/// sees it.
fn substitute(template: &str, args: &Args) -> String {
    let mut out = template.to_owned();
    for (name, value) in args {
        let rendered = match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        for spelling in [format!("{{ ${name} }}"), format!("{{${name}}}")] {
            out = out.replace(&spelling, &rendered);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BODY, TITLE, localize};

    #[test]
    fn it_substitutes_both_spellings_and_leaves_what_it_was_not_given() {
        let catalog = StaticCatalog::new("en").with(
            "en",
            "booking",
            BODY,
            "{ $count } with {$coach}, at { $place }",
        );
        let args: Args = [
            ("count".to_owned(), serde_json::json!(2)),
            ("coach".to_owned(), serde_json::json!("Sari")),
        ]
        .into_iter()
        .collect();
        let rendered = localize(
            &catalog,
            &"en".parse().expect("tag"),
            "booking",
            BODY,
            &args,
        );
        assert_eq!(rendered.text, "2 with Sari, at { $place }");
    }

    #[test]
    fn the_default_locale_is_a_locale_even_with_no_strings_in_it() {
        let catalog = StaticCatalog::new("en").with("id", "booking", TITLE, "Pesanan");
        assert_eq!(catalog.default_locale().to_string(), "en");
        assert_eq!(
            catalog
                .locales()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["en", "id"]
        );
    }
}
