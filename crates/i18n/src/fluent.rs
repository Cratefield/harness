//! A [`Catalog`] over embedded Fluent (`.ftl`) sources.
//!
//! Nothing is read at run time. A venture embeds its `.ftl` files with
//! `include_str!`, so a Worker isolate that has no filesystem builds its
//! bundles from data already in the binary, once, at cold start.
//!
//! # Why the concurrent memoizer, and why the assertion below
//!
//! `fluent_bundle::FluentBundle` — the one every example uses — is
//! `bundle::FluentBundle<R, intl_memoizer::IntlLangMemoizer>`, and that
//! memoizer is built on `Rc<RefCell<..>>`. It is therefore neither `Send`
//! nor `Sync`, and a catalog is held behind an `Arc` and read from every
//! request and every drain, so it must be both.
//!
//! `SendWrapper` is the usual suggestion and it is wrong here twice over:
//! it grants `Send` only — never `Sync`, which is what sharing behind an
//! `Arc` needs — and it panics if the value is dropped on a thread other
//! than the one that created it, which on a work-stealing runtime is a
//! crash waiting for the right schedule.
//!
//! `fluent_bundle::concurrent::FluentBundle` is the same bundle over
//! `intl_memoizer::concurrent::IntlLangMemoizer` (`Arc`/`RwLock`), which
//! is `Send + Sync`. The static assertion below is what makes that a
//! compile error to undo rather than a runtime discovery: swap the import
//! back to the default bundle and this file stops building.

use std::collections::BTreeSet;

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource, FluentValue};
use unic_langid::LanguageIdentifier;

use crate::{Args, Catalog};

/// One locale's bundle: the concurrent memoizer, spelled once.
type Bundle = FluentBundle<FluentResource>;

/// The guarantee, pinned. `Bundle` is what [`FluentCatalog`] holds, and a
/// `Catalog` is `Send + Sync`; if the memoizer is ever swapped back to the
/// `Rc`/`RefCell` default, this is the line that fails.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Bundle>();
    assert_send_sync::<FluentCatalog>();
};

/// Why a catalog could not be built.
///
/// Every variant carries identifiers and positions — a language tag, a
/// message id, a byte offset — and never a line of source or a rendered
/// string. This type is printed by `fz doctor` and logged at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    /// A locale was named with something that is not a BCP 47 tag.
    Locale { tag: String },
    /// No default locale was set. There has to be one: it is the locale a
    /// venture promises is complete, and the answer for every recipient
    /// whose own language this catalog does not have.
    NoDefault,
    /// The default locale was set to one no source was supplied for.
    DefaultHasNoSource { tag: String },
    /// A `.ftl` source did not parse. Reported as byte offsets into the
    /// source the venture embedded, which is enough to find the line, and
    /// deliberately without quoting it.
    Parse { locale: String, offsets: Vec<usize> },
    /// Two sources for one locale define the same message id, so one of
    /// them silently wins.
    Duplicate { locale: String, ids: Vec<String> },
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatalogError::Locale { tag } => {
                write!(f, "i18n: {tag:?} is not a BCP 47 language tag")
            }
            CatalogError::NoDefault => f.write_str(
                "i18n: no default locale — set one with `.default_locale(..)`; it is the \
                 locale every recipient falls back to",
            ),
            CatalogError::DefaultHasNoSource { tag } => write!(
                f,
                "i18n: the default locale {tag:?} has no .ftl source, so the fallback every \
                 recipient depends on renders nothing"
            ),
            CatalogError::Parse { locale, offsets } => write!(
                f,
                "i18n: the {locale} catalog does not parse ({} error(s), at byte offset(s) {})",
                offsets.len(),
                offsets
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            CatalogError::Duplicate { locale, ids } => write!(
                f,
                "i18n: the {locale} catalog defines {} twice; one definition silently wins",
                ids.join(", ")
            ),
        }
    }
}

impl std::error::Error for CatalogError {}

/// A catalog built from embedded `.ftl` sources.
pub struct FluentCatalog {
    default: LanguageIdentifier,
    locales: Vec<LanguageIdentifier>,
    bundles: Vec<(LanguageIdentifier, Bundle)>,
}

impl std::fmt::Debug for FluentCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Locales, never messages: a catalog's contents are the venture's
        // copy and a `Debug` of one ends up in a log.
        f.debug_struct("FluentCatalog")
            .field("default", &self.default.to_string())
            .field(
                "locales",
                &self
                    .locales
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )
            // Non-exhaustive on purpose, and the omitted field is the
            // point: `bundles` holds the venture's copy.
            .finish_non_exhaustive()
    }
}

impl FluentCatalog {
    /// Starts a catalog.
    #[must_use]
    pub fn builder() -> FluentCatalogBuilder {
        FluentCatalogBuilder::default()
    }

    fn bundle(&self, locale: &LanguageIdentifier) -> Option<&Bundle> {
        self.bundles
            .iter()
            .find(|(tag, _)| tag == locale)
            .map(|(_, bundle)| bundle)
    }
}

impl Catalog for FluentCatalog {
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
        let bundle = self.bundle(locale)?;
        let message = bundle.get_message(key)?;
        let pattern = message.get_attribute(attribute)?.value();
        let arguments = fluent_args(args);
        // Resolver errors are deliberately dropped rather than propagated.
        // They describe the *arguments* — a `{ $coach }` nobody supplied —
        // and Fluent renders the placeable literally when one is missing,
        // which is the visible outcome this crate wants. Carrying the error
        // further would carry argument values with it.
        let mut errors = Vec::new();
        Some(
            bundle
                .format_pattern(pattern, Some(&arguments), &mut errors)
                .into_owned(),
        )
    }

    fn has(&self, locale: &LanguageIdentifier, key: &str, attribute: &str) -> bool {
        self.bundle(locale)
            .and_then(|bundle| bundle.get_message(key))
            .and_then(|message| message.get_attribute(attribute))
            .is_some()
    }
}

/// The JSON arguments a caller passed, as Fluent values.
///
/// A number stays a number: `{ $count -> [one] … *[other] … }` selects the
/// plural form from it, and a `"2"` that arrived as a string selects
/// `other` in every language — which is the bug where English reads "2
/// places" correctly and Polish does not.
fn fluent_args(args: &Args) -> FluentArgs<'static> {
    let mut out = FluentArgs::new();
    for (name, value) in args {
        let fluent = match value {
            serde_json::Value::Number(number) => number
                .as_f64()
                .map_or_else(|| FluentValue::from(number.to_string()), FluentValue::from),
            serde_json::Value::String(text) => FluentValue::from(text.clone()),
            // A bool, a list or an object has no Fluent form. The string
            // of it is what a venture would have passed anyway, and the
            // money rules already say amounts arrive pre-formatted.
            other => FluentValue::from(other.to_string()),
        };
        out.set(name.clone(), fluent);
    }
    out
}

/// Assembles a [`FluentCatalog`].
#[derive(Debug, Default, Clone)]
pub struct FluentCatalogBuilder {
    default: Option<String>,
    sources: Vec<(String, String)>,
}

impl FluentCatalogBuilder {
    /// The locale every recipient falls back to, and the one a venture
    /// promises is complete.
    #[must_use]
    pub fn default_locale(mut self, tag: impl Into<String>) -> Self {
        self.default = Some(tag.into());
        self
    }

    /// Adds one `.ftl` source for one locale. Call it more than once for
    /// the same locale to build it from several files.
    #[must_use]
    pub fn locale(mut self, tag: impl Into<String>, ftl: impl Into<String>) -> Self {
        self.sources.push((tag.into(), ftl.into()));
        self
    }

    /// Builds the catalog.
    ///
    /// # Errors
    ///
    /// [`CatalogError`] for an unparsable language tag, a missing or
    /// sourceless default locale, a `.ftl` that does not parse, or a
    /// message defined twice in one locale.
    pub fn build(self) -> Result<FluentCatalog, CatalogError> {
        let default_tag = self.default.ok_or(CatalogError::NoDefault)?;
        let default = parse_tag(&default_tag)?;

        let mut locales: Vec<LanguageIdentifier> = Vec::new();
        let mut bundles: Vec<(LanguageIdentifier, Bundle)> = Vec::new();
        for (tag, ftl) in self.sources {
            let locale = parse_tag(&tag)?;
            let resource =
                FluentResource::try_new(ftl).map_err(|(_, errors)| CatalogError::Parse {
                    locale: locale.to_string(),
                    offsets: errors.iter().map(|error| error.pos.start).collect(),
                })?;
            let index = if let Some(index) = bundles.iter().position(|(known, _)| *known == locale)
            {
                index
            } else {
                let mut bundle = Bundle::new_concurrent(vec![locale.clone()]);
                // Fluent wraps every placeable in U+2068/U+2069 by default,
                // so bidirectional text stays isolated inside a paragraph. A
                // notification title is not a paragraph: those characters
                // reach a lock screen, a `<title>` and a mail subject as
                // invisible junk, and every assertion about a rendered string
                // would have to know about them.
                bundle.set_use_isolating(false);
                locales.push(locale.clone());
                bundles.push((locale.clone(), bundle));
                bundles.len() - 1
            };
            bundles[index]
                .1
                .add_resource(resource)
                .map_err(|errors| CatalogError::Duplicate {
                    locale: locale.to_string(),
                    ids: overridden(&errors),
                })?;
        }

        if !locales.contains(&default) {
            return Err(CatalogError::DefaultHasNoSource { tag: default_tag });
        }
        Ok(FluentCatalog {
            default,
            locales,
            bundles,
        })
    }
}

fn parse_tag(tag: &str) -> Result<LanguageIdentifier, CatalogError> {
    crate::parse_locale(tag).ok_or_else(|| CatalogError::Locale {
        tag: tag.to_owned(),
    })
}

/// The message ids a second source redefined, sorted and deduplicated.
fn overridden(errors: &[fluent_bundle::FluentError]) -> Vec<String> {
    errors
        .iter()
        .filter_map(|error| match error {
            fluent_bundle::FluentError::Overriding { id, .. } => Some(id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BODY, TITLE, localize};

    const EN: &str = "\
booking-confirmed =
    .title = Booking confirmed
    .body = { $count ->
        [one] { $count } place with { $coach }
       *[other] { $count } places with { $coach }
    }
    .subject = Your booking
";

    const ID: &str = "\
booking-confirmed =
    .title = Pesanan dikonfirmasi
    .body = { $count } tempat bersama { $coach }
";

    const AR: &str = "\
booking-confirmed =
    .title = تم تأكيد الحجز
    .body = مع { $coach }
";

    fn catalog() -> FluentCatalog {
        FluentCatalog::builder()
            .default_locale("en")
            .locale("en", EN)
            .locale("id", ID)
            .locale("ar", AR)
            .build()
            .expect("the catalog parses")
    }

    fn args(pairs: &[(&str, serde_json::Value)]) -> Args {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect()
    }

    fn langid(tag: &str) -> LanguageIdentifier {
        tag.parse().expect("a language tag")
    }

    #[test]
    fn plurals_are_selected_per_locale_from_a_number() {
        let catalog = catalog();
        let one = localize(
            &catalog,
            &langid("en"),
            "booking-confirmed",
            BODY,
            &args(&[("count", 1.into()), ("coach", "Sari".into())]),
        );
        assert_eq!(one.text, "1 place with Sari");
        let many = localize(
            &catalog,
            &langid("en"),
            "booking-confirmed",
            BODY,
            &args(&[("count", 3.into()), ("coach", "Sari".into())]),
        );
        assert_eq!(many.text, "3 places with Sari");
    }

    #[test]
    fn a_number_that_arrived_as_a_string_would_have_chosen_the_wrong_form() {
        // Pinning the conversion, not serde: `"1"` selects `other`, which
        // is the bug this mapping exists to prevent.
        let catalog = catalog();
        let rendered = localize(
            &catalog,
            &langid("en"),
            "booking-confirmed",
            BODY,
            &args(&[("count", "1".into()), ("coach", "Sari".into())]),
        );
        assert_eq!(
            rendered.text, "1 places with Sari",
            "a string never selects a plural category; this is why numbers stay numbers"
        );
    }

    #[test]
    fn the_negotiation_chain_is_id_id_then_id_then_en() {
        let catalog = catalog();
        assert_eq!(catalog.negotiate(&langid("id-ID")), langid("id"));
        assert_eq!(catalog.negotiate(&langid("id")), langid("id"));
        assert_eq!(catalog.negotiate(&langid("de-AT")), langid("en"));
        assert_eq!(
            localize(
                &catalog,
                &langid("id-ID"),
                "booking-confirmed",
                TITLE,
                &Args::new()
            )
            .text,
            "Pesanan dikonfirmasi"
        );
    }

    #[test]
    fn nothing_invisible_reaches_a_rendered_string() {
        // Fluent's bidirectional isolation marks, left on by default,
        // would put U+2068/U+2069 around every placeable.
        let rendered = localize(
            &catalog(),
            &langid("id"),
            "booking-confirmed",
            BODY,
            &args(&[("count", 2.into()), ("coach", "Sari".into())]),
        );
        assert_eq!(rendered.text, "2 tempat bersama Sari");
        assert!(
            !rendered.text.contains('\u{2068}') && !rendered.text.contains('\u{2069}'),
            "isolation marks reach a lock screen as junk: {:?}",
            rendered.text
        );
    }

    #[test]
    fn a_missing_attribute_falls_back_and_then_says_so() {
        let catalog = catalog();
        // `id` has no `.subject`; English does.
        let subject = localize(
            &catalog,
            &langid("id"),
            "booking-confirmed",
            crate::SUBJECT,
            &Args::new(),
        );
        assert_eq!(subject.text, "Your booking");
        assert_eq!(subject.locale, langid("en"));
        assert!(!subject.missing);

        // Nothing has `room-starting`.
        let none = localize(
            &catalog,
            &langid("id"),
            "room-starting",
            TITLE,
            &Args::new(),
        );
        assert!(none.missing);
        assert_eq!(none.text, "room-starting.title");
    }

    #[test]
    fn the_completeness_check_names_the_locale_and_the_id() {
        let missing = crate::missing_messages(
            &catalog(),
            &["booking-confirmed", "room-starting"],
            &[TITLE, BODY],
        );
        let listed: Vec<String> = missing.iter().map(ToString::to_string).collect();
        assert_eq!(
            listed,
            [
                "en: room-starting.title",
                "en: room-starting.body",
                "id: room-starting.title",
                "id: room-starting.body",
                "ar: room-starting.title",
                "ar: room-starting.body",
            ],
            "{listed:?}"
        );
    }

    #[test]
    fn a_catalog_is_shareable_across_threads() {
        // The property the static assertion pins, exercised rather than
        // only asserted: a catalog is built once and read from every
        // request, which on a native runtime means several threads.
        let catalog = std::sync::Arc::new(catalog());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let catalog = std::sync::Arc::clone(&catalog);
                std::thread::spawn(move || {
                    localize(
                        &*catalog,
                        &langid("id"),
                        "booking-confirmed",
                        TITLE,
                        &Args::new(),
                    )
                    .text
                })
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().expect("no panic"), "Pesanan dikonfirmasi");
        }
    }

    #[test]
    fn a_broken_source_is_refused_with_an_offset_and_no_quotation() {
        let err = FluentCatalog::builder()
            .default_locale("en")
            .locale("en", "booking-confirmed =\n    .title =\n")
            .build()
            .expect_err("an attribute with no value does not parse");
        let text = err.to_string();
        assert!(text.contains("does not parse"), "{text}");
        assert!(
            !text.contains("booking-confirmed ="),
            "the error names offsets, never the source: {text}"
        );
    }

    #[test]
    fn a_default_with_no_source_is_refused() {
        let err = FluentCatalog::builder()
            .default_locale("en")
            .locale("id", ID)
            .build()
            .expect_err("the fallback has to exist");
        assert!(
            matches!(err, CatalogError::DefaultHasNoSource { .. }),
            "{err}"
        );

        assert!(matches!(
            FluentCatalog::builder().locale("en", EN).build(),
            Err(CatalogError::NoDefault)
        ));
        assert!(matches!(
            FluentCatalog::builder().default_locale("not a tag").build(),
            Err(CatalogError::Locale { .. })
        ));
    }

    #[test]
    fn one_message_defined_twice_in_a_locale_is_refused() {
        let err = FluentCatalog::builder()
            .default_locale("en")
            .locale("en", EN)
            .locale("en", EN)
            .build()
            .expect_err("a silently overridden message is a bug in the sources");
        assert!(
            err.to_string().contains("booking-confirmed"),
            "the error names the id: {err}"
        );
    }

    #[test]
    fn the_debug_of_a_catalog_carries_no_copy() {
        let text = format!("{:?}", catalog());
        assert!(text.contains("\"en\""), "{text}");
        assert!(!text.contains("Booking confirmed"), "{text}");
    }
}
