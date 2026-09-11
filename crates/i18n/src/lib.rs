//! `cratefield-i18n`: the strings a venture owns, in the languages it owns
//! them in (issue #190).
//!
//! Nothing here is notification-specific. A [`Catalog`] answers "render
//! message `booking-confirmed`, attribute `.title`, in `id-ID`", and the
//! caller decides what to do with the answer — a push title, a mail
//! subject, a waitlist template.
//!
//! ```
//! use cratefield_i18n::{Args, Catalog, FluentCatalog, TITLE, localize};
//!
//! let catalog = FluentCatalog::builder()
//!     .default_locale("en")
//!     .locale("en", "booking-confirmed =\n    .title = Booking confirmed\n")
//!     .locale("id", "booking-confirmed =\n    .title = Pesanan dikonfirmasi\n")
//!     .build()
//!     .expect("the catalog parses");
//!
//! let asked = "id-ID".parse().expect("a language tag");
//! let rendered = localize(&catalog, &asked, "booking-confirmed", TITLE, &Args::new());
//! assert_eq!(rendered.text, "Pesanan dikonfirmasi");
//! assert_eq!(rendered.locale.to_string(), "id"); // id-ID negotiated down to id
//! assert!(!rendered.missing);
//! ```
//!
//! # The three things this crate exists to get right
//!
//! **Thread safety.** The default `FluentBundle` is built on `Rc` and
//! `RefCell`: it is neither `Send` nor `Sync`, so it cannot live behind a
//! port that is. `SendWrapper` does not fix it — that grants `Send` alone,
//! and panics if the value is dropped on another thread. This crate uses
//! the **concurrent** memoizer (`Arc`/`RwLock`) instead, and a static
//! assertion in the `fluent` module pins it so the day somebody swaps the import
//! back is a compile error rather than a runtime one.
//!
//! **Direction.** `unic-langid` parses language identifiers and carries no
//! directionality data at all: there is no `is_rtl()` to call. Direction
//! therefore comes from an explicit script and language list here — see
//! [`direction`] — and is tested.
//!
//! **A missing key is visible.** [`localize`] never returns an empty
//! string for a key the catalog does not have. It renders the key itself
//! and sets [`Localized::missing`], so the caller can say so on the bus and
//! whoever reads the notification sees `booking-confirmed.title` rather
//! than a blank line.
//!
//! # What a caller must not do with the answer
//!
//! [`Args`] values come from the caller of a notification — a coach's name,
//! a place, a booking reference. A rendered string is therefore **personal
//! data**: it belongs in the message that is delivered and nowhere else. No
//! error, event or log line in this crate ever carries an argument value or
//! a rendered string, and a caller must keep that boundary too.

#![forbid(unsafe_code)]

mod accept;
mod direction;
mod fixture;
mod fluent;

pub use accept::accept_language;
pub use direction::{Direction, direction};
pub use fixture::StaticCatalog;
pub use fluent::{CatalogError, FluentCatalog, FluentCatalogBuilder};
pub use unic_langid::LanguageIdentifier;

/// The attribute a title is stored under: `booking-confirmed.title`.
pub const TITLE: &str = "title";
/// The attribute a body is stored under.
pub const BODY: &str = "body";
/// The attribute a mail subject is stored under, where a venture wants one
/// that is not the title.
pub const SUBJECT: &str = "subject";

/// The placeables a message is rendered with: `{ $coach }`, `{ $count }`.
///
/// A JSON object rather than a type of this crate's own, because that is
/// what a caller already has — an event payload, a `serde_json::json!`
/// literal — and because a number has to stay a number: Fluent selects the
/// plural form from it, and `"2"` as a string selects `other` in every
/// language.
pub type Args = serde_json::Map<String, serde_json::Value>;

/// A catalog of a venture's own strings.
///
/// Implemented by [`FluentCatalog`] over embedded `.ftl` sources, and by
/// [`StaticCatalog`] for tests that do not want a parser in the way.
///
/// `Send + Sync` is the whole point: a catalog is built once at cold start
/// and read from every request and every drain.
pub trait Catalog: Send + Sync {
    /// Every locale this catalog can render, the default included.
    fn locales(&self) -> &[LanguageIdentifier];

    /// The locale a request that negotiates to nothing falls back to. It
    /// is the one locale a venture promises is complete.
    fn default_locale(&self) -> &LanguageIdentifier;

    /// Renders one attribute in exactly `locale` — no negotiation, no
    /// fallback. `None` when this locale has no such message or no such
    /// attribute on it.
    fn render(
        &self,
        locale: &LanguageIdentifier,
        key: &str,
        attribute: &str,
        args: &Args,
    ) -> Option<String>;

    /// Whether `locale` has `key.attribute` at all.
    ///
    /// Separate from [`Catalog::render`] because the completeness check
    /// (`fz doctor`) asks about thousands of pairs and cares about none of
    /// the answers: formatting each one would run the resolver over
    /// arguments nobody supplied.
    fn has(&self, locale: &LanguageIdentifier, key: &str, attribute: &str) -> bool {
        self.render(locale, key, attribute, &Args::new()).is_some()
    }

    /// The locale in this catalog that best answers `requested`, by RFC
    /// 4647 language-range matching: `id-ID` matches `id`, and anything
    /// that matches nothing falls back to [`Catalog::default_locale`].
    fn negotiate(&self, requested: &LanguageIdentifier) -> LanguageIdentifier {
        let default = self.default_locale();
        fluent_langneg::negotiate_languages(
            std::slice::from_ref(requested),
            self.locales(),
            Some(default),
            fluent_langneg::NegotiationStrategy::Filtering,
        )
        .first()
        .map_or_else(|| default.clone(), |found| (*found).clone())
    }
}

/// One rendered string, and what it took to get there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Localized {
    /// The text to deliver. For a missing key this is the key itself —
    /// never an empty string.
    pub text: String,
    /// The locale it was actually rendered in, after negotiation and any
    /// fallback to the default. This is what `lang`/`dir` and
    /// `Content-Language` must be set from: a request for `ar` that fell
    /// back to English is an English message, and telling a mail client it
    /// is Arabic would right-align it.
    pub locale: LanguageIdentifier,
    /// The catalog had no such key or attribute in any locale, so
    /// [`Localized::text`] is the key. Never silent: the caller is expected
    /// to say so where somebody will see it.
    pub missing: bool,
}

/// Renders `key.attribute` for a recipient who asked for `requested`.
///
/// Three steps, in this order: negotiate `requested` down to a locale the
/// catalog has; render there; and if that locale is missing this particular
/// message, fall back to the catalog's default locale. Only if the default
/// does not have it either is the answer [`Localized::missing`], because at
/// that point no translation of it exists anywhere.
///
/// The fallback is per **message**, not per catalog, which is what makes a
/// half-translated locale useful: an `id` catalog that has
/// `booking-confirmed` but not `coach-notes` renders the first in
/// Indonesian and the second in English, rather than forcing a venture to
/// choose between shipping an incomplete locale and shipping none.
#[must_use]
pub fn localize(
    catalog: &dyn Catalog,
    requested: &LanguageIdentifier,
    key: &str,
    attribute: &str,
    args: &Args,
) -> Localized {
    let negotiated = catalog.negotiate(requested);
    if let Some(text) = catalog.render(&negotiated, key, attribute, args) {
        return Localized {
            text,
            locale: negotiated,
            missing: false,
        };
    }
    let default = catalog.default_locale().clone();
    if default != negotiated
        && let Some(text) = catalog.render(&default, key, attribute, args)
    {
        return Localized {
            text,
            locale: default,
            missing: false,
        };
    }
    Localized {
        text: missing_text(key, attribute),
        locale: default,
        missing: true,
    }
}

/// What a message no locale has renders as: the key and the attribute,
/// exactly as a caller wrote them.
///
/// Deliberately not an empty string and not the venture's name for
/// "something went wrong". A push whose body is blank looks delivered; one
/// that reads `booking-confirmed.body` is a bug report from the person who
/// received it, and it names the key somebody has to add.
#[must_use]
pub fn missing_text(key: &str, attribute: &str) -> String {
    format!("{key}.{attribute}")
}

/// One `key.attribute` a locale does not have, as the completeness check
/// reports it.
///
/// Carries identifiers only — a locale, a message id, an attribute name.
/// Never a rendered string: those are built from caller-supplied arguments
/// and are personal data, and this type exists to be printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing {
    /// The locale that is missing it.
    pub locale: LanguageIdentifier,
    /// The message id.
    pub key: String,
    /// The attribute on it.
    pub attribute: String,
}

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}.{}", self.locale, self.key, self.attribute)
    }
}

/// Every `key.attribute` pair that some locale in `catalog` cannot render,
/// in locale order then key order.
///
/// This is the build-time half of "a missing key is visible": the run-time
/// half renders the key and says so on the bus, and this one lists them
/// before a deployment ever sends anything. A venture passes the keys it
/// actually uses, because a catalog cannot know which messages a caller
/// names.
#[must_use]
pub fn missing_messages(catalog: &dyn Catalog, keys: &[&str], attributes: &[&str]) -> Vec<Missing> {
    let mut missing = Vec::new();
    for locale in catalog.locales() {
        for key in keys {
            for attribute in attributes {
                if !catalog.has(locale, key, attribute) {
                    missing.push(Missing {
                        locale: locale.clone(),
                        key: (*key).to_owned(),
                        attribute: (*attribute).to_owned(),
                    });
                }
            }
        }
    }
    missing
}

/// The one place a language tag enters this system from outside it.
///
/// A locale arrives from a request body, an `Accept-Language` header or a
/// database column, and every one of those is arbitrary text. Parsing it
/// here means a `LanguageIdentifier` is the only form that reaches a
/// column, a log or a rendered page — so a header of 4 KB of HTML, or a
/// device token somebody put in the wrong field, becomes `None` and the
/// caller uses its default rather than storing what it was sent.
///
/// Canonicalising is part of the guarantee: `EN-us` and `en-US` are one
/// locale, and a column that held both would negotiate the same recipient
/// two different ways on two different days.
#[must_use]
pub fn parse_locale(raw: &str) -> Option<LanguageIdentifier> {
    let trimmed = raw.trim();
    // A language subtag is 2-8 characters and the whole tag is short; the
    // parser would reject a long input anyway, but not before allocating
    // over it.
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    trimmed.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn langid(tag: &str) -> LanguageIdentifier {
        tag.parse().expect("a language tag")
    }

    fn catalog() -> StaticCatalog {
        StaticCatalog::new("en")
            .with("en", "booking-confirmed", TITLE, "Booking confirmed")
            .with("en", "booking-confirmed", BODY, "See you on { $day }")
            .with("en", "coach-notes", TITLE, "New notes")
            .with("id", "booking-confirmed", TITLE, "Pesanan dikonfirmasi")
            .with("id", "booking-confirmed", BODY, "Sampai jumpa { $day }")
    }

    #[test]
    fn a_regional_tag_negotiates_down_to_the_language_it_is() {
        let rendered = localize(
            &catalog(),
            &langid("id-ID"),
            "booking-confirmed",
            TITLE,
            &Args::new(),
        );
        assert_eq!(rendered.text, "Pesanan dikonfirmasi");
        assert_eq!(rendered.locale, langid("id"));
    }

    #[test]
    fn a_locale_the_catalog_does_not_have_falls_back_to_the_default() {
        let rendered = localize(
            &catalog(),
            &langid("fr-CA"),
            "booking-confirmed",
            TITLE,
            &Args::new(),
        );
        assert_eq!(rendered.text, "Booking confirmed");
        assert_eq!(
            rendered.locale,
            langid("en"),
            "the locale reported must be the one it was rendered in, or the caller sets \
             lang=\"fr\" on English text"
        );
        assert!(!rendered.missing);
    }

    #[test]
    fn a_half_translated_locale_falls_back_per_message_not_per_catalog() {
        // `coach-notes` exists in `en` only. The point of the per-message
        // fallback: `id` stays useful for everything it does have.
        let rendered = localize(
            &catalog(),
            &langid("id"),
            "coach-notes",
            TITLE,
            &Args::new(),
        );
        assert_eq!(rendered.text, "New notes");
        assert_eq!(rendered.locale, langid("en"));
        assert!(!rendered.missing);
    }

    #[test]
    fn a_key_no_locale_has_renders_as_the_key_and_says_so() {
        let rendered = localize(
            &catalog(),
            &langid("id"),
            "room-starting",
            BODY,
            &Args::new(),
        );
        assert!(rendered.missing, "a key nothing has must not pass silently");
        assert_eq!(rendered.text, "room-starting.body");
        assert!(
            !rendered.text.is_empty(),
            "an empty body looks delivered; the key is a bug report"
        );
    }

    #[test]
    fn garbage_is_refused_at_the_boundary_rather_than_stored() {
        // The failure arm. Every one of these would otherwise reach a
        // column, and from there a log and a rendered page.
        for raw in [
            "",
            "   ",
            "not a language",
            "<script>alert(1)</script>",
            "en; DROP TABLE notifications_subscriptions",
            "e",
            "../../etc/passwd",
        ] {
            assert!(
                parse_locale(raw).is_none(),
                "{raw:?} is not a language tag and must not become one"
            );
        }
        // And the long one, which the parser would reject anyway but only
        // after copying it.
        assert!(parse_locale(&"a".repeat(4096)).is_none());
    }

    #[test]
    fn a_tag_that_parses_is_stored_canonicalised() {
        // `EN-us` and `en-US` are one locale. Two spellings in a column
        // negotiate the same recipient two different ways.
        let parsed = parse_locale("EN-us").expect("a valid tag");
        assert_eq!(parsed.to_string(), "en-US");
        assert_eq!(
            parse_locale(" id-ID ").map(|l| l.to_string()).as_deref(),
            Some("id-ID")
        );
    }

    #[test]
    fn the_completeness_check_lists_ids_and_never_a_rendered_string() {
        let missing = missing_messages(
            &catalog(),
            &["booking-confirmed", "coach-notes"],
            &[TITLE, BODY],
        );
        let listed: Vec<String> = missing.iter().map(ToString::to_string).collect();
        assert_eq!(
            listed,
            [
                "en: coach-notes.body",
                "id: coach-notes.title",
                "id: coach-notes.body",
            ],
            "{listed:?}"
        );
        for entry in &missing {
            assert!(
                !entry.to_string().contains("See you"),
                "the report is identifiers only: {entry}"
            );
        }
    }
}
