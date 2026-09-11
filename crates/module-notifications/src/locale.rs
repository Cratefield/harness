//! Which language one recipient is written to, and what happens when the
//! catalog cannot answer (issue #190).
//!
//! # The chain
//!
//! The **subscription's** locale, then the **account's**, then the
//! venture's default. In that order and no other: a device's own setting
//! is the most accurate signal there is for a push — it is what the person
//! holding the phone chose — while the inbox and the mailbox are one each
//! per account and use the account's answer.
//!
//! Every step is optional and the last one always answers, so the chain is
//! total: a recipient who has never said anything gets the venture's
//! default rather than nothing.
//!
//! # The boundary
//!
//! A rendered string is built from caller-supplied arguments — a name, a
//! place, a reference — so it is personal data, and so is the `url` beside
//! it. A missing translation therefore reports through
//! [`MissingTranslation`] and nothing else: that type can hold only a
//! locale, a message id and an attribute name, so the event payload and
//! the log line cannot carry anything else however a caller builds them.
//! This is the boundary, put here rather than trusted at each call site,
//! because every leak this epic has had came from a value passed through
//! one layer into another layer's error string.

use cratefield_core::{ModuleContext, Notification, Scope};
use cratefield_i18n::{BODY, Catalog, LanguageIdentifier, SUBJECT, TITLE, localize};
use serde_json::json;

use crate::message::Localizable;

/// Emitted when a notification named a message the catalog does not have,
/// in any locale. The notification is still delivered — with the key as
/// its text — so a missing translation is visible from both ends: the
/// recipient sees the id, and the venture gets an event naming it.
///
/// Carries the locale, the message id and the attribute. Never the
/// rendered text and never the arguments: those are the caller's values
/// about a person (see [`MissingTranslation`]).
pub const EVENT_MISSING_TRANSLATION: &str = "notifications.missing_translation";

/// The venture's own fallback when nothing else is configured.
pub(crate) const FALLBACK_LOCALE: &str = "en";

/// One `key.attribute` that no locale in the catalog had.
///
/// Deliberately three owned strings and no more. It is the only thing this
/// module ever says about a failed render, and what it cannot hold it
/// cannot leak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MissingTranslation {
    /// The locale the recipient was to be written to.
    locale: String,
    /// The catalog message id.
    key: String,
    /// The attribute on it: `title`, `body`, `subject`.
    attribute: &'static str,
}

impl MissingTranslation {
    /// The event payload. Identifiers only, by construction.
    fn payload(&self, category: &str) -> serde_json::Value {
        json!({
            "category": category,
            "key": self.key,
            "attribute": self.attribute,
            "locale": self.locale,
        })
    }
}

/// Says on the bus, and in the log, that a message could not be rendered.
///
/// One function so there is one place that decides what is said. A caller
/// hands over [`MissingTranslation`]s and has nothing else to give it.
pub(crate) fn report_missing(
    ctx: &ModuleContext,
    scope: &Scope,
    category: &str,
    missing: &[MissingTranslation],
) {
    for entry in missing {
        tracing::warn!(
            category,
            key = %entry.key,
            attribute = entry.attribute,
            locale = %entry.locale,
            "no translation for this message: the notification carries the key instead"
        );
        ctx.events
            .emit_in(scope, EVENT_MISSING_TRANSLATION, entry.payload(category));
    }
}

/// The locale one recipient is written to: the subscription's, then the
/// account's, then the venture's default.
///
/// The first two arrive as `Option<LanguageIdentifier>` rather than as raw
/// text, which is the point: a tag is parsed where it enters the system
/// ([`cratefield_i18n::parse_locale`]) and only a canonical one is ever
/// stored, so nothing here has to decide what to do with a column full of
/// somebody's `Accept-Language` header.
#[must_use]
pub(crate) fn resolve(
    subscription: Option<LanguageIdentifier>,
    account: Option<LanguageIdentifier>,
    venture: &LanguageIdentifier,
) -> LanguageIdentifier {
    subscription.or(account).unwrap_or_else(|| venture.clone())
}

/// One message, rendered for one recipient.
pub(crate) struct Localised {
    /// The notification to deliver: the caller's `url`, `data`, `icon` and
    /// badge, with a title and body in [`Localised::locale`].
    pub notification: Notification,
    /// The locale it was **actually** rendered in, after negotiation and
    /// any per-message fallback. This is what `lang`, `dir` and
    /// `Content-Language` are set from — a request for `ar` that fell back
    /// to English is an English mail, and marking it `ar` would right-align
    /// it.
    pub locale: LanguageIdentifier,
    /// The mail subject, when the catalog has a `.subject` attribute for
    /// this message. `None` leaves the category's own subject rule alone.
    pub subject: Option<String>,
    /// What the catalog could not render. Report it with
    /// [`report_missing`]; it is the only thing that may be said.
    pub missing: Vec<MissingTranslation>,
}

/// Renders `message` for a recipient who reads `requested`.
pub(crate) fn render(
    catalog: &dyn Catalog,
    message: &Localizable,
    requested: &LanguageIdentifier,
    want_subject: bool,
) -> Localised {
    let title = localize(catalog, requested, &message.key, TITLE, &message.args);
    let body = localize(catalog, requested, &message.key, BODY, &message.args);

    let mut missing = Vec::new();
    for (attribute, rendered) in [(TITLE, &title), (BODY, &body)] {
        if rendered.missing {
            missing.push(MissingTranslation {
                locale: rendered.locale.to_string(),
                key: message.key.clone(),
                attribute,
            });
        }
    }

    // The title's locale, not the one that was asked for: a message the
    // negotiated locale did not have fell back, and the text is in the
    // locale it fell back to.
    let locale = title.locale.clone();
    // A subject is optional in a way a title and a body are not: a venture
    // that does not write one is not missing anything, so its absence is
    // never reported.
    let subject = want_subject
        .then(|| localize(catalog, requested, &message.key, SUBJECT, &message.args))
        .filter(|rendered| !rendered.missing)
        .map(|rendered| rendered.text);

    Localised {
        notification: message.shape(title.text, body.text),
        locale,
        subject,
        missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_i18n::StaticCatalog;

    fn langid(tag: &str) -> LanguageIdentifier {
        tag.parse().expect("a language tag")
    }

    fn catalog() -> StaticCatalog {
        StaticCatalog::new("en")
            .with("en", "booking-confirmed", TITLE, "Booking confirmed")
            .with("en", "booking-confirmed", BODY, "With { $coach }")
            .with("id", "booking-confirmed", TITLE, "Pesanan dikonfirmasi")
            .with("id", "booking-confirmed", BODY, "Bersama { $coach }")
    }

    #[test]
    fn the_subscription_wins_then_the_account_then_the_venture() {
        let venture = langid("en");
        assert_eq!(
            resolve(Some(langid("id")), Some(langid("de")), &venture),
            langid("id"),
            "a device's own setting is the best signal there is for a push"
        );
        assert_eq!(
            resolve(None, Some(langid("de")), &venture),
            langid("de"),
            "a device that never said falls through to the account"
        );
        assert_eq!(resolve(None, None, &venture), venture);
    }

    #[test]
    fn a_missing_key_reports_identifiers_and_nothing_else() {
        // The failure arm. Every value here is one this module must never
        // put in an event or a log: the argument is a recipient's own
        // address, and the url is a bearer capability.
        let message = Localizable::new("room-starting")
            .arg("coach", "alice@example.test")
            .arg("code", "tok_live_51H8sec")
            .url("https://push.example.test/wp/cAPABILITYtoken");
        let rendered = render(&catalog(), &message, &langid("id"), false);

        assert_eq!(rendered.missing.len(), 2, "both the title and the body");
        for entry in &rendered.missing {
            let payload = entry.payload("booking").to_string();
            let debug = format!("{entry:?}");
            for secret in [
                "alice@example.test",
                "tok_live_51H8sec",
                "cAPABILITYtoken",
                "push.example.test",
            ] {
                assert!(!payload.contains(secret), "event payload leaked: {payload}");
                assert!(!debug.contains(secret), "Debug leaked: {debug}");
            }
            assert!(payload.contains("room-starting"), "{payload}");
            assert!(payload.contains("\"locale\":\"en\""), "{payload}");
        }
        // And the notification still carries the caller's url, which is
        // where it belongs.
        assert_eq!(
            rendered.notification.url.as_deref(),
            Some("https://push.example.test/wp/cAPABILITYtoken")
        );
        assert_eq!(rendered.notification.title, "room-starting.title");
    }

    #[test]
    fn a_rendered_message_reports_nothing() {
        let rendered = render(
            &catalog(),
            &Localizable::new("booking-confirmed").arg("coach", "Sari"),
            &langid("id-ID"),
            false,
        );
        assert!(rendered.missing.is_empty());
        assert_eq!(rendered.notification.title, "Pesanan dikonfirmasi");
        assert_eq!(rendered.notification.body, "Bersama Sari");
        assert_eq!(rendered.locale, langid("id"));
    }

    #[test]
    fn an_absent_subject_is_not_a_missing_translation() {
        // A venture that writes no `.subject` is not missing anything: the
        // category's own subject rule answers instead.
        let rendered = render(
            &catalog(),
            &Localizable::new("booking-confirmed").arg("coach", "Sari"),
            &langid("id"),
            true,
        );
        assert!(rendered.subject.is_none());
        assert!(rendered.missing.is_empty(), "{:?}", rendered.missing);
    }

    #[test]
    fn the_locale_reported_is_the_one_it_was_rendered_in() {
        // `de` is not in the catalog, so this is an English notification
        // and must be labelled English.
        let rendered = render(
            &catalog(),
            &Localizable::new("booking-confirmed").arg("coach", "Sari"),
            &langid("de"),
            false,
        );
        assert_eq!(rendered.notification.title, "Booking confirmed");
        assert_eq!(rendered.locale, langid("en"));
    }
}
