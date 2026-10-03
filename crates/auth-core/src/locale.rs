//! Request locale resolution (issue #649): the one place a request's
//! language is decided from the several signals it may carry.
//!
//! `cratefield_core::TemplateRegistry` renders `<id>@<locale>` when that is
//! registered and `<id>` otherwise, and negotiates nothing itself. So the
//! locale string handed to it must already be one the deployment supports:
//! this module picks it, in a fixed priority order, and never invents a tag
//! no template can be registered under.

use cratefield_core::Config;
use cratefield_i18n::{LanguageIdentifier, accept_language, parse_locale};

/// The deployment-wide key listing supported locales, comma-separated in
/// BCP 47 form. The first entry is the deployment default.
///
/// Not a module key: every auth module reads it, and it describes the
/// deployment rather than any one module.
const AUTH_LOCALES_KEY: &str = "AUTH_LOCALES";

/// What a deployment that never set [`AUTH_LOCALES_KEY`] supports.
const DEFAULT_LOCALES: &str = "en";

/// The locales a deployment supports, parsed once from `AUTH_LOCALES`.
#[derive(Debug, Clone)]
pub struct SupportedLocales {
    locales: Vec<LanguageIdentifier>,
}

impl Default for SupportedLocales {
    fn default() -> Self {
        Self::from_raw(DEFAULT_LOCALES)
    }
}

impl SupportedLocales {
    /// Reads `AUTH_LOCALES`: comma-separated BCP 47 tags, the first the
    /// deployment default. Entries that are not language tags are dropped,
    /// and an absent or wholly unusable value falls back to `en`.
    #[must_use]
    pub fn from_config(config: &dyn Config) -> Self {
        Self::from_raw(config.get(AUTH_LOCALES_KEY).as_deref().unwrap_or_default())
    }

    fn from_raw(raw: &str) -> Self {
        let mut locales: Vec<LanguageIdentifier> = Vec::new();
        for entry in raw.split(',') {
            if let Some(locale) = parse_locale(entry)
                && !locales.contains(&locale)
            {
                locales.push(locale);
            }
        }
        if locales.is_empty() {
            locales.push(parse_locale(DEFAULT_LOCALES).expect("a valid language tag"));
        }
        Self { locales }
    }

    /// The locale a request that names nothing supported falls back to.
    #[must_use]
    pub fn default_locale(&self) -> &LanguageIdentifier {
        &self.locales[0]
    }

    /// Every locale the deployment supports, the default first.
    #[must_use]
    pub fn locales(&self) -> &[LanguageIdentifier] {
        &self.locales
    }

    /// The supported locale `raw` names, matched exactly first and then by
    /// language alone (`de-AT` answers to `de`). `None` when it names a
    /// locale this deployment does not have, so the caller falls through to
    /// its next signal rather than to a template that cannot exist.
    #[must_use]
    pub fn canonicalize(&self, raw: &str) -> Option<String> {
        let wanted = parse_locale(raw)?;
        match_one(&wanted, &self.locales).map(ToString::to_string)
    }
}

/// The supported locale `wanted` matches: the same tag, else the same
/// language.
fn match_one<'a>(
    wanted: &LanguageIdentifier,
    supported: &'a [LanguageIdentifier],
) -> Option<&'a LanguageIdentifier> {
    supported
        .iter()
        .find(|locale| *locale == wanted)
        .or_else(|| {
            supported
                .iter()
                .find(|locale| locale.language == wanted.language)
        })
}

/// The locale signals one request carries, most specific first.
///
/// Every field is the raw value from the wire — an explicit `locale` field,
/// the OIDC `ui_locales`, the account's stored locale, an `Accept-Language`
/// header — parsed here rather than by the caller, so a value that is not a
/// language tag falls through to the next signal instead of reaching a
/// template.
#[derive(Debug, Default, Clone, Copy)]
pub struct Hints<'a> {
    pub explicit: Option<&'a str>,
    pub ui_locales: Option<&'a str>,
    pub stored: Option<&'a str>,
    pub accept_language: Option<&'a str>,
}

/// Resolves the locale to render in.
///
/// In order: the request's explicit `locale`, then `ui_locales` (a
/// space-separated preference list, best first), then the account's stored
/// locale, then the header's quality-ordered preferences, and finally the
/// deployment default. The first candidate the deployment supports wins;
/// anything unknown or malformed falls through.
#[must_use]
pub fn resolve(supported: &SupportedLocales, hints: &Hints<'_>) -> String {
    if let Some(found) = hints.explicit.and_then(|raw| supported.canonicalize(raw)) {
        return found;
    }
    if let Some(raw) = hints.ui_locales {
        for tag in raw.split_whitespace() {
            if let Some(found) = supported.canonicalize(tag) {
                return found;
            }
        }
    }
    if let Some(found) = hints.stored.and_then(|raw| supported.canonicalize(raw)) {
        return found;
    }
    if let Some(header) = hints.accept_language {
        for wanted in accept_language(header) {
            if let Some(found) = match_one(&wanted, supported.locales()) {
                return found.to_string();
            }
        }
    }
    supported.default_locale().to_string()
}

/// The `ui_locales` a pending `/authorize` URL carries, when `return_to` is
/// that URL.
///
/// The chooser hands the whole pending request to a login method as
/// `return_to`, so the `ui_locales` an OIDC client asked for arrives inside
/// this query string. Reading it from any other path would be reading
/// somebody else's parameter, so the path is checked first.
#[must_use]
pub fn ui_locales_from_return_to(return_to: &str) -> Option<String> {
    let (path, query) = return_to.split_once('?').unwrap_or((return_to, ""));
    // The mount prefix is the harness's, so it is read from the one place
    // that already holds it rather than copied here.
    if path.strip_prefix(crate::tokens::MODULE_PREFIX) != Some(crate::authorize::AUTHORIZE_ROUTE) {
        return None;
    }
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "ui_locales")
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;

    fn supported(raw: &str) -> SupportedLocales {
        SupportedLocales::from_config(&MapConfig::from_pairs([("AUTH_LOCALES", raw)]))
    }

    #[test]
    fn the_supported_list_is_parsed_canonicalised_and_defaulted() {
        let locales = supported("en,de");
        assert_eq!(locales.default_locale().to_string(), "en");
        assert_eq!(locales.locales().len(), 2);

        // An invalid entry is dropped rather than carried.
        let locales = supported("en,not a language,de");
        assert_eq!(locales.locales().len(), 2);

        // Nothing usable means the default deployment.
        assert_eq!(supported("").default_locale().to_string(), "en");
        assert_eq!(supported("  ,  ").default_locale().to_string(), "en");
        assert_eq!(
            SupportedLocales::default().default_locale().to_string(),
            "en"
        );

        // Duplicates collapse, and a tag is canonicalised.
        assert_eq!(supported("en,en").locales().len(), 1);
        assert_eq!(supported("EN-us").locales()[0].to_string(), "en-US");
    }

    #[test]
    fn each_signal_wins_over_the_ones_after_it() {
        let locales = supported("en,de,fr");
        let all = Hints {
            explicit: Some("de"),
            ui_locales: Some("fr"),
            stored: Some("en"),
            accept_language: Some("fr"),
        };
        assert_eq!(resolve(&locales, &all), "de", "explicit must win");

        let no_explicit = Hints {
            explicit: None,
            ..all
        };
        assert_eq!(resolve(&locales, &no_explicit), "fr", "ui_locales next");

        let no_ui = Hints {
            ui_locales: None,
            ..no_explicit
        };
        assert_eq!(resolve(&locales, &no_ui), "en", "then the stored locale");

        let no_stored = Hints {
            stored: None,
            ..no_ui
        };
        assert_eq!(resolve(&locales, &no_stored), "fr", "then Accept-Language");

        let nothing = Hints {
            accept_language: None,
            ..no_stored
        };
        assert_eq!(resolve(&locales, &nothing), "en", "then the default");
    }

    #[test]
    fn ui_locales_is_a_list_walked_best_first() {
        let locales = supported("en,de");
        let hints = Hints {
            ui_locales: Some("es de"),
            accept_language: Some("en"),
            ..Hints::default()
        };
        // `es` is not supported, so the list is walked to `de`.
        assert_eq!(resolve(&locales, &hints), "de");
    }

    #[test]
    fn a_regional_tag_matches_by_language_and_a_stranger_by_nothing() {
        let locales = supported("en,de");
        // `de-AT` is not listed, but `de` is.
        assert_eq!(locales.canonicalize("de-AT").as_deref(), Some("de"));
        assert_eq!(locales.canonicalize("en-GB").as_deref(), Some("en"));
        // Unknown, malformed and empty all name no supported locale.
        assert_eq!(locales.canonicalize("xx"), None);
        assert_eq!(locales.canonicalize("not a language"), None);
        assert_eq!(locales.canonicalize(""), None);
    }

    #[test]
    fn accept_language_quality_ordering_is_respected() {
        let locales = supported("en,de,fr");
        let hints = Hints {
            accept_language: Some("de;q=0.8, fr"),
            ..Hints::default()
        };
        assert_eq!(resolve(&locales, &hints), "fr", "an absent q is 1.0");
    }

    #[test]
    fn nothing_supported_falls_back_to_the_deployment_default() {
        let locales = supported("de,en");
        // The first listed tag is the default, not `en` unconditionally.
        let hints = Hints {
            explicit: Some("xx"),
            ui_locales: Some("yy"),
            stored: Some("zz"),
            accept_language: Some("qq"),
        };
        assert_eq!(resolve(&locales, &hints), "de");
    }

    #[test]
    fn ui_locales_is_read_only_from_the_authorize_query() {
        assert_eq!(
            ui_locales_from_return_to("/v1/auth-core/authorize?client_id=x&ui_locales=de")
                .as_deref(),
            Some("de")
        );
        // Percent-encoded spaces in a preference list decode to the list.
        assert_eq!(
            ui_locales_from_return_to("/v1/auth-core/authorize?ui_locales=de%20fr").as_deref(),
            Some("de fr")
        );
        // A query on any other path is somebody else's parameter.
        assert_eq!(
            ui_locales_from_return_to("/v1/auth-magic-link/start?ui_locales=de"),
            None
        );
        assert_eq!(ui_locales_from_return_to("/v1/auth-core/authorize"), None);
        assert_eq!(
            ui_locales_from_return_to("/v1/auth-core/authorize?ui_locales="),
            None,
            "an empty value names nothing"
        );
    }
}
