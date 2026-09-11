//! Which way a locale's text runs.
//!
//! **`unic-langid` carries no directionality data.** It parses and
//! canonicalises BCP 47 tags and stops there: there is no `is_rtl()`, no
//! script property table, nothing to ask. The CLDR data that would answer
//! it lives in `icu_properties`/`icu_locid_transform`, which is a
//! megabyte-scale dependency to answer one boolean.
//!
//! So the answer is an explicit list, here, tested. It is short because
//! right-to-left writing systems are few, and it is two lists rather than
//! one because either half can be the one that is present: `ar` names no
//! script and `az-Arab` names no right-to-left *language*.

use unic_langid::LanguageIdentifier;

/// Which way a locale's text runs, as `dir` takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Left to right, which is every locale not on the lists below.
    Ltr,
    /// Right to left.
    Rtl,
}

impl Direction {
    /// The value of an HTML `dir` attribute: `"ltr"` or `"rtl"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Ltr => "ltr",
            Direction::Rtl => "rtl",
        }
    }

    /// Whether this is right-to-left.
    #[must_use]
    pub fn is_rtl(self) -> bool {
        self == Direction::Rtl
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ISO 15924 codes for the right-to-left scripts a venture is plausibly
/// translated into. Checked **first**, because a script subtag overrules
/// the language: `az-Arab` is right-to-left and `az` is not, and
/// `ku-Latn` is left-to-right where bare `ckb` is not.
const RTL_SCRIPTS: [&str; 5] = ["Arab", "Hebr", "Thaa", "Nkoo", "Adlm"];

/// Languages whose default script is right-to-left, for the ordinary tag
/// that names no script at all — which is most of them, because nobody
/// writes `ar-Arab-EG` when `ar` will do.
const RTL_LANGUAGES: [&str; 9] = ["ar", "he", "fa", "ur", "ps", "sd", "yi", "dv", "ckb"];

/// Which way `locale`'s text runs.
///
/// The script subtag wins when there is one, because it is the more
/// specific statement: `az-Arab` is South Azerbaijani in the Arabic script
/// and runs right to left, while plain `az` runs left to right.
#[must_use]
pub fn direction(locale: &LanguageIdentifier) -> Direction {
    if let Some(script) = locale.script {
        return if RTL_SCRIPTS.contains(&script.as_str()) {
            Direction::Rtl
        } else {
            Direction::Ltr
        };
    }
    if RTL_LANGUAGES.contains(&locale.language.as_str()) {
        Direction::Rtl
    } else {
        Direction::Ltr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> Direction {
        direction(&tag.parse::<LanguageIdentifier>().expect("a language tag"))
    }

    #[test]
    fn the_right_to_left_languages_are_right_to_left() {
        for tag in [
            "ar", "ar-EG", "he", "he-IL", "fa", "fa-IR", "ur", "ur-PK", "ps", "sd", "yi", "dv",
            "ckb",
        ] {
            assert_eq!(dir(tag), Direction::Rtl, "{tag} runs right to left");
        }
    }

    #[test]
    fn everything_else_is_left_to_right() {
        for tag in [
            "en", "en-GB", "id", "id-ID", "is", "de", "zh-Hans", "ja", "ko", "ru", "hi", "th",
            // Close to the right-to-left list without being on it: Arabic
            // script *names* look similar and are not the same thing.
            "az", "ku", "ms", "sw",
        ] {
            assert_eq!(dir(tag), Direction::Ltr, "{tag} runs left to right");
        }
    }

    #[test]
    fn a_script_subtag_overrules_the_language_in_both_directions() {
        // The reason this is two lists and not one.
        assert_eq!(
            dir("az-Arab"),
            Direction::Rtl,
            "Arabic script, Latin-script language"
        );
        assert_eq!(dir("pa-Arab"), Direction::Rtl);
        assert_eq!(dir("sr-Cyrl"), Direction::Ltr);
        assert_eq!(
            dir("ku-Latn"),
            Direction::Ltr,
            "Kurdish written in Latin runs left to right"
        );
    }

    #[test]
    fn the_attribute_value_is_what_html_takes() {
        assert_eq!(Direction::Rtl.as_str(), "rtl");
        assert_eq!(Direction::Ltr.as_str(), "ltr");
        assert!(Direction::Rtl.is_rtl());
        assert!(!Direction::Ltr.is_rtl());
        assert_eq!(Direction::Rtl.to_string(), "rtl");
    }
}
