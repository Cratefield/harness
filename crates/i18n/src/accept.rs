//! `Accept-Language`, parsed the way RFC 9110 defines it.
//!
//! The header is the least bad signal a browser gives about what language
//! somebody reads, and it is the only one a Web Push registration has. It
//! is also arbitrary text from the network, so it is parsed here and
//! nothing but [`LanguageIdentifier`](crate::LanguageIdentifier)s come out
//! — see [`parse_locale`](crate::parse_locale) for why that boundary is
//! where it is.

use unic_langid::LanguageIdentifier;

/// How many entries of one header are considered. A browser sends a
/// handful; anything sending hundreds is not asking a question.
const MAX_ENTRIES: usize = 16;

/// The locales `header` asks for, best first.
///
/// Quality values order the result (`en;q=0.8, id` puts `id` first,
/// because an absent `q` is `1`). `q=0` means "not this one" and is
/// dropped, the wildcard `*` is dropped because it names no locale, and
/// anything that is not a language tag is dropped rather than carried.
/// An empty answer means the header said nothing usable, and the caller
/// falls back to its own default.
#[must_use]
pub fn accept_language(header: &str) -> Vec<LanguageIdentifier> {
    let mut scored: Vec<(u16, usize, LanguageIdentifier)> = Vec::new();
    for (position, entry) in header.split(',').take(MAX_ENTRIES).enumerate() {
        let mut parts = entry.split(';');
        let Some(tag) = parts.next().map(str::trim) else {
            continue;
        };
        if tag == "*" {
            continue;
        }
        let Some(locale) = crate::parse_locale(tag) else {
            continue;
        };
        let quality = quality_of(parts);
        if quality == 0 {
            // RFC 9110: `q=0` means "not acceptable". Keeping it would
            // make `en;q=0` a request for English.
            continue;
        }
        scored.push((quality, position, locale));
    }
    // Highest quality first; ties keep the order the header listed them
    // in, which is what a client means by writing them in that order.
    scored.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));

    let mut out: Vec<LanguageIdentifier> = Vec::with_capacity(scored.len());
    for (_, _, locale) in scored {
        if !out.contains(&locale) {
            out.push(locale);
        }
    }
    out
}

/// What an entry with no `q` at all is worth, per RFC 9110: `1.0`.
const DEFAULT_QUALITY: u16 = 1_000;

/// The `q=` of one entry, as thousandths.
fn quality_of<'a>(parameters: impl Iterator<Item = &'a str>) -> u16 {
    for parameter in parameters {
        let Some((name, value)) = parameter.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            return qvalue(value.trim());
        }
    }
    DEFAULT_QUALITY
}

/// One RFC 9110 qvalue — `0[.0*3DIGIT]` or `1[.0*3("0")]` — as
/// thousandths.
///
/// Integer arithmetic on purpose. Ordering decides which language a person
/// is written to, and a float comparison would put that decision at the
/// mercy of rounding; it would also need two cast lints silenced to say so.
///
/// Anything that is not a qvalue at all — `q=high`, `q=-1`, `q=NaN` —
/// counts as `1.0`, because the entry still named a language and the
/// client still asked for it. Only a real, literal zero means "not this
/// one".
fn qvalue(raw: &str) -> u16 {
    let (whole, fraction) = raw.split_once('.').unwrap_or((raw, ""));
    if whole != "0" {
        // "1", "1.0", and everything malformed.
        return DEFAULT_QUALITY;
    }
    if fraction.is_empty() {
        return 0;
    }
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return DEFAULT_QUALITY;
    }
    // Three digits of precision, padded or truncated: `0.8` is 800.
    let mut thousandths = 0u16;
    for index in 0..3 {
        let digit = fraction
            .as_bytes()
            .get(index)
            .map_or(0, |byte| u16::from(byte - b'0'));
        thousandths = thousandths * 10 + digit;
    }
    thousandths
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(header: &str) -> Vec<String> {
        accept_language(header)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn quality_values_order_the_answer() {
        assert_eq!(tags("en;q=0.8, id;q=0.9, de;q=0.1"), ["id", "en", "de"]);
        // An absent `q` is 1.0, so it beats an explicit 0.9.
        assert_eq!(tags("en;q=0.9, id"), ["id", "en"]);
    }

    #[test]
    fn a_tie_keeps_the_order_the_client_wrote() {
        assert_eq!(tags("id, en, de"), ["id", "en", "de"]);
        assert_eq!(tags("en;q=0.5, id;q=0.5"), ["en", "id"]);
    }

    #[test]
    fn q_zero_means_not_this_one() {
        assert_eq!(tags("en;q=0, id;q=0.4"), ["id"]);
        assert!(accept_language("en;q=0").is_empty());
    }

    #[test]
    fn the_wildcard_names_no_locale() {
        assert_eq!(tags("*"), Vec::<String>::new());
        assert_eq!(tags("*;q=0.1, id"), ["id"]);
    }

    #[test]
    fn garbage_is_dropped_and_nothing_panics() {
        // The failure arm: every one of these is a header somebody can
        // send, and none of them may reach a column or a log.
        for header in [
            "",
            ",,,",
            ";q=0.5",
            "not a language",
            "en_US",
            "<script>alert(1)</script>",
            "en;q=NaN",
            "en;q=-1",
            "\u{0}\u{1}\u{2}",
        ] {
            let parsed = accept_language(header);
            assert!(
                parsed.iter().all(|locale| !locale.to_string().is_empty()),
                "{header:?} produced {parsed:?}"
            );
        }
        assert!(accept_language("not a language").is_empty());
        // `unic-langid` accepts the POSIX underscore and canonicalises it,
        // which is the right answer: `en_US` is a spelling, not an attack.
        assert_eq!(tags("en_US"), ["en-US"]);
        // A qvalue that is not a qvalue does not silence the entry: the
        // client still named a language.
        assert_eq!(tags("en;q=NaN"), ["en"]);
        assert_eq!(tags("en;q=-1"), ["en"]);
    }

    #[test]
    fn qvalues_are_read_to_three_digits() {
        assert_eq!(qvalue("1"), 1_000);
        assert_eq!(qvalue("1.0"), 1_000);
        assert_eq!(qvalue("0.8"), 800);
        assert_eq!(qvalue("0.85"), 850);
        assert_eq!(qvalue("0.856"), 856);
        assert_eq!(
            qvalue("0.8569"),
            856,
            "three digits is all RFC 9110 defines"
        );
        assert_eq!(qvalue("0"), 0);
        assert_eq!(qvalue("0.0"), 0);
        assert_eq!(qvalue("0.000"), 0);
    }

    #[test]
    fn a_real_browser_header_parses() {
        assert_eq!(
            tags("id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"),
            ["id-ID", "id", "en-US", "en"]
        );
    }

    #[test]
    fn a_flood_of_entries_is_bounded() {
        let header = (0..500)
            .map(|index| format!("en;q=0.{:03}", index % 1000))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            accept_language(&header).len() <= 1,
            "duplicates collapse and the scan is bounded"
        );
    }

    #[test]
    fn duplicates_collapse_to_the_best_one() {
        assert_eq!(tags("en;q=0.2, id, en;q=0.9"), ["id", "en"]);
    }
}
