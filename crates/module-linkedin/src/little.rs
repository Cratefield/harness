//! LinkedIn's `little` commentary format (issue #12).
//!
//! The grammar reserves fifteen characters and the documentation is explicit
//! that every one of them must be backslash-escaped "even if those characters
//! are not used in one of the supported elements or templates". Escaping only
//! the obvious ones (`#`, `@`, brackets) silently eats `*`, `_` and `~` out of
//! ordinary prose, and an unescaped `(` after a `@[...]` changes the meaning
//! of the text.

/// Every character `little` reserves.
pub const RESERVED: [char; 15] = [
    '\\', '|', '{', '}', '@', '[', ']', '(', ')', '<', '>', '#', '*', '_', '~',
];

/// Escapes plain text for the `commentary` field. A single pass, so the
/// backslashes this adds are never re-escaped.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        if RESERVED.contains(&ch) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// A hashtag as the `HashtagTemplate` the docs prescribe. The `#` inside the
/// template is itself escaped.
pub fn hashtag(tag: &str) -> String {
    format!("{{hashtag|\\#|{}}}", tag.trim_start_matches('#'))
}

/// A mention. The fallback text must match the entity's name exactly or
/// LinkedIn renders it as plain text rather than a link, so it is passed
/// through unescaped by design; the caller supplies the real name.
pub fn mention(name: &str, urn: &str) -> String {
    format!("@[{name}]({urn})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reserved_character_is_escaped() {
        for ch in RESERVED {
            let escaped = escape(&ch.to_string());
            assert_eq!(escaped, format!("\\{ch}"), "{ch} was not escaped");
        }
    }

    #[test]
    fn prose_survives_intact() {
        assert_eq!(escape("a_b*c~d"), "a\\_b\\*c\\~d");
        assert_eq!(escape("100% done"), "100% done");
        assert_eq!(escape("#"), "\\#");
        assert_eq!(escape(""), "");
    }

    #[test]
    fn backslashes_are_escaped_once() {
        assert_eq!(escape("a\\b"), "a\\\\b");
        assert_eq!(escape("\\#"), "\\\\\\#");
    }

    #[test]
    fn templates_are_built_not_escaped() {
        assert_eq!(hashtag("MyTag"), "{hashtag|\\#|MyTag}");
        assert_eq!(hashtag("#MyTag"), "{hashtag|\\#|MyTag}");
        assert_eq!(
            mention("Devtestco", "urn:li:organization:2414183"),
            "@[Devtestco](urn:li:organization:2414183)"
        );
    }
}
