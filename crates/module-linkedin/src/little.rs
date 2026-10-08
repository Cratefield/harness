//! LinkedIn's `little` commentary format (issue #12).
//!
//! The grammar reserves fifteen characters and the documentation is explicit
//! that every one of them must be backslash-escaped "even if those characters
//! are not used in one of the supported elements or templates". Escaping only
//! the obvious ones (`#`, `@`, brackets) silently eats `*`, `_` and `~` out of
//! ordinary prose, and an unescaped `(` after a `@[...]` changes the meaning
//! of the text.

use cratefield_text_guard::ExtraSpan;

/// The [`ExtraSpan`] label of a mention template.
pub(crate) const MENTION: &str = "mention";
/// The [`ExtraSpan`] label of a hashtag template.
pub(crate) const HASHTAG: &str = "hashtag";

/// Every character `little` reserves.
pub(crate) const RESERVED: [char; 15] = [
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

/// The end of a mention template `@[Name](urn:li:type:id)` starting at
/// `start`, if one does. The name is anything up to the first `]` on the
/// line (LinkedIn passes it through unescaped); the URN must be a
/// `urn:li:` URN with a type and an id.
fn mention_at(text: &str, start: usize) -> Option<usize> {
    let rest = text[start..].strip_prefix("@[")?;
    let name_len = rest.find(']')?;
    if name_len == 0 || rest[..name_len].contains('\n') {
        return None;
    }
    let urn_part = rest[name_len + 1..].strip_prefix("(urn:li:")?;
    let close = urn_part.find(')')?;
    let (kind, id) = urn_part[..close].split_once(':')?;
    let valid = !kind.is_empty()
        && kind.chars().all(|c| c.is_ascii_alphabetic())
        && !id.is_empty()
        && !id.contains(char::is_whitespace);
    // "@[" + name + "](urn:li:" + type:id + ")"
    valid.then_some(start + 2 + name_len + "](urn:li:".len() + close + 1)
}

/// A hashtag template `{hashtag|\#|tag}` (or with a bare `#`) starting at
/// `start`: its end and the tag.
fn hashtag_at(text: &str, start: usize) -> Option<(usize, &str)> {
    let rest = text[start..].strip_prefix("{hashtag|")?;
    let rest_after_mark = rest
        .strip_prefix("\\#|")
        .or_else(|| rest.strip_prefix("#|"))?;
    let close = rest_after_mark.find('}')?;
    let tag = &rest_after_mark[..close];
    if tag.is_empty() || tag.contains(|c: char| c.is_whitespace() || RESERVED.contains(&c)) {
        return None;
    }
    let end = text.len() - rest_after_mark.len() + close + 1;
    Some((end, tag))
}

/// The text a fact check reads, and the LinkedIn syntax in it that a
/// rewrite must keep, as caller spans for `cratefield-text-guard`.
///
/// Reading `little` the way a person sees the post: a backslash escape
/// outside a template becomes the character it escapes (so a link with an
/// escaped `_` compares equal to the same link in plain text), a hashtag
/// template becomes `#tag` (what LinkedIn shows, and what a plain-text
/// source would write), and a mention stays verbatim, URN included. Both
/// templates are locked: a mention as `mention`, a hashtag template as
/// `hashtag`. Only unescaped templates count, so `\@\[x\]` in plain
/// commentary is text, not a mention. Plain text without backslashes comes
/// back unchanged.
pub(crate) fn for_check(text: &str) -> (String, Vec<ExtraSpan>) {
    let mut out = String::with_capacity(text.len());
    let mut locks = Vec::new();
    let mut lock = |out: &mut String, locked: &str, label: &str| {
        let from = out.len();
        out.push_str(locked);
        locks.push(ExtraSpan::new(from..out.len(), label));
    };
    let mut i = 0;
    while let Some(c) = text[i..].chars().next() {
        if c == '\\'
            && let Some(next) = text[i + 1..]
                .chars()
                .next()
                .filter(|n| RESERVED.contains(n))
        {
            out.push(next);
            i += 1 + next.len_utf8();
        } else if c == '@'
            && let Some(end) = mention_at(text, i)
        {
            lock(&mut out, &text[i..end], MENTION);
            i = end;
        } else if c == '{'
            && let Some((end, tag)) = hashtag_at(text, i)
        {
            lock(&mut out, &format!("#{tag}"), HASHTAG);
            i = end;
        } else {
            out.push(c);
            i += c.len_utf8();
        }
    }
    (out, locks)
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

    fn locked(text: &str) -> (String, Vec<(String, String)>) {
        let (out, locks) = for_check(text);
        let named = locks
            .iter()
            .map(|lock| (lock.label.clone(), out[lock.range.clone()].to_owned()))
            .collect();
        (out, named)
    }

    #[test]
    fn templates_are_locked_and_hashtags_read_as_shown() {
        let (out, locks) = locked(
            "Thanks @[DevTestCo](urn:li:organization:2414183) and @[Dana](urn:li:person:abc-1) {hashtag|\\#|launch} {hashtag|#|Q3}",
        );
        assert_eq!(
            out,
            "Thanks @[DevTestCo](urn:li:organization:2414183) and @[Dana](urn:li:person:abc-1) #launch #Q3"
        );
        assert_eq!(
            locks,
            [
                (
                    MENTION.to_owned(),
                    "@[DevTestCo](urn:li:organization:2414183)".to_owned()
                ),
                (
                    MENTION.to_owned(),
                    "@[Dana](urn:li:person:abc-1)".to_owned()
                ),
                (HASHTAG.to_owned(), "#launch".to_owned()),
                (HASHTAG.to_owned(), "#Q3".to_owned()),
            ]
        );
    }

    #[test]
    fn escapes_read_as_the_character_and_round_trip_plain_text() {
        let plain = "a_b*c~d #tag (x) <y> {z} |p| @[me](urn:li:person:1) [q] \\ https://x.io/a_b";
        let (out, locks) = for_check(&escape(plain));
        assert_eq!(out, plain);
        // Escaped, so not templates.
        assert!(locks.is_empty());
    }

    #[test]
    fn broken_templates_are_text() {
        for text in [
            "@[](urn:li:person:1)",
            "@[Name](urn:li::1)",
            "@[Name](urn:li:person:)",
            "@[Name](https://example.com)",
            "@[Na\nme](urn:li:person:1)",
            "{hashtag|\\#|}",
            "{hashtag|\\#|two words}",
            "{hashtag|x|tag}",
        ] {
            let (out, locks) = for_check(text);
            assert!(locks.is_empty(), "{text} locked {locks:?}");
            assert!(out.len() <= text.len());
        }
    }
}
