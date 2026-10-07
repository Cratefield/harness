//! `cratefield-text-guard`: keep the facts when a model rewrites text
//! (issue #836).
//!
//! A venture that asks a [`TextModel`](https://docs.rs/cratefield-core) to
//! rewrite, shorten or translate somebody's text has to be sure the model
//! did not quietly change what the text *says*: a figure, a name, a quoted
//! sentence, a line of code. This crate does the two halves of that check
//! and nothing else:
//!
//! 1. [`Guard::extract`] finds the **protected spans** of a text: numbers,
//!    quotations, code and multi-word names ([`SpanKind`]).
//! 2. [`Guard::verify`] checks a rewrite against its original and lists
//!    every protected span that went missing or changed, and every number
//!    the rewrite introduced ([`Violation`]).
//!
//! ```
//! use cratefield_text_guard::{SpanKind, ViolationKind, extract, verify};
//!
//! let original = "Our Q3 revenue grew by 18% to $4.2M, Dana Okafor said.";
//! let kinds: Vec<_> = extract(original).iter().map(|s| (s.kind, s.text.clone())).collect();
//! assert_eq!(kinds, [
//!     (SpanKind::Number, "Q3".to_owned()),
//!     (SpanKind::Number, "18%".to_owned()),
//!     (SpanKind::Number, "$4.2M".to_owned()),
//!     (SpanKind::Name, "Dana Okafor".to_owned()),
//! ]);
//!
//! assert!(verify(original, "Dana Okafor says Q3 revenue rose 18% to $4.2M.").is_ok());
//!
//! let violations = verify(original, "Dana Okafor says Q3 revenue rose 19% to $4.2M.").unwrap_err();
//! assert_eq!(violations.len(), 2);
//! assert_eq!(violations[0].kind, ViolationKind::Missing);   // 18% is gone
//! assert_eq!(violations[1].kind, ViolationKind::Introduced); // 19% came from nowhere
//! ```
//!
//! What a caller does with the violations is its own business: retry the
//! model with the failed spans named, refuse the rewrite, or show them.
//!
//! # The heuristics, on purpose simple
//!
//! No regex engine, no language model, no dictionary: every rule below is a
//! character scan, so its false positives and negatives can be read off the
//! code. Spans never overlap; when two rules match the same text the
//! earlier rule in this list wins.
//!
//! - **Code** ([`SpanKind::Code`]): a fenced block (a line opening with
//!   three or more backticks or tildes, to the matching closing fence or
//!   the end of the text), then inline code (a run of backticks to the next
//!   run of the same length, within one paragraph). Must survive verbatim,
//!   fences included.
//! - **Quotes** ([`SpanKind::Quote`]): text between straight double quotes
//!   (`"…"`), curly double quotes (`“…”`), German low-high quotes (`„…“`)
//!   or guillemets (`«…»`), within one paragraph and at
//!   most [`MAX_QUOTE_CHARS`] long. Single quotes are not quotes here: `’`
//!   is also the apostrophe, and telling the two apart needs grammar. What
//!   must survive is the quoted **words** ([`Span::protected`]): the quote
//!   marks may change style, and a closing `,` `.` `;` or `:` inside the
//!   marks may move, because typographic conventions move them.
//! - **Numbers** ([`SpanKind::Number`]): a token that starts at a word
//!   boundary with an optional currency sign and a digit, continues through
//!   digits joined by `.` `,` `:` `/` or `-` (only between digits, so a
//!   full stop after a figure is not part of it), and keeps a `%` or `‰`
//!   and any letters glued to the end (`$4.2M`, `18%`, `3rd`, `10x`,
//!   `2026-10-08`). Also one to four capitals glued to digits, with an
//!   optional hyphen (`Q3`, `FY2024`, `H1`, `GPT-4`). Spelled-out numbers
//!   ("three million") are not numbers here. Must survive verbatim.
//! - **Names** ([`SpanKind::Name`]): two or more capitalised words in a
//!   row, separated by single spaces (`Dana Okafor`, `Bank of America`:
//!   a small set of lowercase particles may sit **between** capitalised
//!   words). A leading function word (`The`, `In`, `However`, …) is dropped
//!   first, and a trailing possessive `'s` is not part of the name. A
//!   single capitalised word is never a name: that would lock the first
//!   word of every sentence. The flip side: a capitalised word that is not a
//!   function word, followed by a capitalised word, is a name, so a
//!   sentence opening "Ask Dana" locks "Ask Dana". Must survive verbatim.
//!
//! "Survive" means: occur in the rewrite at least once, at a word boundary
//! (`18%` is not found inside `118%`). The rewrite may reorder spans and
//! may use one fewer time than the original; it may not drop or alter one.
//! A number the rewrite contains and the original does not is reported as
//! [`ViolationKind::Introduced`]: a changed figure shows up as one missing
//! and one introduced. Names, quotes and code a rewrite adds are not
//! reported — new wording is the point of a rewrite.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::ops::Range;

use serde::{Deserialize, Serialize};

/// The longest quotation, in characters, that counts as a quote. Longer
/// "quotes" are almost always a stray or unbalanced mark pairing with one
/// paragraphs away, and locking them would freeze most of a text.
pub const MAX_QUOTE_CHARS: usize = 600;

/// What kind of fact a [`Span`] protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    /// Two or more capitalised words: a person, a company, a place.
    Name,
    /// A figure: `18%`, `$4.2M`, `Q3`, `2026-10-08`.
    Number,
    /// A quotation between double quotes.
    Quote,
    /// Inline code or a fenced code block.
    Code,
}

impl SpanKind {
    /// The name used in errors, logs and JSON.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Number => "number",
            Self::Quote => "quote",
            Self::Code => "code",
        }
    }
}

impl std::fmt::Display for SpanKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One protected span of a text: its kind, its text, and where it is.
///
/// `start..end` are **byte** offsets into the text it was extracted from,
/// on `char` boundaries, so `&text[span.range()] == span.text`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    pub kind: SpanKind,
    pub text: String,
    pub start: usize,
    pub end: usize,
}

impl Span {
    /// The byte range of the span in its text.
    pub fn range(&self) -> Range<usize> {
        self.start..self.end
    }

    /// The part of the span a rewrite must keep verbatim: the whole span,
    /// except for a quote, where it is the quoted words without the marks
    /// and without a closing `,` `.` `;` `:` (see the crate docs).
    pub fn protected(&self) -> &str {
        match self.kind {
            SpanKind::Quote => quote_words(&self.text),
            _ => &self.text,
        }
    }
}

/// How a rewrite broke a protected span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// A span of the original that the rewrite does not contain.
    Missing,
    /// A number the rewrite contains that the original does not.
    Introduced,
}

/// One protected span a rewrite did not keep, or a number it made up.
///
/// For [`ViolationKind::Missing`], `span` is located in the **original**;
/// for [`ViolationKind::Introduced`], in the **rewrite**.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Violation {
    pub kind: ViolationKind,
    pub span: Span,
}

/// Which span kinds to look for. [`Guard::new`] looks for all four.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one switch per `SpanKind`, set by name
pub struct Guard {
    names: bool,
    numbers: bool,
    quotes: bool,
    code: bool,
}

impl Default for Guard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard {
    /// A guard for names, numbers, quotes and code.
    pub const fn new() -> Self {
        Self {
            names: true,
            numbers: true,
            quotes: true,
            code: true,
        }
    }

    /// Whether multi-word names are protected (default: yes).
    #[must_use]
    pub const fn names(mut self, on: bool) -> Self {
        self.names = on;
        self
    }

    /// Whether numbers are protected (default: yes).
    #[must_use]
    pub const fn numbers(mut self, on: bool) -> Self {
        self.numbers = on;
        self
    }

    /// Whether quotations are protected (default: yes).
    #[must_use]
    pub const fn quotes(mut self, on: bool) -> Self {
        self.quotes = on;
        self
    }

    /// Whether code is protected (default: yes). Code is still *found* when
    /// off, so a quote or a number inside it is not protected on its own;
    /// it is just not returned.
    #[must_use]
    pub const fn code(mut self, on: bool) -> Self {
        self.code = on;
        self
    }

    /// The protected spans of `text`, in order, never overlapping.
    pub fn extract(&self, text: &str) -> Vec<Span> {
        let mut taken: Vec<Range<usize>> = Vec::new();
        let mut spans = Vec::new();

        let code = code_spans(text);
        for range in &code {
            if self.code {
                spans.push(span(text, SpanKind::Code, range.clone()));
            }
        }
        taken.extend(code);

        if self.quotes {
            for range in quote_spans(text, &taken) {
                spans.push(span(text, SpanKind::Quote, range));
            }
            taken.extend(
                spans
                    .iter()
                    .filter(|s| s.kind == SpanKind::Quote)
                    .map(Span::range),
            );
        }
        if self.numbers {
            let found: Vec<_> = number_spans(text)
                .into_iter()
                .filter(|r| !overlaps(&taken, r))
                .collect();
            taken.extend(found.iter().cloned());
            spans.extend(found.into_iter().map(|r| span(text, SpanKind::Number, r)));
        }
        if self.names {
            let found: Vec<_> = name_spans(text)
                .into_iter()
                .filter(|r| !overlaps(&taken, r))
                .collect();
            spans.extend(found.into_iter().map(|r| span(text, SpanKind::Name, r)));
        }

        spans.sort_by_key(|s| (s.start, s.end));
        spans
    }

    /// The byte ranges of [`Guard::extract`], for a diff that keeps them
    /// whole.
    pub fn ranges(&self, text: &str) -> Vec<Range<usize>> {
        self.extract(text).iter().map(Span::range).collect()
    }

    /// Checks that `rewrite` kept every protected span of `original` and
    /// introduced no number of its own.
    ///
    /// # Errors
    ///
    /// Every [`Violation`], missing ones first in the original's order,
    /// then introduced ones in the rewrite's order. A span that occurs
    /// several times in the original is reported once.
    pub fn verify(&self, original: &str, rewrite: &str) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();
        let mut seen = BTreeSet::new();
        for span in self.extract(original) {
            let key = (span.kind, span.protected().to_owned());
            if seen.contains(&key) {
                continue;
            }
            if !contains_bounded(rewrite, span.protected(), span.kind) {
                violations.push(Violation {
                    kind: ViolationKind::Missing,
                    span,
                });
            }
            seen.insert(key);
        }
        if self.numbers {
            let mut introduced = BTreeSet::new();
            for span in self.extract(rewrite) {
                if span.kind == SpanKind::Number
                    && !contains_bounded(original, &span.text, SpanKind::Number)
                    && introduced.insert(span.text.clone())
                {
                    violations.push(Violation {
                        kind: ViolationKind::Introduced,
                        span,
                    });
                }
            }
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// [`Guard::extract`] with every kind on.
pub fn extract(text: &str) -> Vec<Span> {
    Guard::new().extract(text)
}

/// [`Guard::verify`] with every kind on.
///
/// # Errors
///
/// See [`Guard::verify`].
pub fn verify(original: &str, rewrite: &str) -> Result<(), Vec<Violation>> {
    Guard::new().verify(original, rewrite)
}

fn span(text: &str, kind: SpanKind, range: Range<usize>) -> Span {
    Span {
        kind,
        text: text[range.clone()].to_owned(),
        start: range.start,
        end: range.end,
    }
}

fn overlaps(taken: &[Range<usize>], range: &Range<usize>) -> bool {
    taken
        .iter()
        .any(|t| t.start < range.end && range.start < t.end)
}

// ---------------------------------------------------------------- code ----

/// Fenced blocks first, then inline code outside them.
fn code_spans(text: &str) -> Vec<Range<usize>> {
    let mut spans = fenced_blocks(text);
    let fenced = spans.clone();
    spans.extend(
        inline_code(text)
            .into_iter()
            .filter(|r| !overlaps(&fenced, r)),
    );
    spans.sort_by_key(|r| r.start);
    spans
}

/// The lines of `text` with their byte offsets, newline excluded.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut at = 0;
    text.split_inclusive('\n').map(move |raw| {
        let start = at;
        at += raw.len();
        (start, raw.trim_end_matches(['\n', '\r']))
    })
}

/// The fence a line opens or closes, as (marker char, run length).
fn fence(line: &str) -> Option<(char, usize)> {
    let trimmed = line.trim_start_matches(' ');
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    let marker = trimmed.chars().next().filter(|c| *c == '`' || *c == '~')?;
    let run = trimmed.chars().take_while(|c| *c == marker).count();
    (run >= 3).then_some((marker, run))
}

fn fenced_blocks(text: &str) -> Vec<Range<usize>> {
    let mut blocks = Vec::new();
    let mut open: Option<(usize, char, usize)> = None;
    for (start, line) in lines(text) {
        match open {
            None => {
                if let Some((marker, run)) = fence(line) {
                    let indent = line.len() - line.trim_start_matches(' ').len();
                    open = Some((start + indent, marker, run));
                }
            }
            Some((from, marker, run)) => {
                let closes = fence(line).is_some_and(|(m, r)| {
                    m == marker && r >= run && line.trim().chars().all(|c| c == marker)
                });
                if closes {
                    blocks.push(from..start + line.trim_end().len());
                    open = None;
                }
            }
        }
    }
    // An unclosed fence runs to the end of the text, as in CommonMark.
    if let Some((from, _, _)) = open {
        blocks.push(from..text.trim_end().len().max(from));
    }
    blocks
}

fn inline_code(text: &str) -> Vec<Range<usize>> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'`' {
            i += 1;
            continue;
        }
        let run = bytes[i..].iter().take_while(|b| **b == b'`').count();
        let body = i + run;
        let mut j = body;
        let mut closed = None;
        while j < bytes.len() {
            if text[j..].starts_with("\n\n") || text[j..].starts_with("\r\n\r\n") {
                break;
            }
            if bytes[j] == b'`' {
                let close = bytes[j..].iter().take_while(|b| **b == b'`').count();
                if close == run {
                    closed = Some(j + close);
                    break;
                }
                j += close;
            } else {
                j += 1;
            }
        }
        match closed {
            Some(end) if end > body + run => {
                spans.push(i..end);
                i = end;
            }
            _ => i = body,
        }
    }
    spans
}

// -------------------------------------------------------------- quotes ----

/// The quoted words of a quote span: marks and closing punctuation off.
fn quote_words(quote: &str) -> &str {
    let inner = quote
        .strip_prefix(['"', '“', '„', '«'])
        .and_then(|q| q.strip_suffix(['"', '”', '“', '»']))
        .unwrap_or(quote);
    inner
        .trim()
        .trim_end_matches([',', '.', ';', ':'])
        .trim_end()
}

fn quote_spans(text: &str, taken: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let close = match c {
            '"' => '"',
            '“' => '”',
            '„' => '“',
            '«' => '»',
            _ => continue,
        };
        if taken.iter().any(|t| t.contains(&i)) {
            continue;
        }
        let body = i + c.len_utf8();
        let mut end = None;
        for (count, (j, d)) in text[body..].char_indices().enumerate() {
            if count > MAX_QUOTE_CHARS || text[body + j..].starts_with("\n\n") {
                break;
            }
            if d == close {
                end = Some(body + j + d.len_utf8());
                break;
            }
        }
        let Some(end) = end else { continue };
        let range = i..end;
        let words = quote_words(&text[range.clone()]);
        if words.chars().any(char::is_alphanumeric) && !overlaps(taken, &range) {
            // Skip the closing mark so it cannot open the next quote.
            while chars.peek().is_some_and(|(j, _)| *j < end) {
                chars.next();
            }
            spans.push(range);
        }
    }
    spans
}

// ------------------------------------------------------------- numbers ----

const CURRENCY: &[char] = &[
    '$', '€', '£', '¥', '₹', '₩', '₽', '฿', '₦', '₱', '₫', '₺', '₪', '¢',
];

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric()
}

/// The char before byte `at`, if any.
fn before(text: &str, at: usize) -> Option<char> {
    text[..at].chars().next_back()
}

fn number_spans(text: &str) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let Some(c) = text[i..].chars().next() else {
            break;
        };
        let at_boundary = before(text, i).is_none_or(|p| !is_word_char(p));
        if at_boundary && let Some(end) = number_at(text, i) {
            spans.push(i..end);
            i = end;
            continue;
        }
        i += c.len_utf8();
    }
    spans
}

/// The end of a number token starting at `start`, if one starts there.
fn number_at(text: &str, start: usize) -> Option<usize> {
    let rest = &text[start..];
    let mut chars = rest.char_indices().peekable();
    let (_, first) = *chars.peek()?;

    let digits_from = if CURRENCY.contains(&first) {
        chars.next();
        let (at, c) = *chars.peek()?;
        if !c.is_ascii_digit() {
            return None;
        }
        at
    } else if first.is_ascii_uppercase() {
        // Q3, FY2024, H1, GPT-4: one to four capitals glued to digits.
        let caps = rest.chars().take_while(char::is_ascii_uppercase).count();
        if caps > 4 {
            return None;
        }
        let mut at = caps;
        if rest[at..].starts_with('-') {
            at += 1;
        }
        if !rest[at..].starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        at
    } else if first.is_ascii_digit() {
        0
    } else {
        return None;
    };

    // Digits, joined by separators only when a digit follows.
    let bytes = rest.as_bytes();
    let mut end = digits_from;
    loop {
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        let joins = end + 1 < bytes.len()
            && matches!(bytes[end], b'.' | b',' | b':' | b'/' | b'-')
            && bytes[end + 1].is_ascii_digit();
        if joins {
            end += 1;
        } else {
            break;
        }
    }
    // A percent or per-mille sign, then any letters glued on (M, bn, st, x).
    if let Some(sign) = rest[end..]
        .chars()
        .next()
        .filter(|c| matches!(c, '%' | '‰'))
    {
        end += sign.len_utf8();
    }
    end += rest[end..]
        .chars()
        .take_while(|c| c.is_alphanumeric())
        .map(char::len_utf8)
        .sum::<usize>();
    Some(start + end)
}

// --------------------------------------------------------------- names ----

/// Function words that start a sentence often and a name rarely. Dropped
/// from the front of a run of capitalised words.
const LEADING: &[&str] = &[
    "A",
    "About",
    "After",
    "Also",
    "An",
    "And",
    "As",
    "At",
    "Before",
    "But",
    "By",
    "Dear",
    "During",
    "Each",
    "Every",
    "For",
    "From",
    "Furthermore",
    "He",
    "Her",
    "Here",
    "His",
    "However",
    "I",
    "If",
    "In",
    "Into",
    "It",
    "Its",
    "Meanwhile",
    "Moreover",
    "My",
    "No",
    "Not",
    "Of",
    "On",
    "Once",
    "Or",
    "Our",
    "She",
    "Since",
    "So",
    "Some",
    "That",
    "The",
    "Their",
    "Then",
    "There",
    "These",
    "They",
    "This",
    "Those",
    "Thus",
    "To",
    "Under",
    "Until",
    "We",
    "What",
    "When",
    "Where",
    "While",
    "Why",
    "With",
    "Yet",
    "You",
    "Your",
];

/// Lowercase words that may sit between the capitalised words of a name.
const PARTICLES: &[&str] = &[
    "al", "bin", "da", "de", "del", "der", "di", "du", "la", "le", "of", "van", "von",
];

/// A word: letters, with `'`, `’` or `-` allowed between letters.
fn word_at(text: &str, start: usize) -> Option<usize> {
    let mut end = start;
    let mut chars = text[start..].char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if c.is_alphabetic() {
            end = start + at + c.len_utf8();
        } else if !(matches!(c, '\'' | '’' | '-')
            && end == start + at
            && chars.peek().is_some_and(|(_, n)| n.is_alphabetic()))
        {
            break;
        }
    }
    (end > start).then_some(end)
}

fn is_capitalised(word: &str) -> bool {
    word.chars().next().is_some_and(char::is_uppercase)
}

/// Drops a trailing possessive (`'s`, `’s`, or a bare `'`/`’` after s).
fn without_possessive(word: &str) -> &str {
    for suffix in ["'s", "’s", "'S", "’S"] {
        if let Some(stem) = word.strip_suffix(suffix) {
            return stem;
        }
    }
    word.trim_end_matches(['\'', '’'])
}

fn name_spans(text: &str) -> Vec<Range<usize>> {
    // Every word with its range, and whether exactly one space precedes it.
    let mut words: Vec<(Range<usize>, bool)> = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let c = text[i..].chars().next().unwrap_or(' ');
        let at_boundary = before(text, i).is_none_or(|p| !p.is_alphanumeric());
        if at_boundary
            && c.is_alphabetic()
            && let Some(end) = word_at(text, i)
        {
            // Digits glued on make it not a word (Q3 is a number).
            if text[end..].starts_with(|n: char| n.is_alphanumeric()) {
                i = end;
                continue;
            }
            let joined = words
                .last()
                .is_some_and(|(w, _)| matches!(&text[w.end..i], " " | "\u{a0}"));
            words.push((i..end, joined));
            i = end;
        } else {
            i += c.len_utf8();
        }
    }

    let mut spans = Vec::new();
    let mut k = 0;
    while k < words.len() {
        if !is_capitalised(&text[words[k].0.clone()]) {
            k += 1;
            continue;
        }
        // Grow a run: capitalised words, or a particle between two of them.
        let mut run = vec![k];
        let mut j = k + 1;
        while j < words.len() && words[j].1 {
            // A word ending in a possessive closes the name.
            let last = &text[words[*run.last().unwrap_or(&k)].0.clone()];
            if without_possessive(last) != last {
                break;
            }
            let word = &text[words[j].0.clone()];
            if is_capitalised(word) {
                run.push(j);
                j += 1;
            } else if PARTICLES.contains(&word)
                && j + 1 < words.len()
                && words[j + 1].1
                && is_capitalised(&text[words[j + 1].0.clone()])
            {
                run.push(j);
                run.push(j + 1);
                j += 2;
            } else {
                break;
            }
        }
        while run.first().is_some_and(|f| {
            let word = &text[words[*f].0.clone()];
            LEADING.contains(&word) || !is_capitalised(word)
        }) {
            run.remove(0);
        }
        let capitalised = run
            .iter()
            .filter(|w| is_capitalised(&text[words[**w].0.clone()]))
            .count();
        if capitalised >= 2
            && let (Some(first), Some(last)) = (run.first(), run.last())
        {
            let start = words[*first].0.start;
            let last_range = words[*last].0.clone();
            let end = last_range.start + without_possessive(&text[last_range]).len();
            spans.push(start..end);
        }
        k = j.max(k + 1);
    }
    spans
}

// -------------------------------------------------------------- verify ----

/// Whether `needle` occurs in `hay` at a word boundary for its kind.
fn contains_bounded(hay: &str, needle: &str, kind: SpanKind) -> bool {
    if needle.is_empty() {
        return true;
    }
    let starts_word = needle.starts_with(is_word_char);
    let ends_word = needle.ends_with(is_word_char);
    // 4.2 inside 14.2 or 1,4.2: a number runs on through a separator
    // that has a digit on its far side.
    let number = kind == SpanKind::Number;
    let runs_on = |sep: char, far: Option<char>| {
        number && matches!(sep, '.' | ',') && far.is_some_and(|d| d.is_ascii_digit())
    };
    hay.match_indices(needle).any(|(at, _)| {
        let end = at + needle.len();
        let left_ok = !starts_word
            || before(hay, at)
                .is_none_or(|p| !is_word_char(p) && !runs_on(p, before(hay, at - p.len_utf8())));
        let right_ok = !ends_word
            || hay[end..].chars().next().is_none_or(|n| {
                !is_word_char(n) && !runs_on(n, hay[end + n.len_utf8()..].chars().next())
            });
        left_ok && right_ok
    })
}

#[cfg(test)]
mod tests;
