//! `cratefield-text-diff`: a word-level diff for showing what a rewrite
//! changed (issue #836).
//!
//! [`diff_words`] compares two texts word by word and answers with
//! [`Segment`]s that are [`Op::Removed`], [`Op::Added`] or [`Op::Same`].
//! [`diff_words_locked`] also takes the byte ranges of each text that are
//! **protected** — a figure, a name, a quotation, a line of code, as
//! `cratefield-text-guard` finds them, or ranges from anywhere else. A
//! protected range is one atomic token: it is never split into words, and
//! when it is unchanged it comes back as [`Op::Locked`] so a UI can box it.
//!
//! ```
//! use cratefield_text_diff::{Op, diff_words};
//!
//! let segments = diff_words("revenue grew by 18% to $4.2M", "revenue rose 18% to $4.2M");
//! let ops: Vec<_> = segments.iter().map(|s| (s.op, s.text.as_str())).collect();
//! assert_eq!(ops, [
//!     (Op::Same, "revenue "),
//!     (Op::Removed, "grew by "),
//!     (Op::Added, "rose "),
//!     (Op::Same, "18% to $4.2M"),
//! ]);
//! ```
//!
//! # Tokens and whitespace
//!
//! A token is a protected range, a word (letters and digits, with `'` `’`
//! `-` `.` `,` `%` allowed between or after them, so `don't`, `4.2M` and
//! `18%` stay whole), or a single other character. Whitespace is not a
//! token: it rides on the token before it and is not compared, so
//! re-wrapping a paragraph is not a change. Each segment's text carries its
//! trailing whitespace from the side it came from — the rewrite's for
//! `Same`, `Locked` and `Added`, the original's for `Removed` — so the
//! texts of every segment that is not `Removed`, in order, are exactly the
//! rewrite.
//!
//! # Algorithm
//!
//! Myers' O(ND) difference algorithm in its linear-space form (the
//! "middle snake"), after stripping the common prefix and suffix: a full
//! rewrite of a long text costs memory proportional to its length, not its
//! square. The result is a shortest edit script, so a minimal diff, and
//! within each change everything removed is listed before everything added.

#![forbid(unsafe_code)]

use std::ops::Range;

use serde::{Deserialize, Serialize};

/// What happened to a piece of text between the two versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// In both texts.
    Same,
    /// Only in the original.
    Removed,
    /// Only in the rewrite.
    Added,
    /// A protected range that is in both texts unchanged.
    Locked,
}

/// A run of text with one [`Op`]. Adjacent segments never share an op,
/// except [`Op::Locked`], which is one segment per protected range.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Segment {
    pub op: Op,
    pub text: String,
}

/// The word diff of `before` and `after`, with nothing protected.
pub fn diff_words(before: &str, after: &str) -> Vec<Segment> {
    diff_words_locked(before, after, &[], &[])
}

/// The word diff of `before` and `after`, where `before_locked` and
/// `after_locked` are protected byte ranges of each. A range that is out of
/// bounds, not on a `char` boundary, or overlaps an earlier one is ignored.
pub fn diff_words_locked(
    before: &str,
    after: &str,
    before_locked: &[Range<usize>],
    after_locked: &[Range<usize>],
) -> Vec<Segment> {
    let a = tokenize(before, before_locked);
    let b = tokenize(after, after_locked);
    let a_keys: Vec<&str> = a.iter().map(|t| t.core).collect();
    let b_keys: Vec<&str> = b.iter().map(|t| t.core).collect();

    let mut edits = Vec::with_capacity(a.len().max(b.len()));
    Myers::new(&a_keys, &b_keys).run(&mut edits);

    // Between two unchanged tokens, everything removed comes before
    // everything added, so a replacement reads as "this, then that".
    let mut ordered = Vec::with_capacity(edits.len());
    let mut added = Vec::new();
    for edit in edits {
        match edit {
            Edit::Added(_) => added.push(edit),
            Edit::Removed(_) => ordered.push(edit),
            Edit::Same(..) => {
                ordered.append(&mut added);
                ordered.push(edit);
            }
        }
    }
    ordered.append(&mut added);

    let mut out: Vec<Segment> = Vec::new();
    for edit in ordered {
        let (op, text) = match edit {
            Edit::Same(i, j) => {
                let op = if a[i].locked && b[j].locked {
                    Op::Locked
                } else {
                    Op::Same
                };
                (op, b[j].text())
            }
            Edit::Removed(i) => (Op::Removed, a[i].text()),
            Edit::Added(j) => (Op::Added, b[j].text()),
        };
        match out.last_mut() {
            Some(last) if last.op == op && op != Op::Locked => last.text.push_str(text),
            _ => out.push(Segment {
                op,
                text: text.to_owned(),
            }),
        }
    }
    out
}

/// One token: what is compared (`core`) and the whitespace after it.
#[derive(Debug)]
struct Token<'a> {
    /// `core` and its trailing whitespace, contiguous in the source.
    full: &'a str,
    core: &'a str,
    locked: bool,
}

impl<'a> Token<'a> {
    fn text(&self) -> &'a str {
        self.full
    }
}

fn is_joiner(c: char) -> bool {
    matches!(c, '\'' | '’' | '-' | '.' | ',' | '%')
}

fn tokenize<'a>(text: &'a str, locked: &[Range<usize>]) -> Vec<Token<'a>> {
    let mut ranges: Vec<Range<usize>> = locked
        .iter()
        .filter(|r| {
            r.start < r.end
                && r.end <= text.len()
                && text.is_char_boundary(r.start)
                && text.is_char_boundary(r.end)
        })
        .cloned()
        .collect();
    ranges.sort_by_key(|r| r.start);
    let mut kept: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for r in ranges {
        if kept.last().is_none_or(|k| k.end <= r.start) {
            kept.push(r);
        }
    }
    let mut locked = kept.into_iter().peekable();

    let mut tokens = Vec::new();
    let mut i = 0;
    // Leading whitespace is an empty token, so it is not lost.
    let lead = text.len() - text.trim_start().len();
    if lead > 0 {
        tokens.push(Token {
            full: &text[..lead],
            core: "",
            locked: false,
        });
        i = lead;
    }
    while i < text.len() {
        let (end, is_locked) = if let Some(r) = locked.next_if(|r| r.start <= i) {
            // A range that starts inside whitespace already consumed is
            // clipped to here.
            (r.end.max(i + 1).min(text.len()), true)
        } else {
            let next_lock = locked.peek().map_or(text.len(), |r| r.start);
            (word_end(text, i, next_lock), false)
        };
        let end = end.max(i + text[i..].chars().next().map_or(1, char::len_utf8));
        let ws = text[end..].len() - text[end..].trim_start().len();
        let ws_end = locked
            .peek()
            .map_or(end + ws, |r| (end + ws).min(r.start.max(end)));
        tokens.push(Token {
            full: &text[i..ws_end],
            core: &text[i..end],
            locked: is_locked,
        });
        i = ws_end;
    }
    tokens
}

/// The end of the word (or single character) starting at `start`, never
/// past `limit`.
fn word_end(text: &str, start: usize, limit: usize) -> usize {
    let mut chars = text[start..limit].char_indices().peekable();
    let Some((_, first)) = chars.next() else {
        return start;
    };
    if !first.is_alphanumeric() {
        return start + first.len_utf8();
    }
    let mut end = start + first.len_utf8();
    while let Some((at, c)) = chars.next() {
        if c.is_alphanumeric() {
            end = start + at + c.len_utf8();
        } else if is_joiner(c) && end == start + at {
            // A joiner stays in the word when a letter or digit follows it,
            // or when it is a trailing % (18%).
            let followed = chars.peek().is_some_and(|(_, n)| n.is_alphanumeric());
            if followed || c == '%' {
                end = start + at + c.len_utf8();
            } else {
                break;
            }
        } else {
            break;
        }
    }
    end
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edit {
    Same(usize, usize),
    Removed(usize),
    Added(usize),
}

/// Myers' linear-space diff over two key sequences.
struct Myers<'k> {
    a: &'k [&'k str],
    b: &'k [&'k str],
    forward: Vec<usize>,
    backward: Vec<usize>,
}

/// A snake of the middle: equal tokens from `(x, y)` to `(u, v)`, in
/// coordinates of the current sub-problem.
struct Snake {
    x: usize,
    y: usize,
    u: usize,
    v: usize,
}

impl<'k> Myers<'k> {
    fn new(a: &'k [&'k str], b: &'k [&'k str]) -> Self {
        let size = 2 * (a.len() + b.len()) + 4;
        Self {
            a,
            b,
            forward: vec![0; size],
            backward: vec![0; size],
        }
    }

    fn run(mut self, out: &mut Vec<Edit>) {
        self.compare(0..self.a.len(), 0..self.b.len(), out);
    }

    fn compare(&mut self, mut a: Range<usize>, mut b: Range<usize>, out: &mut Vec<Edit>) {
        while a.start < a.end && b.start < b.end && self.a[a.start] == self.b[b.start] {
            out.push(Edit::Same(a.start, b.start));
            a.start += 1;
            b.start += 1;
        }
        let mut suffix = 0;
        while a.start < a.end - suffix
            && b.start < b.end - suffix
            && self.a[a.end - suffix - 1] == self.b[b.end - suffix - 1]
        {
            suffix += 1;
        }
        a.end -= suffix;
        b.end -= suffix;

        if a.is_empty() {
            out.extend(b.clone().map(Edit::Added));
        } else if b.is_empty() {
            out.extend(a.clone().map(Edit::Removed));
        } else {
            let snake = self.middle_snake(a.clone(), b.clone());
            self.compare(a.start..a.start + snake.x, b.start..b.start + snake.y, out);
            for k in 0..snake.u - snake.x {
                out.push(Edit::Same(a.start + snake.x + k, b.start + snake.y + k));
            }
            self.compare(a.start + snake.u..a.end, b.start + snake.v..b.end, out);
        }

        for k in (1..=suffix).rev() {
            out.push(Edit::Same(a.end + suffix - k, b.end + suffix - k));
        }
    }

    /// The middle snake of a sub-problem whose sides are both non-empty and
    /// share no prefix or suffix (Myers 1986, section 4b).
    // The paper's names (a, b, n, m, d, k, x, y) make it checkable against
    // the paper; the casts are within `isize` for any text that fits memory.
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::many_single_char_names
    )]
    fn middle_snake(&mut self, a: Range<usize>, b: Range<usize>) -> Snake {
        let n = a.len() as isize;
        let m = b.len() as isize;
        let delta = n - m;
        let odd = delta % 2 != 0;
        let max = (n + m + 1) / 2;
        let offset = max + 1;
        let idx = |k: isize| (k + offset) as usize;

        self.forward[idx(1)] = 0;
        self.backward[idx(1)] = 0;
        let fwd_eq =
            |s: &Self, x: isize, y: isize| s.a[a.start + x as usize] == s.b[b.start + y as usize];
        let bwd_eq = |s: &Self, x: isize, y: isize| {
            s.a[a.end - 1 - x as usize] == s.b[b.end - 1 - y as usize]
        };

        for d in 0..=max {
            let mut k = -d;
            while k <= d {
                let mut x =
                    if k == -d || (k != d && self.forward[idx(k - 1)] < self.forward[idx(k + 1)]) {
                        self.forward[idx(k + 1)] as isize
                    } else {
                        self.forward[idx(k - 1)] as isize + 1
                    };
                let mut y = x - k;
                let (x0, y0) = (x, y);
                while x < n && y < m && fwd_eq(self, x, y) {
                    x += 1;
                    y += 1;
                }
                self.forward[idx(k)] = x as usize;
                let c = delta - k;
                if odd && c > -d && c < d && x + self.backward[idx(c)] as isize >= n {
                    return Snake {
                        x: x0 as usize,
                        y: y0 as usize,
                        u: x as usize,
                        v: y as usize,
                    };
                }
                k += 2;
            }

            let mut k = -d;
            while k <= d {
                let mut x = if k == -d
                    || (k != d && self.backward[idx(k - 1)] < self.backward[idx(k + 1)])
                {
                    self.backward[idx(k + 1)] as isize
                } else {
                    self.backward[idx(k - 1)] as isize + 1
                };
                let mut y = x - k;
                let (x0, y0) = (x, y);
                while x < n && y < m && bwd_eq(self, x, y) {
                    x += 1;
                    y += 1;
                }
                self.backward[idx(k)] = x as usize;
                let c = delta - k;
                if !odd && c >= -d && c <= d && x + self.forward[idx(c)] as isize >= n {
                    return Snake {
                        x: (n - x) as usize,
                        y: (m - y) as usize,
                        u: (n - x0) as usize,
                        v: (m - y0) as usize,
                    };
                }
                k += 2;
            }
        }
        unreachable!("two non-empty sequences always have a middle snake within (n + m + 1) / 2")
    }
}

#[cfg(test)]
mod tests;
