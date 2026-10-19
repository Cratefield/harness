//! Chunk-and-reassemble completion for the [`TextModel`] port (issue #847):
//! split a long document into bounded chunks, complete each one, and stitch
//! the answers back together in order.
//!
//! A buffered [`TextModel::complete`] is one provider exchange, and that
//! exchange is bounded by [`HttpPolicy`]: a caller-supplied deadline cannot
//! exceed [`MAX_RESPONSE_TIMEOUT`], because a request must not spend half
//! its Worker lifetime waiting on one upstream. A ghostwritten 10,000-word
//! draft does not fit that budget as a single prompt, so callers have been
//! hand-splitting the document and stitching the outputs back together.
//! The splitter here does it once, for everyone: the round trip is exact,
//! boundaries fall on paragraph boundaries, and a fenced code block is
//! never cut in half.
//!
//! Chunking buys the bound with latency: `n` chunks are `n` sequential
//! round trips. When the job is generation rather than a bounded rewrite —
//! a whole document being written, a first token wanted as fast as the
//! provider can send one — use [`TextModel::stream`] (issue #859) instead,
//! one request with deltas as they arrive. And when each chunk should come
//! back as a structured value, build the schema into the prompt the
//! `prompt` closure returns and pair this with
//! [`TextModelExt`](crate::TextModelExt).
//!
//! ```
//! use async_trait::async_trait;
//! use cratefield_core::{
//!     Completion, ModelTier, Prompt, TextModel, TextModelChunkedExt, TextModelError,
//! };
//!
//! // A stub rewriter: answers each chunk with its uppercase form, so the
//! // example can see each chunk went through the model whole.
//! struct Shouty;
//!
//! #[async_trait]
//! impl TextModel for Shouty {
//!     async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError> {
//!         let chunk = prompt
//!             .messages
//!             .last()
//!             .map(|turn| turn.content.as_str())
//!             .unwrap_or_default();
//!         Ok(Completion::new(chunk.to_uppercase(), "shouty"))
//!     }
//! }
//!
//! let rewritten = pollster::block_on(Shouty.complete_chunked(
//!     "first paragraph\n\nsecond paragraph",
//!     20,
//!     |index, total, chunk| {
//!         Prompt::new(ModelTier::Fast)
//!             .system(format!("rewriting chunk {index} of {total}"))
//!             .user(chunk)
//!     },
//! ))
//! .unwrap();
//! assert_eq!(rewritten, "FIRST PARAGRAPH\n\nSECOND PARAGRAPH");
//! ```

use std::ops::Range;

use async_trait::async_trait;

use crate::ports::{Prompt, TextModel, TextModelError};

/// Splits `text` into chunks of at most `max_chars` chars, on paragraph
/// boundaries wherever packing allows, and never inside a fenced code
/// block.
///
/// The contract, in the order it matters:
///
/// - **Round trip.** The concatenation of the returned chunks is `text`
///   byte-for-byte, always. Separators travel with blocks: a paragraph or
///   fenced block keeps the blank-line run that follows it, and a blank
///   run at the very start of the document rides in front of the first
///   chunk's content whenever the two fit one chunk together (a run that
///   cannot stands alone as a whitespace-only chunk —
///   [`TextModelChunkedExt::complete_chunked`] never asks the model about
///   one). `\r\n` input round-trips too — the split works on byte
///   offsets, and a `\r\n` blank line counts as blank.
/// - **The bound.** Every chunk is at most `max_chars` chars (characters,
///   not bytes), with exactly one exception: a single fenced code block
///   longer than `max_chars` is one oversized chunk, because chunks are
///   never split inside a fence.
/// - **Paragraph preference.** Boundaries fall on blank-line runs whenever
///   packing allows, so a chunk is a whole number of paragraphs and
///   blocks. (The blank-line runs themselves are packing items: a run that
///   no longer fits a chunk starts the next one, still never inside a
///   paragraph.)
/// - **Fences.** A line whose leading-whitespace-stripped form starts with
///   three or more backticks or tildes opens a fence; it closes at a line
///   whose trimmed form is a run of the same marker at least as long, with
///   no info string. A blank line inside a fence stays inside it, an
///   unclosed fence runs to the end of the input as one (possibly
///   oversized) chunk, and a four-backtick fence does not close at an
///   inner three-backtick line. Indented (four-space) code blocks are
///   *not* fence-tracked: they are ordinary lines and may split at line
///   boundaries.
/// - **Fallbacks.** A plain block longer than `max_chars` splits at line
///   boundaries, greedily packing whole lines; a single line longer than
///   the bound is hard-cut every `max_chars` chars, always on a char
///   boundary — multibyte input never splits mid-character.
///
/// Empty input returns an empty [`Vec`]; whitespace-only input is a single
/// chunk holding it, however long — there is nothing in it to model.
///
/// # Panics
///
/// Panics if `max_chars` is zero: a zero-char chunk cannot hold anything.
///
/// # Examples
///
/// ```
/// use cratefield_core::{reassemble_text_chunks, split_text_chunks};
///
/// let text = "first paragraph\n\nsecond paragraph";
/// let chunks = split_text_chunks(text, 20);
/// assert_eq!(chunks, vec!["first paragraph\n\n", "second paragraph"]);
/// assert_eq!(reassemble_text_chunks(&chunks), text);
/// ```
pub fn split_text_chunks(text: &str, max_chars: usize) -> Vec<String> {
    assert!(max_chars > 0, "max_chars must be at least 1, got 0");
    if text.is_empty() {
        return Vec::new();
    }
    if text.chars().all(char::is_whitespace) {
        // Whitespace only, however long: one chunk. Splitting it would
        // only manufacture chunks of padding for the model to answer.
        return vec![text.to_owned()];
    }

    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_chars = 0usize;

    for item in scan_items(text) {
        let item_text = &text[item.range];
        let item_chars = item_text.chars().count();
        if current_chars + item_chars <= max_chars {
            current.push_str(item_text);
            current_chars += item_chars;
            continue;
        }
        // The item cannot join the current chunk: close it.
        if current_chars > 0 {
            chunks.push(std::mem::take(&mut current));
            current_chars = 0;
        }
        if item_chars <= max_chars {
            // The item starts the next chunk whole.
            current.push_str(item_text);
            current_chars = item_chars;
        } else if item.fenced {
            // The one bound exception: a fenced block longer than the
            // bound is atomic, so it stands alone as one oversized chunk.
            chunks.push(item_text.to_owned());
        } else {
            chunks.extend(split_oversized(item_text, max_chars));
        }
    }
    if current_chars > 0 {
        chunks.push(current);
    }
    chunks
}

/// Reassembles per-chunk completions in order: plain concatenation, with
/// no separator inserted, because [`split_text_chunks`] kept every
/// separator inside the chunks. Feeding it the chunks themselves
/// reproduces the input byte-for-byte; feeding it a model's per-chunk
/// answers reproduces the document's shape, whatever the model wrote.
///
/// ```
/// use cratefield_core::reassemble_text_chunks;
///
/// assert_eq!(reassemble_text_chunks(["one", "two", "three"]), "onetwothree");
/// assert_eq!(reassemble_text_chunks(Vec::<&str>::new()), "");
/// ```
pub fn reassemble_text_chunks(chunks: impl IntoIterator<Item: AsRef<str>>) -> String {
    // A `map(..).collect()` here would borrow each chunk from the closure's
    // by-value parameter, which rustc refuses to let escape into a return
    // (E0515); the loop copies each chunk into the answer instead.
    let mut text = String::new();
    for chunk in chunks {
        text.push_str(chunk.as_ref());
    }
    text
}

/// Chunk-and-reassemble companion to
/// [`TextModelExt`](crate::TextModelExt) (issue #847). Blanket-implemented
/// for every `TextModel`, so any model — `Arc<dyn TextModel>` included —
/// gets it; import the trait to call the method.
#[async_trait]
pub trait TextModelChunkedExt: TextModel {
    /// Completes `text` in chunks of at most `max_chars` chars: splits it
    /// with [`split_text_chunks`], calls [`TextModel::complete`] once per
    /// chunk — sequentially, in order, chunk *n* asked only after *n−1*
    /// answered — and reassembles the answers with
    /// [`reassemble_text_chunks`].
    ///
    /// `prompt(chunk_index, total_chunks, chunk_text)` builds each request;
    /// the helper never builds a prompt itself, so the tier, the system
    /// instruction and the token ceiling stay the caller's. Chunk indexes
    /// are 0-based and `total_chunks` is every chunk sent to the model, so
    /// a closure can say "part 3 of 7" without counting anything.
    ///
    /// Empty `text` returns `Ok(String::new())` without calling the model;
    /// whitespace-only `text` returns itself unchanged, also without
    /// calling it. The same rule applies per chunk: a whitespace-only
    /// chunk — a blank run that could not share a chunk with either
    /// neighbour — passes through untouched at no round trip, and is not
    /// counted in `total_chunks`: there is nothing in it to rewrite.
    ///
    /// # Errors
    ///
    /// Whatever [`TextModel::complete`] returned for the chunk that
    /// failed, unchanged — there is no wrapper variant on
    /// [`TextModelError`] that could name the chunk without mislabelling
    /// the failure (`Transient` must keep its `retry_after`, and the
    /// message-carrying variants are documented as provider text). The run
    /// stops at the first failure and completed chunk work is discarded.
    ///
    /// # Panics
    ///
    /// Panics if `max_chars` is zero, via [`split_text_chunks`].
    async fn complete_chunked(
        &self,
        text: &str,
        max_chars: usize,
        // `for<'a>`: an elided `&str` here would be desugared by
        // `#[async_trait]` into a lifetime of the returned future, and no
        // chunk borrowed inside the body could ever satisfy it.
        prompt: impl for<'a> FnMut(usize, usize, &'a str) -> Prompt + Send,
    ) -> Result<String, TextModelError>;
}

#[async_trait]
impl<M: TextModel + ?Sized> TextModelChunkedExt for M {
    async fn complete_chunked(
        &self,
        text: &str,
        max_chars: usize,
        mut prompt: impl for<'a> FnMut(usize, usize, &'a str) -> Prompt + Send,
    ) -> Result<String, TextModelError> {
        let chunks = split_text_chunks(text, max_chars);
        let total = chunks
            .iter()
            .filter(|chunk| !chunk.chars().all(char::is_whitespace))
            .count();
        let mut answers = Vec::with_capacity(chunks.len());
        let mut index = 0usize;
        for chunk in &chunks {
            if chunk.chars().all(char::is_whitespace) {
                // A blank run can end up in a chunk of its own when it cannot
                // share one with either neighbour. There is nothing in it to
                // rewrite: pass it through untouched, at no round trip.
                answers.push(chunk.clone());
                continue;
            }
            let completion = self.complete(&prompt(index, total, chunk)).await?;
            answers.push(completion.text);
            index += 1;
        }
        Ok(reassemble_text_chunks(answers))
    }
}

/// One scanned run of the document: consecutive lines of one kind, as a
/// byte range into the input. Ranges are consecutive and cover the input
/// exactly, which is what makes the round trip byte-for-byte.
struct Item {
    range: Range<usize>,
    /// A fenced code block, opener line through closer line — atomic, and
    /// the one thing allowed to exceed the bound.
    fenced: bool,
}

/// The kind of a plain, non-fenced run of lines. A fence is never
/// accumulated — it is pushed whole when its closer (or end of input) is
/// found — so it needs no kind here.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TextKind {
    /// Blank lines, the separators between blocks.
    Blank,
    /// Non-blank lines, a paragraph.
    Paragraph,
}

/// Scans `text` into ordered items covering it exactly: blank-line runs,
/// paragraphs (maximal runs of non-blank lines), and fenced code blocks
/// (opener through closer, or to the end of the input when unclosed).
/// Fence state is tracked line by line, so a blank line inside a fence
/// stays inside it instead of ending a text block.
fn scan_items(text: &str) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    // The plain item being accumulated: its kind and its byte range so
    // far, `end` always the end of the last line consumed.
    let mut kind: Option<TextKind> = None;
    let mut start = 0;
    let mut end = 0;
    // The open fence's marker byte and opener run length, plus the byte
    // offset the fence item started at.
    let mut fence: Option<(u8, usize)> = None;
    let mut fence_start = 0;

    let mut i = 0;
    while i < text.len() {
        let line_start = i;
        let line_end = match text[i..].find('\n') {
            Some(at) => i + at + 1,
            None => text.len(),
        };
        let trimmed = text[line_start..line_end].trim();

        if let Some((marker, count)) = fence {
            if closes_fence(trimmed, marker, count) {
                fence = None;
                items.push(Item {
                    range: fence_start..line_end,
                    fenced: true,
                });
                kind = None;
            }
            // Any other line — blank included — is fence body.
        } else if trimmed.is_empty() {
            if kind != Some(TextKind::Blank) {
                push_text(&mut items, kind, start, end);
                kind = Some(TextKind::Blank);
                start = line_start;
            }
        } else if let Some((marker, count)) = opens_fence(trimmed) {
            push_text(&mut items, kind, start, end);
            kind = None;
            fence = Some((marker, count));
            fence_start = line_start;
        } else if kind != Some(TextKind::Paragraph) {
            push_text(&mut items, kind, start, end);
            kind = Some(TextKind::Paragraph);
            start = line_start;
        }
        end = line_end;
        i = line_end;
    }

    if fence.is_some() {
        // An unclosed fence runs to the end of the input.
        items.push(Item {
            range: fence_start..text.len(),
            fenced: true,
        });
    } else {
        push_text(&mut items, kind, start, end);
    }
    items
}

/// Closes the accumulated plain item, if there is one. Fences are pushed
/// when their closer is found, or at end of input when unclosed, never
/// here.
fn push_text(items: &mut Vec<Item>, kind: Option<TextKind>, start: usize, end: usize) {
    if matches!(kind, Some(TextKind::Blank | TextKind::Paragraph)) && end > start {
        items.push(Item {
            range: start..end,
            fenced: false,
        });
    }
}

/// The fence a line opens, if any: a leading-whitespace-stripped line
/// starting with three or more backticks or tildes. The run length is the
/// fence's opener count; everything after the run is the info string.
fn opens_fence(trimmed: &str) -> Option<(u8, usize)> {
    let bytes = trimmed.as_bytes();
    let marker = *bytes.first()?;
    if marker != b'`' && marker != b'~' {
        return None;
    }
    let count = bytes.iter().take_while(|&&byte| byte == marker).count();
    (count >= 3).then_some((marker, count))
}

/// Whether `trimmed` closes the fence opened with `marker` repeated
/// `count` times: a run of the same marker at least as long and nothing
/// else — no info string. The caller trims the line, which allows
/// surrounding whitespace.
fn closes_fence(trimmed: &str, marker: u8, count: usize) -> bool {
    let bytes = trimmed.as_bytes();
    bytes.len() >= count && bytes.iter().all(|&byte| byte == marker)
}

/// Splits an oversized plain item at line boundaries, greedily packing
/// whole lines up to `max_chars`; a single line longer than the bound is
/// hard-cut every `max_chars` chars, always on a char boundary.
fn split_oversized(text: &str, max_chars: usize) -> Vec<String> {
    let mut pieces: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_chars = 0usize;

    let mut i = 0;
    while i < text.len() {
        let line_end = match text[i..].find('\n') {
            Some(at) => i + at + 1,
            None => text.len(),
        };
        let line = &text[i..line_end];
        i = line_end;
        let line_chars = line.chars().count();
        if line_chars > max_chars {
            if current_chars > 0 {
                pieces.push(std::mem::take(&mut current));
                current_chars = 0;
            }
            let mut cut = String::new();
            let mut count = 0usize;
            for ch in line.chars() {
                cut.push(ch);
                count += 1;
                if count == max_chars {
                    pieces.push(std::mem::take(&mut cut));
                    count = 0;
                }
            }
            if !cut.is_empty() {
                pieces.push(cut);
            }
        } else if current_chars + line_chars <= max_chars {
            current.push_str(line);
            current_chars += line_chars;
        } else {
            pieces.push(std::mem::take(&mut current));
            current.push_str(line);
            current_chars = line_chars;
        }
    }
    if current_chars > 0 {
        pieces.push(current);
    }
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- The fixture corpus ----

    /// The corpus every property test runs over: the document shapes a
    /// ghostwriting caller actually has.
    fn corpus() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "plain paragraphs",
                "The quick brown fox.\n\nSecond paragraph here.\n\nThird one.\n",
            ),
            (
                "crlf",
                "para one\r\n\r\npara two\r\n```rust\r\nlet x = 1;\r\n```\r\n\r\nafter\r\n",
            ),
            (
                "backtick fences with info string and blank lines inside",
                "intro\n\n```rust\nfn main() {}\n\nlet x = 1;\n```\n\noutro\n",
            ),
            ("tilde fence", "before\n\n~~~text\nbody\n~~~\nafter"),
            ("unclosed fence", "text\n\n```python\nprint(1)\nprint(2)"),
            (
                "long fence",
                "```js\nconst a = 1;\nconst b = 2;\nconst c = 3;\nconst d = 4;\nconst e = 5;\n```\n",
            ),
            (
                "four-backtick fence around a three-backtick line",
                "````\n```\nnot a close\n```\nstill inside\n````\ntail\n",
            ),
            (
                "indented fence",
                "before\n\n   ```js\n   const a = 1;\n   ```\nafter\n",
            ),
            ("blank runs at the edges", "\n\n\nlead\n\ntrail\n\n\n"),
            ("whitespace only", "  \n\t\n \n"),
            ("empty", ""),
            ("one line", "one line only"),
            (
                "multibyte",
                "héllo wörld: 日本語のテキストもここに。Émile résume.",
            ),
            (
                "paragraph, fence, paragraph",
                "alpha\n\n```\ncode\n```\n\nomega\n",
            ),
            (
                "many short lines",
                "aaa bbb\nccc ddd\neee fff\nggg hhh\niii jjj\nkkk lll\n",
            ),
        ]
    }

    // ---- Round trip and the bound, over the whole corpus ----

    #[test]
    fn every_fixture_round_trips_byte_for_byte_at_many_bounds() {
        for (name, text) in corpus() {
            for max_chars in [1, 2, 3, 5, 8, 13, 40, 10_000] {
                let chunks = split_text_chunks(text, max_chars);
                assert_eq!(
                    reassemble_text_chunks(&chunks),
                    text,
                    "{name} at max_chars {max_chars}"
                );
            }
        }
    }

    #[test]
    fn every_chunk_respects_the_bound_except_atomic_fences() {
        for (name, text) in corpus() {
            if text.chars().all(char::is_whitespace) {
                continue; // one chunk by contract, however long
            }
            for max_chars in [1, 2, 3, 5, 8, 13, 40] {
                for chunk in split_text_chunks(text, max_chars) {
                    let chars = chunk.chars().count();
                    assert!(
                        chars <= max_chars || is_single_atomic_fence(&chunk),
                        "{name} at max_chars {max_chars}: {chars}-char chunk {chunk:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_chunk_of_a_fence_heavy_fixture_has_balanced_fences() {
        for (name, text) in corpus() {
            for max_chars in [1, 5, 8, 13, 40] {
                let chunks = split_text_chunks(text, max_chars);
                // No fence is ever cut: a chunk either balances its
                // fences, or it is the last chunk, ending inside the one
                // fence that runs unclosed to the end of the input.
                let open_at_end: Vec<bool> = chunks
                    .iter()
                    .map(|chunk| open_fence_at_end(chunk).is_some())
                    .collect();
                let open_count = open_at_end.iter().filter(|open| **open).count();
                assert!(
                    open_count == 0 || (open_count == 1 && open_at_end[open_at_end.len() - 1]),
                    "{name} at max_chars {max_chars}: a fence crosses a chunk: {chunks:?}"
                );
            }
        }
    }

    /// Whether `chunk` is exactly one fenced block: the first line opens a
    /// fence and the fence closes at the chunk's last line (or runs to the
    /// end of the chunk unclosed) — the shape of the one bound exception.
    /// The opener line is not a closer candidate for its own fence.
    fn is_single_atomic_fence(chunk: &str) -> bool {
        let lines: Vec<&str> = chunk.lines().collect();
        let Some((marker, count)) = lines
            .first()
            .copied()
            .and_then(|line| opens_fence(line.trim_start()))
        else {
            return false;
        };
        match lines[1..]
            .iter()
            .position(|line| closes_fence(line.trim(), marker, count))
        {
            Some(at) => at + 1 == lines.len() - 1,
            None => true,
        }
    }

    /// The fence left open at the chunk's end, if any — the unclosed-fence
    /// shape, where the fence runs to the end of the input.
    fn open_fence_at_end(chunk: &str) -> Option<(u8, usize)> {
        let mut open: Option<(u8, usize)> = None;
        for line in chunk.lines() {
            if let Some((marker, count)) = open {
                if closes_fence(line.trim(), marker, count) {
                    open = None;
                }
            } else if let Some((marker, count)) = opens_fence(line.trim_start()) {
                open = Some((marker, count));
            }
        }
        open
    }

    // ---- Paragraph preference ----

    #[test]
    fn breaks_land_on_blank_line_runs_not_inside_paragraphs() {
        let text = "alpha bravo\n\ncharlie delta\n\necho foxtrot";
        let chunks = split_text_chunks(text, 30);
        assert_eq!(
            chunks,
            vec!["alpha bravo\n\ncharlie delta\n\n", "echo foxtrot"],
            "the break is the blank run between the second and third paragraph"
        );
    }

    #[test]
    fn a_crlf_blank_line_counts_as_blank_and_travels_with_its_paragraph() {
        let text = "para one\r\n\r\npara two is longer\r\n";
        let chunks = split_text_chunks(text, 14);
        assert_eq!(
            chunks[0], "para one\r\n\r\n",
            "the CRLF blank run is a boundary"
        );
        assert_eq!(
            chunks[1..],
            ["para two is lo", "nger\r\n"],
            "the oversized paragraph falls back to line and char splits"
        );
        assert_eq!(reassemble_text_chunks(&chunks), text);
    }

    #[test]
    fn blank_runs_at_the_edges_stay_with_their_neighbours() {
        let text = "\n\n\nlead\n\ntrail\n\n\n";
        let chunks = split_text_chunks(text, 9);
        assert_eq!(
            chunks,
            vec!["\n\n\nlead\n\n", "trail\n\n\n"],
            "the leading run rides with the first block, the trailing run with the last"
        );
    }

    #[test]
    fn a_leading_blank_run_that_cannot_fit_stands_alone_rather_than_bursting_the_bound() {
        let chunks = split_text_chunks("\n\n\nfirst paragraph body", 20);
        assert_eq!(chunks, vec!["\n\n\n", "first paragraph body"]);
        assert_eq!(
            reassemble_text_chunks(&chunks),
            "\n\n\nfirst paragraph body"
        );
    }

    // ---- Fences are atomic ----

    #[test]
    fn a_fence_is_never_split_even_when_it_exceeds_the_bound() {
        let fence = "```js\nconst a = 1;\nconst b = 2;\nconst c = 3;\nconst d = 4;\n```\n";
        let text = format!("before\n\n{fence}after\n");
        let chunks = split_text_chunks(&text, 10);
        assert!(
            chunks.contains(&fence.to_owned()),
            "the oversized fence stands alone as one chunk: {chunks:?}"
        );
        assert_eq!(reassemble_text_chunks(&chunks), text);
    }

    #[test]
    fn a_four_backtick_fence_does_not_close_at_an_inner_three_backtick_line() {
        let text = "````\n```\ninner\n```\nmore\n````\ntail\n";
        // Bounds below the 29-char fence, so it is oversized and must
        // stand alone, inner ``` and all.
        for max_chars in [4, 6, 10, 28] {
            let chunks = split_text_chunks(text, max_chars);
            let fence = chunks
                .iter()
                .find(|chunk| chunk.starts_with("````"))
                .unwrap_or_else(|| {
                    panic!("the ```` block is one chunk at {max_chars}: {chunks:?}")
                });
            assert!(
                fence.contains("```\ninner") && fence.ends_with("````\n"),
                "the inner ``` did not close the ```` fence at {max_chars}: {fence:?}"
            );
            assert_eq!(reassemble_text_chunks(&chunks), text);
        }
        // And when everything fits, the ```` block is intact in the one
        // chunk.
        assert_eq!(split_text_chunks(text, 40), vec![text]);
    }

    #[test]
    fn an_unclosed_fence_runs_to_the_end_of_the_input() {
        let text = "intro\n\n```python\nprint(1)\nprint(2)";
        let chunks = split_text_chunks(text, 8);
        assert_eq!(reassemble_text_chunks(&chunks), text);
        let last = chunks
            .last()
            .unwrap_or_else(|| panic!("chunks: {chunks:?}"));
        assert!(last.starts_with("```python\n"), "{last:?}");
        assert!(
            is_single_atomic_fence(last),
            "the unclosed fence is one atomic chunk: {last:?}"
        );
    }

    #[test]
    fn blank_lines_inside_a_fence_stay_inside_it() {
        let text = "```rust\nfn main() {}\n\n\nlet x = 1;\n```\n";
        let chunks = split_text_chunks(text, 7);
        assert_eq!(
            chunks,
            vec![text],
            "the blank lines did not end the fence, so the whole block is one chunk"
        );
    }

    // ---- Fallbacks for oversized plain blocks ----

    #[test]
    fn an_oversized_paragraph_splits_at_line_boundaries() {
        let chunks = split_text_chunks("aaa bbb\nccc ddd\neee fff", 8);
        assert_eq!(chunks, vec!["aaa bbb\n", "ccc ddd\n", "eee fff"]);
    }

    #[test]
    fn an_oversized_line_is_hard_cut_on_char_boundaries() {
        let text = "héllo 日本語 wörld";
        let chunks = split_text_chunks(text, 3);
        assert_eq!(reassemble_text_chunks(&chunks), text);
        assert_eq!(
            chunks,
            vec!["hél", "lo ", "日本語", " wö", "rld"],
            "every cut is every third char, never mid-character"
        );
    }

    // ---- Edges ----

    #[test]
    fn empty_input_has_no_chunks() {
        assert_eq!(split_text_chunks("", 100), Vec::<String>::new());
    }

    #[test]
    fn whitespace_only_input_is_one_chunk() {
        let text = "  \n\t\n ";
        assert_eq!(split_text_chunks(text, 2), vec![text]);
    }

    #[test]
    fn text_with_no_split_points_is_one_chunk() {
        assert_eq!(
            split_text_chunks("one line only", 100),
            vec!["one line only"]
        );
    }

    #[test]
    fn a_document_that_fits_is_one_chunk() {
        let text = "para\n\n```js\ncode\n```\n\nfin\n";
        assert_eq!(split_text_chunks(text, 1_000), vec![text]);
    }

    #[test]
    #[should_panic(expected = "max_chars")]
    fn a_zero_bound_panics() {
        split_text_chunks("text", 0);
    }

    // ---- Reassembly ----

    #[test]
    fn reassembly_is_plain_concatenation_in_order() {
        assert_eq!(reassemble_text_chunks(["a", "b", "c"]), "abc");
        assert_eq!(
            reassemble_text_chunks(vec![String::new(), "x".to_owned()]),
            "x"
        );
        assert_eq!(reassemble_text_chunks([""]), "");
        assert_eq!(reassemble_text_chunks(Vec::<&str>::new()), "");
    }
}
