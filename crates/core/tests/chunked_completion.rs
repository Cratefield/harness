//! `complete_chunked` end to end (issue #847) over an echoing model: whole
//! paragraphs and whole fences go out as single prompts, in order, and the
//! answers reassemble to the document.
#![expect(
    clippy::disallowed_types,
    reason = "the stub records its calls, as the fakes in cratefield-testing do"
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cratefield_core::{
    Completion, ModelTier, Prompt, TextModel, TextModelChunkedExt, TextModelError,
};

/// A document with three paragraphs and a fenced block. Nothing in it is
/// longer than 60 chars, so a 60-char bound must keep every paragraph and
/// the fence whole.
const DOC: &str = concat!(
    "Opening paragraph about the plan.\n",
    "\n",
    "Second paragraph, a little longer than the first.\n",
    "\n",
    "```rust\n",
    "fn main() { println!(\"hi\"); }\n",
    "```\n",
    "\n",
    "Closing paragraph wraps it up.\n",
);

/// A [`TextModel`] that answers every prompt by echoing its last turn back
/// and recording the prompt, so a test can count calls and read the chunk
/// each one carried. `fail_at` makes call `n` (0-based) fail.
struct EchoModel {
    prompts: Mutex<Vec<Prompt>>,
    fail_at: Option<usize>,
}

impl EchoModel {
    fn new(fail_at: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            prompts: Mutex::new(Vec::new()),
            fail_at,
        })
    }

    fn calls(&self) -> usize {
        self.prompts.lock().expect("prompt log").len()
    }

    /// The chunk text each call carried: the prompt's last turn, which the
    /// test closures always build from the chunk.
    fn chunks(&self) -> Vec<String> {
        self.prompts
            .lock()
            .expect("prompt log")
            .iter()
            .map(|prompt| {
                prompt
                    .messages
                    .last()
                    .map(|turn| turn.content.clone())
                    .unwrap_or_default()
            })
            .collect()
    }
}

#[async_trait]
impl TextModel for EchoModel {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError> {
        let mut log = self.prompts.lock().expect("prompt log");
        let index = log.len();
        log.push(prompt.clone());
        drop(log);
        if self.fail_at == Some(index) {
            return Err(TextModelError::Transport("chunk failed".to_owned()));
        }
        let chunk = prompt
            .messages
            .last()
            .map(|turn| turn.content.as_str())
            .unwrap_or_default();
        Ok(Completion::new(chunk, "echo"))
    }
}

#[test]
fn chunks_carry_whole_paragraphs_and_whole_fences_in_order() {
    let model = EchoModel::new(None);
    let out = pollster::block_on(model.complete_chunked(DOC, 60, |index, total, chunk| {
        Prompt::new(ModelTier::Fast)
            .system(format!("rewriting chunk {index} of {total}"))
            .user(chunk)
    }))
    .expect("every chunk completes");

    // The echoes reassemble to the document, byte for byte.
    assert_eq!(out, DOC);

    // Every prompt carried at most 60 chars of document, and no fence
    // crossed a prompt boundary.
    let chunks = model.chunks();
    assert!(
        chunks.len() > 1,
        "the document must actually split: {chunks:?}"
    );
    let mut offset = 0;
    for chunk in &chunks {
        assert!(chunk.chars().count() <= 60, "{chunk:?}");
        assert!(fences_balanced(chunk), "a fence crossed a chunk: {chunk:?}");
        assert_eq!(
            &DOC[offset..offset + chunk.len()],
            chunk,
            "chunks run in document order"
        );
        offset += chunk.len();
    }
    assert_eq!(offset, DOC.len());
    assert_eq!(chunks.concat(), DOC);
}

#[test]
fn empty_text_short_circuits_without_calling_the_model() {
    let model = EchoModel::new(None);
    let out = pollster::block_on(model.complete_chunked("", 32, |_, _, _| {
        panic!("the model must not be asked about an empty document");
    }))
    .expect("empty input is an empty answer");
    assert_eq!(out, "");
    assert_eq!(model.calls(), 0, "zero model calls for empty input");
}

#[test]
fn an_error_on_a_later_chunk_propagates_and_stops_the_run() {
    // Three paragraphs at a 20-char bound make three chunks; the second
    // call fails.
    let model = EchoModel::new(Some(1));
    let error = pollster::block_on(model.complete_chunked(
        "first paragraph\n\nsecond paragraph\n\nthird paragraph",
        20,
        |_, _, chunk| Prompt::new(ModelTier::Fast).user(chunk),
    ))
    .expect_err("the second chunk fails");
    assert_eq!(error, TextModelError::Transport("chunk failed".to_owned()));
    assert_eq!(model.calls(), 2, "the run stops at the failing chunk");
}

#[test]
fn the_prompt_closure_sees_each_index_and_the_total() {
    let model = EchoModel::new(None);
    let seen: Arc<Mutex<Vec<(usize, usize, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let out = pollster::block_on(model.complete_chunked(
        "first paragraph\n\nsecond paragraph\n\nthird paragraph",
        20,
        move |index, total, chunk| {
            log.lock()
                .expect("seen log")
                .push((index, total, chunk.to_owned()));
            Prompt::new(ModelTier::Fast).user(chunk)
        },
    ))
    .expect("every chunk completes");
    assert_eq!(
        out,
        "first paragraph\n\nsecond paragraph\n\nthird paragraph"
    );

    let seen = seen.lock().expect("seen log");
    assert_eq!(seen.len(), 3);
    for (position, (index, total, chunk)) in seen.iter().enumerate() {
        assert_eq!(*index, position, "indexes run 0, 1, 2");
        assert_eq!(*total, seen.len(), "total is the same on every call");
        assert!(!chunk.is_empty(), "the closure sees the chunk text");
    }
}

#[test]
fn a_whitespace_only_chunk_passes_through_without_a_model_call() {
    // The leading blank run cannot share a chunk with the 20-char
    // paragraph at this bound, so the splitter stands it alone; the
    // model is asked only about the paragraph, renumbered 0 of 1.
    let model = EchoModel::new(None);
    let seen: Arc<Mutex<Vec<(usize, usize, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let out = pollster::block_on(model.complete_chunked(
        "\n\n\nfirst paragraph body",
        20,
        move |index, total, chunk| {
            log.lock()
                .expect("seen log")
                .push((index, total, chunk.to_owned()));
            Prompt::new(ModelTier::Fast).user(chunk)
        },
    ))
    .expect("completes");
    assert_eq!(
        out, "\n\n\nfirst paragraph body",
        "the run reassembles untouched"
    );
    assert_eq!(model.calls(), 1, "the padding chunk cost no round trip");
    assert_eq!(
        *seen.lock().expect("seen log"),
        vec![(0, 1, "first paragraph body".to_owned())],
        "index and total count only the chunks the model saw"
    );
}

#[test]
fn the_extension_reaches_a_dyn_text_model() {
    // The blanket impl is for `M: TextModel + ?Sized`, so a `dyn TextModel`
    // — what a module holds as `Arc<dyn TextModel>` — gets
    // `complete_chunked` too.
    let model: Arc<dyn TextModel> = EchoModel::new(None);
    let out = pollster::block_on(model.complete_chunked("one", 10, |_, _, chunk| {
        Prompt::new(ModelTier::Fast).user(chunk)
    }))
    .expect("completes");
    assert_eq!(out, "one");
}

#[test]
#[should_panic(expected = "max_chars")]
fn a_zero_bound_panics_through_the_splitter() {
    let model: Arc<dyn TextModel> = EchoModel::new(None);
    let _ = pollster::block_on(model.complete_chunked("text", 0, |_, _, _| {
        unreachable!("the splitter panics before any prompt is built")
    }));
}

/// Whether every fence `chunk` opens also closes inside it: no fence
/// crosses a chunk boundary.
fn fences_balanced(chunk: &str) -> bool {
    let mut open: Option<(u8, usize)> = None;
    for line in chunk.lines() {
        if let Some((marker, count)) = open {
            if closes_fence(line.trim(), marker, count) {
                open = None;
            }
        } else if let Some((marker, count)) = opens_fence(line) {
            open = Some((marker, count));
        }
    }
    open.is_none()
}

/// The fence `line` opens, if any: three or more backticks or tildes after
/// leading whitespace — the local twin of the splitter's own rule.
fn opens_fence(line: &str) -> Option<(u8, usize)> {
    let stripped = line.trim_start().as_bytes();
    let marker = *stripped.first()?;
    if marker != b'`' && marker != b'~' {
        return None;
    }
    let count = stripped.iter().take_while(|&&byte| byte == marker).count();
    (count >= 3).then_some((marker, count))
}

/// Whether `trimmed` closes the fence opened with `marker` repeated
/// `count` times: a run of the same marker at least as long, no info
/// string.
fn closes_fence(trimmed: &str, marker: u8, count: usize) -> bool {
    let bytes = trimmed.as_bytes();
    bytes.len() >= count && bytes.iter().all(|&byte| byte == marker)
}
