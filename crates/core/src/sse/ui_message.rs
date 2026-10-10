//! The `Vercel` AI SDK v6 "UI message stream" (issue #860): the chunk
//! vocabulary and wire encoding a `useChat` frontend consumes, written
//! here so a harness route answers a browser chat the AI SDK parses
//! without a TypeScript build step on this side.
//!
//! The wire is plain Server-Sent Events — one `data:` line of JSON per
//! [`UiMessageChunk`], framed by [`SseEvent::encode`](crate::sse::SseEvent::encode),
//! the stream closed by a literal `data: [DONE]` — and the response names
//! its dialect with the [`UI_MESSAGE_STREAM_HEADER`] header set to
//! [`UI_MESSAGE_STREAM_VERSION`]. Chunk fields are the SDK's camelCase
//! `looseObject`s: a field the Rust side carries as `Option` is left off
//! the object entirely when `None`, never sent as `null`.
//!
//! [`UiMessageEncoder`] turns what this crate already streams into those
//! chunks while keeping the parts well-formed: a
//! [`TextDelta`] stream or a
//! [`ToolLoopEvent`] stream becomes a `start`, then
//! one step's `text-*` / `reasoning-*` / `tool-input-*` parts, a
//! `finish-step` per step and a closing `finish` — with part ids
//! (`text-0`, `reasoning-0`, `text-1`, …) assigned deterministically, so
//! the same run always encodes to the same bytes. The committed fixtures
//! under `tests/fixtures/ui-message-stream/v1` are that determinism made
//! checkable, on both sides of the language border.
//!
//! The stream adapters [`text_stream_chunks`] and [`tool_loop_chunks`]
//! wrap the two source streams end to end, and [`ui_message_response`]
//! answers a route with the encoded stream. Errors are masked by default
//! — [`MASKED_ERROR_TEXT`] on the wire, the detail in the log — the same
//! policy the problem+json answers take, for the same reason: provider
//! and transport text can quote a user's prompt straight back. A caller
//! that wants the detail on the wire pushes its own
//! [`UiMessageChunk::Error`].

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures_core::Stream;
use futures_util::StreamExt;
use http::{HeaderName, HeaderValue};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use crate::ports::{Clock, FinishReason, TextDelta, TextModelError};
use crate::sse::{SseEvent, SseResponse};
use crate::stream::BoxStream;
use crate::tool_loop::{ToolLoopError, ToolLoopEvent};

/// The response header that tells an AI SDK client which chunk dialect
/// this stream speaks.
pub const UI_MESSAGE_STREAM_HEADER: &str = "x-vercel-ai-ui-message-stream";

/// The only dialect this module writes.
pub const UI_MESSAGE_STREAM_VERSION: &str = "v1";

/// The end-of-stream marker [`ui_message_response`] appends after the
/// last chunk, and the last line of every fixture file.
const DONE_MARKER: &str = "[DONE]";

/// The error text a stream adapter puts in an
/// [`UiMessageChunk::Error`] when the real error is only logged. The
/// sentence the AI SDK answers with by default: a provider's own words
/// can quote a user's prompt back, so they go to the log, not the wire.
/// A caller that wants the detail on the wire emits its own
/// [`UiMessageChunk::Error`] instead of relying on the adapters.
pub const MASKED_ERROR_TEXT: &str = "An error occurred.";

/// Why a message ended, in the vocabulary the `finish` chunk carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiFinishReason {
    /// The model finished its answer on its own.
    Stop,
    /// The answer was cut off at its token ceiling.
    Length,
    /// The model ended its turn by asking for tool calls.
    ToolCalls,
    /// The provider withheld or truncated content under its own policy.
    ContentFilter,
    /// The message died in an error.
    Error,
    /// A reason this vocabulary does not name.
    Other,
}

impl UiFinishReason {
    /// The word the wire carries.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Length => "length",
            Self::ToolCalls => "tool-calls",
            Self::ContentFilter => "content-filter",
            Self::Error => "error",
            Self::Other => "other",
        }
    }
}

impl Serialize for UiFinishReason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl From<&FinishReason> for UiFinishReason {
    fn from(reason: &FinishReason) -> Self {
        match reason {
            FinishReason::Stop => Self::Stop,
            FinishReason::Length => Self::Length,
            FinishReason::ToolUse => Self::ToolCalls,
            FinishReason::ContentFilter => Self::ContentFilter,
            // `FinishReason` is non_exhaustive and the SDK's word for a
            // reason its vocabulary does not name is `other`.
            _ => Self::Other,
        }
    }
}

/// One chunk of a UI message stream — one `data:` line of JSON on the
/// wire. The variant names are the SDK's chunk types, the fields its
/// camelCase ones; an `Option` field is left out of the object when
/// `None`. Serialisation goes through a serde-derived mirror, with
/// [`Self::Data`] built by hand because its type tag is its own name.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum UiMessageChunk {
    /// Opens the message.
    Start {
        /// The id the client uses for the message it is building.
        message_id: Option<String>,
        /// Metadata the caller wants to ride on the message.
        message_metadata: Option<Value>,
    },
    /// Closes the message. Nothing goes on the wire after it.
    Finish {
        /// Why the message ended.
        finish_reason: Option<UiFinishReason>,
        /// Metadata the caller wants to ride on the message.
        message_metadata: Option<Value>,
    },
    /// Opens a step — one model call's worth of parts.
    StartStep,
    /// Closes the step the previous `start-step` opened.
    FinishStep,
    /// Opens the text part `id`.
    TextStart {
        /// The part's id, `text-0`, `text-1`, … from the encoder.
        id: String,
    },
    /// Grows the text part `id`.
    TextDelta {
        /// The part's id.
        id: String,
        /// The next run of text.
        delta: String,
    },
    /// Closes the text part `id`.
    TextEnd {
        /// The part's id.
        id: String,
    },
    /// Opens the reasoning part `id`.
    ReasoningStart {
        /// The part's id, `reasoning-0`, `reasoning-1`, … from the
        /// encoder.
        id: String,
    },
    /// Grows the reasoning part `id`.
    ReasoningDelta {
        /// The part's id.
        id: String,
        /// The next run of reasoning.
        delta: String,
    },
    /// Closes the reasoning part `id`.
    ReasoningEnd {
        /// The part's id.
        id: String,
    },
    /// Announces the tool call `tool_call_id`; its arguments follow as
    /// `tool-input-delta`s.
    ToolInputStart {
        /// The provider's id for the call.
        tool_call_id: String,
        /// The tool being called.
        tool_name: String,
    },
    /// Grows the arguments of the call `tool_call_id`.
    ToolInputDelta {
        /// The call's id.
        tool_call_id: String,
        /// The next piece of the arguments JSON.
        input_text_delta: String,
    },
    /// The call `tool_call_id` is complete, arguments and all.
    ToolInputAvailable {
        /// The call's id.
        tool_call_id: String,
        /// The tool that was called.
        tool_name: String,
        /// The parsed arguments object.
        input: Value,
    },
    /// The result of running the call `tool_call_id`.
    ToolOutputAvailable {
        /// The call's id.
        tool_call_id: String,
        /// The tool's output, as JSON.
        output: Value,
    },
    /// The call `tool_call_id` failed; the model was shown `error_text`.
    ToolOutputError {
        /// The call's id.
        tool_call_id: String,
        /// The error the model was shown.
        error_text: String,
    },
    /// A source the answer drew on, by URL.
    SourceUrl {
        /// The source's id.
        source_id: String,
        /// Where the source lives.
        url: String,
        /// A display name, where there is one.
        title: Option<String>,
    },
    /// A caller-defined `data-<name>` chunk: the type tag on the wire is
    /// the name joined to the prefix, which is why the enum serialises by
    /// hand.
    Data {
        /// The name after the `data-` prefix.
        name: String,
        /// An id, for a client that updates one data part in place.
        id: Option<String>,
        /// The payload, any JSON.
        data: Value,
        /// Whether the client should keep this only for the live stream
        /// and not persist it into the message.
        transient: Option<bool>,
    },
    /// The message died in an error. Nothing goes on the wire after it.
    Error {
        /// What went wrong, already scrubbed of anything that should not
        /// reach a client.
        error_text: String,
    },
    /// The message was aborted by the caller.
    Abort,
    /// Metadata for the message, mid-stream.
    MessageMetadata {
        /// The metadata.
        message_metadata: Value,
    },
}

impl UiMessageChunk {
    /// The chunk as the SSE event the wire carries: no `event:` name and
    /// no `id:` — the SDK's parser reads `data:` lines only — and the
    /// JSON on the single data line.
    ///
    /// # Panics
    ///
    /// Only if `serde_json` refuses to serialise the chunk's JSON — which
    /// these objects cannot provoke (every key is a string, every value a
    /// [`Value`]), so the `expect` documents an invariant rather than a
    /// reachable failure.
    #[must_use]
    pub fn to_sse_event(&self) -> SseEvent {
        SseEvent::new(serde_json::to_string(self).expect("a chunk serialises to JSON"))
    }
}

/// The wire shape of the chunks whose tag is the variant's own name,
/// derived: `serde` writes the kebab-case `type` tag first and the
/// camelCase fields after it, leaving every `None` out — the exact object
/// [`UiMessageChunk`] serialises to, borrowed so serialising copies
/// nothing but the output bytes. [`UiMessageChunk::Data`] stays outside
/// it: its tag is the caller's name, not a variant name.
#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum Wire<'a> {
    Start {
        #[serde(skip_serializing_if = "Option::is_none")]
        message_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message_metadata: Option<&'a Value>,
    },
    Finish {
        #[serde(skip_serializing_if = "Option::is_none")]
        finish_reason: Option<&'a UiFinishReason>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message_metadata: Option<&'a Value>,
    },
    StartStep,
    FinishStep,
    TextStart {
        id: &'a str,
    },
    TextDelta {
        id: &'a str,
        delta: &'a str,
    },
    TextEnd {
        id: &'a str,
    },
    ReasoningStart {
        id: &'a str,
    },
    ReasoningDelta {
        id: &'a str,
        delta: &'a str,
    },
    ReasoningEnd {
        id: &'a str,
    },
    ToolInputStart {
        tool_call_id: &'a str,
        tool_name: &'a str,
    },
    ToolInputDelta {
        tool_call_id: &'a str,
        input_text_delta: &'a str,
    },
    ToolInputAvailable {
        tool_call_id: &'a str,
        tool_name: &'a str,
        input: &'a Value,
    },
    ToolOutputAvailable {
        tool_call_id: &'a str,
        output: &'a Value,
    },
    ToolOutputError {
        tool_call_id: &'a str,
        error_text: &'a str,
    },
    SourceUrl {
        source_id: &'a str,
        url: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<&'a str>,
    },
    Error {
        error_text: &'a str,
    },
    Abort,
    MessageMetadata {
        message_metadata: &'a Value,
    },
}

impl<'a> From<&'a UiMessageChunk> for Wire<'a> {
    fn from(chunk: &'a UiMessageChunk) -> Self {
        match chunk {
            UiMessageChunk::Start {
                message_id,
                message_metadata,
            } => Self::Start {
                message_id: message_id.as_deref(),
                message_metadata: message_metadata.as_ref(),
            },
            UiMessageChunk::Finish {
                finish_reason,
                message_metadata,
            } => Self::Finish {
                finish_reason: finish_reason.as_ref(),
                message_metadata: message_metadata.as_ref(),
            },
            UiMessageChunk::StartStep => Self::StartStep,
            UiMessageChunk::FinishStep => Self::FinishStep,
            UiMessageChunk::TextStart { id } => Self::TextStart { id },
            UiMessageChunk::TextDelta { id, delta } => Self::TextDelta { id, delta },
            UiMessageChunk::TextEnd { id } => Self::TextEnd { id },
            UiMessageChunk::ReasoningStart { id } => Self::ReasoningStart { id },
            UiMessageChunk::ReasoningDelta { id, delta } => Self::ReasoningDelta { id, delta },
            UiMessageChunk::ReasoningEnd { id } => Self::ReasoningEnd { id },
            UiMessageChunk::ToolInputStart {
                tool_call_id,
                tool_name,
            } => Self::ToolInputStart {
                tool_call_id,
                tool_name,
            },
            UiMessageChunk::ToolInputDelta {
                tool_call_id,
                input_text_delta,
            } => Self::ToolInputDelta {
                tool_call_id,
                input_text_delta,
            },
            UiMessageChunk::ToolInputAvailable {
                tool_call_id,
                tool_name,
                input,
            } => Self::ToolInputAvailable {
                tool_call_id,
                tool_name,
                input,
            },
            UiMessageChunk::ToolOutputAvailable {
                tool_call_id,
                output,
            } => Self::ToolOutputAvailable {
                tool_call_id,
                output,
            },
            UiMessageChunk::ToolOutputError {
                tool_call_id,
                error_text,
            } => Self::ToolOutputError {
                tool_call_id,
                error_text,
            },
            UiMessageChunk::SourceUrl {
                source_id,
                url,
                title,
            } => Self::SourceUrl {
                source_id,
                url,
                title: title.as_deref(),
            },
            UiMessageChunk::Error { error_text } => Self::Error { error_text },
            UiMessageChunk::Abort => Self::Abort,
            UiMessageChunk::MessageMetadata { message_metadata } => {
                Self::MessageMetadata { message_metadata }
            }
            // Its tag is `data-<name>`, not a variant name: `Serialize`
            // builds this chunk's object by hand instead.
            UiMessageChunk::Data { .. } => unreachable!("Data never converts to a Wire chunk"),
        }
    }
}

impl Serialize for UiMessageChunk {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Data {
                name,
                id,
                data,
                transient,
            } => {
                let mut object = Map::new();
                object.insert("type".to_owned(), Value::String(format!("data-{name}")));
                if let Some(id) = id {
                    object.insert("id".to_owned(), Value::String(id.clone()));
                }
                object.insert("data".to_owned(), data.clone());
                if let Some(transient) = transient {
                    object.insert("transient".to_owned(), Value::Bool(*transient));
                }
                object.serialize(serializer)
            }
            other => Wire::from(other).serialize(serializer),
        }
    }
}

/// Folds what this crate streams into UI message chunks, keeping the
/// parts well-formed as it goes (issue #860).
///
/// The encoder is the piece that turns a flat delta stream into the
/// structured shape a chat frontend keeps in state: the message opens
/// with `start` and `start-step` on its first output, whatever kind of
/// output that is; text and reasoning open, grow and close as parts —
/// `text-0`, `reasoning-0`, `text-1`, … ids assigned in order, so the
/// same run always encodes to the same bytes — and opening one closes the
/// other, so a step's parts never interleave. A tool call becomes
/// `tool-input-start`, then `tool-input-delta`s, then
/// `tool-input-available`; a step closes with `finish-step`; the message
/// closes with `finish`.
///
/// Feed it one stream, through one of:
///
/// - [`text_delta`](Self::text_delta) — a plain
///   [`TextDelta`] stream, whose `Finish` ends the
///   message with the reason it names;
/// - [`tool_loop_event`](Self::tool_loop_event) — a
///   [`ToolLoopEvent`] stream, where a delta
///   `Finish` inside the loop only closes the open parts and remembers
///   its reason (the loop carries on), and
///   [`ToolLoopEvent::Done`] ends the
///   message;
/// - [`error`](Self::error) — ends the message with an `error` chunk;
/// - [`finish`](Self::finish) — ends a message whose source stopped
///   without either, so the client's stream closes framed regardless.
///
/// After the first end, every method answers an empty `Vec`: nothing is
/// emitted after the message is over.
#[derive(Debug, Default, Clone)]
pub struct UiMessageEncoder {
    /// The `messageId` the opening `start` carries, when the caller set
    /// one.
    message_id: Option<String>,
    /// Whether `start` and `start-step` have gone out: exactly once, on
    /// the first output of the message.
    started: bool,
    /// Whether a step is open — a `start-step` without its
    /// `finish-step` — which is what makes the first delta after a
    /// finished step open a new one.
    step_open: bool,
    /// The next text and reasoning part ids.
    next_text: usize,
    next_reasoning: usize,
    /// The open text and reasoning parts' ids, when one of each is open.
    open_text: Option<String>,
    open_reasoning: Option<String>,
    /// The tool-call ids whose `tool-input-start` went out, by
    /// [`TextDelta`] index: the address its argument
    /// deltas need. An entry is removed when its call finishes. The tool
    /// name is not remembered — the finish carries its own, and nothing
    /// between a call's start and its finish names it again.
    started_calls: HashMap<usize, String>,
    /// The reason the message ends with: the last `Finish` seen, from a
    /// plain stream's own or the loop's most recent step.
    finish_reason: Option<UiFinishReason>,
    /// Whether the message is over. Set by [`Self::finish`],
    /// [`Self::error`] and a plain stream's `Finish`; nothing goes out
    /// after it.
    finished: bool,
}

impl UiMessageEncoder {
    /// An encoder for a message with no id: the opening `start` carries
    /// no `messageId`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An encoder whose opening `start` names the message `message_id` —
    /// the id a client that persists the message will store it under.
    #[must_use]
    pub fn with_message_id(message_id: impl Into<String>) -> Self {
        Self {
            message_id: Some(message_id.into()),
            ..Self::default()
        }
    }

    /// Folds one delta of a plain [`TextDelta`] stream.
    /// The stream's `Finish` ends the message: open parts close, the open
    /// step gets its `finish-step`, and the `finish` chunk names the
    /// reason.
    pub fn text_delta(&mut self, delta: &TextDelta) -> Vec<UiMessageChunk> {
        if self.finished {
            return Vec::new();
        }
        let TextDelta::Finish { reason, .. } = delta else {
            return self.delta_chunks(delta);
        };
        let mut out = Vec::new();
        self.ensure_started(&mut out);
        self.close_open_parts(&mut out);
        self.finish_reason = Some(UiFinishReason::from(reason));
        self.close_step(&mut out);
        out.push(UiMessageChunk::Finish {
            finish_reason: self.finish_reason.clone(),
            message_metadata: None,
        });
        self.finished = true;
        out
    }

    /// Folds one event of a streamed tool loop. A delta `Finish` inside
    /// the loop only closes the open parts and remembers its reason —
    /// the loop goes on to run tools or call the model again, and the
    /// message ends at `Done` or an `error`, not here. A delta for a new
    /// step — any content delta once the previous step's `finish-step`
    /// went out — opens the step with a `start-step` first. A
    /// [`ToolResult`]'s output rides as JSON where it parses, as one JSON
    /// string where it does not, and as a `tool-output-error` where the
    /// tool failed.
    ///
    /// [`ToolResult`]: crate::ToolResult
    pub fn tool_loop_event(&mut self, event: &ToolLoopEvent) -> Vec<UiMessageChunk> {
        if self.finished {
            return Vec::new();
        }
        match event {
            ToolLoopEvent::Delta { delta, .. } => match delta {
                TextDelta::Finish { reason, .. } => {
                    let mut out = Vec::new();
                    self.ensure_started(&mut out);
                    self.close_open_parts(&mut out);
                    self.finish_reason = Some(UiFinishReason::from(reason));
                    out
                }
                delta => self.delta_chunks(delta),
            },
            ToolLoopEvent::ToolResult { call, result, .. } => {
                let mut out = Vec::new();
                self.ensure_started(&mut out);
                out.push(if result.is_error {
                    UiMessageChunk::ToolOutputError {
                        tool_call_id: call.id.clone(),
                        error_text: result.content.clone(),
                    }
                } else {
                    UiMessageChunk::ToolOutputAvailable {
                        tool_call_id: call.id.clone(),
                        output: output_value(&result.content),
                    }
                });
                out
            }
            ToolLoopEvent::StepFinished { .. } => {
                let mut out = Vec::new();
                self.ensure_started(&mut out);
                self.close_open_parts(&mut out);
                self.close_step(&mut out);
                out
            }
            ToolLoopEvent::Done(_) => self.finish(),
        }
    }

    /// Ends the message with an `error` chunk. The text given goes on the
    /// wire as it is handed over — pass [`MASKED_ERROR_TEXT`] when its
    /// source is a provider or a transport, and log the detail instead,
    /// the way [`text_stream_chunks`] and [`tool_loop_chunks`] do. A
    /// caller that wants the detail on the wire puts it here itself.
    pub fn error(&mut self, error_text: &str) -> Vec<UiMessageChunk> {
        let mut out = Vec::new();
        if self.finished {
            return out;
        }
        self.ensure_started(&mut out);
        self.close_open_parts(&mut out);
        out.push(UiMessageChunk::Error {
            error_text: error_text.to_owned(),
        });
        self.finished = true;
        out
    }

    /// Ends the message the way a stream that stopped without a `Finish`
    /// or an error still should: open parts close, an open step gets its
    /// `finish-step`, and `finish` carries the last reason a `Finish`
    /// recorded — no field at all when none did. This is also how
    /// [`ToolLoopEvent::Done`] ends a loop.
    pub fn finish(&mut self) -> Vec<UiMessageChunk> {
        let mut out = Vec::new();
        if self.finished {
            return out;
        }
        self.ensure_started(&mut out);
        self.close_open_parts(&mut out);
        self.close_step(&mut out);
        out.push(UiMessageChunk::Finish {
            finish_reason: self.finish_reason.clone(),
            message_metadata: None,
        });
        self.finished = true;
        out
    }

    /// The chunks one non-terminal delta produces. Text and reasoning
    /// alternate through parts — opening one closes the other; tool calls
    /// run `start` → `delta`… → `available`; usage is nothing, because
    /// the UI shows the stream, not the meter. The message and step open
    /// only when a chunk is about to land: a delta that produces nothing
    /// (usage, a dangling argument chunk) leaves the stream untouched.
    fn delta_chunks(&mut self, delta: &TextDelta) -> Vec<UiMessageChunk> {
        let mut out = Vec::new();
        match delta {
            TextDelta::Text(text) => {
                self.open_step(&mut out);
                self.close_open_reasoning(&mut out);
                let id = self.open_text_part(&mut out);
                out.push(UiMessageChunk::TextDelta {
                    id,
                    delta: text.clone(),
                });
            }
            TextDelta::Reasoning(text) => {
                self.open_step(&mut out);
                self.close_open_text(&mut out);
                let id = self.open_reasoning_part(&mut out);
                out.push(UiMessageChunk::ReasoningDelta {
                    id,
                    delta: text.clone(),
                });
            }
            TextDelta::ToolCallStarted { index, id, name } => {
                self.open_step(&mut out);
                self.close_open_parts(&mut out);
                self.started_calls.insert(*index, id.clone());
                out.push(UiMessageChunk::ToolInputStart {
                    tool_call_id: id.clone(),
                    tool_name: name.clone(),
                });
            }
            TextDelta::ToolCallArguments { index, chunk } => {
                // An argument chunk for a call whose start never went out
                // has no part to grow: dropped, not invented.
                let tool_call_id = self.started_calls.get(index).cloned();
                if let Some(tool_call_id) = tool_call_id {
                    self.open_step(&mut out);
                    out.push(UiMessageChunk::ToolInputDelta {
                        tool_call_id,
                        input_text_delta: chunk.clone(),
                    });
                }
            }
            TextDelta::ToolCallFinished { index, call } => {
                let remembered = self.started_calls.remove(index).is_some();
                self.open_step(&mut out);
                if !remembered {
                    // The call's start never arrived (an adapter that
                    // skips starts): announce it before the input lands,
                    // so the client sees a whole call either way.
                    self.close_open_parts(&mut out);
                    out.push(UiMessageChunk::ToolInputStart {
                        tool_call_id: call.id.clone(),
                        tool_name: call.name.clone(),
                    });
                }
                out.push(UiMessageChunk::ToolInputAvailable {
                    tool_call_id: call.id.clone(),
                    tool_name: call.name.clone(),
                    input: call.arguments.clone(),
                });
            }
            // Usage is the meter, not the message: the UI stream carries
            // nothing for it. A `Finish` is terminal and ends differently
            // per source kind; the callers handle it before this runs.
            TextDelta::Usage { .. } | TextDelta::Finish { .. } => {}
        }
        out
    }

    /// Emits `start` then `start-step` on the first output of the
    /// message, whatever kind of output it is: the client needs the
    /// message and its first step before any part lands.
    fn ensure_started(&mut self, out: &mut Vec<UiMessageChunk>) {
        if self.started {
            return;
        }
        self.started = true;
        self.step_open = true;
        out.push(UiMessageChunk::Start {
            message_id: self.message_id.clone(),
            message_metadata: None,
        });
        out.push(UiMessageChunk::StartStep);
    }

    /// The step content is about to land in: `start` and `start-step` on
    /// the message's first output, `start-step` alone when a loop's next
    /// step begins after the previous one's `finish-step` went out.
    fn open_step(&mut self, out: &mut Vec<UiMessageChunk>) {
        self.ensure_started(out);
        if !self.step_open {
            self.step_open = true;
            out.push(UiMessageChunk::StartStep);
        }
    }

    /// The open text part's id, opening one — and announcing it — if
    /// there is none.
    fn open_text_part(&mut self, out: &mut Vec<UiMessageChunk>) -> String {
        if let Some(id) = &self.open_text {
            return id.clone();
        }
        let id = format!("text-{}", self.next_text);
        self.next_text += 1;
        self.open_text = Some(id.clone());
        out.push(UiMessageChunk::TextStart { id: id.clone() });
        id
    }

    /// The open reasoning part's id, symmetric with
    /// [`Self::open_text_part`].
    fn open_reasoning_part(&mut self, out: &mut Vec<UiMessageChunk>) -> String {
        if let Some(id) = &self.open_reasoning {
            return id.clone();
        }
        let id = format!("reasoning-{}", self.next_reasoning);
        self.next_reasoning += 1;
        self.open_reasoning = Some(id.clone());
        out.push(UiMessageChunk::ReasoningStart { id: id.clone() });
        id
    }

    fn close_open_text(&mut self, out: &mut Vec<UiMessageChunk>) {
        if let Some(id) = self.open_text.take() {
            out.push(UiMessageChunk::TextEnd { id });
        }
    }

    fn close_open_reasoning(&mut self, out: &mut Vec<UiMessageChunk>) {
        if let Some(id) = self.open_reasoning.take() {
            out.push(UiMessageChunk::ReasoningEnd { id });
        }
    }

    /// Closes whichever parts are open, in the order they opened: a part
    /// never ends after another kind began.
    fn close_open_parts(&mut self, out: &mut Vec<UiMessageChunk>) {
        self.close_open_text(out);
        self.close_open_reasoning(out);
    }

    /// Closes the open step, where there is one. `start-step` and
    /// `finish-step` travel in pairs, or the SDK sees a step that never
    /// ended.
    fn close_step(&mut self, out: &mut Vec<UiMessageChunk>) {
        if self.step_open {
            self.step_open = false;
            out.push(UiMessageChunk::FinishStep);
        }
    }
}

/// A tool's output as the JSON the chunk carries: the content parsed
/// where it *is* JSON, the content as one JSON string where it is not —
/// an executor answers in text, and the wire wants a value either way.
fn output_value(content: &str) -> Value {
    serde_json::from_str(content).unwrap_or_else(|_| Value::String(content.to_owned()))
}

/// The `unfold` state behind [`text_stream_chunks`] and
/// [`tool_loop_chunks`]: the source, boxed so the state stays `Unpin`;
/// the encoder method folding each item; the chunks the last item
/// produced that have not been yielded yet; and the `done` flag that
/// stops the pulls once the source has ended or failed. One source item
/// per consumer poll, and only when the encoder answered the last one
/// with nothing — the adapter never reads ahead, so dropping the chunk
/// stream drops the source, which is the cancellation the response body
/// carries.
struct Chunker<S, T> {
    source: Pin<Box<S>>,
    emit: fn(&mut UiMessageEncoder, &T) -> Vec<UiMessageChunk>,
    encoder: UiMessageEncoder,
    pending: std::vec::IntoIter<UiMessageChunk>,
    done: bool,
}

/// Streams `source` through the encoder as UI message chunks — the shape
/// [`ui_message_response`] takes. One source item per consumer poll; the
/// source's error ends the message with [`MASKED_ERROR_TEXT`] on the
/// wire (the detail is logged), and a source that stops without a
/// `Finish` still gets its closing `finish`.
fn chunk_stream<S, T, E>(
    source: S,
    emit: fn(&mut UiMessageEncoder, &T) -> Vec<UiMessageChunk>,
) -> BoxStream<'static, UiMessageChunk>
where
    S: Stream<Item = Result<T, E>> + Send + 'static,
    T: 'static,
    E: std::fmt::Display + 'static,
{
    Box::pin(futures_util::stream::unfold(
        Chunker {
            source: Box::pin(source),
            emit,
            encoder: UiMessageEncoder::new(),
            pending: Vec::new().into_iter(),
            done: false,
        },
        |mut chunker| async move {
            loop {
                if let Some(chunk) = chunker.pending.next() {
                    return Some((chunk, chunker));
                }
                if chunker.done {
                    return None;
                }
                match chunker.source.next().await {
                    Some(Ok(item)) => {
                        chunker.pending = (chunker.emit)(&mut chunker.encoder, &item).into_iter();
                    }
                    Some(Err(error)) => {
                        // The source's error is the end of the message,
                        // and its text stays here in the log: provider
                        // and transport text can quote a user's prompt
                        // back, so the wire gets the fixed sentence.
                        tracing::warn!(
                            error = %error,
                            "ui message stream failed; the wire carries the masked text"
                        );
                        chunker.pending = chunker.encoder.error(MASKED_ERROR_TEXT).into_iter();
                        chunker.done = true;
                    }
                    None => {
                        // The source stopped without a `Finish` or an
                        // error; close the message anyway, so the
                        // client's stream ends framed.
                        chunker.pending = chunker.encoder.finish().into_iter();
                        chunker.done = true;
                    }
                }
            }
        },
    ))
}

/// Streams a [`TextDelta`] completion as UI message
/// chunks (issue #860): the deltas a route already holds —
/// [`stream_owned`](crate::stream_owned)'s output, say — as the chunks a
/// chat frontend parses. The source's error masks to
/// [`MASKED_ERROR_TEXT`]; a source that ends without a `Finish` still
/// ends the message framed.
pub fn text_stream_chunks<S>(deltas: S) -> BoxStream<'static, UiMessageChunk>
where
    S: Stream<Item = Result<TextDelta, TextModelError>> + Send + 'static,
{
    chunk_stream(deltas, UiMessageEncoder::text_delta)
}

/// Streams a [`ToolLoopEvent`] loop as UI message
/// chunks: every step's parts as they arrive, each executed call's
/// output, and a `finish` carrying the loop's last reason at `Done`.
/// The source's error masks to [`MASKED_ERROR_TEXT`]; a source that ends
/// without a `Done` still ends the message framed.
pub fn tool_loop_chunks<S>(events: S) -> BoxStream<'static, UiMessageChunk>
where
    S: Stream<Item = Result<ToolLoopEvent, ToolLoopError>> + Send + 'static,
{
    chunk_stream(events, UiMessageEncoder::tool_loop_event)
}

/// Answers a route with a UI message stream (issue #860): every chunk
/// encoded and written as it arrives, the `data: [DONE]` marker after
/// the last, the [`UI_MESSAGE_STREAM_HEADER`] dialect header on top of
/// the SSE headers, and the heartbeat, cancellation contract and
/// `ResponseStream` handle of [`SseResponse`] underneath.
#[must_use]
pub fn ui_message_response<S>(chunks: S, clock: Arc<dyn Clock>) -> SseResponse
where
    S: Stream<Item = UiMessageChunk> + Send + 'static,
{
    let events = chunks
        .map(|chunk| chunk.to_sse_event())
        .chain(futures_util::stream::iter([SseEvent::new(DONE_MARKER)]));
    SseResponse::new(events, clock).header(
        HeaderName::from_static(UI_MESSAGE_STREAM_HEADER),
        HeaderValue::from_static(UI_MESSAGE_STREAM_VERSION),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolCall;
    use serde_json::{Value, json};

    /// The chunk's wire JSON, through the real `Serialize` path.
    fn wire(chunk: &UiMessageChunk) -> Value {
        serde_json::to_value(chunk).expect("a chunk serialises")
    }

    /// The chunk type tags in order — the stream's shape.
    fn kinds(chunks: &[UiMessageChunk]) -> Vec<String> {
        chunks
            .iter()
            .map(|chunk| {
                wire(chunk)["type"]
                    .as_str()
                    .map(str::to_owned)
                    .expect("every chunk types")
            })
            .collect()
    }

    #[test]
    fn finish_reasons_map_onto_the_wire_words() {
        assert_eq!(UiFinishReason::from(&FinishReason::Stop).as_str(), "stop");
        assert_eq!(
            UiFinishReason::from(&FinishReason::Length).as_str(),
            "length"
        );
        assert_eq!(
            UiFinishReason::from(&FinishReason::ToolUse).as_str(),
            "tool-calls"
        );
        assert_eq!(
            UiFinishReason::from(&FinishReason::ContentFilter).as_str(),
            "content-filter"
        );
        assert_eq!(
            UiFinishReason::from(&FinishReason::Other("weird".to_owned())).as_str(),
            "other",
            "an unknown reason, and any future one, is `other`"
        );
    }

    #[test]
    fn text_and_reasoning_parts_take_turns() {
        let mut encoder = UiMessageEncoder::new();
        let mut chunks = encoder.text_delta(&TextDelta::Reasoning("hmm".to_owned()));
        chunks.extend(encoder.text_delta(&TextDelta::Text("hi".to_owned())));
        chunks.extend(encoder.text_delta(&TextDelta::Reasoning("again".to_owned())));
        let kinds: Vec<String> = chunks
            .iter()
            .map(|chunk| {
                let object = wire(chunk);
                format!(
                    "{}:{}",
                    object["type"].as_str().expect("typed"),
                    object.get("id").and_then(Value::as_str).unwrap_or("-")
                )
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                "start:-",
                "start-step:-",
                "reasoning-start:reasoning-0",
                "reasoning-delta:reasoning-0",
                "reasoning-end:reasoning-0",
                "text-start:text-0",
                "text-delta:text-0",
                "text-end:text-0",
                "reasoning-start:reasoning-1",
                "reasoning-delta:reasoning-1",
            ],
            "opening one part closes the other; ids count per kind: {chunks:?}"
        );
    }

    #[test]
    fn nothing_is_emitted_after_the_message_ends() {
        let mut encoder = UiMessageEncoder::new();
        encoder.text_delta(&TextDelta::Finish {
            reason: FinishReason::Stop,
            model: "fake".to_owned(),
        });
        assert!(
            encoder
                .text_delta(&TextDelta::Text("late".to_owned()))
                .is_empty()
        );
        assert!(encoder.error("late").is_empty());
        assert!(encoder.finish().is_empty());

        // An error ends a message the same way: the message opens first
        // if it had not, then the error lands, then nothing more.
        let mut encoder = UiMessageEncoder::new();
        assert_eq!(
            kinds(&encoder.error("nope")),
            vec!["start", "start-step", "error"]
        );
        assert!(encoder.finish().is_empty());
        assert!(
            encoder
                .tool_loop_event(&ToolLoopEvent::Delta {
                    step: 0,
                    delta: TextDelta::Text("late".to_owned()),
                })
                .is_empty()
        );
    }

    #[test]
    fn an_argument_chunk_for_a_call_that_never_started_is_dropped() {
        let mut encoder = UiMessageEncoder::new();
        let chunks = encoder.text_delta(&TextDelta::ToolCallArguments {
            index: 3,
            chunk: "{\"q\":".to_owned(),
        });
        assert!(chunks.is_empty(), "no start, no part to grow: {chunks:?}");
    }

    #[test]
    fn a_finished_call_without_a_start_announces_itself_first() {
        let mut encoder = UiMessageEncoder::new();
        let chunks = encoder.text_delta(&TextDelta::ToolCallFinished {
            index: 0,
            call: ToolCall::new("call-9", "lookup", json!({"q": "x"})),
        });
        assert_eq!(
            kinds(&chunks),
            vec![
                "start",
                "start-step",
                "tool-input-start",
                "tool-input-available"
            ]
        );
        assert_eq!(
            wire(&chunks[2])["toolCallId"],
            json!("call-9"),
            "the announcement carries the finished call's own id"
        );
    }

    #[test]
    fn a_tool_output_is_json_where_it_parses_and_a_string_where_it_does_not() {
        assert_eq!(output_value("{\"a\": 1}"), json!({"a": 1}));
        assert_eq!(output_value("ran lookup"), json!("ran lookup"));
    }
}
