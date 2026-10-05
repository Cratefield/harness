//! The `TextModel` port (issue #429): a text completion asked for by
//! **tier**, never by vendor. A module says [`ModelTier::Fast`] for its
//! drafting and [`ModelTier::Strong`] for its judging; which provider
//! answers each tier is the venture's wiring, decided once in `src/lib.rs`
//! and invisible to the module (ADR 0002). [`RoutingTextModel`] is the seam,
//! the way [`RoutingPush`](crate::RoutingPush) is for transports.
//!
//! **Tools arrived in issue #665; streaming stays out of scope.** A
//! [`Prompt`] may carry [`ToolSpec`]s and a [`ToolChoice`]; a
//! [`Completion`] may carry the [`ToolCall`]s the model asked for; and a
//! [`Turn`] can quote an assistant's requested calls and the
//! [`ToolResult`]s a user turn carries back. An adapter that can carry
//! tools says so through [`TextModel::supports`]; one that cannot is never
//! asked — [`RoutingTextModel`] and [`run_tool_loop`](crate::run_tool_loop)
//! refuse a tools-bearing prompt up front with
//! [`TextModelError::Unsupported`]. Embeddings live on the separate
//! [`Embedder`](crate::Embedder) port (issue #561), never here.
//!
//! **Structured output builds on the schema a prompt already carries.**
//! [`TextModelExt`](crate::TextModelExt) wraps `complete` with
//! `complete_json`/`complete_as`: it checks the schema on the tool loop's
//! subset, asks for it through [`Prompt::json_schema`], validates the
//! answer, and allows one repair retry — so a caller holds a value that
//! conforms or a [`TextModelError::SchemaViolation`], never a partial one.
//!
//! Streaming is the deliberate omission, not a gap:
//! `response_to_worker` buffers a whole harness response to
//! `MAX_RESPONSE_BUFFER` (1 MiB, `crates/runtime-cloudflare/src/lib.rs`),
//! so a streamed completion has nowhere to arrive on this runtime — a port
//! that promised deltas would be a port the Workers twin could not keep.
//! A tool loop still is one request and one buffered answer per step.
//!
//! **Image input arrived in issue #628.** A [`Turn`] may carry [`Part`]s —
//! text and images in order — built with [`Turn::user_parts`]; a text-only
//! turn is unchanged. An adapter that can carry images says so through
//! [`Capability::Images`], and the router, the tool loop and every adapter
//! call [`Prompt::check_images`] **before** any network call, so an
//! over-limit prompt is refused locally rather than paid for. Adapters
//! encode with [`encode_image`], needing no base64 dependency of their own.
//!
//! There is no outcome enum on this port, unlike [`Mailer`](crate::Mailer)
//! and [`Push`](crate::Push), and that is deliberate: a completion has no
//! "delivered but not configured" middle state — either text came back or
//! nothing did. The unwired answer is therefore
//! [`TextModelError::NotConfigured`], an error variant the caller can match,
//! so a module that cannot degrade without its model fails loudly instead of
//! silently producing nothing.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::http::MAX_RESPONSE_BYTES;

/// The token ceiling a [`Prompt`] starts with: enough for a drafted reply,
/// small enough that a forgotten `.max_tokens(..)` cannot turn into a run
/// away bill. Explicit in the type so "how long can the answer get" is a
/// field a caller can read, not an adapter's private default.
pub const DEFAULT_MAX_TOKENS: u32 = 1024;

/// The most images one [`Prompt`] may carry (issue #628): four, inside the
/// vendors' own per-request range. [`Prompt::check_images`] refuses more.
pub const MAX_PROMPT_IMAGES: usize = 4;

/// The most base64 bytes one image may encode to (issue #628): 3.75 MiB,
/// the vendors' per-image ceiling. [`encoded_image_len`] gives a raw
/// image's encoded length; [`Prompt::check_images`] refuses any over it.
pub const MAX_IMAGE_ENCODED_BYTES: usize = 3_932_160;

/// The most base64 bytes **all** of a prompt's images may encode to
/// together (issue #628): 4 MiB, the same [`MAX_RESPONSE_BYTES`] ceiling
/// the [`HttpClient`](crate::HttpClient) port puts on a response body.
/// [`Prompt::check_images`] refuses a total over it.
pub const MAX_PROMPT_IMAGE_ENCODED_BYTES: usize = MAX_RESPONSE_BYTES;

/// Which class of model a completion asks for — a **tier**, never a vendor
/// or a model name. A venture maps each tier onto a provider in its own
/// wiring, and can move drafting from one vendor to another without
/// touching a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelTier {
    /// The cheap, quick class: drafting, summarising, classifying.
    Fast,
    /// The best-available class: judging, long synthesis, the one call
    /// where quality is the point.
    Strong,
}

impl ModelTier {
    /// The name used in errors and logs.
    pub fn name(&self) -> &'static str {
        match self {
            ModelTier::Fast => "fast",
            ModelTier::Strong => "strong",
        }
    }
}

impl std::fmt::Display for ModelTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Who is speaking in a [`Turn`]. A prompt is a conversation, and a
/// provider needs to know which side each part came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The human (or module) side of the conversation.
    User,
    /// The model's side, as a previous completion was recorded.
    Assistant,
}

impl Role {
    /// The name used in errors and logs.
    pub fn name(&self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Assistant => "assistant",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Something a [`TextModel`] adapter may or may not be able to do beyond a
/// plain completion. A port whose shape grows over time needs a way for the
/// router to ask "can the model behind this tier actually do this" before a
/// caller wastes a request on one that cannot.
///
/// `#[non_exhaustive]`: today the capabilities are [`Self::Tools`] and
/// [`Self::Images`], and the next one — a provider-native structured
/// output — should not be a breaking change for every `match` a caller
/// writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Capability {
    /// The adapter carries tools: a prompt's [`Prompt::tools`] reach the
    /// provider, and the answer may carry [`Completion::tool_calls`]. An
    /// adapter that does not implement this is never asked to.
    Tools,
    /// The adapter carries images: a prompt's [`Part::Image`]s reach the
    /// provider. An adapter without vision is refused with
    /// [`TextModelError::Unsupported`], never sent an image to drop.
    Images,
}

impl Capability {
    /// The name used in errors and logs.
    pub fn name(&self) -> &'static str {
        match self {
            Capability::Tools => "tools",
            Capability::Images => "images",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A tool the model is offered: a name, the instruction a model reads when
/// deciding whether to call it, and the JSON Schema of the arguments object
/// the call must carry (issue #665).
///
/// `#[non_exhaustive]`: build one with [`ToolSpec::new`] rather than a
/// struct literal, the same rule [`Prompt`] and [`Completion`] follow —
/// what a tool declares grows, and it should not break every caller.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// A JSON Schema (draft 2020-12) of the arguments object a call must
    /// provide. [`run_tool_loop`](crate::run_tool_loop) validates it up
    /// front and then validates every call's arguments against it, and
    /// refuses a schema using a keyword it cannot honour rather than
    /// silently skipping the check.
    pub parameters: Value,
}

impl ToolSpec {
    /// A tool named `name`, described by `description`, taking arguments
    /// conforming to `parameters`.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>, parameters: Value) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters,
        }
    }
}

/// How the model should choose among a prompt's [`Prompt::tools`]: freely,
/// not at all, mandatorily, or pinned to one named tool (issue #665).
///
/// `#[non_exhaustive]`: the wire protocols have more ways to steer this
/// ("any tool but this one", a per-tool probability), and adding one must
/// not break every caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolChoice {
    /// The model decides whether to call a tool or answer directly.
    Auto,
    /// The model must answer without calling a tool.
    None,
    /// The model must call some tool, whichever it picks.
    Required,
    /// The model must call the tool with this name.
    Tool(String),
}

/// One tool call the model asked for: which call it is, which tool, and the
/// arguments the model produced (issue #665). The arguments are exactly
/// what the model sent — [`run_tool_loop`](crate::run_tool_loop) validates
/// them against the tool's schema before any executor sees them.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

impl ToolCall {
    /// A call identified by `id` asking for the tool named `name` with
    /// `arguments`.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>, arguments: Value) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arguments,
        }
    }
}

/// The result of running one [`ToolCall`], fed back to the model as
/// context (issue #665). A tool-level failure is a [`ToolResult::error`],
/// not a failed loop: the model is given the error text and may try again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    /// The [`ToolCall::id`] this answers.
    pub tool_call_id: String,
    pub content: String,
    /// Whether `content` is a tool error the model should see rather than a
    /// successful result.
    pub is_error: bool,
}

impl ToolResult {
    /// A successful result for the call `tool_call_id`.
    #[must_use]
    pub fn ok(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            tool_call_id: tool_call_id.into(),
            content: content.into(),
            is_error: false,
        }
    }

    /// A failed result for the call `tool_call_id`: `content` is the error
    /// the model is shown so it can recover.
    #[must_use]
    pub fn error(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            tool_call_id: tool_call_id.into(),
            content: content.into(),
            is_error: true,
        }
    }
}

/// The media type of an image a [`Part`] carries (issue #628): the closed
/// set the providers accept, so a caller picks one rather than handing the
/// provider a bare string to validate. `#[non_exhaustive]`, so a `match`
/// carries a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageMediaType {
    /// `image/png`.
    Png,
    /// `image/jpeg`.
    Jpeg,
    /// `image/gif`.
    Gif,
    /// `image/webp`.
    Webp,
}

impl ImageMediaType {
    /// The MIME type a provider expects on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ImageMediaType::Png => "image/png",
            ImageMediaType::Jpeg => "image/jpeg",
            ImageMediaType::Gif => "image/gif",
            ImageMediaType::Webp => "image/webp",
        }
    }
}

/// One piece of a [`Turn`]: text, or an image with its media type and raw
/// bytes (issue #628). A parts-bearing turn carries them **in order**;
/// `#[non_exhaustive]`, so a part is built with [`Part::text`] and
/// [`Part::image`] rather than a struct literal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Part {
    /// A run of text.
    Text(String),
    /// An image: its media type and its raw (undecoded) bytes. Adapters
    /// encode with [`encode_image`] when they put it on the wire.
    Image {
        media_type: ImageMediaType,
        bytes: Vec<u8>,
    },
}

impl Part {
    /// A text part.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Part::Text(text.into())
    }

    /// An image part of `media_type` carrying the raw `bytes`.
    #[must_use]
    pub fn image(media_type: ImageMediaType, bytes: impl Into<Vec<u8>>) -> Self {
        Part::Image {
            media_type,
            bytes: bytes.into(),
        }
    }
}

/// The standard, padded base64 encoding of an image's raw bytes (issue
/// #628) — the form every provider expects for inline image data. Here so
/// an adapter needs no base64 dependency of its own.
#[must_use]
pub fn encode_image(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The length of [`encode_image`]'s output for `raw_len` raw bytes (issue
/// #628): `4 * ceil(raw_len / 3)`, padding included. Pure arithmetic, so
/// [`Prompt::check_images`] can size an image without encoding it — to
/// refuse an over-limit image before the allocation, not after.
#[must_use]
pub const fn encoded_image_len(raw_len: usize) -> usize {
    raw_len.div_ceil(3) * 4
}

/// One message of the conversation a [`Prompt`] carries.
///
/// `#[non_exhaustive]`: a turn grew its tool fields in issue #665 and its
/// image [`Part`]s in issue #628 and will grow again, so it is built with
/// [`Turn::user`], [`Turn::user_parts`], [`Turn::assistant`],
/// [`Turn::assistant_tool_calls`] or [`Turn::tool_results`] rather than a
/// struct literal.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Turn {
    pub role: Role,
    pub content: String,
    /// The turn's content as ordered [`Part`]s, where it carries any
    /// (issue #628). When non-empty it **is** the whole content, in order,
    /// and [`content`](Self::content) is empty; a text-only turn keeps it
    /// empty so it serialises exactly as before images existed.
    pub parts: Vec<Part>,
    /// The calls an assistant turn asked for. Carried on a
    /// [`Role::Assistant`] turn; empty on every other turn.
    pub tool_calls: Vec<ToolCall>,
    /// The results a user turn carries back for the previous assistant
    /// turn's calls. Carried on a [`Role::User`] turn; empty otherwise.
    pub tool_results: Vec<ToolResult>,
}

impl Turn {
    /// A turn spoken by the [`Role::User`] side.
    #[must_use]
    pub fn user(content: impl Into<String>) -> Self {
        Turn {
            role: Role::User,
            content: content.into(),
            parts: Vec::new(),
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
        }
    }

    /// A user turn carrying `parts` — text and images in order — with an
    /// empty [`content`](Self::content) (issue #628). The way a prompt
    /// sends an image: providers expect text and image in one message, so
    /// the parts travel together rather than across two turns.
    #[must_use]
    pub fn user_parts(parts: impl IntoIterator<Item = Part>) -> Self {
        Turn {
            role: Role::User,
            content: String::new(),
            parts: parts.into_iter().collect(),
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
        }
    }

    /// A turn spoken by the [`Role::Assistant`] side — a previous
    /// completion, quoted back as context.
    #[must_use]
    pub fn assistant(content: impl Into<String>) -> Self {
        Turn {
            role: Role::Assistant,
            content: content.into(),
            parts: Vec::new(),
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
        }
    }

    /// An assistant turn that asked to call `calls`. `content` is the text
    /// the model wrote alongside the calls (often empty).
    #[must_use]
    pub fn assistant_tool_calls(content: impl Into<String>, calls: Vec<ToolCall>) -> Self {
        Turn {
            role: Role::Assistant,
            content: content.into(),
            parts: Vec::new(),
            tool_calls: calls,
            tool_results: Vec::new(),
        }
    }

    /// A user turn carrying the `results` of the previous assistant turn's
    /// tool calls — the shape a provider expects the tool answers back in.
    #[must_use]
    pub fn tool_results(results: Vec<ToolResult>) -> Self {
        Turn {
            role: Role::User,
            content: String::new(),
            parts: Vec::new(),
            tool_calls: Vec::new(),
            tool_results: results,
        }
    }
}

/// One completion request: the tier asked for, the conversation so far, and
/// what the caller will accept back.
///
/// `#[non_exhaustive]`: build one with [`Prompt::new`] and the builder
/// methods rather than a struct literal. What a v2 port has to carry —
/// tools, temperature, a stop sequence — should not be a breaking change
/// for every caller, the same way [`Message`](crate::Message) is built.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Prompt {
    pub tier: ModelTier,
    pub system: Option<String>,
    pub messages: Vec<Turn>,
    /// A JSON Schema (draft 2020-12) the answer should conform to. When set,
    /// the adapter asks its provider for structured output; a provider that
    /// honours it fills [`Completion::json`], and one that cannot leaves the
    /// raw answer in [`Completion::text`] with `json` `None`, rather than
    /// failing the call.
    pub json_schema: Option<Value>,
    pub max_tokens: u32,
    /// The tools the model may call. Empty by default: a prompt that sends
    /// no tools behaves exactly as it did before tools existed, and an
    /// adapter is never asked to carry tools it was not given.
    pub tools: Vec<ToolSpec>,
    /// How the model should choose among [`Prompt::tools`]. `None` leaves
    /// the choice to the provider's own default; the builder sets it.
    pub tool_choice: Option<ToolChoice>,
}

impl Prompt {
    /// An empty prompt for `tier`: no system prompt, no messages, no
    /// schema, no tools, and [`DEFAULT_MAX_TOKENS`] as the ceiling.
    /// Everything else is a builder method.
    #[must_use]
    pub fn new(tier: ModelTier) -> Self {
        Self {
            tier,
            system: None,
            messages: Vec::new(),
            json_schema: None,
            max_tokens: DEFAULT_MAX_TOKENS,
            tools: Vec::new(),
            tool_choice: None,
        }
    }

    /// Offers the model one more tool it may call.
    #[must_use]
    pub fn tool(mut self, tool: ToolSpec) -> Self {
        self.tools.push(tool);
        self
    }

    /// Offers the model every tool in `tools`.
    #[must_use]
    pub fn tools(mut self, tools: impl IntoIterator<Item = ToolSpec>) -> Self {
        self.tools.extend(tools);
        self
    }

    /// Steers how the model chooses among the offered tools.
    #[must_use]
    pub fn tool_choice(mut self, tool_choice: ToolChoice) -> Self {
        self.tool_choice = Some(tool_choice);
        self
    }

    /// The standing instruction the model answers under.
    #[must_use]
    pub fn system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Appends a [`Turn::user`] — the common case, a one-message prompt.
    #[must_use]
    pub fn user(mut self, content: impl Into<String>) -> Self {
        self.messages.push(Turn::user(content));
        self
    }

    /// Appends a [`Turn::user_parts`] — a user message carrying text and
    /// images in order (issue #628).
    #[must_use]
    pub fn user_parts(mut self, parts: impl IntoIterator<Item = Part>) -> Self {
        self.messages.push(Turn::user_parts(parts));
        self
    }

    /// Appends a [`Turn::assistant`].
    #[must_use]
    pub fn assistant(mut self, content: impl Into<String>) -> Self {
        self.messages.push(Turn::assistant(content));
        self
    }

    /// Appends a whole turn, for a conversation built elsewhere.
    #[must_use]
    pub fn turn(mut self, turn: Turn) -> Self {
        self.messages.push(turn);
        self
    }

    /// Asks for structured output conforming to `schema`; a successful
    /// completion then carries the parsed value in [`Completion::json`].
    #[must_use]
    pub fn json_schema(mut self, schema: Value) -> Self {
        self.json_schema = Some(schema);
        self
    }

    /// The token ceiling for the answer.
    #[must_use]
    pub fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    /// Whether any turn carries an image [`Part`] (issue #628). The router
    /// and the tool loop gate [`Capability::Images`] on this, exactly as
    /// they gate [`Capability::Tools`] on [`Prompt::tools`].
    #[must_use]
    pub fn has_images(&self) -> bool {
        self.messages.iter().any(|turn| {
            turn.parts
                .iter()
                .any(|part| matches!(part, Part::Image { .. }))
        })
    }

    /// Refuses a prompt whose images exceed a bound (issue #628), without
    /// encoding anything: the count against [`MAX_PROMPT_IMAGES`], each
    /// image's [`encoded_image_len`] against [`MAX_IMAGE_ENCODED_BYTES`],
    /// and their sum against [`MAX_PROMPT_IMAGE_ENCODED_BYTES`].
    ///
    /// # Errors
    ///
    /// [`TextModelError::ImageLimit`], naming which bound was crossed:
    /// [`ImageLimit::TooMany`], [`ImageLimit::ImageTooLarge`] (with the
    /// 0-based index among the prompt's images) or
    /// [`ImageLimit::TotalTooLarge`].
    pub fn check_images(&self) -> Result<(), TextModelError> {
        let count = self
            .messages
            .iter()
            .flat_map(|turn| &turn.parts)
            .filter(|part| matches!(part, Part::Image { .. }))
            .count();
        if count > MAX_PROMPT_IMAGES {
            return Err(TextModelError::ImageLimit(ImageLimit::TooMany { count }));
        }

        let mut total: usize = 0;
        let mut index: usize = 0;
        for turn in &self.messages {
            for part in &turn.parts {
                let Part::Image { bytes, .. } = part else {
                    continue;
                };
                let encoded_bytes = encoded_image_len(bytes.len());
                if encoded_bytes > MAX_IMAGE_ENCODED_BYTES {
                    return Err(TextModelError::ImageLimit(ImageLimit::ImageTooLarge {
                        index,
                        encoded_bytes,
                    }));
                }
                total = total.saturating_add(encoded_bytes);
                index += 1;
            }
        }
        if total > MAX_PROMPT_IMAGE_ENCODED_BYTES {
            return Err(TextModelError::ImageLimit(ImageLimit::TotalTooLarge {
                encoded_bytes: total,
            }));
        }
        Ok(())
    }
}

/// A completed completion: the text, the model that answered (a provider
/// identifier, for the log line), and the token usage.
///
/// The two token counts have a fixed relationship: [`Completion::input_tokens`]
/// is the **total** prompt tokens the provider processed, and
/// [`Completion::cached_input_tokens`] — where the provider reports one —
/// is the subset of that total served from the provider's own prompt
/// cache. A caller costing a completion never subtracts; the total already
/// includes the cached part.
///
/// `#[non_exhaustive]` for the same reason [`Prompt`] is: what a provider
/// reports back grows, and it should not break every caller.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Completion {
    pub text: String,
    /// The parsed answer, when the prompt carried a
    /// [`Prompt::json_schema`]. `None` when it did not, or the provider's
    /// answer could not be parsed — in which case `text` still holds what
    /// came back.
    pub json: Option<Value>,
    pub model: String,
    /// The total prompt tokens the provider processed, cached tokens
    /// included — a provider that reports caching reports them alongside
    /// the uncached remainder, not inside it. The discount question is
    /// [`Completion::cached_input_tokens`], never a smaller total here.
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// The subset of [`Completion::input_tokens`] the provider served from
    /// its own prompt cache, where the provider reports one. `None` when it
    /// does not: an absent report and a reported zero mean different things
    /// (a vendor that does not do caching versus a cache miss), so the
    /// option is never collapsed.
    pub cached_input_tokens: Option<u64>,
    /// The tools the model asked to call. Empty for a plain answer, and
    /// empty for a prompt that offered no tools.
    pub tool_calls: Vec<ToolCall>,
}

impl Completion {
    /// A completion with just the text and the model that wrote it; the
    /// usage, parsed JSON and tool calls are builder methods.
    #[must_use]
    pub fn new(text: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            json: None,
            model: model.into(),
            input_tokens: 0,
            output_tokens: 0,
            cached_input_tokens: None,
            tool_calls: Vec::new(),
        }
    }

    /// The tools the model asked to call, in the order it named them.
    #[must_use]
    pub fn tool_calls(mut self, tool_calls: Vec<ToolCall>) -> Self {
        self.tool_calls = tool_calls;
        self
    }

    /// The parsed structured answer, for a prompt that asked for one.
    #[must_use]
    pub fn json(mut self, json: Value) -> Self {
        self.json = Some(json);
        self
    }

    /// The token counts the provider reported.
    #[must_use]
    pub fn usage(mut self, input_tokens: u64, output_tokens: u64) -> Self {
        self.input_tokens = input_tokens;
        self.output_tokens = output_tokens;
        self
    }

    /// The subset of the input tokens the provider served from its own
    /// prompt cache, where the provider reports one.
    /// [`Completion::input_tokens`] stays the total, cached included.
    #[must_use]
    pub fn cached_input_tokens(mut self, cached_input_tokens: u64) -> Self {
        self.cached_input_tokens = Some(cached_input_tokens);
        self
    }
}

/// Which image bound a [`Prompt`] crossed (issue #628): the count, one
/// image's encoded size, or the whole prompt's. Carries only sizes and
/// indices — never user content — so it is safe in a log line as-is.
///
/// `#[non_exhaustive]`: another bound should not break every `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageLimit {
    /// The prompt carries more than [`MAX_PROMPT_IMAGES`] images.
    TooMany { count: usize },
    /// The image at 0-based `index` among the prompt's images encodes to
    /// more than [`MAX_IMAGE_ENCODED_BYTES`] base64 bytes.
    ImageTooLarge { index: usize, encoded_bytes: usize },
    /// The prompt's images encode to more than
    /// [`MAX_PROMPT_IMAGE_ENCODED_BYTES`] base64 bytes together.
    TotalTooLarge { encoded_bytes: usize },
}

impl std::fmt::Display for ImageLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooMany { count } => write!(
                f,
                "a prompt may carry at most {MAX_PROMPT_IMAGES} images, but this one carries {count}"
            ),
            Self::ImageTooLarge {
                index,
                encoded_bytes,
            } => write!(
                f,
                "image {index} encodes to {encoded_bytes} bytes, over the \
                 {MAX_IMAGE_ENCODED_BYTES}-byte per-image ceiling"
            ),
            Self::TotalTooLarge { encoded_bytes } => write!(
                f,
                "the prompt's images encode to {encoded_bytes} bytes, over the \
                 {MAX_PROMPT_IMAGE_ENCODED_BYTES}-byte total"
            ),
        }
    }
}

/// Completion failures.
///
/// [`NotConfigured`](Self::NotConfigured) sits on the **error** enum here,
/// unlike [`SendOutcome::NotConfigured`](crate::SendOutcome) and
/// [`PushOutcome::NotConfigured`](crate::PushOutcome): a completion has no
/// "delivered but not configured" middle state, so an unwired tier is an
/// error the caller matches, not an outcome it inspects.
///
/// `Transient` deliberately carries **only** `retry_after`, where
/// [`PushError::Transient`](crate::PushError) also carries a message: with
/// no provider text of its own there is nothing to scrub, and provider text
/// belongs on [`Rejected`](Self::Rejected) and [`Transport`](Self::Transport).
///
/// The two variants that carry provider text are sanitized in `Display`,
/// the same way [`PushError`](crate::PushError)'s and
/// [`MailError`](crate::MailError)'s are (issue #235). What an adapter wraps
/// is the provider's own words, and a prompt is exactly the kind of value
/// that rides back in them — a drafting module quotes a customer's note, and
/// the provider's `4xx` quotes it straight back. `Display` therefore runs it
/// through [`crate::logging::scrub_text`]; `Debug` still shows the raw
/// string for tests.
///
/// `#[non_exhaustive]`: a port's failure set grows with its shape, and
/// [`Unsupported`](Self::Unsupported) is exactly such a growth — a caller
/// that matches the variants it knows and treats anything else as a
/// transport failure should not have to recompile when one is added.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TextModelError {
    /// The tier asked for has no adapter — the venture did not wire it.
    /// Nothing is wrong with the prompt: a module may degrade, the way it
    /// degrades on a `NotConfigured` mailer, and
    /// [`RoutingTextModel`] answers this for every tier it has no
    /// adapter for.
    NotConfigured,
    /// The provider refused the request (a `4xx`), or refused the prompt's
    /// content or schema; not retryable without a change.
    Rejected(String),
    /// A transient failure (a `5xx`, a `429`, a transport error): retry
    /// later, and not before `retry_after` when the provider named one.
    /// Carries no message — provider text belongs on
    /// [`Rejected`](Self::Rejected) and [`Transport`](Self::Transport).
    Transient { retry_after: Option<Duration> },
    /// The request never completed as a conversation — the adapter could
    /// not reach the provider, or the answer did not survive the hop.
    Transport(String),
    /// The model behind this tier cannot do what the prompt asked for —
    /// a prompt carrying [`Prompt::tools`] or image [`Part`]s reached an
    /// adapter whose [`TextModel::supports`] is false for
    /// [`Capability::Tools`] or [`Capability::Images`], so the adapter was
    /// never called. A fixed sentence, never provider text, so there is
    /// nothing to scrub.
    Unsupported(Capability),
    /// The schema itself cannot be honoured: it uses a JSON Schema keyword
    /// the built-in validator does not implement (a `$ref`, a `pattern`,
    /// an `if`), or is malformed. This is a **caller bug** — the schema was
    /// written by the caller, not the model — so the model was never
    /// called. Raised by
    /// [`TextModelExt::complete_json`](crate::TextModelExt::complete_json)
    /// before the first request.
    InvalidSchema(String),
    /// The model's answer did not conform to the required schema, after the
    /// one repair retry
    /// [`TextModelExt::complete_json`](crate::TextModelExt::complete_json)
    /// allows. Carries only the schema path and reason the answer failed
    /// (for example `the property "price" is invalid: …`) — **never the
    /// model's own output**, which may hold the personal data the schema
    /// was there to structure.
    SchemaViolation(String),
    /// The prompt's images crossed a bound [`Prompt::check_images`]
    /// enforces: too many, one too large, or too large together.
    ImageLimit(ImageLimit),
}

impl std::fmt::Display for TextModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::NotConfigured => f.write_str("no text model is wired for this tier"),
            Self::Rejected(message) => write!(f, "completion rejected: {}", scrub(message)),
            Self::Transient { .. } => f.write_str("completion failed, retryable"),
            Self::Transport(message) => {
                write!(f, "completion transport failed: {}", scrub(message))
            }
            Self::Unsupported(capability) => {
                write!(f, "the text model does not support {capability}")
            }
            Self::InvalidSchema(reason) => {
                write!(f, "the JSON schema cannot be honoured: {}", scrub(reason))
            }
            Self::SchemaViolation(reason) => write!(
                f,
                "the model's answer did not match the schema: {}",
                scrub(reason)
            ),
            Self::ImageLimit(limit) => write!(f, "the prompt's images exceed a limit: {limit}"),
        }
    }
}

impl std::error::Error for TextModelError {}

impl TextModelError {
    /// How long the provider asked the caller to wait, where it said. An
    /// [`Unsupported`](Self::Unsupported) capability is not a back-off: no
    /// wait makes a model grow a capability it lacks.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            TextModelError::Transient { retry_after } => *retry_after,
            _ => None,
        }
    }
}

/// Completes a prompt, over whichever provider the venture wired for the
/// [`Prompt::tier`] it was asked for. An adapter serves any tier it is
/// configured for (typically one); [`RoutingTextModel`] dispatches between
/// the adapters a venture configured.
#[async_trait]
pub trait TextModel: Send + Sync {
    /// Completes `prompt`.
    ///
    /// [`Prompt::json_schema`] is a request: an adapter whose provider
    /// cannot honour structured output answers with plain text in
    /// [`Completion::text`] and `None` in [`Completion::json`], rather than
    /// failing the call.
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError>;

    /// Whether this adapter can do `capability` for a prompt routed to
    /// `tier`. Defaults to `false`: a model that has not opted in is
    /// refused a tools-bearing prompt by [`RoutingTextModel`] and
    /// [`run_tool_loop`](crate::run_tool_loop) before it is ever called,
    /// rather than sent a request it would silently drop the tools from.
    /// An adapter that carries [`Capability::Tools`] or
    /// [`Capability::Images`] overrides this to answer `true` for it.
    ///
    /// `tier` is the router's own routing key, not the adapter's: an
    /// adapter serves whatever tier it was wired for and is free to ignore
    /// it — an adapter only honours `tier` if the same deployment could be
    /// wired for two tiers with different capabilities. The parameter is
    /// on the method so a caller never has to ask the router which model a
    /// tier holds just to ask what it can do.
    fn supports(&self, _tier: ModelTier, _capability: Capability) -> bool {
        false
    }
}

/// Dispatches by [`Prompt::tier`] to the adapter a venture configured for
/// that tier, so venture code holds one `Arc<dyn TextModel>` and never
/// matches on the tier or the vendor itself (ADR 0002). The router lives
/// above the adapters, in core — the same place
/// [`RoutingPush`](crate::RoutingPush) does, and for the same reason
/// (ADR 0015).
///
/// This is the seam that lets a venture put drafting on one vendor and an
/// independent judge on another without either module knowing.
///
/// A tier with no adapter is [`TextModelError::NotConfigured`] —
/// deliberately not [`TextModelError::Rejected`]: nothing is wrong with the
/// prompt, the venture simply did not wire that tier.
///
/// The router also enforces capability agreement (issue #665): a prompt
/// that carries [`Prompt::tools`] is refused with
/// [`TextModelError::Unsupported`] before a tier that does not report
/// [`Capability::Tools`] for that tier is called, so a venture can assert
/// once at compose time — `router.supports(ModelTier::Strong,
/// Capability::Tools)` — that the tier it routed tools to can carry them.
/// [`RoutingTextModel::supports`] answers for the single routed tier: the
/// adapter wired for `tier`, or `false` when that tier is unwired. It is
/// deliberately **not** an aggregate over every wired tier: a prompt goes
/// to exactly one tier, so what matters is that tier's answer, and a
/// strong-tier judge that cannot carry tools must not make a fast-tier
/// drafting model look incapable.
///
/// The same agreement covers images (issue #628): a prompt carrying a
/// [`Part::Image`] is refused with [`TextModelError::Unsupported`] before a
/// tier that does not report [`Capability::Images`] is called, and an
/// over-limit prompt by [`Prompt::check_images`] before the tier is looked
/// up at all.
#[derive(Default, Clone)]
pub struct RoutingTextModel {
    fast: Option<Arc<dyn TextModel>>,
    strong: Option<Arc<dyn TextModel>>,
}

impl RoutingTextModel {
    /// A router with no adapters: every tier is `NotConfigured`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The adapter for [`ModelTier::Fast`].
    #[must_use]
    pub fn fast(mut self, model: Arc<dyn TextModel>) -> Self {
        self.fast = Some(model);
        self
    }

    /// The adapter for [`ModelTier::Strong`].
    #[must_use]
    pub fn strong(mut self, model: Arc<dyn TextModel>) -> Self {
        self.strong = Some(model);
        self
    }

    /// The adapter that serves `tier`, if one is configured.
    #[must_use]
    pub fn route_for(&self, tier: ModelTier) -> Option<&Arc<dyn TextModel>> {
        match tier {
            ModelTier::Fast => self.fast.as_ref(),
            ModelTier::Strong => self.strong.as_ref(),
        }
    }
}

impl std::fmt::Debug for RoutingTextModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingTextModel")
            .field("fast", &self.fast.is_some())
            .field("strong", &self.strong.is_some())
            .finish()
    }
}

#[async_trait]
impl TextModel for RoutingTextModel {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError> {
        // An over-limit image prompt is refused before anything is routed:
        // the limits are about the request a provider would be handed, so
        // they hold whatever tier answers.
        prompt.check_images()?;
        match self.route_for(prompt.tier) {
            Some(model) => {
                // A tools-bearing prompt to a model that cannot carry tools
                // is refused here, not silently sent with the tools
                // dropped: the caller asked for something the wiring cannot
                // honour, and a fabricated plain answer would hide that.
                if !prompt.tools.is_empty() && !model.supports(prompt.tier, Capability::Tools) {
                    return Err(TextModelError::Unsupported(Capability::Tools));
                }
                // The same rule for images: a prompt carrying one to a
                // model without vision is refused, never sent with the image
                // silently dropped.
                if prompt.has_images() && !model.supports(prompt.tier, Capability::Images) {
                    return Err(TextModelError::Unsupported(Capability::Images));
                }
                model.complete(prompt).await
            }
            None => Err(TextModelError::NotConfigured),
        }
    }

    fn supports(&self, tier: ModelTier, capability: Capability) -> bool {
        // The routed tier's own answer, and `false` for an unwired tier:
        // nothing is wired to do anything. A prompt goes to one tier, so
        // this is the tier that must be able to carry the capability — not
        // an aggregate over the tiers the router happens to hold.
        self.route_for(tier)
            .is_some_and(|model| model.supports(tier, capability))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // ModelTier, Role, and the wire form

    #[test]
    fn a_tier_and_a_role_round_trip_through_json() {
        for tier in [ModelTier::Fast, ModelTier::Strong] {
            let json = serde_json::to_string(&tier).expect("serialises");
            let back: ModelTier = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(tier, back);
        }
        for role in [Role::User, Role::Assistant] {
            let json = serde_json::to_string(&role).expect("serialises");
            let back: Role = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(role, back);
        }
    }

    #[test]
    fn the_wire_form_is_snake_case() {
        // The point of `rename_all`: the persisted name is the prose name,
        // so a config file reads `"strong"`, not `"Strong"`.
        assert_eq!(serde_json::to_value(ModelTier::Strong).unwrap(), "strong");
        assert_eq!(serde_json::to_value(Role::User).unwrap(), "user");
    }

    #[test]
    fn the_tier_names_itself_for_logs_and_errors() {
        assert_eq!(ModelTier::Fast.name(), "fast");
        assert_eq!(ModelTier::Strong.to_string(), "strong");
        assert_eq!(Role::Assistant.name(), "assistant");
        assert_eq!(Role::User.to_string(), "user");
    }

    // -----------------------------------------------------------------
    // Prompt and Completion builders

    #[test]
    fn a_prompt_starts_empty_and_builds_up() {
        let prompt = Prompt::new(ModelTier::Fast);
        assert_eq!(prompt.tier, ModelTier::Fast);
        assert_eq!(prompt.system, None);
        assert!(prompt.messages.is_empty());
        assert_eq!(prompt.json_schema, None);
        assert_eq!(prompt.max_tokens, DEFAULT_MAX_TOKENS);
        assert_eq!(DEFAULT_MAX_TOKENS, 1024);

        let prompt = prompt
            .system("Draft the reply.")
            .user("Hello")
            .assistant("Hi there")
            .turn(Turn::user("And again"))
            .json_schema(serde_json::json!({ "type": "object" }))
            .max_tokens(256);

        assert_eq!(prompt.system.as_deref(), Some("Draft the reply."));
        assert_eq!(
            prompt.messages,
            vec![
                Turn::user("Hello"),
                Turn::assistant("Hi there"),
                Turn::user("And again"),
            ]
        );
        assert_eq!(
            prompt.json_schema,
            Some(serde_json::json!({ "type": "object" }))
        );
        assert_eq!(prompt.max_tokens, 256);
    }

    #[test]
    fn a_completion_starts_with_text_and_model_and_builds_up() {
        let completion = Completion::new("the answer", "vendor-1");
        assert_eq!(completion.text, "the answer");
        assert_eq!(completion.model, "vendor-1");
        assert_eq!(completion.json, None);
        assert_eq!(completion.input_tokens, 0);
        assert_eq!(completion.output_tokens, 0);

        let completion = completion
            .json(serde_json::json!({ "reply": "the answer" }))
            .usage(12, 34);
        assert_eq!(
            completion.json,
            Some(serde_json::json!({ "reply": "the answer" }))
        );
        assert_eq!(completion.input_tokens, 12);
        assert_eq!(completion.output_tokens, 34);
    }

    #[test]
    fn cached_input_tokens_defaults_to_absent_and_never_shrinks_the_total() {
        // A vendor that says nothing about caching stays `None` — a
        // reported zero (a cache miss) and an absent report (a vendor
        // without caching) are different facts.
        let completion = Completion::new("the answer", "vendor-1");
        assert_eq!(completion.cached_input_tokens, None);

        // The builder records the cache read without shrinking the total:
        // `input_tokens` is what the vendor processed, cached included.
        let completion = Completion::new("the answer", "vendor-1")
            .usage(17, 5)
            .cached_input_tokens(9);
        assert_eq!(completion.input_tokens, 17);
        assert_eq!(completion.cached_input_tokens, Some(9));
    }

    // -----------------------------------------------------------------
    // TextModelError

    #[test]
    fn display_sanitizes_the_provider_text() {
        // Issue #235. The text an adapter wraps is the provider's own
        // words, and a drafting prompt quotes whatever a user wrote: what
        // the provider echoes back must not survive into a log line or a
        // dead-letter row carrying its URLs, tokens or addresses.
        let error = TextModelError::Rejected(
            "provider 400 for https://api.example.test/v1/complete?token=secret-abcdef".to_owned(),
        );
        let text = error.to_string();
        assert!(text.contains("completion rejected"), "{text}");
        assert!(!text.contains("secret-abcdef"), "{text}");
        assert!(text.contains("?[redacted]"), "{text}");

        let error = TextModelError::Transport("timeout quoting alice@example.test".to_owned());
        let text = error.to_string();
        assert!(text.contains("completion transport failed"), "{text}");
        assert!(!text.contains('@'), "{text}");

        // `Debug` still shows the raw string for a failing test to read.
        assert!(format!("{error:?}").contains("alice@example.test"));
    }

    #[test]
    fn transient_says_retryable_and_carries_no_text_to_scrub() {
        // `Transient` has no message field on purpose — the fixed sentence
        // is the whole `Display`, and a provider's words would be an
        // unsanitised leak by construction.
        let error = TextModelError::Transient {
            retry_after: Some(Duration::from_secs(30)),
        };
        assert_eq!(error.to_string(), "completion failed, retryable");
    }

    #[test]
    fn transient_carries_an_optional_retry_after() {
        let throttled = TextModelError::Transient {
            retry_after: Some(Duration::from_secs(30)),
        };
        assert_eq!(throttled.retry_after(), Some(Duration::from_secs(30)));
        let plain = TextModelError::Transient { retry_after: None };
        assert_eq!(plain.retry_after(), None);
        assert_eq!(TextModelError::NotConfigured.retry_after(), None);
        assert_eq!(
            TextModelError::Rejected("422".to_owned()).retry_after(),
            None,
            "a rejection is not a back-off"
        );
        assert_eq!(
            TextModelError::Transport("timed out".to_owned()).retry_after(),
            None
        );
    }

    #[test]
    fn not_configured_names_the_missing_wiring() {
        assert_eq!(
            TextModelError::NotConfigured.to_string(),
            "no text model is wired for this tier"
        );
    }

    #[test]
    fn the_structured_output_failures_name_themselves_and_never_back_off() {
        let invalid =
            TextModelError::InvalidSchema("the `pattern` keyword is not supported".to_owned());
        assert_eq!(
            invalid.to_string(),
            "the JSON schema cannot be honoured: the `pattern` keyword is not supported"
        );
        let violation =
            TextModelError::SchemaViolation("the property \"price\" is invalid".to_owned());
        assert!(
            violation.to_string().contains("did not match the schema"),
            "{violation}"
        );
        assert_eq!(invalid.retry_after(), None);
        assert_eq!(violation.retry_after(), None);
    }

    // -----------------------------------------------------------------
    // RoutingTextModel

    struct Recording {
        label: &'static str,
        tools: bool,
        images: bool,
        seen: std::sync::atomic::AtomicUsize,
    }

    impl Recording {
        /// A model that reports no capability — the default for an adapter
        /// that has not opted into tools.
        fn new(label: &'static str) -> Arc<Self> {
            Arc::new(Self {
                label,
                tools: false,
                images: false,
                seen: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        /// A model that reports [`Capability::Tools`].
        fn tool_capable(label: &'static str) -> Arc<Self> {
            Arc::new(Self {
                label,
                tools: true,
                images: false,
                seen: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        /// A model that reports [`Capability::Images`].
        fn image_capable(label: &'static str) -> Arc<Self> {
            Arc::new(Self {
                label,
                tools: false,
                images: true,
                seen: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn count(&self) -> usize {
            self.seen.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl TextModel for Recording {
        async fn complete(&self, _prompt: &Prompt) -> Result<Completion, TextModelError> {
            self.seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Completion::new("recorded", self.label))
        }

        fn supports(&self, _tier: ModelTier, capability: Capability) -> bool {
            (capability == Capability::Tools && self.tools)
                || (capability == Capability::Images && self.images)
        }
    }

    #[test]
    fn the_router_dispatches_by_tier() {
        let fast = Recording::new("fast-vendor");
        let strong = Recording::new("strong-vendor");
        let router = RoutingTextModel::new()
            .fast(fast.clone())
            .strong(strong.clone());

        let completion =
            pollster::block_on(router.complete(&Prompt::new(ModelTier::Fast).user("hi"))).unwrap();
        assert_eq!(
            completion.model, "fast-vendor",
            "the fast tier reached its adapter"
        );
        let completion =
            pollster::block_on(router.complete(&Prompt::new(ModelTier::Strong).user("hi")))
                .unwrap();
        assert_eq!(
            completion.model, "strong-vendor",
            "the strong tier reached its own, different adapter"
        );
        assert_eq!(fast.count(), 1);
        assert_eq!(strong.count(), 1);
    }

    #[test]
    fn a_tier_with_no_adapter_is_not_configured_not_rejected() {
        let router = RoutingTextModel::new().fast(Recording::new("fast-vendor"));
        let error = pollster::block_on(router.complete(&Prompt::new(ModelTier::Strong).user("hi")))
            .unwrap_err();
        assert_eq!(error, TextModelError::NotConfigured);
        assert!(router.route_for(ModelTier::Strong).is_none());
    }

    #[test]
    fn an_empty_router_is_not_configured_for_every_tier() {
        let router = RoutingTextModel::new();
        for tier in [ModelTier::Fast, ModelTier::Strong] {
            let error =
                pollster::block_on(router.complete(&Prompt::new(tier).user("hi"))).unwrap_err();
            assert_eq!(error, TextModelError::NotConfigured);
            assert!(router.route_for(tier).is_none());
        }
    }

    #[test]
    fn debug_prints_which_tiers_are_wired_and_nothing_else() {
        // The adapters themselves are `Arc<dyn TextModel>` and have no
        // meaningful `Debug`; printing their presence is the whole report.
        let router = RoutingTextModel::new().fast(Recording::new("fast-vendor"));
        let printed = format!("{router:?}");
        assert!(printed.contains("RoutingTextModel"), "{printed}");
        assert!(printed.contains("fast: true"), "{printed}");
        assert!(printed.contains("strong: false"), "{printed}");
    }

    // -----------------------------------------------------------------
    // Tools (issue #665)

    #[test]
    fn a_capability_names_itself_for_logs_and_errors() {
        assert_eq!(Capability::Tools.name(), "tools");
        assert_eq!(Capability::Tools.to_string(), "tools");
        assert_eq!(Capability::Images.name(), "images");
        assert_eq!(Capability::Images.to_string(), "images");
    }

    #[test]
    fn a_tool_spec_carries_its_name_description_and_schema() {
        let tool = ToolSpec::new(
            "lookup",
            "Look a thing up.",
            serde_json::json!({ "type": "object" }),
        );
        assert_eq!(tool.name, "lookup");
        assert_eq!(tool.description, "Look a thing up.");
        assert_eq!(tool.parameters, serde_json::json!({ "type": "object" }));
    }

    #[test]
    fn a_tool_call_and_result_round_trip_their_fields() {
        let call = ToolCall::new("call-1", "lookup", serde_json::json!({ "q": "x" }));
        assert_eq!(call.id, "call-1");
        assert_eq!(call.name, "lookup");
        assert_eq!(call.arguments, serde_json::json!({ "q": "x" }));

        let ok = ToolResult::ok("call-1", "the answer");
        assert_eq!(ok.tool_call_id, "call-1");
        assert_eq!(ok.content, "the answer");
        assert!(!ok.is_error);

        let error = ToolResult::error("call-1", "it broke");
        assert!(error.is_error);
        assert_eq!(error.content, "it broke");
    }

    #[test]
    fn a_turn_can_quote_tool_calls_and_carry_results_back() {
        let call = ToolCall::new("call-1", "lookup", serde_json::json!({}));
        let assistant = Turn::assistant_tool_calls("thinking", vec![call.clone()]);
        assert_eq!(assistant.role, Role::Assistant);
        assert_eq!(assistant.content, "thinking");
        assert_eq!(assistant.tool_calls, vec![call]);
        assert!(assistant.tool_results.is_empty());

        let results = Turn::tool_results(vec![ToolResult::ok("call-1", "fine")]);
        assert_eq!(results.role, Role::User);
        assert_eq!(results.content, "");
        assert!(results.tool_calls.is_empty());
        assert_eq!(results.tool_results.len(), 1);

        // The plain constructors still carry neither list, so an existing
        // caller that builds a prompt with them is unaffected.
        assert!(Turn::user("hi").tool_calls.is_empty());
        assert!(Turn::assistant("hi").tool_results.is_empty());
    }

    #[test]
    fn a_prompt_starts_without_tools_and_builds_them_up() {
        let prompt = Prompt::new(ModelTier::Fast);
        assert!(prompt.tools.is_empty());
        assert_eq!(prompt.tool_choice, None);

        let prompt = prompt
            .tool(ToolSpec::new("a", "A", serde_json::json!({})))
            .tools(vec![
                ToolSpec::new("b", "B", serde_json::json!({})),
                ToolSpec::new("c", "C", serde_json::json!({})),
            ])
            .tool_choice(ToolChoice::Required);
        assert_eq!(prompt.tools.len(), 3);
        assert_eq!(
            prompt
                .tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        assert_eq!(prompt.tool_choice, Some(ToolChoice::Required));
    }

    #[test]
    fn a_completion_starts_without_tool_calls_and_builds_them_up() {
        let completion = Completion::new("the answer", "vendor-1");
        assert!(completion.tool_calls.is_empty());
        let completion = completion.tool_calls(vec![ToolCall::new(
            "call-1",
            "lookup",
            serde_json::json!({}),
        )]);
        assert_eq!(completion.tool_calls.len(), 1);
    }

    #[test]
    fn an_unsupported_capability_names_what_is_missing_and_never_backs_off() {
        let error = TextModelError::Unsupported(Capability::Tools);
        assert_eq!(error.to_string(), "the text model does not support tools");
        assert_eq!(error.retry_after(), None);
    }

    #[test]
    fn the_default_capability_answer_is_no() {
        // An adapter that has not opted into tools reports none, so the
        // router and the tool loop refuse a tools-bearing prompt before it
        // is called. An adapter ignores the tier it is asked about.
        assert!(!Recording::new("plain").supports(ModelTier::Fast, Capability::Tools));
        assert!(Recording::tool_capable("capable").supports(ModelTier::Strong, Capability::Tools));
    }

    #[test]
    fn tools_to_a_tier_that_cannot_carry_them_are_refused_before_the_call() {
        let fast = Recording::new("fast-vendor");
        let router = RoutingTextModel::new().fast(fast.clone());
        let prompt = Prompt::new(ModelTier::Fast).user("hi").tool(ToolSpec::new(
            "lookup",
            "Look up.",
            serde_json::json!({}),
        ));

        let error = pollster::block_on(router.complete(&prompt)).unwrap_err();
        assert_eq!(error, TextModelError::Unsupported(Capability::Tools));
        assert_eq!(
            fast.count(),
            0,
            "the adapter was never called, tools and all"
        );
    }

    #[test]
    fn tools_to_a_capable_tier_pass_through_untouched() {
        let fast = Recording::tool_capable("fast-vendor");
        let router = RoutingTextModel::new().fast(fast.clone());
        let prompt = Prompt::new(ModelTier::Fast).tool(ToolSpec::new(
            "lookup",
            "Look up.",
            serde_json::json!({}),
        ));

        let completion = pollster::block_on(router.complete(&prompt)).unwrap();
        assert_eq!(completion.model, "fast-vendor");
        assert_eq!(fast.count(), 1);
    }

    #[test]
    fn a_prompt_without_tools_reaches_a_plain_model_as_before() {
        // The capability gate is only for tools: a prompt carrying none is
        // served by a model that reports no capabilities, unchanged.
        let fast = Recording::new("fast-vendor");
        let router = RoutingTextModel::new().fast(fast.clone());
        let completion =
            pollster::block_on(router.complete(&Prompt::new(ModelTier::Fast).user("hi"))).unwrap();
        assert_eq!(completion.model, "fast-vendor");
        assert_eq!(fast.count(), 1);
    }

    #[test]
    fn the_router_answers_a_capability_per_tier_and_false_when_unwired() {
        let capable = Recording::tool_capable("capable");
        let plain = Recording::new("plain");
        let router = RoutingTextModel::new()
            .fast(capable.clone())
            .strong(plain.clone());

        // The routed tier's own answer: a prompt goes to one tier, so a
        // capable fast tier reads capable even when the strong tier is not,
        // and vice versa.
        assert!(router.supports(ModelTier::Fast, Capability::Tools));
        assert!(!router.supports(ModelTier::Strong, Capability::Tools));

        // Nothing wired for a tier: no capability, whatever the other tier
        // holds.
        let unwired = RoutingTextModel::new();
        assert!(!unwired.supports(ModelTier::Fast, Capability::Tools));
        assert!(!unwired.supports(ModelTier::Strong, Capability::Tools));
    }

    // -----------------------------------------------------------------
    // Images (issue #628)

    /// A raw byte length whose standard, padded base64 encoding is exactly
    /// `encoded`, for `encoded` a multiple of four.
    fn raw_len_for_encoded(encoded: usize) -> usize {
        (encoded / 4) * 3
    }

    #[test]
    fn an_image_media_type_names_its_wire_mime() {
        assert_eq!(ImageMediaType::Png.as_str(), "image/png");
        assert_eq!(ImageMediaType::Jpeg.as_str(), "image/jpeg");
        assert_eq!(ImageMediaType::Gif.as_str(), "image/gif");
        assert_eq!(ImageMediaType::Webp.as_str(), "image/webp");
    }

    #[test]
    fn encode_image_is_standard_padded_base64_and_encoded_image_len_predicts_it() {
        // The canonical RFC 4648 test vectors, padded.
        assert_eq!(encode_image(b""), "");
        assert_eq!(encode_image(b"f"), "Zg==");
        assert_eq!(encode_image(b"fo"), "Zm8=");
        assert_eq!(encode_image(b"foo"), "Zm9v");
        assert_eq!(encode_image(b"foob"), "Zm9vYg==");
        assert_eq!(encode_image(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_image(b"foobar"), "Zm9vYmFy");

        // `encoded_image_len` is pure arithmetic and agrees with the
        // encoding for every remainder class.
        for raw in 0..=8usize {
            assert_eq!(
                encoded_image_len(raw),
                encode_image(&vec![0u8; raw]).len(),
                "raw length {raw}"
            );
        }
        assert_eq!(encoded_image_len(0), 0);
        assert_eq!(encoded_image_len(1), 4);
        assert_eq!(encoded_image_len(3), 4);
        assert_eq!(encoded_image_len(4), 8);
    }

    #[test]
    fn a_parts_turn_carries_its_parts_in_order_and_a_text_turn_carries_none() {
        let with_image = Prompt::new(ModelTier::Fast).user_parts([
            Part::text("look"),
            Part::image(ImageMediaType::Jpeg, vec![1, 2, 3]),
        ]);
        let turn = &with_image.messages[0];
        assert_eq!(turn.role, Role::User);
        assert_eq!(turn.content, "", "the parts are the whole content");
        assert_eq!(
            turn.parts,
            vec![
                Part::Text("look".to_owned()),
                Part::Image {
                    media_type: ImageMediaType::Jpeg,
                    bytes: vec![1, 2, 3],
                },
            ]
        );
        assert!(with_image.has_images());
        assert!(
            !Prompt::new(ModelTier::Fast)
                .user_parts([Part::text("no image here")])
                .has_images()
        );

        // The compatibility promise: a turn built the old way carries no
        // parts, so an adapter serialises it exactly as before images.
        let text_only = Prompt::new(ModelTier::Fast).user("hi");
        assert!(text_only.messages[0].parts.is_empty());
        assert!(!text_only.has_images());
        assert_eq!(text_only.check_images(), Ok(()));
    }

    #[test]
    fn check_images_holds_each_bound_as_a_ceiling() {
        // At the bound the prompt passes; one step over, the matching error.
        let four = Prompt::new(ModelTier::Fast).user_parts(
            (0..MAX_PROMPT_IMAGES).map(|_| Part::image(ImageMediaType::Png, vec![0u8])),
        );
        assert_eq!(four.check_images(), Ok(()));
        let each_raw = raw_len_for_encoded(MAX_IMAGE_ENCODED_BYTES);
        assert_eq!(encoded_image_len(each_raw), MAX_IMAGE_ENCODED_BYTES);
        let at_ceiling = Prompt::new(ModelTier::Fast)
            .user_parts([Part::image(ImageMediaType::Png, vec![0u8; each_raw])]);
        assert_eq!(at_ceiling.check_images(), Ok(()));

        // One image too many.
        let five = Prompt::new(ModelTier::Fast).user_parts(
            (0..=MAX_PROMPT_IMAGES).map(|_| Part::image(ImageMediaType::Png, vec![0u8])),
        );
        assert_eq!(
            five.check_images(),
            Err(TextModelError::ImageLimit(ImageLimit::TooMany {
                count: MAX_PROMPT_IMAGES + 1,
            }))
        );

        // A raw length encoding to one base64 group over the per-image cap.
        let over = MAX_IMAGE_ENCODED_BYTES + 4;
        let over_raw = raw_len_for_encoded(over);
        assert_eq!(encoded_image_len(over_raw), over);
        let too_large = Prompt::new(ModelTier::Fast)
            .user_parts([Part::image(ImageMediaType::Png, vec![0u8; over_raw])]);
        assert_eq!(
            too_large.check_images(),
            Err(TextModelError::ImageLimit(ImageLimit::ImageTooLarge {
                index: 0,
                encoded_bytes: over,
            }))
        );

        // Two images just under the per-image cap, together over the total:
        // the count and each image are legal, the sum is not.
        let each = MAX_IMAGE_ENCODED_BYTES - 4;
        let raw = raw_len_for_encoded(each);
        assert!(2 * each > MAX_PROMPT_IMAGE_ENCODED_BYTES);
        let too_total = Prompt::new(ModelTier::Fast).user_parts([
            Part::image(ImageMediaType::Png, vec![0u8; raw]),
            Part::image(ImageMediaType::Jpeg, vec![0u8; raw]),
        ]);
        assert_eq!(
            too_total.check_images(),
            Err(TextModelError::ImageLimit(ImageLimit::TotalTooLarge {
                encoded_bytes: 2 * each,
            }))
        );
    }

    #[test]
    fn the_image_limit_error_is_displayed_without_any_user_content() {
        let error = TextModelError::ImageLimit(ImageLimit::TooMany { count: 9 });
        assert_eq!(
            error.to_string(),
            "the prompt's images exceed a limit: a prompt may carry at most 4 images, but this \
             one carries 9"
        );
        assert_eq!(error.retry_after(), None);
    }

    #[test]
    fn images_to_a_tier_that_cannot_carry_them_are_refused_before_the_call() {
        let fast = Recording::new("fast-vendor");
        let router = RoutingTextModel::new().fast(fast.clone());
        let prompt = Prompt::new(ModelTier::Fast)
            .user_parts([Part::image(ImageMediaType::Png, vec![0u8; 4])]);

        let error = pollster::block_on(router.complete(&prompt)).unwrap_err();
        assert_eq!(error, TextModelError::Unsupported(Capability::Images));
        assert_eq!(fast.count(), 0, "the adapter was never called");

        // The capable mirror: the same prompt passes through untouched, but
        // an over-limit one is still refused by the router before the tier,
        // whatever the deployment claims.
        let capable = Recording::image_capable("fast-vendor");
        let router = RoutingTextModel::new().fast(capable.clone());
        let prompt = Prompt::new(ModelTier::Fast)
            .user_parts([Part::image(ImageMediaType::Webp, vec![0u8; 4])]);
        assert_eq!(
            pollster::block_on(router.complete(&prompt)).unwrap().model,
            "fast-vendor"
        );
        assert_eq!(capable.count(), 1);

        let over = Prompt::new(ModelTier::Fast).user_parts(
            (0..=MAX_PROMPT_IMAGES).map(|_| Part::image(ImageMediaType::Png, vec![0u8])),
        );
        assert_eq!(
            pollster::block_on(router.complete(&over)).unwrap_err(),
            TextModelError::ImageLimit(ImageLimit::TooMany {
                count: MAX_PROMPT_IMAGES + 1,
            })
        );
        assert_eq!(capable.count(), 1, "the over-limit prompt never reached it");
    }
}
