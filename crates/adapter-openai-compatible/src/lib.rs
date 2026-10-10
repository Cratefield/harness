//! `cratefield-adapter-openai-compatible`: the [`TextModel`] port over the
//! `OpenAI` chat-completions wire (issue #560). One adapter speaks every
//! server that answers that wire — `OpenAI` itself, Workers AI's
//! `OpenAI`-compatible endpoint, `OpenRouter`, and local servers like `vLLM`,
//! llama.cpp and Ollama — because the base URL is a constructor argument,
//! not a constant.
//!
//! Uses the runtime's [`HttpClient`] port — no `reqwest`, no vendor SDK —
//! so the same adapter runs on Workers and natively, and inherits that
//! port's destination vetting, deadline and response-size caps.
//!
//! **Degraded mode.** When the API key is absent the adapter answers
//! [`TextModelError::NotConfigured`] without any network call, so a
//! pipeline stage can degrade instead of breaking. A keyless local server
//! takes any placeholder key: the adapter always sends the
//! `Authorization` header, and a server that never checks it ignores it.
//!
//! **Tools (issue #665).** The adapter carries `OpenAI`'s function-calling
//! shape by default: a [`Prompt`]'s tools ride in the request's `tools`
//! array, the assistant message's `tool_calls` parse into
//! [`Completion::tool_calls`], and a conversation quoting a tool call and
//! its result goes back out as an assistant message with `tool_calls` and
//! one `role: "tool"` message per result. Every server behind this wire is
//! not equally capable — a model that does not speak tools either ignores
//! the array or rejects the request — so
//! [`OpenAiCompatible::without_tools`] turns the capability off for one
//! deployment: [`TextModel::supports`] then reports
//! [`Capability::Tools`](cratefield_core::Capability) as `false`, and a
//! tools-bearing prompt is refused with [`TextModelError::Unsupported`]
//! before any request reaches the server.
//!
//! **Images (issue #628).** The wire carries images in the same `content`
//! array text does, but not every server behind it has a vision model, so
//! image input is **opt-in**, the mirror of tools' opt-out: a deployment
//! calls [`OpenAiCompatible::with_images`] and [`TextModel::supports`] then
//! reports [`Capability::Images`](cratefield_core::Capability) as `true`;
//! off by default, an image-bearing prompt is refused with
//! [`TextModelError::Unsupported`] before any request. Every call runs
//! [`Prompt::check_images`] first — before the network and before the
//! capability gate — so an over-limit prompt is refused locally rather than
//! paid for, whatever the deployment is configured for.
//!
//! **Speech (issue #861).** The same wire carries audio:
//! [`OpenAiCompatibleSpeech`] transcribes through the Whisper-shaped
//! `audio/transcriptions` endpoint and voices text through `audio/speech`,
//! at any base URL, under the same key and degraded-mode rules.
//!
//! **Streaming (issue #859).** [`TextModel::stream`] speaks the same wire
//! natively: the request `complete` builds plus `stream: true` and
//! `include_usage`, its Server-Sent Events decoded by core's shared
//! [`SseDecoder`](cratefield_core::sse::SseDecoder) into
//! [`TextDelta`](cratefield_core::TextDelta)s. Dropping the returned stream
//! drops the response body and with it the upstream exchange, so a
//! disconnecting caller stops the spend.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::sse::{self, SseEvent};
use cratefield_core::{
    BoxStream, ByteStream, Capability, Clock, Completion, FinishReason, HttpClient, HttpError,
    HttpPolicy, MAX_RESPONSE_BYTES, MAX_RESPONSE_TIMEOUT, ModelTier, Part, Prompt, Role, TextDelta,
    TextModel, TextModelError, ToolCall, ToolChoice, ToolResult, Turn, completion_deltas,
    encode_image, retry_after,
};
use futures_util::StreamExt;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

// The `Speech` port (issue #861): the audio wire alongside the chat wire
// above, kept in its own module.
mod speech;

pub use speech::{DEFAULT_SPEECH_MODEL, DEFAULT_TRANSCRIPTION_MODEL, OpenAiCompatibleSpeech};

/// The endpoint every request goes to unless
/// [`OpenAiCompatible::with_base_url`] says otherwise: `OpenAI`'s own
/// chat-completions path. Point it at `OpenRouter`
/// (`https://openrouter.ai/api/v1`), a Workers AI `OpenAI`-compatible
/// route, or a local server (`http://127.0.0.1:11434/v1` for Ollama;
/// `vLLM` and llama.cpp serve a `/v1` of their own).
pub const DEFAULT_ENDPOINT: &str = "https://api.openai.com/v1";

/// The model [`OpenAiCompatible::from_env`] uses when `OPENAI_MODEL` is
/// unset: a small chat model that accepts the `max_tokens` field this
/// adapter sends. Overriding it has one catch on `OpenAI`'s own API: the
/// GPT-5 and o-series models refuse `max_tokens` (they take
/// `max_completion_tokens`, which the compatible-server ecosystem mostly
/// does not speak), so a first-party key needs a model that still takes
/// `max_tokens` — most non-`OpenAI` servers take both.
pub const DEFAULT_MODEL: &str = "gpt-4o-mini";

/// The name the JSON path gives the caller's schema inside
/// `response_format` — a label the wire requires and the answer never
/// carries; the schema itself is the caller's [`Prompt::json_schema`].
const JSON_SCHEMA_NAME: &str = "response";

/// The `OpenAI`-compatible `TextModel` over `POST {base_url}/chat/completions`.
pub struct OpenAiCompatible {
    http: Arc<dyn HttpClient>,
    /// Needed only to read the HTTP-date form of `Retry-After` (issue #278).
    /// A constructor argument rather than a builder default so a deployment
    /// that forgets it fails to compile instead of silently retrying a
    /// date-form 429 immediately.
    clock: Arc<dyn Clock>,
    api_key: Option<String>,
    model: String,
    base_url: String,
    /// Whether this deployment carries tools. `true` by default — the wire
    /// speaks function calling — and turned off with
    /// [`OpenAiCompatible::without_tools`] for a server or model behind it
    /// that does not.
    tools: bool,
    /// Whether this deployment carries image input (issue #628). `false` by
    /// default — the wire speaks images but not every model behind it has
    /// vision — and turned on with [`OpenAiCompatible::with_images`].
    images: bool,
}

impl OpenAiCompatible {
    /// `api_key: None` => every call is [`TextModelError::NotConfigured`]
    /// (no network). A server that checks no key still gets the header:
    /// pass a placeholder rather than wiring degraded mode by accident.
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        api_key: Option<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            http,
            clock,
            api_key,
            model: model.into(),
            base_url: DEFAULT_ENDPOINT.to_owned(),
            tools: true,
            images: false,
        }
    }

    /// Turns tools off for this deployment: the adapter then sends no
    /// `tools` and reports [`Capability::Tools`] as unsupported, so a
    /// tools-bearing prompt is refused with
    /// [`TextModelError::Unsupported`] before any request is made. The
    /// wire itself speaks function calling — [`OpenAiCompatible::new`]
    /// keeps it on — so this is for a server or model behind the wire that
    /// does not: one that would silently drop the array and answer as if no
    /// tool was offered.
    #[must_use]
    pub fn without_tools(mut self) -> Self {
        self.tools = false;
        self
    }

    /// Turns image input on for this deployment (issue #628): the adapter
    /// then reports [`Capability::Images`] and serialises a prompt's
    /// [`Part::Image`]s into the wire's `content` array. Off by default —
    /// the wire speaks images but not every model behind it has vision. The
    /// mirror of [`OpenAiCompatible::without_tools`]: there the wire spoke
    /// the feature and a deployment opted out; here a deployment opts in.
    #[must_use]
    pub fn with_images(mut self) -> Self {
        self.images = true;
        self
    }

    /// Points the adapter at a different chat-completions server —
    /// `OpenRouter`, a Workers AI `OpenAI`-compatible route, or a local `vLLM`,
    /// llama.cpp or Ollama server. A trailing slash on the base is
    /// harmless; the wire path is appended.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Reads `OPENAI_API_KEY`, `OPENAI_MODEL` (default [`DEFAULT_MODEL`])
    /// and `OPENAI_BASE_URL` (default [`DEFAULT_ENDPOINT`]) from the
    /// process environment. On Workers the venture should read the secrets
    /// from its `Env` and use [`OpenAiCompatible::new`] instead (`std::env`
    /// has no Workers vars).
    pub fn from_env(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self::new(
            http,
            clock,
            std::env::var("OPENAI_API_KEY").ok(),
            std::env::var("OPENAI_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_owned()),
        )
        .with_base_url(
            std::env::var("OPENAI_BASE_URL").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_owned()),
        )
    }

    /// The chat-completions URL for the configured base: the base with one
    /// trailing slash trimmed, then the wire path.
    fn endpoint(&self) -> String {
        format!("{}/chat/completions", self.base_url.trim_end_matches('/'))
    }

    /// Status → port error, the one place the provider's taxonomy meets
    /// ours. The provider's error envelope
    /// (`{"error":{"message":…,…}}`) is parsed once for its message; the
    /// raw body is the fallback, so a proxy's HTML error page still leaves
    /// the caller something to log.
    fn map_status(status: StatusCode, body: &str, retry_after: Option<Duration>) -> TextModelError {
        let detail = provider_message(body);
        match status {
            // "Later", in both shapes the wire says it: an explicit rate
            // limit (its `Retry-After` honoured in both RFC 9110 forms,
            // through core's parser) and a server on its side.
            StatusCode::TOO_MANY_REQUESTS => TextModelError::Transient { retry_after },
            status if status.is_server_error() => TextModelError::Transient { retry_after: None },
            // The server refused the request itself: 400 a malformed or
            // over-limit prompt, 422 content it will not process. Neither
            // is worth a retry unchanged.
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
                TextModelError::Rejected(detail)
            }
            // A bad, revoked or unauthorised key is a configuration
            // mistake, not a condition time fixes: retrying with the same
            // key burns the rate budget and fails the same way.
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => TextModelError::Rejected(detail),
            // Any other 4xx is still the request's fault (404: the model
            // is not served here; 413: the prompt is too large).
            status if status.is_client_error() => TextModelError::Rejected(detail),
            // Redirects and anything unmodelled: the call did not complete.
            _ => TextModelError::Transport(format!("unexpected status {status}: {detail}")),
        }
    }

    /// The pre-flight refusals both halves of the port share — `complete`
    /// and `stream` run the same gates in the same order, so a prompt
    /// refused on one half is refused identically on the other: image
    /// bounds first (they hold whatever this deployment is configured for),
    /// then the key, then the capability gates. Returns the API key, so a
    /// caller never reaches the wire without one.
    fn preflight(&self, prompt: &Prompt) -> Result<&str, TextModelError> {
        // An over-limit image prompt is refused first, before any request:
        // the bounds hold whatever this deployment is configured for.
        prompt.check_images()?;

        let Some(api_key) = &self.api_key else {
            tracing::info!(
                provider = "openai-compatible",
                outcome = "not_configured",
                model = %self.model,
                "text model outcome"
            );
            return Err(TextModelError::NotConfigured);
        };

        // A tools-bearing prompt to an adapter whose deployment turned
        // tools off is refused here, before any request: sending the tools
        // anyway and letting the model ignore them would answer as if none
        // had been offered, hiding the mismatch. The router and
        // `run_tool_loop` refuse this up front too; this is the adapter's
        // own guard for a direct caller.
        if !self.tools && !prompt.tools.is_empty() {
            tracing::warn!(
                provider = "openai-compatible",
                outcome = "unsupported",
                model = %self.model,
                "text model outcome"
            );
            return Err(TextModelError::Unsupported(Capability::Tools));
        }

        // The same guard for images (issue #628): a deployment that did not
        // opt into vision is refused an image-bearing prompt before any
        // request.
        if !self.images && prompt.has_images() {
            tracing::warn!(
                provider = "openai-compatible",
                outcome = "unsupported",
                model = %self.model,
                "text model outcome"
            );
            return Err(TextModelError::Unsupported(Capability::Images));
        }

        Ok(api_key)
    }

    /// Serialises the wire body and frames the request: the shared headers,
    /// and the port's widest [`HttpPolicy`] — as on the Anthropic adapter,
    /// the port's 30 s ceiling for a model call's head, the port's body
    /// cap, and `HttpPolicy::clamped` so a caller can tighten but never
    /// raise.
    fn frame(
        &self,
        api_key: &str,
        payload: &ChatCompletionsRequest<'_>,
    ) -> Result<Request<Bytes>, TextModelError> {
        let body = serde_json::to_vec(&payload)
            .map_err(|err| TextModelError::Transport(err.to_string()))?;
        let mut request = Request::builder()
            .method(http::Method::POST)
            .uri(self.endpoint())
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {api_key}"))
            .body(Bytes::from(body))
            .map_err(|err| TextModelError::Transport(err.to_string()))?;
        request.extensions_mut().insert(HttpPolicy {
            timeout: MAX_RESPONSE_TIMEOUT,
            max_response_bytes: MAX_RESPONSE_BYTES,
        });
        Ok(request)
    }
}

fn wire_role(role: Role) -> &'static str {
    match role {
        Role::User => "user",
        Role::Assistant => "assistant",
    }
}

#[derive(serde::Serialize)]
struct ChatCompletionsRequest<'a> {
    model: &'a str,
    /// The field name the broadest set of compatible servers accepts.
    /// `OpenAI`'s first-party API deprecates it in favour of
    /// `max_completion_tokens`, and its GPT-5/o-series models refuse it
    /// outright (see [`DEFAULT_MODEL`]); every compatible server this
    /// adapter targets accepts `max_tokens`, and most speak nothing else.
    max_tokens: u32,
    messages: Vec<WireMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<WireResponseFormat<'a>>,
    /// Absent when the prompt offered no tools, so a tool-free request
    /// serialises exactly as it did before tools existed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<WireTool<'a>>,
    /// Absent when the prompt left the choice to the provider's default.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<Value>,
    /// Set only by the streaming path ([`TextModel::stream`], issue #859):
    /// absent on the buffered path, so a `complete` request body is
    /// byte-for-byte what it always was.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
    /// Only ever sent beside `stream: true`: without `include_usage` the
    /// chunk stream carries no trailing `usage` block, and the port's Usage
    /// delta would have nothing to read.
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_options: Option<WireStreamOptions>,
}

/// The streaming flags the delta path adds to the body `complete` builds
/// (issue #859). `include_usage` is the point of the envelope: it asks for
/// the final, choices-empty chunk that carries the token counts.
#[derive(serde::Serialize)]
struct WireStreamOptions {
    include_usage: bool,
}

/// One message of the request. Owned rather than borrowed because a tool
/// result may need to prefix its content (see [`wire_tool_result`]), so the
/// content is not always a slice of the prompt.
#[derive(serde::Serialize)]
struct WireMessage {
    role: &'static str,
    /// `Some` for every plain message; `None` (an explicit `null`) only for
    /// an assistant turn that carried no text and only tool calls — the
    /// shape `OpenAI` documents for a call-only turn.
    content: Option<WireContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<WireToolCall>>,
    /// Set on a `role: "tool"` message: which call it answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

/// A message's content: a plain string for a text-only turn, an ordered
/// array of parts once the turn carries any (issue #628). Untagged, so a
/// text-only message serialises byte-for-byte as it did before images
/// existed.
#[derive(serde::Serialize)]
#[serde(untagged)]
enum WireContent {
    /// A text-only message's content.
    Text(String),
    /// A message that carries [`Part`]s, in order.
    Parts(Vec<WirePart>),
}

/// One part of a message's `content` array, in the `OpenAI` shape: a text
/// object or an `image_url` object with a `data:` URL.
#[derive(serde::Serialize)]
#[serde(tag = "type")]
enum WirePart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image_url")]
    ImageUrl { image_url: WireImageUrl },
}

/// The `image_url` envelope of an image part: a single `url`, carrying the
/// image inline as a base64 `data:` URL.
#[derive(serde::Serialize)]
struct WireImageUrl {
    url: String,
}

/// One tool offered to the model: the `{"type":"function","function":…}`
/// envelope `OpenAI` defines for the request's `tools` array.
#[derive(serde::Serialize)]
struct WireTool<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    function: WireToolFunction<'a>,
}

#[derive(serde::Serialize)]
struct WireToolFunction<'a> {
    name: &'a str,
    description: &'a str,
    parameters: &'a Value,
}

/// One tool call, in the shape the request and the answer share: the
/// assistant message the caller sends back and the assistant message the
/// server returns are the same object.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct WireToolCall {
    #[serde(default)]
    id: String,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    function: Option<WireFunctionCall>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct WireFunctionCall {
    #[serde(default)]
    name: String,
    /// A JSON **string** on the wire — the model's arguments serialised —
    /// not an object. It is re-serialised from [`ToolCall::arguments`] on
    /// the way out — except a [`Value::String`], which is already the raw
    /// text and is emitted verbatim — and parsed back on the way in.
    #[serde(default)]
    arguments: String,
}

#[derive(serde::Serialize)]
struct WireResponseFormat<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    json_schema: WireJsonSchema<'a>,
}

#[derive(serde::Serialize)]
struct WireJsonSchema<'a> {
    name: &'static str,
    schema: &'a serde_json::Value,
    strict: bool,
}

/// The wire's `tool_choice` for a port [`ToolChoice`]: a bare string for the
/// three prose choices, an object pinning one function for
/// [`ToolChoice::Tool`]. `None` for a variant this adapter does not know —
/// [`ToolChoice`] is `#[non_exhaustive]`, and a choice it cannot express is
/// left to the provider's default rather than sent as something wrong.
fn wire_tool_choice(choice: &ToolChoice) -> Option<Value> {
    match choice {
        ToolChoice::Auto => Some(json!("auto")),
        ToolChoice::None => Some(json!("none")),
        ToolChoice::Required => Some(json!("required")),
        ToolChoice::Tool(name) => Some(json!({
            "type": "function",
            "function": {"name": name},
        })),
        _ => None,
    }
}

/// One tool call on the way out: the arguments object the port holds becomes
/// the JSON *string* the wire carries. `Value`'s own `Display` is exactly
/// that compact JSON and cannot fail.
///
/// A `Value::String` is the exception: it is arguments this adapter already
/// failed to parse out of a previous answer and kept verbatim (see
/// [`parse_tool_call`]). Re-serialising it would double-encode the raw text
/// into a quoted JSON string — replaying `{"location":` as `"{\"location\":"`
/// — so it is emitted exactly as it arrived.
fn wire_tool_call(call: &ToolCall) -> WireToolCall {
    WireToolCall {
        id: call.id.clone(),
        kind: Some("function".to_owned()),
        function: Some(WireFunctionCall {
            name: call.name.clone(),
            arguments: match &call.arguments {
                Value::String(raw) => raw.clone(),
                other => other.to_string(),
            },
        }),
    }
}

/// The content of a `role: "tool"` message. The wire has no `is_error` field
/// on a tool message, so a failed result's text is prefixed with `Error: ` —
/// the model reads the failure in the text, which is all the wire offers.
fn wire_tool_result(result: &ToolResult) -> String {
    if result.is_error {
        format!("Error: {}", result.content)
    } else {
        result.content.clone()
    }
}

/// One part on the wire. An image becomes an `image_url` part whose URL is
/// the inline `data:` form — media type and base64 bytes.
///
/// # Errors
///
/// [`TextModelError::Rejected`] for a [`Part`] variant this adapter does
/// not know: `Part` is `#[non_exhaustive]`, so a future file reference or
/// provider-hosted URL is refused rather than silently dropped — the same
/// rule the Anthropic adapter's `wire_turn` applies. (Unreachable today:
/// [`Part::Text`] and [`Part::Image`] are the only variants, and the
/// capability gate admits no others.)
fn wire_part(part: &Part) -> Result<WirePart, TextModelError> {
    match part {
        Part::Text(text) => Ok(WirePart::Text { text: text.clone() }),
        Part::Image { media_type, bytes } => Ok(WirePart::ImageUrl {
            image_url: WireImageUrl {
                url: format!(
                    "data:{};base64,{}",
                    media_type.as_str(),
                    encode_image(bytes)
                ),
            },
        }),
        _ => Err(TextModelError::Rejected(
            "the prompt carries a content part this adapter does not know how to send".to_owned(),
        )),
    }
}

/// A turn's content for the wire: its ordered [`Part`]s as an array when it
/// carries any (issue #628), otherwise its text as a plain string, exactly
/// as it serialised before images existed.
///
/// # Errors
///
/// Propagates [`wire_part`]'s refusal of a [`Part`] that cannot be
/// serialised, so no part is ever silently dropped.
fn wire_content(turn: &Turn) -> Result<WireContent, TextModelError> {
    if turn.parts.is_empty() {
        Ok(WireContent::Text(turn.content.clone()))
    } else {
        Ok(WireContent::Parts(
            turn.parts
                .iter()
                .map(wire_part)
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

/// Appends the wire message(s) one [`Turn`] becomes: a plain message, an
/// assistant message that quotes its `tool_calls`, or one `role: "tool"`
/// message per result — followed by a user message when a tool-results turn
/// also carries text of its own.
///
/// # Errors
///
/// Propagates [`wire_content`]'s refusal of a [`Part`] this adapter cannot
/// serialise.
fn push_turn(messages: &mut Vec<WireMessage>, turn: &Turn) -> Result<(), TextModelError> {
    match turn.role {
        Role::Assistant if !turn.tool_calls.is_empty() => {
            messages.push(WireMessage {
                role: "assistant",
                // A call-only turn has no text; the wire wants `null` for it,
                // not an empty string.
                content: (!turn.content.is_empty() || !turn.parts.is_empty())
                    .then(|| wire_content(turn))
                    .transpose()?,
                tool_calls: Some(turn.tool_calls.iter().map(wire_tool_call).collect()),
                tool_call_id: None,
            });
        }
        Role::User if !turn.tool_results.is_empty() => {
            for result in &turn.tool_results {
                messages.push(WireMessage {
                    role: "tool",
                    content: Some(WireContent::Text(wire_tool_result(result))),
                    tool_calls: None,
                    tool_call_id: Some(result.tool_call_id.clone()),
                });
            }
            if !turn.content.is_empty() {
                messages.push(WireMessage {
                    role: "user",
                    content: Some(WireContent::Text(turn.content.clone())),
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
        }
        _ => messages.push(WireMessage {
            role: wire_role(turn.role),
            content: Some(wire_content(turn)?),
            tool_calls: None,
            tool_call_id: None,
        }),
    }
    Ok(())
}

/// Builds the wire body: the messages plus, when the prompt asked for them,
/// a `response_format` carrying the caller's schema, the `tools` array and
/// the `tool_choice`. Hand-rolling this JSON would be a second escaping bug
/// waiting to happen; the prompt is user content.
///
/// # Errors
///
/// Propagates [`push_turn`]'s refusal of a [`Part`] this adapter cannot
/// serialise.
fn wire_request<'a>(
    model: &'a str,
    prompt: &'a Prompt,
) -> Result<ChatCompletionsRequest<'a>, TextModelError> {
    let response_format = prompt
        .json_schema
        .as_ref()
        .map(|schema| WireResponseFormat {
            kind: "json_schema",
            json_schema: WireJsonSchema {
                name: JSON_SCHEMA_NAME,
                schema,
                // `strict: false`: the port allows any draft 2020-12
                // schema, and `OpenAI`'s strict mode answers 400 to an
                // ordinary one (it demands `additionalProperties: false`
                // and every property required). What the adapter enforces
                // is the parse below; a caller who wants strict-mode
                // guarantees supplies a strict-compatible schema and keeps
                // their own check on the parsed answer.
                strict: false,
            },
        });
    // The system prompt is a leading message on this wire, not a
    // parameter of its own.
    let mut messages = Vec::with_capacity(prompt.messages.len() + 1);
    if let Some(system) = prompt.system.as_deref() {
        messages.push(WireMessage {
            role: "system",
            content: Some(WireContent::Text(system.to_owned())),
            tool_calls: None,
            tool_call_id: None,
        });
    }
    for turn in &prompt.messages {
        push_turn(&mut messages, turn)?;
    }
    let tools = prompt
        .tools
        .iter()
        .map(|tool| WireTool {
            kind: "function",
            function: WireToolFunction {
                name: &tool.name,
                description: &tool.description,
                parameters: &tool.parameters,
            },
        })
        .collect();
    Ok(ChatCompletionsRequest {
        model,
        max_tokens: prompt.max_tokens,
        messages,
        response_format,
        tools,
        tool_choice: prompt.tool_choice.as_ref().and_then(wire_tool_choice),
        // The buffered defaults: the streaming override turns both on
        // without rebuilding the rest of the body.
        stream: false,
        stream_options: None,
    })
}

#[derive(serde::Deserialize)]
struct ChatCompletionsResponse {
    #[serde(default)]
    model: String,
    #[serde(default)]
    choices: Vec<WireChoice>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(serde::Deserialize)]
struct WireChoice {
    #[serde(default)]
    message: Option<WireAnswer>,
    #[serde(default)]
    finish_reason: Option<String>,
}

/// The content is `Option` rather than defaulted: servers send an explicit
/// `null` when a refusal or a tool call replaces the text, and that must
/// not refuse the whole response. The refusal rides in the same message
/// — `refusal` set, `content` `null` — so it is read before any
/// content-shaped decision.
#[derive(serde::Deserialize)]
struct WireAnswer {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    refusal: Option<String>,
    /// The calls the model asked for. Empty for a plain answer, and for a
    /// server that does not speak function calling.
    #[serde(default)]
    tool_calls: Vec<WireToolCall>,
}

#[derive(serde::Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
    /// The vendor's cache report: present when the vendor does caching at
    /// all, absent otherwise — which is exactly the
    /// [`Completion::cached_input_tokens`] distinction between a reported
    /// zero and no report.
    #[serde(default)]
    prompt_tokens_details: Option<PromptTokensDetails>,
}

#[derive(serde::Deserialize)]
struct PromptTokensDetails {
    #[serde(default)]
    cached_tokens: u32,
}

#[derive(serde::Deserialize)]
struct ErrorEnvelope {
    #[serde(default)]
    error: Option<ApiErrorBody>,
}

#[derive(serde::Deserialize)]
struct ApiErrorBody {
    #[serde(default)]
    message: String,
}

/// The provider's own words, from its error envelope, with the raw body as
/// the fallback when the envelope does not parse.
fn provider_message(body: &str) -> String {
    match serde_json::from_str::<ErrorEnvelope>(body) {
        Ok(parsed) => match parsed.error {
            Some(error) if !error.message.is_empty() => error.message,
            _ => body.to_string(),
        },
        Err(_) => body.to_string(),
    }
}

/// A refusal inside an otherwise-successful response, or the server's
/// content filter: both rejections that arrive after a 200, checked
/// before anything reads the answer content. The provider's refusal text
/// goes to the log, where the operator reads it the same way they read a
/// provider error message; the error itself carries the adapter's own
/// words, the convention of every other `Rejected` path.
fn refusal_guard(choice: &WireChoice, model: &str) -> Option<TextModelError> {
    if let Some(refusal) = choice
        .message
        .as_ref()
        .and_then(|message| message.refusal.as_deref())
        .filter(|refusal| !refusal.is_empty())
    {
        tracing::warn!(
            provider = "openai-compatible",
            outcome = "refused",
            model = %model,
            refusal = refusal,
            "text model outcome"
        );
        return Some(TextModelError::Rejected(
            "the model declined the prompt (refusal); the provider's words are in the log"
                .to_owned(),
        ));
    }
    // The content filter stopped the answer before it was one, on either
    // path — through [`content_filter_rejected`], the very error the
    // streamed half ends on for the same `finish_reason`.
    if choice.finish_reason.as_deref() == Some("content_filter") {
        return Some(content_filter_rejected(model));
    }
    None
}

/// The content filter's rejection, word for word the same on both halves
/// of the port: the buffered [`refusal_guard`] answers its
/// `finish_reason: "content_filter"` with this, and the streaming fold
/// ends on it — so `run_tool_loop` and `run_tool_loop_stream` cannot
/// disagree about an answer the filter stopped. `Rejected`, not
/// `Transient`: the prompt is what tripped it, so retrying unchanged
/// fails the same way. The provider's report goes to the log, where the
/// operator reads it the same way they read a provider error message; the
/// error itself carries the adapter's own words, the convention of every
/// other `Rejected` path.
fn content_filter_rejected(model: &str) -> TextModelError {
    tracing::warn!(
        provider = "openai-compatible",
        outcome = "content_filter",
        model = %model,
        "text model outcome"
    );
    TextModelError::Rejected("the server's content filter stopped the answer".to_owned())
}

/// The completion's usage, or the defaulted zero when the server sent
/// none — warned about, because a missing report must not silently read
/// as a free completion in the cost accounting.
fn reported_usage(usage: Option<WireUsage>, model: &str) -> WireUsage {
    usage.unwrap_or_else(|| {
        tracing::warn!(
            provider = "openai-compatible",
            model = %model,
            "text model completed without a usage block; token counts default to zero"
        );
        WireUsage::default()
    })
}

/// The model's tool calls, parsed from the wire. Only function calls exist
/// on this wire; an entry naming another `type` is skipped rather than
/// misread as one.
fn parse_tool_calls(message: Option<&WireAnswer>) -> Vec<ToolCall> {
    let Some(calls) = message.map(|message| message.tool_calls.as_slice()) else {
        return Vec::new();
    };
    calls.iter().filter_map(parse_tool_call).collect()
}

fn parse_tool_call(call: &WireToolCall) -> Option<ToolCall> {
    match call.kind.as_deref() {
        None | Some("function") => {}
        Some(_) => return None,
    }
    let function = call.function.as_ref()?;
    // The arguments arrive as a JSON *string*. One that parses becomes the
    // object the port holds; one that does not is kept as that raw string,
    // so `run_tool_loop` refuses the call — tool arguments must be a JSON
    // object — and feeds the error back to the model. A truncated or
    // malformed call never reaches an executor, and never becomes a parse
    // failure of the whole response.
    let arguments = serde_json::from_str(&function.arguments)
        .unwrap_or_else(|_| Value::String(function.arguments.clone()));
    Some(ToolCall::new(
        call.id.clone(),
        function.name.clone(),
        arguments,
    ))
}

/// The `data:` payload that ends a chat-completions chunk stream. Some
/// compatible servers omit it after a `finish_reason` + usage; a stream
/// that ends with neither sentinel nor reason never finished.
const DONE_SENTINEL: &str = "[DONE]";

/// One chat-completion **chunk** of a streamed answer (issue #859): the
/// same envelope as [`ChatCompletionsResponse`] with a `delta` where the
/// full message was, and — when `include_usage` was asked for — a final,
/// choices-empty chunk carrying only the `usage`.
#[derive(serde::Deserialize)]
struct ChatChunk {
    #[serde(default)]
    model: String,
    #[serde(default)]
    choices: Vec<WireChunkChoice>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(serde::Deserialize)]
struct WireChunkChoice {
    #[serde(default)]
    delta: Option<WireDelta>,
    #[serde(default)]
    finish_reason: Option<String>,
}

/// A chunk's delta: whichever pieces of the answer arrived with this chunk.
/// Both reasoning spellings the compatible-server ecosystem has shipped are
/// read (`reasoning_content` first, `reasoning` beside it); a server that
/// exposes neither simply never trips the arm.
#[derive(serde::Deserialize)]
struct WireDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
    #[serde(default)]
    reasoning: Option<String>,
    #[serde(default)]
    refusal: Option<String>,
    #[serde(default)]
    tool_calls: Vec<WireToolCallChunk>,
}

/// One fragment of one tool call inside a chunk: the call's `index` in the
/// completion's tool-call order, and whichever parts travelled with this
/// fragment — id and name on the first, argument text on every one after.
/// `index` is defaulted as well as optional: a server that streams one call
/// at a time is allowed to omit it (the one call is index 0), while a
/// parallel-call server must send it to keep the calls apart.
#[derive(serde::Deserialize)]
struct WireToolCallChunk {
    #[serde(default)]
    index: usize,
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    function: Option<WireFunctionFragment>,
}

#[derive(serde::Deserialize)]
struct WireFunctionFragment {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

/// The wire's `finish_reason` → the port's [`FinishReason`]: the four words
/// of the vocabulary map one-to-one (`function_call`, the legacy spelling,
/// lands on [`FinishReason::ToolUse`] beside `tool_calls`), and anything a
/// server invents rides in [`FinishReason::Other`] for the log line.
fn finish_reason(reason: &str) -> FinishReason {
    match reason {
        "stop" => FinishReason::Stop,
        "length" => FinishReason::Length,
        "tool_calls" | "function_call" => FinishReason::ToolUse,
        "content_filter" => FinishReason::ContentFilter,
        other => FinishReason::Other(other.to_owned()),
    }
}

/// One tool call being reassembled across chunks: the wire shape
/// [`parse_tool_call`] consumes — so a finished call is parsed by exactly
/// the code path `complete` parses its answer with, never a second parser —
/// plus whether the call's `ToolCallStarted` delta has gone out.
#[derive(Default)]
struct CallAcc {
    wire: WireToolCall,
    started: bool,
}

/// The streaming fold (issue #859): the SSE-decoded body plus everything
/// the chunk sequence accumulates into — the calls keyed by wire `index`,
/// the `finish_reason` the Finish delta waits for, the model, whether a
/// `usage` chunk arrived — yielding [`TextDelta`]s as events dispatch. The
/// fold owns the body, so dropping the delta stream drops the upstream
/// exchange; nothing is spawned and nothing outlives the stream.
struct Fold {
    events: BoxStream<'static, Result<SseEvent, HttpError>>,
    calls: BTreeMap<usize, CallAcc>,
    reason: Option<FinishReason>,
    model: String,
    usage_seen: bool,
    /// Deltas a chunk folded into that have not been yielded yet: one event
    /// can produce several (a call's start and its first argument fragment
    /// share a chunk), and the stream yields one item per poll.
    pending: std::vec::IntoIter<TextDelta>,
    /// Fused once the answer is over — `[DONE]`, the body's end or an
    /// error. Nothing is pulled from `events` again.
    done: bool,
}

impl Fold {
    /// A fold over `events`, reporting the configured `model` unless a
    /// chunk's own `model` names another.
    fn new(events: BoxStream<'static, Result<SseEvent, HttpError>>, model: String) -> Self {
        Self {
            events,
            calls: BTreeMap::new(),
            reason: None,
            model,
            usage_seen: false,
            pending: Vec::new().into_iter(),
            done: false,
        }
    }

    /// Folds one dispatched `data:` payload in.
    ///
    /// # Errors
    ///
    /// [`TextModelError::Transport`] for an in-stream error payload
    /// (`{"error": …}` — the head was 2xx, so the request was accepted but
    /// the answer died mid-generation: the same bucket as a connection cut
    /// off mid-body, the provider's own words in the detail) and for a
    /// payload that is neither JSON nor the sentinel.
    fn push(&mut self, data: &str) -> Result<Vec<TextDelta>, TextModelError> {
        if data.trim() == DONE_SENTINEL {
            return self.finish(true);
        }
        if let Ok(envelope) = serde_json::from_str::<ErrorEnvelope>(data)
            && envelope.error.is_some()
        {
            let error = TextModelError::Transport(format!(
                "the stream carried an error: {}",
                provider_message(data)
            ));
            tracing::warn!(
                provider = "openai-compatible",
                outcome = "failed",
                model = %self.model,
                error = %error,
                "text model outcome"
            );
            return Err(error);
        }
        let chunk: ChatChunk = serde_json::from_str(data).map_err(|err| {
            TextModelError::Transport(format!("stream chunk did not parse: {err}"))
        })?;
        if !chunk.model.is_empty() {
            self.model = chunk.model;
        }
        let mut deltas = Vec::new();
        // One choice per stream — the port sends no `n` — so each chunk is
        // the same choice's next piece. The choices-empty chunk is the
        // usage trailer `include_usage` asked for.
        if let Some(choice) = chunk.choices.first() {
            self.push_choice(choice, &mut deltas)?;
        }
        if let Some(usage) = chunk.usage {
            self.usage_seen = true;
            deltas.push(TextDelta::Usage {
                input_tokens: u64::from(usage.prompt_tokens),
                output_tokens: u64::from(usage.completion_tokens),
                // The same cache report `complete` reads, keeping "no
                // report" and "reported zero" distinct.
                cached_input_tokens: usage
                    .prompt_tokens_details
                    .map(|details| u64::from(details.cached_tokens)),
            });
        }
        Ok(deltas)
    }

    /// Folds one chunk's choice into `deltas`: refusal first (a declined
    /// prompt never reaches the caller as text), then text, reasoning,
    /// tool-call fragments, and the `finish_reason` the Finish delta waits
    /// for.
    ///
    /// # Errors
    ///
    /// [`TextModelError::Rejected`] for a refusal, as `complete`'s
    /// `refusal_guard` answers the buffered one.
    fn push_choice(
        &mut self,
        choice: &WireChunkChoice,
        deltas: &mut Vec<TextDelta>,
    ) -> Result<(), TextModelError> {
        if let Some(delta) = choice.delta.as_ref() {
            if let Some(refusal) = delta.refusal.as_deref().filter(|r| !r.is_empty()) {
                tracing::warn!(
                    provider = "openai-compatible",
                    outcome = "refused",
                    model = %self.model,
                    refusal = refusal,
                    "text model outcome"
                );
                return Err(TextModelError::Rejected(
                    "the model declined the prompt (refusal); the provider's words are in the log"
                        .to_owned(),
                ));
            }
            if let Some(text) = delta.content.as_deref().filter(|text| !text.is_empty()) {
                deltas.push(TextDelta::Text(text.to_owned()));
            }
            let reasoning = delta
                .reasoning_content
                .as_deref()
                .filter(|reasoning| !reasoning.is_empty())
                .or_else(|| {
                    delta
                        .reasoning
                        .as_deref()
                        .filter(|reasoning| !reasoning.is_empty())
                });
            if let Some(reasoning) = reasoning {
                deltas.push(TextDelta::Reasoning(reasoning.to_owned()));
            }
            for fragment in &delta.tool_calls {
                self.push_tool_call(deltas, fragment);
            }
        }
        if let Some(reason) = choice.finish_reason.as_deref() {
            self.reason = Some(finish_reason(reason));
        }
        Ok(())
    }

    /// Folds one tool-call fragment in. The first fragment carrying an id
    /// or a name opens the call with a [`TextDelta::ToolCallStarted`]; every
    /// argument text grows it with [`TextDelta::ToolCallArguments`]; the
    /// pieces accumulate in the wire shape [`parse_tool_call`] consumes, so
    /// the finished call is the call `complete` would return. A server that
    /// splits id and name across fragments gets its `Started` with whatever
    /// had arrived — the `Finished` call always carries both.
    fn push_tool_call(&mut self, deltas: &mut Vec<TextDelta>, fragment: &WireToolCallChunk) {
        // Only function calls exist on this wire; an entry naming another
        // `type` is skipped rather than misread as one, as in `complete`.
        match fragment.kind.as_deref() {
            None | Some("function") => {}
            Some(_) => return,
        }
        let acc = self.calls.entry(fragment.index).or_default();
        let mut named = false;
        if let Some(id) = fragment.id.as_deref() {
            id.clone_into(&mut acc.wire.id);
            named = true;
        }
        if let Some(kind) = fragment.kind.as_deref() {
            acc.wire.kind = Some(kind.to_owned());
        }
        if let Some(function) = fragment.function.as_ref() {
            let wire = acc.wire.function.get_or_insert_with(Default::default);
            if let Some(name) = function.name.as_deref() {
                name.clone_into(&mut wire.name);
                named = true;
            }
            if let Some(chunk) = function.arguments.as_deref().filter(|c| !c.is_empty()) {
                wire.arguments.push_str(chunk);
                deltas.push(TextDelta::ToolCallArguments {
                    index: fragment.index,
                    chunk: chunk.to_owned(),
                });
            }
        }
        if !acc.started && named {
            acc.started = true;
            deltas.push(TextDelta::ToolCallStarted {
                index: fragment.index,
                id: acc.wire.id.clone(),
                name: acc
                    .wire
                    .function
                    .as_ref()
                    .map(|function| function.name.clone())
                    .unwrap_or_default(),
            });
        }
    }

    /// The finish deltas, however the stream ended: each reassembled call
    /// in index order — parsed by the shared [`parse_tool_call`] — then the
    /// one `Finish`. `sentinel` says the `[DONE]` payload arrived and
    /// stands in for a `finish_reason` a server never sent; a stream with
    /// neither never finished at all.
    ///
    /// # Errors
    ///
    /// [`TextModelError::Transport`] when neither an ending nor a reason
    /// arrived, and the buffered path's [`TextModelError::Rejected`] where
    /// `complete` refuses, so a stream may not smuggle through what the
    /// buffered answer refuses: a `finish_reason` of `length` beside tool
    /// calls (arguments cut off mid-string must never reach an executor),
    /// and `content_filter` — both through the very errors
    /// `completion_from_response` raises, so `run_tool_loop` and
    /// `run_tool_loop_stream` answer an answer the server stopped
    /// identically.
    fn finish(&mut self, sentinel: bool) -> Result<Vec<TextDelta>, TextModelError> {
        self.done = true;
        if self.reason.is_none() && !sentinel {
            return Err(TextModelError::Transport(
                "the stream ended without a finish_reason or [DONE] sentinel".to_owned(),
            ));
        }
        // Parse first, decide second: the truncation rule reads on the
        // calls the parser would return, exactly as `complete`'s does.
        let calls: Vec<(usize, ToolCall)> = self
            .calls
            .iter()
            .filter_map(|(index, acc)| parse_tool_call(&acc.wire).map(|call| (*index, call)))
            .collect();
        if !calls.is_empty() && self.reason.as_ref() == Some(&FinishReason::Length) {
            return Err(TextModelError::Rejected(
                "the response was truncated at max_tokens before the tool call arguments were \
                 complete; a larger max_tokens is needed"
                    .to_owned(),
            ));
        }
        // The content filter stopped the answer: the same `Rejected`
        // `complete`'s `refusal_guard` returns for the same `finish_reason`,
        // not a successful `Finish{ContentFilter}` a caller could assemble
        // into the completion the buffered path refuses.
        if self.reason.as_ref() == Some(&FinishReason::ContentFilter) {
            return Err(content_filter_rejected(&self.model));
        }
        if !self.usage_seen {
            // Said out loud, not silent — the same warning the buffered
            // path gives a server that omits the usage block.
            tracing::warn!(
                provider = "openai-compatible",
                model = %self.model,
                "text model completed without a usage block; token counts default to zero"
            );
        }
        let tool_calls = calls.len();
        let mut deltas: Vec<TextDelta> = calls
            .into_iter()
            .map(|(index, call)| TextDelta::ToolCallFinished { index, call })
            .collect();
        deltas.push(TextDelta::Finish {
            reason: self.reason.clone().unwrap_or(FinishReason::Stop),
            model: self.model.clone(),
        });
        tracing::info!(
            provider = "openai-compatible",
            outcome = "completed",
            model = %self.model,
            tool_calls,
            "text model outcome"
        );
        Ok(deltas)
    }
}

/// The unfold state of a native stream: sending the head, folding the body,
/// or fused after an error.
enum StreamPhase {
    Head,
    Body(Fold),
    Done,
}

/// Drains a non-2xx body for the error mapping, stopping at `cap` — the
/// buffered path's own ceiling, read off the request before it was sent. An
/// error page's worth of bytes is all [`OpenAiCompatible::map_status`] can
/// read; more arrives as a stream and must not outrun the bound.
async fn collect_bounded(mut body: ByteStream, cap: usize) -> String {
    let mut bytes = Vec::new();
    while bytes.len() < cap {
        match body.next().await {
            Some(Ok(chunk)) => bytes.extend_from_slice(&chunk),
            // The body's own error ends the drain: what arrived so far is
            // still something to log and map.
            Some(Err(_)) | None => break,
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}

#[async_trait]
impl TextModel for OpenAiCompatible {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError> {
        // Outcome logging in the Anthropic adapter's shape: provider,
        // status, outcome, model, token counts. The API key is never
        // logged, and neither is the prompt nor the completion — a prompt
        // is user content, and the operator needs none of it to see what
        // happened. The pre-flight refusals live in `preflight`, shared
        // with the streaming half of the port.
        let api_key = self.preflight(prompt)?;

        let payload = wire_request(&self.model, prompt)?;
        let request = self.frame(api_key, &payload)?;

        let response = self
            .http
            .send(request)
            .await
            .map_err(|err: HttpError| TextModelError::Transport(err.to_string()))?;

        let status = response.status();
        // One parser for both `Retry-After` forms (issue #214/#278); the
        // date form needs the clock this adapter is constructed with.
        let retry_after = retry_after(response.headers(), self.clock.as_ref());
        let text = String::from_utf8_lossy(response.body()).to_string();

        if !status.is_success() {
            let error = Self::map_status(status, &text, retry_after);
            tracing::warn!(
                provider = "openai-compatible",
                code = status.as_u16(),
                outcome = "failed",
                model = %self.model,
                error = %error,
                "text model outcome"
            );
            return Err(error);
        }

        // A 2xx body that does not parse is not a "rejected": nothing about
        // the prompt was refused, the answer just never arrived in usable
        // form — the same bucket as a cut-off connection.
        let parsed: ChatCompletionsResponse = serde_json::from_str(&text).map_err(|err| {
            TextModelError::Transport(format!("model response did not parse: {err}"))
        })?;
        let completion = self.completion_from_response(parsed, prompt)?;

        tracing::info!(
            provider = "openai-compatible",
            code = status.as_u16(),
            outcome = "completed",
            model = %completion.model,
            input_tokens = completion.input_tokens,
            output_tokens = completion.output_tokens,
            tool_calls = completion.tool_calls.len(),
            "text model outcome"
        );
        Ok(completion)
    }

    /// Streams `prompt` over the same wire with `stream: true` and
    /// `include_usage` (issue #859): the request `complete` builds plus the
    /// two streaming fields, the head under the same [`HttpPolicy`] and the
    /// body under the port's default
    /// [`StreamPolicy`](cratefield_core::StreamPolicy) — the adapter
    /// tightens nothing, and a runtime wrapping the client clamps as
    /// always. A prompt asking for structured output does not stream
    /// natively; it takes the buffered fallback (`stream_buffered`).
    ///
    /// # Cancellation
    ///
    /// The returned stream is the only holder of the response body: one
    /// `unfold` state machine owns head-then-body, so dropping the stream
    /// drops the body and with it the upstream exchange — the contract
    /// [`HttpClient::send_streaming`] carries. Nothing is spawned; nothing
    /// outlives the stream.
    fn stream<'a>(
        &'a self,
        prompt: &'a Prompt,
    ) -> BoxStream<'a, Result<TextDelta, TextModelError>> {
        if prompt.json_schema.is_some() {
            return self.stream_buffered(prompt);
        }
        Box::pin(futures_util::stream::unfold(
            StreamPhase::Head,
            move |mut phase| async move {
                loop {
                    match phase {
                        StreamPhase::Head => {
                            phase = match self.stream_head(prompt).await {
                                Ok(fold) => StreamPhase::Body(fold),
                                Err(err) => return Some((Err(err), StreamPhase::Done)),
                            };
                        }
                        StreamPhase::Body(mut fold) => {
                            if let Some(delta) = fold.pending.next() {
                                return Some((Ok(delta), StreamPhase::Body(fold)));
                            }
                            if fold.done {
                                return None;
                            }
                            match fold.events.next().await {
                                Some(Ok(event)) => match fold.push(&event.data) {
                                    Ok(deltas) => fold.pending = deltas.into_iter(),
                                    Err(err) => return Some((Err(err), StreamPhase::Done)),
                                },
                                Some(Err(err)) => {
                                    // The body's error is the stream's error,
                                    // and the body drops here, cancelling the
                                    // upstream.
                                    return Some((
                                        Err(TextModelError::Transport(err.to_string())),
                                        StreamPhase::Done,
                                    ));
                                }
                                None => match fold.finish(false) {
                                    // End of body. A server that sent a
                                    // finish_reason (and its usage chunk) but
                                    // omitted the `[DONE]` sentinel still
                                    // finished; anything else is an answer
                                    // that never completed.
                                    Ok(deltas) => fold.pending = deltas.into_iter(),
                                    Err(err) => return Some((Err(err), StreamPhase::Done)),
                                },
                            }
                            phase = StreamPhase::Body(fold);
                        }
                        StreamPhase::Done => return None,
                    }
                }
            },
        ))
    }

    fn supports(&self, _tier: ModelTier, capability: Capability) -> bool {
        // The wire speaks function calling, so tools are on unless the
        // deployment turned them off; it speaks images too, but a model
        // behind it may not have vision, so images are off until the
        // deployment opts in. `Capability` is `#[non_exhaustive]`: an
        // unknown capability is one this adapter does not claim. The tier is
        // the router's routing key; this adapter serves whatever tier it is
        // wired for, so it is ignored.
        (capability == Capability::Tools && self.tools)
            || (capability == Capability::Images && self.images)
    }
}

impl OpenAiCompatible {
    /// Sends the streaming request: the shared pre-flight, the shared
    /// request builder with the two streaming fields turned on, the head
    /// bounded by the same [`HttpPolicy`] deadline `send` answers under. A
    /// 2xx head hands back the fold the body is consumed through; a non-2xx
    /// one collects its (bounded) body and maps exactly as `complete` does.
    async fn stream_head(&self, prompt: &Prompt) -> Result<Fold, TextModelError> {
        let api_key = self.preflight(prompt)?;
        let mut payload = wire_request(&self.model, prompt)?;
        payload.stream = true;
        payload.stream_options = Some(WireStreamOptions {
            include_usage: true,
        });
        let request = self.frame(api_key, &payload)?;
        // The head is bounded by the policy the buffered request carries;
        // the error path reuses its cap for the body it drains.
        let cap = HttpPolicy::of_request(&request).max_response_bytes;

        let response = self
            .http
            .send_streaming(request)
            .await
            .map_err(|err: HttpError| TextModelError::Transport(err.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            // One parser for both `Retry-After` forms (issue #214/#278), as
            // on the buffered path.
            let retry_after = retry_after(response.headers(), self.clock.as_ref());
            let text = collect_bounded(response.into_body(), cap).await;
            let error = Self::map_status(status, &text, retry_after);
            tracing::warn!(
                provider = "openai-compatible",
                code = status.as_u16(),
                outcome = "failed",
                model = %self.model,
                error = %error,
                "text model outcome"
            );
            return Err(error);
        }

        Ok(Fold::new(
            sse::sse_events(response.into_body()),
            self.model.clone(),
        ))
    }

    /// The buffered fallback for the one shape a chunk stream cannot carry:
    /// a prompt with [`Prompt::json_schema`] — structured output is a
    /// buffered feature, because [`Completion::json`] needs the whole
    /// answer to validate against the prompt's schema, which a stream that
    /// relayed itself away never promised (see `CompletionBuilder`). One
    /// `complete` round trip, decomposed by
    /// [`completion_deltas`](cratefield_core::completion_deltas) — the
    /// port's default `stream`, written out here because a default trait
    /// body cannot be called from an override.
    fn stream_buffered<'a>(
        &'a self,
        prompt: &'a Prompt,
    ) -> BoxStream<'a, Result<TextDelta, TextModelError>> {
        Box::pin(
            futures_util::stream::once(self.complete(prompt)).flat_map(|outcome| {
                futures_util::stream::iter(match outcome {
                    Ok(completion) => completion_deltas(&completion)
                        .into_iter()
                        .map(Ok)
                        .collect::<Vec<_>>(),
                    Err(err) => vec![Err(err)],
                })
            }),
        )
    }

    /// Turns a parsed success body into a [`Completion`]: the first choice's
    /// text, its tool calls, the parsed schema-shaped JSON where the prompt
    /// asked for it, and the usage. Every refusal that arrives inside a 200
    /// — the model's own, the content filter, a truncated tool call — is a
    /// `Rejected` error, decided here.
    fn completion_from_response(
        &self,
        parsed: ChatCompletionsResponse,
        prompt: &Prompt,
    ) -> Result<Completion, TextModelError> {
        // One choice per completion — the port sends no `n`. A well-formed
        // envelope with no choice is the JSON path breaking between the
        // server and here, not a refusal (that would have been a 4xx).
        let choice = parsed.choices.first().ok_or_else(|| {
            TextModelError::Transport("model response came back without a choice".to_owned())
        })?;
        if let Some(error) = refusal_guard(choice, &self.model) {
            return Err(error);
        }
        let content = choice
            .message
            .as_ref()
            .and_then(|message| message.content.clone())
            .unwrap_or_default();
        let tool_calls = parse_tool_calls(choice.message.as_ref());

        // `finish_reason: "length"` with tool calls means the arguments were
        // cut off mid-string; such a call must never reach an executor.
        // `Rejected`, not `Transient`: retrying the identical request
        // truncates identically.
        if !tool_calls.is_empty() && choice.finish_reason.as_deref() == Some("length") {
            return Err(TextModelError::Rejected(
                "the response was truncated at max_tokens before the tool call arguments were \
                 complete; a larger max_tokens is needed"
                    .to_owned(),
            ));
        }

        let mut json = None;
        // A tool-calling answer is not the schema-shaped answer a
        // `response_format` asked for — its content is `null` — so the JSON
        // path stands down while the model is still choosing a tool. The
        // final, tool-free answer is parsed as before.
        if prompt.json_schema.is_some() && tool_calls.is_empty() {
            // `finish_reason: "length"` cut the schema-shaped JSON off
            // mid-string — returning the fragment as a schema-shaped
            // success would be a lie. `Rejected`, not `Transient`: retrying
            // the identical request truncates identically; only a larger
            // `max_tokens` changes the outcome. (The Anthropic adapter
            // draws the same line on its `stop_reason`.)
            if choice.finish_reason.as_deref() == Some("length") {
                return Err(TextModelError::Rejected(
                    "the response was truncated at max_tokens before the schema-shaped \
                     result was complete; a larger max_tokens is needed"
                        .to_owned(),
                ));
            }
            // A server that ignored `response_format` answers in prose. That
            // is not a transport failure: the raw content rides in `text`
            // with no parsed value, and the port's `complete_json` parses it
            // (stripping a fence), validates it and repairs it if it does not
            // conform — the same fallback a provider without native
            // structured output takes.
            if let Ok(parsed_json) = serde_json::from_str(&content) {
                json = Some(parsed_json);
            }
        }

        // A server that answers without a `usage` block still completes,
        // with the counts defaulting to zero — said out loud, not silent.
        let usage = reported_usage(parsed.usage, &self.model);
        let model = if parsed.model.is_empty() {
            self.model.clone()
        } else {
            parsed.model
        };
        let mut completion = Completion::new(content, model).usage(
            u64::from(usage.prompt_tokens),
            u64::from(usage.completion_tokens),
        );
        if !tool_calls.is_empty() {
            completion = completion.tool_calls(tool_calls);
        }
        if let Some(cached) = usage.prompt_tokens_details {
            completion = completion.cached_input_tokens(u64::from(cached.cached_tokens));
        }
        if let Some(json) = json {
            completion = completion.json(json);
        }
        Ok(completion)
    }
}
