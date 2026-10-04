//! `cratefield-adapter-anthropic`: the minimal [`TextModel`] port over the
//! Anthropic Messages API (issue #430). Uses the runtime's [`HttpClient`]
//! port — no `reqwest`, no vendor SDK — so the same adapter runs on
//! Workers and natively, and inherits that port's destination vetting,
//! deadline and response-size caps.
//!
//! **Degraded mode.** When the API key is absent the adapter answers
//! [`TextModelError::NotConfigured`] without any network call, so a
//! pipeline stage can degrade instead of breaking.
//!
//! **Tools** (issue #665): [`Prompt::tools`] travel as the Messages API's
//! `tools` array, [`Prompt::tool_choice`] as its `tool_choice`, and the
//! answer's `tool_use` blocks come back as [`Completion::tool_calls`]. A
//! turn built with [`Turn::assistant_tool_calls`] or
//! [`Turn::tool_results`] is sent as the content-block array the API
//! requires; every other turn keeps the bare-string content it always sent.
//! [`Anthropic::supports`] reports [`Capability::Tools`]. A prompt that
//! carries both [`Prompt::json_schema`] and its own tools is refused with
//! [`TextModelError::Rejected`] before any request.
//!
//! **Images** (issue #628): a turn built with [`Turn::user_parts`] is sent
//! as the content-block array the Messages API requires — each [`Part`] as
//! a `text` block or an inline base64 `image` block, in order — and
//! [`Anthropic::supports`] reports [`Capability::Images`], because every
//! current Claude model accepts image input. An over-limit prompt is
//! refused by [`Prompt::check_images`] before any network call.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Capability, Clock, Completion, HttpClient, HttpError, HttpPolicy, MAX_RESPONSE_BYTES,
    MAX_RESPONSE_TIMEOUT, ModelTier, Part, Prompt, Role, TextModel, TextModelError, ToolCall,
    ToolChoice, Turn, encode_image, retry_after,
};
use http::header::CONTENT_TYPE;
use http::{Request, StatusCode};
use std::sync::Arc;
use std::time::Duration;

const MESSAGES_ENDPOINT: &str = "https://api.anthropic.com/v1/messages";

/// The `anthropic-version` header value the Messages API requires on every
/// call. `2023-06-01` is the GA version date the API documents as the
/// required value; features arrive behind request fields, not versions.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The model [`Anthropic::from_env`] uses when `ANTHROPIC_MODEL` is unset:
/// the current most-capable Claude 5 model id. The Messages API takes
/// exact ids — no date suffixes. Overriding it has a catch: the JSON path
/// forces `tool_choice: {"type":"tool"}`, and a model that rejects a
/// forced tool choice makes every `json_schema` call come back a 400
/// [`TextModelError::Rejected`].
pub const DEFAULT_MODEL: &str = "claude-opus-5";

/// The single tool the JSON path declares; its input schema is the
/// caller's [`Prompt::json_schema`], and forcing it is how a completion
/// comes back as JSON without the adapter parsing it out of prose.
const JSON_TOOL_NAME: &str = "respond";
const JSON_TOOL_DESCRIPTION: &str =
    "Return the completion as JSON matching the provided schema exactly.";

/// The Anthropic `TextModel` over `POST https://api.anthropic.com/v1/messages`.
pub struct Anthropic {
    http: Arc<dyn HttpClient>,
    /// Needed only to read the HTTP-date form of `Retry-After` (issue #278).
    /// A constructor argument rather than a builder default so a deployment
    /// that forgets it fails to compile instead of silently retrying a
    /// date-form 429 immediately.
    clock: Arc<dyn Clock>,
    api_key: Option<String>,
    model: String,
}

impl Anthropic {
    /// `api_key: None` => every call is [`TextModelError::NotConfigured`]
    /// (no network).
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
        }
    }

    /// Reads `ANTHROPIC_API_KEY` and `ANTHROPIC_MODEL` (default
    /// [`DEFAULT_MODEL`]) from the process environment. On Workers the
    /// venture should read the secrets from its `Env` and use
    /// [`Anthropic::new`] instead (`std::env` has no Workers vars).
    pub fn from_env(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self::new(
            http,
            clock,
            std::env::var("ANTHROPIC_API_KEY").ok(),
            std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_owned()),
        )
    }

    /// Status → port error, the one place the provider's taxonomy meets
    /// ours. The provider's error envelope
    /// (`{"type":"error","error":{"type":…,"message":…}}`) is parsed once
    /// for its message; the raw body is the fallback, so a proxy's HTML
    /// error page still leaves the caller something to log.
    fn map_status(status: StatusCode, body: &str, retry_after: Option<Duration>) -> TextModelError {
        let detail = provider_message(body);
        match status {
            // "Later", in both shapes the provider says it: an explicit
            // rate limit (its `Retry-After` honoured in both RFC 9110
            // forms, through core's parser) and a server on its side.
            StatusCode::TOO_MANY_REQUESTS => TextModelError::Transient { retry_after },
            status if status.is_server_error() => TextModelError::Transient { retry_after: None },
            // The provider refused the request itself: 400 a malformed or
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
            // is not available to this org; 413: the prompt is too large).
            status if status.is_client_error() => TextModelError::Rejected(detail),
            // Redirects and anything unmodelled: the call did not complete.
            _ => TextModelError::Transport(format!("unexpected status {status}: {detail}")),
        }
    }
}

const fn wire_role(role: Role) -> &'static str {
    match role {
        Role::User => "user",
        Role::Assistant => "assistant",
    }
}

#[derive(serde::Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<&'a str>,
    messages: Vec<WireTurn<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<WireTool<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<WireToolChoice<'a>>,
}

/// One message on the wire. `content` is the bare string the adapter has
/// always sent for a turn that carries neither tool calls nor tool results,
/// and the content-block array the Messages API needs for the tool turns
/// (issue #665).
#[derive(serde::Serialize)]
struct WireTurn<'a> {
    role: &'static str,
    content: WireContent<'a>,
}

/// A turn's content: a bare string, or the block array a tool turn needs.
/// `untagged` so the plain form stays exactly the string it was before
/// tools existed — no existing request shape changes.
#[derive(serde::Serialize)]
#[serde(untagged)]
enum WireContent<'a> {
    Text(&'a str),
    Blocks(Vec<WireBlock<'a>>),
}

/// One content block of a tool or image turn.
#[derive(serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireBlock<'a> {
    /// The model's own words alongside (or answering) tool calls, or one
    /// text [`Part`] of a parts-bearing turn (issue #628).
    Text { text: &'a str },
    /// An inline image [`Part`] (issue #628): the base64 source the
    /// Messages API expects.
    Image { source: WireImageSource },
    /// A call the assistant asked for, read back as a previous turn.
    ToolUse {
        id: &'a str,
        name: &'a str,
        input: &'a serde_json::Value,
    },
    /// The result a user turn carries back for one call.
    ToolResult {
        tool_use_id: &'a str,
        content: &'a str,
        // A successful result omits `is_error`, matching the documented
        // shape; only a tool-level failure carries it.
        #[serde(skip_serializing_if = "is_false")]
        is_error: bool,
    },
}

/// The `source` of an inline image block (issue #628): the base64 payload
/// and media type the Messages API documents for an inline image. `data` is
/// owned because the encoding is built here from the part's raw bytes.
#[derive(serde::Serialize)]
struct WireImageSource {
    #[serde(rename = "type")]
    kind: &'static str,
    media_type: &'static str,
    data: String,
}

/// `skip_serializing_if` for the `is_error` flag. Serde passes the field by
/// reference, so the signature is fixed even though a `bool` is `Copy`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(serde::Serialize)]
struct WireTool<'a> {
    name: &'a str,
    description: &'a str,
    input_schema: &'a serde_json::Value,
}

/// The `tool_choice` wire shape: a `type` always, a `name` only for the
/// `tool` form that pins one tool.
#[derive(serde::Serialize)]
struct WireToolChoice<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

/// Maps the port's [`ToolChoice`] onto the Messages wire. The port's enum
/// is `#[non_exhaustive]`; a choice this adapter does not know falls back
/// to the provider's own default, `auto`.
fn wire_tool_choice(choice: &ToolChoice) -> WireToolChoice<'_> {
    let (kind, name) = match choice {
        ToolChoice::None => ("none", None),
        ToolChoice::Required => ("any", None),
        ToolChoice::Tool(name) => ("tool", Some(name.as_str())),
        // `Auto`, and any future variant this adapter does not know: the
        // provider's own default.
        _ => ("auto", None),
    };
    WireToolChoice { kind, name }
}

/// Serialises one turn. A turn carrying no parts, no tool calls and no tool
/// results keeps its old shape exactly — `content` as a bare string. Every
/// other turn becomes the content-block array the Messages API requires:
/// the turn's [`Part`]s in order (issue #628), then, for a tool turn, the
/// text block (only when non-empty) and the `tool_use`/`tool_result` blocks.
///
/// # Errors
///
/// [`TextModelError::Rejected`] when a part is a variant this adapter was
/// never taught to send: [`Part`] is `#[non_exhaustive]`, and a prompt is
/// refused rather than sent with a part silently dropped.
fn wire_turn(turn: &Turn) -> Result<WireTurn<'_>, TextModelError> {
    let role = wire_role(turn.role);
    if turn.parts.is_empty() && turn.tool_calls.is_empty() && turn.tool_results.is_empty() {
        return Ok(WireTurn {
            role,
            content: WireContent::Text(turn.content.as_str()),
        });
    }

    let mut blocks =
        Vec::with_capacity(turn.parts.len() + turn.tool_calls.len() + turn.tool_results.len() + 1);
    // The parts a caller built with `Turn::user_parts` travel in order —
    // text and image interleaved exactly as given.
    for part in &turn.parts {
        match part {
            Part::Text(text) => blocks.push(WireBlock::Text {
                text: text.as_str(),
            }),
            Part::Image { media_type, bytes } => blocks.push(WireBlock::Image {
                source: WireImageSource {
                    kind: "base64",
                    media_type: media_type.as_str(),
                    data: encode_image(bytes),
                },
            }),
            // `Part` is `#[non_exhaustive]`: a variant this adapter has not
            // been taught to serialise is refused rather than dropped, the
            // same "never silently drop" rule. Not `Unsupported`: no
            // capability names an unknown content kind.
            _ => {
                return Err(TextModelError::Rejected(
                    "the prompt carries a content part this adapter does not know how to send"
                        .to_owned(),
                ));
            }
        }
    }
    if !turn.tool_calls.is_empty() && !turn.content.is_empty() {
        blocks.push(WireBlock::Text {
            text: turn.content.as_str(),
        });
    }
    for call in &turn.tool_calls {
        blocks.push(WireBlock::ToolUse {
            id: call.id.as_str(),
            name: call.name.as_str(),
            input: &call.arguments,
        });
    }
    for result in &turn.tool_results {
        blocks.push(WireBlock::ToolResult {
            tool_use_id: result.tool_call_id.as_str(),
            content: result.content.as_str(),
            is_error: result.is_error,
        });
    }
    if !turn.tool_results.is_empty() && !turn.content.is_empty() {
        blocks.push(WireBlock::Text {
            text: turn.content.as_str(),
        });
    }

    Ok(WireTurn {
        role,
        content: WireContent::Blocks(blocks),
    })
}

/// Builds the wire body: a single forced tool — input schema = the caller's
/// — when a schema was asked for; the caller's own `tools` and `tool_choice`
/// when tools were offered; plain text otherwise. Hand-rolling this JSON
/// would be a second escaping bug waiting to happen; the prompt is user
/// content.
///
/// A prompt that carries both a [`Prompt::json_schema`] and its own
/// [`Prompt::tools`] is [`TextModelError::Rejected`]: the schema path
/// already declares a synthetic forced tool of its own, so the two would
/// collide on the same request (issue #665). A turn carrying a [`Part`]
/// this adapter cannot serialise is refused the same way, by
/// [`wire_turn`].
fn wire_request<'a>(
    model: &'a str,
    prompt: &'a Prompt,
) -> Result<MessagesRequest<'a>, TextModelError> {
    if prompt.json_schema.is_some() && !prompt.tools.is_empty() {
        return Err(TextModelError::Rejected(
            "a prompt cannot carry both json_schema and tools: the json_schema path already \
             declares a forced tool of its own, so the two would collide"
                .to_owned(),
        ));
    }

    let (tools, tool_choice): (Vec<WireTool<'a>>, Option<WireToolChoice<'a>>) =
        match prompt.json_schema.as_ref() {
            Some(schema) => (
                vec![WireTool {
                    name: JSON_TOOL_NAME,
                    description: JSON_TOOL_DESCRIPTION,
                    input_schema: schema,
                }],
                Some(WireToolChoice {
                    kind: "tool",
                    name: Some(JSON_TOOL_NAME),
                }),
            ),
            None => (
                prompt
                    .tools
                    .iter()
                    .map(|tool| WireTool {
                        name: tool.name.as_str(),
                        description: tool.description.as_str(),
                        input_schema: &tool.parameters,
                    })
                    .collect(),
                prompt.tool_choice.as_ref().map(wire_tool_choice),
            ),
        };

    Ok(MessagesRequest {
        model,
        max_tokens: prompt.max_tokens,
        system: prompt.system.as_deref(),
        messages: prompt
            .messages
            .iter()
            .map(wire_turn)
            .collect::<Result<Vec<_>, _>>()?,
        tools,
        tool_choice,
    })
}

#[derive(serde::Deserialize)]
struct MessagesResponse {
    #[serde(default)]
    model: String,
    #[serde(default)]
    content: Vec<ContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

/// The content blocks the port has a use for. `thinking`,
/// `redacted_thinking`, server-tool results and whatever ships next parse
/// as [`ContentBlock::Other`] rather than refusing the whole response —
/// the adapter was never asked to produce them.
#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(other)]
    Other,
}

// The field names are the provider's wire names, kept verbatim so the
// struct reads against the Messages API reference; the shared `_tokens`
// postfix is theirs, not ours.
#[allow(clippy::struct_field_names)]
#[derive(serde::Deserialize, Default, Clone, Copy)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
    /// Prompt tokens served from the provider's prompt cache (issue #560):
    /// absent unless the call actually read one. Reported separately from
    /// `input_tokens` — the wire's `input_tokens` counts only the
    /// uncached remainder.
    #[serde(default)]
    cache_read_input_tokens: Option<u32>,
    /// Prompt tokens the call wrote into the provider's cache, billed as
    /// input: absent unless the call cached something new.
    #[serde(default)]
    cache_creation_input_tokens: Option<u32>,
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

/// The wire's split prompt — the uncached remainder, cache writes (billed
/// as input) and cache reads — summed into the port's one total plus the
/// cached subset (issue #560). The port wants every completion's
/// `input_tokens` to be the total the provider processed; only the read
/// half is `cached_input_tokens`, because only a read was *served* from
/// the cache.
fn reported_usage(usage: WireUsage) -> (u64, u64, Option<u64>) {
    let input_tokens = usage
        .input_tokens
        .saturating_add(usage.cache_creation_input_tokens.unwrap_or_default())
        .saturating_add(usage.cache_read_input_tokens.unwrap_or_default());
    (
        u64::from(input_tokens),
        u64::from(usage.output_tokens),
        usage.cache_read_input_tokens.map(u64::from),
    )
}

/// Reads a parsed answer into the port's three content shapes: the joined
/// text, the forced tool's input on the schema path, and the calls the model
/// asked for on every other path (issue #665). The schema path's truncation
/// and missing-block guards live here because they depend on what the blocks
/// turned out to be.
///
/// The text may be empty when the model only calls tools, and that is not an
/// error.
fn interpret_content(
    prompt: &Prompt,
    parsed: &MessagesResponse,
) -> Result<(String, Option<serde_json::Value>, Vec<ToolCall>), TextModelError> {
    let mut text = String::new();
    let mut json = None;
    let mut tool_calls = Vec::new();
    for block in &parsed.content {
        match block {
            ContentBlock::Text { text: block_text } => text.push_str(block_text),
            // On the schema path the forced tool's input is the answer; on
            // every other path a `tool_use` block is a call the model asked
            // for, collected in the order the model named them. A response
            // the adapter never asked for tools on can still carry one, and
            // it is a call either way.
            ContentBlock::ToolUse { id, name, input } => {
                if prompt.json_schema.is_some() {
                    json = Some(input.clone());
                } else {
                    tool_calls.push(ToolCall::new(id.clone(), name.clone(), input.clone()));
                }
            }
            ContentBlock::Other => {}
        }
    }

    if prompt.json_schema.is_some() {
        // `max_tokens` can cut the forced tool call off mid-JSON, leaving
        // `input` empty or partial (a JSON `null` parses to `Value::Null`
        // here) — returning that as a schema-shaped success would be a lie.
        // `Rejected`, not `Transient`: retrying the identical request
        // truncates identically; only a larger `max_tokens` changes the
        // outcome.
        if parsed.stop_reason.as_deref() == Some("max_tokens") {
            return Err(TextModelError::Rejected(
                "the response was truncated at max_tokens before the schema-shaped \
                 result was complete; a larger max_tokens is needed"
                    .to_owned(),
            ));
        }
        // Forced tool use was the whole point of the call. A response without
        // the tool block is not a refusal (that would have been a 4xx) and
        // not an empty answer — the JSON path broke between provider and
        // here, which is a transport failure.
        if json.is_none() {
            return Err(TextModelError::Transport(
                "forced tool call came back without a tool_use block".to_owned(),
            ));
        }
    } else {
        // No schema was requested; `json` stays `None` even if the provider
        // somehow answered with a tool block — on this path a tool block is a
        // call, not a structured answer. A text completion cut off by
        // `max_tokens` is still a useful answer, so it is returned as-is. A
        // *tool* call cut off at `max_tokens` is not: its `input` may be
        // partial, and handing that to an executor is exactly what the schema
        // check downstream exists to prevent. `Rejected`, not `Transient`:
        // retrying the identical request truncates identically.
        json = None;
        if parsed.stop_reason.as_deref() == Some("max_tokens") && !tool_calls.is_empty() {
            return Err(TextModelError::Rejected(
                "the response was truncated at max_tokens before the tool call's arguments \
                 were complete; a larger max_tokens is needed"
                    .to_owned(),
            ));
        }
    }

    Ok((text, json, tool_calls))
}

#[async_trait]
impl TextModel for Anthropic {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError> {
        // An over-limit image prompt is refused before anything is built or
        // sent: the limits are about the request a provider would be handed
        // (issue #628).
        prompt.check_images()?;

        // Outcome logging in the resend adapter's shape: provider, status,
        // outcome, model, token counts. The API key is never logged, and
        // neither is the prompt nor the completion — a prompt is user
        // content, and the operator needs none of it to see what happened.
        let Some(api_key) = &self.api_key else {
            tracing::info!(
                provider = "anthropic",
                outcome = "not_configured",
                model = %self.model,
                "text model outcome"
            );
            return Err(TextModelError::NotConfigured);
        };

        let payload = wire_request(&self.model, prompt)?;
        let body = serde_json::to_vec(&payload)
            .map_err(|err| TextModelError::Transport(err.to_string()))?;

        let mut request = Request::builder()
            .method(http::Method::POST)
            .uri(MESSAGES_ENDPOINT)
            .header(CONTENT_TYPE, "application/json")
            .header("x-api-key", api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .body(Bytes::from(body))
            .map_err(|err| TextModelError::Transport(err.to_string()))?;
        // The caps are the design (issue #430). The port's default 10 s
        // deadline is a model call's normal case, not its tail, so the
        // adapter asks for the port ceiling — 30 s, the most a Worker
        // request can responsibly spend on one upstream — and keeps the
        // port's body cap. `HttpPolicy::clamped` can only tighten, so this
        // is also the widest request any caller can get through the
        // adapter. The consequences are deliberate: keep `max_tokens`
        // modest (a body over the cap is refused, not truncated), one
        // model call per pipeline stage, and a timeout surfaces as
        // `Transport` for the caller to judge — no retry happens in here.
        // Resend attaches no policy; this one does, on purpose.
        request.extensions_mut().insert(HttpPolicy {
            timeout: MAX_RESPONSE_TIMEOUT,
            max_response_bytes: MAX_RESPONSE_BYTES,
        });

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
                provider = "anthropic",
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
        let parsed: MessagesResponse = serde_json::from_str(&text).map_err(|err| {
            TextModelError::Transport(format!("model response did not parse: {err}"))
        })?;

        let (completion_text, json, tool_calls) = interpret_content(prompt, &parsed)?;

        // `Completion` is non-exhaustive and carries the counts flat, so
        // the wire's usage block is unwrapped straight onto the builder
        // rather than rebuilt as a struct of its own.
        let (input_tokens, output_tokens, cached_input_tokens) =
            reported_usage(parsed.usage.unwrap_or_default());
        let model = if parsed.model.is_empty() {
            self.model.clone()
        } else {
            parsed.model
        };
        tracing::info!(
            provider = "anthropic",
            code = status.as_u16(),
            outcome = "completed",
            model = %model,
            input_tokens,
            output_tokens,
            "text model outcome"
        );
        let mut completion =
            Completion::new(completion_text, model).usage(input_tokens, output_tokens);
        if let Some(cached_input_tokens) = cached_input_tokens {
            completion = completion.cached_input_tokens(cached_input_tokens);
        }
        if let Some(json) = json {
            completion = completion.json(json);
        }
        if !tool_calls.is_empty() {
            completion = completion.tool_calls(tool_calls);
        }
        Ok(completion)
    }

    fn supports(&self, _tier: ModelTier, capability: Capability) -> bool {
        // The Messages API carries tools and inline images, so this adapter
        // does both — and nothing else. Every current Claude model accepts
        // image input, so `Images` is reported for whatever model id this
        // adapter was constructed with. The tier is the router's routing key
        // and is ignored; `Capability` is `#[non_exhaustive]`, so an
        // unclaimed capability stays "no".
        matches!(capability, Capability::Tools | Capability::Images)
    }
}
