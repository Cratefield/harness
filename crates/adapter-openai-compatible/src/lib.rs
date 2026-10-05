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

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Capability, Clock, Completion, HttpClient, HttpError, HttpPolicy, MAX_RESPONSE_BYTES,
    MAX_RESPONSE_TIMEOUT, ModelTier, Prompt, Role, TextModel, TextModelError, ToolCall, ToolChoice,
    ToolResult, Turn, retry_after,
};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

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
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<WireToolCall>>,
    /// Set on a `role: "tool"` message: which call it answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
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
#[derive(serde::Serialize, serde::Deserialize)]
struct WireToolCall {
    #[serde(default)]
    id: String,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    function: Option<WireFunctionCall>,
}

#[derive(serde::Serialize, serde::Deserialize)]
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

/// Appends the wire message(s) one [`Turn`] becomes: a plain message, an
/// assistant message that quotes its `tool_calls`, or one `role: "tool"`
/// message per result — followed by a user message when a tool-results turn
/// also carries text of its own.
fn push_turn(messages: &mut Vec<WireMessage>, turn: &Turn) {
    match turn.role {
        Role::Assistant if !turn.tool_calls.is_empty() => {
            messages.push(WireMessage {
                role: "assistant",
                // A call-only turn has no text; the wire wants `null` for it,
                // not an empty string.
                content: (!turn.content.is_empty()).then(|| turn.content.clone()),
                tool_calls: Some(turn.tool_calls.iter().map(wire_tool_call).collect()),
                tool_call_id: None,
            });
        }
        Role::User if !turn.tool_results.is_empty() => {
            for result in &turn.tool_results {
                messages.push(WireMessage {
                    role: "tool",
                    content: Some(wire_tool_result(result)),
                    tool_calls: None,
                    tool_call_id: Some(result.tool_call_id.clone()),
                });
            }
            if !turn.content.is_empty() {
                messages.push(WireMessage {
                    role: "user",
                    content: Some(turn.content.clone()),
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
        }
        _ => messages.push(WireMessage {
            role: wire_role(turn.role),
            content: Some(turn.content.clone()),
            tool_calls: None,
            tool_call_id: None,
        }),
    }
}

/// Builds the wire body: the messages plus, when the prompt asked for them,
/// a `response_format` carrying the caller's schema, the `tools` array and
/// the `tool_choice`. Hand-rolling this JSON would be a second escaping bug
/// waiting to happen; the prompt is user content.
fn wire_request<'a>(model: &'a str, prompt: &'a Prompt) -> ChatCompletionsRequest<'a> {
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
            content: Some(system.to_owned()),
            tool_calls: None,
            tool_call_id: None,
        });
    }
    for turn in &prompt.messages {
        push_turn(&mut messages, turn);
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
    ChatCompletionsRequest {
        model,
        max_tokens: prompt.max_tokens,
        messages,
        response_format,
        tools,
        tool_choice: prompt.tool_choice.as_ref().and_then(wire_tool_choice),
    }
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
    // path. `Rejected`, not `Transient`: the prompt is what tripped it,
    // so retrying unchanged fails the same way.
    if choice.finish_reason.as_deref() == Some("content_filter") {
        tracing::warn!(
            provider = "openai-compatible",
            outcome = "content_filter",
            model = %model,
            "text model outcome"
        );
        return Some(TextModelError::Rejected(
            "the server's content filter stopped the answer".to_owned(),
        ));
    }
    None
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

#[async_trait]
impl TextModel for OpenAiCompatible {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError> {
        // Outcome logging in the Anthropic adapter's shape: provider,
        // status, outcome, model, token counts. The API key is never
        // logged, and neither is the prompt nor the completion — a prompt
        // is user content, and the operator needs none of it to see what
        // happened.
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

        let payload = wire_request(&self.model, prompt);
        let body = serde_json::to_vec(&payload)
            .map_err(|err| TextModelError::Transport(err.to_string()))?;

        let mut request = Request::builder()
            .method(http::Method::POST)
            .uri(self.endpoint())
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {api_key}"))
            .body(Bytes::from(body))
            .map_err(|err| TextModelError::Transport(err.to_string()))?;
        // The caps are the design, as on the Anthropic adapter: the port's
        // 30 s ceiling for a model call's tail, the port's body cap, and
        // `HttpPolicy::clamped` so a caller can tighten but never raise.
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

    fn supports(&self, _tier: ModelTier, capability: Capability) -> bool {
        // The wire speaks function calling, so tools are on unless the
        // deployment turned them off. `Capability` is `#[non_exhaustive]`:
        // an unknown capability is one this adapter does not claim. The tier
        // is the router's routing key; this adapter serves whatever tier it
        // is wired for, so it is ignored.
        capability == Capability::Tools && self.tools
    }
}

impl OpenAiCompatible {
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
