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

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, Completion, HttpClient, HttpError, HttpPolicy, MAX_RESPONSE_BYTES, MAX_RESPONSE_TIMEOUT,
    Prompt, Role, TextModel, TextModelError, retry_after,
};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
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
        }
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
    messages: Vec<WireMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<WireResponseFormat<'a>>,
}

#[derive(serde::Serialize)]
struct WireMessage<'a> {
    role: &'static str,
    content: &'a str,
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

/// Builds the wire body: plain messages, or the same messages plus a
/// `response_format` carrying the caller's schema when one was asked
/// for. Hand-rolling this JSON would be a second escaping bug
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
            content: system,
        });
    }
    messages.extend(prompt.messages.iter().map(|turn| WireMessage {
        role: wire_role(turn.role),
        content: turn.content.as_str(),
    }));
    ChatCompletionsRequest {
        model,
        max_tokens: prompt.max_tokens,
        messages,
        response_format,
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

        let mut json = None;
        if prompt.json_schema.is_some() {
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
            // A `response_format` was the whole point of the call.
            // Content that is not the asked-for JSON means the server did
            // not honour it — the answer never arrived in usable form,
            // which is a transport failure, not a refusal.
            let parsed_json: serde_json::Value = serde_json::from_str(&content).map_err(|err| {
                TextModelError::Transport(format!("the schema-shaped answer did not parse: {err}"))
            })?;
            json = Some(parsed_json);
        }

        // A server that answers without a `usage` block still completes,
        // with the counts defaulting to zero — said out loud, not silent.
        let usage = reported_usage(parsed.usage, &self.model);
        let input_tokens = u64::from(usage.prompt_tokens);
        let output_tokens = u64::from(usage.completion_tokens);
        let model = if parsed.model.is_empty() {
            self.model.clone()
        } else {
            parsed.model
        };
        tracing::info!(
            provider = "openai-compatible",
            code = status.as_u16(),
            outcome = "completed",
            model = %model,
            input_tokens,
            output_tokens,
            "text model outcome"
        );
        let mut completion = Completion::new(content, model).usage(input_tokens, output_tokens);
        if let Some(cached) = usage.prompt_tokens_details {
            completion = completion.cached_input_tokens(u64::from(cached.cached_tokens));
        }
        if let Some(json) = json {
            completion = completion.json(json);
        }
        Ok(completion)
    }
}
