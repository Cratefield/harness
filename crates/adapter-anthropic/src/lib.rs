//! `cratefield-adapter-anthropic`: the minimal [`TextModel`] port over the
//! Anthropic Messages API (issue #430). Uses the runtime's [`HttpClient`]
//! port — no `reqwest`, no vendor SDK — so the same adapter runs on
//! Workers and natively, and inherits that port's destination vetting,
//! deadline and response-size caps.
//!
//! **Degraded mode.** When the API key is absent the adapter answers
//! [`TextModelError::NotConfigured`] without any network call, so a
//! pipeline stage can degrade instead of breaking.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, Completion, HttpClient, HttpError, HttpPolicy, MAX_RESPONSE_BYTES, MAX_RESPONSE_TIMEOUT,
    Prompt, Role, TextModel, TextModelError, retry_after,
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

#[derive(serde::Serialize)]
struct WireTurn<'a> {
    role: &'static str,
    content: &'a str,
}

#[derive(serde::Serialize)]
struct WireTool<'a> {
    name: &'static str,
    description: &'static str,
    input_schema: &'a serde_json::Value,
}

#[derive(serde::Serialize)]
struct WireToolChoice<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    name: &'a str,
}

/// Builds the wire body: plain text when no schema was asked for; a single
/// forced tool — input schema = the caller's — when one was. Hand-rolling
/// this JSON would be a second escaping bug waiting to happen; the prompt
/// is user content.
fn wire_request<'a>(model: &'a str, prompt: &'a Prompt) -> MessagesRequest<'a> {
    let tools = prompt
        .json_schema
        .as_ref()
        .map(|schema| {
            vec![WireTool {
                name: JSON_TOOL_NAME,
                description: JSON_TOOL_DESCRIPTION,
                input_schema: schema,
            }]
        })
        .unwrap_or_default();
    let tool_choice = tools.first().map(|tool| WireToolChoice {
        kind: "tool",
        name: tool.name,
    });
    MessagesRequest {
        model,
        max_tokens: prompt.max_tokens,
        system: prompt.system.as_deref(),
        messages: prompt
            .turns
            .iter()
            .map(|turn| WireTurn {
                role: wire_role(turn.role),
                content: turn.text.as_str(),
            })
            .collect(),
        tools,
        tool_choice,
    }
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
        input: serde_json::Value,
    },
    #[serde(other)]
    Other,
}

#[derive(serde::Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
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

#[async_trait]
impl TextModel for Anthropic {
    async fn complete(&self, prompt: Prompt) -> Result<Completion, TextModelError> {
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

        let payload = wire_request(&self.model, &prompt);
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

        let mut completion_text = String::new();
        let mut json = None;
        for block in parsed.content {
            match block {
                ContentBlock::Text { text } => completion_text.push_str(&text),
                ContentBlock::ToolUse { input } => json = Some(input),
                ContentBlock::Other => {}
            }
        }
        if prompt.json_schema.is_some() {
            // `max_tokens` can cut the forced tool call off mid-JSON, leaving
            // `input` empty or partial (a JSON `null` parses to `Value::Null`
            // here) — returning that as a schema-shaped success would be a
            // lie. `Rejected`, not `Transient`: retrying the identical
            // request truncates identically; only a larger `max_tokens`
            // changes the outcome.
            if parsed.stop_reason.as_deref() == Some("max_tokens") {
                return Err(TextModelError::Rejected(
                    "the response was truncated at max_tokens before the schema-shaped \
                     result was complete; a larger max_tokens is needed"
                        .to_owned(),
                ));
            }
            // Forced tool use was the whole point of the call. A response
            // without the tool block is not a refusal (that would have been
            // a 4xx) and not an empty answer — the JSON path broke between
            // provider and here, which is a transport failure.
            if json.is_none() {
                return Err(TextModelError::Transport(
                    "forced tool call came back without a tool_use block".to_owned(),
                ));
            }
        } else {
            // No schema was requested and no tools were sent; `json` stays
            // `None` even if the provider somehow answered with one. A text
            // completion cut off by `max_tokens` is still a useful answer,
            // so it is returned as-is — only the schema path guards above.
            json = None;
        }

        let wire_usage = parsed.usage.unwrap_or_default();
        let usage = cratefield_core::Usage {
            input_tokens: wire_usage.input_tokens,
            output_tokens: wire_usage.output_tokens,
        };
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
            input_tokens = usage.input_tokens,
            output_tokens = usage.output_tokens,
            "text model outcome"
        );
        Ok(Completion {
            text: completion_text,
            json,
            model,
            usage,
        })
    }
}
