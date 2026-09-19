//! The `TextModel` port: one call to a language-model provider — a prompt
//! in, a completion out. The smallest surface that carries an adapter
//! (issue #430): no streaming, no tool-execution loop, and **no retries
//! inside the adapter** — the caller decides what a transient failure is
//! worth to it, the same way it decides for every other port.
//!
//! Deliberately **not** a [`Port`](super::Port) variant, on the precedent
//! of [`Dispatcher`](super::Dispatcher): this ships as a trait module so
//! an adapter can be written against it, while wiring it as a first-class
//! port — runtime population, a conformance fake, `view_for` plumbing —
//! belongs to the port issue. Keeping it out of the enum leaves
//! `Port::ALL` and the runtime wiring untouched, so the two changes cannot
//! conflict.
//!
//! # Errors, as a caller sees them
//!
//! - [`TextModelError::NotConfigured`] — no API key is set: nothing was
//!   sent and nothing will be until the deployment is fixed. Not an
//!   outage; degrade or refuse, do not retry.
//! - [`TextModelError::Transient`] — the provider said "later": a rate
//!   limit or a server-side failure. Retrying is reasonable;
//!   `retry_after` is the provider's own `Retry-After` when it named one.
//! - [`TextModelError::Rejected`] — the provider refused this prompt (a
//!   4xx): a bad key, a malformed request, filtered content. Retrying
//!   unchanged will fail the same way.
//! - [`TextModelError::Transport`] — the call did not complete: connect
//!   failure, deadline, a body over the [`HttpClient`](crate::HttpClient)
//!   cap, a response that does not parse. Whether that is worth a retry
//!   is the caller's judgement.

use async_trait::async_trait;
use std::time::Duration;

/// Who a [`Turn`] speaks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The caller (or the human acting through it).
    User,
    /// The model's earlier answer, fed back as context.
    Assistant,
}

/// One message of the conversation a [`Prompt`] carries.
#[derive(Debug, Clone)]
pub struct Turn {
    pub role: Role,
    pub text: String,
}

/// One model call, addressed by role rather than by index so a caller
/// cannot send a provider-agnostic "system turn" by accident: the system
/// prompt is its own field, because every provider takes it outside the
/// transcript.
#[derive(Debug, Clone)]
pub struct Prompt {
    /// Instructions the model answers under, when there are any.
    pub system: Option<String>,
    /// The conversation so far, in order.
    pub turns: Vec<Turn>,
    /// Output ceiling in tokens. Keep it modest: a completion large enough
    /// to threaten the port's response-size cap is refused as
    /// [`TextModelError::Transport`], not truncated.
    pub max_tokens: u32,
    /// When set, the completion is requested as JSON matching this schema
    /// (a JSON Schema object) and returned in [`Completion::json`].
    pub json_schema: Option<serde_json::Value>,
}

impl Prompt {
    /// The one-turn prompt most calls are: a user message and a token
    /// ceiling. Everything else is a builder method.
    #[must_use]
    pub fn user(text: impl Into<String>, max_tokens: u32) -> Self {
        Self {
            system: None,
            turns: vec![Turn {
                role: Role::User,
                text: text.into(),
            }],
            max_tokens,
            json_schema: None,
        }
    }

    /// Sets the system prompt the model answers under.
    #[must_use]
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Requests the completion as JSON matching `schema`, returned in
    /// [`Completion::json`].
    #[must_use]
    pub fn with_json_schema(mut self, schema: serde_json::Value) -> Self {
        self.json_schema = Some(schema);
        self
    }
}

/// Token counts the provider reports for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

/// The model's answer.
#[derive(Debug, Clone)]
pub struct Completion {
    /// The completion's text, with every text block joined in order.
    pub text: String,
    /// The completion as JSON when [`Prompt::json_schema`] asked for it.
    pub json: Option<serde_json::Value>,
    /// The model that actually answered, as the provider names it.
    pub model: String,
    pub usage: Usage,
}

/// Failures of one model call, mapped by the adapter from the provider's
/// response. Each variant's meaning for a caller is in the enum's module
/// docs; the variant set is the contract.
///
/// Every variant that carries provider text is sanitized in `Display`,
/// the same way [`MailError`](crate::MailError)'s is: the text an adapter
/// wraps is the provider's own response, and an error message can quote
/// back whatever the request carried — an address, a token, a key.
/// `Display` therefore runs that text through
/// [`crate::logging::scrub_text`], so every `tracing` field, problem
/// detail and `format!` that renders a `TextModelError` gets the
/// sanitized text rather than each call site remembering to. `Debug`
/// still shows the raw string for tests; the logging formatters scrub
/// `{:?}` output too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextModelError {
    /// No API key is configured; nothing was sent.
    NotConfigured,
    /// The provider asked for patience: a rate limit or a server-side
    /// failure. Retry no earlier than `retry_after` when one was stated.
    Transient {
        /// The provider's `Retry-After`, already parsed to a delay: a
        /// seconds-form header becomes its duration, and a date-form
        /// header the delta from now until that date.
        retry_after: Option<Duration>,
    },
    /// The provider refused the request itself. The string is **its**
    /// wording, so it can quote back whatever the request carried — see
    /// the type docs.
    Rejected(String),
    /// The call did not complete: a socket, a DNS failure, a deadline, a
    /// response over the port's size cap, a body that does not parse.
    Transport(String),
}

impl std::fmt::Display for TextModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::NotConfigured => f.write_str("text model is not configured (check the API key)"),
            Self::Transient { retry_after } => write!(
                f,
                "text model asked the caller to try later; retry after {retry_after:?}"
            ),
            Self::Rejected(reason) => {
                write!(f, "text model rejected the prompt: {}", scrub(reason))
            }
            Self::Transport(message) => {
                write!(f, "text model transport error: {}", scrub(message))
            }
        }
    }
}

impl std::error::Error for TextModelError {}

#[async_trait]
pub trait TextModel: Send + Sync {
    /// One model call: the prompt in, one completion out. No streaming,
    /// no retries — a [`TextModelError::Transient`] is the caller's to
    /// spend or drop.
    ///
    /// # Errors
    ///
    /// Never panics; every failure mode is a [`TextModelError`], and
    /// `NotConfigured` is answered before any network call is made.
    async fn complete(&self, prompt: Prompt) -> Result<Completion, TextModelError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_sanitizes_the_provider_text() {
        // The same finding the mailer's Display guards (issue #235): the
        // wrapped text is the provider's own response, and it can quote
        // back whatever the request carried.
        let error = TextModelError::Rejected(
            "prompt not accepted for alice@example.test: cited https://x.test/rules?ref=live-abcdef"
                .to_owned(),
        );
        let text = error.to_string();
        assert!(!text.contains('@'), "{text}");
        assert!(!text.contains("alice"), "{text}");
        assert!(!text.contains("live-abcdef"), "{text}");
        assert!(text.contains("[subject_hash:"), "{text}");

        // A transport message echoing the request URL must not disclose
        // the query it carried.
        let error = TextModelError::Transport(
            "POST https://api.anthropic.com/v1/messages?key=live-abcdef failed".to_owned(),
        );
        let text = error.to_string();
        assert!(!text.contains("live-abcdef"), "{text}");
        assert!(text.contains("?[redacted]"), "{text}");

        // The variants with nothing to hide read exactly as before.
        assert_eq!(
            TextModelError::NotConfigured.to_string(),
            "text model is not configured (check the API key)"
        );
        assert_eq!(
            TextModelError::Transient { retry_after: None }.to_string(),
            "text model asked the caller to try later; retry after None"
        );

        // `Debug` still shows the raw string, which is what a failing
        // test needs to be readable; the log formatters scrub `{:?}` too.
        assert!(format!("{error:?}").contains("live-abcdef"));
    }

    #[test]
    fn a_prompt_builds_from_one_turn_and_grows_by_builder() {
        let prompt = Prompt::user("hello", 256)
            .with_system("be brief")
            .with_json_schema(serde_json::json!({"type": "object"}));
        assert_eq!(prompt.turns.len(), 1);
        assert_eq!(prompt.turns[0].role, Role::User);
        assert_eq!(prompt.system.as_deref(), Some("be brief"));
        assert!(prompt.json_schema.is_some());
        assert_eq!(prompt.max_tokens, 256);

        let bare = Prompt::user("hi", 16);
        assert!(bare.system.is_none() && bare.json_schema.is_none());
    }
}
