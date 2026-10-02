//! `cratefield-adapter-owlpost`: the [`Mailer`] port over the Owlpost REST
//! API (issue #591), the harness's second mail provider alongside
//! `adapter-resend`. Uses the runtime's [`HttpClient`] port — no `reqwest`,
//! no vendor SDK — so the same adapter runs on Workers and natively.
//!
//! Owlpost is Resend-compatible: the same `POST {base}/v1/emails` request
//! shape in, the same `{"id": "..."}` body out. The differences are the
//! endpoint host, the `OWLPOST_*` secrets and the error body — Owlpost
//! answers RFC 9457 `application/problem+json` (`type`, `title`, `status`,
//! `detail`) where Resend answers `{"message": "..."}`.
//!
//! **Degraded mode.** With no `OWLPOST_API_KEY` (or a blank one) the adapter
//! reports [`SendOutcome::NotConfigured`] without any network call, so forms
//! keep working — the same mode `adapter-resend` ships.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, HttpClient, HttpError, MailError, Mailer, Message, SendOutcome, retry_after,
};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// The hosted Owlpost API. A self-hosted or proxy deployment points the
/// adapter elsewhere with [`Owlpost::with_base_url`] /
/// [`OWLPOST_BASE_URL`](Owlpost::from_env); the wire path `/v1/emails` is
/// appended to whatever base is configured.
pub const DEFAULT_BASE_URL: &str = "https://api.owlpost.to";

/// `Mailer` over `POST {base}/v1/emails`.
pub struct Owlpost {
    http: Arc<dyn HttpClient>,
    /// Needed only to read the HTTP-date form of `Retry-After` (issue #278):
    /// a seconds-form header needs no clock, a "come back at 08:49:37 GMT"
    /// does.
    clock: Arc<dyn Clock>,
    api_key: Option<String>,
    from: String,
    reply_to: Option<String>,
    base_url: String,
}

/// `Debug` names the base URL and whether a key is configured — never the
/// key, which rides the `Authorization` header and nothing else.
impl fmt::Debug for Owlpost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Owlpost")
            .field("base_url", &self.base_url)
            .field("from", &self.from)
            .field("api_key_configured", &self.api_key.is_some())
            .finish_non_exhaustive()
    }
}

impl Owlpost {
    /// `api_key: None` — or a blank key, which is no key — makes the adapter
    /// `NotConfigured` (no network). `from` is the default sender; a
    /// [`Message`] with a non-empty `from` overrides it. The base URL is
    /// [`DEFAULT_BASE_URL`]; override it with [`Owlpost::with_base_url`].
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        api_key: Option<String>,
        from: impl Into<String>,
        reply_to: Option<String>,
    ) -> Self {
        Self {
            http,
            clock,
            api_key: normalize_key(api_key),
            from: from.into(),
            reply_to,
            base_url: DEFAULT_BASE_URL.to_owned(),
        }
    }

    /// Points the adapter at a different Owlpost base — a self-hosted
    /// deployment or a proxy. A trailing slash on the base is harmless; the
    /// wire path `/v1/emails` is appended.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Reads `OWLPOST_API_KEY`, `OWLPOST_BASE_URL` (default
    /// [`DEFAULT_BASE_URL`]), `MAIL_FROM` and `MAIL_REPLY_TO` from the
    /// process environment. On Workers the venture reads the secrets from its
    /// `Env` and uses [`Owlpost::new`] instead (`std::env` has no Workers
    /// vars).
    pub fn from_env(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self::new(
            http,
            clock,
            std::env::var("OWLPOST_API_KEY").ok(),
            std::env::var("MAIL_FROM").unwrap_or_else(|_| String::new()),
            std::env::var("MAIL_REPLY_TO").ok(),
        )
        .with_base_url(base_url_from_env(std::env::var("OWLPOST_BASE_URL").ok()))
    }

    /// The send URL: the base with one trailing slash trimmed, then the wire
    /// path.
    fn endpoint(&self) -> String {
        format!("{}/v1/emails", self.base_url.trim_end_matches('/'))
    }
}

/// A key that is empty or only whitespace is no key: `Bearer ` is not a
/// credential, and `OWLPOST_API_KEY=` in a shell or a secret that failed to
/// mount must read as absent (degraded mode), not as a request the provider
/// answers 401.
fn normalize_key(key: Option<String>) -> Option<String> {
    key.filter(|key| !key.trim().is_empty())
}

/// `OWLPOST_BASE_URL` honoured only when set and non-blank: a blank variable
/// is no configuration, not a base of `""`.
fn base_url_from_env(value: Option<String>) -> String {
    match value {
        Some(base) if !base.trim().is_empty() => base.trim().to_owned(),
        _ => DEFAULT_BASE_URL.to_owned(),
    }
}

#[derive(serde::Serialize)]
struct OutboundEmail<'a> {
    from: &'a str,
    to: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<&'a str>,
    subject: &'a str,
    html: &'a str,
    text: &'a str,
    /// Extra RFC 5322 headers, in the order the caller set them (see
    /// [`MessageHeaders`]).
    #[serde(skip_serializing_if = "MessageHeaders::is_empty")]
    headers: MessageHeaders<'a>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<OwlpostTag>,
}

/// Serialises `Message::headers` as a JSON object in insertion order.
/// `serde_json` emits a map's entries as `Serialize` yields them, so the
/// caller's order reaches the wire — the RFC 8058 pair stays paired — where a
/// `BTreeMap` would sort it.
struct MessageHeaders<'a>(&'a [(String, String)]);

impl MessageHeaders<'_> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl serde::Serialize for MessageHeaders<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(name, value)| (name, value)))
    }
}

/// Owlpost requires each tag to be a `{ name, value }` object whose fields
/// contain only ASCII letters, digits, `_` or `-` — the Resend shape
/// (issue #110), which Owlpost inherits. A harness tag is a single label,
/// so it becomes the `name` (sanitised) with a constant `value`.
#[derive(serde::Serialize)]
struct OwlpostTag {
    name: String,
    value: &'static str,
}

fn owlpost_tags(tags: &[String]) -> Vec<OwlpostTag> {
    tags.iter()
        .map(|tag| OwlpostTag {
            name: sanitize_tag(tag),
            value: "1",
        })
        .collect()
}

/// Keeps only the allowed tag characters (ASCII letters, digits, `_`, `-`),
/// mapping anything else to `_`, and never emits an empty name.
fn sanitize_tag(tag: &str) -> String {
    let cleaned: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "tag".to_owned()
    } else {
        cleaned
    }
}

#[derive(serde::Deserialize)]
struct SendResponse {
    #[serde(default)]
    id: String,
}

/// An RFC 9457 `application/problem+json` body. Every field optional so a
/// proxy's partial body still parses.
#[derive(serde::Deserialize)]
struct ProblemDetails {
    #[serde(default)]
    title: String,
    #[serde(default)]
    detail: String,
}

/// One human-readable line from a problem body: `title: detail` when both
/// are present, whichever is, or the raw body when neither parses.
fn problem_detail(body: &str) -> String {
    match serde_json::from_str::<ProblemDetails>(body) {
        Ok(problem) => {
            let title = problem.title.trim();
            let detail = problem.detail.trim();
            match (title.is_empty(), detail.is_empty()) {
                (false, false) => format!("{title}: {detail}"),
                (false, true) => title.to_owned(),
                (true, false) => detail.to_owned(),
                (true, true) => body.to_string(),
            }
        }
        Err(_) => body.to_string(),
    }
}

/// Pulls the sending domain out of a problem detail like "Domain
/// send.example.test is not verified" — the first dot-separated token,
/// otherwise the whole message. The Resend-compatible 403 shape.
fn extract_domain(message: &str) -> String {
    message
        .split_whitespace()
        .find(|token| token.contains('.') && !token.starts_with('"'))
        .unwrap_or(message)
        .trim_matches(['"', '.', ','])
        .to_string()
}

/// A 5xx maps to `Upstream(String)`, which carries no structured retry hint,
/// so a named `Retry-After` is appended: "later" is the whole point of a
/// retryable answer.
fn upstream_detail(detail: String, retry_after: Option<Duration>) -> String {
    match retry_after {
        Some(after) => format!("{detail} (retry after {}s)", after.as_secs()),
        None => detail,
    }
}

impl Owlpost {
    fn map_status(status: StatusCode, body: &str, retry_after: Option<Duration>) -> MailError {
        let detail = problem_detail(body);
        match status {
            StatusCode::UNAUTHORIZED => MailError::Unauthorized,
            // Owlpost has no problem `type` for an unverified domain, so the
            // 403 is classified by its own wording, exactly as
            // `adapter-resend` does for its `{"message"}` body.
            StatusCode::FORBIDDEN => {
                let lowered = detail.to_ascii_lowercase();
                if lowered.contains("verify") || lowered.contains("domain") {
                    MailError::DomainNotVerified {
                        domain: extract_domain(&detail),
                    }
                } else {
                    MailError::Unauthorized
                }
            }
            StatusCode::TOO_MANY_REQUESTS => MailError::RateLimited { retry_after },
            status if status.is_server_error() => {
                MailError::Upstream(upstream_detail(detail, retry_after))
            }
            // Every other 4xx is the message or key being refused: 400 a
            // malformed body, 422 content the provider will not accept, and
            // the rest the same class. Permanent.
            status if status.is_client_error() => MailError::Invalid { detail },
            status => MailError::Upstream(format!("unexpected status {status}: {detail}")),
        }
    }
}

#[async_trait]
impl Mailer for Owlpost {
    async fn send(&self, message: Message) -> Result<SendOutcome, MailError> {
        // Outcome logging per issue #14: provider, code, idempotency key;
        // the recipient is never logged and the key never appears.
        let Some(api_key) = &self.api_key else {
            tracing::info!(
                provider = "owlpost",
                outcome = "not_configured",
                idempotency = message.idempotency_key.as_deref().unwrap_or(""),
                "mailer outcome"
            );
            return Ok(SendOutcome::NotConfigured);
        };

        let from = if message.from.is_empty() {
            self.from.as_str()
        } else {
            message.from.as_str()
        };
        let reply_to = message.reply_to.as_deref().or(self.reply_to.as_deref());

        let payload = OutboundEmail {
            from,
            to: &message.to,
            reply_to,
            subject: &message.subject,
            html: &message.html,
            text: &message.text,
            headers: MessageHeaders(&message.headers),
            tags: owlpost_tags(&message.tags),
        };
        let body =
            serde_json::to_vec(&payload).map_err(|err| MailError::Transport(err.to_string()))?;

        let mut builder = Request::builder()
            .method(http::Method::POST)
            .uri(self.endpoint())
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {api_key}"));
        if let Some(key) = &message.idempotency_key {
            builder = builder.header("Idempotency-Key", key);
        }
        let request = builder
            .body(Bytes::from(body))
            .map_err(|err| MailError::Transport(err.to_string()))?;

        let response = self
            .http
            .send(request)
            .await
            .map_err(|err: HttpError| MailError::Transport(err.to_string()))?;

        let status = response.status();
        // One parser for both `Retry-After` forms (issue #214/#278); the
        // date form needs the clock this adapter is constructed with.
        let retry_after = retry_after(response.headers(), self.clock.as_ref());
        let text = String::from_utf8_lossy(response.body()).to_string();

        if status.is_success() {
            let parsed: SendResponse =
                serde_json::from_str(&text).map_err(|err| MailError::Transport(err.to_string()))?;
            tracing::info!(
                provider = "owlpost",
                code = status.as_u16(),
                outcome = "sent",
                idempotency = message.idempotency_key.as_deref().unwrap_or(""),
                "mailer outcome"
            );
            return Ok(SendOutcome::Sent { id: parsed.id });
        }
        let error = Self::map_status(status, &text, retry_after);
        tracing::warn!(
            provider = "owlpost",
            code = status.as_u16(),
            outcome = "failed",
            idempotency = message.idempotency_key.as_deref().unwrap_or(""),
            error = %error,
            "mailer outcome"
        );
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_key_or_base_url_reads_as_unset() {
        // A blank variable is no configuration, not a key of `""` or a base
        // of `""`.
        assert_eq!(normalize_key(None), None);
        assert_eq!(normalize_key(Some(String::new())), None);
        assert_eq!(normalize_key(Some("   ".to_owned())), None);
        assert_eq!(
            normalize_key(Some("op_live_x".to_owned())),
            Some("op_live_x".to_owned())
        );

        assert_eq!(base_url_from_env(None), DEFAULT_BASE_URL);
        assert_eq!(base_url_from_env(Some(String::new())), DEFAULT_BASE_URL);
        assert_eq!(base_url_from_env(Some("   ".to_owned())), DEFAULT_BASE_URL);
        assert_eq!(
            base_url_from_env(Some("  http://owlpost.fake  ".to_owned())),
            "http://owlpost.fake"
        );
    }

    #[test]
    fn tag_names_never_contain_a_forbidden_character() {
        assert_eq!(sanitize_tag("waitlist:cratefield"), "waitlist_cratefield");
        assert_eq!(sanitize_tag(""), "tag");
        assert_eq!(sanitize_tag("ok-name_1"), "ok-name_1");
    }

    #[test]
    fn problem_detail_prefers_title_and_detail() {
        assert_eq!(
            problem_detail(r#"{"title":"Bad Request","detail":"bad to"}"#),
            "Bad Request: bad to"
        );
        assert_eq!(problem_detail(r#"{"title":"Bad Request"}"#), "Bad Request");
        assert_eq!(problem_detail(r#"{"detail":"bad to"}"#), "bad to");
        // Unparseable: the raw body is the fallback.
        assert_eq!(problem_detail("boom"), "boom");
    }
}
