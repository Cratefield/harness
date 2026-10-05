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

mod inbound;

pub use inbound::{MessageDetail, MessagePage, MessageQuery, MessageSummary};

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

pub mod webhook;

pub use webhook::{Envelope, OwlpostEvent, WebhookError, parse_verified};

mod suppressions;

pub use suppressions::Suppression;

mod domains;

pub use domains::{DnsRecord, Domain, DomainError, DomainStatus, RecordPurpose, RecordType};

/// The hosted Owlpost API. A self-hosted or proxy deployment points the
/// adapter elsewhere with [`Owlpost::with_base_url`] /
/// [`OWLPOST_BASE_URL`](Owlpost::from_env); the wire path `/v1/emails` is
/// appended to whatever base is configured.
pub const DEFAULT_BASE_URL: &str = "https://api.owlpost.to";

/// The largest batch [`Owlpost::batch`] accepts (the Resend-compatible cap).
/// A larger batch is refused without a request.
pub const MAX_BATCH: usize = 100;

/// `Mailer` over `POST {base}/v1/emails`, holding the default sender and
/// delegating the wire to `OwlpostClient`. `Debug` delegates to the client's,
/// so it never prints the key.
#[derive(Debug)]
pub struct Owlpost {
    client: OwlpostClient,
    from: String,
    reply_to: Option<String>,
}

impl Owlpost {
    /// `api_key: None` — or a blank key, which is no key — makes the adapter
    /// `NotConfigured` (no network). `from` is the default sender; a
    /// [`Message`] with a non-empty `from` overrides it.
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        api_key: Option<String>,
        from: impl Into<String>,
        reply_to: Option<String>,
    ) -> Self {
        Self {
            client: OwlpostClient::new(http, clock, api_key),
            from: from.into(),
            reply_to,
        }
    }

    /// Points the adapter at a different base (self-hosted, proxy); a
    /// trailing slash is harmless.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.client = self.client.with_base_url(base_url);
        self
    }

    /// Reads `OWLPOST_API_KEY`, `OWLPOST_BASE_URL`, `MAIL_FROM` and
    /// `MAIL_REPLY_TO`. On Workers read the secrets from the venture's `Env`
    /// and use [`Owlpost::new`] instead.
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

    /// [`Mailer::send`] with the extra [`SendOptions`] the port cannot express.
    /// Local refusals are checked before the key, so a programming error
    /// surfaces even with no key configured.
    ///
    /// # Errors
    ///
    /// [`MailError::Invalid`] for a `topic` with [`Stream::Transactional`].
    // The whole send travels by value, as `Mailer::send` does for the message.
    #[allow(clippy::needless_pass_by_value)]
    pub async fn send_with(
        &self,
        message: Message,
        options: SendOptions,
    ) -> Result<SendOutcome, MailError> {
        match self
            .client
            .send_email(&self.from, self.reply_to.as_deref(), &message, &options)
            .await
        {
            Ok(id) => Ok(SendOutcome::Sent { id }),
            Err(OwlpostError::NotConfigured) => Ok(SendOutcome::NotConfigured),
            Err(error) => Err(error.into()),
        }
    }

    /// Sends up to [`MAX_BATCH`] emails in one `POST {base}/v1/emails/batch`,
    /// returning the ids in order. The refusals are local and precede the key
    /// check.
    ///
    /// # Errors
    ///
    /// [`OwlpostError`] for an empty or oversized batch, or an item with a
    /// `topic` on [`Stream::Transactional`].
    #[allow(clippy::needless_pass_by_value)]
    pub async fn batch(
        &self,
        emails: Vec<(Message, SendOptions)>,
        idempotency_key: Option<String>,
    ) -> Result<Vec<String>, OwlpostError> {
        self.client
            .send_batch(
                &self.from,
                self.reply_to.as_deref(),
                &emails,
                idempotency_key.as_deref(),
            )
            .await
    }

    /// Fetches one sent email by provider id (`GET {base}/v1/emails/{id}`);
    /// the id is validated locally, before the key check.
    ///
    /// # Errors
    ///
    /// [`OwlpostError`] for an empty or path-like id.
    pub async fn get_email(&self, id: &str) -> Result<Email, OwlpostError> {
        self.client.get_email(id).await
    }
}

/// The reusable request engine: base URL, API key, clock, one `call` for every
/// request and one status mapper. It carries no default sender, so each method
/// takes the resolved `from`/`reply_to`. Crate-internal; reach it via
/// [`Owlpost`].
pub(crate) struct OwlpostClient {
    http: Arc<dyn HttpClient>,
    /// Reads the HTTP-date form of `Retry-After` (issue #278).
    clock: Arc<dyn Clock>,
    api_key: Option<String>,
    base_url: String,
}

/// Names the base URL and whether a key is configured — never the key.
impl fmt::Debug for OwlpostClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwlpostClient")
            .field("base_url", &self.base_url)
            .field("api_key_configured", &self.api_key.is_some())
            .finish_non_exhaustive()
    }
}

impl OwlpostClient {
    /// `api_key: None` — or blank — makes every request `NotConfigured` with no
    /// network. The base is [`DEFAULT_BASE_URL`].
    fn new(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>, api_key: Option<String>) -> Self {
        Self {
            http,
            clock,
            api_key: normalize_key(api_key),
            base_url: DEFAULT_BASE_URL.to_owned(),
        }
    }

    /// Points the client at a different base; a trailing slash is harmless.
    fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// A transport failure, with any key its text echoes redacted.
    fn transport(&self, err: impl fmt::Display) -> OwlpostError {
        OwlpostError::Mail(MailError::Transport(self.redact(err.to_string())))
    }

    /// One request: builds the URL and headers, sends it, and returns the body
    /// text on success, or the mapped error. No key is `NotConfigured` and
    /// nothing is sent.
    async fn call(
        &self,
        method: http::Method,
        path: &str,
        body: Option<Vec<u8>>,
        idempotency_key: Option<&str>,
    ) -> Result<String, OwlpostError> {
        self.call_mapped(
            method,
            path,
            body,
            idempotency_key,
            |client, status, text, retry_after| -> OwlpostError {
                client.map_status(status, text, retry_after).into()
            },
        )
        .await
    }

    /// The same request, with the caller's own mapping for a non-success
    /// response. [`Self::call`] keeps the [`MailError`] mapping for the mail
    /// routes; the sending domains map 404, 409 and 422 to their own
    /// variants, which [`MailError`] would fold into one. A no-key short
    /// circuit and a transport failure both arrive as `E::from`.
    async fn call_mapped<E>(
        &self,
        method: http::Method,
        path: &str,
        body: Option<Vec<u8>>,
        idempotency_key: Option<&str>,
        map: impl FnOnce(&OwlpostClient, StatusCode, &str, Option<Duration>) -> E,
    ) -> Result<String, E>
    where
        E: From<OwlpostError> + fmt::Display,
    {
        let Some(api_key) = &self.api_key else {
            tracing::info!(
                provider = "owlpost",
                outcome = "not_configured",
                idempotency = idempotency_key.unwrap_or(""),
                "mailer outcome"
            );
            return Err(E::from(OwlpostError::NotConfigured));
        };
        // What the log calls the answer: a POST sends and a PUT renames (both
        // "sent"), a DELETE removes, a GET reads.
        let outcome = match method {
            http::Method::POST | http::Method::PUT | http::Method::PATCH => "sent",
            http::Method::DELETE => "deleted",
            _ => "read",
        };
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base_url.trim_end_matches('/')))
            .header(AUTHORIZATION, format!("Bearer {api_key}"));
        if body.is_some() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        if let Some(key) = idempotency_key {
            builder = builder.header("Idempotency-Key", key);
        }
        let request = builder
            .body(Bytes::from(body.unwrap_or_default()))
            .map_err(|err| E::from(self.transport(err)))?;

        let response = self
            .http
            .send(request)
            .await
            .map_err(|err: HttpError| E::from(self.transport(err)))?;
        let status = response.status();
        let retry_after = retry_after(response.headers(), self.clock.as_ref());
        let text = String::from_utf8_lossy(response.body()).to_string();
        if status.is_success() {
            tracing::info!(
                provider = "owlpost",
                code = status.as_u16(),
                outcome,
                idempotency = idempotency_key.unwrap_or(""),
                "mailer outcome"
            );
            return Ok(text);
        }
        let error = map(self, status, &text, retry_after);
        tracing::warn!(
            provider = "owlpost",
            code = status.as_u16(),
            outcome = "failed",
            idempotency = idempotency_key.unwrap_or(""),
            error = %error,
            "mailer outcome"
        );
        Err(error)
    }

    /// `POST {base}/v1/emails` for one message, returning the provider id.
    async fn send_email(
        &self,
        from_default: &str,
        reply_to_default: Option<&str>,
        message: &Message,
        options: &SendOptions,
    ) -> Result<String, OwlpostError> {
        refuse_topic_with_transactional(options)?;
        let payload = outbound(from_default, reply_to_default, message, options);
        let body = serde_json::to_vec(&payload).map_err(|err| self.transport(err))?;
        let text = self
            .call(
                http::Method::POST,
                "/v1/emails",
                Some(body),
                message.idempotency_key.as_deref(),
            )
            .await?;
        let parsed: SendResponse =
            serde_json::from_str(&text).map_err(|err| self.transport(err))?;
        Ok(parsed.id)
    }

    /// `POST {base}/v1/emails/batch` for up to [`MAX_BATCH`] messages.
    async fn send_batch(
        &self,
        from_default: &str,
        reply_to_default: Option<&str>,
        emails: &[(Message, SendOptions)],
        idempotency_key: Option<&str>,
    ) -> Result<Vec<String>, OwlpostError> {
        if emails.is_empty() {
            return Err(MailError::Invalid {
                detail: "a batch must contain at least one email".to_owned(),
            }
            .into());
        }
        if emails.len() > MAX_BATCH {
            return Err(MailError::Invalid {
                detail: format!(
                    "a batch of {} emails exceeds the {MAX_BATCH} maximum",
                    emails.len()
                ),
            }
            .into());
        }
        for (_, options) in emails {
            refuse_topic_with_transactional(options)?;
        }
        let payloads: Vec<OutboundEmail<'_>> = emails
            .iter()
            .map(|(message, options)| outbound(from_default, reply_to_default, message, options))
            .collect();
        let body = serde_json::to_vec(&payloads).map_err(|err| self.transport(err))?;
        let text = self
            .call(
                http::Method::POST,
                "/v1/emails/batch",
                Some(body),
                idempotency_key,
            )
            .await?;
        let parsed: BatchResponse =
            serde_json::from_str(&text).map_err(|err| self.transport(err))?;
        Ok(parsed.data.into_iter().map(|item| item.id).collect())
    }

    /// `GET {base}/v1/emails/{id}` for one sent email.
    async fn get_email(&self, id: &str) -> Result<Email, OwlpostError> {
        if !valid_email_id(id) {
            return Err(MailError::Invalid {
                detail: format!("invalid email id {id:?}"),
            }
            .into());
        }
        let text = self
            .call(http::Method::GET, &format!("/v1/emails/{id}"), None, None)
            .await?;
        serde_json::from_str(&text).map_err(|err| self.transport(err))
    }

    /// Maps a non-success response to a [`MailError`], with the API key
    /// stripped from any provider text first (see [`Self::redact`]).
    fn map_status(
        &self,
        status: StatusCode,
        body: &str,
        retry_after: Option<Duration>,
    ) -> MailError {
        let detail = self.redact(problem_detail(body));
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
            // malformed body, 404 a message that is not there, 422 content
            // the provider will not accept. Permanent.
            status if status.is_client_error() => MailError::Invalid { detail },
            status => MailError::Upstream(format!("unexpected status {status}: {detail}")),
        }
    }

    /// Replaces the API key wherever the provider's own text echoed it, so no
    /// error can hand the credential back to a logger.
    fn redact(&self, text: String) -> String {
        match &self.api_key {
            Some(key) => text.replace(key.as_str(), "[redacted]"),
            None => text,
        }
    }
}

/// What one Owlpost call outside the [`Mailer`] port can fail with: the
/// degraded-mode `NotConfigured`, or a wrapped [`MailError`] (a provider
/// failure or a local refusal). `#[non_exhaustive]`: match with a wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwlpostError {
    /// No API key, so no call was made. [`Mailer::send`] reports
    /// `SendOutcome::NotConfigured` instead.
    NotConfigured,
    /// A mapped provider failure, or a local refusal.
    Mail(MailError),
}

impl fmt::Display for OwlpostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("owlpost mailer is not configured (no API key)"),
            Self::Mail(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for OwlpostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotConfigured => None,
            Self::Mail(error) => Some(error),
        }
    }
}

impl From<MailError> for OwlpostError {
    fn from(error: MailError) -> Self {
        Self::Mail(error)
    }
}

/// `NotConfigured` has no `MailError` counterpart (the port returns
/// `SendOutcome::NotConfigured` first) and defensively maps to `Unauthorized`.
impl From<OwlpostError> for MailError {
    fn from(error: OwlpostError) -> Self {
        match error {
            OwlpostError::NotConfigured => MailError::Unauthorized,
            OwlpostError::Mail(error) => error,
        }
    }
}

/// Extra send options [`Message`] does not carry. `#[non_exhaustive]`: build
/// with [`SendOptions::default`] and set fields — not a struct literal.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SendOptions {
    /// The stream; `None` uses the provider's default.
    pub stream: Option<Stream>,
    /// A broadcast topic. Refused with [`Stream::Transactional`].
    pub topic: Option<String>,
    /// Carbon-copy recipients.
    pub cc: Vec<String>,
    /// Blind carbon-copy recipients.
    pub bcc: Vec<String>,
    /// When to send, as an RFC 3339 timestamp.
    pub scheduled_at: Option<String>,
}

/// The stream a message is sent on, serialised lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Stream {
    Transactional,
    Broadcast,
}

/// One sent email, as `GET {base}/v1/emails/{id}` returns it.
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Email {
    pub id: String,
    pub to: Vec<String>,
    pub from: String,
    pub subject: String,
    pub created_at: String,
    #[serde(default)]
    pub last_event: Option<String>,
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
    /// From [`SendOptions`]; omitted when unset, so a plain `send` body is
    /// byte-for-byte what it always was.
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<Stream>,
    #[serde(skip_serializing_if = "Option::is_none")]
    topic: Option<&'a str>,
    #[serde(skip_serializing_if = "slice_is_empty")]
    cc: &'a [String],
    #[serde(skip_serializing_if = "slice_is_empty")]
    bcc: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    scheduled_at: Option<&'a str>,
}

/// `skip_serializing_if` for a slice field: serde hands the predicate `&&[T]`.
fn slice_is_empty<T>(slice: &&[T]) -> bool {
    slice.is_empty()
}

/// Builds one request body, resolving the sender: a non-empty
/// `message.from` wins, otherwise the adapter default; `message.reply_to`
/// wins, otherwise the default. Shared by `send` and every batch item.
fn outbound<'a>(
    from_default: &'a str,
    reply_to_default: Option<&'a str>,
    message: &'a Message,
    options: &'a SendOptions,
) -> OutboundEmail<'a> {
    OutboundEmail {
        from: if message.from.is_empty() {
            from_default
        } else {
            message.from.as_str()
        },
        to: &message.to,
        reply_to: message.reply_to.as_deref().or(reply_to_default),
        subject: &message.subject,
        html: &message.html,
        text: &message.text,
        headers: MessageHeaders(&message.headers),
        tags: owlpost_tags(&message.tags),
        stream: options.stream,
        topic: options.topic.as_deref(),
        cc: &options.cc,
        bcc: &options.bcc,
        scheduled_at: options.scheduled_at.as_deref(),
    }
}

/// A message id is spliced into a path, so it must hold only the characters a
/// provider id does — never a `/` or `..`. An empty id is refused too.
fn valid_email_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Refuses, before any network call, a `topic` set with an explicit
/// [`Stream::Transactional`]: a topic is broadcast-only.
fn refuse_topic_with_transactional(options: &SendOptions) -> Result<(), MailError> {
    if options.topic.is_some() && options.stream == Some(Stream::Transactional) {
        return Err(MailError::Invalid {
            detail: "a topic is only valid for broadcast mail; a transactional message must not \
                     carry one"
                .to_owned(),
        });
    }
    Ok(())
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

/// The `{"data": [{"id": "..."}]}` body a batch send answers with.
#[derive(serde::Deserialize)]
struct BatchResponse {
    #[serde(default)]
    data: Vec<SendResponse>,
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

#[async_trait]
impl Mailer for Owlpost {
    /// Delegates to [`Owlpost::send_with`] with no extra options; the outcome
    /// logging lives in the client, per issue #14.
    async fn send(&self, message: Message) -> Result<SendOutcome, MailError> {
        self.send_with(message, SendOptions::default()).await
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
