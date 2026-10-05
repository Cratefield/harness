//! `cratefield-adapter-colonizer`: an HTTP client for the **Colonizer
//! mothership** (issue #675), over the runtime's [`HttpClient`] port — no
//! `reqwest`, no vendor SDK — so it runs on Workers and natively unchanged.
//! The routes, the error mapping and the reachability requirement are in the
//! crate README, which is this crate's documentation.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cratefield_core::{Clock, HttpClient, HttpError, retry_after};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// The API path prefix every route hangs off.
const API: &str = "/api/v1";

/// What one call can report. `Transient` is the only one a caller retries.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColonizerError {
    /// No usable token or base URL: reported without touching the network.
    NotConfigured,
    /// 400 and the other 4xx, and every local refusal. `detail` is the
    /// provider's `{"error": …}` text, redacted.
    Invalid { detail: String },
    /// 401: the token is missing, unknown or expired.
    Unauthorized,
    /// 403: the token may not do that, or is missing a scope.
    Forbidden { scope: Option<String> },
    /// 404: no such colony, or no such question on it.
    NotFound,
    /// 409: the colony is in a state that refuses this call.
    Conflict { detail: String },
    /// 429 and every 5xx: worth retrying.
    Transient { retry_after: Option<Duration> },
    /// A body that was not the JSON this client expects.
    Decode { detail: String },
    /// The request never reached the mothership — including
    /// `HttpError::BlockedDestination`, a base URL the port refuses.
    Transport { detail: String },
}

impl fmt::Display for ColonizerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("colonizer is not configured: no API token"),
            Self::Invalid { detail } => write!(f, "colonizer rejected the request: {detail}"),
            Self::Unauthorized => f.write_str("colonizer rejected the token (401)"),
            Self::Forbidden { scope: Some(s) } => {
                write!(f, "the token lacks the {s:?} scope (403)")
            }
            Self::Forbidden { scope: None } => f.write_str("the token may not do that (403)"),
            Self::NotFound => f.write_str("no such colony (404)"),
            Self::Conflict { detail } => write!(f, "the colony is in the wrong state: {detail}"),
            Self::Transient {
                retry_after: Some(d),
            } => {
                write!(f, "colonizer is unavailable, retry in {}s", d.as_secs())
            }
            Self::Transient { retry_after: None } => f.write_str("colonizer is unavailable"),
            Self::Decode { detail } => write!(f, "could not read the reply: {detail}"),
            Self::Transport { detail } => write!(f, "could not reach the mothership: {detail}"),
        }
    }
}

impl std::error::Error for ColonizerError {}

/// The account a token acts as, and the scopes it carries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Whoami {
    pub login: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// A colony to open: `owner/name`, the issue, and the brief. Unset fields are
/// omitted from the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NewColony {
    pub repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
}

/// A colony as the mothership reports it. `id` is the `{id}` every other route
/// takes; `status` is where it is; an omitted field reads as empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Colony {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub issue: Option<u64>,
    #[serde(default)]
    pub branch: Option<String>,
}

/// One page of colonies and the cursor for the next, which goes back to
/// [`Colonizer::list`] and is absent on the last page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColonyPage {
    #[serde(default)]
    pub colonies: Vec<Colony>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// A question a colony is blocked on: the `id` [`Colonizer::answer`] quotes
/// back, the `text` asked, and the `options` offered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Question {
    pub id: String,
    pub text: String,
    #[serde(default)]
    pub options: Vec<String>,
}

/// A client for the Colonizer mothership API. `Debug` prints the base URL and
/// whether a token is configured, never the token itself.
pub struct Colonizer {
    inner: Option<Live>,
}

struct Live {
    http: Arc<dyn HttpClient>,
    /// Reads the HTTP-date form of `Retry-After` (issue #278).
    clock: Arc<dyn Clock>,
    token: String,
    base_url: String,
}

impl fmt::Debug for Colonizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            Some(live) => f
                .debug_struct("Colonizer")
                .field("base_url", &live.base_url)
                .field("token_configured", &!live.token.is_empty())
                .finish_non_exhaustive(),
            None => f.write_str("Colonizer(NotConfigured)"),
        }
    }
}

impl Colonizer {
    /// A client for the mothership at `base_url` (a trailing slash is
    /// harmless); with no usable token or base URL it makes no request.
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        base_url: impl Into<String>,
        token: Option<String>,
    ) -> Self {
        let (base_url, token) = (base_url.into(), token.unwrap_or_default());
        let usable = !base_url.trim().is_empty() && !token.trim().is_empty();
        let inner = usable.then(|| Live {
            http,
            clock,
            token: token.trim().to_owned(),
            base_url: base_url.trim().to_owned(),
        });
        Self { inner }
    }

    /// `GET {base}/api/v1/whoami`: the account this token acts as.
    ///
    /// # Errors
    /// [`ColonizerError`]: the status mapping, or `NotConfigured` with no token.
    pub async fn whoami(&self) -> Result<Whoami, ColonizerError> {
        self.json(Method::GET, &format!("{API}/whoami"), None::<&()>)
            .await
    }

    /// `POST {base}/api/v1/colonies`: opens a colony.
    ///
    /// # Errors
    /// [`ColonizerError`]: `Conflict` when one is already running.
    pub async fn create_session(&self, new: &NewColony) -> Result<Colony, ColonizerError> {
        self.json(Method::POST, &format!("{API}/colonies"), Some(new))
            .await
    }

    /// `GET {base}/api/v1/colonies/{id}`.
    ///
    /// # Errors
    /// [`ColonizerError`]: `Invalid` for a path-like id, else the status mapping.
    pub async fn get(&self, id: &str) -> Result<Colony, ColonizerError> {
        self.colony(id, "get").await
    }

    /// `GET {base}/api/v1/colonies?limit=N[&cursor=…]`: one page plus the next
    /// cursor, percent-encoded so it cannot inject a parameter.
    ///
    /// # Errors
    /// [`ColonizerError`]: the status mapping, or `NotConfigured` with no token.
    pub async fn list(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ColonyPage, ColonizerError> {
        let mut path = format!("{API}/colonies?limit={limit}");
        if let Some(cursor) = cursor {
            let _ = write!(path, "&cursor={}", percent_encode(cursor));
        }
        self.json(Method::GET, &path, None::<&()>).await
    }

    /// `GET {base}/api/v1/colonies/{id}/question`: what the colony is blocked
    /// on, or `Ok(None)` when it asks nothing (a 204 or a JSON `null`).
    ///
    /// # Errors
    /// [`ColonizerError`]: `Invalid` for a path-like id, else the status mapping.
    pub async fn question(&self, id: &str) -> Result<Option<Question>, ColonizerError> {
        let path = format!("{}/question", Self::colony_path(id)?);
        self.json(Method::GET, &path, None::<&()>).await
    }

    /// `POST {base}/api/v1/colonies/{id}/answer`: answers `question_id`.
    ///
    /// # Errors
    /// As [`question`](Self::question), plus `NotFound` once answered elsewhere.
    pub async fn answer(
        &self,
        id: &str,
        question_id: &str,
        answer: &str,
    ) -> Result<(), ColonizerError> {
        self.post(
            id,
            "answer",
            &serde_json::json!({
                "question_id": question_id,
                "answer": answer,
            }),
        )
        .await
    }

    /// `POST {base}/api/v1/colonies/{id}/messages`: notes something in the log.
    ///
    /// # Errors
    /// [`ColonizerError`]: `Invalid` for a path-like id, else the status mapping.
    pub async fn message(&self, id: &str, text: &str) -> Result<(), ColonizerError> {
        self.post(id, "messages", &serde_json::json!({ "text": text }))
            .await
    }

    /// `POST {base}/api/v1/colonies/{id}/stop`: stops a colony, returning it
    /// in its new state.
    ///
    /// # Errors
    /// As [`question`](Self::question), plus `Conflict` when already stopped.
    pub async fn stop(&self, id: &str) -> Result<Colony, ColonizerError> {
        self.colony(id, "stop").await
    }

    /// `POST {base}/api/v1/colonies/{id}/resume`: starts a colony again,
    /// returning it in its new state.
    ///
    /// # Errors
    /// As [`question`](Self::question), plus `Conflict` when already running.
    pub async fn resume(&self, id: &str) -> Result<Colony, ColonizerError> {
        self.colony(id, "resume").await
    }

    /// A body-less colony route: `{id}` for `get`, `{id}/{action}` for the two
    /// mutations.
    async fn colony(&self, id: &str, action: &str) -> Result<Colony, ColonizerError> {
        let path = Self::colony_path(id)?;
        let (method, path) = if action == "get" {
            (Method::GET, path)
        } else {
            (Method::POST, format!("{path}/{action}"))
        };
        self.json(method, &path, None::<&()>).await
    }

    /// A body-bearing call under `{id}/{action}`, discarding the empty reply.
    async fn post(
        &self,
        id: &str,
        action: &str,
        body: &serde_json::Value,
    ) -> Result<(), ColonizerError> {
        let path = format!("{}/{action}", Self::colony_path(id)?);
        let _: serde_json::Value = self.json(Method::POST, &path, Some(body)).await?;
        Ok(())
    }

    /// `/api/v1/colonies/{id}`, refusing an id that is not one plain path
    /// segment before any request. A colony id is `[A-Za-z0-9_.-]` without
    /// `..`; anything else would rewrite the path.
    fn colony_path(id: &str) -> Result<String, ColonizerError> {
        let refused = id.is_empty()
            || id.contains("..")
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        if refused {
            let detail = format!("{id:?} is not a colony id");
            return Err(ColonizerError::Invalid {
                detail: cratefield_core::scrub_text(&detail),
            });
        }
        Ok(format!("{API}/colonies/{id}"))
    }

    /// Send `body` (if any) and read the reply as `T`; a 204 or a JSON `null`
    /// is `Ok(None)`.
    async fn json<T: DeserializeOwned, B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, ColonizerError> {
        let live = self.live()?;
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|err| live.transport(&err.to_string()))?
            .map(Bytes::from);
        let text = live.send(&method, path, body).await?;
        match serde_json::from_str(&text) {
            Ok(value) => Ok(value),
            // An empty or `null` body is `None`, not a decode failure — but
            // only when `T` can actually be `Option<_>`.
            Err(_) if text.trim().is_empty() || text.trim() == "null" => {
                serde_json::from_str("null").map_err(|e| live.decode(&e.to_string()))
            }
            Err(err) => Err(live.decode(&err.to_string())),
        }
    }

    fn live(&self) -> Result<&Live, ColonizerError> {
        self.inner.as_ref().ok_or_else(|| {
            tracing::info!(
                provider = "colonizer",
                outcome = "not_configured",
                "colony outcome"
            );
            ColonizerError::NotConfigured
        })
    }
}

impl Live {
    /// One request: the URL, `Bearer` auth and the JSON content type, then the
    /// status mapping. Returns the body text on success.
    async fn send(
        &self,
        method: &Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<String, ColonizerError> {
        let mut builder = Request::builder()
            .method(method.clone())
            .uri(format!("{}{path}", self.base_url.trim_end_matches('/')))
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(ACCEPT, "application/json");
        if body.is_some() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        let request = builder
            .body(body.unwrap_or_default())
            .map_err(|err| self.transport(&err.to_string()))?;

        let response = self
            .http
            .send(request)
            .await
            .map_err(|err: HttpError| self.transport(&err.to_string()))?;
        let status = response.status();
        let retry_after = retry_after(response.headers(), self.clock.as_ref());
        let text = String::from_utf8_lossy(response.body()).to_string();
        if status.is_success() {
            tracing::info!(provider = "colonizer", code = status.as_u16(), method = %method, outcome = "ok", "colony outcome");
            return Ok(text);
        }
        let error = self.map_status(status, &text, retry_after);
        tracing::warn!(provider = "colonizer", code = status.as_u16(), method = %method, outcome = "failed", error = %error, "colony outcome");
        Err(error)
    }

    /// The status mapping, one place for every route.
    fn map_status(
        &self,
        status: StatusCode,
        body: &str,
        retry_after: Option<Duration>,
    ) -> ColonizerError {
        let detail = || self.provider_detail(body);
        match status {
            StatusCode::UNAUTHORIZED => ColonizerError::Unauthorized,
            StatusCode::FORBIDDEN => ColonizerError::Forbidden {
                scope: self.scope(body),
            },
            StatusCode::NOT_FOUND => ColonizerError::NotFound,
            StatusCode::CONFLICT => ColonizerError::Conflict { detail: detail() },
            // 429 and every 5xx are the caller's business to retry.
            other if other == StatusCode::TOO_MANY_REQUESTS || other.is_server_error() => {
                ColonizerError::Transient { retry_after }
            }
            // 400 and every other 4xx are a request this client got wrong.
            _ => ColonizerError::Invalid { detail: detail() },
        }
    }

    /// The mothership's `{"error": "…"}` text, redacted; any other body
    /// still yields something worth putting in the error.
    fn provider_detail(&self, body: &str) -> String {
        let text = Self::field(body, "error").unwrap_or_else(|| body.trim().to_owned());
        redact(&text, &self.token)
    }

    /// The scope a 403 named, from `scope` or `required_scope`. It is provider
    /// text, so it is redacted like any other detail.
    fn scope(&self, body: &str) -> Option<String> {
        Self::field(body, "scope")
            .or_else(|| Self::field(body, "required_scope"))
            .map(|scope| redact(&scope, &self.token))
    }

    fn field(body: &str, name: &str) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()?
            .get(name)?
            .as_str()
            .map(str::to_owned)
    }

    /// A failure that never reached the mothership, token-redacted.
    fn transport(&self, err: &str) -> ColonizerError {
        ColonizerError::Transport {
            detail: redact(err, &self.token),
        }
    }

    /// A body that was not the JSON this client expects.
    fn decode(&self, err: &str) -> ColonizerError {
        ColonizerError::Decode {
            detail: redact(err, &self.token),
        }
    }
}

/// Cuts the token out of text on its way into an error, then runs core's
/// scrubber over what is left.
fn redact(text: &str, token: &str) -> String {
    cratefield_core::scrub_text(&text.replace(token, "[redacted]"))
}

/// Percent-encodes a query value: anything outside the unreserved set is `%XX`.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}
