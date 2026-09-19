//! `cratefield-adapter-github-issues`: the [`Tracker`] port over the GitHub
//! Issues REST API (issue #432). Uses the runtime's [`HttpClient`] and
//! [`Clock`] ports — no vendor SDK — so the same adapter runs on Workers and
//! natively (ADR 0002: the port lives in core, the vendor client here).
//!
//! **At-least-once means search-before-create.** The outbox may call
//! [`Tracker::file`] twice for one [`TicketDraft`], so the adapter stamps
//! every issue body with an invisible HTML comment carrying the draft's
//! idempotency key and looks for its own stamp before creating. A lookup
//! that *fails* fails the whole call — creating after an unreliable dedupe
//! check is exactly the double-file the check exists to prevent.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, Destination, Filed, HttpClient, HttpError, TicketDraft, Tracker, TrackerError,
    retry_after,
};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use http::{Request, StatusCode};
use std::fmt::Write as _;
use std::sync::Arc;

const DEFAULT_BASE: &str = "https://api.github.com";
/// GitHub's current REST API version, pinned the way their docs say to.
const API_VERSION: &str = "2022-11-28";
/// GitHub rejects requests without a `User-Agent`.
const CLIENT_USER_AGENT: &str = "cratefield-adapter-github-issues";
/// How far back the fast-retry scan reaches. A page of the 100 most recent
/// issues covers the window where the search index has not caught up yet —
/// the common redelivery is seconds, not hours, after the first attempt.
const RECENT_ISSUES_PAGE: &str = "state=all&per_page=100";

/// `Tracker` over the GitHub Issues REST API.
///
/// No `Debug` derive: the struct holds the installation token, and a derived
/// `Debug` would print it wherever a log line or a panic message met the
/// adapter.
pub struct GitHubIssues {
    http: Arc<dyn HttpClient>,
    /// Needed only to read the HTTP-date form of `Retry-After` (issue #278),
    /// the same reason `Resend` holds one. A constructor argument rather
    /// than a builder default so a deployment that forgets it fails to
    /// compile instead of silently retrying a date-form 429 immediately.
    clock: Arc<dyn Clock>,
    token: String,
    /// The API root. Defaults to `https://api.github.com`;
    /// [`GitHubIssues::with_base`] overrides it for GitHub Enterprise Server
    /// and for tests pointed at a fake.
    base: String,
}

impl std::fmt::Debug for GitHubIssues {
    /// Never prints the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubIssues")
            .field("token", &"[redacted]")
            .field("base", &self.base)
            // The http and clock ports are struct fields too; nothing about
            // either belongs in a log line.
            .finish_non_exhaustive()
    }
}

impl GitHubIssues {
    /// An adapter for one installation token, pointed at `https://api.github.com`.
    pub fn new(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>, token: impl Into<String>) -> Self {
        Self {
            http,
            clock,
            token: token.into(),
            base: DEFAULT_BASE.to_owned(),
        }
    }

    /// Points the adapter at another API root — GitHub Enterprise Server, or
    /// a fake in tests — instead of `https://api.github.com`.
    #[must_use]
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    /// The headers every GitHub request carries: the token, the pinned API
    /// version, and the `User-Agent` GitHub refuses requests without.
    fn request(&self, method: http::Method, uri: String) -> http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header(USER_AGENT, CLIENT_USER_AGENT)
    }

    /// Sends one request and returns the body of a `2xx` answer. Anything
    /// else — a transport failure or a non-2xx status — comes back as a
    /// [`TrackerError`], already mapped, so a lookup caller cannot fall
    /// through a failed check into a create.
    async fn send_checked(&self, request: Request<Bytes>) -> Result<String, TrackerError> {
        let response = self.http.send(request).await.map_err(|err: HttpError| {
            match err {
                // The port's SSRF vetting refused the destination URL
                // (a scheme, userinfo, or a loopback / private / link-local /
                // metadata destination, re-vetted per redirect hop). That is
                // a config error, not weather: retrying will not fix it.
                HttpError::BlockedDestination(detail) => {
                    TrackerError::Rejected(format!("github issues destination refused: {detail}"))
                }
                // Any other transport failure is weather — retry.
                other => TrackerError::transient(other.to_string()),
            }
        })?;
        let status = response.status();
        let text = String::from_utf8_lossy(response.body()).to_string();
        if !status.is_success() {
            // One parser for both `Retry-After` forms (issue #214/#278); the
            // date form needs the clock this adapter is constructed with.
            let delay = retry_after(response.headers(), self.clock.as_ref());
            return Err(Self::map_status(status, &text, delay));
        }
        Ok(text)
    }

    /// Maps a GitHub status onto the port's error taxonomy. The table is the
    /// issue's: `401`/`403` say the token is wrong or powerless;
    /// `404` says the repository is gone or invisible to the token, and
    /// `422` says GitHub refused the ticket itself — neither is fixed by
    /// retrying; `429` and the `5xx` family are the provider having a
    /// moment. For the rest, the defensible rule is that a `4xx` is a fact
    /// about *our* request (`Rejected`) and nothing else is: a stray `3xx`
    /// a proxy produced is weather, not a verdict on the draft.
    fn map_status(
        status: StatusCode,
        body: &str,
        retry_after: Option<std::time::Duration>,
    ) -> TrackerError {
        let detail = match serde_json::from_str::<ErrorResponse>(body) {
            Ok(parsed) if !parsed.message.is_empty() => parsed.message,
            _ => body.to_string(),
        };
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => TrackerError::Unauthorized,
            StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY => {
                TrackerError::Rejected(format!("github issues {status}: {detail}"))
            }
            // `429` and the `5xx` family are the provider having a moment:
            // retry, and not before `retry_after` where the provider named
            // one. (`retry_after` reads both header forms and answers `None`
            // when no header came, so a bare 500 stays unscheduled.)
            status if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS => {
                TrackerError::transient_after(
                    format!("github issues {status}: {detail}"),
                    retry_after,
                )
            }
            // The rest of the `4xx` family reads the same way as `404` and
            // `422`: a fact about our request, which a retry will not fix.
            status if status.is_client_error() => {
                TrackerError::Rejected(format!("github issues {status}: {detail}"))
            }
            // A stray `3xx` an unfollowing proxy produced is weather, not a
            // verdict on the draft.
            status => TrackerError::transient_after(
                format!("github issues {status}: {detail}"),
                retry_after,
            ),
        }
    }

    /// The dedupe lookups, in order. `Err` is fail-closed: it propagates out
    /// of `file` instead of falling through to the create, because a ticket
    /// created after an *unreliable* dedupe check is exactly the duplicate
    /// the check exists to prevent.
    async fn find_existing(
        &self,
        owner: &str,
        repo: &str,
        marker: &str,
    ) -> Result<Option<Filed>, TrackerError> {
        // The search index covers the whole repository's history, so it is
        // the general answer. It is also eventually consistent: a retry that
        // lands seconds after the first attempt can predate it, which is
        // what the recent-issues page below is for.
        if let Some(existing) = self.search_existing(owner, repo, marker).await? {
            return Ok(Some(existing));
        }
        self.recent_existing(owner, repo, marker).await
    }

    /// The search-index half of the dedupe check: the quoted marker text
    /// plus `repo:`/`is:issue` qualifiers, and — because search
    /// token-matches and must not be trusted blind — a verify that the
    /// marker really appears in a hit's body before accepting it.
    async fn search_existing(
        &self,
        owner: &str,
        repo: &str,
        marker: &str,
    ) -> Result<Option<Filed>, TrackerError> {
        let query = format!("\"{marker}\" repo:{owner}/{repo} is:issue");
        let uri = format!("{}/search/issues?q={}", self.base, percent_encode(&query));
        let request = self
            .request(http::Method::GET, uri)
            .body(Bytes::new())
            .map_err(|err| TrackerError::transient(err.to_string()))?;
        let text = self.send_checked(request).await?;
        let parsed: SearchResponse = serde_json::from_str(&text).map_err(|err| {
            TrackerError::transient(format!("unparseable search response: {err}"))
        })?;
        Ok(parsed
            .items
            .iter()
            .find(|issue| issue.carries(marker))
            .and_then(|issue| issue.filed(true)))
    }

    /// The recent-issues half of the dedupe check, for the fast-retry window
    /// where the search index has not caught up. The list endpoint also
    /// returns pull requests among the "issues"; `IssueRef::carries` skips
    /// those.
    async fn recent_existing(
        &self,
        owner: &str,
        repo: &str,
        marker: &str,
    ) -> Result<Option<Filed>, TrackerError> {
        let uri = format!(
            "{}/repos/{owner}/{repo}/issues?{RECENT_ISSUES_PAGE}",
            self.base
        );
        let request = self
            .request(http::Method::GET, uri)
            .body(Bytes::new())
            .map_err(|err| TrackerError::transient(err.to_string()))?;
        let text = self.send_checked(request).await?;
        let parsed: Vec<IssueRef> = serde_json::from_str(&text).map_err(|err| {
            TrackerError::transient(format!("unparseable issues response: {err}"))
        })?;
        Ok(parsed
            .iter()
            .find(|issue| issue.carries(marker))
            .and_then(|issue| issue.filed(true)))
    }
}

#[async_trait]
impl Tracker for GitHubIssues {
    async fn file(&self, draft: &TicketDraft) -> Result<Filed, TrackerError> {
        let (owner, repo) = match &draft.destination {
            Destination::GitHubIssues { owner, repo } => (owner, repo),
            Destination::Webhook { .. } => {
                return Err(TrackerError::Rejected(
                    "destination is Webhook; this adapter files GitHub issues only".to_owned(),
                ));
            }
            // `#[non_exhaustive]`: a destination a later core adds is
            // refused here, named, rather than silently doing nothing.
            _ => {
                return Err(TrackerError::Rejected(
                    "this adapter files GitHub issues only".to_owned(),
                ));
            }
        };
        let marker = idem_marker(&draft.idempotency_key);

        // Search before creating. The outbox is at-least-once, so this WILL
        // be called twice for one draft; and the `?` here is the fail-closed
        // rule — a lookup that itself fails ends the call.
        if let Some(existing) = self.find_existing(owner, repo, &marker).await? {
            tracing::info!(
                provider = "github-issues",
                outcome = "deduplicated",
                idempotency = %draft.idempotency_key,
                issue = %existing.id,
                "tracker outcome"
            );
            return Ok(existing);
        }

        // The marker rides in the body as an HTML comment: invisible when
        // GitHub renders the issue, greppable by the dedupe check.
        let body = format!("{}\n\n{marker}", draft.body);
        let payload = NewIssue {
            title: &draft.title,
            body: &body,
            labels: draft.labels.iter().map(String::as_str).collect(),
        };
        let json =
            serde_json::to_vec(&payload).map_err(|err| TrackerError::transient(err.to_string()))?;
        let uri = format!("{}/repos/{owner}/{repo}/issues", self.base);
        let request = self
            .request(http::Method::POST, uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Bytes::from(json))
            .map_err(|err| TrackerError::transient(err.to_string()))?;
        let text = self.send_checked(request).await?;
        let created: IssueRef = serde_json::from_str(&text).map_err(|err| {
            // A 2xx we cannot read is not a create we can trust: report it
            // transient, and let the next attempt's dedupe check settle it.
            TrackerError::transient(format!("unparseable issue response: {err}"))
        })?;
        let filed = created
            .filed(false)
            .ok_or_else(|| TrackerError::transient("github issues 201 without an issue number"))?;
        tracing::info!(
            provider = "github-issues",
            outcome = "created",
            idempotency = %draft.idempotency_key,
            issue = %filed.id,
            "tracker outcome"
        );
        Ok(filed)
    }
}

/// The invisible-in-rendering HTML comment that ties an issue to an outbox
/// idempotency key. It is the crate's own prefix (`cratefield-idem`), so a
/// venture's prose can never collide with it by accident.
fn idem_marker(idempotency_key: &str) -> String {
    format!("<!-- cratefield-idem: {idempotency_key} -->")
}

/// The issue fields this adapter reads, common to the search, list and
/// create responses.
#[derive(serde::Deserialize)]
struct IssueRef {
    /// The issue number, what the REST API addresses a ticket by.
    #[serde(default)]
    number: Option<i64>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    /// Set on pull requests, which the list endpoint returns among the
    /// "issues"; a PR must never satisfy a marker match.
    #[serde(default)]
    pull_request: Option<serde_json::Value>,
}

impl IssueRef {
    /// Whether this issue really is the one the marker names. The marker is
    /// matched whole: search's token and substring matching is exactly why
    /// the verify exists.
    fn carries(&self, marker: &str) -> bool {
        self.pull_request.is_none()
            && self
                .body
                .as_deref()
                .is_some_and(|body| body.contains(marker))
    }

    /// The [`Filed`] this wire shape reports, or `None` when GitHub answered
    /// without a number — which no successful lookup or create does.
    fn filed(&self, deduplicated: bool) -> Option<Filed> {
        let id = self.number?.to_string();
        Some(Filed {
            id,
            url: self.html_url.clone(),
            deduplicated,
        })
    }
}

#[derive(serde::Deserialize)]
struct SearchResponse {
    #[serde(default)]
    items: Vec<IssueRef>,
}

#[derive(serde::Deserialize)]
struct ErrorResponse {
    #[serde(default)]
    message: String,
}

#[derive(serde::Serialize)]
struct NewIssue<'a> {
    title: &'a str,
    body: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    labels: Vec<&'a str>,
}

/// Percent-encodes a value for a query parameter. The allowlist is RFC 3986's
/// unreserved set, so the quoted marker's spaces, `<`/`>` and `:` all come
/// out encoded instead of terminating the parameter early. (No `url` crate:
/// one parameter is not worth a dependency.)
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            other => {
                // Writing to a String cannot fail.
                let _ = write!(encoded, "%{other:02X}");
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_is_an_html_comment_naming_the_crate() {
        assert_eq!(
            idem_marker("idem-123"),
            "<!-- cratefield-idem: idem-123 -->"
        );
    }

    #[test]
    fn a_search_query_is_percent_encoded_parameter_safe() {
        // Space, `<`, `>`, `!`, `:` and `/` must all survive as one `q=`
        // value, none of them terminating the parameter early.
        let encoded =
            percent_encode("\"<!-- cratefield-idem: k-1 -->\" repo:acme/widgets is:issue");
        assert_eq!(
            encoded,
            "%22%3C%21--%20cratefield-idem%3A%20k-1%20--%3E%22%20repo%3Aacme%2Fwidgets%20is%3Aissue"
        );
    }

    #[test]
    fn a_pull_request_or_a_markerless_body_is_never_a_match() {
        let marker = idem_marker("k-1");
        let pr: IssueRef = serde_json::from_value(serde_json::json!({
            "number": 9, "body": marker, "html_url": "https://github.test/acme/widgets/pull/9",
            "pull_request": { "url": "https://github.test/acme/widgets/pull/9" },
        }))
        .expect("parses");
        assert!(!pr.carries(&marker), "a pull request is not an issue");

        let near_miss: IssueRef = serde_json::from_value(
            serde_json::json!({ "number": 8, "body": "<!-- cratefield-idem: k-12 -->" }),
        )
        .expect("parses");
        assert!(
            !near_miss.carries(&marker),
            "a substring of the marker is not the marker"
        );

        let verified: IssueRef = serde_json::from_value(
            serde_json::json!({ "number": 7, "body": format!("hi\n\n{marker}") }),
        )
        .expect("parses");
        assert!(verified.carries(&marker));
        let filed = verified.filed(true).expect("a number");
        assert_eq!(filed.id, "7");
        assert!(filed.deduplicated);
    }

    #[test]
    fn debug_of_the_adapter_redacts_the_token() {
        let adapter = GitHubIssues::new(
            Arc::new(NoHttp),
            Arc::new(cratefield_core::SystemClock),
            "ghp_super_secret_token",
        );
        let printed = format!("{adapter:?}");
        assert!(printed.contains("GitHubIssues"), "{printed}");
        assert!(!printed.contains("ghp_super_secret_token"), "{printed}");
        assert!(printed.contains("[redacted]"), "{printed}");
    }

    /// The transport is never reached by the `Debug` test above.
    struct NoHttp;

    #[async_trait]
    impl HttpClient for NoHttp {
        async fn send(&self, _request: Request<Bytes>) -> Result<http::Response<Bytes>, HttpError> {
            Err(HttpError::Transport("not used".to_owned()))
        }
    }
}
