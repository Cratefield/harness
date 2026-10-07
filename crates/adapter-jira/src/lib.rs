//! `cratefield-adapter-jira`: the [`Tracker`] port over the Jira Cloud
//! REST API v3 (issue #559). Uses the runtime's [`HttpClient`] and
//! [`Clock`] ports — no vendor SDK — so the same adapter runs on Workers
//! and natively (ADR 0002: the port lives in core, the vendor client here).
//!
//! **At-least-once means search-before-create**, the same rule the sibling
//! `cratefield-adapter-github-issues` follows: the outbox may call
//! [`Tracker::file`] twice for one [`TicketDraft`], so the adapter stamps
//! every issue with a derived label and looks for its own stamp by JQL
//! before creating. A lookup that *fails* fails the whole call — creating
//! after an unreliable dedupe check is exactly the double-file the check
//! exists to prevent.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use cratefield_core::{
    Clock, Credential, Destination, Filed, HttpClient, HttpError, InboundStatusError,
    ProviderScheme, SignatureEncoding, StatusUpdate, StatusWebhook, TicketComment, TicketDraft,
    TicketState, TicketStatus, Tracker, TrackerError, WebhookVerifier, retry_after,
};
use futures_util::lock::Mutex as AsyncMutex;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The issue type every ticket is filed as, unless
/// [`JiraCloud::with_issue_type`] names another. The name must already
/// exist in the destination project — Jira refuses the create with a `400`
/// otherwise, which surfaces as [`TrackerError::Rejected`].
const DEFAULT_ISSUE_TYPE: &str = "Bug";
/// Jira's documented cap on the `summary` field; a longer title is
/// truncated on a character boundary rather than failing the create.
const MAX_SUMMARY_CHARS: usize = 255;
/// The comment property carrying the caller's idempotency key, so a
/// retried note stays greppable in Jira even though comments have no
/// search-before-write.
const IDEM_PROPERTY: &str = "cratefield-idem";
/// The label prefix tying an issue to an outbox idempotency key — the
/// Jira counterpart of the GitHub adapter's invisible HTML comment. It is
/// the crate's own prefix, so a venture's own labels can never collide
/// with it by accident.
const IDEM_LABEL_PREFIX: &str = "cratefield-idem-";
/// Jira Cloud's current search endpoint (the one `search/jql` moved to),
/// where the dedupe lookup runs.
const SEARCH_PATH: &str = "/rest/api/3/search/jql";

/// `Tracker` over the Jira Cloud REST API v3.
///
/// No `Debug` derive: kept explicit so a field added later cannot print
/// `Debug` would print it wherever a log line or a panic message met the
/// adapter.
pub struct JiraCloud {
    http: Arc<dyn HttpClient>,
    /// Needed only to read the HTTP-date form of `Retry-After` (issue
    /// #278), the same reason the GitHub Issues adapter holds one. A
    /// constructor argument rather than a builder default so a deployment
    /// that forgets it fails to compile instead of silently retrying a
    /// date-form 429 immediately.
    clock: Arc<dyn Clock>,
    issue_type: String,
    /// `None` — the default — builds each URL from the destination's own
    /// site (`https://{site}/rest/api/3/…`), which is what Jira Cloud is.
    /// A value overrides the scheme and host for tests pointed at a fake
    /// ([`JiraCloud::with_base`]).
    base: Option<String>,
    /// Held across the whole search-then-create of one [`Tracker::file`],
    /// so two in-process callers racing on one idempotency key cannot
    /// both observe "no such issue" and both create one. Jira labels are
    /// not a uniqueness constraint, so nothing on the provider side
    /// closes that window — this gate is the same single-flight
    /// `GithubApp` holds across its token exchange.
    ///
    /// It serialises *all* filings on one adapter, not just same-key
    /// ones: a per-key table would leak an entry per key ever filed and
    /// buy nothing a retry does not already give — the create is one
    /// POST either way.
    file_gate: AsyncMutex<()>,
}

impl std::fmt::Debug for JiraCloud {
    /// Holds no credential to leak: the `email:api_token` pair arrives per
    /// call (#453).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JiraCloud")
            .field("issue_type", &self.issue_type)
            .field("base", &self.base)
            // The http and clock ports are struct fields too; nothing about
            // either belongs in a log line.
            .finish_non_exhaustive()
    }
}

impl JiraCloud {
    /// An adapter pointed at Jira Cloud. It holds no credential: which
    /// site, addressed under whose `email:api_token`, is tenant data and
    /// arrives with each call (#453).
    pub fn new(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self {
            http,
            clock,
            issue_type: DEFAULT_ISSUE_TYPE.to_owned(),
            base: None,
            file_gate: AsyncMutex::new(()),
        }
    }

    /// Files every ticket as issue type `name` instead of `"Bug"`.
    #[must_use]
    pub fn with_issue_type(mut self, name: impl Into<String>) -> Self {
        self.issue_type = name.into();
        self
    }

    /// Overrides the scheme and host every request is built from — a fake
    /// in tests — instead of `https://` plus the destination's own site.
    #[must_use]
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = Some(base.into());
        self
    }

    /// The absolute URL for `path` under the destination's `site`.
    fn endpoint(&self, site: &str, path: &str) -> String {
        match &self.base {
            Some(base) => format!("{base}{path}"),
            None => format!("https://{site}{path}"),
        }
    }

    /// The headers every Jira request carries: HTTP Basic over the
    /// `email:api_token` credential, and the JSON accept Jira v3 answers
    /// with. Takes the credential per call: whose site is addressed under
    /// whose token is tenant data (#453), so the adapter holds none — and
    /// nothing formats the pair but the request itself, so no log line
    /// can meet it.
    fn request(cred: &Credential, method: http::Method, uri: String) -> http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, basic_auth(cred))
            .header(ACCEPT, "application/json")
    }

    /// The dedupe lookup: one JQL search for this project's issue carrying
    /// the idempotency label. Jira's label search matches whole labels, so
    /// unlike GitHub's token-matching text search no body verify is needed
    /// on the hit. `Err` is fail-closed: it propagates out of `file`
    /// instead of falling through to the create, because a ticket created
    /// after an *unreliable* dedupe check is exactly the duplicate the
    /// check exists to prevent.
    async fn find_existing(
        &self,
        cred: &Credential,
        site: &str,
        project: &str,
        label: &str,
    ) -> Result<Option<Filed>, TrackerError> {
        let jql = format!("project = \"{project}\" AND labels = \"{label}\"");
        let uri = format!(
            "{}?jql={}&fields=status&maxResults=1",
            self.endpoint(site, SEARCH_PATH),
            percent_encode(&jql)
        );
        let request = Self::request(cred, http::Method::GET, uri)
            .body(Bytes::new())
            .map_err(|_| TrackerError::Transient { retry_after: None })?;
        let text = self.send_checked(request).await?;
        let parsed: SearchResponse = serde_json::from_str(&text)
            .map_err(|_| TrackerError::Transient { retry_after: None })?;
        Ok(parsed.issues.into_iter().find_map(|issue| {
            issue.key.map(|key| Filed {
                external_id: key.clone(),
                url: browse_url(site, &key),
            })
        }))
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
                    TrackerError::Rejected(format!("jira destination refused: {detail}"))
                }
                // Any other transport failure is weather — retry. The
                // provider's text cannot ride `Transient`, which carries
                // only the delay, so it goes to the log the way the
                // sibling adapters' does: an operator still gets to read it.
                other => {
                    tracing::warn!(
                        provider = "jira",
                        outcome = "failed",
                        error = %other,
                        "tracker outcome"
                    );
                    TrackerError::Transient { retry_after: None }
                }
            }
        })?;
        let status = response.status();
        let text = String::from_utf8_lossy(response.body()).to_string();
        if !status.is_success() {
            // One parser for both `Retry-After` forms (issue #214/#278); the
            // date form needs the clock this adapter is constructed with.
            let delay = retry_after(response.headers(), self.clock.as_ref());
            let error = Self::map_status(status, &text, delay);
            tracing::warn!(
                provider = "jira",
                code = status.as_u16(),
                outcome = "failed",
                detail = %text,
                error = %error,
                "tracker outcome"
            );
            return Err(error);
        }
        Ok(text)
    }

    /// Maps a Jira status onto the port's error taxonomy — the same table
    /// the GitHub Issues adapter applies: `401`/`403` say the
    /// `email:api_token` pair is wrong or powerless; the rest of the
    /// `4xx` family (Jira answers a bad project key, a missing issue type,
    /// an unpermitted field with a `400` carrying `errorMessages`/`errors`)
    /// is a fact about our request, which a retry will not fix; `429` and
    /// the `5xx` family are the provider having a moment. A stray `3xx` an
    /// unfollowing proxy produced is weather, not a verdict on the draft.
    fn map_status(
        status: StatusCode,
        body: &str,
        retry_after: Option<std::time::Duration>,
    ) -> TrackerError {
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => TrackerError::Unauthorized,
            // `429` and the `5xx` family are the provider having a moment:
            // retry, and not before `retry_after` where it named one.
            // (`retry_after` reads both header forms and answers `None` when
            // no header came, so a bare 500 stays unscheduled.) This arm
            // must precede the `4xx` one — 429 *is* a client error.
            status if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS => {
                TrackerError::Transient { retry_after }
            }
            status if status.is_client_error() => {
                TrackerError::Rejected(format!("jira {status}: {}", error_detail(body)))
            }
            _ => TrackerError::Transient { retry_after },
        }
    }
}

#[async_trait]
impl Tracker for JiraCloud {
    async fn file(
        &self,
        dest: &Destination,
        cred: &Credential,
        draft: &TicketDraft,
    ) -> Result<Filed, TrackerError> {
        let (site, project) = site_and_project(dest)?;
        validate_site(site)?;
        validate_project(project)?;
        let label = idem_label(&draft.idempotency_key);

        // Held across the lookup AND the create: the gate is what makes
        // search-before-create safe rather than merely hopeful. A second
        // caller arriving mid-flight waits here, and by the time its JQL
        // search runs the first one's labelled issue exists. Taken after
        // the destination validation, so a malformed site is refused
        // without queueing behind a stranger's create.
        let _single_flight = self.file_gate.lock().await;

        // Search before creating. The outbox is at-least-once, so this WILL
        // be called twice for one draft; and the `?` here is the fail-closed
        // rule — a lookup that itself fails ends the call.
        if let Some(existing) = self.find_existing(cred, site, project, &label).await? {
            tracing::info!(
                provider = "jira",
                outcome = "deduplicated",
                idempotency = %draft.idempotency_key,
                issue = %existing.external_id,
                "tracker outcome"
            );
            return Ok(existing);
        }

        let payload = serde_json::json!({
            "fields": {
                "project": { "key": project },
                "summary": truncate_summary(&draft.title),
                "issuetype": { "name": self.issue_type },
                "labels": labels(draft, &label),
                "description": adf_document(&draft.body_markdown),
            }
        });
        let json = serde_json::to_vec(&payload)
            .map_err(|_| TrackerError::Transient { retry_after: None })?;
        let request = Self::request(
            cred,
            http::Method::POST,
            self.endpoint(site, "/rest/api/3/issue"),
        )
        .header(CONTENT_TYPE, "application/json")
        .body(Bytes::from(json))
        .map_err(|_| TrackerError::Transient { retry_after: None })?;
        let text = self.send_checked(request).await?;
        let created: CreatedIssue = serde_json::from_str(&text).map_err(|_| {
            // A 2xx we cannot read is not a create we can trust: report it
            // transient, and let the next attempt's dedupe check settle it.
            TrackerError::Transient { retry_after: None }
        })?;
        let Some(key) = created.key else {
            return Err(TrackerError::Transient { retry_after: None });
        };
        tracing::info!(
            provider = "jira",
            outcome = "created",
            idempotency = %draft.idempotency_key,
            issue = %key,
            "tracker outcome"
        );
        Ok(Filed {
            external_id: key.clone(),
            url: browse_url(site, &key),
        })
    }

    /// Jira has a ticket to read back, so this is a real read: GET the
    /// issue's status and map its `statusCategory` — Jira's own rollup,
    /// the field that survives every custom workflow a tenant renames —
    /// onto the port's five.
    async fn status(
        &self,
        dest: &Destination,
        cred: &Credential,
        external_id: &str,
    ) -> Result<TicketStatus, TrackerError> {
        let (site, _) = site_and_project(dest)?;
        validate_site(site)?;
        validate_issue_key(external_id)?;
        let uri = format!(
            "{}?fields=status",
            self.endpoint(site, &format!("/rest/api/3/issue/{external_id}"))
        );
        let request = Self::request(cred, http::Method::GET, uri)
            .body(Bytes::new())
            .map_err(|_| TrackerError::Transient { retry_after: None })?;
        let text = self.send_checked(request).await?;
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|_| TrackerError::Transient { retry_after: None })?;
        // `Value` indexing answers `Null`, never panics, for every missing
        // hop — a status Jira answered without is an unknown, not a crash.
        let state = match parsed["fields"]["status"]["statusCategory"]["key"].as_str() {
            Some("new") => TicketState::Open,
            Some("indeterminate") => TicketState::InProgress,
            Some("done") => TicketState::Resolved,
            // The port names what it can; a category it cannot is said so
            // rather than guessed into one of the four above.
            _ => TicketState::Unknown,
        };
        Ok(TicketStatus {
            external_id: external_id.to_owned(),
            state,
            url: Some(browse_url(site, external_id)),
        })
    }

    /// Posts the note as a Jira comment. There is no search-before-write
    /// here — comments are not worth a second request — so a redelivery
    /// **may duplicate the note**; the caller's idempotency key rides a
    /// comment property, which makes any duplicate findable and deletable.
    async fn comment(
        &self,
        dest: &Destination,
        cred: &Credential,
        external_id: &str,
        comment: &TicketComment,
    ) -> Result<(), TrackerError> {
        let (site, _) = site_and_project(dest)?;
        validate_site(site)?;
        validate_issue_key(external_id)?;
        let body = match comment.link.as_deref() {
            // The link becomes a paragraph with a link mark; only an
            // http(s) link is worth one, decided before any request.
            Some(link) if link.starts_with("https://") || link.starts_with("http://") => {
                adf_with_link(&comment.body_markdown, link)
            }
            Some(_) => {
                return Err(TrackerError::Rejected(
                    "jira comment link must be an http(s) URL".to_owned(),
                ));
            }
            None => adf_document(&comment.body_markdown),
        };
        let payload = serde_json::json!({
            "body": body,
            "properties": [{ "key": IDEM_PROPERTY, "value": comment.idempotency_key }],
        });
        let json = serde_json::to_vec(&payload)
            .map_err(|_| TrackerError::Transient { retry_after: None })?;
        let uri = self.endpoint(site, &format!("/rest/api/3/issue/{external_id}/comment"));
        let request = Self::request(cred, http::Method::POST, uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Bytes::from(json))
            .map_err(|_| TrackerError::Transient { retry_after: None })?;
        let _ = self.send_checked(request).await?;
        tracing::info!(
            provider = "jira",
            outcome = "commented",
            idempotency = %comment.idempotency_key,
            issue = external_id,
            "tracker outcome"
        );
        Ok(())
    }
}

/// The `Authorization` value for Atlassian's API-token scheme: HTTP Basic
/// over the caller's `email:api_token` pair, standard base64 exactly as
/// RFC 7617 (and Atlassian's docs) spell it. The pair is the credential;
/// it lives only here and only inside the request.
fn basic_auth(cred: &Credential) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(cred.expose().as_bytes())
    )
}

/// The labels a filed issue carries: the draft's own, the idempotency
/// label the dedupe search greps for, and one naming the severity — the
/// port's [`Severity`] rendered as the flat `severity/<name>` text a Jira
/// label is. None contains a space, which Jira labels cannot carry.
fn labels(draft: &TicketDraft, idem_label: &str) -> Vec<String> {
    let mut all = Vec::with_capacity(draft.labels.len() + 2);
    all.extend(draft.labels.iter().cloned());
    all.push(idem_label.to_owned());
    all.push(format!("severity/{}", draft.severity.name()));
    all
}

/// The label that ties an issue to an outbox idempotency key:
/// [`IDEM_LABEL_PREFIX`] plus the first 16 bytes of SHA-256 of the key,
/// hex — hashed, because a label is flat text a search greps for and a
/// caller's key may quote tenant data.
fn idem_label(idempotency_key: &str) -> String {
    let digest = Sha256::digest(idempotency_key.as_bytes());
    format!("{IDEM_LABEL_PREFIX}{}", hex::encode(&digest[..16]))
}

/// Jira caps `summary` at [`MAX_SUMMARY_CHARS`]; a longer title is
/// truncated on a character boundary — a split character is something
/// serde's JSON writer would refuse to emit.
fn truncate_summary(title: &str) -> &str {
    match title.char_indices().nth(MAX_SUMMARY_CHARS) {
        Some((at, _)) => &title[..at],
        None => title,
    }
}

/// The site and project a [`Destination::Jira`] names, or the rejection
/// for any other destination — decided before any request, the way the
/// GitHub adapter refuses a webhook.
fn site_and_project(dest: &Destination) -> Result<(&str, &str), TrackerError> {
    match dest {
        Destination::Jira { site, project } => Ok((site.as_str(), project.as_str())),
        other => Err(TrackerError::unsupported_destination(other)),
    }
}

/// A site must be a bare hostname (`acme.atlassian.net`): scheme, path,
/// port, userinfo and whitespace are all rejected before any request, so
/// a malformed tenant value cannot move the Basic credential off the host
/// it names. The allowlist is a hostname's own characters —
/// alphanumerics, dots and hyphens — which is narrower than any URL
/// parser's and cannot be talked past.
fn validate_site(site: &str) -> Result<(), TrackerError> {
    let valid = !site.is_empty()
        && site.len() <= 253
        && site
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !site.starts_with(['-', '.'])
        && !site.ends_with(['-', '.'])
        && !site.contains("..");
    if valid {
        Ok(())
    } else {
        Err(TrackerError::Rejected(
            "jira site must be a bare hostname like acme.atlassian.net".to_owned(),
        ))
    }
}

/// A project key is Jira's own shape: uppercase letters, digits and
/// underscores, starting with a letter. Decided before any request so a
/// malformed key cannot become a mangled URL.
fn validate_project(project: &str) -> Result<(), TrackerError> {
    let valid = !project.is_empty()
        && project.len() <= 255
        && project.starts_with(|c: char| c.is_ascii_uppercase())
        && project
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if valid {
        Ok(())
    } else {
        Err(TrackerError::Rejected(
            "jira project key must be uppercase letters, digits or underscores, starting with a \
             letter (e.g. PROJ)"
                .to_owned(),
        ))
    }
}

/// An external id must look like a Jira key (`PROJ-123`) before it is put
/// into a URL: project-key-shaped, one hyphen, then digits. A value that
/// does not parse never rides a path this adapter builds.
fn validate_issue_key(external_id: &str) -> Result<(), TrackerError> {
    let shaped = match external_id.split_once('-') {
        Some((key, number)) => {
            !key.is_empty()
                && !number.is_empty()
                && number.bytes().all(|b| b.is_ascii_digit())
                && key.starts_with(|c: char| c.is_ascii_uppercase())
                && key
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        }
        None => false,
    };
    if shaped {
        Ok(())
    } else {
        Err(TrackerError::Rejected(
            "jira external id must look like a Jira key (e.g. PROJ-123)".to_owned(),
        ))
    }
}

/// The human URL for an issue: `https://{site}/browse/{key}` — Jira Cloud
/// renders every issue there.
fn browse_url(site: &str, key: &str) -> String {
    format!("https://{site}/browse/{key}")
}

/// The human URL rebuilt from an issue's `self` API URL
/// (`https://{host}/rest/api/3/issue/10002` → `https://{host}/browse/KEY`),
/// for a webhook payload that names no site of its own: `None` when the
/// payload carries no sensible one.
fn browse_url_from_self(api_self: Option<&str>, key: &str) -> Option<String> {
    let (scheme, rest) = api_self?.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = rest.split('/').next().filter(|host| !host.is_empty())?;
    Some(format!("{scheme}://{host}/browse/{key}"))
}

/// The body's Markdown as Jira's Atlassian Document Format: each
/// blank-line-separated block becomes one paragraph of one plain text
/// node — the Markdown syntax rides as literal text, which Jira renders
/// verbatim — and the blank lines themselves are skipped. A draft whose
/// body is only blanks still gets one empty paragraph: Jira v3 can reject
/// a document whose `content` array is empty, and an empty paragraph is
/// the shape Jira's own editor writes for a blank page.
fn adf_document(markdown: &str) -> Value {
    let paragraphs = markdown
        .split("\n\n")
        .map(str::trim)
        .filter(|block| !block.is_empty())
        .map(|block| {
            serde_json::json!({
                "type": "paragraph",
                "content": [{ "type": "text", "text": block }],
            })
        })
        .collect::<Vec<_>>();
    let content = if paragraphs.is_empty() {
        vec![serde_json::json!({ "type": "paragraph", "content": [] })]
    } else {
        paragraphs
    };
    serde_json::json!({ "type": "doc", "version": 1, "content": content })
}

/// The comment body's [`adf_document`] plus one paragraph carrying
/// `href` as a text node with a link mark — the one way ADF renders a
/// clickable URL.
fn adf_with_link(markdown: &str, href: &str) -> Value {
    let mut document = adf_document(markdown);
    if let Some(paragraphs) = document["content"].as_array_mut() {
        paragraphs.push(serde_json::json!({
            "type": "paragraph",
            "content": [{
                "type": "text",
                "text": href,
                "marks": [{ "type": "link", "attrs": { "href": href } }],
            }],
        }));
    }
    document
}

/// The human text inside a Jira error body — the `errorMessages` array
/// plus the field-by-field `errors` map — flattened to one line. It rides
/// `TrackerError::Rejected`, whose `Display` scrubs it: a Jira error can
/// quote tenant data. A body that is not JSON at all is quoted whole.
fn error_detail(body: &str) -> String {
    let Ok(parsed) = serde_json::from_str::<ErrorResponse>(body) else {
        return body.to_owned();
    };
    let mut parts = parsed.error_messages;
    for (field, message) in parsed.errors {
        parts.push(format!("{field}: {message}"));
    }
    if parts.is_empty() {
        body.to_owned()
    } else {
        parts.join("; ")
    }
}

/// Percent-encodes a value for a query parameter. The allowlist is RFC 3986's
/// unreserved set, so the quoted JQL's spaces, `"` and `=` all come out
/// encoded instead of terminating the parameter early. (No `url` crate:
/// one parameter is not worth a dependency.)
fn percent_encode(value: &str) -> String {
    use std::fmt::Write as _;
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

/// The slice of a create or search answer this adapter reads: the issue
/// key (`PROJ-7`), what the REST API addresses a ticket by.
#[derive(serde::Deserialize)]
struct CreatedIssue {
    #[serde(default)]
    key: Option<String>,
}

#[derive(serde::Deserialize)]
struct SearchResponse {
    #[serde(default)]
    issues: Vec<CreatedIssue>,
}

/// The two places Jira puts human text in an error body.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    #[serde(default)]
    error_messages: Vec<String>,
    #[serde(default)]
    errors: HashMap<String, String>,
}

/// Jira Cloud's inbound status webhook, over core's [`ProviderScheme`]:
/// `X-Hub-Signature: sha256=<hex>`, HMAC-SHA256 over the raw body, read by
/// [`cratefield_core::receive_status`] — verify, then parse.
///
/// **Replay is the scheme's known gap.** Jira's signature covers the body
/// and nothing else — there is no timestamp header — so the verifier's
/// replay tolerance has nothing to run on, and a captured delivery
/// verifies forever. Terminate on TLS, rotate the per-tenant secret, and
/// treat the secret as the only replay defence; that is a property of
/// Jira's scheme, not a choice of this adapter.
pub struct JiraStatusWebhook;

impl StatusWebhook for JiraStatusWebhook {
    fn kind(&self) -> &'static str {
        "jira"
    }

    /// Constant-time compare, fail-closed on unreadable input: inherited
    /// from core's [`WebhookVerifier`], never re-derived here.
    fn verifier(&self) -> WebhookVerifier {
        WebhookVerifier::new(ProviderScheme {
            signature: "X-Hub-Signature",
            encoding: SignatureEncoding::Hex,
            prefix: Some("sha256="),
            // Jira signs the body and nothing else — no timestamp header
            // exists to bind. See the replay note above.
            timestamp: None,
        })
    }

    /// Reads one **verified** delivery. A `jira:issue_updated` or
    /// `jira:issue_created` carrying a status maps onto a [`StatusUpdate`],
    /// its URL rebuilt from the issue's `self` host; every other event, and
    /// an update that names no status, is `Ok(None)` — verified silence,
    /// not an error.
    ///
    /// # Errors
    ///
    /// [`InboundStatusError::Malformed`] when the verified body is not JSON
    /// or a status event arrives without its issue key. Never
    /// [`InboundStatusError::Signature`] — that answer belongs to
    /// [`cratefield_core::receive_status`], before bytes are parsed.
    fn parse(&self, body: &[u8]) -> Result<Option<StatusUpdate>, InboundStatusError> {
        let event: Value = serde_json::from_slice(body)
            .map_err(|error| InboundStatusError::Malformed(error.to_string()))?;
        match event["webhookEvent"].as_str() {
            Some("jira:issue_updated" | "jira:issue_created") => {}
            // A ping, a comment, a delete: verified, but carries no status.
            _ => return Ok(None),
        }
        let Some(category) = event["issue"]["fields"]["status"]["statusCategory"]["key"].as_str()
        else {
            return Ok(None);
        };
        let Some(key) = event["issue"]["key"].as_str() else {
            return Err(InboundStatusError::Malformed(
                "a Jira status event carried no issue key".to_owned(),
            ));
        };
        let state = match category {
            "new" => TicketState::Open,
            "indeterminate" => TicketState::InProgress,
            "done" => TicketState::Resolved,
            _ => TicketState::Unknown,
        };
        Ok(Some(StatusUpdate {
            external_id: key.to_owned(),
            state,
            url: browse_url_from_self(event["issue"]["self"].as_str(), key),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_idem_label_is_a_prefixed_hash_of_the_key() {
        let label = idem_label("outbox-42");
        assert!(label.starts_with("cratefield-idem-"), "{label}");
        let hex_part = label.trim_start_matches("cratefield-idem-");
        assert_eq!(hex_part.len(), 32, "16 SHA-256 bytes in hex: {label}");
        assert!(hex_part.bytes().all(|b| b.is_ascii_hexdigit()));
        // Deterministic, and distinct per key.
        assert_eq!(label, idem_label("outbox-42"));
        assert_ne!(label, idem_label("outbox-43"));
    }

    #[test]
    fn a_long_title_is_truncated_on_a_character_boundary() {
        assert_eq!(truncate_summary("short"), "short");
        // Multi-byte characters: the cut must land between characters, not
        // inside one.
        let long = "é".repeat(400);
        assert_eq!(truncate_summary(&long).chars().count(), MAX_SUMMARY_CHARS);
    }

    #[test]
    /// A body of only blanks is one empty paragraph, never `content: []` —
    /// an empty `content` array is the shape Jira v3 rejects.
    fn an_all_blank_body_still_yields_one_paragraph() {
        for blank in ["", "   ", " \n\n \n"] {
            let document = adf_document(blank);
            assert_eq!(document["type"], "doc");
            let content = document["content"].as_array().expect("content array");
            assert_eq!(content.len(), 1, "{blank:?}: one paragraph, not []");
            assert_eq!(content[0]["type"], "paragraph");
            assert_eq!(content[0]["content"].as_array().map(Vec::len), Some(0));
        }
        // A body with real text is unchanged: one paragraph per block.
        let content = adf_document("first\n\nsecond")["content"]
            .as_array()
            .expect("content array")
            .clone();
        assert_eq!(content.len(), 2);
    }

    #[test]
    /// Stronger than redaction: there is no credential in the struct to
    /// redact. The `email:api_token` pair arrives per call (#453), so a
    /// `Debug` print — and anything else that reaches for the adapter's
    /// fields — cannot leak one however the struct grows.
    fn debug_of_the_adapter_holds_no_credential() {
        let adapter = JiraCloud::new(Arc::new(NoHttp), Arc::new(cratefield_core::SystemClock));
        let printed = format!("{adapter:?}");
        assert!(printed.contains("JiraCloud"), "{printed}");
        assert!(!printed.contains("api_token"), "{printed}");
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
