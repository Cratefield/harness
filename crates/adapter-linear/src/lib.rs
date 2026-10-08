#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, Credential, Destination, Filed, HttpClient, HttpError, InboundStatusError,
    ProviderScheme, SignatureEncoding, StatusUpdate, StatusWebhook, TicketComment, TicketDraft,
    TicketState, TicketStatus, Tracker, TrackerError, WebhookVerifier, retry_after,
};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use http::{Request, StatusCode};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Linear's GraphQL endpoint — one URL for every operation, so the
/// operation rides the body's `query` and the arguments its `variables`.
const GRAPHQL_URL: &str = "https://api.linear.app/graphql";
/// The prefix every Linear **personal API key** carries, and the only thing
/// that tells a personal key from an OAuth access token in core's
/// one-opaque-string [`Credential`]. A key is sent bare; a token behind
/// `Bearer `.
const PERSONAL_KEY_PREFIX: &str = "lin_api_";
/// Linear's cap on `title`; a longer one is truncated on a character boundary
/// rather than failing the create.
const MAX_TITLE_CHARS: usize = 255;
/// The idempotency stamp folded into the description and every comment body,
/// so an at-least-once redelivery that files or notes twice leaves a
/// duplicate a single text search can find. The crate's own prefix, so a
/// tenant's text can never collide with it.
const IDEM_PREFIX: &str = "cratefield-idem-";

/// `mutation IssueCreate($input: IssueCreateInput!)` — one create, the
/// issue's UUID and `url` read straight back off it.
const ISSUE_CREATE: &str = "mutation IssueCreate($input: IssueCreateInput!) { \
     issueCreate(input: $input) { success issue { id url } } }";
/// `query Issue($id: String!)`. Linear's `issue(id:)` takes the UUID or an
/// `ENG-123` identifier; this adapter files and reports by UUID, because
/// `CommentCreateInput.issueId` is only documented to take the former.
const ISSUE_QUERY: &str = "query Issue($id: String!) { issue(id: $id) { id url state { type } } }";
/// `mutation CommentCreate($input: CommentCreateInput!)`.
const COMMENT_CREATE: &str = "mutation CommentCreate($input: CommentCreateInput!) { commentCreate(input: $input) { success } }";

/// `Tracker` over the Linear GraphQL API.
///
/// No `Debug` derive: kept explicit so a field added later cannot print
/// `Debug` would print it wherever a log line or a panic message met the
/// adapter.
pub struct LinearTracker {
    http: Arc<dyn HttpClient>,
    /// Needed only to read the HTTP-date form of `Retry-After` (issue #278),
    /// the same reason the GitHub Issues and Jira adapters hold one. A
    /// constructor argument rather than a builder default so a deployment
    /// that forgets it fails to compile instead of silently retrying a
    /// date-form 429 immediately.
    clock: Arc<dyn Clock>,
    /// `None` — the default — posts to [`GRAPHQL_URL`]; a value overrides it
    /// for tests pointed at a fake.
    base: Option<String>,
}

impl std::fmt::Debug for LinearTracker {
    /// Holds no credential to leak: the Linear key or OAuth token arrives
    /// per call (#453).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinearTracker")
            .field("base", &self.base)
            // The http and clock ports are struct fields too; nothing about
            // either belongs in a log line.
            .finish_non_exhaustive()
    }
}

impl LinearTracker {
    /// An adapter pointed at Linear's GraphQL API. It holds no credential:
    /// which team, addressed under whose key, is tenant data and arrives
    /// with each call (#453).
    #[must_use]
    pub fn new(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self {
            http,
            clock,
            base: None,
        }
    }

    /// Overrides the URL every request is posted to — a fake in tests —
    /// instead of Linear's own `https://api.linear.app/graphql`.
    #[must_use]
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = Some(base.into());
        self
    }

    /// The absolute URL requests are posted to.
    fn endpoint(&self) -> &str {
        self.base.as_deref().unwrap_or(GRAPHQL_URL)
    }

    /// The headers every Linear request carries: the tenant's
    /// `Authorization`, and the JSON accept Linear answers with.
    ///
    /// A credential the HTTP layer cannot carry is refused here rather than
    /// sent. Neither that nor an empty one is retryable: an empty one is
    /// [`TrackerError::NotConfigured`], a malformed one
    /// [`TrackerError::Rejected`].
    fn request(cred: &Credential, uri: &str, body: Bytes) -> Result<Request<Bytes>, TrackerError> {
        let secret = cred.expose();
        if secret.is_empty() {
            return Err(TrackerError::NotConfigured);
        }
        // Narrower than `HeaderValue::from_str` accepts, which admits a
        // space and any byte above 127 as obs-text — neither of which a
        // Linear key carries.
        let malformed =
            || TrackerError::Rejected("linear credential is not a legal header value".to_owned());
        if !secret.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(malformed());
        }
        let value = HeaderValue::from_str(&auth_header(secret)).map_err(|_| malformed())?;
        Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(AUTHORIZATION, value)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .map_err(|_| TrackerError::Rejected("linear request could not be built".into()))
    }

    /// Sends one request and returns the body of a `2xx` answer. Anything
    /// else — a transport failure or a non-2xx status — comes back as a
    /// [`TrackerError`], already mapped.
    async fn send_checked(&self, request: Request<Bytes>) -> Result<String, TrackerError> {
        let response = self.http.send(request).await.map_err(|err: HttpError| {
            match err {
                // The port's SSRF vetting refused the destination URL (a
                // scheme, userinfo, or a loopback / private / link-local /
                // metadata destination, re-vetted per redirect hop): a config
                // error, not weather.
                HttpError::BlockedDestination(detail) => {
                    TrackerError::Rejected(format!("linear destination refused: {detail}"))
                }
                // Any other transport failure is weather — retry. The
                // provider's text cannot ride `Transient`, which carries
                // only the delay, so it goes to the log the way the sibling
                // adapters' does: an operator still gets to read it.
                other => {
                    tracing::warn!(provider = "linear", outcome = "failed", error = %other, "tracker outcome");
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
                provider = "linear",
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

    /// Maps a Linear HTTP status onto the port's error taxonomy — the same
    /// table the GitHub Issues and Jira adapters apply: `401`/`403` say the
    /// key is wrong or powerless; the rest of the `4xx` family is a fact
    /// about our request; `429` and the `5xx` family are the provider having
    /// a moment.
    fn map_status(
        status: StatusCode,
        body: &str,
        retry_after: Option<std::time::Duration>,
    ) -> TrackerError {
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => TrackerError::Unauthorized,
            // Must precede the `4xx` arm — 429 *is* a client error.
            // (`retry_after` reads both header forms and answers `None` when
            // no header came, so a bare 500 stays unscheduled.)
            status if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS => {
                TrackerError::Transient { retry_after }
            }
            status if status.is_client_error() => {
                TrackerError::Rejected(format!("linear {status}: {}", flatten_errors(body)))
            }
            _ => TrackerError::Transient { retry_after },
        }
    }

    /// Posts one GraphQL operation and returns its `data`.
    ///
    /// The GraphQL-specific half of "is this a failure": Linear answers a
    /// failed operation with a **`200`** whose body carries a top-level
    /// `errors` array, so a status check alone would read every rejection as
    /// a success.
    ///
    /// `accepted` says whether this operation's own payload reports that it
    /// took effect. A mutation that did — `issueCreate { success: true }` —
    /// wins over a non-fatal `errors` array, which Linear attaches to partial
    /// successes; failing such a create would file a duplicate on the next
    /// attempt. The errors are mapped only when nothing accepted the call.
    async fn graphql(
        &self,
        cred: &Credential,
        query: &str,
        variables: serde_json::Value,
        accepted: impl Fn(&Payload) -> bool,
    ) -> Result<Payload, TrackerError> {
        let body = serde_json::json!({ "query": query, "variables": variables });
        let json =
            serde_json::to_vec(&body).map_err(|_| TrackerError::Transient { retry_after: None })?;
        let request = Self::request(cred, self.endpoint(), Bytes::from(json))?;
        let text = self.send_checked(request).await?;
        // Every response shape is read through a typed struct, never by
        // indexing a `Value`: indexing where an object was expected panics,
        // and these bodies come from the network. A 2xx we cannot read is
        // not one we can trust — transient, and let the caller retry.
        let response: Response = serde_json::from_str(&text)
            .map_err(|_| TrackerError::Transient { retry_after: None })?;
        if response.errors.is_empty() || accepted(&response.data) {
            return Ok(response.data);
        }
        Err(map_errors(&response.errors))
    }
}

#[async_trait]
impl Tracker for LinearTracker {
    /// One `issueCreate` mutation. `title` is the draft's own, truncated to
    /// Linear's cap; `description` is the Markdown body verbatim (Linear
    /// renders Markdown, so there is no document format to translate) plus a
    /// footnote carrying what the port's shape has and Linear's input has no
    /// field for: the labels, the environment, the severity, the stamp.
    ///
    /// **`external_id` is the issue's UUID**, the only id
    /// `CommentCreateInput.issueId` is documented to take. **`Filed` is not
    /// idempotent:** Linear offers no stamp to search an issue by, so the
    /// at-least-once outbox may file twice; see the README.
    async fn file(
        &self,
        dest: &Destination,
        cred: &Credential,
        draft: &TicketDraft,
    ) -> Result<Filed, TrackerError> {
        let team = team_of(dest)?;
        let input = serde_json::json!({
            "teamId": team,
            "title": truncate_title(&draft.title),
            "description": description(draft),
        });
        let data = self
            .graphql(
                cred,
                ISSUE_CREATE,
                serde_json::json!({ "input": input }),
                |data| {
                    data.issue_create
                        .as_ref()
                        .is_some_and(|made| made.success == Some(true))
                },
            )
            .await?;
        let created = data
            .issue_create
            .as_ref()
            // Linear's `success: false` with no `errors` is the other shape
            // of a refusal; both must fail the call.
            .filter(|made| made.success != Some(false))
            .ok_or_else(|| {
                TrackerError::Rejected("linear issueCreate reported success: false".to_owned())
            })?;
        // A 2xx carrying no issue is not a create this adapter can trust:
        // transient, and let the next attempt settle it.
        let issue = created
            .issue
            .as_ref()
            .ok_or(TrackerError::Transient { retry_after: None })?;
        let external_id = issue
            .id
            .as_deref()
            .ok_or(TrackerError::Transient { retry_after: None })?;
        let url = issue
            .url
            .as_deref()
            .ok_or(TrackerError::Transient { retry_after: None })?;
        tracing::info!(
            provider = "linear",
            outcome = "created",
            idempotency = %draft.idempotency_key,
            issue = %external_id,
            "tracker outcome"
        );
        Ok(Filed {
            external_id: external_id.to_owned(),
            url: url.to_owned(),
        })
    }

    /// One `issue(id:)` query, mapping `state.type` — Linear's own
    /// workflow-type rollup, the field that survives every custom workflow a
    /// tenant renames — onto the port's five.
    async fn status(
        &self,
        dest: &Destination,
        cred: &Credential,
        external_id: &str,
    ) -> Result<TicketStatus, TrackerError> {
        team_of(dest)?;
        validate_external_id(external_id)?;
        let data = self
            .graphql(
                cred,
                ISSUE_QUERY,
                serde_json::json!({ "id": external_id }),
                |_| false,
            )
            .await?;
        let issue = data.issue.as_ref().ok_or_else(|| {
            // `issue: null` is Linear's not-found — the same fact a bare
            // `404` carries, and the same answer: `Rejected`, since a retry
            // of a missing issue changes nothing. `Unknown` would read as
            // "the state is one this port cannot name", a different thing.
            TrackerError::Rejected(format!("linear has no issue {external_id}"))
        })?;
        Ok(TicketStatus {
            external_id: external_id.to_owned(),
            state: state_of(issue.state.as_ref().and_then(|state| state.kind.as_deref())),
            // Linear's own URL, or none: its `linear.app/{workspace}/issue/…`
            // form needs the workspace slug, which nothing here carries, and
            // a guess that would 404 is worse than the port's `None`.
            url: issue.url.clone(),
        })
    }

    /// One `commentCreate` mutation: the note's Markdown verbatim plus, when
    /// it carries one, a trailing line linking it. No search-before-write, so
    /// a redelivery may duplicate the note — but the key rides the body as
    /// the same `cratefield-idem-…` stamp, so any duplicate is findable.
    async fn comment(
        &self,
        dest: &Destination,
        cred: &Credential,
        external_id: &str,
        comment: &TicketComment,
    ) -> Result<(), TrackerError> {
        team_of(dest)?;
        validate_external_id(external_id)?;
        let body = match comment.link.as_deref() {
            // Linear renders Markdown, so the link is one markdown line;
            // only an http(s) link with no control character in it is worth
            // one, decided before any request.
            Some(link)
                if (link.starts_with("https://") || link.starts_with("http://"))
                    && !link.chars().any(char::is_control) =>
            {
                format!("{}\n\n{link}", comment.body_markdown.trim_end())
            }
            Some(_) => {
                return Err(TrackerError::Rejected(
                    "linear comment link must be an http(s) URL with no control characters"
                        .to_owned(),
                ));
            }
            None => comment.body_markdown.clone(),
        };
        let input = serde_json::json!({
            "issueId": external_id,
            "body": format!("{body}\n\n---\n\n{IDEM_PREFIX}{}", idem_hash(&comment.idempotency_key)),
        });
        let data = self
            .graphql(
                cred,
                COMMENT_CREATE,
                serde_json::json!({ "input": input }),
                |data| {
                    data.comment_create
                        .as_ref()
                        .is_some_and(|made| made.success == Some(true))
                },
            )
            .await?;
        if data
            .comment_create
            .as_ref()
            .is_none_or(|made| made.success == Some(false))
        {
            return Err(TrackerError::Rejected(
                "linear commentCreate reported success: false".to_owned(),
            ));
        }
        tracing::info!(
            provider = "linear",
            outcome = "commented",
            idempotency = %comment.idempotency_key,
            issue = external_id,
            "tracker outcome"
        );
        Ok(())
    }
}

/// One GraphQL response, read as a struct: `serde` fails on a body whose
/// shape is not this one, which keeps a hostile or simply odd `200` from
/// turning into a panic.
#[derive(Deserialize, Default)]
struct Response {
    #[serde(default)]
    errors: Vec<GraphqlError>,
    #[serde(default)]
    data: Payload,
}

/// The `data` object. Every field is optional: which one an operation fills
/// is the operation's own business, and a missing one is a `2xx` read as an
/// answer this adapter cannot trust — never as an index panic.
#[derive(Deserialize, Default)]
struct Payload {
    #[serde(rename = "issueCreate")]
    issue_create: Option<Mutation>,
    #[serde(rename = "commentCreate")]
    comment_create: Option<Mutation>,
    issue: Option<Issue>,
}

/// One mutation's `success` and, for a create, the issue it made.
#[derive(Deserialize, Default)]
struct Mutation {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    issue: Option<Issue>,
}

/// The slice of an issue this adapter reads.
#[derive(Deserialize)]
struct Issue {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    state: Option<WorkflowState>,
}

/// A workflow state, read for its `type` — the rollup, not the name, which a
/// tenant renames freely.
#[derive(Deserialize)]
struct WorkflowState {
    #[serde(rename = "type", default)]
    kind: Option<String>,
}

/// One entry of a GraphQL `errors` array, and the `extensions` it carries for
/// its machine-readable code.
#[derive(Deserialize, Default)]
struct GraphqlError {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    extensions: Option<GraphqlErrorExtensions>,
}

#[derive(Deserialize, Default)]
struct GraphqlErrorExtensions {
    #[serde(default)]
    code: Option<String>,
}

/// Linear's inbound status webhook, over core's [`ProviderScheme`]:
/// `Linear-Signature: <hex>`, HMAC-SHA256 over the raw body with no prefix,
/// read by [`cratefield_core::receive_status`] — verify, then parse.
///
/// **Replay protection is not provided here.** Linear signs the raw body
/// alone — its `webhookTimestamp` (ms) rides *inside* that body, not in a
/// header — and core's [`ProviderScheme`] can only bind a timestamp *header*
/// into the signed payload, so the verifier's replay tolerance has nothing to
/// run on and a captured delivery verifies forever, exactly as with Jira.
/// This type parses the body and nothing else; a caller wanting a freshness
/// window must read `webhookTimestamp` (and the delivery's `webhookId`) out of
/// the already-verified body itself. Terminate on TLS and rotate the
/// per-tenant secret either way.
pub struct LinearStatusWebhook;

impl StatusWebhook for LinearStatusWebhook {
    fn kind(&self) -> &'static str {
        "linear"
    }

    /// Constant-time compare, fail-closed on unreadable input: inherited
    /// from core's [`WebhookVerifier`], never re-derived here.
    fn verifier(&self) -> WebhookVerifier {
        WebhookVerifier::new(ProviderScheme {
            signature: "Linear-Signature",
            encoding: SignatureEncoding::Hex,
            // Linear sends bare hex — no `sha256=` prefix, unlike GitHub.
            prefix: None,
            // Linear's timestamp is in the body, not a header, so it cannot
            // be bound into the signed payload here. See the replay note.
            timestamp: None,
        })
    }

    /// Reads one **verified** delivery. An `update` on `"type": "Issue"`
    /// that carries a state **and** names the state it came from
    /// (`updatedFrom.stateId`) maps onto a [`StatusUpdate`] keyed by the same
    /// issue UUID [`Tracker::file`] returns; every other event, and an update
    /// that touched no state, is `Ok(None)` — verified silence, not an error.
    ///
    /// # Errors
    ///
    /// [`InboundStatusError::Malformed`] when the verified body is not JSON or
    /// not an event of the shape Linear sends, or a state change arrives with
    /// no id to key it by. Never [`InboundStatusError::Signature`] — that
    /// belongs to [`cratefield_core::receive_status`], before parsing.
    fn parse(&self, body: &[u8]) -> Result<Option<StatusUpdate>, InboundStatusError> {
        // Typed, so a body that is a JSON array or a bare string is
        // `Malformed` rather than a panic on a missing field.
        let event: Event = serde_json::from_slice(body)
            .map_err(|error| InboundStatusError::Malformed(error.to_string()))?;
        // A comment, a project, an issue *created*: verified, but not a
        // state change we were told to trust.
        if event.kind.as_deref() != Some("Issue") || event.action.as_deref() != Some("update") {
            return Ok(None);
        }
        let data = event.data.as_ref();
        let Some(state_type) = data
            .and_then(|data| data.state.as_ref())
            .and_then(|state| state.kind.as_deref())
        else {
            return Ok(None);
        };
        // `updatedFrom.stateId` is Linear's own "this field changed" marker:
        // without it the update touched something else (an assignee, a
        // title) and the state here is the one it already had.
        if !event.state_changed() {
            return Ok(None);
        }
        let external_id = data.and_then(|data| data.id.as_deref()).ok_or_else(|| {
            InboundStatusError::Malformed("a Linear state change carried no issue id".to_owned())
        })?;
        Ok(Some(StatusUpdate {
            external_id: external_id.to_owned(),
            state: state_of(Some(state_type)),
            url: event.url.clone(),
        }))
    }
}

/// One inbound webhook event, in the shape [`LinearStatusWebhook::parse`]
/// reads. Linear puts `updatedFrom` **beside** `data`, not inside it: the
/// fields this delivery changed.
#[derive(Deserialize)]
struct Event {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    data: Option<EventData>,
    #[serde(rename = "updatedFrom", default)]
    updated_from: Option<UpdatedFrom>,
}

impl Event {
    /// Whether the **state** is what changed: the presence of
    /// `updatedFrom.stateId`, which is the whole of its meaning — its value
    /// is never read.
    fn state_changed(&self) -> bool {
        self.updated_from
            .as_ref()
            .is_some_and(|from| from.state_id.is_some())
    }
}

/// The `data` of an issue event.
#[derive(Deserialize)]
struct EventData {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    state: Option<WorkflowState>,
}

/// Linear's `updatedFrom`, present only on an update that changed something.
#[derive(Deserialize)]
struct UpdatedFrom {
    #[serde(rename = "stateId", default)]
    state_id: Option<String>,
}

/// The `Authorization` value for Linear's two credential shapes.
///
/// Core's [`Credential`] is one opaque string, so this is decided by Linear's
/// own documented prefix: a **personal API key** (always `lin_api_…`) is sent
/// **bare**, with no `Bearer` — Linear rejects the prefix on personal keys —
/// while anything else is an OAuth **access token** and takes `Bearer `.
///
/// The returned `String` is a copy the HTTP layer owns; only the
/// [`Credential`]'s own buffer is zeroised on drop. The token appears here,
/// in that header, and nowhere else — never in an error, a log or a `Debug`.
fn auth_header(secret: &str) -> String {
    if secret.starts_with(PERSONAL_KEY_PREFIX) {
        secret.to_owned()
    } else {
        format!("Bearer {secret}")
    }
}

/// The GraphQL `errors` array, mapped onto the port's taxonomy.
///
/// Linear signals a rate limit with `RATELIMITED` in
/// `errors[].extensions.code` and **HTTP 200**, so a status-only check would
/// file a throttled create as a success. Authentication comes first: Linear
/// answers an expired OAuth token with `AUTHENTICATION`, and a team the key
/// cannot reach with `AUTHORIZATION`.
fn map_errors(errors: &[GraphqlError]) -> TrackerError {
    let code = |wanted: &[&str]| {
        errors
            .iter()
            .filter_map(|error| error.extensions.as_ref())
            .filter_map(|extensions| extensions.code.as_deref())
            .any(|code| wanted.contains(&code))
    };
    if code(&["AUTHENTICATION", "AUTHORIZATION", "INVALID_TOKEN"]) {
        return TrackerError::Unauthorized;
    }
    if code(&[
        "RATELIMITED",
        "INTERNAL_SERVER_ERROR",
        "SERVICE_UNAVAILABLE",
        "TIMEOUT",
    ]) {
        // Linear names no `Retry-After` alongside a 200, so there is no delay
        // to schedule; the caller's own backoff is the answer.
        return TrackerError::Transient { retry_after: None };
    }
    TrackerError::Rejected(format!("linear graphql error: {}", join_messages(errors)))
}

/// Every `errors[].message` flattened to one line, or a stand-in when none
/// came. It rides [`TrackerError::Rejected`], whose `Display` scrubs it — a
/// Linear error can quote tenant data.
fn join_messages(errors: &[GraphqlError]) -> String {
    let detail = errors
        .iter()
        .filter_map(|error| error.message.as_deref())
        .filter(|message| !message.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    if detail.is_empty() {
        "the response carried no message".to_owned()
    } else {
        detail
    }
}

/// The human text inside an error **body**, whether or not it is a GraphQL
/// envelope: its `errors[].message` array flattened to one line, or the body
/// quoted whole when it is not JSON or carries no message.
fn flatten_errors(body: &str) -> String {
    match serde_json::from_str::<Response>(body) {
        Ok(response) if !response.errors.is_empty() => join_messages(&response.errors),
        _ => body.to_owned(),
    }
}

/// The team a [`Destination::Linear`] names, or the rejection for any other
/// destination — decided before any request, the way the GitHub adapter
/// refuses a webhook.
///
/// Linear's `issueCreate` takes `teamId`, the team's UUID, not its key, so
/// that is what a tenant configures here.
fn team_of(dest: &Destination) -> Result<&str, TrackerError> {
    match dest {
        Destination::Linear { team } => {
            validate_team(team)?;
            Ok(team.as_str())
        }
        other => Err(TrackerError::unsupported_destination(other)),
    }
}

/// A team id must be a UUID or a team key: ASCII alphanumerics, `-` and `_`,
/// nothing else, and not empty or absurdly long.
///
/// This is **fail-fast input checking, not injection defence** — the value
/// rides as a GraphQL *variable*, which serde JSON-encodes, so it cannot
/// reshape the operation whatever it holds. What it buys is naming a
/// misconfigured team at the call site instead of surfacing as an opaque
/// GraphQL rejection.
fn validate_team(team: &str) -> Result<(), TrackerError> {
    let valid = !team.is_empty()
        && team.len() <= 64
        && team
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        Err(TrackerError::Rejected(
            "linear team must be a team UUID or key (letters, digits, '-' and '_')".to_owned(),
        ))
    }
}

/// An external id must be one Linear's `issue(id:)` accepts — the UUID
/// [`Tracker::file`] returns, or an `ENG-123` identifier — before it is sent.
/// Same fail-fast rationale as [`validate_team`]: it rides as a GraphQL
/// variable, so it names a malformed value at the call site.
fn validate_external_id(external_id: &str) -> Result<(), TrackerError> {
    let is_uuid = external_id.len() == 36
        && external_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-')
        && external_id.matches('-').count() == 4;
    let is_identifier = match external_id.split_once('-') {
        Some((key, number)) => {
            !key.is_empty()
                && !number.is_empty()
                && number.bytes().all(|b| b.is_ascii_digit())
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    };
    if is_uuid || is_identifier {
        Ok(())
    } else {
        Err(TrackerError::Rejected(
            "linear external id must be an issue UUID or an ENG-123 identifier".to_owned(),
        ))
    }
}

/// The description a filed issue carries: the draft's Markdown verbatim
/// (Linear renders Markdown natively, so unlike Jira there is no document
/// format to translate) plus a footnote with everything the port's shape has
/// and `IssueCreateInput` has no field for.
///
/// **The labels are folded in here rather than mapped to `labelIds`.** Linear
/// addresses a label by its UUID, and the port's `labels` are free-form text
/// a tenant chose — guessing a UUID from a label name would attach a
/// *different* tenant's label, or none, so the text rides the body where it is
/// at least findable.
fn description(draft: &TicketDraft) -> String {
    let mut facts = vec![format!("severity/{}", draft.severity.name())];
    facts.extend(draft.labels.iter().map(|label| format!("label/{label}")));
    if let Some(environment) = &draft.environment {
        facts.push(format!("environment/{environment}"));
    }
    format!(
        "{}\n\n---\n\n{}\n\n{IDEM_PREFIX}{}",
        draft.body_markdown.trim_end(),
        facts.join(" · "),
        idem_hash(&draft.idempotency_key)
    )
}

/// The stamp tying an issue or a note to an outbox idempotency key:
/// [`IDEM_PREFIX`] plus the first 16 bytes of SHA-256 of the key, hex —
/// hashed, because the body is text a Linear search greps for and a caller's
/// key may quote tenant data.
fn idem_hash(idempotency_key: &str) -> String {
    hex::encode(&Sha256::digest(idempotency_key.as_bytes())[..16])
}

/// Linear caps `title` at [`MAX_TITLE_CHARS`]; a longer title is truncated on
/// a character boundary — a split character is something serde's JSON writer
/// would refuse to emit.
fn truncate_title(title: &str) -> &str {
    match title.char_indices().nth(MAX_TITLE_CHARS) {
        Some((at, _)) => &title[..at],
        None => title,
    }
}

/// Maps Linear's `state.type` — its workflow-type rollup, which survives
/// every custom workflow a tenant renames — onto the port's five. A type the
/// port cannot name is said so rather than guessed into one of the four.
/// Canceled is done, not done-and-fixed: `Closed` is the port's "will not be
/// reopened".
fn state_of(state_type: Option<&str>) -> TicketState {
    match state_type {
        // Filed, triaged, backlogged or scheduled, but nobody started it.
        Some("triage" | "backlog" | "unstarted") => TicketState::Open,
        Some("started") => TicketState::InProgress,
        Some("completed") => TicketState::Resolved,
        Some("canceled") => TicketState::Closed,
        _ => TicketState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_title_is_truncated_on_a_character_boundary() {
        assert_eq!(truncate_title("short"), "short");
        // Multi-byte characters: the cut must land between characters, not
        // inside one.
        let long = "é".repeat(400);
        assert_eq!(truncate_title(&long).chars().count(), MAX_TITLE_CHARS);
    }
}
