//! Linear adapter acceptance tests (issue #559): the one-GQL-call-per-op
//! shape, the two credential styles, the description that folds the port's
//! labels in, the state mapping table, the GraphQL failures that arrive with
//! HTTP 200, the refusals decided before any request, and the inbound status
//! webhook's verify-then-parse.

#![allow(clippy::disallowed_types)]
// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_linear::{LinearStatusWebhook, LinearTracker};
use cratefield_core::{
    Credential, Destination, HttpClient, HttpError, InboundStatusError, Severity, StatusWebhook,
    TicketComment, TicketDraft, TicketState, Tracker, TrackerError, receive_status,
};
use hmac::{Hmac, KeyInit, Mac};
use http::{HeaderMap, Request, Response, StatusCode};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// Obvious dummy values, never real.
const TEAM: &str = "8a7b1c2d-3e4f-4a5b-9c6d-7e8f9a0b1c2d";
const ISSUE_UUID: &str = "9f1c1d4e-6b2a-4f0c-9a7e-2d5b8c3e1a70";
const PERSONAL_KEY: &str = "lin_api_dummy0000000000000000000000";
const OAUTH_TOKEN: &str = "lin_oauth_dummy0000000000000000000000";
const BASE: &str = "http://linear.fake/graphql";
const ISSUE_URL: &str = "https://linear.app/acme/issue/ENG-123/outbox-refund-failed";

const ISSUE_CREATED: &str = include_str!("fixtures/issue-created.json");
const ISSUE_TRIAGE: &str = include_str!("fixtures/issue-triage.json");
const ISSUE_STARTED: &str = include_str!("fixtures/issue-started.json");
const ISSUE_COMPLETED: &str = include_str!("fixtures/issue-completed.json");
const ISSUE_CANCELED: &str = include_str!("fixtures/issue-canceled.json");
const COMMENT_CREATED: &str = include_str!("fixtures/comment-created.json");
const ERROR_400: &str = include_str!("fixtures/error-400.json");
const ERROR_401: &str = include_str!("fixtures/error-401.json");
const ERROR_RATELIMITED: &str = include_str!("fixtures/error-ratelimited.json");
const WEBHOOK_ISSUE_STATE: &str = include_str!("fixtures/webhook-issue-state.json");

/// The stamp the adapter folds in, derived as the crate derives it: the
/// first 16 bytes of SHA-256 of the idempotency key, hex.
fn idem_stamp(key: &str) -> String {
    format!(
        "cratefield-idem-{}",
        hex::encode(&Sha256::digest(key.as_bytes())[..16])
    )
}

struct CapturedRequest {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: String,
}

/// One queued response, in the order the adapter will ask for it.
struct Scripted {
    status: u16,
    body: String,
    retry_after: Option<String>,
}

fn respond(status: u16, body: &str) -> Scripted {
    Scripted {
        status,
        body: body.to_owned(),
        retry_after: None,
    }
}

impl Scripted {
    fn with_retry_after(mut self, value: &str) -> Self {
        self.retry_after = Some(value.to_owned());
        self
    }
}

/// A scripted fake: records every request out through a channel and hands
/// back the queued responses in order.
struct FakeHttp {
    responses: std::sync::Mutex<mpsc::Receiver<Scripted>>,
    calls: AtomicUsize,
    tx: mpsc::Sender<CapturedRequest>,
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (parts, body) = request.into_parts();
        self.tx
            .send(CapturedRequest {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body: String::from_utf8_lossy(&body).to_string(),
            })
            .expect("test channel open");
        let scripted = self
            .responses
            .lock()
            .expect("response queue lock")
            .try_recv()
            .expect("every request has a queued response");
        let mut builder = Response::builder()
            .status(StatusCode::from_u16(scripted.status).expect("valid status"));
        if let Some(retry) = &scripted.retry_after {
            builder = builder.header("retry-after", retry.as_str());
        }
        builder
            .body(Bytes::from(scripted.body))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

fn fixture(responses: Vec<Scripted>) -> (Arc<FakeHttp>, mpsc::Receiver<CapturedRequest>) {
    let (stx, srx) = mpsc::channel();
    for response in responses {
        stx.send(response).expect("queue holds");
    }
    drop(stx);
    let (tx, rx) = mpsc::channel();
    (
        Arc::new(FakeHttp {
            responses: std::sync::Mutex::new(srx),
            calls: AtomicUsize::new(0),
            tx,
        }),
        rx,
    )
}

fn captured(rx: &mpsc::Receiver<CapturedRequest>) -> Vec<CapturedRequest> {
    let mut seen = Vec::new();
    while let Ok(request) = rx.try_recv() {
        seen.push(request);
    }
    seen
}

fn draft() -> TicketDraft {
    TicketDraft::new(
        "idem-123",
        "Outbox: refund failed",
        "The refund webhook failed twice.\n\nSecond paragraph, after a blank line.",
        Severity::Error,
    )
    .labels(vec!["from-outbox".to_owned()])
    .environment("production")
}

/// The team these tests file into. Destination and credential ride every
/// call — tenant data (#453).
fn dest() -> Destination {
    Destination::Linear {
        team: TEAM.to_owned(),
    }
}

fn cred() -> Credential {
    Credential::new(PERSONAL_KEY)
}

fn adapter(http: Arc<FakeHttp>) -> LinearTracker {
    LinearTracker::new(http, Arc::new(cratefield_core::SystemClock)).with_base(BASE)
}

/// The `{query, variables}` body every Linear request carries.
fn operation(request: &CapturedRequest) -> Value {
    serde_json::from_str(&request.body).expect("json body")
}

// ---------------------------------------------------------------------------
// file: one mutation, both credential styles, the folded-in fields

#[pollster::test]
async fn a_file_creates_with_the_variables_the_mutation_names() {
    let (http, rx) = fixture(vec![respond(200, ISSUE_CREATED)]);
    let filed = adapter(http.clone())
        .file(&dest(), &cred(), &draft())
        .await
        .expect("file ok");
    // The UUID, not the `ENG-123` identifier: `CommentCreateInput.issueId`
    // is only documented to take the former.
    assert_eq!(filed.external_id, ISSUE_UUID);
    assert_eq!(filed.url, ISSUE_URL);

    let requests = captured(&rx);
    assert_eq!(requests.len(), 1, "one create, no dedupe lookup to make");
    let post = &requests[0];
    assert_eq!(post.method, "POST");
    assert_eq!(post.uri, BASE);
    assert_eq!(post.headers.get("accept").unwrap(), "application/json");

    let body = operation(post);
    let query = body["query"].as_str().expect("query");
    assert!(query.contains("issueCreate(input: $input)"), "{query}");
    let input = &body["variables"]["input"];
    assert_eq!(input["teamId"], TEAM);
    assert_eq!(input["title"], "Outbox: refund failed");
    // The body rides verbatim, plus the footnote the labels, the environment
    // and the stamp ride in: `IssueCreateInput` has no field for any of them.
    let description = input["description"].as_str().expect("description");
    assert!(
        description.starts_with(
            "The refund webhook failed twice.\n\nSecond paragraph, after a blank line."
        ),
        "{description}"
    );
    assert!(description.contains("label/from-outbox"), "{description}");
    assert!(description.contains("severity/error"), "{description}");
    assert!(
        description.contains("environment/production"),
        "{description}"
    );
    assert!(
        description.contains(&idem_stamp("idem-123")),
        "{description}"
    );
}

#[pollster::test]
async fn a_personal_key_is_sent_bare_and_an_oauth_token_behind_bearer() {
    // Linear's asymmetry: a personal API key takes NO `Bearer` prefix.
    let cases = [
        (PERSONAL_KEY, PERSONAL_KEY),
        (OAUTH_TOKEN, &format!("Bearer {OAUTH_TOKEN}")),
    ];
    for (secret, expected) in cases {
        let (http, rx) = fixture(vec![respond(200, ISSUE_CREATED)]);
        adapter(http.clone())
            .file(&dest(), &Credential::new(secret), &draft())
            .await
            .expect("file ok");
        let requests = captured(&rx);
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].headers.get("authorization").unwrap(),
            expected,
            "{secret}"
        );
    }
}

// ---------------------------------------------------------------------------
// status: the state-type table

#[pollster::test]
async fn status_maps_the_linear_workflow_state_types() {
    // A body shaped like Linear's own but with no `url`: this adapter
    // reports the port's `None` rather than guessing a workspace-scoped URL
    // that would 404.
    let no_url = |state_type: &str| {
        format!(
            r#"{{"data":{{"issue":{{"id":"{ISSUE_UUID}","state":{{"type":"{state_type}"}}}}}}}}"#
        )
    };
    let cases = [
        // The recorded fixtures, then the shapes a tenant's custom
        // workflows and Linear's own edge answers produce.
        (ISSUE_TRIAGE.to_owned(), TicketState::Open),
        (ISSUE_STARTED.to_owned(), TicketState::InProgress),
        (ISSUE_COMPLETED.to_owned(), TicketState::Resolved),
        (ISSUE_CANCELED.to_owned(), TicketState::Closed),
        (no_url("backlog"), TicketState::Open),
        (
            // A custom workflow added after this table was written must be
            // said so, not guessed into one of the four.
            no_url("snorkeling"),
            TicketState::Unknown,
        ),
        (no_url("started"), TicketState::InProgress),
    ];
    for (body, expected) in cases {
        let (http, rx) = fixture(vec![respond(200, &body)]);
        let status = adapter(http.clone())
            .status(&dest(), &cred(), ISSUE_UUID)
            .await
            .expect("status ok");
        assert_eq!(status.external_id, ISSUE_UUID);
        assert_eq!(status.state, expected, "{body}");
        let requests = captured(&rx);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert!(
            operation(&requests[0])["query"]
                .as_str()
                .expect("query")
                .contains("issue(id: $id)")
        );
        // The recorded fixtures carry Linear's own URL; the inline ones do
        // not.
        if body.contains(ISSUE_URL) {
            assert_eq!(status.url.as_deref(), Some(ISSUE_URL));
        } else {
            assert_eq!(status.url, None, "{body}");
        }
    }
}

#[pollster::test]
async fn a_missing_issue_is_rejected_not_reported_as_an_unknown_state() {
    // `issue: null` is Linear's not-found — the same fact a bare `404`
    // carries. `Unknown` would say "a state this port cannot name", a
    // different thing.
    let (http, _rx) = fixture(vec![respond(200, r#"{"data":{"issue":null}}"#)]);
    let err = adapter(http)
        .status(&dest(), &cred(), ISSUE_UUID)
        .await
        .expect_err("a null issue is a not-found");
    match err {
        TrackerError::Rejected(detail) => {
            assert!(detail.contains(ISSUE_UUID), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
}

// ---------------------------------------------------------------------------
// comment: one mutation, the link line, the stamp

#[pollster::test]
async fn a_comment_posts_the_markdown_with_its_link_and_the_idem_stamp() {
    let (http, rx) = fixture(vec![respond(200, COMMENT_CREATED)]);
    let comment = TicketComment::new("outbox-43", "Duplicate of the checkout 500s.")
        .with_link("https://reports.example.test/43");
    adapter(http.clone())
        .comment(&dest(), &cred(), ISSUE_UUID, &comment)
        .await
        .expect("comment ok");
    let requests = captured(&rx);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    let body = operation(&requests[0]);
    assert!(
        body["query"]
            .as_str()
            .expect("query")
            .contains("commentCreate"),
        "{body}"
    );
    let input = &body["variables"]["input"];
    // The UUID is what `issueId` is documented to take, and what `file`
    // returned.
    assert_eq!(input["issueId"], ISSUE_UUID);
    let comment_body = input["body"].as_str().expect("body");
    assert!(
        comment_body
            .starts_with("Duplicate of the checkout 500s.\n\nhttps://reports.example.test/43"),
        "{comment_body}"
    );
    assert!(
        comment_body.contains(&idem_stamp("outbox-43")),
        "{comment_body}"
    );
}

#[pollster::test]
async fn a_non_http_or_control_char_link_is_rejected_before_any_request() {
    let (http, rx) = fixture(vec![]);
    let comment = TicketComment::new("outbox-43", "See this.");
    for link in [
        "ftp://reports.example.test/43",
        // A newline would break the markdown line, and Linear's raw input is
        // not ours to sanitise afterwards.
        "https://reports.example.test/43\nhttps://elsewhere.example.test",
        "",
    ] {
        let err = adapter(http.clone())
            .comment(
                &dest(),
                &cred(),
                ISSUE_UUID,
                &comment.clone().with_link(link),
            )
            .await
            .expect_err("only a clean http(s) link is accepted");
        assert!(matches!(err, TrackerError::Rejected(_)), "{link:?}: {err}");
    }
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert!(captured(&rx).is_empty());
}

// ---------------------------------------------------------------------------
// Refusals decided before any request

#[pollster::test]
async fn a_malformed_team_or_external_id_is_rejected_with_zero_requests() {
    for team in ["", "ENG-123 team", "ENG\"}", "ENG-123\n", &"x".repeat(65)] {
        let (http, rx) = fixture(vec![]);
        let bad = Destination::Linear {
            team: team.to_owned(),
        };
        let err = adapter(http.clone())
            .file(&bad, &cred(), &draft())
            .await
            .expect_err("a malformed team is refused");
        assert!(matches!(err, TrackerError::Rejected(_)), "{team:?}: {err}");
        assert_eq!(
            http.calls.load(Ordering::SeqCst),
            0,
            "{team:?} hit the network"
        );
        assert!(captured(&rx).is_empty());
    }
    for external_id in ["ENG123", "ENG-", "-123", "ENG-123-x", "not json!"] {
        let (http, rx) = fixture(vec![]);
        let err = adapter(http.clone())
            .status(&dest(), &cred(), external_id)
            .await
            .expect_err("a malformed id is refused");
        assert!(
            matches!(err, TrackerError::Rejected(_)),
            "{external_id}: {err}"
        );
        assert_eq!(
            http.calls.load(Ordering::SeqCst),
            0,
            "{external_id} hit the network"
        );
        assert!(captured(&rx).is_empty());
    }
}

#[pollster::test]
async fn an_identifier_external_id_is_accepted_as_well_as_a_uuid() {
    // Linear's `issue(id:)` takes either; the UUID is what this adapter
    // files by, but a caller holding an identifier can read status.
    let (http, rx) = fixture(vec![respond(200, ISSUE_STARTED)]);
    adapter(http.clone())
        .status(&dest(), &cred(), "ENG-123")
        .await
        .expect("issue(id:) takes the identifier too");
    assert_eq!(captured(&rx).len(), 1);
}

#[pollster::test]
async fn a_non_linear_destination_is_rejected_without_network() {
    let (http, rx) = fixture(vec![]);
    let zendesk = Destination::Zendesk {
        subdomain: "acme".to_owned(),
    };
    let err = adapter(http.clone())
        .file(&zendesk, &cred(), &draft())
        .await
        .expect_err("this adapter does not serve Zendesk");
    match err {
        TrackerError::Rejected(detail) => {
            assert!(detail.contains("unsupported destination"), "{detail}");
            assert!(detail.contains("zendesk"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert!(captured(&rx).is_empty());
}

#[pollster::test]
async fn a_credential_that_cannot_be_a_header_is_refused_as_not_retryable() {
    // Neither shape ever reaches Linear, so neither may be reported as
    // weather to retry: an empty credential is `NotConfigured` (the adapter
    // has none) and a malformed one `Rejected`.
    let (http, rx) = fixture(vec![]);
    for (secret, expected) in [
        ("", "not configured"),
        ("lin_api_with a newline\n", "rejected"),
        ("lin_api_nonascii-é", "rejected"),
    ] {
        let err = adapter(http.clone())
            .file(&dest(), &Credential::new(secret), &draft())
            .await
            .expect_err("a credential the HTTP layer cannot carry is refused");
        match expected {
            "not configured" => assert!(
                matches!(err, TrackerError::NotConfigured),
                "{secret:?}: {err}"
            ),
            _ => assert!(
                matches!(err, TrackerError::Rejected(_)),
                "{secret:?}: {err}"
            ),
        }
    }
    assert_eq!(http.calls.load(Ordering::SeqCst), 0, "nothing was sent");
    assert!(captured(&rx).is_empty());
}

// ---------------------------------------------------------------------------
// GraphQL failures, which arrive with HTTP 200

#[pollster::test]
async fn a_graphql_error_in_a_two_hundred_fails_the_call() {
    // The failure a status-only check would file as a success: Linear
    // signals each of these in the body, with a `200`.
    let cases = [
        (ERROR_400, "rejected", "Entity not found: Team"),
        (ERROR_RATELIMITED, "transient", ""),
        (ERROR_401, "unauthorized", ""),
        // An `errors` array of strings rather than objects: a body shape
        // the typed read refuses rather than indexes into.
        (r#"{"errors":["oops"]}"#, "transient", ""),
    ];
    for (body, expected, detail) in cases {
        let (http, rx) = fixture(vec![respond(200, body)]);
        let err = adapter(http.clone())
            .file(&dest(), &cred(), &draft())
            .await
            .expect_err("a 200 carrying errors is a failure");
        match (expected, &err) {
            ("rejected", TrackerError::Rejected(seen)) => {
                assert!(seen.contains(detail), "{body}: {seen}");
            }
            ("transient" | "unauthorized", _) => {}
            (_, other) => panic!("{body}: wrong error: {other}"),
        }
        // The Linear credential never rides an error, in any rendering.
        assert!(!format!("{err:?}").contains(PERSONAL_KEY));
        assert_eq!(captured(&rx).len(), 1, "the mutation was still sent once");
    }
}

#[pollster::test]
async fn a_wrongly_shaped_two_hundred_is_an_error_not_a_panic() {
    // Every response is read through a typed struct, so a `200` whose
    // `data` is a string, or whose `errors` holds non-objects, fails the
    // call rather than indexing a value where an object was expected.
    for body in [r#"{"data":"boom"}"#, r#"{"errors":["oops"]}"#, "[1,2,3]"] {
        let (http, _rx) = fixture(vec![respond(200, body)]);
        let err = adapter(http)
            .file(&dest(), &cred(), &draft())
            .await
            .expect_err("a shape we cannot read is an error");
        assert!(
            matches!(err, TrackerError::Transient { .. }),
            "{body}: {err}"
        );
    }
}

#[pollster::test]
async fn a_create_that_reports_success_true_wins_over_a_non_fatal_errors_array() {
    // Linear attaches `errors` to partial successes — a notice the caller
    // should not re-run; failing one would file a duplicate next attempt.
    let body = serde_json::json!({
        "errors": [{ "message": "Team was archived; filed under its successor" }],
        "data": { "issueCreate": { "success": true,
            "issue": { "id": ISSUE_UUID, "url": ISSUE_URL } } },
    })
    .to_string();
    let (http, _rx) = fixture(vec![respond(200, &body)]);
    let filed = adapter(http)
        .file(&dest(), &cred(), &draft())
        .await
        .expect("a create that took effect must not be retried into a duplicate");
    assert_eq!(filed.external_id, ISSUE_UUID);
}

#[pollster::test]
async fn a_mutation_answering_success_false_is_a_failure() {
    for body in [
        serde_json::json!({ "data": { "issueCreate": { "success": false, "issue": null } } }),
        serde_json::json!({ "data": { "commentCreate": { "success": false } } }),
    ] {
        let (http, _rx) = fixture(vec![respond(200, &body.to_string())]);
        let err = if body.to_string().contains("commentCreate") {
            adapter(http)
                .comment(
                    &dest(),
                    &cred(),
                    ISSUE_UUID,
                    &TicketComment::new("outbox-43", "See this."),
                )
                .await
                .expect_err("success: false is a refusal")
        } else {
            adapter(http)
                .file(&dest(), &cred(), &draft())
                .await
                .expect_err("success: false is a refusal")
        };
        match err {
            TrackerError::Rejected(detail) => {
                assert!(detail.contains("success: false"), "{detail}");
            }
            other => panic!("wrong error: {other}"),
        }
    }
}

#[pollster::test]
async fn status_mapping_is_the_error_table() {
    let cases = [
        (401u16, None, "unauthorized"),
        (403, None, "unauthorized"),
        (400, None, "rejected"),
        (404, None, "rejected"),
        // The seconds form of `Retry-After` (issue #214) rides the 429.
        (429, Some("5"), "transient"),
        (500, None, "transient"),
        (503, None, "transient"),
    ];
    for (status, retry_after, expected) in cases {
        let scripted = match retry_after {
            Some(value) => respond(status, ERROR_400).with_retry_after(value),
            None => respond(status, ERROR_400),
        };
        let (http, _rx) = fixture(vec![scripted]);
        let err = adapter(http)
            .status(&dest(), &cred(), ISSUE_UUID)
            .await
            .expect_err("must fail");
        match (&err, expected) {
            (TrackerError::Unauthorized, "unauthorized")
            | (TrackerError::Rejected(_), "rejected") => {}
            (TrackerError::Transient { retry_after: seen }, "transient") => {
                let want = retry_after.map(|value| Duration::from_secs(value.parse().unwrap()));
                assert_eq!(*seen, want, "status {status}: {err}");
            }
            _ => panic!("status {status}: wrong error: {err}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The inbound status webhook

/// The bare-hex signature Linear would send for this body.
fn linear_signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn sig_headers(value: &str) -> HeaderMap {
    [(
        "linear-signature".parse().expect("header name"),
        value.parse().expect("header value"),
    )]
    .into_iter()
    .collect()
}

/// Signs `body` the way Linear would and hands it to `receive_status`.
fn receive(
    secret: &str,
    body: &[u8],
) -> Result<Option<cratefield_core::StatusUpdate>, InboundStatusError> {
    receive_status(
        &LinearStatusWebhook,
        secret,
        &sig_headers(&linear_signature(secret, body)),
        body,
        0,
    )
}

#[test]
fn a_correctly_signed_webhook_yields_a_status_update() {
    assert_eq!(LinearStatusWebhook.kind(), "linear");
    let body = WEBHOOK_ISSUE_STATE.as_bytes();
    assert_eq!(
        receive("shared-secret", body).expect("verified"),
        Some(cratefield_core::StatusUpdate {
            // The issue UUID, exactly what `file` returns.
            external_id: ISSUE_UUID.to_owned(),
            state: TicketState::Resolved,
            url: Some(ISSUE_URL.to_owned()),
        })
    );
}

#[test]
fn a_bad_signature_is_refused_without_parsing() {
    let body = WEBHOOK_ISSUE_STATE.as_bytes();
    let signed = sig_headers(&linear_signature("shared-secret", body));
    // A wrong secret and a tampered body: both `Signature`, never a parse.
    assert_eq!(
        receive_status(&LinearStatusWebhook, "wrong-secret", &signed, body, 0).unwrap_err(),
        InboundStatusError::Signature
    );
    assert_eq!(
        receive_status(
            &LinearStatusWebhook,
            "shared-secret",
            &signed,
            br#"{"action":"update"}"#,
            0
        )
        .unwrap_err(),
        InboundStatusError::Signature
    );
    assert_eq!(
        receive_status(
            &LinearStatusWebhook,
            "shared-secret",
            &HeaderMap::new(),
            body,
            0
        )
        .unwrap_err(),
        InboundStatusError::Signature
    );
}

#[test]
fn a_non_state_event_or_one_that_touched_no_state_is_none() {
    // A comment, a project, an issue *created*, and an issue update whose
    // `updatedFrom` names no state: verified silence, not an error.
    let issue_data = serde_json::json!({
        "id": ISSUE_UUID,
        "identifier": "ENG-123",
        "state": { "type": "completed", "name": "Done" },
    });
    let cases = [
        serde_json::json!({ "action": "create", "type": "Issue", "data": issue_data }),
        serde_json::json!({ "action": "remove", "type": "Issue", "data": issue_data }),
        serde_json::json!({ "action": "update", "type": "Comment",
                           "data": { "issueId": ISSUE_UUID } }),
        serde_json::json!({ "action": "update", "type": "Project",
                           "data": { "name": "Platform" } }),
        // An update that touched an assignee, not the state.
        serde_json::json!({ "action": "update", "type": "Issue", "data": issue_data,
                           "updatedFrom": { "assigneeId": "user-1" } }),
    ];
    for payload in cases {
        let body = serde_json::to_vec(&payload).expect("serialises");
        assert_eq!(
            receive("shared-secret", &body).expect("verified"),
            None,
            "{payload}"
        );
    }
}

#[test]
fn verified_but_unreadable_json_is_malformed() {
    // Not JSON at all, and JSON that is not an event shape: a typed read's
    // failure, never a panic on a missing field.
    for body in [
        &b"not json at all"[..],
        b"[1]",
        b"\"a string\"",
        br#"{"action":"update","type":"Issue","data":"boom"}"#,
        br#"{"action":"update","type":12}"#,
    ] {
        let err = receive("shared-secret", body).expect_err("must be malformed");
        assert!(matches!(err, InboundStatusError::Malformed(_)), "{err}");
    }
}

// ---------------------------------------------------------------------------
// The dependency tree

#[test]
fn linear_deps_are_wasm_safe() {
    cratefield_testing::assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
