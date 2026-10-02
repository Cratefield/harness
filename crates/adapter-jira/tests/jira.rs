//! Jira Cloud adapter acceptance tests (issue #559): search-before-create
//! dedupe, the fail-closed lookup, the Basic credential, ADF bodies, the
//! status mapping table, the site/project/key validation that refuses
//! before any request, and the inbound status webhook's verify-then-parse.

#![allow(clippy::disallowed_types)]
// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use cratefield_adapter_jira::{JiraCloud, JiraStatusWebhook};
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
const SITE: &str = "acme.atlassian.net";
const PROJECT: &str = "PROJ";
const CREDENTIAL: &str = "devops@acme.test:ATATTdummytoken0000000000";
const BASE: &str = "http://jira.fake";
const SEARCH_PREFIX: &str = "http://jira.fake/rest/api/3/search/jql?jql=";
const ISSUE_URI: &str = "http://jira.fake/rest/api/3/issue";
const COMMENT_URI: &str = "http://jira.fake/rest/api/3/issue/PROJ-7/comment";

const CREATE_ISSUE: &str = include_str!("fixtures/create-issue.json");
const SEARCH_HIT: &str = include_str!("fixtures/search-hit.json");
const SEARCH_EMPTY: &str = include_str!("fixtures/search-empty.json");
const STATUS_NEW: &str = include_str!("fixtures/issue-status-new.json");
const STATUS_INDETERMINATE: &str = include_str!("fixtures/issue-status-indeterminate.json");
const STATUS_DONE: &str = include_str!("fixtures/issue-status-done.json");
const ERROR_400: &str = include_str!("fixtures/error-400.json");
const COMMENT_CREATED: &str = include_str!("fixtures/comment-created.json");
const WEBHOOK_ISSUE_UPDATED: &str = include_str!("fixtures/webhook-issue-updated.json");

/// The label the adapter stamps, derived exactly as the crate derives it:
/// first 16 bytes of SHA-256 of the idempotency key, hex.
fn idem_label(key: &str) -> String {
    format!(
        "cratefield-idem-{}",
        hex_encode(&Sha256::digest(key.as_bytes())[..16])
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The Basic header value for the test credential, built the way RFC 7617
/// builds it.
fn basic_header() -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(CREDENTIAL.as_bytes())
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

/// A scripted fake: records every request (method, uri, headers, body) out
/// through a channel and hands back the queued responses in order.
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

/// The site and project these tests file into. Destination and credential
/// ride every call — they are tenant data (#453).
fn dest() -> Destination {
    Destination::Jira {
        site: SITE.to_owned(),
        project: PROJECT.to_owned(),
    }
}

fn cred() -> Credential {
    Credential::new(CREDENTIAL)
}

fn adapter(http: Arc<FakeHttp>) -> JiraCloud {
    JiraCloud::new(http, Arc::new(cratefield_core::SystemClock)).with_base(BASE)
}

// ---------------------------------------------------------------------------
// file: the happy path, the dedupe, the fail-closed rule

#[pollster::test]
async fn a_file_creates_through_the_search_with_basic_auth_and_an_adf_body() {
    let (http, rx) = fixture(vec![respond(200, SEARCH_EMPTY), respond(201, CREATE_ISSUE)]);
    let filed = adapter(http.clone())
        .file(&dest(), &cred(), &draft())
        .await
        .expect("file ok");
    assert_eq!(filed.external_id, "PROJ-7");
    assert_eq!(filed.url, "https://acme.atlassian.net/browse/PROJ-7");

    let requests = captured(&rx);
    assert_eq!(requests.len(), 2, "search, then the create");

    // The search: one JQL over this project and this key's label.
    let search = &requests[0];
    assert_eq!(search.method, "GET");
    assert!(search.uri.starts_with(SEARCH_PREFIX), "{}", search.uri);
    assert!(
        search.uri.contains("project%20%3D%20%22PROJ%22"),
        "{}",
        search.uri
    );
    let label = idem_label("idem-123");
    assert!(
        search
            .uri
            .contains(&format!("labels%20%3D%20%22{label}%22")),
        "{}",
        search.uri
    );
    assert!(
        search.uri.ends_with("&fields=status&maxResults=1"),
        "{}",
        search.uri
    );

    // The create: Basic auth, project, issue type, labels, ADF body.
    let post = &requests[1];
    assert_eq!(post.method, "POST");
    assert_eq!(post.uri, ISSUE_URI);
    assert_eq!(
        post.headers.get("authorization").unwrap(),
        basic_header().as_str()
    );
    assert_eq!(post.headers.get("accept").unwrap(), "application/json");
    let payload: Value = serde_json::from_str(&post.body).expect("json body");
    assert_eq!(payload["fields"]["project"]["key"], PROJECT);
    assert_eq!(payload["fields"]["summary"], "Outbox: refund failed");
    assert_eq!(payload["fields"]["issuetype"]["name"], "Bug");
    let labels: Vec<&str> = payload["fields"]["labels"]
        .as_array()
        .expect("labels array")
        .iter()
        .map(Value::as_str)
        .collect::<Option<_>>()
        .expect("string labels");
    assert!(labels.contains(&"from-outbox"), "{labels:?}");
    assert!(labels.contains(&label.as_str()), "{labels:?}");
    assert!(labels.contains(&"severity/error"), "{labels:?}");
    let description = &payload["fields"]["description"];
    assert_eq!(description["type"], "doc");
    assert_eq!(description["version"], 1);
    assert_eq!(
        description["content"][0]["content"][0]["text"],
        "The refund webhook failed twice."
    );
    assert_eq!(
        description["content"][1]["content"][0]["text"],
        "Second paragraph, after a blank line."
    );
}

#[pollster::test]
async fn a_dedupe_hit_returns_the_existing_ticket_without_posting() {
    // The at-least-once redelivery: the search finds what the first attempt
    // created, and no create call is made at all.
    let (http, rx) = fixture(vec![respond(200, SEARCH_HIT)]);
    let filed = adapter(http.clone())
        .file(&dest(), &cred(), &draft())
        .await
        .expect("file ok");
    assert_eq!(filed.external_id, "PROJ-7");
    assert_eq!(filed.url, "https://acme.atlassian.net/browse/PROJ-7");
    let requests = captured(&rx);
    assert_eq!(requests.len(), 1, "a verified hit stops at the search");
    assert_ne!(requests[0].method, "POST", "a verified hit must not POST");
}

#[pollster::test]
async fn a_failed_search_fails_closed_and_never_creates() {
    let (http, rx) = fixture(vec![respond(503, r#"{"errorMessages":["slow down"]}"#)]);
    let err = adapter(http.clone())
        .file(&dest(), &cred(), &draft())
        .await
        .expect_err("a failed lookup must fail the call");
    assert!(matches!(err, TrackerError::Transient { .. }), "{err}");
    let requests = captured(&rx);
    assert_eq!(requests.len(), 1, "stopped at the lookup that failed");
    assert_ne!(requests[0].method, "POST", "the create never followed");
}

// ---------------------------------------------------------------------------
// status: the three status categories

#[pollster::test]
async fn status_maps_the_three_status_categories() {
    let cases = [
        (STATUS_NEW, TicketState::Open),
        (STATUS_INDETERMINATE, TicketState::InProgress),
        (STATUS_DONE, TicketState::Resolved),
    ];
    for (body, expected) in cases {
        let (http, rx) = fixture(vec![respond(200, body)]);
        let status = adapter(http.clone())
            .status(&dest(), &cred(), "PROJ-7")
            .await
            .expect("status ok");
        assert_eq!(status.external_id, "PROJ-7");
        assert_eq!(status.state, expected, "{body}");
        assert_eq!(
            status.url.as_deref(),
            Some("https://acme.atlassian.net/browse/PROJ-7")
        );
        let requests = captured(&rx);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].uri, format!("{ISSUE_URI}/PROJ-7?fields=status"));
    }
}

// ---------------------------------------------------------------------------
// comment: the right URL, the link mark, the idempotency property

#[pollster::test]
async fn a_comment_posts_to_the_issue_with_a_link_mark_and_the_idem_property() {
    let (http, rx) = fixture(vec![respond(200, COMMENT_CREATED)]);
    let comment = TicketComment::new("outbox-43", "Duplicate of the checkout 500s.")
        .with_link("https://reports.example.test/43");
    adapter(http.clone())
        .comment(&dest(), &cred(), "PROJ-7", &comment)
        .await
        .expect("comment ok");
    let requests = captured(&rx);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].uri, COMMENT_URI);
    assert_eq!(
        requests[0].headers.get("authorization").unwrap(),
        basic_header().as_str()
    );
    let payload: Value = serde_json::from_str(&requests[0].body).expect("json body");
    // The idempotency key is greppable in Jira as a comment property.
    assert_eq!(payload["properties"][0]["key"], "cratefield-idem");
    assert_eq!(payload["properties"][0]["value"], "outbox-43");
    let content = payload["body"]["content"].as_array().expect("adf content");
    assert_eq!(
        content[0]["content"][0]["text"],
        "Duplicate of the checkout 500s."
    );
    let link_paragraph = &content[content.len() - 1];
    assert_eq!(
        link_paragraph["content"][0]["text"],
        "https://reports.example.test/43"
    );
    assert_eq!(link_paragraph["content"][0]["marks"][0]["type"], "link");
    assert_eq!(
        link_paragraph["content"][0]["marks"][0]["attrs"]["href"],
        "https://reports.example.test/43"
    );
}

#[pollster::test]
async fn a_non_http_link_is_rejected_before_any_request() {
    let (http, rx) = fixture(vec![]);
    let comment =
        TicketComment::new("outbox-43", "See this.").with_link("ftp://reports.example.test/43");
    let err = adapter(http.clone())
        .comment(&dest(), &cred(), "PROJ-7", &comment)
        .await
        .expect_err("only http(s) links are accepted");
    assert!(matches!(err, TrackerError::Rejected(_)), "{err}");
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert!(captured(&rx).is_empty());
}

// ---------------------------------------------------------------------------
// Refusals decided before any request

#[pollster::test]
async fn a_bad_site_or_project_is_rejected_with_zero_requests() {
    // Sites: a URL, a path, a port, userinfo, whitespace, empty, and dots
    // where no hostname has them. Projects: lowercase, digit-led, hyphenated.
    let bad_destinations = [
        (vec![("", PROJECT)]),
        (vec![("https://acme.atlassian.net", PROJECT)]),
        (vec![("acme.atlassian.net/", PROJECT)]),
        (vec![("acme.atlassian.net:443", PROJECT)]),
        (vec![("ops@acme.atlassian.net", PROJECT)]),
        (vec![("acme atlassian.net", PROJECT)]),
        (vec![(".acme.atlassian.net", PROJECT)]),
        (vec![("acme..atlassian.net", PROJECT)]),
        (vec![(SITE, "proj")]),
        (vec![(SITE, "1PROJ")]),
        (vec![(SITE, "PR-OJ")]),
        (vec![(SITE, "")]),
    ];
    for sites_projects in bad_destinations {
        for (site, project) in sites_projects {
            let (http, rx) = fixture(vec![]);
            let bad = Destination::Jira {
                site: site.to_owned(),
                project: project.to_owned(),
            };
            let err = adapter(http.clone())
                .file(&bad, &cred(), &draft())
                .await
                .expect_err("a malformed destination is refused");
            assert!(
                matches!(err, TrackerError::Rejected(_)),
                "{site}|{project}: {err}"
            );
            assert_eq!(
                http.calls.load(Ordering::SeqCst),
                0,
                "{site}|{project} reached the network"
            );
            assert!(captured(&rx).is_empty());
        }
    }
}

#[pollster::test]
async fn a_bad_external_id_is_rejected_with_zero_requests() {
    for external_id in ["PROJ7", "proj-7", "PROJ-", "-7", "PROJ-7-x", ""] {
        let (http, rx) = fixture(vec![]);
        let err = adapter(http.clone())
            .status(&dest(), &cred(), external_id)
            .await
            .expect_err("a malformed key is refused");
        assert!(
            matches!(err, TrackerError::Rejected(_)),
            "{external_id}: {err}"
        );
        assert_eq!(
            http.calls.load(Ordering::SeqCst),
            0,
            "{external_id} reached the network"
        );
        assert!(captured(&rx).is_empty());
    }
}

#[pollster::test]
async fn a_non_jira_destination_is_rejected_without_network() {
    let (http, rx) = fixture(vec![]);
    let github = Destination::GitHub {
        owner: "acme".to_owned(),
        repo: "widgets".to_owned(),
    };
    let err = adapter(http.clone())
        .file(&github, &cred(), &draft())
        .await
        .expect_err("this adapter does not serve GitHub");
    match err {
        TrackerError::Rejected(detail) => {
            assert!(detail.contains("unsupported destination"), "{detail}");
            assert!(detail.contains("github"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert!(captured(&rx).is_empty());
}

// ---------------------------------------------------------------------------
// Status mapping

#[pollster::test]
async fn status_mapping_is_the_error_table() {
    let cases = [
        (401u16, "unauthorized"),
        (403, "unauthorized"),
        (400, "rejected"),
        (404, "rejected"),
        (418, "rejected"),
        (429, "transient"),
        (500, "transient"),
        (502, "transient"),
        (503, "transient"),
    ];
    for (status, expected) in cases {
        let (http, _rx) = fixture(vec![respond(status, r#"{"errorMessages":["nope"]}"#)]);
        let err = adapter(http)
            .status(&dest(), &cred(), "PROJ-7")
            .await
            .expect_err("must fail");
        match expected {
            "unauthorized" => assert!(
                matches!(err, TrackerError::Unauthorized),
                "status {status}: {err}"
            ),
            "rejected" => assert!(
                matches!(err, TrackerError::Rejected(_)),
                "status {status}: {err}"
            ),
            _ => assert!(
                matches!(err, TrackerError::Transient { .. }),
                "status {status}: {err}"
            ),
        }
    }
}

#[pollster::test]
async fn a_rejected_create_carries_jira_scrubbed_error_text() {
    let (http, _rx) = fixture(vec![respond(400, ERROR_400)]);
    let err = adapter(http)
        .file(&dest(), &cred(), &draft())
        .await
        .expect_err("Jira refused the draft");
    match &err {
        TrackerError::Rejected(detail) => {
            // The errorMessages/errors text is flattened in, field by field.
            assert!(
                detail.contains("issuetype: The issue type selected is invalid."),
                "{detail}"
            );
            assert!(detail.contains("project: project is required"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
    // The Basic credential never rides an error, in any rendering.
    assert!(!err.to_string().contains(CREDENTIAL), "{}", err);
    assert!(!format!("{err:?}").contains(CREDENTIAL));
}

#[pollster::test]
async fn rate_limit_reads_the_seconds_form_of_retry_after() {
    let (http, _rx) = fixture(vec![
        respond(429, r#"{"errorMessages":["Rate limit exceeded"]}"#).with_retry_after("5"),
    ]);
    let err = adapter(http)
        .status(&dest(), &cred(), "PROJ-7")
        .await
        .unwrap_err();
    match err {
        TrackerError::Transient { retry_after } => {
            assert_eq!(retry_after, Some(Duration::from_secs(5)));
        }
        other => panic!("wrong error: {other}"),
    }
}

// ---------------------------------------------------------------------------
// The inbound status webhook

/// The `sha256=<hex>` signature Jira Cloud would send for this body.
fn jira_signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(body);
    hex_encode(&mac.finalize().into_bytes())
}

fn sig_headers(value: &str) -> HeaderMap {
    [(
        "x-hub-signature"
            .parse::<http::header::HeaderName>()
            .expect("test header name"),
        value
            .parse::<http::HeaderValue>()
            .expect("test header value"),
    )]
    .into_iter()
    .collect()
}

#[test]
fn a_correctly_signed_webhook_yields_a_status_update() {
    let hook = JiraStatusWebhook;
    assert_eq!(hook.kind(), "jira");
    let body = WEBHOOK_ISSUE_UPDATED.as_bytes();
    let signed = sig_headers(&format!("sha256={}", jira_signature("shared-secret", body)));
    let update = receive_status(&hook, "shared-secret", &signed, body, 0).expect("verified");
    assert_eq!(
        update,
        Some(cratefield_core::StatusUpdate {
            external_id: "PROJ-7".to_owned(),
            state: TicketState::InProgress,
            url: Some("https://acme.atlassian.net/browse/PROJ-7".to_owned()),
        })
    );
}

#[test]
fn a_bad_signature_is_refused_without_parsing() {
    let hook = JiraStatusWebhook;
    let body = WEBHOOK_ISSUE_UPDATED.as_bytes();
    let signed = sig_headers(&format!("sha256={}", jira_signature("shared-secret", body)));
    // A wrong secret, and a tampered body: both `Signature`, never a parse.
    assert_eq!(
        receive_status(&hook, "wrong-secret", &signed, body, 0).unwrap_err(),
        InboundStatusError::Signature
    );
    assert_eq!(
        receive_status(&hook, "shared-secret", &signed, br#"{"issue":{}}"#, 0).unwrap_err(),
        InboundStatusError::Signature
    );
    assert_eq!(
        receive_status(&hook, "shared-secret", &HeaderMap::new(), body, 0).unwrap_err(),
        InboundStatusError::Signature
    );
}

#[test]
fn a_non_status_event_or_one_without_a_status_is_none() {
    let hook = JiraStatusWebhook;
    // A comment event, and a status-bearing event whose update names no
    // status: verified silence, not an error.
    let cases = [
        serde_json::json!({
            "webhookEvent": "jira:comment_created",
            "issue": { "key": "PROJ-7", "fields": {} },
            "comment": { "body": "working on it" },
        }),
        serde_json::json!({
            "webhookEvent": "jira:issue_updated",
            "issue": { "key": "PROJ-7", "fields": { "assignee": { "displayName": "Ada" } } },
        }),
    ];
    for payload in cases {
        let body = serde_json::to_vec(&payload).expect("serialises");
        let signed = sig_headers(&format!(
            "sha256={}",
            jira_signature("shared-secret", &body)
        ));
        assert_eq!(
            receive_status(&hook, "shared-secret", &signed, &body, 0).expect("verified"),
            None,
            "{payload}"
        );
    }
}

#[test]
fn verified_but_unreadable_json_is_malformed() {
    let hook = JiraStatusWebhook;
    let body = b"not json at all".as_slice();
    let signed = sig_headers(&format!("sha256={}", jira_signature("shared-secret", body)));
    let err = receive_status(&hook, "shared-secret", &signed, body, 0).unwrap_err();
    assert!(matches!(err, InboundStatusError::Malformed(_)), "{err}");
}

// ---------------------------------------------------------------------------
// The dependency tree

#[test]
fn jira_deps_are_wasm_safe() {
    cratefield_testing::assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}

impl Scripted {
    fn with_retry_after(mut self, value: &str) -> Self {
        self.retry_after = Some(value.to_owned());
        self
    }
}
