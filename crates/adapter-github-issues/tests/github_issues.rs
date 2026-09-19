//! GitHub Issues adapter acceptance tests (issue #432): search-before-create
//! dedupe, the fail-closed lookup, the status mapping table, the idempotency
//! marker, and the token never appearing in any error string.

#![allow(clippy::disallowed_types)]
// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_github_issues::GitHubIssues;
use cratefield_core::{
    Clock, Destination, HttpClient, HttpError, TicketDraft, Tracker, TrackerError,
};
use http::{HeaderMap, Request, Response, StatusCode};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// Obvious dummy token, never real.
const TOKEN: &str = "ghp_dummy_token_0000000000";
const BASE: &str = "http://github.fake";
const OWNER: &str = "acme";
const REPO: &str = "widgets";
const MARKER: &str = "<!-- cratefield-idem: idem-123 -->";
/// What an issue body looks like after the first attempt stamped it.
const EXISTING_BODY: &str =
    "The refund webhook failed twice.\n\n<!-- cratefield-idem: idem-123 -->";
const ISSUES_URI: &str = "http://github.fake/repos/acme/widgets/issues";

/// Frozen wall clock, so the HTTP-date form of `Retry-After` has a
/// deterministic delta.
struct FixedClock(time::OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

fn clock_at(secs_past_epoch: i64) -> Arc<dyn Clock> {
    Arc::new(FixedClock(
        time::OffsetDateTime::from_unix_timestamp(secs_past_epoch).expect("valid timestamp"),
    ))
}

/// IMF-fixdate, the one date form RFC 9110 requires senders to emit.
fn http_date(at: time::OffsetDateTime) -> String {
    let format = time::format_description::parse_borrowed::<2>(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT",
    )
    .expect("valid format");
    at.format(&format).expect("formats")
}

struct CapturedRequest {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: String,
}

/// One queued response, in the order the adapter will ask for it. The happy
/// path alone is three: search, the recent-issues page, the create.
struct Scripted {
    status: u16,
    body: String,
    retry_after: Option<String>,
}

fn respond(status: u16, body: impl Into<String>) -> Scripted {
    Scripted {
        status,
        body: body.into(),
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

/// A fake whose sends always fail, for the transport half of fail-closed.
struct FailingHttp {
    tx: mpsc::Sender<CapturedRequest>,
}

#[async_trait]
impl HttpClient for FailingHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        self.tx
            .send(CapturedRequest {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body: String::from_utf8_lossy(&body).to_string(),
            })
            .expect("test channel open");
        Err(HttpError::Transport("dns is down".to_string()))
    }
}

/// A fake whose vetting refuses the destination — what the real port
/// implementations do before any socket opens (issue #136, destinations).
struct BlockingHttp;

#[async_trait]
impl HttpClient for BlockingHttp {
    async fn send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        Err(HttpError::BlockedDestination(
            "169.254.169.254 is not a public destination".to_owned(),
        ))
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

fn posts_to_issues(requests: &[CapturedRequest]) -> usize {
    requests
        .iter()
        .filter(|request| request.method == "POST" && request.uri == ISSUES_URI)
        .count()
}

fn draft() -> TicketDraft {
    TicketDraft::new(
        "Outbox: refund failed",
        "The refund webhook failed twice.",
        Destination::GitHubIssues {
            owner: OWNER.to_owned(),
            repo: REPO.to_owned(),
        },
        "idem-123",
    )
    .labels(["from-outbox"])
}

fn adapter(http: Arc<FakeHttp>) -> GitHubIssues {
    GitHubIssues::new(http, clock_at(0), TOKEN).with_base(BASE)
}

/// One issue in the shape the search, list and create responses all carry.
fn issue(number: i64, body: &str) -> serde_json::Value {
    serde_json::json!({
        "number": number,
        "body": body,
        "html_url": format!("https://github.com/{OWNER}/{REPO}/issues/{number}"),
    })
}

fn search_results(hits: &[(i64, &str)]) -> String {
    let items: Vec<serde_json::Value> = hits
        .iter()
        .map(|(number, body)| issue(*number, body))
        .collect();
    serde_json::json!({ "total_count": items.len(), "items": items }).to_string()
}

fn issue_list(issues: &[(i64, &str)]) -> String {
    serde_json::json!(
        issues
            .iter()
            .map(|(number, body)| issue(*number, body))
            .collect::<Vec<_>>()
    )
    .to_string()
}

// ---------------------------------------------------------------------------
// Status mapping

#[pollster::test]
async fn status_mapping_is_the_issue_table() {
    // (status, expected): 401/403 the token is wrong or powerless; 404 the
    // repository is gone or invisible; 422 the ticket itself was refused;
    // every other 4xx is a fact about our request; 429 and the 5xx family
    // are the provider having a moment.
    let cases = [
        (401u16, "unauthorized"),
        (403, "unauthorized"),
        (404, "rejected"),
        (422, "rejected"),
        (400, "rejected"),
        (418, "rejected"),
        (429, "transient"),
        (500, "transient"),
        (502, "transient"),
        (503, "transient"),
    ];
    for (status, expected) in cases {
        let (http, rx) = fixture(vec![respond(status, r#"{"message":"nope"}"#)]);
        let err = adapter(http)
            .file(&draft())
            .await
            .expect_err("a failed lookup must fail the call");
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
        // Fail-closed: the create never follows a failed lookup.
        let requests = captured(&rx);
        assert_eq!(
            posts_to_issues(&requests),
            0,
            "status {status} created an issue after a failed lookup"
        );
        assert_eq!(
            requests.len(),
            1,
            "status {status} stopped at the lookup that failed"
        );
    }
}

#[pollster::test]
async fn rate_limit_reads_the_seconds_form_of_retry_after() {
    let (http, _rx) = fixture(vec![
        respond(429, r#"{"message":"API rate limit exceeded"}"#).with_retry_after("5"),
    ]);
    let err = adapter(http).file(&draft()).await.unwrap_err();
    match err {
        TrackerError::Transient { retry_after, .. } => {
            assert_eq!(retry_after, Some(Duration::from_secs(5)));
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn rate_limit_reads_the_http_date_form_of_retry_after() {
    // A CDN in front of GitHub answers with a date (issue #278): one hour
    // from the adapter's clock, not an immediate retry.
    let at = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid timestamp");
    let date = http_date(at + time::Duration::seconds(3_600));
    let (http, _rx) = fixture(vec![
        respond(503, r#"{"message":"slow down"}"#).with_retry_after(&date),
    ]);
    let err = GitHubIssues::new(http, clock_at(1_800_000_000), TOKEN)
        .with_base(BASE)
        .file(&draft())
        .await
        .unwrap_err();
    match err {
        TrackerError::Transient { retry_after, .. } => {
            assert_eq!(retry_after, Some(Duration::from_secs(3_600)));
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn a_transport_failure_is_transient_and_never_creates() {
    let (tx, rx) = mpsc::channel();
    let err = GitHubIssues::new(Arc::new(FailingHttp { tx }), clock_at(0), TOKEN)
        .with_base(BASE)
        .file(&draft())
        .await
        .expect_err("dns is down");
    match err {
        TrackerError::Transient {
            message,
            retry_after,
        } => {
            assert!(message.contains("dns is down"), "{message}");
            assert_eq!(retry_after, None);
        }
        other => panic!("wrong error: {other}"),
    }
    let requests = captured(&rx);
    assert_eq!(requests.len(), 1, "the failed lookup, and nothing after");
    assert_eq!(posts_to_issues(&requests), 0);
}

#[pollster::test]
async fn a_blocked_destination_is_rejected_not_transient() {
    // The port's SSRF vetting refused the destination URL. A config
    // error, not weather: `Rejected`, and no retry delay is named.
    let err = GitHubIssues::new(Arc::new(BlockingHttp), clock_at(0), TOKEN)
        .with_base(BASE)
        .file(&draft())
        .await
        .expect_err("the port refused the destination");
    match &err {
        TrackerError::Rejected(detail) => {
            assert!(detail.contains("169.254.169.254"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
    assert_eq!(err.retry_after(), None);
    let rendered = err.to_string();
    assert!(!rendered.contains(TOKEN), "{rendered}");
}

// ---------------------------------------------------------------------------
// Search before create

#[pollster::test]
async fn two_files_with_one_key_create_exactly_one_issue() {
    // First delivery: search empty, recent issues empty, so a create.
    let (http, rx) = fixture(vec![
        respond(200, search_results(&[])),
        respond(200, issue_list(&[])),
        respond(201, issue(11, EXISTING_BODY).to_string()),
    ]);
    let first = adapter(http.clone()).file(&draft()).await.expect("file ok");
    assert_eq!(first.id, "11");
    assert_eq!(
        first.url.as_deref(),
        Some("https://github.com/acme/widgets/issues/11")
    );
    assert!(!first.deduplicated, "a create is not a dedupe");

    // The at-least-once redelivery: search finds what the first created,
    // and no create call is made at all.
    let (http, rx_redelivery) = fixture(vec![respond(200, search_results(&[(11, EXISTING_BODY)]))]);
    let second = adapter(http.clone()).file(&draft()).await.expect("file ok");
    assert!(
        second.deduplicated,
        "the redelivery reports the existing ticket"
    );
    assert_eq!(second.id, "11");
    assert_eq!(
        second.url.as_deref(),
        Some("https://github.com/acme/widgets/issues/11")
    );

    assert_eq!(
        posts_to_issues(&captured(&rx)),
        1,
        "the first delivery created once"
    );
    let redelivery = captured(&rx_redelivery);
    assert_eq!(
        posts_to_issues(&redelivery),
        0,
        "a verified hit must not POST"
    );
    assert_eq!(redelivery.len(), 1, "a verified hit stops at the search");
}

#[pollster::test]
async fn a_retry_finds_the_existing_issue_when_the_search_index_lags() {
    // The search index is eventually consistent: it answers empty seconds
    // after the create. The recent-issues page still shows the ticket, so
    // the common fast-retry case still dedupes.
    let (http, rx) = fixture(vec![
        respond(200, search_results(&[])),
        respond(200, issue_list(&[(7, EXISTING_BODY)])),
    ]);
    let filed = adapter(http.clone()).file(&draft()).await.expect("file ok");
    assert!(filed.deduplicated);
    assert_eq!(filed.id, "7");
    assert_eq!(
        filed.url.as_deref(),
        Some("https://github.com/acme/widgets/issues/7")
    );
    let requests = captured(&rx);
    assert_eq!(requests.len(), 2, "search, then the recent-issues page");
    assert_eq!(
        posts_to_issues(&requests),
        0,
        "no create when the list scan verified the hit"
    );
}

#[pollster::test]
async fn a_search_hit_without_the_marker_is_a_false_positive() {
    // Search token-matches: this hit carries a *different* key whose name
    // extends ours. Without the body verify it would swallow the create.
    let (http, rx) = fixture(vec![
        respond(
            200,
            search_results(&[(9, "<!-- cratefield-idem: idem-1234 -->")]),
        ),
        respond(200, issue_list(&[])),
        respond(201, issue(12, EXISTING_BODY).to_string()),
    ]);
    let filed = adapter(http.clone())
        .file(&draft())
        .await
        .expect("create still happens");
    assert!(!filed.deduplicated);
    assert_eq!(filed.id, "12");
    let requests = captured(&rx);
    assert_eq!(requests.len(), 3, "search, recent issues, then the create");
    assert_eq!(
        posts_to_issues(&requests),
        1,
        "an unverified hit must not swallow the create"
    );
}

// ---------------------------------------------------------------------------
// The wire

#[pollster::test]
async fn the_created_body_carries_the_marker_as_an_html_comment() {
    let (http, rx) = fixture(vec![
        respond(200, search_results(&[])),
        respond(200, issue_list(&[])),
        respond(201, issue(11, EXISTING_BODY).to_string()),
    ]);
    adapter(http.clone()).file(&draft()).await.expect("file ok");
    let requests = captured(&rx);
    let post = requests
        .iter()
        .find(|request| request.method == "POST")
        .expect("a create");
    let payload: serde_json::Value = serde_json::from_str(&post.body).expect("json body");
    let rendered = payload["body"].as_str().expect("body is a string");
    // The draft's text first, then the marker appended as the HTML comment
    // GitHub will not render — the thing the dedupe check greps for.
    assert!(
        rendered.starts_with("The refund webhook failed twice."),
        "{rendered}"
    );
    assert!(MARKER.starts_with("<!--") && MARKER.ends_with("-->"));
    assert!(
        rendered.ends_with(MARKER),
        "the marker is the appended comment: {rendered}"
    );
    assert_eq!(payload["title"], "Outbox: refund failed");
    assert_eq!(payload["labels"][0], "from-outbox");
}

#[pollster::test]
async fn every_request_carries_the_github_headers_and_the_base_url() {
    let (http, rx) = fixture(vec![
        respond(200, search_results(&[])),
        respond(200, issue_list(&[])),
        respond(201, issue(11, EXISTING_BODY).to_string()),
    ]);
    adapter(http.clone()).file(&draft()).await.expect("file ok");
    for request in captured(&rx) {
        assert_eq!(
            request.headers.get("authorization").unwrap(),
            format!("Bearer {TOKEN}").as_str()
        );
        assert_eq!(
            request.headers.get("accept").unwrap(),
            "application/vnd.github+json"
        );
        assert_eq!(
            request.headers.get("x-github-api-version").unwrap(),
            "2022-11-28"
        );
        assert!(
            request.headers.get("user-agent").is_some(),
            "GitHub rejects requests without a User-Agent"
        );
        assert!(request.uri.starts_with(BASE), "{}", request.uri);
    }
}

#[pollster::test]
async fn the_search_targets_the_repository_and_issues_only() {
    let (http, rx) = fixture(vec![
        respond(200, search_results(&[])),
        respond(200, issue_list(&[])),
        respond(201, issue(11, EXISTING_BODY).to_string()),
    ]);
    adapter(http.clone()).file(&draft()).await.expect("file ok");
    let requests = captured(&rx);
    let search = &requests[0];
    assert_eq!(search.method, "GET");
    assert!(
        search.uri.starts_with(&format!("{BASE}/search/issues?q=")),
        "{}",
        search.uri
    );
    assert!(
        search.uri.contains("repo%3Aacme%2Fwidgets"),
        "{}",
        search.uri
    );
    assert!(search.uri.contains("is%3Aissue"), "{}", search.uri);

    let list = &requests[1];
    assert_eq!(list.uri, format!("{ISSUES_URI}?state=all&per_page=100"));
}

#[pollster::test]
async fn a_webhook_destination_is_rejected_without_network() {
    let (http, rx) = fixture(vec![]);
    let webhook = TicketDraft::new(
        "Outbox: refund failed",
        "The refund webhook failed twice.",
        Destination::Webhook {
            url: "https://hooks.example.test/tickets".to_owned(),
        },
        "idem-123",
    );
    let err = adapter(http.clone())
        .file(&webhook)
        .await
        .expect_err("this adapter does not serve webhooks");
    match err {
        TrackerError::Rejected(detail) => {
            assert!(detail.contains("Webhook"), "{detail}");
            assert!(detail.contains("GitHub"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
    assert_eq!(
        http.calls.load(Ordering::SeqCst),
        0,
        "the mismatch is known before any network call"
    );
    assert!(captured(&rx).is_empty());
}

// ---------------------------------------------------------------------------
// The token

#[pollster::test]
async fn every_error_display_omits_the_token() {
    let variants = [
        (401u16, r#"{"message":"Bad credentials"}"#),
        (
            403,
            r#"{"message":"Resource not accessible by integration"}"#,
        ),
        (404, r#"{"message":"Not Found"}"#),
        (422, r#"{"message":"Validation Failed"}"#),
        (429, r#"{"message":"API rate limit exceeded"}"#),
        (500, "server error"),
        (418, r#"{"message":"teapot"}"#),
    ];
    for (status, body) in variants {
        let (http, _rx) = fixture(vec![respond(status, body)]);
        let err = adapter(http).file(&draft()).await.expect_err("must fail");
        let rendered = err.to_string();
        // An empty rendering omits the token and everything else. The
        // display has to remain useful for this absence to mean anything.
        assert!(
            rendered.len() > 8,
            "status {status} rendered an error that says nothing: {rendered:?}"
        );
        assert!(
            !rendered.contains(TOKEN),
            "status {status} leaked the token: {rendered}"
        );
        assert!(
            !format!("{err:?}").contains(TOKEN),
            "status {status} leaked the token in Debug: {err:?}"
        );
    }
}

#[test]
fn github_issues_deps_are_wasm_safe() {
    cratefield_testing::assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}

impl Scripted {
    fn with_retry_after(mut self, value: &str) -> Self {
        self.retry_after = Some(value.to_owned());
        self
    }
}
