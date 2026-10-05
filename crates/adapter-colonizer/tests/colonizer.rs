//! The Colonizer mothership client (issue #675): every route's method, path
//! and body from one table; the whole status mapping; the local refusals and
//! `NotConfigured` (both with zero requests); and the `col_` token staying out
//! of `Debug` and out of every error.

// Test-side recording doubles, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use cratefield_adapter_colonizer::{
    Colonizer, ColonizerError, Colony, ColonyPage, NewColony, Question, Whoami,
};
use cratefield_core::{Clock, HttpClient, HttpError};
use cratefield_testing::{FakeHttpClient, FixedClock, error_json, with_retry_after};
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TOKEN: &str = "col_test_dummy_000000000000";
const BASE: &str = "https://mothership.example";
const ID: &str = "col_abc123";
const REPO: &str = "Cratefield/harness";
const COLONY: &str = r#"{"id":"col_abc123","status":"running",
  "repo":"Cratefield/harness","issue":675,"branch":"colonizer/675"}"#;
const PAGE: &str = r#"{"colonies":[{"id":"col_abc123","status":"running"}],"next_cursor":"c2"}"#;
const QUESTION: &str = r#"{"id":"q1","text":"merge?","options":["yes","no"]}"#;

/// A reply with `body` at `status`.
fn reply(status: u16, body: &str) -> Arc<FakeHttpClient> {
    Arc::new(FakeHttpClient::scripted(vec![Ok(Response::builder()
        .status(status)
        .body(bytes::Bytes::copy_from_slice(body.as_bytes()))
        .expect("a response builds"))]))
}

fn ok_json(body: &'static str) -> Arc<FakeHttpClient> {
    reply(200, body)
}

fn clock() -> Arc<dyn Clock> {
    Arc::new(FixedClock(
        time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
    ))
}

fn client_with(http: Arc<dyn HttpClient>, token: Option<String>) -> Colonizer {
    Colonizer::new(http, clock(), BASE, token)
}

fn client(http: Arc<dyn HttpClient>) -> Colonizer {
    client_with(http, Some(TOKEN.to_owned()))
}

fn colony() -> Colony {
    Colony {
        id: ID.to_owned(),
        status: "running".to_owned(),
        repo: REPO.to_owned(),
        issue: Some(675),
        branch: Some("colonizer/675".to_owned()),
    }
}

fn new_colony() -> NewColony {
    NewColony {
        repo: REPO.into(),
        issue: Some(675),
        prompt: None,
    }
}

/// As `colony()`, as the JSON the caller gets back.
fn colony_json() -> String {
    json(colony())
}

/// What the page fixture reads back as: the colony's omitted `repo`, `issue`
/// and `branch` take their defaults, and the cursor survives.
fn page_json() -> String {
    json(ColonyPage {
        colonies: vec![Colony {
            id: ID.to_owned(),
            status: "running".to_owned(),
            repo: String::new(),
            issue: None,
            branch: None,
        }],
        next_cursor: Some("c2".to_owned()),
    })
}

/// The JSON a reply is read back as.
fn json(value: impl serde::Serialize) -> String {
    serde_json::to_string(&value).expect("a serialisable reply")
}

fn parsed(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("json")
}

/// Asserts the one recorded request, so a route's row stays short.
fn assert_sent(http: &Arc<FakeHttpClient>, method: &str, path: &str, body: Option<&str>) {
    let captured = http.captured();
    assert_eq!(captured.len(), 1, "one request");
    assert_eq!(
        (captured[0].0.as_str(), captured[0].1.as_str()),
        (method, path),
        "method and path"
    );
    let sent = captured[0].2.parse().unwrap_or(serde_json::Value::Null);
    let want = body.map_or(serde_json::Value::Null, parsed);
    assert_eq!(sent, want, "body");
}

/// An `HttpClient` that keeps every request's headers, which
/// `FakeHttpClient::captured` stops short of recording.
#[derive(Default)]
struct HeaderSpy {
    sent: Mutex<Vec<HeaderMap>>,
}

#[async_trait]
impl HttpClient for HeaderSpy {
    async fn send(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> Result<Response<bytes::Bytes>, HttpError> {
        self.sent
            .lock()
            .expect("an unpoisoned mutex")
            .push(request.headers().clone());
        Ok(Response::builder()
            .status(200)
            .body(bytes::Bytes::copy_from_slice(COLONY.as_bytes()))
            .expect("a response builds"))
    }
}

fn header_of(sent: &[HeaderMap], at: usize, name: &str) -> Option<String> {
    sent[at]
        .get(HeaderName::from_bytes(name.as_bytes()).expect("a header name"))
        .map(HeaderValue::to_str)
        .transpose()
        .expect("a header value")
        .map(str::to_owned)
}

#[pollster::test]
async fn every_request_is_a_bearer_authenticated_json_call() {
    let spy = Arc::new(HeaderSpy::default());
    let mothership = client(spy.clone() as Arc<dyn HttpClient>);
    mothership.get(ID).await.expect("gets");
    mothership.answer(ID, "q1", "yes").await.expect("answers");
    let sent = spy.sent.lock().expect("an unpoisoned mutex").clone();
    assert_eq!(sent.len(), 2, "one request per call");
    for at in 0..2 {
        assert_eq!(
            header_of(&sent, at, "authorization").as_deref(),
            Some(&*format!("Bearer {TOKEN}"))
        );
        assert_eq!(
            header_of(&sent, at, "accept").as_deref(),
            Some("application/json")
        );
    }
    // Only the call that carries a body says what it is.
    assert_eq!(header_of(&sent, 0, "content-type"), None);
    assert_eq!(
        header_of(&sent, 1, "content-type").as_deref(),
        Some("application/json")
    );
}

// ---------------------------------------------------------------------------
// Every route, from one table: `|m| { … }` makes the call, then the reply's
// status, the method, path and body the request must carry, and what the reply
// must read back as (`None` for a route that returns only `()`).

macro_rules! routes {
    ($(|$m:ident| $call:block => $status:literal, $body:expr, $method:literal, $path:literal, $sent:expr, $read:expr;)+) => {
        #[pollster::test]
        async fn every_route_sends_the_method_path_and_body_it_should() {
            $({
                let call = |$m: Colonizer| async move $call;
                let http = reply($status, $body);
                let got = call(client(http.clone())).await;
                let sent: Option<&str> = $sent;
                assert_sent(&http, $method, &format!($path), sent);
                let read: Option<String> = $read;
                if let Some(want) = read {
                    assert_eq!(parsed(&got), parsed(&want), "{} {}", $method, $path);
                }
            })*
        }
    };
}

routes! {
    // whoami
    |m| { json(m.whoami().await.expect("whoami")) } => 200,
        r#"{"login":"bot","scopes":["colonies:write"]}"#, "GET", "{BASE}/api/v1/whoami", None,
        Some(r#"{"login":"bot","scopes":["colonies:write"]}"#.to_owned());
    // an omitted scope reads as no scopes at all
    |m| { json(m.whoami().await.expect("whoami")) } => 200,
        r#"{"login":"bot"}"#, "GET", "{BASE}/api/v1/whoami", None,
        Some(r#"{"login":"bot","scopes":[]}"#.to_owned());
    // create_session
    |m| { json(m.create_session(&new_colony()).await.expect("creates")) } => 200,
        COLONY, "POST", "{BASE}/api/v1/colonies",
        Some(r#"{"repo":"Cratefield/harness","issue":675}"#), Some(colony_json());
    // get
    |m| { json(m.get(ID).await.expect("gets")) } => 200,
        COLONY, "GET", "{BASE}/api/v1/colonies/{ID}", None, Some(colony_json());
    // list, with the cursor percent-encoded so it cannot inject a parameter
    |m| { json(m.list(20, Some("a b&c")).await.expect("lists")) } => 200,
        PAGE, "GET", "{BASE}/api/v1/colonies?limit=20&cursor=a%20b%26c", None, Some(page_json());
    // list, with no cursor at all
    |m| { json(m.list(5, None).await.expect("lists")) } => 200,
        r#"{"colonies":[]}"#, "GET", "{BASE}/api/v1/colonies?limit=5", None,
        Some(r#"{"colonies":[],"next_cursor":null}"#.to_owned());
    // question
    |m| { json(m.question(ID).await.expect("question").expect("asking")) } => 200,
        QUESTION, "GET", "{BASE}/api/v1/colonies/{ID}/question", None, Some(QUESTION.to_owned());
    // answer, which returns nothing
    |m| { m.answer(ID, "q1", "yes").await.expect("answers"); String::new() } => 204,
        "", "POST", "{BASE}/api/v1/colonies/{ID}/answer",
        Some(r#"{"question_id":"q1","answer":"yes"}"#), None;
    // message, which returns nothing
    |m| { m.message(ID, "hold").await.expect("messages"); String::new() } => 204,
        "", "POST", "{BASE}/api/v1/colonies/{ID}/messages", Some(r#"{"text":"hold"}"#), None;
    // stop
    |m| { json(m.stop(ID).await.expect("stops")) } => 200,
        COLONY, "POST", "{BASE}/api/v1/colonies/{ID}/stop", None, Some(colony_json());
    // resume
    |m| { json(m.resume(ID).await.expect("resumes")) } => 200,
        COLONY, "POST", "{BASE}/api/v1/colonies/{ID}/resume", None, Some(colony_json());
}

#[pollster::test]
async fn a_colony_asking_nothing_is_no_question() {
    // A 204 and a JSON `null` both mean "not asking anything".
    for http in [reply(204, ""), ok_json("null")] {
        assert!(client(http).question(ID).await.expect("question").is_none());
    }
}

#[pollster::test]
async fn a_page_and_a_question_read_into_the_public_types() {
    let http = ok_json(PAGE);
    let page = client(http).list(1, None).await.expect("lists");
    assert_eq!(page.colonies.len(), 1);
    assert_eq!(page.next_cursor.as_deref(), Some("c2"));
    assert_eq!(
        client(ok_json(QUESTION))
            .question(ID)
            .await
            .expect("question")
            .expect("asking"),
        Question {
            id: "q1".into(),
            text: "merge?".into(),
            options: vec!["yes".into(), "no".into()],
        }
    );
    assert_eq!(
        client(ok_json(r#"{"login":"bot"}"#))
            .whoami()
            .await
            .expect("whoami"),
        Whoami {
            login: "bot".into(),
            scopes: vec![]
        }
    );
}

#[pollster::test]
async fn a_trailing_slash_on_the_base_url_is_harmless() {
    let http = ok_json(COLONY);
    Colonizer::new(
        http.clone() as Arc<dyn HttpClient>,
        clock(),
        format!("{BASE}/"),
        Some(TOKEN.to_owned()),
    )
    .get(ID)
    .await
    .expect("gets");
    assert_sent(&http, "GET", &format!("{BASE}/api/v1/colonies/{ID}"), None);
}

// ---------------------------------------------------------------------------
// Status mapping

/// The variant a `{"error": msg}` body at `status` must map to.
fn mapped(status: u16, msg: &str) -> ColonizerError {
    match status {
        400 | 422 => ColonizerError::Invalid {
            detail: msg.to_owned(),
        },
        401 => ColonizerError::Unauthorized,
        403 => ColonizerError::Forbidden { scope: None },
        404 => ColonizerError::NotFound,
        409 => ColonizerError::Conflict {
            detail: msg.to_owned(),
        },
        // 429 and every 5xx: the caller's business to retry.
        _ => ColonizerError::Transient { retry_after: None },
    }
}

#[pollster::test]
async fn every_status_maps_to_its_own_variant() {
    for status in [400, 401, 403, 404, 409, 422, 429, 503] {
        let http = reply(status, r#"{"error":"no"}"#);
        assert_eq!(
            client(http).get(ID).await.unwrap_err(),
            mapped(status, "no"),
            "{status}"
        );
    }
}

#[pollster::test]
async fn a_429_carries_its_retry_after() {
    let http = Arc::new(FakeHttpClient::scripted(vec![Ok(with_retry_after(
        error_json(StatusCode::TOO_MANY_REQUESTS, "slow down"),
        30,
    ))]));
    assert_eq!(
        client(http).get(ID).await.unwrap_err(),
        ColonizerError::Transient {
            retry_after: Some(Duration::from_secs(30))
        }
    );
}

#[pollster::test]
async fn a_403_names_the_scope_it_wants() {
    // Both spellings the mothership uses for the field.
    for field in ["scope", "required_scope"] {
        let http = reply(
            403,
            &format!(r#"{{"error":"no","{field}":"colonies:write"}}"#),
        );
        assert_eq!(
            client(http).get(ID).await.unwrap_err(),
            ColonizerError::Forbidden {
                scope: Some("colonies:write".to_owned())
            }
        );
    }
}

#[pollster::test]
async fn a_body_the_client_cannot_read_is_a_decode_error() {
    assert!(matches!(
        client(ok_json("not json at all"))
            .get(ID)
            .await
            .unwrap_err(),
        ColonizerError::Decode { .. }
    ));
}

#[pollster::test]
async fn a_refused_destination_is_a_transport_error() {
    // The port refuses private destinations, so a localhost base URL never
    // leaves the isolate — it comes back as a transport failure.
    let http = Arc::new(FakeHttpClient::scripted(vec![Err(
        HttpError::BlockedDestination("127.0.0.1 is not public".to_owned()),
    )]));
    assert!(matches!(
        client(http).get(ID).await.unwrap_err(),
        ColonizerError::Transport { .. }
    ));
}

// ---------------------------------------------------------------------------
// Local refusals and NotConfigured — both with zero requests

#[pollster::test]
async fn a_path_like_colony_id_is_refused_before_any_request() {
    for id in ["", "..", "../colonies", "col/abc", "col abc", "col?x=1"] {
        let http = ok_json(COLONY);
        let err = client(http.clone()).get(id).await.unwrap_err();
        assert!(
            matches!(err, ColonizerError::Invalid { .. }),
            "{id:?} gives {err:?}"
        );
        assert!(http.captured().is_empty(), "{id:?} sent a request");
    }
}

#[pollster::test]
async fn no_token_or_no_base_url_means_no_request_on_any_route() {
    for token in [None, Some(String::new()), Some("   ".to_owned())] {
        for base in [BASE, ""] {
            let http = ok_json(COLONY);
            let mothership = Colonizer::new(
                http.clone() as Arc<dyn HttpClient>,
                clock(),
                base,
                token.clone(),
            );
            assert_eq!(
                mothership.whoami().await.unwrap_err(),
                ColonizerError::NotConfigured
            );
            assert_eq!(
                mothership.get(ID).await.unwrap_err(),
                ColonizerError::NotConfigured
            );
            assert!(http.captured().is_empty(), "unconfigured sent a request");
        }
    }
}

// ---------------------------------------------------------------------------
// The token never surfaces

#[test]
fn the_token_is_never_in_debug() {
    let idle = Arc::new(FakeHttpClient::scripted(vec![]));
    let debug = format!("{:?}", client_with(idle.clone(), Some(TOKEN.to_owned())));
    assert!(!debug.contains(TOKEN), "{debug}");
    assert!(debug.contains(BASE), "{debug}");
    // The unconfigured client says so rather than nothing.
    assert!(format!("{:?}", client_with(idle, None)).contains("NotConfigured"));
}

#[pollster::test]
async fn neither_a_provider_nor_a_transport_error_can_leak_the_token() {
    // A provider that puts the token in its own error message, and a port
    // that echoes the `Bearer` line, must both be redacted.
    let cases = vec![
        reply(400, &format!(r#"{{"error":"bad token {TOKEN}"}}"#)),
        // A 403 carries provider text twice: in the detail and in the scope.
        reply(403, &format!(r#"{{"error":"no","scope":"needs {TOKEN}"}}"#)),
        Arc::new(FakeHttpClient::scripted(vec![Err(HttpError::Transport(
            format!("failed with Bearer {TOKEN}"),
        ))])),
    ];
    for http in cases {
        let err = client(http).get(ID).await.unwrap_err();
        for shown in [format!("{err:?}"), err.to_string()] {
            assert!(!shown.contains(TOKEN), "{shown}");
            assert!(shown.contains("[redacted]"), "{shown}");
        }
    }
}
