//! Owlpost inbound message tests (issue #682): every `/v1/inbound/messages`
//! route hits the path and verb it should, query values are percent-encoded,
//! pagination follows the `next` cursor, a bad id is refused before any
//! request, and a held body is reachable only by an explicit get or raw fetch.
#![allow(clippy::disallowed_types)] // test doubles record calls via a Mutex

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_owlpost::{MessageQuery, MessageSummary, Owlpost, OwlpostError};
use cratefield_core::{Clock, HttpClient, HttpError, MailError, Message};
use http::{Request, Response, StatusCode};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

const DUMMY_KEY: &str = "op_test_dummy_key_000000000000";
const BASE: &str = "https://api.owlpost.to";
const LIST: &str = r#"{"data":[{"id":"msg_1","inbox":"inb_1","status":"held"}]}"#;
/// Real CRLF, and a body that parses as `{"id": …}` — `raw_message` returns
/// both verbatim.
const RAW: &str = "Subject: Quote\r\n\r\nbody";
const RAW_JSON: &str = r#"{"id":"msg_1"}"#;

/// Every route with the body it answers, in the order the test calls them.
const ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/v1/inbound/messages", LIST),
    (
        "GET",
        "/v1/inbound/messages/msg_1",
        r#"{"id":"msg_1","inbox":"inb_1","status":"held","text":"hi"}"#,
    ),
    ("GET", "/v1/inbound/messages/msg_1/raw", RAW),
    ("GET", "/v1/inbound/messages/msg_1/raw", RAW_JSON),
    (
        "POST",
        "/v1/inbound/messages/msg_1/reply",
        r#"{"id":"msg_reply"}"#,
    ),
    ("POST", "/v1/inbound/messages/msg_1/release", ""),
];

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp")
    }
}

/// Scripted replies in order, capturing every request.
struct Scripted {
    replies: Mutex<VecDeque<(u16, String)>>,
    requests: Mutex<Vec<(String, String, String)>>,
}

impl Scripted {
    fn new(replies: Vec<(u16, &str)>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(
                replies
                    .into_iter()
                    .map(|(status, body)| (status, body.to_owned()))
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
        })
    }

    fn count(&self) -> usize {
        self.requests.lock().expect("lock").len()
    }

    /// `(method, uri, body)` of the `index`th request.
    fn request(&self, index: usize) -> (String, String, String) {
        self.requests.lock().expect("lock")[index].clone()
    }
}

#[async_trait]
impl HttpClient for Scripted {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        self.requests.lock().expect("lock").push((
            parts.method.to_string(),
            parts.uri.to_string(),
            String::from_utf8_lossy(&body).to_string(),
        ));
        let (status, text) = self
            .replies
            .lock()
            .expect("lock")
            .pop_front()
            .unwrap_or((200, "{}".to_owned()));
        Response::builder()
            .status(StatusCode::from_u16(status).expect("valid status"))
            .body(Bytes::from(text))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

fn owlpost(http: Arc<Scripted>) -> Owlpost {
    Owlpost::new(
        http,
        Arc::new(FixedClock),
        Some(DUMMY_KEY.to_owned()),
        "Acme <no-reply@test.factory0.dev>",
        None,
    )
}

/// Every route: the method, the path, and a body where there is one.
#[pollster::test]
async fn every_route_hits_its_endpoint() {
    let http = Scripted::new(ROUTES.iter().map(|&(_, _, body)| (200, body)).collect());
    let owlpost = owlpost(http.clone());

    let page = owlpost
        .list_messages(&MessageQuery::default())
        .await
        .expect("list messages");
    assert_eq!((page.data[0].id.as_str(), page.next), ("msg_1", None));
    let detail = owlpost.get_message("msg_1").await.expect("get message");
    assert_eq!(detail.text.as_deref(), Some("hi"));
    assert_eq!(detail.summary.status, "held");
    for expected in [RAW, RAW_JSON] {
        assert_eq!(
            owlpost.raw_message("msg_1").await.expect("raw message"),
            expected
        );
    }
    assert_eq!(
        owlpost
            .reply(
                "msg_1",
                Message::new("a@b.test", "", "Re: Quote", "Thanks", "<p>Thanks</p>"),
            )
            .await
            .expect("reply"),
        "msg_reply"
    );
    owlpost.release("msg_1").await.expect("release");

    for (index, &(method, path, _)) in ROUTES.iter().enumerate() {
        let (got, uri, body) = http.request(index);
        assert_eq!(format!("{got} {uri}"), format!("{method} {BASE}{path}"));
        // Only the reply carries a request body.
        assert_eq!(body.is_empty(), index != 4, "{body}");
    }
    let (_, _, reply) = http.request(4);
    assert!(reply.contains(r#""text":"Thanks""#), "{reply}");
}

/// Page two is requested with the `next` cursor as `before`, and a query value
/// with a space and an `&` in it is percent-encoded.
#[pollster::test]
async fn list_pages_by_cursor_and_encodes_the_query() {
    let http = Scripted::new(vec![
        (
            200,
            r#"{"next":"cur 1&x","data":[{"id":"msg_1","inbox":"inb_1","status":"held"}]}"#,
        ),
        (200, r#"{"data":[]}"#),
    ]);
    let owlpost = owlpost(http.clone());

    let mut query = MessageQuery::default();
    query.inbox = Some("inb_1".to_owned());
    query.q = Some("quote & tax".to_owned());
    query.limit = Some(2);
    let first = owlpost.list_messages(&query).await.expect("page one");
    assert_eq!(first.next.as_deref(), Some("cur 1&x"));

    let second = owlpost
        .list_held("inb_1", first.next.as_deref())
        .await
        .expect("page two");
    assert!(second.data.is_empty());
    assert_eq!(
        http.request(0).1,
        format!("{BASE}/v1/inbound/messages?inbox=inb_1&q=quote%20%26%20tax&limit=2")
    );
    assert_eq!(
        http.request(1).1,
        format!("{BASE}/v1/inbound/messages?inbox=inb_1&before=cur%201%26x&status=held")
    );
}

/// A held body is only ever an explicit fetch: the summary a listing returns
/// has no body field, so one the provider filled in does not reach the caller,
/// while get and raw do hand it over.
#[pollster::test]
async fn a_held_body_comes_only_from_get_or_raw() {
    let listed = r#"{"data":[{"id":"msg_1","inbox":"inb_1","status":"held",
        "text":"secret","html":"<p>secret</p>"}]}"#;
    let http = Scripted::new(vec![
        (200, listed),
        (
            200,
            r#"{"id":"msg_1","inbox":"inb_1","status":"held","text":"secret"}"#,
        ),
        (200, "Subject: Quote\r\n\r\nsecret"),
    ]);
    let owlpost = owlpost(http.clone());

    let page = owlpost.list_held("inb_1", None).await.expect("list held");
    let summary: &MessageSummary = &page.data[0];
    assert_eq!(summary.id, "msg_1");
    // The wire response did carry the body; the parsed type has nowhere to put
    // it, so `Debug` — every field it does have — never mentions it.
    let wire: serde_json::Value = serde_json::from_str(listed).expect("listing parses");
    assert_eq!(wire["data"][0]["text"], "secret");
    assert!(
        !format!("{summary:?}").contains("secret"),
        "a held body reached the caller from a listing"
    );
    assert_eq!(
        http.request(0).1,
        format!("{BASE}/v1/inbound/messages?inbox=inb_1&status=held")
    );
    let got = owlpost.get_message("msg_1").await.expect("get");
    assert_eq!(got.text.as_deref(), Some("secret"));
    let raw = owlpost.raw_message("msg_1").await.expect("raw");
    assert!(raw.contains("secret"), "raw is the RFC 822 source: {raw}");
}

/// A path-like or empty id is refused locally, before the network — and
/// before the key, so a keyless adapter reports the refusal, not
/// `NotConfigured`.
#[pollster::test]
async fn an_invalid_id_is_refused_with_no_request() {
    for bad in ["", "../../secrets", "msg/1", "msg 1"] {
        let http = Scripted::new(Vec::new());
        let keyless = Owlpost::new(http.clone(), Arc::new(FixedClock), None, "a@b.test", None);
        assert!(
            matches!(
                keyless.get_message(bad).await,
                Err(OwlpostError::Mail(MailError::Invalid { .. }))
            ),
            "{bad:?} with no key"
        );
        let owlpost = owlpost(http.clone());
        assert!(owlpost.get_message(bad).await.is_err(), "get {bad:?}");
        assert!(owlpost.raw_message(bad).await.is_err(), "raw {bad:?}");
        assert!(
            owlpost
                .reply(bad, Message::new("a@b.test", "", "", "", ""))
                .await
                .is_err(),
            "reply {bad:?}"
        );
        assert!(owlpost.release(bad).await.is_err(), "release {bad:?}");
        assert_eq!(http.count(), 0, "{bad:?} reached the network");
    }
}

/// A reply whose answer carries no `{"id": …}` body — an HTML proxy page, a
/// `204` — is a transport error, not a silent empty id.
#[pollster::test]
async fn a_reply_that_answers_no_id_is_a_transport_error() {
    for body in ["", "<html>gateway</html>", "204 No Content"] {
        let http = Scripted::new(vec![(200, body)]);
        let err = owlpost(http.clone())
            .reply("msg_1", Message::new("a@b.test", "", "", "", ""))
            .await
            .expect_err("no id in the answer");
        assert!(
            matches!(err, OwlpostError::Mail(MailError::Transport(_))),
            "{body:?} gave {err:?}"
        );
        assert_eq!(http.count(), 1);
    }
}
