//! Sending-domain tests (issue #681): the five routes on the wire, the
//! typed DKIM and MAIL FROM records, the 404/409/422 mapping against a
//! delegated status, and the refusals and keyless mode that must cost no
//! request.

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_owlpost::{
    DEFAULT_BASE_URL, DomainError, DomainStatus, Owlpost, RecordPurpose, RecordType,
};
use cratefield_core::{Clock, HttpClient, HttpError, MailError};
use http::{HeaderMap, Request, Response, StatusCode};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

// Obvious dummy key, never real.
const DUMMY_KEY: &str = "op_test_dummy_key_000000000000";

/// A domain with both record sets, as Owlpost answers it.
const DOMAIN: &str = concat!(
    r#"{"id":"d_123","name":"send.example.com","status":"not_started","created_at":"2026-01-02T03:04:05.000Z","#,
    r#""records":[{"record":"DKIM","name":"resend._domainkey","value":"p=MIGf...","ttl":"Auto","status":"not_started"},"#,
    r#"{"record":"MAIL FROM","type":"MX","name":"send","value":"mx.example.com","priority":10,"ttl":"Auto","status":"pending"}]}"#,
);

/// What the fake records per request.
type Captured = (String, String, HeaderMap, String);

struct FakeHttp {
    /// Answers in call order, so one walk can serve every route.
    answers: Vec<(u16, &'static str)>,
    calls: AtomicUsize,
    tx: mpsc::Sender<Captured>,
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let (parts, body) = request.into_parts();
        self.tx
            .send((
                parts.method.to_string(),
                parts.uri.to_string(),
                parts.headers,
                String::from_utf8_lossy(&body).to_string(),
            ))
            .expect("test channel open");
        let (status, body) = self.answers.get(call).copied().unwrap_or((200, "{}"));
        Response::builder()
            .status(StatusCode::from_u16(status).expect("valid status"))
            .body(Bytes::from(body))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

struct FixedClock(time::OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

fn fake(answers: Vec<(u16, &'static str)>) -> (Arc<FakeHttp>, mpsc::Receiver<Captured>) {
    let (tx, rx) = mpsc::channel();
    (
        Arc::new(FakeHttp {
            answers,
            calls: AtomicUsize::new(0),
            tx,
        }),
        rx,
    )
}

fn adapter(http: Arc<FakeHttp>) -> Owlpost {
    Owlpost::new(
        http,
        Arc::new(FixedClock(
            time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
        )),
        Some(DUMMY_KEY.to_string()),
        "Factory Zero <no-reply@test.factory0.dev>",
        None,
    )
}

#[pollster::test]
async fn the_five_routes_hit_their_endpoints() {
    let (http, rx) = fake(vec![
        (200, DOMAIN),
        (
            200,
            r#"{"object":"list","data":[{"id":"d_1","name":"a.example.com","status":"verified"}]}"#,
        ),
        (200, DOMAIN),
        (200, r#"{"id":"d_123"}"#),
        (200, r#"{"id":"d_123","deleted":true}"#),
    ]);
    let owlpost = adapter(http);
    owlpost
        .create_domain("send.example.com")
        .await
        .expect("create");
    owlpost.list_domains().await.expect("list");
    owlpost.get_domain("d_123").await.expect("get");
    owlpost.verify_domain("d_123").await.expect("verify");
    owlpost.delete_domain("d_123").await.expect("delete");

    let base = DEFAULT_BASE_URL.to_owned();
    let seen: Vec<(String, String)> = rx
        .try_iter()
        .map(|(method, uri, headers, body)| {
            // Every route carries the key, and only create sends a body.
            assert_eq!(
                headers.get("authorization").unwrap(),
                format!("Bearer {DUMMY_KEY}").as_str()
            );
            assert_eq!(
                !body.is_empty(),
                uri == format!("{base}/v1/domains") && method == "POST"
            );
            (method, uri)
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("POST".to_owned(), format!("{base}/v1/domains")),
            ("GET".to_owned(), format!("{base}/v1/domains")),
            ("GET".to_owned(), format!("{base}/v1/domains/d_123")),
            ("POST".to_owned(), format!("{base}/v1/domains/d_123/verify")),
            ("DELETE".to_owned(), format!("{base}/v1/domains/d_123")),
        ]
    );
}

#[pollster::test]
async fn a_created_domain_carries_its_dkim_and_mail_from_records() {
    let (http, rx) = fake(vec![(200, DOMAIN)]);
    let domain = adapter(http)
        .create_domain("send.example.com")
        .await
        .expect("create");
    let body: serde_json::Value =
        serde_json::from_str(&rx.try_recv().expect("one request").3).unwrap();
    assert_eq!(body["name"], "send.example.com");

    assert_eq!(domain.id, "d_123");
    assert_eq!(domain.status, DomainStatus::NotStarted);
    assert_eq!(
        domain.created_at.as_deref(),
        Some("2026-01-02T03:04:05.000Z")
    );
    assert_eq!(domain.records.len(), 2, "{:?}", domain.records);
    let (dkim, mail_from) = (&domain.records[0], &domain.records[1]);
    assert_eq!(
        (
            dkim.purpose,
            dkim.kind,
            &*dkim.name,
            &*dkim.value,
            dkim.ttl.as_deref(),
            dkim.priority,
            dkim.status,
        ),
        (
            RecordPurpose::Dkim,
            RecordType::Txt,
            "resend._domainkey",
            "p=MIGf...",
            Some("Auto"),
            None,
            Some(DomainStatus::NotStarted),
        )
    );
    assert_eq!(
        (
            mail_from.purpose,
            mail_from.kind,
            &*mail_from.name,
            mail_from.priority,
            mail_from.status,
        ),
        (
            RecordPurpose::MailFrom,
            RecordType::Mx,
            "send",
            Some(10),
            Some(DomainStatus::Pending),
        )
    );
}

#[pollster::test]
async fn an_unknown_state_and_purpose_parse_as_unknown() {
    // A provider that adds a state must not break the adapter.
    let (http, _rx) = fake(vec![(
        200,
        r#"{"id":"d_9","name":"b.example.com","status":"in_review","records":[{"record":"BIMI","type":"TXT","name":"default._bimi","value":"v=N"}]}"#,
    )]);
    let domain = adapter(http).get_domain("d_9").await.expect("get");
    assert_eq!(domain.status, DomainStatus::Unknown);
    assert_eq!(domain.records.len(), 1);
    assert_eq!(domain.records[0].purpose, RecordPurpose::Unknown);
    assert_eq!(domain.records[0].kind, RecordType::Txt);
}

/// The statuses a domain caller must tell apart, plus one that delegates to
/// the mail routes' [`MailError`] mapping.
#[pollster::test]
async fn statuses_map_to_their_own_variants() {
    let invalid = |detail: &str| DomainError::Invalid {
        detail: detail.to_owned(),
    };
    for (status, body, expected) in [
        (
            404,
            r#"{"title":"Not Found","detail":"Domain not found"}"#,
            DomainError::NotFound {
                detail: "Not Found: Domain not found".to_owned(),
            },
        ),
        (
            409,
            r#"{"detail":"Domain already exists"}"#,
            DomainError::AlreadyExists {
                detail: "Domain already exists".to_owned(),
            },
        ),
        (
            422,
            r#"{"detail":"Invalid domain"}"#,
            invalid("Invalid domain"),
        ),
        (
            401,
            r#"{"detail":"invalid key"}"#,
            DomainError::Mail(MailError::Unauthorized),
        ),
        // 403 on a domain route is a key without `domains:manage`, not an
        // unverified sending domain — even when the body says "domain".
        (
            403,
            r#"{"detail":"domain scope required"}"#,
            DomainError::Mail(MailError::Unauthorized),
        ),
    ] {
        let (http, _rx) = fake(vec![(status, body)]);
        let error = adapter(http)
            .create_domain("send.example.com")
            .await
            .expect_err("refused");
        assert_eq!(error, expected, "status {status}");
    }
}

#[pollster::test]
async fn local_refusals_and_a_missing_key_cost_no_request() {
    let (http, rx) = fake(vec![(200, DOMAIN)]);
    let owlpost = adapter(http.clone());

    for name in [
        "",
        "send.example.com.",
        ".send.example.com",
        "a..b",
        "localhost",
        "send_ex.com",
    ] {
        let error = owlpost.create_domain(name).await.expect_err("refused");
        assert!(
            matches!(&error, DomainError::Invalid { detail } if detail.contains("name")),
            "{name:?} gave {error:?}"
        );
    }
    // An id is spliced into the path, so `..` must never reach the wire.
    for id in ["", "../emails", "d 123"] {
        let error = owlpost.get_domain(id).await.expect_err("refused");
        assert!(
            matches!(&error, DomainError::Invalid { detail } if detail.contains("id")),
            "{id:?} gave {error:?}"
        );
    }
    let keyless = Owlpost::new(
        http.clone(),
        Arc::new(FixedClock(
            time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
        )),
        None,
        "Factory Zero <no-reply@test.factory0.dev>",
        None,
    );
    assert_eq!(
        keyless.list_domains().await,
        Err(DomainError::NotConfigured),
        "list must not call out"
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert!(rx.try_recv().is_err());
}
