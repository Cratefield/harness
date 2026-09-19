//! Issue #21 end to end.

use async_trait::async_trait;
use cratefield_core::{
    Clock, Config, Database, MailError, Mailer, MapConfig, Message, SendOutcome, Statement,
};
use cratefield_testing::TestHarness;
use factory0_auth_core::{AuthCore, STATUS_ACTIVE, UserRow, insert_user, user_by_primary_email};
use factory0_auth_magic_link::MagicLink;
use http::{HeaderMap, Method, Request, StatusCode, header};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;
use tower::ServiceExt;

const REQUEST: &str = "/v1/auth-magic-link/request";
const CONSUME: &str = "/v1/auth-magic-link/consume";
const BASE: &str = "https://auth.factory0.ventures";

/// A token-shaped value that was never issued: exactly the length and
/// alphabet a real token has, so it gets past the shape guard and reaches
/// the lookup, which is where a made-up credential belongs.
const BOGUS_TOKEN: &str = "a-bogus-token-of-exactly-the-correct-length";

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("in range")
    }
}

/// A mailer that keeps what it was given.
#[derive(Clone, Default)]
struct Outbox {
    sent: Arc<RwLock<Vec<Message>>>,
    outcome: Arc<RwLock<Option<SendOutcome>>>,
}

#[async_trait]
impl Mailer for Outbox {
    async fn send(&self, message: Message) -> Result<SendOutcome, MailError> {
        self.sent.write().expect("lock").push(message);
        Ok(self
            .outcome
            .read()
            .expect("lock")
            .clone()
            .unwrap_or(SendOutcome::Sent {
                id: "test-message".to_owned(),
            }))
    }
}

impl Outbox {
    fn last(&self) -> Option<Message> {
        self.sent.read().expect("lock").last().cloned()
    }

    fn count(&self) -> usize {
        self.sent.read().expect("lock").len()
    }

    /// The token out of the link in the text part, the way a person would
    /// read it.
    fn last_token(&self) -> Option<String> {
        let message = self.last()?;
        let start = message.text.find("token=")? + "token=".len();
        let rest = &message.text[start..];
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        Some(rest[..end].to_owned())
    }
}

struct Kit {
    harness: TestHarness,
    outbox: Outbox,
    clock: Arc<TestClock>,
    db: Arc<dyn Database>,
}

fn kit() -> Kit {
    kit_with(&[])
}

fn kit_with(extra: &[(&str, &str)]) -> Kit {
    let mut pairs = vec![
        ("AUTH_MAGIC_LINK_PUBLIC_BASE".to_owned(), BASE.to_owned()),
        (
            "AUTH_MAGIC_LINK_MAIL_FROM".to_owned(),
            "sign-in@factory0.ventures".to_owned(),
        ),
    ];
    for (key, value) in extra {
        pairs.push(((*key).to_owned(), (*value).to_owned()));
    }
    let outbox = Outbox::default();
    let clock = Arc::new(TestClock(AtomicI64::new(1_788_775_200)));
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(pairs));

    let mailer = outbox.clone();
    let clock_for_ports = clock.clone();
    let config_for_ports = config.clone();
    let harness = TestHarness::with_ports(
        vec![Box::new(AuthCore::new()), Box::new(MagicLink::new())],
        move |ports| {
            ports.mailer = Some(Arc::new(mailer));
            ports.clock = Some(clock_for_ports);
            ports.config = config_for_ports;
        },
    );
    let db = harness.db.clone();
    Kit {
        harness,
        outbox,
        clock,
        db,
    }
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Res {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|header| {
                let value = header.strip_prefix(&format!("{name}="))?;
                let value = value.split(';').next()?.trim();
                (!value.is_empty()).then(|| value.to_owned())
            })
    }

    fn location(&self) -> Option<String> {
        self.headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }
}

async fn send(kit: &Kit, request: Request<axum::body::Body>) -> Res {
    let response = kit
        .harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

async fn request_link(kit: &Kit, email: &str) -> Res {
    let request = Request::builder()
        .method(Method::POST)
        .uri(REQUEST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            json!({ "email": email }).to_string(),
        ))
        .expect("request");
    send(kit, request).await
}

/// A `GET /consume` with the fetch metadata a browser sends when somebody
/// clicks a link in a mail client.
async fn click(kit: &Kit, token: &str) -> Res {
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("{CONSUME}?token={token}"))
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .body(axum::body::Body::empty())
        .expect("request");
    send(kit, request).await
}

/// A `GET /consume` with no fetch metadata, which is what a mail scanner
/// prefetching the URL looks like.
async fn prefetch(kit: &Kit, token: &str) -> Res {
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("{CONSUME}?token={token}"))
        .body(axum::body::Body::empty())
        .expect("request");
    send(kit, request).await
}

fn count(kit: &Kit, table: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) AS n FROM {table}");
    let rows = pollster::block_on(kit.db.query(&Statement::new(sql))).expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
}

async fn seed(kit: &Kit, email: &str, verified: bool) -> String {
    let id = format!("u-{}", email.split('@').next().unwrap_or("x"));
    insert_user(
        &*kit.db,
        &UserRow {
            id: id.clone(),
            display_name: None,
            primary_email: Some(email.to_owned()),
            primary_email_verified: verified,
            status: STATUS_ACTIVE.to_owned(),
            created_at: "2026-09-07T10:00:00Z".to_owned(),
            updated_at: "2026-09-07T10:00:00Z".to_owned(),
        },
    )
    .await
    .expect("seeds");
    id
}

// ---------------------------------------------------------------------

/// The acceptance criterion: known and unknown addresses are identical.
#[test]
fn a_known_and_an_unknown_address_answer_identically() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;

        let known = request_link(&kit, "ada@example.com").await;
        let unknown = request_link(&kit, "nobody@example.com").await;
        let rubbish = request_link(&kit, "not-an-address").await;

        assert_eq!(known.status, StatusCode::ACCEPTED);
        assert_eq!(unknown.status, known.status);
        assert_eq!(rubbish.status, known.status);
        assert_eq!(unknown.body, known.body, "the bodies differ");
        assert_eq!(rubbish.body, known.body, "the bodies differ");
        // And the body says nothing either way.
        assert_eq!(known.json()["status"], "accepted");
        let message = known.json()["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(message.contains("If that address"), "{message}");

        // Only the known address got a mail.
        assert_eq!(kit.outbox.count(), 1);
        assert_eq!(kit.outbox.last().expect("a mail").to, "ada@example.com");
    });
}

#[test]
fn a_disabled_account_gets_no_link_and_the_caller_cannot_tell() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", true).await;
        kit.db
            .execute(&Statement::new("UPDATE users SET status = 'disabled'"))
            .await
            .expect("disables");

        let response = request_link(&kit, "ada@example.com").await;
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(kit.outbox.count(), 0, "a disabled account was mailed");
    });
}

#[test]
fn the_mail_carries_a_working_link_and_the_token_is_stored_hashed() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;
        request_link(&kit, "ada@example.com").await;

        let message = kit.outbox.last().expect("a mail");
        assert!(message.text.contains(BASE), "{}", message.text);
        assert!(message.subject.contains("Sign in"), "{}", message.subject);
        let token = kit.outbox.last_token().expect("a token in the link");
        assert!(token.len() >= 43, "{token}");

        // The row stores a digest, never the token: a leaked database is
        // not a way in. Looked up *by* the digest, which is also what
        // proves the stored value is the digest and not the token.
        let digest = {
            use sha2::{Digest, Sha256};
            Sha256::digest(token.as_bytes()).to_vec()
        };
        assert!(
            factory0_auth_core::single_use_token_by_hash(&*kit.db, &digest)
                .await
                .expect("query")
                .is_some(),
            "the row is not keyed by the token's digest"
        );
        assert!(
            factory0_auth_core::single_use_token_by_hash(&*kit.db, token.as_bytes())
                .await
                .expect("query")
                .is_none(),
            "the token itself was stored"
        );
    });
}

#[test]
fn clicking_the_link_signs_in_and_verifies_the_address() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;
        request_link(&kit, "ada@example.com").await;
        let token = kit.outbox.last_token().expect("a token");

        let response = click(&kit, &token).await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        assert!(response.cookie("__Host-fz_session").is_some());
        assert_eq!(response.location().as_deref(), Some("/"));
        assert_eq!(count(&kit, "sessions"), 1);

        // Opening a link sent to an address is the proof it is theirs, and
        // the only proof this service has.
        let user = user_by_primary_email(&*kit.db, "ada@example.com")
            .await
            .expect("query")
            .expect("a user");
        assert!(
            user.primary_email_verified,
            "consuming a link did not verify the address"
        );
    });
}

/// The acceptance criterion: two simultaneous consumes yield one session.
#[test]
fn a_token_is_single_use_even_under_concurrency() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;
        request_link(&kit, "ada@example.com").await;
        let token = kit.outbox.last_token().expect("a token");

        // Both futures are driven together, so both reach the consume
        // statement before either has finished. The guarantee is the
        // `where consumed_at is null` plus the affected-row count, not
        // ordering.
        let (first, second) =
            futures_lite::future::zip(click(&kit, &token), click(&kit, &token)).await;

        let won = [&first, &second]
            .iter()
            .filter(|response| response.status == StatusCode::FOUND)
            .count();
        assert_eq!(won, 1, "two consumes both succeeded");
        assert_eq!(count(&kit, "sessions"), 1, "two sessions from one token");

        // And the loser is told exactly what an expired link is told.
        let lost = if first.status == StatusCode::FOUND {
            &second
        } else {
            &first
        };
        assert_eq!(lost.status, StatusCode::BAD_REQUEST);
    });
}

#[test]
fn an_expired_and_an_already_used_token_fail_identically() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;

        // Used.
        request_link(&kit, "ada@example.com").await;
        let used = kit.outbox.last_token().expect("a token");
        assert_eq!(click(&kit, &used).await.status, StatusCode::FOUND);
        let spent = click(&kit, &used).await;

        // Expired.
        request_link(&kit, "ada@example.com").await;
        let stale = kit.outbox.last_token().expect("a token");
        kit.clock.0.fetch_add(901, Ordering::SeqCst);
        let expired = click(&kit, &stale).await;

        // Never issued.
        let never = click(&kit, BOGUS_TOKEN).await;

        assert_eq!(spent.status, StatusCode::BAD_REQUEST);
        assert_eq!(expired.status, spent.status);
        assert_eq!(never.status, spent.status);
        assert_eq!(
            expired.body, spent.body,
            "an expired link is distinguishable"
        );
        assert_eq!(
            never.body, spent.body,
            "an unissued token is distinguishable"
        );
    });
}

/// The prefetch defence. Mail scanners fetch every URL in a message; one
/// that consumed the token would sign nobody in and leave the person with
/// a link that has already been used.
#[test]
fn a_prefetch_does_not_spend_the_token_and_a_click_still_works() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;
        request_link(&kit, "ada@example.com").await;
        let token = kit.outbox.last_token().expect("a token");

        // Three scanners, as a corporate mail path might.
        for _ in 0..3 {
            let response = prefetch(&kit, &token).await;
            assert_eq!(response.status, StatusCode::OK);
            assert!(
                response.cookie("__Host-fz_session").is_none(),
                "a prefetch signed somebody in"
            );
            assert!(response.text().contains("Confirm"), "{}", response.text());
        }
        assert_eq!(count(&kit, "sessions"), 0);

        // The person then clicks, and it still works.
        let response = click(&kit, &token).await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        assert_eq!(count(&kit, "sessions"), 1);
    });
}

/// And the confirm button on that page works, for browsers that send no
/// fetch metadata at all.
#[test]
fn the_confirm_button_spends_the_token() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;
        request_link(&kit, "ada@example.com").await;
        let token = kit.outbox.last_token().expect("a token");

        let request = Request::builder()
            .method(Method::POST)
            .uri(CONSUME)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(format!("token={token}")))
            .expect("request");
        let response = send(&kit, request).await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        assert!(response.cookie("__Host-fz_session").is_some());
    });
}

/// The confirm button spends the token and mints a session, so a form on
/// another site must not be able to press it for somebody (issue #439):
/// refused on arrival, the token unspent. A same-origin press — every
/// header a real browser sends — still works.
#[test]
fn a_cross_site_confirm_cannot_spend_a_token_or_sign_anyone_in() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;
        request_link(&kit, "ada@example.com").await;
        let token = kit.outbox.last_token().expect("a token");

        let cross_site = post_form_with(
            &kit,
            CONSUME,
            &format!("token={token}"),
            &[
                ("host", "auth.example.test"),
                ("origin", "https://evil.example"),
            ],
        )
        .await;
        assert_eq!(
            cross_site.status,
            StatusCode::FORBIDDEN,
            "{}",
            cross_site.text()
        );
        assert_eq!(
            cross_site.json()["type"],
            "https://factory0.ventures/problems/auth/cross-site-request"
        );
        assert!(
            cross_site.cookie("__Host-fz_session").is_none(),
            "the cross-site confirm signed somebody in"
        );
        assert_eq!(count(&kit, "sessions"), 0, "a session was issued anyway");

        // The refusal spent nothing: the same token, same-origin, still
        // signs the person in.
        let own = post_form_with(
            &kit,
            CONSUME,
            &format!("token={token}"),
            &[
                ("host", "auth.example.test"),
                ("origin", "https://auth.example.test"),
                ("sec-fetch-site", "same-origin"),
            ],
        )
        .await;
        assert_eq!(own.status, StatusCode::FOUND, "{}", own.text());
        assert!(own.cookie("__Host-fz_session").is_some());
    });
}

/// A prefetch must not become an oracle either: a real token and a fake
/// one get the same page.
#[test]
fn a_prefetch_cannot_be_used_to_test_whether_a_token_is_real() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;
        request_link(&kit, "ada@example.com").await;
        let real = kit.outbox.last_token().expect("a token");

        let genuine = prefetch(&kit, &real).await;
        let invented = prefetch(&kit, BOGUS_TOKEN).await;
        assert_eq!(genuine.status, invented.status);
        // The bodies differ only in the token echoed into the form.
        assert!(genuine.text().contains("Confirm"));
        assert!(invented.text().contains("Confirm"));
    });
}

/// The confirm page interpolates the token it was handed, so the shape
/// guard is what stands between a hostile query parameter and the
/// document: a value that could not be a token is not a token, and gets
/// the expired page instead of reaching the HTML at all.
#[test]
fn a_token_that_is_not_token_shaped_gets_the_expired_page() {
    pollster::block_on(async {
        // The shape check is the first guard and the escape in the hidden
        // field the second — the order that survives either being widened
        // alone.
        let kit = kit();
        let attack = "\"><script>alert(1)</script>";
        let encoded = "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E";
        let response = prefetch(&kit, encoded).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{}",
            response.text()
        );
        let html = response.text();
        assert!(html.contains("expired"), "not the expired page: {html}");
        assert!(!html.contains("<script"), "{html}");
        assert!(
            !html.contains(attack),
            "the raw value reached the document: {html}"
        );
        assert!(!html.contains("<form"), "the confirm form rendered: {html}");
    });
}

/// And the confirm button demands the same token shape: the two entry
/// points parse the value independently, so the guard is pinned on each.
#[test]
fn a_posted_token_that_is_not_token_shaped_gets_the_expired_page() {
    pollster::block_on(async {
        let kit = kit();
        let attack = "\"><script>alert(1)</script>";
        let response = post_form(
            &kit,
            CONSUME,
            "token=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{}",
            response.text()
        );
        let html = response.text();
        assert!(html.contains("expired"), "not the expired page: {html}");
        assert!(!html.contains("<script"), "{html}");
        assert!(
            !html.contains(attack),
            "the raw value reached the document: {html}"
        );
        assert!(!html.contains("<form"), "the confirm form rendered: {html}");
        assert_eq!(count(&kit, "sessions"), 0, "a malformed token spent one");
    });
}

/// And the guard refuses only what could never be a token: a stranger's
/// value of the exact right shape still reaches the lookup, and is
/// answered exactly the way an expired link is.
#[test]
fn a_well_formed_but_unknown_token_still_fails_like_an_expired_one() {
    pollster::block_on(async {
        let kit = kit();
        assert_eq!(BOGUS_TOKEN.len(), 43, "the shape the guard demands");
        seed(&kit, "ada@example.com", false).await;

        // A genuinely expired link, to compare against.
        request_link(&kit, "ada@example.com").await;
        let real = kit.outbox.last_token().expect("a token");
        kit.clock.0.fetch_add(901, Ordering::SeqCst);
        let expired = click(&kit, &real).await;

        let invented = click(&kit, BOGUS_TOKEN).await;
        assert_eq!(invented.status, expired.status);
        assert_eq!(
            invented.body, expired.body,
            "a well-formed stranger is distinguishable from an expired link"
        );
    });
}

#[test]
fn registration_by_link_is_off_unless_a_venture_asks_for_it() {
    pollster::block_on(async {
        // Off: an unknown address gets nothing.
        let kit = kit();
        request_link(&kit, "nobody@example.com").await;
        assert_eq!(count(&kit, "users"), 0);
        assert_eq!(kit.outbox.count(), 0);

        // On: the account is created, unverified, and the link verifies it.
        let kit = kit_with(&[("AUTH_MAGIC_LINK_ALLOW_REGISTRATION", "true")]);
        let response = request_link(&kit, "ada@example.com").await;
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(count(&kit, "users"), 1);
        let user = user_by_primary_email(&*kit.db, "ada@example.com")
            .await
            .expect("query")
            .expect("a user");
        assert!(
            !user.primary_email_verified,
            "creating the row is not proof; opening the mail is"
        );

        let token = kit.outbox.last_token().expect("a token");
        assert_eq!(click(&kit, &token).await.status, StatusCode::FOUND);
        let user = user_by_primary_email(&*kit.db, "ada@example.com")
            .await
            .expect("query")
            .expect("a user");
        assert!(user.primary_email_verified);
    });
}

#[test]
fn a_return_to_survives_the_round_trip_and_an_absolute_one_does_not() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;

        let post = |body: Value| {
            let request = Request::builder()
                .method(Method::POST)
                .uri(REQUEST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request");
            send(&kit, request)
        };

        post(json!({ "email": "ada@example.com", "return_to": "/v1/auth-core/authorize?x=1" }))
            .await;
        let token = kit.outbox.last_token().expect("a token");
        let response = click(&kit, &token).await;
        assert_eq!(
            response.location().as_deref(),
            Some("/v1/auth-core/authorize?x=1")
        );

        // Past the send cooldown, or the second request below is refused
        // and this test reads the first mail twice.
        kit.clock.0.fetch_add(61, Ordering::SeqCst);

        // An absolute one is an open redirect, and is dropped for the
        // default rather than followed.
        post(json!({ "email": "ada@example.com", "return_to": "https://evil.example" })).await;
        let token = kit.outbox.last_token().expect("a token");
        let response = click(&kit, &token).await;
        assert_eq!(response.location().as_deref(), Some("/"));
    });
}

#[test]
fn a_token_of_another_kind_cannot_be_spent_here() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;

        // An authorization code, presented to the magic link. Different
        // kind, same table: without the kind check this would be a way to
        // turn one credential into another. Token-shaped on purpose, so
        // it is the kind check that refuses it and not the shape guard
        // before it.
        let token = BOGUS_TOKEN;
        let digest = {
            use sha2::{Digest, Sha256};
            Sha256::digest(token.as_bytes()).to_vec()
        };
        factory0_auth_core::insert_single_use_token(
            &*kit.db,
            &factory0_auth_core::SingleUseTokenRow {
                id: "t1".to_owned(),
                kind: factory0_auth_core::TOKEN_AUTHORIZATION_CODE.to_owned(),
                token_hash: factory0_auth_core::Redacted(digest),
                user_id: Some("u-ada".to_owned()),
                client_id: None,
                payload: None,
                expires_at: "2099-01-01T00:00:00Z".to_owned(),
                consumed_at: None,
            },
        )
        .await
        .expect("seeds");

        let response = click(&kit, token).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(response.cookie("__Host-fz_session").is_none());
        assert_eq!(count(&kit, "sessions"), 0);
    });
}

#[test]
fn a_second_request_inside_the_window_sends_no_second_mail() {
    pollster::block_on(async {
        // The rate limiter is a distributed counter whose transport can
        // fail open; this backstop is a row the database enforces. There
        // is no `RateLimiter` port in this kit at all, which is exactly
        // the fail-open case.
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;

        let first = request_link(&kit, "ada@example.com").await;
        let second = request_link(&kit, "ada@example.com").await;
        let third = request_link(&kit, "ada@example.com").await;

        assert_eq!(kit.outbox.count(), 1, "the window leaked a second mail");

        // And a refusal is indistinguishable from a send: a caller who can
        // tell "you already asked" from "no such account" can enumerate
        // addresses, which is what every other branch of this handler is
        // careful about.
        assert_eq!(second.status, first.status);
        assert_eq!(second.body, first.body);
        assert_eq!(third.body, first.body);
        let unknown = request_link(&kit, "nobody@example.com").await;
        assert_eq!(second.body, unknown.body);

        // The window is per address, not global.
        seed(&kit, "grace@example.com", false).await;
        request_link(&kit, "grace@example.com").await;
        assert_eq!(kit.outbox.count(), 2, "one address blocked another");

        // And it ends.
        kit.clock.0.fetch_add(61, Ordering::SeqCst);
        request_link(&kit, "ada@example.com").await;
        assert_eq!(kit.outbox.count(), 3, "the window never reopened");
    });
}

#[test]
fn a_new_link_retires_the_one_it_replaces() {
    pollster::block_on(async {
        // Two live links are two windows in which a forwarded mail or a
        // link scanner signs somebody in. Asking for a second one says the
        // first is not the one being used.
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;

        request_link(&kit, "ada@example.com").await;
        let first = kit.outbox.last_token().expect("a token");

        kit.clock.0.fetch_add(61, Ordering::SeqCst);
        request_link(&kit, "ada@example.com").await;
        let second = kit.outbox.last_token().expect("a token");
        assert_ne!(first, second, "the same token was mailed twice");

        // The newest link works.
        let response = click(&kit, &second).await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());

        // The one it replaced does not — and fails the way a made-up token
        // does, so holding a retired link teaches nothing.
        let retired = click(&kit, &first).await;
        let invented = click(&kit, BOGUS_TOKEN).await;
        assert_eq!(retired.status, invented.status);
        assert_eq!(retired.body, invented.body);
    });
}

#[test]
fn retiring_a_link_leaves_another_accounts_link_alone() {
    pollster::block_on(async {
        // The retire is scoped to one user and one kind. A `WHERE` that
        // lost either would sign everybody out of their pending links the
        // moment one person asked for a second.
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;
        seed(&kit, "grace@example.com", false).await;

        request_link(&kit, "grace@example.com").await;
        let graces = kit.outbox.last_token().expect("a token");

        request_link(&kit, "ada@example.com").await;
        kit.clock.0.fetch_add(61, Ordering::SeqCst);
        request_link(&kit, "ada@example.com").await;

        let response = click(&kit, &graces).await;
        assert_eq!(
            response.status,
            StatusCode::FOUND,
            "another account's link was retired: {}",
            response.text()
        );
    });
}

const START: &str = "/v1/auth-magic-link/start";

async fn get_page(kit: &Kit, uri: &str) -> Res {
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(axum::body::Body::empty())
        .expect("request");
    send(kit, request).await
}

async fn post_form(kit: &Kit, uri: &str, body: &str) -> Res {
    post_form_with(kit, uri, body, &[]).await
}

/// `post_form` for a request that carries extra headers — the browser
/// headers (`origin`, `host`, `sec-fetch-site`) the login-CSRF guard reads.
async fn post_form_with(kit: &Kit, uri: &str, body: &str, extra: &[(&str, &str)]) -> Res {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(axum::body::Body::from(body.to_owned()))
        .expect("request");
    send(kit, request).await
}

#[test]
fn the_form_works_with_no_script_and_posts_to_itself() {
    pollster::block_on(async {
        // The reason this method is a page and not a button: an address
        // has to be typed. The reason it is a plain form is that every
        // redirect method on the chooser works with script off, and this
        // one should not be the exception.
        let kit = kit();
        let form = get_page(&kit, START).await;
        assert_eq!(form.status, StatusCode::OK);
        let html = form.text();
        assert!(html.contains("<form method=\"post\""), "{html}");
        assert!(html.contains("name=\"email\""), "{html}");
        assert!(
            !html.contains("<script"),
            "the form needs no script: {html}"
        );
        assert!(
            form.headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/html")),
            "{:?}",
            form.headers.get(header::CONTENT_TYPE)
        );
    });
}

#[test]
fn submitting_the_form_sends_a_link_and_says_nothing_about_the_address() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;

        let known = post_form(&kit, START, "email=ada%40example.com").await;
        assert_eq!(known.status, StatusCode::ACCEPTED);
        assert_eq!(kit.outbox.count(), 1);
        assert!(
            known.text().contains("Check your inbox"),
            "{}",
            known.text()
        );

        // The whole property of this endpoint, in the page form: an
        // unknown address is answered identically, byte for byte.
        kit.clock.0.fetch_add(61, Ordering::SeqCst);
        let unknown = post_form(&kit, START, "email=nobody%40example.com").await;
        assert_eq!(unknown.status, known.status);
        assert_eq!(unknown.body, known.body, "the two pages differ");
        assert_eq!(kit.outbox.count(), 1, "an unknown address got a mail");
    });
}

#[test]
fn the_page_and_the_json_route_reach_the_same_decisions() {
    pollster::block_on(async {
        // Two entry points to one rule. If the page grew its own idea of
        // who gets a mail, this is what would say so.
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;

        // The send cooldown is one ledger, not one per entry point.
        post_form(&kit, START, "email=ada%40example.com").await;
        assert_eq!(kit.outbox.count(), 1);
        let json = request_link(&kit, "ada@example.com").await;
        assert_eq!(json.status, StatusCode::ACCEPTED);
        assert_eq!(
            kit.outbox.count(),
            1,
            "the JSON route sent a second mail inside the page's window"
        );

        // And the other way round.
        kit.clock.0.fetch_add(61, Ordering::SeqCst);
        request_link(&kit, "ada@example.com").await;
        assert_eq!(kit.outbox.count(), 2);
        post_form(&kit, START, "email=ada%40example.com").await;
        assert_eq!(
            kit.outbox.count(),
            2,
            "the page sent a second mail inside the JSON route's window"
        );
    });
}

#[test]
fn a_return_to_survives_the_form_and_an_absolute_one_does_not() {
    pollster::block_on(async {
        let kit = kit();
        seed(&kit, "ada@example.com", false).await;

        let form = get_page(&kit, &format!("{START}?return_to=/somewhere")).await;
        assert!(
            form.text()
                .contains("name=\"return_to\" value=\"/somewhere\""),
            "{}",
            form.text()
        );

        post_form(
            &kit,
            START,
            "email=ada%40example.com&return_to=%2Fv1%2Fauth-core%2Fauthorize%3Fx%3D1",
        )
        .await;
        let token = kit.outbox.last_token().expect("a token");
        let response = click(&kit, &token).await;
        assert_eq!(
            response.location().as_deref(),
            Some("/v1/auth-core/authorize?x=1")
        );

        // An absolute one is an open redirect and never reaches the form.
        let hostile = get_page(&kit, &format!("{START}?return_to=https://evil.example")).await;
        assert!(
            !hostile.text().contains("evil.example"),
            "an absolute return_to reached the page: {}",
            hostile.text()
        );
    });
}

#[test]
fn a_return_to_cannot_break_out_of_the_hidden_field() {
    pollster::block_on(async {
        // `return_to` is caller-supplied and lands in a `value="…"`.
        // `safe_return_to` already requires a leading `/`, so the escape
        // is the second guard rather than the first — which is the order
        // that survives someone widening the first one.
        let kit = kit();
        let attack = "/ok\"><script>alert(1)</script>";
        let encoded = "%2Fok%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E";
        let page = get_page(&kit, &format!("{START}?return_to={encoded}")).await;
        let html = page.text();
        assert!(!html.contains("<script>alert"), "{html}");
        assert!(
            !html.contains(attack),
            "the raw value reached the document: {html}"
        );
    });
}

#[test]
fn an_empty_box_is_the_one_thing_the_page_will_say() {
    pollster::block_on(async {
        // Everything about an account is withheld. What the person typed
        // is theirs, and a form that silently does nothing is worse.
        let kit = kit();
        let answer = post_form(&kit, START, "email=").await;
        assert_eq!(answer.status, StatusCode::OK);
        assert!(
            answer.text().contains("Enter your email"),
            "{}",
            answer.text()
        );
        assert!(answer.text().contains("<form"), "the form comes back");
        assert_eq!(kit.outbox.count(), 0);
    });
}
