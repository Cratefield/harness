//! One entry flow, the email half: a new address for an application that asks
//! its sign-up question gets no account until the link is opened and the
//! question is answered there. The request answers the same for a known and an
//! unknown address (anti-enumeration), an invite-only deployment answers the
//! same too, and the answer is recorded for the account and client it was given
//! for. A deployment whose client asks nothing keeps today's behaviour.

use async_trait::async_trait;
use cratefield_auth_core::{AuthCore, STATUS_ACTIVE, UserRow, insert_user, user_by_primary_email};
use cratefield_auth_magic_link::MagicLink;
use cratefield_core::{
    Clock, Config, Database, MailError, Mailer, MapConfig, Message, SendOutcome, Statement,
};
use cratefield_testing::TestHarness;
use http::{HeaderMap, Method, Request, StatusCode, header};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;
use tower::ServiceExt;

const REQUEST: &str = "/v1/auth-magic-link/request";
const CONSUME: &str = "/v1/auth-magic-link/consume";
const ADMIN: &str = "test-admin-token-0123456789abcdef";
const REDIRECT: &str = "https://undercoverrockstars.com/auth/callback";
const BASE: &str = "https://auth.acme.example";

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("in range")
    }
}

#[derive(Clone, Default)]
struct Outbox {
    sent: Arc<RwLock<Vec<Message>>>,
}

#[async_trait]
impl Mailer for Outbox {
    async fn send(&self, message: Message) -> Result<SendOutcome, MailError> {
        self.sent.write().expect("lock").push(message);
        Ok(SendOutcome::Sent {
            id: "test-message".to_owned(),
        })
    }
}

impl Outbox {
    fn count(&self) -> usize {
        self.sent.read().expect("lock").len()
    }

    /// The token out of the link in the newest mail's text part.
    fn last_token(&self) -> Option<String> {
        let sent = self.sent.read().expect("lock");
        token_of(&sent.last()?.text)
    }

    /// The token out of the `index`th mail sent.
    fn token_at(&self, index: usize) -> Option<String> {
        let sent = self.sent.read().expect("lock");
        token_of(&sent.get(index)?.text)
    }
}

fn token_of(text: &str) -> Option<String> {
    let start = text.find("token=")? + "token=".len();
    let rest = &text[start..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

/// Moves the deployment's clock forward: past the send window, or a link's life.
fn advance(kit: &Kit, secs: i64) {
    kit.clock.0.fetch_add(secs, Ordering::SeqCst);
}

/// Stores an unspent link for `email` by hand, expiring at `expires_at_secs`,
/// so a test can hold a link across a change of deployment settings.
async fn pending_link(kit: &Kit, token: &str, email: &str, client: &str, expires_at_secs: i64) {
    use cratefield_auth_core::{
        Redacted, SingleUseTokenRow, TOKEN_MAGIC_LINK, insert_single_use_token,
    };
    use sha2::{Digest, Sha256};
    let expires = OffsetDateTime::from_unix_timestamp(expires_at_secs)
        .expect("in range")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339");
    insert_single_use_token(
        &*kit.db,
        &SingleUseTokenRow {
            id: format!("pending-{token}"),
            kind: TOKEN_MAGIC_LINK.to_owned(),
            token_hash: Redacted(Sha256::digest(token.as_bytes()).to_vec()),
            user_id: None,
            client_id: None,
            payload: Some(
                json!({ "new_email": email, "client_id": client, "locale": "en" }).to_string(),
            ),
            expires_at: expires,
            consumed_at: None,
        },
    )
    .await
    .expect("stores");
}

struct Kit {
    clock: Arc<TestClock>,
    harness: TestHarness,
    outbox: Outbox,
    db: Arc<dyn Database>,
}

/// The deployment: registration by link on or off, the admin token for
/// registering a client, and no client yet.
fn kit(allow_registration: bool) -> Kit {
    let mut pairs = vec![
        ("AUTH_MAGIC_LINK_PUBLIC_BASE".to_owned(), BASE.to_owned()),
        (
            "AUTH_MAGIC_LINK_MAIL_FROM".to_owned(),
            "sign-in@acme.example".to_owned(),
        ),
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
    ];
    if allow_registration {
        pairs.push((
            "AUTH_MAGIC_LINK_ALLOW_REGISTRATION".to_owned(),
            "true".to_owned(),
        ));
    }
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(pairs));
    let outbox = Outbox::default();
    let mailer = outbox.clone();
    let clock = Arc::new(TestClock(AtomicI64::new(1_788_775_200)));
    let clock_for_ports = clock.clone();
    let harness = TestHarness::with_ports(
        vec![Box::new(AuthCore::new()), Box::new(MagicLink::new())],
        move |ports| {
            ports.mailer = Some(Arc::new(mailer));
            ports.rate_limiter =
                Some(Arc::new(cratefield_testing::FakeRateLimiter::always_allow()));
            ports.clock = Some(clock_for_ports);
            ports.config = config;
        },
    );
    let db = harness.db.clone();
    Kit {
        clock,
        harness,
        outbox,
        db,
    }
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
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
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
    }
}

/// Registers a public client with the given sign-up intents through the
/// admin API, and returns its id.
async fn register_client(kit: &Kit, intents: Value) -> String {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/auth-core/admin/clients")
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            json!({
                "name": "Undercover Rockstars",
                "kind": "public",
                "redirect_uris": [REDIRECT],
                "signup_intents": intents,
            })
            .to_string(),
        ))
        .expect("request");
    let response = send(kit, request).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
    serde_json::from_str::<Value>(&response.body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// The `return_to` a sign-in for `client` carries: the authorize request as
/// the chooser hands it back, with a sign-up answer when given.
fn return_to_for(client: &str, extra: &str) -> String {
    format!(
        "/v1/auth-core/authorize?response_type=code&client_id={client}\
         &redirect_uri={REDIRECT}&code_challenge=abc&code_challenge_method=S256&scope=openid{extra}"
    )
}

async fn request_link(kit: &Kit, email: &str, return_to: Option<&str>) -> Res {
    let mut body = json!({ "email": email });
    if let Some(return_to) = return_to {
        body["return_to"] = json!(return_to);
    }
    let request = Request::builder()
        .method(Method::POST)
        .uri(REQUEST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    send(kit, request).await
}

/// The confirm page's own POST, from the same origin a browser sends.
async fn confirm(kit: &Kit, body: &str) -> Res {
    let request = Request::builder()
        .method(Method::POST)
        .uri(CONSUME)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("host", "auth.acme.example")
        .header("origin", BASE)
        .header("sec-fetch-site", "same-origin")
        .body(axum::body::Body::from(body.to_owned()))
        .expect("request");
    send(kit, request).await
}

async fn users_with(kit: &Kit, email: &str) -> bool {
    user_by_primary_email(&*kit.db, email)
        .await
        .expect("query")
        .is_some()
}

async fn seed_user(kit: &Kit, email: &str) {
    insert_user(
        &*kit.db,
        &UserRow {
            id: format!("u-{}", email.split('@').next().unwrap_or("x")),
            display_name: None,
            primary_email: Some(email.to_owned()),
            primary_email_verified: true,
            locale: None,
            status: STATUS_ACTIVE.to_owned(),
            created_at: "2026-09-07T10:00:00Z".to_owned(),
            updated_at: "2026-09-07T10:00:00Z".to_owned(),
        },
    )
    .await
    .expect("seeds");
}

fn builder_list() -> Value {
    json!([
        { "key": "builder", "label": { "en": "I build things" } },
        { "key": "buyer", "label": { "en": "I buy things" } },
        { "key": "just_looking", "label": { "en": "Just looking" }, "multi": false }
    ])
}

fn session_cookie(response: &Res) -> Option<String> {
    response
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("__Host-session="))
        .map(str::to_owned)
}

#[pollster::test]
async fn a_new_address_for_an_asking_client_makes_no_account_until_the_question_is_answered() {
    let kit = kit(true);
    let client = register_client(&kit, builder_list()).await;
    let return_to = return_to_for(&client, "");

    let response = request_link(&kit, "ada@example.com", Some(&return_to)).await;
    assert_eq!(response.status, StatusCode::ACCEPTED);
    assert!(
        !users_with(&kit, "ada@example.com").await,
        "no account before the link is opened"
    );
    assert_eq!(kit.outbox.count(), 1, "the link is still sent");
    let token = kit.outbox.last_token().expect("a token");

    // Opening the link and pressing the confirm button first shows the
    // question. Nothing is spent and no account exists yet.
    let asked = confirm(&kit, &format!("token={token}")).await;
    assert_eq!(asked.status, StatusCode::OK, "{}", asked.body);
    assert!(
        asked.body.contains("What brings you here?"),
        "{}",
        asked.body
    );
    assert!(
        asked.body.contains("name=\"intents\" value=\"builder\""),
        "{}",
        asked.body
    );
    assert!(session_cookie(&asked).is_none());
    assert!(!users_with(&kit, "ada@example.com").await);

    // A refused answer asks again, still unspent.
    let refused = confirm(
        &kit,
        &format!("token={token}&intents_step=1&intents=wizard"),
    )
    .await;
    assert_eq!(refused.status, StatusCode::OK);
    assert!(refused.body.contains("What brings you here?"));
    assert!(!users_with(&kit, "ada@example.com").await);

    // The answer makes the account, verifies the address, signs in, and
    // records the choice for this client.
    let answered = confirm(
        &kit,
        &format!("token={token}&intents_step=1&intents=builder&intents=buyer"),
    )
    .await;
    assert_eq!(answered.status, StatusCode::FOUND, "{}", answered.body);
    assert!(session_cookie(&answered).is_some(), "signed in");
    let user = user_by_primary_email(&*kit.db, "ada@example.com")
        .await
        .expect("query")
        .expect("the account exists now");
    assert!(user.primary_email_verified);
    let chosen = cratefield_auth_core::intents::chosen(&*kit.db, &user.id, &client)
        .await
        .expect("query");
    assert_eq!(chosen, Some(vec!["builder".to_owned(), "buyer".to_owned()]));

    // The link works once.
    let again = confirm(
        &kit,
        &format!("token={token}&intents_step=1&intents=builder"),
    )
    .await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST, "{}", again.body);
}

#[pollster::test]
async fn an_exclusive_answer_combined_with_another_is_refused_and_nothing_is_spent() {
    let kit = kit(true);
    let client = register_client(&kit, builder_list()).await;
    request_link(&kit, "ada@example.com", Some(&return_to_for(&client, ""))).await;
    let token = kit.outbox.last_token().expect("a token");
    let mixed = confirm(
        &kit,
        &format!("token={token}&intents_step=1&intents=just_looking&intents=builder"),
    )
    .await;
    assert_eq!(mixed.status, StatusCode::OK);
    assert!(mixed.body.contains("What brings you here?"));
    assert!(!users_with(&kit, "ada@example.com").await);
}

#[pollster::test]
async fn an_application_that_answers_for_the_person_skips_the_question() {
    let kit = kit(true);
    let client = register_client(&kit, builder_list()).await;
    request_link(
        &kit,
        "ada@example.com",
        Some(&return_to_for(&client, "&intents=buyer")),
    )
    .await;
    assert!(
        users_with(&kit, "ada@example.com").await,
        "the account is made straight away"
    );
    let token = kit.outbox.last_token().expect("a token");

    let done = confirm(&kit, &format!("token={token}")).await;
    assert_eq!(done.status, StatusCode::FOUND, "{}", done.body);
    let user = user_by_primary_email(&*kit.db, "ada@example.com")
        .await
        .expect("query")
        .expect("user");
    assert_eq!(
        cratefield_auth_core::intents::chosen(&*kit.db, &user.id, &client)
            .await
            .expect("query"),
        Some(vec!["buyer".to_owned()])
    );
}

#[pollster::test]
async fn an_unknown_and_a_known_address_answer_identically_when_registration_is_off() {
    let kit = kit(false);
    let client = register_client(&kit, builder_list()).await;
    seed_user(&kit, "ada@example.com").await;
    let known = request_link(&kit, "ada@example.com", Some(&return_to_for(&client, ""))).await;
    let unknown = request_link(
        &kit,
        "nobody@example.com",
        Some(&return_to_for(&client, "")),
    )
    .await;
    assert_eq!(known.status, StatusCode::ACCEPTED);
    assert_eq!(unknown.status, known.status);
    assert_eq!(
        unknown.body, known.body,
        "the answer must not say whether the address has an account"
    );
    assert!(
        !users_with(&kit, "nobody@example.com").await,
        "invite-only: nothing is made"
    );
    assert_eq!(kit.outbox.count(), 1, "only the known address is mailed");
}

#[pollster::test]
async fn a_known_and_an_unknown_address_answer_identically_when_registration_is_on() {
    let kit = kit(true);
    let client = register_client(&kit, builder_list()).await;
    seed_user(&kit, "ada@example.com").await;
    let known = request_link(&kit, "ada@example.com", Some(&return_to_for(&client, ""))).await;
    let unknown = request_link(&kit, "new@example.com", Some(&return_to_for(&client, ""))).await;
    assert_eq!(known.status, unknown.status);
    assert_eq!(known.body, unknown.body);
    assert_eq!(kit.outbox.count(), 2, "both get a link");
}

#[pollster::test]
async fn a_client_that_asks_nothing_keeps_the_account_made_at_request_time() {
    let kit = kit(true);
    let response = request_link(
        &kit,
        "ada@example.com",
        Some("/v1/auth-core/authorize?client_id=none"),
    )
    .await;
    assert_eq!(response.status, StatusCode::ACCEPTED);
    assert!(users_with(&kit, "ada@example.com").await);
}

#[pollster::test]
async fn a_spent_link_for_an_asking_client_is_refused_as_expired() {
    let kit = kit(true);
    let client = register_client(&kit, builder_list()).await;
    request_link(&kit, "ada@example.com", Some(&return_to_for(&client, ""))).await;
    let token = kit.outbox.last_token().expect("a token");
    let first = confirm(&kit, &format!("token={token}&intents_step=1&intents=buyer")).await;
    assert_eq!(first.status, StatusCode::FOUND);
    let second = confirm(&kit, &format!("token={token}&intents_step=1&intents=buyer")).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert!(
        second.body.contains("expired") || second.body.contains("already used"),
        "{}",
        second.body
    );
    let count = pollster::block_on(kit.db.query(&Statement::new(
        "SELECT COUNT(*) AS n FROM users".to_owned(),
    )))
    .expect("query");
    assert_eq!(count.first().and_then(|row| row.get::<i64>("n")), Some(1));
}

// --- hardening: existing sign-ins keep answers, one account per address,
// --- expired and withdrawn links answer as expired.

#[pollster::test]
async fn a_sign_in_by_link_keeps_the_intents_the_person_already_chose() {
    let kit = kit(true);
    let client = register_client(&kit, builder_list()).await;
    seed_user(&kit, "ada@example.com").await;
    let user = user_by_primary_email(&*kit.db, "ada@example.com")
        .await
        .expect("query")
        .expect("user");
    cratefield_auth_core::intents::record(
        &*kit.db,
        &*kit.clock,
        &user.id,
        &client,
        &["builder".to_owned()],
    )
    .await
    .expect("record");

    // An ordinary sign-in for the same application: no answer in the link.
    request_link(&kit, "ada@example.com", Some(&return_to_for(&client, ""))).await;
    let token = kit.outbox.last_token().expect("a token");
    let done = confirm(&kit, &format!("token={token}")).await;
    assert_eq!(done.status, StatusCode::FOUND, "{}", done.body);
    assert_eq!(
        cratefield_auth_core::intents::chosen(&*kit.db, &user.id, &client)
            .await
            .expect("query"),
        Some(vec!["builder".to_owned()]),
        "a sign-in must not wipe the saved answer"
    );
}

#[pollster::test]
async fn two_links_for_one_address_make_one_account_and_the_second_is_dead() {
    let kit = kit(true);
    let client = register_client(&kit, builder_list()).await;
    request_link(&kit, "ada@example.com", Some(&return_to_for(&client, ""))).await;
    let first = kit.outbox.token_at(0).expect("first token");
    advance(&kit, 61);
    request_link(&kit, "ada@example.com", Some(&return_to_for(&client, ""))).await;
    let second = kit.outbox.token_at(1).expect("second token");
    assert_ne!(first, second);

    let made = confirm(
        &kit,
        &format!("token={first}&intents_step=1&intents=builder"),
    )
    .await;
    assert_eq!(made.status, StatusCode::FOUND, "{}", made.body);
    let user = user_by_primary_email(&*kit.db, "ada@example.com")
        .await
        .expect("query")
        .expect("the account exists");
    assert_eq!(
        user.locale.as_deref(),
        Some("en"),
        "the mail's locale carries to the account"
    );

    let other = confirm(
        &kit,
        &format!("token={second}&intents_step=1&intents=buyer"),
    )
    .await;
    assert_eq!(other.status, StatusCode::BAD_REQUEST, "{}", other.body);
    assert!(session_cookie(&other).is_none());
    let count = pollster::block_on(kit.db.query(&Statement::new(
        "SELECT COUNT(*) AS n FROM users WHERE primary_email = 'ada@example.com'".to_owned(),
    )))
    .expect("query");
    assert_eq!(count.first().and_then(|row| row.get::<i64>("n")), Some(1));
}

#[pollster::test]
async fn an_expired_link_for_an_asking_client_says_expired_and_asks_nothing() {
    let kit = kit(true);
    let client = register_client(&kit, builder_list()).await;
    request_link(&kit, "ada@example.com", Some(&return_to_for(&client, ""))).await;
    let token = kit.outbox.last_token().expect("a token");
    advance(&kit, 3_600);
    let response = confirm(&kit, &format!("token={token}")).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    assert!(
        !response.body.contains("name=\"intents\""),
        "{}",
        response.body
    );
    assert!(!users_with(&kit, "ada@example.com").await);
}

#[pollster::test]
async fn a_link_for_a_new_account_is_refused_once_registration_is_switched_off() {
    let kit = kit(false);
    let client = register_client(&kit, builder_list()).await;
    let now = 1_788_775_200;
    let token = "a".repeat(43);
    pending_link(&kit, &token, "ada@example.com", &client, now + 900).await;
    let response = confirm(
        &kit,
        &format!("token={token}&intents_step=1&intents=builder"),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    assert!(session_cookie(&response).is_none());
    assert!(!users_with(&kit, "ada@example.com").await);
}
