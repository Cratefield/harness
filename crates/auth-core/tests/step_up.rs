//! Issue #912 acceptance: step-up re-authentication, `auth_time`, `amr`,
//! the `roles` claim and what discovery advertises.
//!
//! The properties a relying party relies on before it lets a person
//! approve something:
//!
//! - `prompt=login` and `max_age=0` are met only by a passkey or email
//!   ceremony that the request's own transaction began: a session from
//!   before the demand never satisfies it, nor an unrelated later login,
//!   nor a federated sign-in, and a transaction is single-use and bound to
//!   its account and client;
//! - a request that makes no demand (`max_age=N`, `prompt=none`) leaves
//!   nothing behind that a later login could spend;
//! - `auth_time` is the last real authentication, and a refresh never moves
//!   it; `azp` and `sid` name the client and the session;
//! - `roles` reaches only the clients registered for it, and only what the
//!   server recorded for the account; a change of role is audited;
//! - discovery advertises what is supported.

use axum::http::{Method, StatusCode, header};
use base64ct::{Base64UrlUnpadded, Encoding};
use cratefield_auth_core::{AuthCore, Login, Redacted, UserRow, insert_user, issue};
use cratefield_core::{MapConfig, Rows, Statement, UlidIdGen};
use cratefield_testing::{ManualClock, TestHarness};
use p256::ecdsa;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const EPOCH: i64 = 1_800_000_000;
const ISSUER: &str = "https://auth.test.example";
const REDIRECT: &str = "https://undercoverrockstars.com/auth/callback";
const VERIFIER: &str = "a-verifier-of-at-least-43-characters-1234567890";
const ADMIN: &str = "test-admin-token-0123456789abcdef";
const BASE: &str = "/v1/auth-core";

fn iso(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .expect("epoch in range")
        .replace_nanosecond(0)
        .expect("in range")
        .format(&Rfc3339)
        .expect("rfc3339")
}

/// A throwaway P-256 key, generated in the test.
fn dummy_key(kid: &str) -> Value {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("entropy");
    bytes[0] = 1;
    let secret = p256::SecretKey::from_slice(&bytes).expect("scalar");
    let _ = ecdsa::SigningKey::from(&secret);
    let d = Base64UrlUnpadded::encode_string(&secret.to_bytes());
    json!({ "kty": "EC", "crv": "P-256", "kid": kid, "d": d })
}

/// The router, with signing keys, an issuer and an admin token, and a clock
/// the test moves by hand. The clock starts ten minutes before [`EPOCH`], so
/// a session can be created "ten minutes ago" and then the test moves on.
fn kit() -> (TestHarness, ManualClock) {
    let clock =
        ManualClock::new(OffsetDateTime::from_unix_timestamp(EPOCH - 600).expect("epoch in range"));
    let config = MapConfig::from_pairs([
        (
            "AUTH_CORE_SIGNING_KEYS",
            serde_json::to_string(&vec![dummy_key("k1")]).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE", "k1".to_owned()),
        ("AUTH_CORE_ISSUER", ISSUER.to_owned()),
        ("ADMIN_TOKEN", ADMIN.to_owned()),
        // The chooser carries its return path on its buttons, so there must be
        // buttons for the transaction to be seen on.
        ("AUTH_CORE_LOGIN_METHODS", "google,magic-link".to_owned()),
    ]);
    let router_clock = clock.clone();
    let kit = TestHarness::with_ports(vec![Box::new(AuthCore::new())], move |ports| {
        ports.config = Arc::new(config);
        ports.clock = Some(Arc::new(router_clock));
    });
    (kit, clock)
}

fn now_secs(clock: &ManualClock) -> i64 {
    use cratefield_core::Clock as _;
    clock.now().unix_timestamp()
}

fn challenge() -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()))
}

async fn send(
    kit: &TestHarness,
    request: axum::http::request::Builder,
    body: axum::body::Body,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = kit
        .router
        .clone()
        .oneshot(request.body(body).expect("request builds"))
        .await
        .expect("router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    (status, headers, String::from_utf8_lossy(&bytes).to_string())
}

/// `/authorize` with an optional extra query string and session cookie.
async fn authorize(
    kit: &TestHarness,
    client: &str,
    extra: &str,
    cookie: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let uri = format!(
        "{BASE}/authorize?response_type=code&client_id={client}&redirect_uri={REDIRECT}\
         &code_challenge={}&code_challenge_method=S256&state=xyz{extra}",
        challenge()
    );
    let mut request = axum::http::Request::builder().method(Method::GET).uri(uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, format!("__Host-session={cookie}"));
    }
    send(kit, request, axum::body::Body::empty()).await
}

fn location(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::LOCATION)
        .expect("Location")
        .to_str()
        .expect("ascii")
        .to_owned()
}

fn is_code(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(header::LOCATION)
        .is_some_and(|value| value.to_str().is_ok_and(|v| v.contains("code=")))
}

/// The `code` a redirect to the registered URI carries.
fn code_in(location: &str) -> String {
    let query = location.split_once('?').expect("query").1;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("code="))
        .expect("a code")
        .to_owned()
}

/// The step-up transaction value a login chooser carries, if it carries one.
/// The value is base64url, so it ends at the first character that is not.
fn transaction_in(page: &str) -> Option<String> {
    let at = page.find("step_up")?;
    let rest = &page[at + "step_up".len()..];
    let rest = rest
        .strip_prefix('=')
        .or_else(|| rest.strip_prefix("%3D"))
        .or_else(|| rest.strip_prefix("%3d"))?;
    let value: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    (!value.is_empty()).then_some(value)
}

async fn seed_user(kit: &TestHarness, id: &str) {
    insert_user(
        &*kit.db,
        &UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: Some(format!("{id}@example.com")),
            primary_email_verified: true,
            locale: None,
            status: "active".to_owned(),
            created_at: iso(EPOCH - 10_000),
            updated_at: iso(EPOCH - 10_000),
        },
    )
    .await
    .expect("user");
}

/// A session created at the clock's current moment, carrying the methods.
async fn session_now(
    kit: &TestHarness,
    clock: &ManualClock,
    user_id: &str,
    amr: &[&str],
) -> String {
    issue(
        &*kit.db,
        clock,
        &UlidIdGen,
        Login {
            user_id,
            ip: None,
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr,
        },
    )
    .await
    .expect("session")
    .value
}

/// A session created `ago` seconds before the clock's current moment.
async fn session_ago(
    kit: &TestHarness,
    clock: &ManualClock,
    user_id: &str,
    ago: i64,
    amr: &[&str],
) -> String {
    let now = now_secs(clock);
    let past = ManualClock::new(OffsetDateTime::from_unix_timestamp(now - ago).expect("epoch"));
    issue(
        &*kit.db,
        &past,
        &UlidIdGen,
        Login {
            user_id,
            ip: None,
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr,
        },
    )
    .await
    .expect("session")
    .value
}

async fn admin(
    kit: &TestHarness,
    method: Method,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, String) {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(format!("{BASE}{path}"));
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(json) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(json.to_string())
        }
        None => axum::body::Body::empty(),
    };
    let (status, _, text) = send(kit, request, body).await;
    (status, text)
}

/// A public client registered with the given `roles_claim`, through the
/// admin API, the way an operator would register it.
async fn client(kit: &TestHarness, roles_claim: bool) -> String {
    let (status, text) = admin(
        kit,
        Method::POST,
        "/admin/clients",
        Some(json!({
            "name": "Undercover Rockstars",
            "kind": "public",
            "redirect_uris": [REDIRECT],
            "roles_claim": roles_claim,
        })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{text}");
    serde_json::from_str::<Value>(&text).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

async fn exchange_code(kit: &TestHarness, client: &str, code: &str) -> Value {
    let body = format!(
        "grant_type=authorization_code&client_id={client}&code={code}\
         &redirect_uri={REDIRECT}&code_verifier={VERIFIER}"
    );
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("{BASE}/token"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    let (status, _, text) = send(kit, request, axum::body::Body::from(body)).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    serde_json::from_str(&text).expect("json")
}

async fn refresh(kit: &TestHarness, client: &str, refresh_token: &str) -> Value {
    let body = format!("grant_type=refresh_token&client_id={client}&refresh_token={refresh_token}");
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("{BASE}/token"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    let (status, _, text) = send(kit, request, axum::body::Body::from(body)).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    serde_json::from_str(&text).expect("json")
}

/// The claims of a compact JWT, unverified: signature checks belong to
/// `tokens.rs`; here the question is what the token says.
fn claims_of(token: &str) -> Value {
    let part = token.split('.').nth(1).expect("claims");
    serde_json::from_slice(&Base64UrlUnpadded::decode_vec(part).expect("b64url")).expect("json")
}

/// The whole code flow for a session the browser holds, with `openid` asked
/// for, as an OpenID Connect client asks for it.
async fn openid_flow(kit: &TestHarness, client: &str, cookie: &str, extra: &str) -> Value {
    let (status, headers, _) =
        authorize(kit, client, &format!("&scope=openid{extra}"), Some(cookie)).await;
    assert_eq!(status, StatusCode::FOUND, "expected a code, got {status}");
    exchange_code(kit, client, &code_in(&location(&headers))).await
}

async fn transactions(kit: &TestHarness) -> usize {
    let rows: Rows = kit
        .db
        .query(&Statement::new(
            "SELECT id FROM step_up_transactions".to_owned(),
        ))
        .await
        .expect("count");
    rows.len()
}

/// A demand made by `prompt=login` on a live session, returning the
/// transaction the chooser carries.
async fn demand(kit: &TestHarness, client: &str, cookie: &str) -> String {
    let (status, headers, body) = authorize(kit, client, "&prompt=login", Some(cookie)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the chooser, not a redirect: {headers:?}"
    );
    assert!(headers.get(header::LOCATION).is_none());
    transaction_in(&body).expect("the chooser carries a transaction")
}

// ------------------------------------------------------------ prompt=login

#[pollster::test]
async fn prompt_login_with_a_live_session_renders_the_chooser_and_a_transaction() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;

    let (status, headers, body) = authorize(&kit, &client, "&prompt=login", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(headers.get(header::LOCATION).is_none());
    assert!(
        transaction_in(&body).is_some(),
        "the chooser carries the transaction"
    );
    assert_eq!(transactions(&kit).await, 1);
}

#[pollster::test]
async fn prompt_login_is_met_only_by_a_ceremony_its_transaction_began() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;

    let tx = demand(&kit, &client, &old).await;

    // The session the demand was made on does not satisfy it.
    let (status, headers, _) = authorize(
        &kit,
        &client,
        &format!("&prompt=login&step_up={tx}"),
        Some(&old),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{headers:?}");

    // The ceremony the transaction began: a passkey, after the demand.
    clock_advance(&clock, 5);
    let fresh = session_now(&kit, &clock, "u1", &["passkey", "user", "mfa"]).await;
    let (status, headers, _) = authorize(
        &kit,
        &client,
        &format!("&prompt=login&step_up={tx}"),
        Some(&fresh),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).starts_with(REDIRECT));

    // Single use: the same transaction does not satisfy a second request.
    let (status, _, _) = authorize(
        &kit,
        &client,
        &format!("&prompt=login&step_up={tx}"),
        Some(&fresh),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a spent transaction satisfies nothing"
    );
}

fn clock_advance(clock: &ManualClock, secs: u64) {
    clock.advance(std::time::Duration::from_secs(secs));
}

#[pollster::test]
async fn a_transaction_is_bound_to_its_client_and_its_account() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    seed_user(&kit, "u2").await;
    let first = client(&kit, false).await;
    let second = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;
    let tx = demand(&kit, &first, &old).await;

    clock_advance(&clock, 5);
    let fresh = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    let other_client = authorize(
        &kit,
        &second,
        &format!("&prompt=login&step_up={tx}"),
        Some(&fresh),
    )
    .await;
    assert_eq!(
        other_client.0,
        StatusCode::OK,
        "another client's transaction"
    );

    let other_account = session_now(&kit, &clock, "u2", &["passkey", "user"]).await;
    let (status, _, _) = authorize(
        &kit,
        &first,
        &format!("&prompt=login&step_up={tx}"),
        Some(&other_account),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "another account's session");
}

#[pollster::test]
async fn a_transaction_expires_after_ten_minutes() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;
    let tx = demand(&kit, &client, &old).await;

    clock_advance(&clock, 601);
    let fresh = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    let (status, _, _) = authorize(
        &kit,
        &client,
        &format!("&prompt=login&step_up={tx}"),
        Some(&fresh),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "an expired transaction");
}

#[pollster::test]
async fn the_ceremony_must_be_recent_when_the_transaction_is_spent() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;
    let tx = demand(&kit, &client, &old).await;

    clock_advance(&clock, 1);
    let fresh = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    clock_advance(&clock, 200);
    let (status, _, _) = authorize(
        &kit,
        &client,
        &format!("&prompt=login&step_up={tx}"),
        Some(&fresh),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a session older than 120s");
}

#[pollster::test]
async fn federated_and_password_sign_ins_do_not_satisfy_a_step_up() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;
    let tx = demand(&kit, &client, &old).await;

    clock_advance(&clock, 1);
    for amr in [["federated"], ["sso"], ["pwd"]] {
        let fresh = session_now(&kit, &clock, "u1", &amr).await;
        let (status, _, _) = authorize(
            &kit,
            &client,
            &format!("&prompt=login&step_up={tx}"),
            Some(&fresh),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{amr:?} must not satisfy a step-up");
    }

    // An email link is a ceremony the transaction accepts.
    let emailed = session_now(&kit, &clock, "u1", &["email"]).await;
    let (status, _, _) = authorize(
        &kit,
        &client,
        &format!("&prompt=login&step_up={tx}"),
        Some(&emailed),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "an email ceremony satisfies it");
}

#[pollster::test]
async fn an_unrelated_later_login_cannot_satisfy_a_demand_it_did_not_begin() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;
    // A demand is made and abandoned.
    let _abandoned = demand(&kit, &client, &old).await;

    clock_advance(&clock, 5);
    let later = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    // Without the transaction, the later login is not a step-up.
    let (status, _, _) = authorize(&kit, &client, "&prompt=login", Some(&later)).await;
    assert_eq!(status, StatusCode::OK, "a login without the transaction");
}

/// The browser's step-up cookie value a chooser sets, if it sets one.
fn browser_cookie_in(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            value
                .strip_prefix("__Host-step-up=")
                .map(|rest| rest.split(';').next().unwrap_or_default().to_owned())
        })
}

/// A demand made before anyone is signed in: the chooser carries it, bound to
/// the browser by a cookie. Returns the transaction and the cookie.
async fn unbound_demand(kit: &TestHarness, client: &str, extra: &str) -> (String, String) {
    let (status, headers, body) =
        authorize(kit, client, &format!("&prompt=login{extra}"), None).await;
    assert_eq!(status, StatusCode::OK, "{headers:?}");
    let cookie = browser_cookie_in(&headers).expect("the chooser binds the browser");
    (transaction_in(&body).expect("a transaction"), cookie)
}

#[pollster::test]
async fn prompt_login_without_a_session_makes_an_unbound_demand_for_this_browser() {
    let (kit, _clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let (_tx, cookie) = unbound_demand(&kit, &client, "").await;
    assert!(!cookie.is_empty());
    assert_eq!(transactions(&kit).await, 1);
}

/// Probe D (issue #912, second review): with no session, `prompt=login` was
/// dropped on the way to the login, and a federated sign-in then minted a code.
#[pollster::test]
async fn probe_d_no_session_prompt_login_is_not_met_by_a_federated_sign_in() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let (tx, cookie) = unbound_demand(&kit, &client, "&scope=openid").await;

    clock_advance(&clock, 1);
    let federated = session_now(&kit, &clock, "u1", &["federated"]).await;
    // The browser that asked is the one returning, with its cookie: binding
    // is not what refuses the federated sign-in, its method is.
    let uri = format!(
        "{BASE}/authorize?response_type=code&client_id={client}&redirect_uri={REDIRECT}\
         &code_challenge={}&code_challenge_method=S256&state=xyz\
         &prompt=login&scope=openid&step_up={tx}",
        challenge()
    );
    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(
            header::COOKIE,
            format!("__Host-session={federated}; __Host-step-up={cookie}"),
        );
    let (status, headers, _) = send(&kit, request, axum::body::Body::empty()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "BYPASS: a federated sign-in met prompt=login: {headers:?}"
    );
    assert!(!is_code(&headers));
}

/// The same return path with a passkey ceremony, begun after the demand and
/// carrying the browser's cookie, is met, and the session earns `acr`.
#[pollster::test]
async fn an_unbound_demand_is_met_by_a_passkey_ceremony_from_the_same_browser() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let (tx, cookie) = unbound_demand(&kit, &client, "&scope=openid").await;

    clock_advance(&clock, 1);
    let passkey = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    let uri = format!("&prompt=login&scope=openid&step_up={tx}");
    // Without the browser's cookie the demand is not answered.
    let (status, _, _) = authorize(&kit, &client, &uri, Some(&passkey)).await;
    assert_eq!(status, StatusCode::OK, "another browser cannot answer it");

    let mut request = axum::http::Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{BASE}/authorize?response_type=code&client_id={client}&redirect_uri={REDIRECT}\
             &code_challenge={}&code_challenge_method=S256&state=xyz{uri}",
            challenge()
        ))
        .header(
            header::COOKIE,
            format!("__Host-session={passkey}; __Host-step-up={cookie}"),
        );
    request = request.header(header::ACCEPT, "*/*");
    let (status, headers, _) = send(&kit, request, axum::body::Body::empty()).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "the browser that asked is answered"
    );
    let tokens = exchange_code(&kit, &client, &code_in(&location(&headers))).await;
    assert_eq!(
        claims_of(tokens["access_token"].as_str().expect("at"))["acr"],
        "urn:cratefield:stepup"
    );
    assert_eq!(
        claims_of(tokens["id_token"].as_str().expect("id"))["acr"],
        "urn:cratefield:stepup"
    );
}

/// Probe E (issue #912, second review): `max_age=N` is an age check and
/// implies no method. It is documented here, so the claim is not mistaken for
/// step-up: a federated sign-in ends a `max_age` window.
#[pollster::test]
async fn max_age_is_only_an_age_and_a_federated_sign_in_meets_it() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 3600, &["passkey", "user"]).await;
    let (_, headers, _) = authorize(&kit, &client, "&max_age=60", Some(&old)).await;
    assert!(!is_code(&headers));
    clock_advance(&clock, 1);
    let federated = session_now(&kit, &clock, "u1", &["federated"]).await;
    let (_, headers, _) = authorize(&kit, &client, "&max_age=60", Some(&federated)).await;
    assert!(
        is_code(&headers),
        "max_age is age-only; step-up callers use prompt=login"
    );
}

/// Probe F (issue #912, second review): transaction abuse, one property each.
#[pollster::test]
async fn probe_f_transaction_abuse_is_refused_and_the_ceremony_rule_is_precise() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    seed_user(&kit, "u2").await;
    let a = client(&kit, false).await;
    let b = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 3600, &["passkey", "user"]).await;
    let v1 = demand(&kit, &a, &old).await;
    let v2 = demand(&kit, &a, &old).await;
    let vb = demand(&kit, &b, &old).await;

    // The session that was there before the demand, presenting its own.
    let (status, headers, _) =
        authorize(&kit, &a, &format!("&prompt=login&step_up={v1}"), Some(&old)).await;
    assert_eq!(status, StatusCode::OK, "{headers:?}");

    // A ceremony in the very same second, a millisecond after the demand, counts.
    clock_advance_ms(&clock, 1);
    let same_second = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    let (_, headers, _) = authorize(
        &kit,
        &a,
        &format!("&prompt=login&step_up={v1}"),
        Some(&same_second),
    )
    .await;
    assert!(
        is_code(&headers),
        "a ceremony one millisecond after the demand is met"
    );

    // Replay of the spent transaction is refused.
    let (_, headers, _) = authorize(
        &kit,
        &a,
        &format!("&prompt=login&step_up={v1}"),
        Some(&same_second),
    )
    .await;
    assert!(!is_code(&headers), "replay");

    // Client binding: a's transaction is not b's, and b's is bound to b.
    let (_, headers, _) = authorize(
        &kit,
        &b,
        &format!("&prompt=login&step_up={v2}"),
        Some(&same_second),
    )
    .await;
    assert!(!is_code(&headers), "a's transaction at b");

    // One ceremony satisfies every open transaction of its account, one at a
    // time: the second of a's transactions, and b's, are met by the same
    // ceremony that met v1 (documented in the README).
    let (_, headers, _) = authorize(
        &kit,
        &a,
        &format!("&prompt=login&step_up={v2}"),
        Some(&same_second),
    )
    .await;
    assert!(
        is_code(&headers),
        "a second open transaction of the account"
    );
    let (_, headers, _) = authorize(
        &kit,
        &b,
        &format!("&prompt=login&step_up={vb}"),
        Some(&same_second),
    )
    .await;
    assert!(
        is_code(&headers),
        "b's transaction, same account, same ceremony"
    );

    // Another account's session does not answer a's demand.
    let v3 = demand(&kit, &a, &old).await;
    clock_advance(&clock, 2);
    let u2 = session_now(&kit, &clock, "u2", &["passkey", "user"]).await;
    let (_, headers, _) =
        authorize(&kit, &a, &format!("&prompt=login&step_up={v3}"), Some(&u2)).await;
    assert!(!is_code(&headers), "cross-account");

    // A ceremony older than two minutes does not spend it.
    let v4 = demand(&kit, &a, &old).await;
    clock_advance(&clock, 1);
    let stale = session_now(&kit, &clock, "u1", &["email"]).await;
    clock_advance(&clock, 121);
    let (_, headers, _) =
        authorize(&kit, &a, &format!("&max_age=0&step_up={v4}"), Some(&stale)).await;
    assert!(!is_code(&headers), "a 121-second-old ceremony");

    // prompt=none: a transaction met by a fresh ceremony answers with a code,
    // and with the session the demand was made on it is a refusal, not a page.
    let v5 = demand(&kit, &a, &old).await;
    let (_, headers, _) = authorize(
        &kit,
        &a,
        &format!("&prompt=none&max_age=0&step_up={v5}"),
        Some(&old),
    )
    .await;
    assert!(location(&headers).contains("error=login_required"));
    clock_advance(&clock, 1);
    let email = session_now(&kit, &clock, "u1", &["email"]).await;
    let (_, headers, _) = authorize(
        &kit,
        &a,
        &format!("&prompt=none&max_age=0&step_up={v5}"),
        Some(&email),
    )
    .await;
    assert!(
        is_code(&headers),
        "no interaction is needed once the ceremony is met"
    );

    // A step_up value the client injects is never carried into the chooser.
    let (_, _, body) = authorize(&kit, &a, "&prompt=login&step_up=INJECTED", None).await;
    assert!(
        !body.contains("INJECTED"),
        "an injected transaction is dropped"
    );
    let (_, _, body) = authorize(&kit, &a, "&prompt=login&step_up=INJECTED", Some(&old)).await;
    assert!(
        !body.contains("INJECTED"),
        "an injected transaction is dropped"
    );
}

fn clock_advance_ms(clock: &ManualClock, ms: u64) {
    clock.advance(std::time::Duration::from_millis(ms));
}

// ---------------------------------------------------- regressions: no bypass

/// Probe A (issue #912 review): an ordinary `max_age=N` step-up must not
/// leave a demand that a later session can satisfy `prompt=login` with.
#[pollster::test]
async fn max_age_plants_no_demand_that_later_bypasses_prompt_login() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 1000, &["passkey", "user"]).await;

    let (status, _, body) = authorize(&kit, &client, "&max_age=60", Some(&old)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        transaction_in(&body).is_none(),
        "max_age>0 records no demand"
    );
    assert_eq!(transactions(&kit).await, 0);

    // The person signs in again, and the max_age request completes.
    clock_advance(&clock, 1);
    let fresh = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    let (status, headers, _) = authorize(&kit, &client, "&max_age=60", Some(&fresh)).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(is_code(&headers));

    // A later prompt=login must still ask for a ceremony.
    let (status, headers, body) = authorize(&kit, &client, "&prompt=login", Some(&fresh)).await;
    assert_eq!(status, StatusCode::OK, "BYPASS: prompt=login minted a code");
    assert!(!is_code(&headers));
    assert!(transaction_in(&body).is_some());
}

/// Probe B (issue #912 review): a silent `prompt=none&max_age=0` must not
/// record a demand that any later login satisfies `prompt=login` with.
#[pollster::test]
async fn prompt_none_plants_no_demand_that_a_later_session_can_spend() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 1000, &["passkey", "user"]).await;

    let (status, headers, _) = authorize(&kit, &client, "&prompt=none&max_age=0", Some(&old)).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).contains("error=login_required"));
    assert_eq!(transactions(&kit).await, 0, "prompt=none records nothing");

    clock_advance(&clock, 5);
    let later = session_now(&kit, &clock, "u1", &["email"]).await;
    let (status, headers, _) = authorize(&kit, &client, "&prompt=login", Some(&later)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "BYPASS: prompt=login satisfied by an unrelated login"
    );
    assert!(!is_code(&headers));
}

// ------------------------------------------------------------- max_age

#[pollster::test]
async fn max_age_zero_always_demands_a_transaction() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;

    let (status, headers, body) = authorize(&kit, &client, "&max_age=0", Some(&cookie)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "max_age=0 mints no code on the old session"
    );
    assert!(headers.get(header::LOCATION).is_none());
    let tx = transaction_in(&body).expect("a transaction");

    clock_advance(&clock, 1);
    let fresh = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    let (status, _, _) = authorize(
        &kit,
        &client,
        &format!("&max_age=0&step_up={tx}"),
        Some(&fresh),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
}

#[pollster::test]
async fn max_age_is_an_age_check_against_the_last_authentication() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;

    let (status, _, _) = authorize(&kit, &client, "&max_age=60", Some(&cookie)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a 600s-old login is older than max_age=60"
    );

    let (status, _, _) = authorize(&kit, &client, "&max_age=900", Some(&cookie)).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "a 600s-old login is within max_age=900"
    );
}

#[pollster::test]
async fn malformed_step_up_parameters_are_refused_as_oauth_errors() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    let too_long_nonce = "n".repeat(600);

    for extra in [
        "&max_age=-1".to_owned(),
        "&max_age=abc".to_owned(),
        "&max_age=1.5".to_owned(),
        "&prompt=bogus".to_owned(),
        "&prompt=none+login".to_owned(),
        format!("&nonce={too_long_nonce}"),
    ] {
        let (status, headers, body) = authorize(&kit, &client, &extra, Some(&cookie)).await;
        assert_eq!(status, StatusCode::FOUND, "{extra}: {body}");
        let location = location(&headers);
        assert!(location.starts_with(REDIRECT), "{extra}: {location}");
        assert!(
            location.contains("error=invalid_request"),
            "{extra}: {location}"
        );
        assert!(!location.contains("code="), "{extra}: {location}");
    }
}

#[pollster::test]
async fn prompt_none_without_a_session_answers_login_required() {
    let (kit, _clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;

    let (status, headers, _) = authorize(&kit, &client, "&prompt=none", None).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).contains("error=login_required"));
}

// ------------------------------------------------------- SSO and step-up

#[pollster::test]
async fn a_named_sso_connection_is_not_a_way_to_meet_a_step_up() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    cratefield_auth_core::insert_sso_connection(
        &*kit.db,
        &cratefield_auth_core::SsoConnectionRow {
            id: "conn1".to_owned(),
            client_id: client.clone(),
            org_ref: "acme".to_owned(),
            issuer: "https://idp.example".to_owned(),
            oidc_client_id: "idp-client".to_owned(),
            oidc_client_secret_sealed: Redacted("sealed".to_owned()),
            domains: vec!["acme.example".to_owned()],
            status: "active".to_owned(),
            created_at: iso(EPOCH - 10_000),
            updated_at: iso(EPOCH - 10_000),
        },
    )
    .await
    .expect("connection");
    let cookie = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;

    // Without a demand, the connection is what the request routes to.
    let (status, headers, _) = authorize(&kit, &client, "&connection=conn1", Some(&cookie)).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).starts_with("/v1/auth-oidc/sso/conn1/start"));

    // With a demand, the IdP is not sent to: the chooser is shown.
    let (status, headers, body) = authorize(
        &kit,
        &client,
        "&connection=conn1&prompt=login",
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{headers:?}");
    assert!(headers.get(header::LOCATION).is_none());
    assert!(transaction_in(&body).is_some());
}

// ------------------------------------------------------- claims in the tokens

#[pollster::test]
async fn the_id_token_carries_auth_time_amr_azp_sid_and_the_nonce() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_ago(&kit, &clock, "u1", 600, &["passkey", "user", "mfa"]).await;

    let tokens = openid_flow(&kit, &client, &cookie, "&nonce=n-0S6_WzA2Mj").await;
    let id = claims_of(tokens["id_token"].as_str().expect("an id_token"));
    assert_eq!(id["aud"], client);
    assert_eq!(id["azp"], client);
    assert_eq!(id["sub"], "u1");
    assert_eq!(id["iss"], ISSUER);
    assert_eq!(id["auth_time"], now_secs(&clock) - 600);
    assert_eq!(id["amr"], json!(["passkey", "user", "mfa"]));
    assert_eq!(id["nonce"], "n-0S6_WzA2Mj");
    assert!(
        id.get("roles").is_none(),
        "a client that did not ask gets no roles"
    );

    let access = claims_of(tokens["access_token"].as_str().expect("access"));
    assert_eq!(
        id["sid"], access["sid"],
        "the ID token names the same session"
    );
    assert_eq!(access["auth_time"], now_secs(&clock) - 600);
    assert_eq!(access["amr"], json!(["passkey", "user", "mfa"]));
    assert_eq!(access["email_verified"], true);
    assert_eq!(access["email"], "u1@example.com");
}

#[pollster::test]
async fn no_id_token_without_the_openid_scope() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;

    let (status, headers, _) = authorize(&kit, &client, "", Some(&cookie)).await;
    assert_eq!(status, StatusCode::FOUND);
    let tokens = exchange_code(&kit, &client, &code_in(&location(&headers))).await;
    assert!(
        tokens.get("id_token").is_none(),
        "no openid scope, no ID token"
    );
    assert!(tokens["access_token"].is_string());
}

#[pollster::test]
async fn a_refresh_never_moves_auth_time() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;

    let first = openid_flow(&kit, &client, &cookie, "").await;
    let expected = now_secs(&clock) - 600;
    assert_eq!(
        claims_of(first["access_token"].as_str().expect("at"))["auth_time"],
        expected
    );

    clock_advance(&clock, 300);
    let second = refresh(&kit, &client, first["refresh_token"].as_str().expect("rt")).await;
    let access = claims_of(second["access_token"].as_str().expect("at"));
    assert_eq!(access["auth_time"], expected, "a refresh is not a ceremony");
    assert!(
        second.get("id_token").is_none(),
        "a refresh answers no ID token"
    );
}

// ----------------------------------------------------------------- roles

#[pollster::test]
async fn roles_reach_only_the_owner_and_only_a_client_that_asked() {
    let (kit, clock) = kit();
    seed_user(&kit, "owner").await;
    seed_user(&kit, "member").await;
    let (status, text) = admin(
        &kit,
        Method::POST,
        "/admin/users/owner/role",
        Some(json!({ "role": "owner" })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");

    let asks = client(&kit, true).await;
    let silent = client(&kit, false).await;
    let owner_cookie = session_now(&kit, &clock, "owner", &["passkey", "user"]).await;
    let member_cookie = session_now(&kit, &clock, "member", &["passkey", "user"]).await;

    let owner_tokens = openid_flow(&kit, &asks, &owner_cookie, "").await;
    assert_eq!(
        claims_of(owner_tokens["access_token"].as_str().expect("at"))["roles"],
        json!(["owner"])
    );
    assert_eq!(
        claims_of(owner_tokens["id_token"].as_str().expect("id"))["roles"],
        json!(["owner"])
    );

    let member_tokens = openid_flow(&kit, &asks, &member_cookie, "").await;
    assert_eq!(
        claims_of(member_tokens["access_token"].as_str().expect("at"))["roles"],
        json!(["member"])
    );

    let silent_tokens = openid_flow(&kit, &silent, &owner_cookie, "").await;
    assert!(
        claims_of(silent_tokens["access_token"].as_str().expect("at"))
            .get("roles")
            .is_none()
    );
}

#[pollster::test]
async fn a_role_change_is_audited() {
    let (kit, _clock) = kit();
    seed_user(&kit, "u1").await;
    let (status, _) = admin(
        &kit,
        Method::POST,
        "/admin/users/u1/role",
        Some(json!({ "role": "admin" })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows: Rows = kit
        .db
        .query(&Statement::new(
            "SELECT role FROM user_role_audit WHERE user_id = 'u1'".to_owned(),
        ))
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 1, "the role change wrote its audit row");
}

#[pollster::test]
async fn the_role_endpoint_is_admin_only_and_validates_the_role() {
    let (kit, _clock) = kit();
    seed_user(&kit, "u1").await;
    let path = "/admin/users/u1/role";

    let (status, _) = admin(
        &kit,
        Method::POST,
        path,
        Some(json!({ "role": "owner" })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = admin(
        &kit,
        Method::POST,
        path,
        Some(json!({ "role": "superuser" })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = admin(
        &kit,
        Method::POST,
        "/admin/users/nobody/role",
        Some(json!({ "role": "owner" })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, text) = admin(
        &kit,
        Method::POST,
        path,
        Some(json!({ "role": "admin" })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&text).expect("json")["role"],
        "admin"
    );
}

#[pollster::test]
async fn a_client_cannot_claim_a_role_for_itself() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, true).await;
    let cookie = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;

    let (status, headers, _) =
        authorize(&kit, &client, "&roles=owner&role=owner", Some(&cookie)).await;
    assert_eq!(status, StatusCode::FOUND);
    let code = code_in(&location(&headers));
    let body = format!(
        "grant_type=authorization_code&client_id={client}&code={code}\
         &redirect_uri={REDIRECT}&code_verifier={VERIFIER}&roles=owner"
    );
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("{BASE}/token"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    let (status, _, text) = send(&kit, request, axum::body::Body::from(body)).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let tokens: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(
        claims_of(tokens["access_token"].as_str().expect("at"))["roles"],
        json!(["member"])
    );
}

#[pollster::test]
async fn the_roles_claim_is_registered_per_client_through_the_admin_api() {
    let (kit, _clock) = kit();
    let id = client(&kit, true).await;

    let (status, text) = admin(
        &kit,
        Method::PATCH,
        &format!("/admin/clients/{id}"),
        Some(json!({ "roles_claim": false })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text).expect("json")["roles_claim"],
        false
    );

    let (status, text) = admin(
        &kit,
        Method::PATCH,
        &format!("/admin/clients/{id}"),
        Some(json!({ "roles_claim": true })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text).expect("json")["roles_claim"],
        true
    );
}

// ------------------------------------------------------------------ discovery

#[pollster::test]
async fn discovery_advertises_prompt_values_and_the_claims_it_emits() {
    let (kit, _clock) = kit();
    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/.well-known/openid-configuration");
    let (status, _, text) = send(&kit, request, axum::body::Body::empty()).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let doc: Value = serde_json::from_str(&text).expect("json");

    assert_eq!(
        doc["prompt_values_supported"],
        json!(["none", "login", "consent", "select_account"])
    );
    let claims = doc["claims_supported"].as_array().expect("claims list");
    for claim in [
        "auth_time",
        "amr",
        "roles",
        "email_verified",
        "nonce",
        "azp",
        "sid",
    ] {
        assert!(
            claims.iter().any(|c| c == claim),
            "{claim} is not advertised"
        );
    }
}

/// Issue #912, second review: a passkey or address change in the last 24 hours
/// stops the account's passkey and email ceremonies from passing a step-up, so
/// a session that enrolled a credential cannot use it to pass one.
#[pollster::test]
async fn a_recent_passkey_change_stops_the_account_passing_a_step_up() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;
    let tx = demand(&kit, &client, &old).await;

    // The account's passkeys changed just now.
    cratefield_auth_core::record_security_change(&*kit.db, &clock, "u1")
        .await
        .expect("recorded");
    clock_advance(&clock, 1);
    let ceremony = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    let (_, headers, _) = authorize(
        &kit,
        &client,
        &format!("&prompt=login&step_up={tx}"),
        Some(&ceremony),
    )
    .await;
    assert!(
        !is_code(&headers),
        "a passkey that changed today does not step up"
    );

    // A day later the account is quiet again, and the same kind of ceremony does.
    let later_tx = {
        clock_advance(&clock, 24 * 60 * 60);
        demand(&kit, &client, &ceremony).await
    };
    clock_advance(&clock, 1);
    let quiet = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    let (_, headers, _) = authorize(
        &kit,
        &client,
        &format!("&prompt=login&step_up={later_tx}"),
        Some(&quiet),
    )
    .await;
    assert!(is_code(&headers), "a quiet day later the ceremony counts");
}

/// Issue #912, second review: an account holds at most twenty open demands,
/// and the oldest are dropped when a new one would exceed that.
#[pollster::test]
async fn open_transactions_are_capped_per_account() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;
    let first = demand(&kit, &client, &old).await;
    for _ in 0..24 {
        demand(&kit, &client, &old).await;
    }
    let rows: Rows = kit
        .db
        .query(&Statement::new(
            "SELECT id FROM step_up_transactions WHERE user_id = 'u1' AND consumed_at IS NULL"
                .to_owned(),
        ))
        .await
        .expect("count");
    assert_eq!(rows.len(), 20, "at most twenty open demands");
    // The oldest was dropped, so it no longer answers.
    clock_advance(&clock, 1);
    let ceremony = session_now(&kit, &clock, "u1", &["passkey", "user"]).await;
    let (_, headers, _) = authorize(
        &kit,
        &client,
        &format!("&prompt=login&step_up={first}"),
        Some(&ceremony),
    )
    .await;
    assert!(!is_code(&headers), "the dropped demand is gone");
}

/// Issue #912, second review: spent and expired transactions are purged when a
/// new demand is made.
#[pollster::test]
async fn spent_and_expired_transactions_are_purged_on_the_next_demand() {
    let (kit, clock) = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let old = session_ago(&kit, &clock, "u1", 600, &["passkey", "user"]).await;
    let _abandoned = demand(&kit, &client, &old).await;
    clock_advance(&clock, 601);
    let _next = demand(&kit, &client, &old).await;
    let rows: Rows = kit
        .db
        .query(&Statement::new(
            "SELECT id FROM step_up_transactions".to_owned(),
        ))
        .await
        .expect("count");
    assert_eq!(rows.len(), 1, "the expired demand was purged");
}
