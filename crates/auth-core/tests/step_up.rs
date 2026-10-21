//! Issue #912 acceptance: step-up re-authentication, `auth_time`, `amr`,
//! the `roles` claim and what discovery advertises.
//!
//! The properties asserted here are the ones a relying party relies on
//! before it lets a person approve something:
//!
//! - `prompt=login` forces a fresh ceremony even with a live session, and
//!   only a ceremony that completes after the demand satisfies it;
//! - `max_age` is honoured, `max_age=0` always, and a malformed value is
//!   refused rather than ignored;
//! - `auth_time` is the last real authentication and a refresh never moves
//!   it;
//! - `roles` reaches only the clients registered for it, and only what the
//!   server recorded for the account; nothing the client sends can set it;
//! - the PKCE and single-use rules of the code flow still hold (the
//!   existing `authorize` and `tokens` suites pin those in detail).

use axum::http::{Method, StatusCode, header};
use base64ct::{Base64UrlUnpadded, Encoding};
use cratefield_auth_core::{AuthCore, Login, UserRow, insert_user, issue};
use cratefield_core::{MapConfig, UlidIdGen};
use cratefield_testing::{FixedClock, TestHarness};
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

fn at(secs: i64) -> FixedClock {
    FixedClock(OffsetDateTime::from_unix_timestamp(secs).expect("epoch in range"))
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

/// The router, with signing keys, an issuer and an admin token. Its clock
/// is fixed at [`EPOCH`]: sessions are created at the moments a test
/// names, so "the last login was ten minutes ago" is a session created at
/// `EPOCH - 600`.
fn kit() -> TestHarness {
    let config = MapConfig::from_pairs([
        (
            "AUTH_CORE_SIGNING_KEYS",
            serde_json::to_string(&vec![dummy_key("k1")]).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE", "k1".to_owned()),
        ("AUTH_CORE_ISSUER", ISSUER.to_owned()),
        ("ADMIN_TOKEN", ADMIN.to_owned()),
    ]);
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = Arc::new(config);
    })
}

fn challenge() -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()))
}

async fn reply(response: axum::response::Response) -> (StatusCode, axum::http::HeaderMap, String) {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    (status, headers, String::from_utf8_lossy(&bytes).to_string())
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
    reply(response).await
}

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

/// The `code` a redirect to the registered URI carries.
fn code_in(location: &str) -> String {
    let query = location.split_once('?').expect("query").1;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("code="))
        .expect("a code")
        .to_owned()
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

/// A session created at `created_at`, carrying the given methods.
async fn session_at(kit: &TestHarness, user_id: &str, created_at: i64, amr: &[&str]) -> String {
    issue(
        &*kit.db,
        &at(created_at),
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

/// A admin call against the instance's own admin routes.
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

/// Exchanges a code for tokens at `/token`, as the public client does.
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

/// Runs the whole code flow for a session the browser already holds and
/// returns the token response.
async fn full_flow(kit: &TestHarness, client: &str, cookie: &str, extra: &str) -> Value {
    let (status, headers, _) = authorize(kit, client, extra, Some(cookie)).await;
    assert_eq!(status, StatusCode::FOUND, "expected a code, got {status}");
    let code = code_in(&location(&headers));
    exchange_code(kit, client, &code).await
}

// ---------------------------------------------------------------- prompt=login

#[pollster::test]
async fn prompt_login_with_a_live_session_runs_the_ceremony_and_mints_no_code() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let cookie = session_at(&kit, "u1", EPOCH, &["passkey", "user"]).await;
    let client = client(&kit, false).await;

    // The session is live and fresh, but the relying party asked for a
    // fresh ceremony: the chooser, not a code.
    let (status, headers, body) = authorize(&kit, &client, "&prompt=login", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(headers.get(header::LOCATION).is_none());
    assert!(!body.is_empty(), "the chooser page");
}

#[pollster::test]
async fn prompt_login_is_met_only_by_a_session_created_after_the_demand() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let old = session_at(&kit, "u1", EPOCH - 600, &["passkey", "user"]).await;
    let client = client(&kit, false).await;

    // The demand is made: the chooser.
    let (status, _, _) = authorize(&kit, &client, "&prompt=login", Some(&old)).await;
    assert_eq!(status, StatusCode::OK);

    // Coming back on the same session still does not satisfy it.
    let (status, _, _) = authorize(&kit, &client, "&prompt=login", Some(&old)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a session from before the demand must not satisfy it"
    );

    // The ceremony completes: a new session, created after the demand.
    let fresh = session_at(&kit, "u1", EPOCH + 60, &["passkey", "user", "mfa"]).await;
    let (status, headers, _) = authorize(&kit, &client, "&prompt=login", Some(&fresh)).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).starts_with(REDIRECT));

    // And the demand is spent: the next request on that session is an
    // ordinary one, with no further ceremony asked for.
    let (status, _, _) = authorize(&kit, &client, "", Some(&fresh)).await;
    assert_eq!(status, StatusCode::FOUND);
}

#[pollster::test]
async fn prompt_login_without_a_session_shows_the_chooser_without_the_demand() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;

    let (status, _, body) = authorize(&kit, &client, "&prompt=login", None).await;
    assert_eq!(status, StatusCode::OK);
    // The login the chooser starts is itself the ceremony, so the demand
    // is not carried back: a return to `/authorize` must not loop.
    assert!(
        !body.contains("prompt%3Dlogin") && !body.contains("prompt=login"),
        "{body}"
    );
}

// --------------------------------------------------------------------- max_age

#[pollster::test]
async fn max_age_zero_always_demands_a_ceremony() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_at(&kit, "u1", EPOCH, &["passkey", "user"]).await;

    let (status, headers, _) = authorize(&kit, &client, "&max_age=0", Some(&cookie)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "max_age=0 must not mint a code on the old session"
    );
    assert!(headers.get(header::LOCATION).is_none());

    let fresh = session_at(&kit, "u1", EPOCH + 1, &["passkey", "user"]).await;
    let (status, _, _) = authorize(&kit, &client, "&max_age=0", Some(&fresh)).await;
    assert_eq!(status, StatusCode::FOUND);
}

#[pollster::test]
async fn max_age_is_an_age_check_against_the_last_authentication() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    // Authenticated ten minutes ago.
    let cookie = session_at(&kit, "u1", EPOCH - 600, &["passkey", "user"]).await;

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
    let kit = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_at(&kit, "u1", EPOCH, &["passkey", "user"]).await;
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

// ------------------------------------------------------------------- prompt=none

#[pollster::test]
async fn prompt_none_without_a_session_answers_login_required_not_a_page() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;

    let (status, headers, _) = authorize(&kit, &client, "&prompt=none", None).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).contains("error=login_required"));
}

#[pollster::test]
async fn prompt_none_with_a_demand_answers_login_required() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_at(&kit, "u1", EPOCH, &["passkey", "user"]).await;

    let (status, headers, _) =
        authorize(&kit, &client, "&prompt=none+consent", Some(&cookie)).await;
    // `none` alongside another value is malformed, so it is invalid_request.
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).contains("error=invalid_request"));

    let (status, headers, _) =
        authorize(&kit, &client, "&prompt=none&max_age=0", Some(&cookie)).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location(&headers).contains("error=login_required"));
}

// ------------------------------------------------------- claims in the tokens

#[pollster::test]
async fn the_id_token_carries_auth_time_amr_and_the_echoed_nonce() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_at(&kit, "u1", EPOCH - 600, &["passkey", "user", "mfa"]).await;

    let tokens = full_flow(&kit, &client, &cookie, "&nonce=n-0S6_WzA2Mj").await;
    let id = claims_of(tokens["id_token"].as_str().expect("an id_token"));
    assert_eq!(id["aud"], client);
    assert_eq!(id["sub"], "u1");
    assert_eq!(id["iss"], ISSUER);
    assert_eq!(id["auth_time"], EPOCH - 600);
    assert_eq!(id["amr"], json!(["passkey", "user", "mfa"]));
    assert_eq!(id["nonce"], "n-0S6_WzA2Mj");
    assert!(
        id.get("roles").is_none(),
        "a client that did not ask gets no roles"
    );

    let access = claims_of(tokens["access_token"].as_str().expect("access"));
    assert_eq!(access["auth_time"], EPOCH - 600);
    assert_eq!(access["amr"], json!(["passkey", "user", "mfa"]));
    assert_eq!(access["email_verified"], true);
    assert_eq!(access["email"], "u1@example.com");
}

#[pollster::test]
async fn the_id_token_has_no_nonce_when_the_request_sent_none() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_at(&kit, "u1", EPOCH, &["passkey", "user"]).await;

    let tokens = full_flow(&kit, &client, &cookie, "").await;
    let id = claims_of(tokens["id_token"].as_str().expect("an id_token"));
    assert!(id.get("nonce").is_none());
}

#[pollster::test]
async fn a_refresh_never_moves_auth_time() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, false).await;
    let cookie = session_at(&kit, "u1", EPOCH - 600, &["passkey", "user"]).await;

    let first = full_flow(&kit, &client, &cookie, "").await;
    assert_eq!(
        claims_of(first["access_token"].as_str().expect("at"))["auth_time"],
        EPOCH - 600
    );

    let second = refresh(&kit, &client, first["refresh_token"].as_str().expect("rt")).await;
    let access = claims_of(second["access_token"].as_str().expect("at"));
    assert_eq!(
        access["auth_time"],
        EPOCH - 600,
        "a refresh is not a ceremony"
    );
    assert!(
        second.get("id_token").is_none(),
        "a refresh answers no ID token"
    );
}

// ----------------------------------------------------------------- roles

#[pollster::test]
async fn roles_reach_only_the_owner_and_only_a_client_that_asked() {
    let kit = kit();
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
    let owner_cookie = session_at(&kit, "owner", EPOCH, &["passkey", "user"]).await;
    let member_cookie = session_at(&kit, "member", EPOCH, &["passkey", "user"]).await;

    let owner_tokens = full_flow(&kit, &asks, &owner_cookie, "").await;
    let owner_access = claims_of(owner_tokens["access_token"].as_str().expect("at"));
    let owner_id = claims_of(owner_tokens["id_token"].as_str().expect("id"));
    assert_eq!(owner_access["roles"], json!(["owner"]));
    assert_eq!(owner_id["roles"], json!(["owner"]));

    let member_tokens = full_flow(&kit, &asks, &member_cookie, "").await;
    assert_eq!(
        claims_of(member_tokens["access_token"].as_str().expect("at"))["roles"],
        json!(["member"]),
        "the member is not the owner"
    );

    // The owner, through a client that did not ask: no roles claim at all.
    let silent_tokens = full_flow(&kit, &silent, &owner_cookie, "").await;
    assert!(
        claims_of(silent_tokens["access_token"].as_str().expect("at"))
            .get("roles")
            .is_none()
    );
}

#[pollster::test]
async fn the_role_endpoint_is_admin_only_and_validates_the_role() {
    let kit = kit();
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
    let kit = kit();
    seed_user(&kit, "u1").await;
    let client = client(&kit, true).await;
    let cookie = session_at(&kit, "u1", EPOCH, &["passkey", "user"]).await;

    // Anything the client sends about roles is ignored: the authorization
    // request has no such parameter, and the token request has none either.
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
    let kit = kit();
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
    let kit = kit();
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
    for claim in ["auth_time", "amr", "roles", "email_verified", "nonce"] {
        assert!(
            claims.iter().any(|c| c == claim),
            "{claim} is not advertised"
        );
    }
}
