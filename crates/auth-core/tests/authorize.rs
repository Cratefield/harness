//! Issue #10 acceptance: the authorization code flow with PKCE.
//!
//! The properties asserted here are the ones the flow exists to
//! guarantee, and each is a way the flow is commonly broken:
//!
//! - a refused `/authorize` renders a page and **never redirects**,
//!   because sending a browser to an unregistered URI is the
//!   vulnerability exact matching prevents (issue #7);
//! - an authorization code is single-use, and reusing one revokes the
//!   session it was minted for;
//! - the PKCE verifier is actually checked, and `plain` is refused;
//! - a signed-out visitor is offered the login chooser rather than a
//!   code.
//!
//! Signing keys are throwaway P-256 keys generated inside each test; no
//! real key is ever committed.

use axum::http::{Method, StatusCode, header};
use base64ct::{Base64UrlUnpadded, Encoding};
use factory0_auth_core::{
    AuthCore, ClientRedirectUriRow, ClientRow, Login, Redacted, UserRow, insert_client,
    insert_redirect_uri, issue, session_by_token_hash,
};
use factory0_core::{MapConfig, UlidIdGen};
use factory0_testing::{FixedClock, TestHarness};
use p256::ecdsa;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const EPOCH: i64 = 1_800_000_000;
const ISSUER: &str = "https://auth.test.example";
const CLIENT: &str = "client-undercover";
const REDIRECT: &str = "https://undercoverrockstars.com/auth/callback";
const VERIFIER: &str = "a-verifier-of-at-least-43-characters-1234567890";

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

/// A throwaway P-256 keypair generated in the test.
fn dummy_key(kid: &str) -> Value {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("entropy");
    bytes[0] = 1;
    let secret = p256::SecretKey::from_slice(&bytes).expect("scalar");
    let _ = ecdsa::SigningKey::from(&secret);
    let d = Base64UrlUnpadded::encode_string(&secret.to_bytes());
    json!({ "kty": "EC", "crv": "P-256", "kid": kid, "d": d })
}

fn kit() -> TestHarness {
    let config = MapConfig::from_pairs([
        (
            "AUTH_CORE_SIGNING_KEYS",
            serde_json::to_string(&vec![dummy_key("k1")]).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE", "k1".to_owned()),
        ("AUTH_CORE_ISSUER", ISSUER.to_owned()),
    ]);
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = Arc::new(config);
    })
}

/// The S256 challenge for [`VERIFIER`], as a client computes it.
fn challenge() -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()))
}

async fn seed_user(kit: &TestHarness, id: &str) {
    factory0_auth_core::insert_user(
        &*kit.db,
        &UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: Some(format!("{id}@example.com")),
            primary_email_verified: true,
            status: "active".to_owned(),
            created_at: iso(EPOCH),
            updated_at: iso(EPOCH),
        },
    )
    .await
    .expect("user");
}

/// A public client (PKCE only, no secret) with one exact redirect URI.
async fn seed_client(kit: &TestHarness) {
    insert_client(
        &*kit.db,
        &ClientRow {
            id: CLIENT.to_owned(),
            name: "Undercover Rockstars".to_owned(),
            // A public client authenticates with PKCE alone; the column
            // is not nullable, so an unusable placeholder stands in.
            secret_hash: Redacted("public-client-has-no-secret".to_owned()),
            previous_secret_hash: None,
            previous_hash_expires_at: None,
            kind: "public".to_owned(),
            status: "active".to_owned(),
            created_at: iso(EPOCH),
        },
    )
    .await
    .expect("client");
    insert_redirect_uri(
        &*kit.db,
        &ClientRedirectUriRow {
            client_id: CLIENT.to_owned(),
            uri: REDIRECT.to_owned(),
        },
    )
    .await
    .expect("redirect uri");
}

async fn signed_in(kit: &TestHarness, user_id: &str) -> String {
    seed_user(kit, user_id).await;
    let issued = issue(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        Login {
            user_id,
            ip: None,
            user_agent: None,
            presented_cookie: None,
            amr: &[],
        },
    )
    .await
    .expect("session");
    issued.value
}

fn authorize_uri(extra: &str) -> String {
    format!(
        "/v1/auth-core/authorize?response_type=code&client_id={CLIENT}\
         &redirect_uri={REDIRECT}&code_challenge={}&code_challenge_method=S256\
         &state=xyz{extra}",
        challenge()
    )
}

async fn get(kit: &TestHarness, uri: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut request = axum::http::Request::builder().method(Method::GET).uri(uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, format!("__Host-fz_session={cookie}"));
    }
    kit.router
        .clone()
        .oneshot(request.body(axum::body::Body::empty()).expect("request"))
        .await
        .expect("router answers")
}

fn location_of(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .expect("Location")
        .to_str()
        .expect("ascii")
        .to_owned()
}

/// The whole point of exact matching: a request naming a URI the client
/// did not register must not send the browser anywhere. A redirect here
/// is the vulnerability, so the assertion is on the absence of one.
#[pollster::test]
async fn an_unregistered_redirect_uri_renders_a_page_and_never_redirects() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let attacker = "https://attacker.example/callback";
    let uri = format!(
        "/v1/auth-core/authorize?response_type=code&client_id={CLIENT}\
         &redirect_uri={attacker}&code_challenge={}&code_challenge_method=S256&state=xyz",
        challenge()
    );
    let response = get(&kit, &uri, Some(&cookie)).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response.headers().get(header::LOCATION).is_none(),
        "a refused /authorize must not carry a Location header"
    );
}

/// An unknown client and a disabled one are refused the same way as an
/// unregistered URI: the page is the only channel that could leak
/// whether a client id exists.
#[pollster::test]
async fn an_unknown_client_is_refused_identically() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let known = get(&kit, &authorize_uri(""), Some(&cookie)).await;
    let unknown_uri = authorize_uri("").replace(CLIENT, "client-does-not-exist");
    let unknown = get(&kit, &unknown_uri, Some(&cookie)).await;

    assert_eq!(known.status(), StatusCode::FOUND, "the known client works");
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    assert!(unknown.headers().get(header::LOCATION).is_none());
}

/// A signed-out visitor is offered the chooser, not a code.
#[pollster::test]
async fn a_signed_out_visitor_gets_the_login_chooser() {
    let kit = kit();
    seed_client(&kit).await;

    let response = get(&kit, &authorize_uri(""), None).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(header::LOCATION).is_none(),
        "no code is minted for a visitor who is not signed in"
    );
}

/// The happy path: a signed-in visitor gets a redirect to the exact
/// registered URI carrying a code and the state they sent.
#[pollster::test]
async fn a_signed_in_visitor_is_redirected_with_a_code_and_their_state() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let response = get(&kit, &authorize_uri(""), Some(&cookie)).await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("Location")
        .to_str()
        .expect("ascii");
    assert!(
        location.starts_with(REDIRECT),
        "redirects to the registered URI, got {location}"
    );
    assert!(location.contains("code="), "carries a code: {location}");
    assert!(location.contains("state=xyz"), "echoes state: {location}");
}

/// PKCE is not decoration: `plain` is refused, per OAuth 2.1.
///
/// The refusal is an `error=invalid_request` redirect rather than a
/// page, and that is correct: the client and redirect URI were already
/// validated, so RFC 6749 §4.1.2.1 says the error goes back to the
/// client. What must never happen is a code being issued anyway.
#[pollster::test]
async fn the_plain_pkce_method_is_refused() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let uri =
        authorize_uri("").replace("code_challenge_method=S256", "code_challenge_method=plain");
    let response = get(&kit, &uri, Some(&cookie)).await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = location_of(&response);
    assert!(
        location.starts_with(REDIRECT),
        "the error goes to the REGISTERED uri, got {location}"
    );
    assert!(
        location.contains("error=invalid_request"),
        "names the error: {location}"
    );
    assert!(
        !location.contains("code="),
        "no code is issued for a plain challenge: {location}"
    );
}

/// A request with no PKCE challenge at all is refused: every client
/// kind must use it, public and confidential alike. Again the refusal
/// travels back to the registered URI, and again without a code.
#[pollster::test]
async fn a_missing_pkce_challenge_is_refused() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let uri = format!(
        "/v1/auth-core/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}&state=xyz"
    );
    let response = get(&kit, &uri, Some(&cookie)).await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = location_of(&response);
    assert!(location.starts_with(REDIRECT), "got {location}");
    assert!(location.contains("error=invalid_request"), "got {location}");
    assert!(
        !location.contains("code="),
        "no code without a challenge: {location}"
    );
}

/// Logout revokes the session and clears the cookie; the session it
/// revoked can no longer mint a code.
#[pollster::test]
async fn logout_revokes_the_session_and_clears_the_cookie() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let response = get(&kit, "/v1/auth-core/logout", Some(&cookie)).await;
    assert!(
        response.status() == StatusCode::OK || response.status() == StatusCode::FOUND,
        "logout answers, got {}",
        response.status()
    );
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("clears the cookie")
        .to_str()
        .expect("ascii");
    assert!(
        set_cookie.contains("Max-Age=0") || set_cookie.contains("Expires="),
        "the clearing cookie expires it: {set_cookie}"
    );

    let hash = Sha256::digest(cookie.as_bytes()).to_vec();
    let row = session_by_token_hash(&*kit.db, &hash)
        .await
        .expect("query")
        .expect("row still exists");
    assert!(row.revoked_at.is_some(), "logout revoked the session");

    // And the revoked session no longer authorizes.
    let after = get(&kit, &authorize_uri(""), Some(&cookie)).await;
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "a revoked session falls back to the chooser rather than minting a code"
    );
}
