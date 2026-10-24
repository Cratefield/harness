//! Venture linking, the grants list and its two changes (revoke, and grant
//! again), end to end through the router with real tokens.
//!
//! The load-bearing claim is the middle one: once a person has revoked a
//! client, `/authorize` refuses it with `access_denied` and issues no code,
//! until the person grants it again. A silent re-authorization would undo the
//! revocation. The other claims: only the account console's token may read or
//! change grants, a person's grants are not addressable by another person,
//! and with the console unset the routes do not exist.

use axum::http::{Method, StatusCode, header};
use base64ct::{Base64UrlUnpadded, Encoding};
use cratefield_auth_core::{
    AuthCore, ClientRedirectUriRow, ClientRow, Login, Redacted, UserRow, insert_client,
    insert_redirect_uri, insert_user, issue,
};
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
const CONSOLE: &str = "client-console";
const VENTURE: &str = "client-ledgers";
const REDIRECT: &str = "https://app.ledgers.example/auth/callback";
const VERIFIER: &str = "a-verifier-of-at-least-43-characters-1234567890";
const BASE: &str = "/v1/auth-core";

fn at(secs: i64) -> FixedClock {
    FixedClock(OffsetDateTime::from_unix_timestamp(secs).expect("epoch in range"))
}

fn iso(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .expect("in range")
        .format(&Rfc3339)
        .expect("rfc3339")
}

fn dummy_key(kid: &str) -> Value {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("entropy");
    bytes[0] = 1;
    let secret = p256::SecretKey::from_slice(&bytes).expect("scalar");
    let _ = ecdsa::SigningKey::from(&secret);
    let d = Base64UrlUnpadded::encode_string(&secret.to_bytes());
    json!({ "kty": "EC", "crv": "P-256", "kid": kid, "d": d })
}

/// A harness with signing keys (so `/token` works) and, when `console` is
/// true, the account console configured as the one grants client.
fn kit(console: bool) -> TestHarness {
    let mut pairs = vec![
        (
            "AUTH_CORE_SIGNING_KEYS".to_owned(),
            serde_json::to_string(&vec![dummy_key("k1")]).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE".to_owned(), "k1".to_owned()),
        ("AUTH_CORE_ISSUER".to_owned(), ISSUER.to_owned()),
    ];
    if console {
        pairs.push(("AUTH_CORE_GRANTS_CLIENT_ID".to_owned(), CONSOLE.to_owned()));
    }
    let config = Arc::new(MapConfig::from_pairs(pairs));
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], move |ports| {
        ports.config = config;
    })
}

fn challenge() -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()))
}

async fn seed_clients(kit: &TestHarness) {
    for (id, name) in [(CONSOLE, "Account console"), (VENTURE, "Ledgers")] {
        insert_client(
            &*kit.db,
            &ClientRow {
                id: id.to_owned(),
                name: name.to_owned(),
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
                client_id: id.to_owned(),
                uri: REDIRECT.to_owned(),
            },
        )
        .await
        .expect("redirect uri");
    }
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
            created_at: iso(EPOCH),
            updated_at: iso(EPOCH),
        },
    )
    .await
    .expect("user");
}

async fn signed_in(kit: &TestHarness, user_id: &str) -> String {
    seed_user(kit, user_id).await;
    issue(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        Login {
            user_id,
            ip: None,
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr: &["email"],
        },
    )
    .await
    .expect("session")
    .value
}

fn authorize_uri(client: &str) -> String {
    format!(
        "{BASE}/authorize?response_type=code&client_id={client}&redirect_uri={REDIRECT}\
         &code_challenge={}&code_challenge_method=S256&state=xyz&scope=openid",
        challenge()
    )
}

async fn send(
    kit: &TestHarness,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    form: Option<&str>,
) -> axum::response::Response {
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    if form.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, format!("__Host-session={cookie}"));
    }
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder
        .body(axum::body::Body::from(form.unwrap_or_default().to_owned()))
        .expect("request");
    kit.router.clone().oneshot(request).await.expect("answers")
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
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

/// Signs `user` in, authorizes `client`, and redeems the code: the person's
/// grant to that client is written, and the client gets an access token.
async fn authorize_and_redeem(kit: &TestHarness, cookie: &str, client: &str) -> String {
    let response = send(
        kit,
        Method::GET,
        &authorize_uri(client),
        Some(cookie),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = location_of(&response);
    let code = location
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("a code")
        .to_owned();
    let form = format!(
        "grant_type=authorization_code&client_id={client}&code={code}\
         &redirect_uri={REDIRECT}&code_verifier={VERIFIER}"
    );
    let token = send(
        kit,
        Method::POST,
        &format!("{BASE}/token"),
        None,
        None,
        Some(&form),
    )
    .await;
    assert_eq!(token.status(), StatusCode::OK);
    body_json(token).await["access_token"]
        .as_str()
        .expect("access token")
        .to_owned()
}

#[pollster::test]
async fn the_console_lists_what_the_person_signed_in_to() {
    let kit = kit(true);
    seed_clients(&kit).await;
    let cookie = signed_in(&kit, "u1").await;
    let console_token = authorize_and_redeem(&kit, &cookie, CONSOLE).await;
    assert!(
        body_json(
            send(
                &kit,
                Method::GET,
                &format!("{BASE}/grants"),
                None,
                Some(&console_token),
                None
            )
            .await
        )
        .await["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .any(|grant| grant["client_id"] == CONSOLE),
        "the console is itself a grant once it has been signed in to"
    );

    authorize_and_redeem(&kit, &cookie, VENTURE).await;
    let listed = body_json(
        send(
            &kit,
            Method::GET,
            &format!("{BASE}/grants"),
            None,
            Some(&console_token),
            None,
        )
        .await,
    )
    .await;
    let venture = listed["grants"]
        .as_array()
        .expect("grants")
        .iter()
        .find(|grant| grant["client_id"] == VENTURE)
        .expect("the venture is listed");
    assert_eq!(venture["name"], "Ledgers");
}

#[pollster::test]
async fn a_revoked_client_gets_no_code_until_the_person_grants_it_again() {
    let kit = kit(true);
    seed_clients(&kit).await;
    let cookie = signed_in(&kit, "u1").await;
    let console_token = authorize_and_redeem(&kit, &cookie, CONSOLE).await;
    authorize_and_redeem(&kit, &cookie, VENTURE).await;

    let revoked = send(
        &kit,
        Method::DELETE,
        &format!("{BASE}/grants/{VENTURE}"),
        None,
        Some(&console_token),
        None,
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);

    let listed = body_json(
        send(
            &kit,
            Method::GET,
            &format!("{BASE}/grants"),
            None,
            Some(&console_token),
            None,
        )
        .await,
    )
    .await;
    assert!(
        listed["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .all(|grant| grant["client_id"] != VENTURE)
    );

    // A silent authorization is refused the RFC 6749 way: an error, no code.
    let refused = send(
        &kit,
        Method::GET,
        &authorize_uri(VENTURE),
        Some(&cookie),
        None,
        None,
    )
    .await;
    let target = location_of(&refused);
    assert!(target.starts_with(REDIRECT), "{target}");
    assert!(target.contains("error=access_denied"), "{target}");
    assert!(!target.contains("code="), "{target}");

    // The person grants it again (the "Link" action); the code comes back.
    let granted = send(
        &kit,
        Method::POST,
        &format!("{BASE}/grants/{VENTURE}"),
        None,
        Some(&console_token),
        None,
    )
    .await;
    assert_eq!(granted.status(), StatusCode::OK);
    let again = send(
        &kit,
        Method::GET,
        &authorize_uri(VENTURE),
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert!(
        location_of(&again).contains("code="),
        "{}",
        location_of(&again)
    );
}

#[pollster::test]
async fn only_the_console_may_read_or_change_grants() {
    let kit = kit(true);
    seed_clients(&kit).await;
    let cookie = signed_in(&kit, "u1").await;
    let venture_token = authorize_and_redeem(&kit, &cookie, VENTURE).await;

    // A venture holds a perfectly good token for this person, and still may
    // not see the person's other ventures.
    let listed = send(
        &kit,
        Method::GET,
        &format!("{BASE}/grants"),
        None,
        Some(&venture_token),
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::UNAUTHORIZED);
    let revoked = send(
        &kit,
        Method::DELETE,
        &format!("{BASE}/grants/{VENTURE}"),
        None,
        Some(&venture_token),
        None,
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
}

#[pollster::test]
async fn another_persons_grant_is_not_addressable() {
    let kit = kit(true);
    seed_clients(&kit).await;
    let alice = signed_in(&kit, "alice").await;
    let bob = signed_in(&kit, "bob").await;
    let alice_console = authorize_and_redeem(&kit, &alice, CONSOLE).await;
    let bob_console = authorize_and_redeem(&kit, &bob, CONSOLE).await;
    authorize_and_redeem(&kit, &alice, VENTURE).await;

    let bob_list = body_json(
        send(
            &kit,
            Method::GET,
            &format!("{BASE}/grants"),
            None,
            Some(&bob_console),
            None,
        )
        .await,
    )
    .await;
    assert!(
        bob_list["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .all(|grant| grant["client_id"] != VENTURE),
        "bob does not see alice's venture"
    );
    let bob_revoke = send(
        &kit,
        Method::DELETE,
        &format!("{BASE}/grants/{VENTURE}"),
        None,
        Some(&bob_console),
        None,
    )
    .await;
    assert_eq!(bob_revoke.status(), StatusCode::NOT_FOUND);

    let alice_list = body_json(
        send(
            &kit,
            Method::GET,
            &format!("{BASE}/grants"),
            None,
            Some(&alice_console),
            None,
        )
        .await,
    )
    .await;
    assert!(
        alice_list["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .any(|grant| grant["client_id"] == VENTURE),
        "alice's grant survives bob's attempt"
    );
}

#[pollster::test]
async fn no_token_is_refused() {
    let kit = kit(true);
    seed_clients(&kit).await;
    let response = send(
        &kit,
        Method::GET,
        &format!("{BASE}/grants"),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[pollster::test]
async fn with_no_console_configured_the_routes_do_not_exist() {
    let kit = kit(false);
    seed_clients(&kit).await;
    let cookie = signed_in(&kit, "u1").await;
    let token = authorize_and_redeem(&kit, &cookie, CONSOLE).await;
    let response = send(
        &kit,
        Method::GET,
        &format!("{BASE}/grants"),
        None,
        Some(&token),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
