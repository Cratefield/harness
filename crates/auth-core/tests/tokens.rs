//! Issue #9 acceptance, integration half: the discovery endpoints
//! under `/.well-known` (public keys only, cache headers, rotation
//! overlap), access tokens carrying the recommended claims, and
//! refresh tokens that are single-use with reuse detection revoking
//! the session — against the sqlite adapter through the `Clock` port.
//!
//! Signing keys are throwaway P-256 keys generated inside each test;
//! no real key is ever committed.

use axum::http::{Method, StatusCode, header};
use base64ct::{Base64UrlUnpadded, Encoding};
use factory0_auth_core::{
    AuthCore, Login, RefreshOutcome, SLIDE_WINDOW_DAYS, SigningKeys, UserRow,
    exchange_refresh_token, issue, mint_access_token, mint_refresh_token, session_by_token_hash,
};
use factory0_core::{MapConfig, UlidIdGen};
use factory0_testing::{FixedClock, TestHarness};
use p256::ecdsa::{self, signature::Verifier};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const EPOCH: i64 = 1_800_000_000;
const DAY: i64 = 86_400;
const ISSUER: &str = "https://auth.test.example";

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

/// A throwaway P-256 keypair generated in the test: the private JWK
/// for the config, the signer for signature assertions.
fn dummy_key(kid: &str) -> (Value, ecdsa::SigningKey) {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("entropy");
    bytes[0] = 1; // keep the scalar valid while staying obviously fake
    let secret = p256::SecretKey::from_slice(&bytes).expect("scalar");
    let signing = ecdsa::SigningKey::from(&secret);
    let d = Base64UrlUnpadded::encode_string(&secret.to_bytes());
    (
        json!({ "kty": "EC", "crv": "P-256", "kid": kid, "d": d }),
        signing,
    )
}

/// One signed test environment: the harness (whose router resolves
/// keys from the same config), the parsed keys for direct minting, and
/// the raw signers so tests can verify signatures independently.
struct SignedKit {
    kit: TestHarness,
    keys: Arc<SigningKeys>,
    signers: Vec<ecdsa::SigningKey>,
}

fn signed_kit(active: &str, pairs: Vec<(Value, ecdsa::SigningKey)>) -> SignedKit {
    let jwks: Vec<Value> = pairs.iter().map(|(jwk, _)| jwk.clone()).collect();
    let signers: Vec<ecdsa::SigningKey> = pairs.into_iter().map(|(_, signing)| signing).collect();
    let config = MapConfig::from_pairs([
        (
            "AUTH_CORE_SIGNING_KEYS",
            serde_json::to_string(&jwks).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE", active.to_owned()),
        ("AUTH_CORE_ISSUER", ISSUER.to_owned()),
    ]);
    let keys = Arc::new(
        SigningKeys::from_config(&config)
            .expect("config parses")
            .expect("keys configured"),
    );
    let kit = TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = Arc::new(config);
    });
    SignedKit { kit, keys, signers }
}

fn plain_kit() -> TestHarness {
    TestHarness::new(vec![Box::new(AuthCore::new())])
}

async fn seed_user(kit: &TestHarness, id: &str, email: Option<&str>, verified: bool) {
    factory0_auth_core::insert_user(
        &*kit.db,
        &UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: email.map(str::to_owned),
            primary_email_verified: verified,
            status: "active".to_owned(),
            created_at: iso(EPOCH),
            updated_at: iso(EPOCH),
        },
    )
    .await
    .expect("user");
}

async fn seed_session(
    kit: &TestHarness,
    user_id: &str,
    amr: &[&str],
) -> factory0_auth_core::IssuedSession {
    issue(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        Login {
            user_id,
            ip: Some("203.0.113.7"),
            user_agent: Some("Mozilla/5.0 Macintosh Safari/605.1.15"),
            presented_cookie: None,
            amr,
        },
    )
    .await
    .expect("session")
}

async fn get(kit: &TestHarness, path: &str) -> (StatusCode, Option<String>, Value, Vec<u8>) {
    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(axum::body::Body::empty())
        .expect("builds");
    let response = kit.router.clone().oneshot(request).await.expect("answers");
    let status = response.status();
    let cache = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, cache, json, body.to_vec())
}

fn b64url_json(part: &str) -> Value {
    serde_json::from_slice(&Base64UrlUnpadded::decode_vec(part).expect("b64url")).expect("json")
}

fn header_of(token: &str) -> Value {
    b64url_json(token.split('.').next().expect("header"))
}

fn claims_of(token: &str) -> Value {
    b64url_json(token.split('.').nth(1).expect("claims"))
}

fn verify_signature(token: &str, signer: &ecdsa::SigningKey) {
    let mut parts = token.split('.');
    let head = parts.next().expect("header");
    let claims = parts.next().expect("claims");
    let raw = Base64UrlUnpadded::decode_vec(parts.next().expect("signature")).expect("b64url");
    let signature = ecdsa::Signature::from_slice(&raw).expect("r||s");
    signer
        .verifying_key()
        .verify(format!("{head}.{claims}").as_bytes(), &signature)
        .expect("signature verifies");
}

#[pollster::test]
async fn jwks_publishes_public_parts_of_every_configured_key() {
    let signed = signed_kit("k-new", vec![dummy_key("k-old"), dummy_key("k-new")]);
    let (status, cache, body, raw) = get(&signed.kit, "/.well-known/jwks.json").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("public, max-age=300"));
    let keys = body["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 2, "current and previous keys are published");
    let kids: Vec<&str> = keys
        .iter()
        .map(|key| key["kid"].as_str().expect("kid"))
        .collect();
    assert_eq!(kids, ["k-old", "k-new"]);
    for key in keys {
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["use"], "sig");
        assert!(key["x"].as_str().is_some_and(|x| x.len() == 43));
        assert!(key["y"].as_str().is_some_and(|y| y.len() == 43));
    }
    assert!(
        !raw.windows(3).any(|window| window == b"\"d\""),
        "the JWKS response must never contain the private `d` field"
    );
}

#[pollster::test]
async fn openid_configuration_advertises_the_issuer_endpoints_and_algorithms() {
    let signed = signed_kit("k", vec![dummy_key("k")]);
    let (status, cache, body, _) = get(&signed.kit, "/.well-known/openid-configuration").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("public, max-age=3600"));
    assert_eq!(body["issuer"], ISSUER);
    assert_eq!(body["jwks_uri"], format!("{ISSUER}/.well-known/jwks.json"));
    assert_eq!(
        body["authorization_endpoint"],
        format!("{ISSUER}/v1/auth-core/authorize")
    );
    assert_eq!(
        body["token_endpoint"],
        format!("{ISSUER}/v1/auth-core/token")
    );
    assert_eq!(
        body["end_session_endpoint"],
        format!("{ISSUER}/v1/auth-core/logout")
    );
    assert_eq!(body["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        body["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(body["response_types_supported"], json!(["code"]));
    assert!(
        !body.to_string().contains("implicit"),
        "no implicit flow, no password grant is advertised"
    );
}

#[pollster::test]
async fn unconfigured_keys_answer_the_stable_problem_on_both_documents() {
    let kit = plain_kit();
    let (status, _, body, _) = get(&kit, "/.well-known/jwks.json").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body["type"],
        "https://factory0.ventures/problems/auth/tokens-unconfigured"
    );

    let (status, _, body, _) = get(&kit, "/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body["type"],
        "https://factory0.ventures/problems/auth/tokens-unconfigured"
    );
}

#[pollster::test]
async fn access_tokens_carry_the_recommended_claims_and_verify() {
    let signed = signed_kit("k", vec![dummy_key("k")]);
    seed_user(&signed.kit, "u1", Some("u1@example.com"), true).await;
    let session = seed_session(&signed.kit, "u1", &["user", "passkey"]).await;

    let token = mint_access_token(
        &signed.keys,
        &at(EPOCH + 60),
        &session.session_id,
        "u1",
        Some(("u1@example.com", true)),
        "client_1",
        &["user".to_owned(), "passkey".to_owned()],
    )
    .expect("mint");

    let header = header_of(&token);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["kid"], "k");
    verify_signature(&token, &signed.signers[0]);

    let claims = claims_of(&token);
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["sub"], "u1");
    assert_eq!(claims["aud"], "client_1");
    assert_eq!(claims["sid"], session.session_id);
    assert_eq!(claims["iat"], EPOCH + 60);
    assert_eq!(claims["exp"], EPOCH + 60 + 600);
    assert_eq!(claims["email"], "u1@example.com");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["amr"], json!(["user", "passkey"]));
}

#[pollster::test]
async fn rotation_overlaps_both_keys_and_signs_with_the_active_one() {
    let signed = signed_kit("k-new", vec![dummy_key("k-old"), dummy_key("k-new")]);
    let (status, _, body, _) = get(&signed.kit, "/.well-known/jwks.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["keys"].as_array().expect("keys").len(),
        2,
        "the previous key keeps verifying during the overlap"
    );

    assert_eq!(signed.keys.active_kid(), "k-new");
    let token =
        mint_access_token(&signed.keys, &at(EPOCH), "s", "u", None, "c", &[]).expect("mint");
    assert_eq!(header_of(&token)["kid"], "k-new");
    verify_signature(&token, &signed.signers[1]);
}

#[pollster::test]
async fn refresh_tokens_are_single_use_and_reuse_revokes_the_session() {
    let kit = plain_kit();
    seed_user(&kit, "u1", None, false).await;
    let session = seed_session(&kit, "u1", &[]).await;

    let value = mint_refresh_token(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        &session.session_id,
        "u1",
        "client_1",
    )
    .await
    .expect("mint");
    assert_eq!(value.len(), 43);

    // Only the hash is stored, bound to the session, 30-day expiry.
    let hash = Sha256::digest(value.as_bytes()).to_vec();
    let row = factory0_auth_core::single_use_token_by_hash(&*kit.db, &hash)
        .await
        .expect("query")
        .expect("stored");
    assert_eq!(row.kind, "refresh_token");
    assert_eq!(row.client_id.as_deref(), Some("client_1"));
    assert_eq!(row.expires_at, iso(EPOCH + SLIDE_WINDOW_DAYS * DAY));

    // First exchange wins.
    let (outcome, grant) = exchange_refresh_token(&*kit.db, &at(EPOCH + 10), &value, "client_1")
        .await
        .expect("exchange");
    assert_eq!(outcome, RefreshOutcome::Granted);
    let grant = grant.expect("grant");
    assert_eq!(grant.session_id, session.session_id);
    assert_eq!(grant.user_id, "u1");
    assert_eq!(grant.client_id, "client_1");

    // Reuse: refused, and the session is revoked.
    let (outcome, grant) = exchange_refresh_token(&*kit.db, &at(EPOCH + 20), &value, "client_1")
        .await
        .expect("exchange");
    assert_eq!(outcome, RefreshOutcome::Refused);
    assert!(grant.is_none());
    let revoked = session_by_token_hash(&*kit.db, &Sha256::digest(session.value.as_bytes()))
        .await
        .expect("query")
        .expect("session");
    assert!(revoked.revoked_at.is_some(), "reuse revoked the session");
}

#[pollster::test]
async fn a_refresh_token_presented_for_the_wrong_client_is_not_consumed() {
    let kit = plain_kit();
    seed_user(&kit, "u1", None, false).await;
    let session = seed_session(&kit, "u1", &[]).await;

    let value = mint_refresh_token(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        &session.session_id,
        "u1",
        "client_1",
    )
    .await
    .expect("mint");

    let (outcome, _) = exchange_refresh_token(&*kit.db, &at(EPOCH), &value, "client_other")
        .await
        .expect("exchange");
    assert_eq!(outcome, RefreshOutcome::Refused);

    // The rightful client can still use it, and the session lives on.
    let (outcome, _) = exchange_refresh_token(&*kit.db, &at(EPOCH), &value, "client_1")
        .await
        .expect("exchange");
    assert_eq!(outcome, RefreshOutcome::Granted);
    let live = session_by_token_hash(&*kit.db, &Sha256::digest(session.value.as_bytes()))
        .await
        .expect("query")
        .expect("session");
    assert!(live.revoked_at.is_none());
}

#[pollster::test]
async fn an_unknown_refresh_token_is_refused_without_side_effects() {
    let kit = plain_kit();
    let (outcome, grant) = exchange_refresh_token(
        &*kit.db,
        &at(EPOCH),
        "not-a-real-token-at-all-just-43-chars-xxxx",
        "client_1",
    )
    .await
    .expect("exchange");
    assert_eq!(outcome, RefreshOutcome::Refused);
    assert!(grant.is_none());
}
