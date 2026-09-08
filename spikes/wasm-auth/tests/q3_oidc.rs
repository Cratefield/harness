use openidconnect::core::{CoreIdTokenVerifier, CoreJsonWebKeySet};
use openidconnect::{ClientId, IssuerUrl, Nonce};

const TOKEN_RESPONSE_FIXTURE: &str = include_str!("../fixtures/google-token-response.json");
const JWKS_FIXTURE: &str = include_str!("../fixtures/google-jwks.json");

#[test]
fn fixture_id_token_verifies_against_fixture_jwks() {
    let token_response: serde_json::Value =
        serde_json::from_str(TOKEN_RESPONSE_FIXTURE).expect("token fixture parses");
    let id_token_string = token_response["id_token"]
        .as_str()
        .expect("id_token present");
    let id_token = wasm_auth_spike::q3_oidc::fixture_id_token().expect("id token parses");

    let jwks: CoreJsonWebKeySet = serde_json::from_str(JWKS_FIXTURE).expect("jwks fixture parses");
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new("spike-fixture-client.apps.googleusercontent.com".to_string()),
        IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
        jwks,
    );
    let nonce = Nonce::new("spike-fixture-nonce".to_string());
    let claims = id_token
        .claims(&verifier, &nonce)
        .expect("fixture id token verifies");

    assert_eq!(claims.subject().as_str(), "10769150350006150715113082367");
    assert_eq!(
        claims.email().map(|e| e.as_str()),
        Some("spike-user@example.com")
    );
    assert_ne!(id_token_string.len(), 0);
}

#[test]
fn id_token_with_wrong_audience_is_rejected() {
    let id_token = wasm_auth_spike::q3_oidc::fixture_id_token().expect("id token parses");
    let jwks: CoreJsonWebKeySet = serde_json::from_str(JWKS_FIXTURE).expect("jwks fixture parses");
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new("some-other-client.apps.googleusercontent.com".to_string()),
        IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
        jwks,
    );
    let nonce = Nonce::new("spike-fixture-nonce".to_string());
    let error = id_token
        .claims(&verifier, &nonce)
        .expect_err("wrong audience must fail");
    assert!(
        error.to_string().contains("aud"),
        "unexpected error: {error}"
    );
}

#[test]
fn id_token_with_wrong_nonce_is_rejected() {
    let id_token = wasm_auth_spike::q3_oidc::fixture_id_token().expect("id token parses");
    let jwks: CoreJsonWebKeySet = serde_json::from_str(JWKS_FIXTURE).expect("jwks fixture parses");
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new("spike-fixture-client.apps.googleusercontent.com".to_string()),
        IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
        jwks,
    );
    let nonce = Nonce::new("wrong-nonce".to_string());
    let error = id_token
        .claims(&verifier, &nonce)
        .expect_err("wrong nonce must fail");
    assert!(
        error.to_string().to_lowercase().contains("nonce"),
        "unexpected error: {error}"
    );
}
