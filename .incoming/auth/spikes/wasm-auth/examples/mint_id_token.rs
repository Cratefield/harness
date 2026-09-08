//! Host-only fixture generator for Q3 (examples are never built for the wasm
//! target).
//!
//! Mints a Google-shaped RS256 ID token with a fixed RSA keypair (embedded
//! below — public fixture material, not a secret: it signs only self-minted
//! fixtures), plus the JWKS containing its public half, and writes
//! `fixtures/google-token-response.json` and `fixtures/google-jwks.json`.
//! RS256 signing is deterministic, so re-running reproduces both files.

use chrono::{TimeZone, Utc};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey,
};
use openidconnect::{
    AccessToken, Audience, AuthorizationCode, EmptyAdditionalClaims, IssuerUrl, JsonWebKeyId,
    PrivateSigningKey, StandardClaims,
};
use serde_json::json;

// openssl genrsa 2048 (PKCS#1). Public fixture material; see module docs.
const FIXTURE_RSA_PEM: &str = concat!(
    "-----BEGIN RSA PRIVATE KEY-----\n",
    include_str!("../fixtures/google-fixture.key"),
    "-----END RSA PRIVATE KEY-----\n",
);

fn main() {
    let signing_key = CoreRsaPrivateSigningKey::from_pem(
        FIXTURE_RSA_PEM,
        Some(JsonWebKeyId::new("spike-fixture-key-1".to_string())),
    )
    .expect("fixture key parses");

    let issuer = IssuerUrl::new("https://accounts.google.com".to_string()).unwrap();
    let exp = Utc.timestamp_opt(1893456000, 0).unwrap(); // 2030-01-01
    let iat = Utc.timestamp_opt(1893456000 - 7200, 0).unwrap();
    let standard_claims = StandardClaims::new(openidconnect::SubjectIdentifier::new(
        "10769150350006150715113082367".to_string(),
    ))
    .set_email(Some(openidconnect::EndUserEmail::new(
        "spike-user@example.com".to_string(),
    )));

    let claims = CoreIdTokenClaims::new(
        issuer,
        vec![Audience::new(
            "spike-fixture-client.apps.googleusercontent.com".to_string(),
        )],
        exp,
        iat,
        standard_claims,
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(openidconnect::Nonce::new(
        "spike-fixture-nonce".to_string(),
    )))
    .set_auth_time(Some(Utc.timestamp_opt(1893456000 - 3600, 0).unwrap()));

    let access_token = AccessToken::new("spike-fixture-access-token".to_string());
    let id_token = CoreIdToken::new(
        claims,
        &signing_key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        Some(&access_token),
        Some(&AuthorizationCode::new(
            "spike-fixture-auth-code".to_string(),
        )),
    )
    .expect("fixture id token signs");

    let token_response = json!({
        "access_token": access_token.secret(),
        "id_token": id_token.to_string(),
        "token_type": "Bearer",
        "expires_in": 3599,
        "scope": "openid email profile",
    });

    let public_jwk = signing_key.as_verification_key();
    let jwks = json!({ "keys": [public_jwk] });

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures");
    std::fs::create_dir_all(dir).expect("fixtures dir exists");
    std::fs::write(
        format!("{dir}/google-token-response.json"),
        serde_json::to_vec_pretty(&token_response).unwrap(),
    )
    .expect("token response fixture written");
    std::fs::write(
        format!("{dir}/google-jwks.json"),
        serde_json::to_vec_pretty(&jwks).unwrap(),
    )
    .expect("jwks fixture written");
    println!("wrote fixtures/google-token-response.json and fixtures/google-jwks.json");
}
