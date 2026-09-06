use base64::Engine;
use base64urlsafedata::Base64UrlSafeData;
use wasm_auth_spike::q2_webauthn::{self, PasskeyFixture};

fn fixture() -> PasskeyFixture {
    let raw = include_str!("../fixtures/passkey.json");
    serde_json::from_str(raw).expect("fixture parses")
}

fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn recorded_passkey_fixture_verifies_registration_and_assertion() {
    let verified = q2_webauthn::run_fixture(&fixture()).expect("fixture verifies");
    assert_eq!(verified.sign_count, 2);
}

#[test]
fn tampered_assertion_signature_is_rejected() {
    let mut f = fixture();
    let mut signature = f.assertion.response.signature.as_ref().to_vec();
    let last = signature.len() - 1;
    signature[last] ^= 0x01;
    f.assertion.response.signature = Base64UrlSafeData::from(signature);
    let err = q2_webauthn::run_fixture(&f).expect_err("tampered signature must fail");
    assert!(err.contains("signature invalid"), "unexpected error: {err}");
}

#[test]
fn wrong_assertion_challenge_is_rejected() {
    let mut f = fixture();
    f.assertion_challenge = b64u(&[0u8; 32]);
    let err = q2_webauthn::run_fixture(&f).expect_err("challenge swap must fail");
    assert!(err.contains("challenge"), "unexpected error: {err}");
}

#[test]
fn wrong_origin_is_rejected() {
    let mut f = fixture();
    f.origin = "https://evil.example".parse().unwrap();
    let err = q2_webauthn::run_fixture(&f).expect_err("origin swap must fail");
    assert!(err.contains("origin"), "unexpected error: {err}");
}

#[test]
fn replayed_assertion_without_counter_advance_is_rejected() {
    let f = fixture();
    let registration_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&f.registration_challenge)
        .unwrap();
    let assertion_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&f.assertion_challenge)
        .unwrap();
    let credential = q2_webauthn::verify_registration(
        &f.rp_id,
        &f.origin,
        &registration_challenge,
        &f.registration,
    )
    .expect("registration verifies");
    let first = q2_webauthn::verify_assertion(
        &f.rp_id,
        &f.origin,
        &assertion_challenge,
        &credential,
        &f.assertion,
    )
    .expect("first assertion verifies");
    let replayed = q2_webauthn::verify_assertion(
        &f.rp_id,
        &f.origin,
        &assertion_challenge,
        &q2_webauthn::RegisteredCredential {
            credential_id: credential.credential_id.clone(),
            cose_public_key: credential.cose_public_key.clone(),
            sign_count: first.sign_count,
            attestation_format: credential.attestation_format.clone(),
            attestation_unverified: credential.attestation_unverified,
        },
        &f.assertion,
    );
    assert!(
        replayed.is_err(),
        "replay with non-advancing counter must fail"
    );
}
