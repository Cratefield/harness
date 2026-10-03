//! The public verifier (`factory0_auth_passkeys::webauthn`) against
//! ceremonies **recorded from real authenticators**, not minted by the
//! software authenticator the other suites use: a Yubico security key assertion and a
//! Touch ID (Edge) registration.
//!
//! The vectors are test data from `webauthn-rs-core` 0.5.5
//! (`src/core.rs`, `test_authentication` and
//! `test_edge_touchid_rk_verified`), MPL-2.0, (c) the webauthn-rs authors;
//! this file is therefore MPL-2.0 too. Nothing else in the crate is.

use ciborium::Value;
use factory0_auth_passkeys::webauthn::{
    StoredPasskey, UserVerification, WebauthnError, verify_assertion, verify_registration,
};
use webauthn_rs_proto::{PublicKeyCredential, RegisterPublicKeyCredential};

fn localhost() -> Vec<url::Url> {
    vec![url::Url::parse("http://localhost:8080").expect("url")]
}

/// The Yubico key's P-256 key, as the COSE key an authenticator would have
/// registered.
fn yubikey_cose_key() -> Vec<u8> {
    let x: Vec<u8> = vec![
        46, 121, 76, 233, 118, 208, 250, 74, 227, 182, 8, 145, 45, 46, 5, 9, 199, 186, 84, 83, 7,
        237, 130, 73, 16, 90, 17, 54, 33, 255, 54, 56,
    ];
    let y: Vec<u8> = vec![
        117, 105, 1, 23, 253, 223, 67, 135, 253, 219, 253, 223, 17, 247, 91, 197, 205, 225, 143,
        59, 47, 138, 70, 120, 74, 155, 177, 177, 166, 233, 48, 71,
    ];
    let key = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (Value::Integer(3.into()), Value::Integer((-7).into())),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (Value::Integer((-2).into()), Value::Bytes(x)),
        (Value::Integer((-3).into()), Value::Bytes(y)),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&key, &mut out).expect("encodes");
    out
}

const YUBIKEY_CREDENTIAL_ID: [u8; 64] = [
    106, 223, 133, 124, 161, 172, 56, 141, 181, 18, 27, 66, 187, 181, 113, 251, 187, 123, 20, 169,
    41, 80, 236, 138, 92, 137, 4, 4, 16, 255, 188, 47, 158, 202, 111, 192, 117, 110, 152, 245, 95,
    22, 200, 172, 71, 154, 40, 181, 212, 64, 80, 17, 238, 238, 21, 13, 27, 145, 140, 27, 208, 101,
    166, 81,
];

const YUBIKEY_CHALLENGE: [u8; 32] = [
    90, 5, 243, 254, 68, 239, 221, 101, 20, 214, 76, 60, 134, 111, 142, 26, 129, 146, 225, 144,
    135, 95, 253, 219, 18, 161, 199, 216, 251, 213, 167, 195,
];

fn yubikey_assertion() -> PublicKeyCredential {
    serde_json::from_str(
        r#"{
            "id":"at-FfKGsOI21EhtCu7Vx-7t7FKkpUOyKXIkEBBD_vC-eym_AdW6Y9V8WyKxHmii11EBQEe7uFQ0bkYwb0GWmUQ",
            "rawId":"at-FfKGsOI21EhtCu7Vx-7t7FKkpUOyKXIkEBBD_vC-eym_AdW6Y9V8WyKxHmii11EBQEe7uFQ0bkYwb0GWmUQ",
            "response":{
                "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAFA",
                "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXZ1h6X2tUdjNXVVUxa3c4aG0tT0dvR1M0WkNIWF8zYkVxSEgyUHZWcDhNIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9",
                "signature":"MEYCIQDmLVOqv85cdRup4Fr8Pf9zC4AWO-XKBJqa8xPwYFCCMAIhAOiExLoyes0xipmUmq0BVlqJaCKLn_MFKG9GIDsCGq_-",
                "userHandle":null
            },
            "type":"public-key"
        }"#,
    )
    .expect("recorded assertion parses")
}

#[test]
fn a_recorded_yubikey_assertion_verifies() {
    let key = yubikey_cose_key();
    let stored = StoredPasskey {
        credential_id: &YUBIKEY_CREDENTIAL_ID,
        cose_key: &key,
        sign_count: 1,
    };
    let verified = verify_assertion(
        "localhost",
        &localhost(),
        &YUBIKEY_CHALLENGE,
        UserVerification::Preferred,
        &stored,
        &yubikey_assertion(),
    )
    .expect("the recorded assertion verifies");
    assert_eq!(verified.sign_count, 20);
    assert!(!verified.user_verified, "the key only tested presence");
}

#[test]
fn the_recorded_assertion_is_refused_wherever_one_thing_is_off() {
    let key = yubikey_cose_key();
    let stored = |count| StoredPasskey {
        credential_id: &YUBIKEY_CREDENTIAL_ID,
        cose_key: &key,
        sign_count: count,
    };
    let check = |rp: &str, origins: &[url::Url], challenge: &[u8], uv, count| {
        verify_assertion(
            rp,
            origins,
            challenge,
            uv,
            &stored(count),
            &yubikey_assertion(),
        )
    };
    let pref = UserVerification::Preferred;
    // No PIN or biometric was used, so a policy that demands one refuses.
    assert_eq!(
        check(
            "localhost",
            &localhost(),
            &YUBIKEY_CHALLENGE,
            UserVerification::Required,
            1
        )
        .err(),
        Some(WebauthnError::UserNotVerified)
    );
    assert_eq!(
        check("example.com", &localhost(), &YUBIKEY_CHALLENGE, pref, 1).err(),
        Some(WebauthnError::RpIdMismatch("example.com".to_owned()))
    );
    let other = vec![url::Url::parse("https://localhost:8080").expect("url")];
    assert!(matches!(
        check("localhost", &other, &YUBIKEY_CHALLENGE, pref, 1),
        Err(WebauthnError::OriginNotAllowed(_))
    ));
    assert_eq!(
        check("localhost", &localhost(), &[0u8; 32], pref, 1).err(),
        Some(WebauthnError::ChallengeMismatch)
    );
    // A stored counter at or past the presented 20 is a cloned key.
    assert!(matches!(
        check("localhost", &localhost(), &YUBIKEY_CHALLENGE, pref, 20),
        Err(WebauthnError::CounterRegression { .. })
    ));
    // A different key does not verify the recorded signature.
    let mut wrong = YUBIKEY_CREDENTIAL_ID;
    wrong[0] ^= 1;
    let mismatched = StoredPasskey {
        credential_id: &wrong,
        cose_key: &key,
        sign_count: 1,
    };
    assert_eq!(
        verify_assertion(
            "localhost",
            &localhost(),
            &YUBIKEY_CHALLENGE,
            pref,
            &mismatched,
            &yubikey_assertion()
        )
        .err(),
        Some(WebauthnError::CredentialMismatch)
    );
}

#[test]
fn a_recorded_touch_id_registration_verifies_with_user_verification_required() {
    let attestation_object: Vec<u8> = vec![
        163, 99, 102, 109, 116, 102, 112, 97, 99, 107, 101, 100, 103, 97, 116, 116, 83, 116, 109,
        116, 162, 99, 97, 108, 103, 38, 99, 115, 105, 103, 88, 72, 48, 70, 2, 33, 0, 234, 66, 128,
        149, 10, 78, 90, 6, 183, 58, 163, 114, 112, 146, 47, 204, 176, 27, 86, 218, 77, 135, 121,
        88, 40, 94, 115, 7, 221, 248, 13, 37, 2, 33, 0, 187, 63, 74, 17, 114, 129, 51, 239, 145,
        128, 216, 117, 39, 191, 130, 6, 239, 79, 15, 80, 58, 52, 18, 24, 57, 174, 125, 198, 248,
        46, 138, 177, 104, 97, 117, 116, 104, 68, 97, 116, 97, 88, 169, 73, 150, 13, 229, 136, 14,
        140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143, 228, 174, 185, 162, 134, 50, 199, 153,
        92, 243, 186, 131, 29, 151, 99, 69, 98, 76, 219, 31, 173, 206, 0, 2, 53, 188, 198, 10, 100,
        139, 11, 37, 241, 240, 85, 3, 0, 37, 1, 107, 83, 248, 212, 152, 28, 217, 153, 140, 253,
        145, 244, 144, 27, 6, 108, 31, 222, 197, 140, 198, 207, 203, 227, 243, 182, 94, 130, 47,
        35, 193, 216, 250, 177, 143, 140, 165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 143, 255, 51, 238,
        28, 38, 130, 245, 24, 48, 164, 117, 49, 102, 142, 103, 25, 46, 253, 137, 228, 16, 220, 131,
        17, 229, 52, 165, 75, 224, 218, 237, 34, 88, 32, 115, 152, 43, 120, 40, 171, 135, 110, 112,
        253, 28, 142, 154, 9, 9, 149, 94, 254, 147, 235, 38, 4, 215, 26, 217, 51, 245, 151, 148,
        192, 141, 169,
    ];
    let client_data = br#"{"type":"webauthn.create","challenge":"bCE-p6LqJD-w56E6Kel1ndL0exzCZCJEIAG38GThtjA","origin":"http://localhost:8080","crossOrigin":false}"#;
    let raw_id: Vec<u8> = vec![
        1, 107, 83, 248, 212, 152, 28, 217, 153, 140, 253, 145, 244, 144, 27, 6, 108, 31, 222, 197,
        140, 198, 207, 203, 227, 243, 182, 94, 130, 47, 35, 193, 216, 250, 177, 143, 140,
    ];
    let challenge: [u8; 32] = [
        108, 33, 62, 167, 162, 234, 36, 63, 176, 231, 161, 58, 41, 233, 117, 157, 210, 244, 123,
        28, 194, 100, 34, 68, 32, 1, 183, 240, 100, 225, 182, 48,
    ];
    let response = RegisterPublicKeyCredential {
        id: "AWtT-NSYHNmZjP2R9JAbBmwf3sWMxs_L4_O2XoIvI8HY-rGPjA".to_owned(),
        raw_id: raw_id.clone().into(),
        response: webauthn_rs_proto::AuthenticatorAttestationResponseRaw {
            attestation_object: attestation_object.into(),
            client_data_json: client_data.to_vec().into(),
            transports: None,
        },
        type_: "public-key".to_owned(),
        extensions: webauthn_rs_proto::RegistrationExtensionsClientOutputs::default(),
    };
    let registered = verify_registration(
        "localhost",
        &localhost(),
        &challenge,
        UserVerification::Required,
        &response,
    )
    .expect("the recorded registration verifies");
    assert_eq!(registered.credential_id, raw_id);
    assert!(registered.user_verified);
    assert_eq!(registered.attestation_format, "packed");
    assert!(
        registered.attestation_unverified,
        "packed is stored, not checked"
    );
    // Touch ID's counter is a timestamp, not a count from zero.
    assert_eq!(registered.sign_count, 1_649_203_999);

    // The same registration answered to a different challenge is refused.
    assert_eq!(
        verify_registration(
            "localhost",
            &localhost(),
            &[0u8; 32],
            UserVerification::Required,
            &response,
        )
        .err(),
        Some(WebauthnError::ChallengeMismatch)
    );
}
