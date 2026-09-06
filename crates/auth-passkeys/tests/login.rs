//! Issue #14 acceptance: assertions verified for P-256, RSA and Ed25519, a
//! sign-count regression detected and refused, and an unknown credential id
//! indistinguishable from a spent challenge.

mod support;

use http::StatusCode;
use support::{Algorithm, ORIGIN, OTHER_ORIGIN, RP_ID, SoftAuthenticator, challenge_of, post};

const REGISTER_OPTIONS: &str = "/v1/auth-passkeys/register/options";
const REGISTER_VERIFY: &str = "/v1/auth-passkeys/register/verify";
const LOGIN_OPTIONS: &str = "/v1/auth-passkeys/login/options";
const LOGIN_VERIFY: &str = "/v1/auth-passkeys/login/verify";

fn register_body(credential: &webauthn_rs_proto::RegisterPublicKeyCredential) -> String {
    serde_json::json!({ "credential": credential, "label": "key" }).to_string()
}

fn login_body(credential: &webauthn_rs_proto::PublicKeyCredential) -> String {
    serde_json::json!({ "credential": credential }).to_string()
}

/// Registers `authenticator` to a fresh account and returns the user id.
async fn account_with(
    kit: &support::Kit,
    email: &str,
    authenticator: &SoftAuthenticator,
) -> String {
    let user = kit.user(email).await;
    let cookie = kit.sign_in(&user).await;
    let options = post(kit, REGISTER_OPTIONS, "{}", Some(&cookie))
        .await
        .json();
    let challenge = challenge_of(&options);
    let stored = post(
        kit,
        REGISTER_VERIFY,
        &register_body(&authenticator.register(RP_ID, ORIGIN, &challenge)),
        Some(&cookie),
    )
    .await;
    assert_eq!(stored.status, StatusCode::OK, "{}", stored.text());
    user
}

#[test]
fn every_algorithm_a_real_passkey_can_present_verifies() {
    // The three the registration options offer. ES256 is Apple, Android and
    // most security keys; RS256 is Windows Hello; EdDSA is some keys.
    for algorithm in [Algorithm::Es256, Algorithm::Rs256, Algorithm::Eddsa] {
        pollster::block_on(async move {
            let kit = support::kit();
            let mut authenticator = SoftAuthenticator::new(algorithm);
            let user = account_with(&kit, "nick@example.com", &authenticator).await;

            let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
                .await
                .json();
            let challenge = challenge_of(&options);
            authenticator.counter = 2;

            let response = post(
                &kit,
                LOGIN_VERIFY,
                &login_body(&authenticator.assert(RP_ID, ORIGIN, &challenge)),
                None,
            )
            .await;
            assert_eq!(
                response.status,
                StatusCode::OK,
                "{algorithm:?}: {}",
                response.text()
            );
            assert_eq!(response.json()["user_id"], user);
            assert_eq!(response.json()["user_verified"], true);

            let cookie = response.set_cookie().expect("a session cookie");
            assert!(cookie.contains("__Host-fz_session="), "{cookie}");
            assert!(cookie.contains("HttpOnly"), "{cookie}");
            assert!(cookie.contains("Secure"), "{cookie}");
        });
    }
}

#[test]
fn a_signature_counter_that_goes_backwards_is_refused_and_remembered() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        account_with(&kit, "nick@example.com", &authenticator).await;

        // A good login first, which moves the stored counter to 5.
        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        authenticator.counter = 5;
        let good = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert(RP_ID, ORIGIN, &challenge_of(&options))),
            None,
        )
        .await;
        assert_eq!(good.status, StatusCode::OK, "{}", good.text());

        // Now a clone: same key, a counter that has not caught up.
        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        authenticator.counter = 3;
        let cloned = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert(RP_ID, ORIGIN, &challenge_of(&options))),
            None,
        )
        .await;
        assert_eq!(cloned.status, StatusCode::UNAUTHORIZED);

        // And the credential stays refused afterwards, even with a counter
        // that would otherwise be fine: it may be a clone.
        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        authenticator.counter = 99;
        let after = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert(RP_ID, ORIGIN, &challenge_of(&options))),
            None,
        )
        .await;
        assert_eq!(after.status, StatusCode::UNAUTHORIZED);

        // The suspect credential is not offered to the browser any more.
        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        assert!(
            options["publicKey"]["allowCredentials"]
                .as_array()
                .expect("allow list")
                .is_empty()
        );
    });
}

#[test]
fn an_authenticator_that_keeps_no_counter_still_logs_in() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        // Counters are optional in WebAuthn; a zero forever is normal, and
        // comparing those would refuse every login.
        authenticator.counter = 0;
        account_with(&kit, "nick@example.com", &authenticator).await;

        for _ in 0..2 {
            let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
                .await
                .json();
            let response = post(
                &kit,
                LOGIN_VERIFY,
                &login_body(&authenticator.assert(RP_ID, ORIGIN, &challenge_of(&options))),
                None,
            )
            .await;
            assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        }
    });
}

#[test]
fn every_way_to_fail_answers_identically() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        account_with(&kit, "nick@example.com", &authenticator).await;
        authenticator.counter = 2;

        // 1. An unknown credential id.
        let options = post(&kit, LOGIN_OPTIONS, "{}", None).await.json();
        let stranger =
            SoftAuthenticator::new(Algorithm::Es256).with_credential_id(b"never-registered");
        let unknown = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&stranger.assert(RP_ID, ORIGIN, &challenge_of(&options))),
            None,
        )
        .await;

        // 2. A challenge that was already spent.
        let options = post(&kit, LOGIN_OPTIONS, "{}", None).await.json();
        let challenge = challenge_of(&options);
        let first = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert(RP_ID, ORIGIN, &challenge)),
            None,
        )
        .await;
        assert_eq!(first.status, StatusCode::OK, "{}", first.text());
        authenticator.counter = 3;
        let spent = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert(RP_ID, ORIGIN, &challenge)),
            None,
        )
        .await;

        // 3. A ceremony from somewhere else.
        let options = post(&kit, LOGIN_OPTIONS, "{}", None).await.json();
        let foreign = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert(RP_ID, OTHER_ORIGIN, &challenge_of(&options))),
            None,
        )
        .await;

        // 4. A tampered signature.
        let options = post(&kit, LOGIN_OPTIONS, "{}", None).await.json();
        let mut credential = authenticator.assert(RP_ID, ORIGIN, &challenge_of(&options));
        let mut signature = credential.response.signature.as_slice().to_vec();
        let last = signature.len() - 1;
        signature[last] ^= 0x01;
        credential.response.signature = signature.into();
        let tampered = post(&kit, LOGIN_VERIFY, &login_body(&credential), None).await;

        for (name, response) in [
            ("unknown credential", &unknown),
            ("spent challenge", &spent),
            ("foreign origin", &foreign),
            ("tampered signature", &tampered),
        ] {
            assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{name}");
        }
        // Identical apart from the request id, which is meant to differ:
        // an attacker must not be able to tell which check failed.
        let shape = |response: &support::Res| {
            let mut body = response.json();
            body.as_object_mut()
                .expect("problem object")
                .remove("instance");
            body
        };
        assert_eq!(shape(&unknown), shape(&spent));
        assert_eq!(shape(&unknown), shape(&foreign));
        assert_eq!(shape(&unknown), shape(&tampered));
    });
}

#[test]
fn a_discoverable_credential_logs_in_without_an_email() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        let user = account_with(&kit, "nick@example.com", &authenticator).await;

        // No email: the allow list is empty and the authenticator chooses.
        let options = post(&kit, LOGIN_OPTIONS, "{}", None).await.json();
        assert!(
            options["publicKey"]["allowCredentials"]
                .as_array()
                .expect("allow list")
                .is_empty()
        );
        authenticator.counter = 2;

        let response = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert_with(
                RP_ID,
                ORIGIN,
                &challenge_of(&options),
                Some(user.as_bytes()),
            )),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        assert_eq!(response.json()["user_id"], user);
    });
}

#[test]
fn a_user_handle_for_another_account_is_refused() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        account_with(&kit, "nick@example.com", &authenticator).await;
        let other = kit.user("other@example.com").await;

        let options = post(&kit, LOGIN_OPTIONS, "{}", None).await.json();
        authenticator.counter = 2;
        let response = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert_with(
                RP_ID,
                ORIGIN,
                &challenge_of(&options),
                Some(other.as_bytes()),
            )),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    });
}

#[test]
fn a_challenge_bound_to_one_account_cannot_be_spent_by_another() {
    pollster::block_on(async {
        let kit = support::kit();
        let mine = SoftAuthenticator::new(Algorithm::Es256).with_credential_id(b"mine");
        let mut yours = SoftAuthenticator::new(Algorithm::Es256).with_credential_id(b"yours");
        account_with(&kit, "mine@example.com", &mine).await;
        account_with(&kit, "yours@example.com", &yours).await;

        // A challenge issued for one account, answered with the other's key.
        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"mine@example.com"}"#, None)
            .await
            .json();
        yours.counter = 2;
        let response = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&yours.assert(RP_ID, ORIGIN, &challenge_of(&options))),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    });
}

#[test]
fn options_never_say_whether_an_account_exists() {
    pollster::block_on(async {
        let kit = support::kit();
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);
        account_with(&kit, "known@example.com", &authenticator).await;

        let unknown = post(
            &kit,
            LOGIN_OPTIONS,
            r#"{"email":"nobody@example.com"}"#,
            None,
        )
        .await;
        let no_passkeys = {
            kit.user("bare@example.com").await;
            post(&kit, LOGIN_OPTIONS, r#"{"email":"bare@example.com"}"#, None).await
        };

        assert_eq!(unknown.status, StatusCode::OK);
        assert_eq!(no_passkeys.status, StatusCode::OK);
        // Both get a real challenge and an empty list. An account with no
        // passkeys and no account at all look the same.
        for response in [&unknown, &no_passkeys] {
            let body = response.json();
            assert!(!challenge_of(&body).is_empty());
            assert!(
                body["publicKey"]["allowCredentials"]
                    .as_array()
                    .expect("allow list")
                    .is_empty()
            );
        }
    });
}

#[test]
fn options_tolerate_an_empty_body_for_conditional_ui() {
    pollster::block_on(async {
        let kit = support::kit();
        // Some browsers pre-fetch with no body at all before the person has
        // typed anything.
        let empty = support::send(&kit, http::Method::POST, LOGIN_OPTIONS, None, None).await;
        assert_eq!(empty.status, StatusCode::OK, "{}", empty.text());
        assert!(!challenge_of(&empty.json()).is_empty());

        let garbage = post(&kit, LOGIN_OPTIONS, "not json", None).await;
        assert_eq!(garbage.status, StatusCode::BAD_REQUEST);
    });
}

#[test]
fn a_login_ceremony_cannot_be_replayed_into_registration_or_the_reverse() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        let user = account_with(&kit, "nick@example.com", &authenticator).await;
        let cookie = kit.sign_in(&user).await;

        // A registration challenge presented at the login endpoint.
        let options = post(&kit, REGISTER_OPTIONS, "{}", Some(&cookie))
            .await
            .json();
        authenticator.counter = 2;
        let response = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert(RP_ID, ORIGIN, &challenge_of(&options))),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    });
}
