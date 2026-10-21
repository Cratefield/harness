//! Issue #914 acceptance: passkey-first sign-up. A new account is made by a
//! passkey alone, with no email address; the terms are accepted in the same
//! step; the answer carries recovery codes, shown once; and the account can
//! sign back in with that passkey. Anonymous requests are rate-limited.

mod support;

use http::StatusCode;
use serde_json::json;
use support::{Algorithm, ORIGIN, RP_ID, SoftAuthenticator, challenge_of, post};

const OPTIONS: &str = "/v1/auth-passkeys/signup/options";
const VERIFY: &str = "/v1/auth-passkeys/signup/verify";
const LOGIN_OPTIONS: &str = "/v1/auth-passkeys/login/options";
const LOGIN_VERIFY: &str = "/v1/auth-passkeys/login/verify";

fn terms(accepted: bool, version: &str) -> serde_json::Value {
    json!({ "accepted": accepted, "terms_version": version, "privacy_version": version })
}

/// Options, a passkey made against them, and the verify body that carries it.
async fn signup_body(
    kit: &support::Kit,
    authenticator: &SoftAuthenticator,
    accept: serde_json::Value,
) -> (Option<String>, String) {
    let options = post(kit, OPTIONS, "{}", None).await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.text());
    let json = options.json();
    let credential = authenticator.register(RP_ID, ORIGIN, &challenge_of(&json));
    let body = json!({ "credential": credential, "label": "laptop", "terms": accept });
    (
        Some(json["publicKey"]["user"]["id"].to_string()),
        body.to_string(),
    )
}

#[test]
fn a_passkey_makes_an_account_with_no_email_and_the_terms_it_accepted() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        let (_, body) = signup_body(&kit, &authenticator, terms(true, "2026-10")).await;
        let res = post(&kit, VERIFY, &body, None).await;
        assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
        let json = res.json();
        assert_eq!(json["email_required"], false);
        assert_eq!(json["recovery_codes"].as_array().expect("codes").len(), 10);
        assert!(res.set_cookie().is_some(), "a session is issued");
        let sub = json["sub"].as_str().expect("sub").to_owned();

        // The account can sign back in with the passkey alone.
        let login_options = post(&kit, LOGIN_OPTIONS, "{}", None).await;
        assert_eq!(
            login_options.status,
            StatusCode::OK,
            "{}",
            login_options.text()
        );
        // No allow list: the authenticator names the account by its user handle.
        authenticator.counter = 2;
        let assertion = authenticator.assert_with(
            RP_ID,
            ORIGIN,
            &challenge_of(&login_options.json()),
            Some(sub.as_bytes()),
        );
        let signed_in = post(
            &kit,
            LOGIN_VERIFY,
            &json!({ "credential": assertion }).to_string(),
            None,
        )
        .await;
        assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.text());
        assert_eq!(signed_in.json()["user_id"], sub);
    });
}

#[test]
fn the_terms_must_be_accepted_at_the_current_versions() {
    pollster::block_on(async {
        let kit = support::kit();
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);
        for accept in [terms(false, "2026-10"), terms(true, "2025-01")] {
            let (_, body) = signup_body(&kit, &authenticator, accept).await;
            let res = post(&kit, VERIFY, &body, None).await;
            assert_ne!(res.status, StatusCode::CREATED, "{}", res.text());
            assert!(res.set_cookie().is_none());
        }
    });
}

#[test]
fn a_sign_up_challenge_is_spent_once() {
    pollster::block_on(async {
        let kit = support::kit();
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);
        let options = post(&kit, OPTIONS, "{}", None).await.json();
        let challenge = challenge_of(&options);
        let credential = authenticator.register(RP_ID, ORIGIN, &challenge);
        let body = json!({ "credential": credential, "terms": terms(true, "2026-10") }).to_string();
        assert_eq!(
            post(&kit, VERIFY, &body, None).await.status,
            StatusCode::CREATED
        );
        let replay = post(&kit, VERIFY, &body, None).await;
        assert_ne!(
            replay.status,
            StatusCode::CREATED,
            "a replayed challenge makes nothing"
        );
    });
}

#[test]
fn anonymous_sign_up_is_rate_limited() {
    pollster::block_on(async {
        let kit = support::kit_rate_limited();
        let res = post(&kit, OPTIONS, "{}", None).await;
        assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    });
}

/// Issue #914: anonymous sign-up passes the captcha. A request whose token the
/// captcha does not accept is refused, and no challenge is issued for it.
#[test]
fn a_sign_up_without_a_captcha_pass_is_refused() {
    pollster::block_on(async {
        let kit = support::kit_patched(support::config_pairs(), |ports| {
            ports.captcha = Some(std::sync::Arc::new(
                cratefield_testing::FakeCaptcha::with_tokens(Vec::<String>::new()),
            ));
        });
        let res = post(&kit, OPTIONS, r#"{"captchaToken":"nope"}"#, None).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    });
}

/// Issue #914 (security review): a sign-up that fails part way leaves nothing.
/// The same authenticator signing up twice makes one account, not two: the second
/// is refused on its passkey, and the batch leaves no user row behind.
#[test]
fn a_refused_sign_up_leaves_no_account_behind() {
    pollster::block_on(async {
        let kit = support::kit();
        let authenticator =
            SoftAuthenticator::new(Algorithm::Es256).with_credential_id(b"same-key");
        let (_, body) = signup_body(&kit, &authenticator, terms(true, "2026-10")).await;
        assert_eq!(
            post(&kit, VERIFY, &body, None).await.status,
            StatusCode::CREATED
        );
        let (_, body) = signup_body(&kit, &authenticator, terms(true, "2026-10")).await;
        let second = post(&kit, VERIFY, &body, None).await;
        assert_ne!(second.status, StatusCode::CREATED, "{}", second.text());
        assert_eq!(
            support::count(&kit, "users"),
            1,
            "no second account was left behind"
        );
    });
}
