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
fn a_forged_assertion_cannot_disable_someone_elses_passkey() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        account_with(&kit, "victim@example.com", &authenticator).await;

        // Everything here is public: `login/options` hands out the account's
        // credential ids, the rpIdHash is a hash of a published domain, and
        // the flags and counter are the attacker's to choose. The only thing
        // they cannot produce is a signature.
        let options = post(
            &kit,
            LOGIN_OPTIONS,
            r#"{"email":"victim@example.com"}"#,
            None,
        )
        .await
        .json();
        let mut forged =
            SoftAuthenticator::new(Algorithm::Eddsa).with_credential_id(b"a-test-credential-id");
        forged.counter = 1;
        let mut credential = forged.assert(RP_ID, ORIGIN, &challenge_of(&options));
        credential.response.signature = vec![0u8; 64].into();

        let attack = post(&kit, LOGIN_VERIFY, &login_body(&credential), None).await;
        assert_eq!(attack.status, StatusCode::UNAUTHORIZED);

        // The victim must still be able to log in. If an unverified assertion
        // can mark a credential suspect, one unauthenticated request locks
        // every counter-keeping passkey out for good, with no way back.
        let options = post(
            &kit,
            LOGIN_OPTIONS,
            r#"{"email":"victim@example.com"}"#,
            None,
        )
        .await
        .json();
        assert_eq!(
            options["publicKey"]["allowCredentials"]
                .as_array()
                .expect("allow list")
                .len(),
            1,
            "the forged assertion took the credential out of the allow list"
        );
        authenticator.counter = 2;
        let legitimate = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert(RP_ID, ORIGIN, &challenge_of(&options))),
            None,
        )
        .await;
        assert_eq!(
            legitimate.status,
            StatusCode::OK,
            "a forged assertion locked the victim out: {}",
            legitimate.text()
        );
    });
}

#[test]
fn a_disabled_account_cannot_log_in() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        let user = account_with(&kit, "nick@example.com", &authenticator).await;
        kit.disable(&user).await;

        let options = post(&kit, LOGIN_OPTIONS, "{}", None).await.json();
        authenticator.counter = 2;
        let response = post(
            &kit,
            LOGIN_VERIFY,
            &login_body(&authenticator.assert(RP_ID, ORIGIN, &challenge_of(&options))),
            None,
        )
        .await;
        // The account status is the one administrative kill switch; a login
        // method that ignores it makes it useless.
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert!(response.set_cookie().is_none());
    });
}

#[test]
fn a_counter_that_drops_to_zero_is_still_a_regression() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        authenticator.counter = 5;
        account_with(&kit, "nick@example.com", &authenticator).await;

        // The spec's rule is "if either value is non-zero, the presented one
        // must be greater". A stored 5 and a presented 0 is a regression, and
        // storing that 0 would switch clone detection off for good.
        let options = post(&kit, LOGIN_OPTIONS, "{}", None).await.json();
        authenticator.counter = 0;
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
fn an_account_with_no_passkeys_looks_like_no_account_at_all() {
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
        // Both get a real challenge and an empty list, so these two are
        // indistinguishable. This is **not** full enumeration resistance: an
        // account that does have a passkey answers with its credential ids,
        // which is inherent to the non-discoverable flow. The challenge
        // budget is what bounds how many addresses a caller can ask about.
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
fn the_endpoints_anyone_can_call_are_rate_limited() {
    pollster::block_on(async {
        let kit = support::kit_rate_limited();
        // Both endpoints are unauthenticated, and every options call writes
        // a challenge row, so an unlimited one is a free write amplifier as
        // well as an enumeration surface.
        for (path, body) in [
            (LOGIN_OPTIONS, "{}"),
            (LOGIN_VERIFY, r#"{"credential":{}}"#),
        ] {
            let response = post(&kit, path, body, None).await;
            assert_eq!(
                response.status,
                StatusCode::TOO_MANY_REQUESTS,
                "{path} was not limited"
            );
        }
        // Nothing was written on the way to the refusal.
        assert_eq!(support::count(&kit, "single_use_tokens"), 0);
    });
}

#[test]
fn the_challenge_budget_allows_a_person_and_refuses_a_sweep() {
    pollster::block_on(async {
        // No rate limiter wired: the budget is what refuses, which is the
        // deployment shape the whole fix is for.
        let kit = support::kit_without_limiter();
        // Five challenges for one address in a minute (`budget::CHALLENGE_BUDGET_PER_EMAIL`)
        // — a person retrying, or two devices at once — all arrive.
        for _ in 0..5 {
            let response = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None).await;
            assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        }

        // The sixth is refused, and the refusal is the project's 429 with a
        // Retry-After, not the ceremony-failed answer a browser cannot
        // distinguish from a broken passkey.
        let refused = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None).await;
        assert_eq!(
            refused.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{}",
            refused.text()
        );
        assert_eq!(
            refused
                .headers
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("60"),
            "{:?}",
            refused.headers
        );

        // Nothing was stored for the refused call: the cap bounds the write
        // amplifier, not only the oracle.
        assert_eq!(support::count(&kit, "single_use_tokens"), 5);

        // A window later (`CHALLENGE_BUDGET_WINDOW_SECS`) the same address
        // gets a real challenge again.
        kit.clock.advance_secs(61);
        let after = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None).await;
        assert_eq!(after.status, StatusCode::OK, "{}", after.text());
        assert_eq!(support::count(&kit, "single_use_tokens"), 6);
    });
}

#[test]
fn the_challenge_budget_is_per_client_address_across_every_address_it_names() {
    pollster::block_on(async {
        let kit = support::kit_without_limiter();
        // Thirty different addresses from one client (`CHALLENGE_BUDGET_PER_IP`):
        // no single address comes near its own budget, so the sweep is
        // stopped by the client-address cap and nothing else.
        for i in 0..30 {
            let body = format!(r#"{{"email":"sweep{i}@example.com"}}"#);
            let response = post(&kit, LOGIN_OPTIONS, &body, None).await;
            assert_eq!(response.status, StatusCode::OK, "{i}: {}", response.text());
        }
        let refused = post(
            &kit,
            LOGIN_OPTIONS,
            r#"{"email":"sweep30@example.com"}"#,
            None,
        )
        .await;
        assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);

        // A different client address has a budget of its own: an office's
        // other machines keep working while one is capped.
        let stranger = support::post_from(
            &kit,
            LOGIN_OPTIONS,
            r#"{"email":"sweep30@example.com"}"#,
            Some("203.0.113.9"),
        )
        .await;
        assert_eq!(stranger.status, StatusCode::OK, "{}", stranger.text());
    });
}

#[test]
fn a_budget_refusal_does_not_say_which_address_has_a_passkey() {
    pollster::block_on(async {
        let kit = support::kit_without_limiter();
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);
        account_with(&kit, "known@example.com", &authenticator).await;

        // Spend one client address's budget on addresses this test invented.
        for i in 0..30 {
            let body = format!(r#"{{"email":"probe{i}@example.com"}}"#);
            let response = post(&kit, LOGIN_OPTIONS, &body, None).await;
            assert_eq!(response.status, StatusCode::OK, "{i}: {}", response.text());
        }

        // Capped, the endpoint answers the account with a passkey, the
        // account without one, and the address nobody has, with the same
        // refusal: the budget is spent before the account lookup, so the
        // cap is not a finer-grained oracle than the endpoint it guards.
        let with_passkey = post(
            &kit,
            LOGIN_OPTIONS,
            r#"{"email":"known@example.com"}"#,
            None,
        )
        .await;
        let without = {
            kit.user("bare@example.com").await;
            post(&kit, LOGIN_OPTIONS, r#"{"email":"bare@example.com"}"#, None).await
        };
        let unknown = post(
            &kit,
            LOGIN_OPTIONS,
            r#"{"email":"nobody@example.com"}"#,
            None,
        )
        .await;

        for (name, response) in [
            ("with passkey", &with_passkey),
            ("without", &without),
            ("unknown", &unknown),
        ] {
            assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS, "{name}");
        }
        let shape = |response: &support::Res| {
            let mut body = response.json();
            body.as_object_mut()
                .expect("problem object")
                .remove("instance");
            body
        };
        assert_eq!(shape(&with_passkey), shape(&without));
        assert_eq!(shape(&with_passkey), shape(&unknown));
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

/// A verified assertion issues a session, so a form on another site must
/// not be able to complete one (issue #439): refused on arrival, before
/// the limiter or the body is looked at. A same-origin request still
/// reaches the handler's own logic — the same malformed body answers the
/// route's ordinary validation failure there, not the cross-site refusal.
#[test]
fn a_cross_site_assertion_cannot_sign_anyone_in() {
    pollster::block_on(async {
        let kit = support::kit();

        let cross_site = support::post_with_headers(
            &kit,
            LOGIN_VERIFY,
            r#"{"credential":{}}"#,
            &[("host", "auth.factory0.ventures"), ("origin", OTHER_ORIGIN)],
        )
        .await;
        assert_eq!(
            cross_site.status,
            StatusCode::FORBIDDEN,
            "{}",
            cross_site.text()
        );
        assert_eq!(
            cross_site.json()["type"],
            "https://factory0.ventures/problems/auth/cross-site-request"
        );
        assert!(
            cross_site.set_cookie().is_none(),
            "the cross-site assertion signed somebody in"
        );
        assert_eq!(
            support::count(&kit, "sessions"),
            0,
            "a session was issued anyway"
        );

        // The other signal the guard reads, with no `Origin` at all — a
        // scripted form POST still carries fetch metadata.
        let fetch_metadata = support::post_with_headers(
            &kit,
            LOGIN_VERIFY,
            r#"{"credential":{}}"#,
            &[
                ("host", "auth.factory0.ventures"),
                ("sec-fetch-site", "cross-site"),
            ],
        )
        .await;
        assert_eq!(
            fetch_metadata.status,
            StatusCode::FORBIDDEN,
            "{}",
            fetch_metadata.text()
        );
        assert_eq!(
            fetch_metadata.json()["type"],
            "https://factory0.ventures/problems/auth/cross-site-request"
        );

        // A same-origin request — every header a real browser sends — gets
        // past the guard and into the handler: this body is not a
        // credential, so the answer is the route's ordinary validation
        // failure rather than the refusal. The identical body from another
        // site never reaches that check.
        let own = support::post_with_headers(
            &kit,
            LOGIN_VERIFY,
            "not json",
            &[
                ("host", "auth.factory0.ventures"),
                ("origin", ORIGIN),
                ("sec-fetch-site", "same-origin"),
            ],
        )
        .await;
        assert_eq!(own.status, StatusCode::BAD_REQUEST, "{}", own.text());
        assert_eq!(
            own.json()["type"],
            "https://factory0.ventures/problems/validation-failed"
        );
        assert!(own.set_cookie().is_none());

        let same_body_cross_site = support::post_with_headers(
            &kit,
            LOGIN_VERIFY,
            "not json",
            &[("host", "auth.factory0.ventures"), ("origin", OTHER_ORIGIN)],
        )
        .await;
        assert_eq!(
            same_body_cross_site.status,
            StatusCode::FORBIDDEN,
            "{}",
            same_body_cross_site.text()
        );
    });
}
