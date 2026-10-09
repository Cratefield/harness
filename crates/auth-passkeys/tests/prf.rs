//! Issue #756: the PRF extension. The salts a login hands out, what each
//! ceremony shows about whether the passkey can answer the extension at
//! all, and the rule that the extension's *output* is never accepted or
//! stored — a body carrying one is refused before anything is read.

mod support;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use http::{Method, StatusCode};
use serde_json::{Value, json};
use support::{Algorithm, ORIGIN, RP_ID, SoftAuthenticator, challenge_of, post, send};

const REGISTER_OPTIONS: &str = "/v1/auth-passkeys/register/options";
const REGISTER_VERIFY: &str = "/v1/auth-passkeys/register/verify";
const LOGIN_OPTIONS: &str = "/v1/auth-passkeys/login/options";
const LOGIN_VERIFY: &str = "/v1/auth-passkeys/login/verify";
const CREDENTIALS: &str = "/v1/auth-passkeys/credentials";
const PRF: &str = "/v1/auth-passkeys/passkeys/prf";
const PROBLEM: &str = "https://test.example/problems/auth/passkey-prf-output-rejected";

fn register_body(credential: &webauthn_rs_proto::RegisterPublicKeyCredential) -> String {
    json!({ "credential": credential, "label": "key" }).to_string()
}

fn login_body(credential: &webauthn_rs_proto::PublicKeyCredential) -> String {
    json!({ "credential": credential }).to_string()
}

/// The verify body with `clientExtensionResults.prf` set to `prf` — the
/// spelling a real browser sends. The serialised `extensions` key goes
/// first: the wire structs alias the two names, and serde refuses both at
/// once.
fn body_with_client_prf(credential: &impl serde::Serialize, prf: Value) -> String {
    let mut value = json!({ "credential": credential });
    value["credential"]
        .as_object_mut()
        .expect("credential object")
        .remove("extensions");
    value["credential"]["clientExtensionResults"] = prf;
    value.to_string()
}

/// The bytes of a base64url field.
fn decoded(field: &Value, at: &str) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(field.as_str().unwrap_or_else(|| panic!("no {at}")))
        .unwrap_or_else(|err| panic!("{at} is not base64url: {err}"))
}

/// The `auth_passkeys_prf` row for a credential id: (salt, state).
async fn prf_row(kit: &support::Kit, credential_id: &[u8]) -> (Vec<u8>, String) {
    let rows = kit
        .db
        .query(&cratefield_core::Statement::with_values(
            "SELECT salt, prf FROM auth_passkeys_prf WHERE credential_id = ?".to_owned(),
            vec![credential_id.to_vec().into()],
        ))
        .await
        .expect("prf row reads");
    let row = rows.first().expect("the prf row exists");
    (
        row.get::<Vec<u8>>("salt").expect("salt"),
        row.get::<String>("prf").expect("prf"),
    )
}

/// A registration answer to `challenge`, from an authenticator with its
/// own credential id, for tests that decorate the body before it is sent.
fn registration_for(challenge: &[u8], id: &[u8]) -> webauthn_rs_proto::RegisterPublicKeyCredential {
    SoftAuthenticator::new(Algorithm::Es256)
        .with_credential_id(id)
        .register(RP_ID, ORIGIN, challenge)
}

/// Registers `authenticator` to a fresh account and returns (user id,
/// cookie, verify response).
async fn register_to_fresh_account(
    kit: &support::Kit,
    email: &str,
    authenticator: &SoftAuthenticator,
) -> (String, String, Value) {
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
    (user, cookie, stored.json())
}

#[test]
fn registration_options_ask_for_prf() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        let options = post(&kit, REGISTER_OPTIONS, "{}", Some(&cookie))
            .await
            .json();
        // The whole extension object, exactly: an empty prf input. The
        // salts are this service's to choose, per assertion, at login.
        assert_eq!(options["publicKey"]["extensions"], json!({ "prf": {} }));
    });
}

#[test]
fn login_options_hand_one_salt_to_a_single_credential() {
    pollster::block_on(async {
        let kit = support::kit();
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);
        register_to_fresh_account(&kit, "nick@example.com", &authenticator).await;

        // The row was created at registration; delete it to prove the
        // options call recreates one lazily for a credential that
        // predates the extension.
        kit.db
            .execute(&cratefield_core::Statement::new(
                "DELETE FROM auth_passkeys_prf".to_owned(),
            ))
            .await
            .expect("delete applies");
        assert_eq!(support::count(&kit, "auth_passkeys_prf"), 0);

        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        let first = decoded(
            &options["publicKey"]["extensions"]["prf"]["eval"]["first"],
            "salt",
        );
        assert_eq!(first.len(), 32, "the salt is 32 bytes");
        assert_eq!(
            support::count(&kit, "auth_passkeys_prf"),
            1,
            "the options call created the salt row"
        );

        // The same salt again: it is per credential, not per call.
        let again = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        assert_eq!(
            again["publicKey"]["extensions"]["prf"]["eval"]["first"],
            options["publicKey"]["extensions"]["prf"]["eval"]["first"]
        );
        let (stored, state) = prf_row(&kit, &authenticator.credential_id).await;
        assert_eq!(stored, first, "the handed-out salt is the stored one");
        assert_eq!(state, "unknown");
    });
}

#[test]
fn login_options_key_every_credential_by_its_id_when_there_are_several() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let mut ids = Vec::new();
        for credential_id in [b"first-key".as_slice(), b"second-key".as_slice()] {
            let options = post(&kit, REGISTER_OPTIONS, "{}", Some(&cookie))
                .await
                .json();
            let stored = post(
                &kit,
                REGISTER_VERIFY,
                &register_body(&registration_for(&challenge_of(&options), credential_id)),
                Some(&cookie),
            )
            .await;
            assert_eq!(stored.status, StatusCode::OK, "{}", stored.text());
            ids.push(credential_id.to_vec());
        }

        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        let by_credential = options["publicKey"]["extensions"]["prf"]["evalByCredential"]
            .as_object()
            .expect("evalByCredential object");
        assert_eq!(by_credential.len(), 2);
        // Keyed by the base64url credential id, the WebAuthn JSON form,
        // each with its own salt.
        for (key, value) in by_credential {
            let id = Base64UrlUnpadded::decode_vec(key).expect("credential id key");
            assert!(ids.contains(&id), "{key} is not one of the allowed ids");
            assert_eq!(decoded(&value["first"], "salt").len(), 32);
        }
        // And no bare `eval` rides along.
        assert!(options["publicKey"]["extensions"]["prf"]["eval"].is_null());
    });
}

#[test]
fn a_discoverable_login_has_no_prf_extension() {
    pollster::block_on(async {
        let kit = support::kit();
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);
        register_to_fresh_account(&kit, "nick@example.com", &authenticator).await;

        // No email: this service cannot know which credential will answer,
        // so there is no salt to evaluate with and no extension at all.
        let options = post(&kit, LOGIN_OPTIONS, "{}", None).await.json();
        assert!(options["publicKey"]["extensions"].is_null());

        // An address with no passkey looks the same.
        let unknown = post(&kit, LOGIN_OPTIONS, r#"{"email":"bare@example.com"}"#, None)
            .await
            .json();
        assert!(unknown["publicKey"]["extensions"].is_null());
    });
}

#[test]
fn a_signed_hmac_secret_answer_records_supported() {
    pollster::block_on(async {
        let kit = support::kit();
        // The CBOR vector: authenticator data with the ED flag set and the
        // extension map answering `hmac-secret: true` — CTAP2.1's signed
        // word that the passkey can evaluate PRF.
        let authenticator = SoftAuthenticator::new(Algorithm::Es256).with_hmac_secret();
        let (_, _, stored) =
            register_to_fresh_account(&kit, "nick@example.com", &authenticator).await;

        assert_eq!(stored["prf"], "supported");
        let salt = decoded(&stored["prfSalt"], "prfSalt");
        assert_eq!(salt.len(), 32);

        let (stored_salt, state) = prf_row(&kit, &authenticator.credential_id).await;
        assert_eq!(stored_salt, salt);
        assert_eq!(state, "supported");
    });
}

#[test]
fn a_failed_prf_write_does_not_lose_the_registration() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let options = post(&kit, REGISTER_OPTIONS, "{}", Some(&cookie))
            .await
            .json();
        // The table is gone, so the salt write fails after the credential
        // has landed. The ceremony must still succeed: a refusal here would
        // leave the client retrying into `passkey-already-registered`.
        kit.db
            .execute(&cratefield_core::Statement::new(
                "DROP TABLE auth_passkeys_prf",
            ))
            .await
            .expect("the prf table drops");
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);
        let stored = post(
            &kit,
            REGISTER_VERIFY,
            &register_body(&authenticator.register(RP_ID, ORIGIN, &challenge_of(&options))),
            Some(&cookie),
        )
        .await;
        assert_eq!(stored.status, StatusCode::OK, "{}", stored.text());

        // Nothing was persisted, so there is nothing to report: the pair is
        // omitted rather than named with values no row holds.
        let body = stored.json();
        assert!(body["prf"].is_null());
        assert!(body["prfSalt"].is_null());

        // The credential itself is stored.
        let credentials = send(&kit, Method::GET, CREDENTIALS, None, Some(&cookie))
            .await
            .json();
        assert_eq!(
            credentials["passkeys"].as_array().expect("passkeys").len(),
            1
        );
    });
}

#[test]
fn a_client_enabled_report_alone_records_supported() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        // No extension output in the authenticator data: the only signal
        // is the browser's, unsigned.
        let options = post(&kit, REGISTER_OPTIONS, "{}", Some(&cookie))
            .await
            .json();
        let credential = registration_for(&challenge_of(&options), b"reporting-key");
        let stored = post(
            &kit,
            REGISTER_VERIFY,
            &body_with_client_prf(&credential, json!({ "prf": { "enabled": true } })),
            Some(&cookie),
        )
        .await;
        assert_eq!(stored.status, StatusCode::OK, "{}", stored.text());
        assert_eq!(stored.json()["prf"], "supported");

        let (_, state) = prf_row(&kit, &credential.raw_id).await;
        assert_eq!(state, "supported");
    });
}

#[test]
fn no_signal_at_creation_stays_unknown() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        // No extension outputs and no client report. Some authenticators
        // (Samsung Pass among them) answer only on the next sign-in, so
        // absence of evidence at creation is not evidence of absence.
        let options = post(&kit, REGISTER_OPTIONS, "{}", Some(&cookie))
            .await
            .json();
        let quiet = post(
            &kit,
            REGISTER_VERIFY,
            &register_body(&registration_for(&challenge_of(&options), b"quiet-key")),
            Some(&cookie),
        )
        .await;
        assert_eq!(quiet.status, StatusCode::OK, "{}", quiet.text());
        assert_eq!(quiet.json()["prf"], "unknown");

        // An explicit `enabled: false` is the same: never `unsupported` at
        // registration, whatever the report says.
        let options = post(&kit, REGISTER_OPTIONS, "{}", Some(&cookie))
            .await
            .json();
        let reported = post(
            &kit,
            REGISTER_VERIFY,
            &body_with_client_prf(
                &registration_for(&challenge_of(&options), b"declining-key"),
                json!({ "prf": { "enabled": false } }),
            ),
            Some(&cookie),
        )
        .await;
        assert_eq!(reported.status, StatusCode::OK, "{}", reported.text());
        assert_eq!(reported.json()["prf"], "unknown");
    });
}

#[test]
fn a_registration_without_prf_still_works() {
    pollster::block_on(async {
        let kit = support::kit();
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);
        let (_, cookie, stored) =
            register_to_fresh_account(&kit, "nick@example.com", &authenticator).await;

        // The PRF fields are additive, and present even with no PRF
        // anywhere in the ceremony.
        assert_eq!(decoded(&stored["prfSalt"], "prfSalt").len(), 32);

        let listed = send(&kit, Method::GET, CREDENTIALS, None, Some(&cookie))
            .await
            .json();
        assert_eq!(listed["passkeys"].as_array().expect("passkeys").len(), 1);
    });
}

#[test]
fn a_registration_presenting_a_prf_result_is_refused_and_stores_nothing() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        let options = post(&kit, REGISTER_OPTIONS, "{}", Some(&cookie))
            .await
            .json();
        let challenge = challenge_of(&options);
        let credential = registration_for(&challenge, b"probing-key");
        // Distinctive output bytes, so the scan below can prove they went
        // nowhere.
        let results = json!({ "prf": { "enabled": true, "results": {
            "first": Base64UrlUnpadded::encode_string(&[0xAB; 32])
        } } });

        let refused = post(
            &kit,
            REGISTER_VERIFY,
            &body_with_client_prf(&credential, results),
            Some(&cookie),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{}",
            refused.text()
        );
        assert_eq!(refused.json()["type"], PROBLEM);

        // Nothing about the ceremony was written...
        assert_eq!(support::count(&kit, "auth_passkeys_prf"), 0);
        assert_eq!(support::count(&kit, "credentials"), 0);

        // ...and the challenge was not spent: the same ceremony without
        // the result registers.
        let clean = post(
            &kit,
            REGISTER_VERIFY,
            &register_body(&credential),
            Some(&cookie),
        )
        .await;
        assert_eq!(clean.status, StatusCode::OK, "{}", clean.text());
    });
}

#[test]
fn a_login_presenting_a_prf_result_is_refused_and_issues_no_session() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        register_to_fresh_account(&kit, "nick@example.com", &authenticator).await;

        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        let challenge = challenge_of(&options);
        authenticator.counter = 2;
        let credential = authenticator.assert(RP_ID, ORIGIN, &challenge);
        let results = json!({ "prf": { "enabled": true, "results": {
            "first": Base64UrlUnpadded::encode_string(&[0xCD; 32]),
            "second": Base64UrlUnpadded::encode_string(&[0xEF; 32])
        } } });

        let refused = post(
            &kit,
            LOGIN_VERIFY,
            &body_with_client_prf(&credential, results),
            None,
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{}",
            refused.text()
        );
        assert_eq!(refused.json()["type"], PROBLEM);
        assert!(
            refused.set_cookie().is_none(),
            "a session was issued anyway"
        );
        // The harness sign-in created one session; the refusal added none.
        assert_eq!(support::count(&kit, "sessions"), 1);

        // Nothing was written, and the challenge was not spent.
        let (_, state) = prf_row(&kit, &authenticator.credential_id).await;
        assert_eq!(state, "unknown", "the refusal did not touch the state");

        // The same assertion without the result signs in.
        let clean = post(&kit, LOGIN_VERIFY, &login_body(&credential), None).await;
        assert_eq!(clean.status, StatusCode::OK, "{}", clean.text());
        assert!(clean.set_cookie().is_some());
    });
}

#[test]
fn the_login_report_updates_the_capability_and_supported_is_sticky() {
    pollster::block_on(async {
        let kit = support::kit();
        let mut authenticator = SoftAuthenticator::new(Algorithm::Es256);
        register_to_fresh_account(&kit, "nick@example.com", &authenticator).await;
        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        let salt = decoded(
            &options["publicKey"]["extensions"]["prf"]["eval"]["first"],
            "salt",
        );

        // A redacted `enabled: true` records `supported`.
        authenticator.counter = 2;
        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        let login = post(
            &kit,
            LOGIN_VERIFY,
            &body_with_client_prf(
                &authenticator.assert(RP_ID, ORIGIN, &challenge_of(&options)),
                json!({ "prf": { "enabled": true } }),
            ),
            None,
        )
        .await;
        assert_eq!(login.status, StatusCode::OK, "{}", login.text());

        // The one row holds the server's salt — the same one the options
        // call handed out, not the client's — and nothing else: there is
        // no column an output could land in, and the credential row still
        // holds exactly the key material the registration signed.
        let (stored_salt, state) = prf_row(&kit, &authenticator.credential_id).await;
        assert_eq!(stored_salt, salt);
        assert_eq!(state, "supported");
        let stored =
            cratefield_auth_core::passkey_by_credential_id(&*kit.db, &authenticator.credential_id)
                .await
                .expect("credential reads")
                .expect("credential exists");
        assert_eq!(
            stored.passkey_credential_id.as_ref().expect("id").0,
            authenticator.credential_id
        );
        assert_eq!(
            stored.passkey_public_key_cose.as_ref().expect("key").0,
            authenticator.cose_key()
        );

        // A later report of `false` does not downgrade it.
        authenticator.counter = 3;
        let options = post(&kit, LOGIN_OPTIONS, r#"{"email":"nick@example.com"}"#, None)
            .await
            .json();
        let downgraded = post(
            &kit,
            LOGIN_VERIFY,
            &body_with_client_prf(
                &authenticator.assert(RP_ID, ORIGIN, &challenge_of(&options)),
                json!({ "prf": { "enabled": false } }),
            ),
            None,
        )
        .await;
        assert_eq!(downgraded.status, StatusCode::OK, "{}", downgraded.text());
        let (_, state) = prf_row(&kit, &authenticator.credential_id).await;
        assert_eq!(state, "supported", "supported is sticky");
    });
}

#[test]
fn the_capability_route_lists_salt_and_state_and_needs_a_session() {
    pollster::block_on(async {
        let kit = support::kit();
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);
        let (user, _, stored) =
            register_to_fresh_account(&kit, "nick@example.com", &authenticator).await;
        let cookie = kit.sign_in(&user).await;

        // Signed out, the one 401 every signed-out caller sees.
        let denied = send(&kit, Method::GET, PRF, None, None).await;
        assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            denied.json()["type"],
            "https://test.example/problems/auth/session-invalid"
        );

        let listed = send(&kit, Method::GET, PRF, None, Some(&cookie))
            .await
            .json();
        let passkeys = listed["passkeys"].as_array().expect("passkeys");
        assert_eq!(passkeys.len(), 1);
        assert_eq!(
            passkeys[0]["credentialId"],
            Base64UrlUnpadded::encode_string(&authenticator.credential_id)
        );
        assert_eq!(passkeys[0]["prf"], "unknown");
        // The salt is the one the registration handed back, and it does
        // not change between calls.
        assert_eq!(passkeys[0]["prfSalt"], stored["prfSalt"]);
        let again = send(&kit, Method::GET, PRF, None, Some(&cookie))
            .await
            .json();
        assert_eq!(again["passkeys"][0]["prfSalt"], stored["prfSalt"]);
    });
}

#[test]
fn deleting_a_passkey_deletes_its_salt_row() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        let mut ids = Vec::new();
        for credential_id in [b"kept-key".as_slice(), b"gone-key".as_slice()] {
            let options = post(&kit, REGISTER_OPTIONS, "{}", Some(&cookie))
                .await
                .json();
            let stored = post(
                &kit,
                REGISTER_VERIFY,
                &register_body(&registration_for(&challenge_of(&options), credential_id)),
                Some(&cookie),
            )
            .await;
            assert_eq!(stored.status, StatusCode::OK, "{}", stored.text());
            ids.push(stored.json()["id"].as_str().expect("id").to_owned());
        }
        assert_eq!(support::count(&kit, "auth_passkeys_prf"), 2);

        let deleted = send(
            &kit,
            Method::DELETE,
            &format!("{CREDENTIALS}/{}", ids[1]),
            None,
            Some(&cookie),
        )
        .await;
        assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text());
        assert_eq!(
            support::count(&kit, "auth_passkeys_prf"),
            1,
            "the salt row went with its credential"
        );
    });
}
