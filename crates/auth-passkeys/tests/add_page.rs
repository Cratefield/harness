//! The hosted "Add a passkey" page: a signed-in person gets the ceremony,
//! a signed-out one is sent to sign in and back, and `return_to` only ever
//! points at a registered client's origin.

// `support` re-exports the soft authenticator, which this file never needs.
#![allow(unused_imports)]

mod support;

use cratefield_auth_core::{
    CLIENT_PUBLIC, ClientRedirectUriRow, ClientRow, Redacted, STATUS_ACTIVE, insert_client,
    insert_redirect_uri,
};
use http::{Method, StatusCode};
use support::{Kit, send};

const PAGE: &str = "/v1/auth-passkeys/add";

async fn register_client(kit: &Kit, redirect: &str) {
    insert_client(
        &*kit.db,
        &ClientRow {
            id: "01CLIENT".to_owned(),
            name: "App".to_owned(),
            secret_hash: Redacted(String::new()),
            previous_secret_hash: None,
            previous_hash_expires_at: None,
            kind: CLIENT_PUBLIC.to_owned(),
            status: STATUS_ACTIVE.to_owned(),
            created_at: "2026-09-07T10:00:00Z".to_owned(),
        },
    )
    .await
    .expect("client inserts");
    insert_redirect_uri(
        &*kit.db,
        &ClientRedirectUriRow {
            client_id: "01CLIENT".to_owned(),
            uri: redirect.to_owned(),
        },
    )
    .await
    .expect("redirect inserts");
}

fn kit_with_magic_link() -> Kit {
    let mut pairs = support::config_pairs();
    pairs.push((
        "AUTH_CORE_LOGIN_METHODS".to_owned(),
        "passkey,magic-link".to_owned(),
    ));
    support::kit_with(pairs)
}

#[test]
fn a_signed_in_person_gets_the_ceremony_and_the_app_to_return_to() {
    pollster::block_on(async {
        let kit = kit_with_magic_link();
        register_client(&kit, "https://app.example/auth/callback").await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        let response = send(
            &kit,
            Method::GET,
            &format!("{PAGE}?return_to=https%3A%2F%2Fapp.example%2F%3Fs%3D1"),
            None,
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK);
        let html = response.text();
        assert!(html.contains("id=\"cf-add-passkey\""), "{html}");
        assert!(
            html.contains("/v1/auth-passkeys/register/options"),
            "{html}"
        );
        assert!(html.contains("prf: {}"), "{html}");
        assert!(
            html.contains("data-return-to=\"https://app.example/?s=1\""),
            "{html}"
        );
        assert!(
            html.contains("href=\"https://app.example/?s=1#cf_passkey_error=cancelled\""),
            "{html}"
        );
        assert_eq!(
            response.headers.get(http::header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    });
}

#[test]
fn a_signed_out_person_is_sent_to_sign_in_and_back_here() {
    pollster::block_on(async {
        let kit = kit_with_magic_link();
        register_client(&kit, "https://app.example/auth/callback").await;

        let response = send(
            &kit,
            Method::GET,
            &format!("{PAGE}?return_to=https%3A%2F%2Fapp.example%2F"),
            None,
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::OK);
        let html = response.text();
        assert!(html.contains("Sign in first"), "{html}");
        assert!(!html.contains("cf-add-passkey"), "{html}");
        // The magic-link start carries this very page as its return_to.
        assert!(
            html.contains(
                "/v1/auth-magic-link/start?return_to=%2Fv1%2Fauth-passkeys%2Fadd%3Freturn_to%3D"
            ),
            "{html}"
        );
    });
}

#[test]
fn a_foreign_return_to_is_dropped_and_never_redirected_to() {
    pollster::block_on(async {
        let kit = kit_with_magic_link();
        register_client(&kit, "https://app.example/auth/callback").await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        for hostile in [
            "https%3A%2F%2Fevil.example%2F",
            "http%3A%2F%2Fapp.example%2F",
            "javascript%3Aalert(1)",
            "%2F%2Fevil.example",
        ] {
            let response = send(
                &kit,
                Method::GET,
                &format!("{PAGE}?return_to={hostile}"),
                None,
                Some(&cookie),
            )
            .await;
            assert_eq!(response.status, StatusCode::OK, "{hostile}");
            assert!(response.headers.get(http::header::LOCATION).is_none());
            let html = response.text();
            assert!(!html.contains("evil.example"), "{hostile}: {html}");
            assert!(html.contains("data-return-to=\"\""), "{hostile}: {html}");
            assert!(
                html.contains("Done, you can close this tab"),
                "{hostile}: {html}"
            );
        }
    });
}

#[test]
fn no_return_to_still_renders_the_page() {
    pollster::block_on(async {
        let kit = kit_with_magic_link();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let response = send(&kit, Method::GET, PAGE, None, Some(&cookie)).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.text().contains("Done, you can close this tab"));
    });
}
