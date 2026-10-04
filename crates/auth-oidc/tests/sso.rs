//! Issue #627 acceptance: an enterprise SSO connection, end to end.
//!
//! A fake `IdP` — discovery, JWKS and a real RS256 ID token — stands in for
//! an organization's provider. A connection is registered through the admin
//! API with the client's own credentials, and then:
//!
//! - `/authorize?connection=<id>` routes the browser to that connection's
//!   `/start`, and the callback completes a session whose access token
//!   names the connection and carries `amr: ["sso"]`;
//! - `/authorize?login_hint=<addr>` routes the same way when the address's
//!   domain is one the connection claims, and falls through to the chooser
//!   when it is not;
//! - an ID token the connection does not vouch for — wrong issuer, an
//!   unverified or missing address, an address outside the connection's
//!   domains — is refused with the one generic refusal;
//! - an unknown or disabled connection is not routable;
//! - another client's connection id or domain routes nothing.

mod support;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use http::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::kit::{
    ADMIN, APP_REDIRECT, Res, auth_basic, create_client, create_connection, get, post_form, send,
    sso_callback, sso_kit, sso_start,
};
use support::provider::{SSO_CLIENT_ID, SSO_CLIENT_SECRET, SSO_EMAIL, SSO_ISSUER, TokenClaims};

const VERIFIER: &str = "a-verifier-of-at-least-43-characters-1234567890";

fn challenge() -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()))
}

/// The `/authorize` a person's browser is on when they are asked to sign in.
fn authorize_uri(client_id: &str, extra: &str) -> String {
    format!(
        "/v1/auth-core/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={APP_REDIRECT}&code_challenge={}&code_challenge_method=S256&state=xyz{extra}",
        challenge()
    )
}

/// A connection whose domain is `acme.example`, registered for `client_id`.
async fn connection(
    kit: &support::Kit,
    client_id: &str,
    client_secret: &str,
    domains: &[&str],
) -> String {
    let body = json!({
        "org_ref": "acme",
        "issuer": SSO_ISSUER,
        "oidc_client_id": SSO_CLIENT_ID,
        "oidc_client_secret": SSO_CLIENT_SECRET,
        "domains": domains,
    });
    let response = create_connection(kit, client_id, client_secret, &body).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    response.json()["id"].as_str().expect("an id").to_owned()
}

/// Where an `/authorize` handed the browser: the connection's `/start`,
/// carrying the pending authorization back as `return_to`.
///
/// Returns the raw query to replay against `/start`, and checks the
/// round trip: the `return_to` decodes to the request that was pending.
fn start_handoff(response: &Res, connection_id: &str, pending: &str) -> String {
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    let location = response.location().expect("a Location");
    let parsed =
        url::Url::parse(&format!("http://test.invalid{location}")).expect("an absolute url");
    assert_eq!(
        parsed.path(),
        format!("/v1/auth-oidc/sso/{connection_id}/start")
    );
    let return_to = parsed
        .query_pairs()
        .find(|(key, _)| key == "return_to")
        .expect("a return_to")
        .1
        .into_owned();
    assert_eq!(
        return_to, pending,
        "the pending authorization rides through"
    );
    location
        .split_once('?')
        .map_or_else(String::new, |(_, query)| query.to_owned())
}

/// Runs `/authorize …connection=…` through the start, the `IdP` and the
/// callback, and returns the `Set-Cookie` naming the new session.
async fn sign_in_through(kit: &support::Kit, pending: &str, connection_id: &str) -> String {
    // 1. `/authorize` hands the browser to the connection's `/start`.
    let response = get(kit, pending, &[]).await;
    let query = start_handoff(&response, connection_id, pending);

    // 2. `/start` builds the authorization URL and seals the flow.
    let started = sso_start(kit, connection_id, &format!("?{query}")).await;
    assert!(
        started
            .authorization_url
            .starts_with(&format!("{SSO_ISSUER}/authorize")),
        "{}",
        started.authorization_url
    );

    // 3. The `IdP` sends the browser back to the one fixed callback.
    let callback = sso_callback(kit, &started, "the-code", &started.state).await;
    assert_eq!(callback.status, StatusCode::FOUND, "{}", callback.text());
    assert_eq!(
        callback.location().as_deref(),
        Some(pending),
        "back to the pending authorization"
    );
    callback
        .cookie("__Host-fz_session")
        .expect("a session cookie")
}

/// The `code` an `/authorize` with a live session redirects with.
async fn code_for(kit: &support::Kit, pending: &str, session: &str) -> String {
    let response = get(kit, pending, &[("__Host-fz_session", session)]).await;
    assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    let location = response.location().expect("a Location");
    assert!(
        location.starts_with(APP_REDIRECT),
        "expected the registered redirect, got {location}"
    );
    location
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .expect("a code")
        .to_owned()
}

/// Redeems a code for a token pair.
async fn tokens(kit: &support::Kit, client_id: &str, client_secret: &str, code: &str) -> Value {
    let form = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}\
         &code={code}&redirect_uri={APP_REDIRECT}&code_verifier={VERIFIER}"
    );
    let response = post_form(kit, "/v1/auth-core/token", &form).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    response.json()
}

fn claims(access_token: &str) -> Value {
    let payload = access_token.split('.').nth(1).expect("a payload");
    let bytes = Base64UrlUnpadded::decode_vec(payload).expect("base64url");
    serde_json::from_slice(&bytes).expect("claims are JSON")
}

fn is_the_generic_refusal(response: &Res) {
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    let kind = response.json()["type"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        kind.ends_with("/problems/auth/oidc-callback-refused"),
        "{kind}"
    );
}

#[pollster::test]
async fn a_connection_signs_a_person_in_and_names_itself_on_the_token() {
    let kit = sso_kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let connection_id = connection(&kit, &client, &secret, &["acme.example"]).await;
    kit.provider
        .set_claims(TokenClaims::sso(SSO_ISSUER, SSO_CLIENT_ID, SSO_EMAIL));

    let pending = authorize_uri(&client, &format!("&connection={connection_id}"));
    let session = sign_in_through(&kit, &pending, &connection_id).await;

    let code = code_for(&kit, &pending, &session).await;
    let tokens = tokens(&kit, &client, &secret, &code).await;
    let access = tokens["access_token"].as_str().expect("an access token");
    assert_eq!(claims(access)["sso_connection"], connection_id.as_str());
    assert_eq!(claims(access)["amr"], json!(["sso"]));
    assert_eq!(claims(access)["aud"], client.as_str());

    // A refresh keeps saying the same thing.
    let form = format!(
        "grant_type=refresh_token&client_id={client}&client_secret={secret}&refresh_token={}",
        tokens["refresh_token"].as_str().expect("a refresh token")
    );
    let refreshed = post_form(&kit, "/v1/auth-core/token", &form).await;
    assert_eq!(refreshed.status, StatusCode::OK, "{}", refreshed.text());
    let access = refreshed.json()["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned();
    assert_eq!(claims(&access)["sso_connection"], connection_id.as_str());
    assert_eq!(claims(&access)["amr"], json!(["sso"]));
}

#[pollster::test]
async fn a_login_hint_routes_to_the_connection_that_claims_its_domain() {
    let kit = sso_kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let connection_id = connection(&kit, &client, &secret, &["acme.example"]).await;

    // The hint names the connection: its domain is one this client's own
    // active connection claims.
    let hint = authorize_uri(&client, &format!("&login_hint={SSO_EMAIL}"));
    let response = get(&kit, &hint, &[]).await;
    let _ = start_handoff(&response, &connection_id, &hint);

    // A hint nobody claims falls through to the chooser: it is a hint, and
    // routing it anywhere would be steering.
    let unclaimed = authorize_uri(&client, "&login_hint=nick@somewhere-else.example");
    let response = get(&kit, &unclaimed, &[]).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.location().is_none());

    // The same address, a client with no such connection: still a chooser.
    let (other, _) = create_client(&kit, "Somebody Else").await;
    let mistaken = authorize_uri(&other, &format!("&login_hint={SSO_EMAIL}"));
    let response = get(&kit, &mistaken, &[]).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.location().is_none());
}

#[pollster::test]
async fn the_token_endpoints_own_document_decides_the_client_authentication() {
    let kit = sso_kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let connection_id = connection(&kit, &client, &secret, &["acme.example"]).await;
    kit.provider
        .set_claims(TokenClaims::sso(SSO_ISSUER, SSO_CLIENT_ID, SSO_EMAIL));
    // The document says the token endpoint wants the secret in the body.
    kit.provider.set_token_auth_methods(&["client_secret_post"]);

    let pending = authorize_uri(&client, &format!("&connection={connection_id}"));
    let session = sign_in_through(&kit, &pending, &connection_id).await;
    let _ = code_for(&kit, &pending, &session).await;

    let token_calls: Vec<String> = kit
        .provider
        .calls()
        .into_iter()
        .filter(|(_, url, _)| url.ends_with("/token"))
        .map(|(_, _, body)| body)
        .collect();
    assert_eq!(token_calls.len(), 1, "{token_calls:?}");
    assert!(
        token_calls[0].contains("client_secret="),
        "the secret rode in the body: {:?}",
        token_calls[0]
    );
    assert!(token_calls[0].contains(&format!("client_id={SSO_CLIENT_ID}")));
}

#[pollster::test]
async fn an_id_token_the_connection_does_not_vouch_for_is_refused() {
    let kit = sso_kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let connection_id = connection(&kit, &client, &secret, &["acme.example"]).await;

    let cases: [(&str, TokenClaims); 4] = [
        (
            "an issuer this connection is not",
            TokenClaims {
                issuer: "https://idp.somewhere-else.example".to_owned(),
                ..TokenClaims::sso(SSO_ISSUER, SSO_CLIENT_ID, SSO_EMAIL)
            },
        ),
        (
            "an address the provider did not verify",
            TokenClaims {
                email_verified: false,
                ..TokenClaims::sso(SSO_ISSUER, SSO_CLIENT_ID, SSO_EMAIL)
            },
        ),
        (
            "no address at all",
            TokenClaims {
                email: None,
                ..TokenClaims::sso(SSO_ISSUER, SSO_CLIENT_ID, SSO_EMAIL)
            },
        ),
        (
            "an address outside the connection's domains",
            TokenClaims::sso(SSO_ISSUER, SSO_CLIENT_ID, "ada@not-acme.example"),
        ),
    ];

    for (reason, token_claims) in cases {
        let pending = authorize_uri(&client, &format!("&connection={connection_id}"));
        let response = get(&kit, &pending, &[]).await;
        let query = start_handoff(&response, &connection_id, &pending);
        let started = sso_start(&kit, &connection_id, &format!("?{query}")).await;
        kit.provider.set_claims(token_claims);

        let callback = sso_callback(&kit, &started, "the-code", &started.state).await;
        is_the_generic_refusal(&callback);
        assert!(callback.cookie("__Host-fz_session").is_none(), "{reason}");
        // Nothing the refusal says may leak which check failed, or the
        // identity the `IdP` asserted.
        assert!(!callback.text().contains("acme.example"), "{reason}");
    }
}

#[pollster::test]
async fn an_unknown_connection_start_is_a_404() {
    let kit = sso_kit();
    let response = get(&kit, "/v1/auth-oidc/sso/ssoc_nobody/start", &[]).await;
    assert_eq!(
        response.status,
        StatusCode::NOT_FOUND,
        "{}",
        response.text()
    );
}

#[pollster::test]
async fn disabling_a_connection_mid_flow_refuses_the_callback() {
    let kit = sso_kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let connection_id = connection(&kit, &client, &secret, &["acme.example"]).await;
    kit.provider
        .set_claims(TokenClaims::sso(SSO_ISSUER, SSO_CLIENT_ID, SSO_EMAIL));

    let started = sso_start(&kit, &connection_id, "").await;

    let disabled = send(
        &kit,
        http::Method::PATCH,
        &format!("/v1/auth-core/sso/connections/{connection_id}"),
        Some(&auth_basic(&client, &secret)),
        Some(r#"{"status":"disabled"}"#),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text());

    // The flow was signed while the connection was live; the callback
    // re-reads the row and refuses, and the connection is not routable at
    // all any more.
    let callback: Res = sso_callback(&kit, &started, "the-code", &started.state).await;
    is_the_generic_refusal(&callback);

    let start = get(
        &kit,
        &format!("/v1/auth-oidc/sso/{connection_id}/start"),
        &[],
    )
    .await;
    assert_eq!(start.status, StatusCode::NOT_FOUND);
}

#[pollster::test]
async fn disabling_the_owning_client_refuses_the_callback() {
    let kit = sso_kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let connection_id = connection(&kit, &client, &secret, &["acme.example"]).await;
    kit.provider
        .set_claims(TokenClaims::sso(SSO_ISSUER, SSO_CLIENT_ID, SSO_EMAIL));

    let started = sso_start(&kit, &connection_id, "").await;

    // The connection row itself is left active; only the venture that owns
    // it is disabled, and that alone must refuse the sign-in.
    let disabled = send(
        &kit,
        http::Method::PATCH,
        &format!("/v1/auth-core/admin/clients/{client}"),
        Some(&format!("Bearer {ADMIN}")),
        Some(r#"{"status":"disabled"}"#),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text());

    let callback: Res = sso_callback(&kit, &started, "the-code", &started.state).await;
    is_the_generic_refusal(&callback);
}

#[pollster::test]
async fn another_clients_connection_is_not_routable() {
    let kit = sso_kit();
    let (owner, owner_secret) = create_client(&kit, "Undercover Rockstars").await;
    let (other, _) = create_client(&kit, "Somebody Else").await;
    let connection_id = connection(&kit, &owner, &owner_secret, &["acme.example"]).await;

    // The other client names the owner's connection: a refused page, and
    // no redirect — least of all to the owner's identity provider.
    let uri = authorize_uri(&other, &format!("&connection={connection_id}"));
    let response = get(&kit, &uri, &[]).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    assert!(response.location().is_none());
    assert!(
        !response.text().contains("idp.acme.example"),
        "{}",
        response.text()
    );

    // The owner may route it, so the refusal above was about ownership and
    // not about the connection being unusable.
    let their_own = authorize_uri(&owner, &format!("&connection={connection_id}"));
    let response = get(&kit, &their_own, &[]).await;
    let _ = start_handoff(&response, &connection_id, &their_own);
}

#[pollster::test]
async fn the_admin_api_never_answers_with_a_secret() {
    let kit = sso_kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let body = json!({
        "org_ref": "acme",
        "issuer": SSO_ISSUER,
        "oidc_client_id": SSO_CLIENT_ID,
        "oidc_client_secret": SSO_CLIENT_SECRET,
        "domains": ["acme.example"],
    });
    let created = create_connection(&kit, &client, &secret, &body).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text());
    assert!(!created.text().contains(SSO_CLIENT_SECRET));

    let listed = send(
        &kit,
        http::Method::GET,
        "/v1/auth-core/sso/connections",
        Some(&auth_basic(&client, &secret)),
        None,
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert!(!listed.text().contains(SSO_CLIENT_SECRET));

    // A wrong secret is one 401 with the challenge.
    let wrong = send(
        &kit,
        http::Method::POST,
        "/v1/auth-core/sso/connections",
        Some(&auth_basic(&client, "not-the-secret")),
        Some(&body.to_string()),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        wrong
            .headers
            .get(http::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(' ')
            .next(),
        Some("Basic")
    );
}
