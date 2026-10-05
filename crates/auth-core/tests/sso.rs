//! Issue #627 acceptance, admin half: the enterprise SSO connection API.
//!
//! The admin API is the only way a connection is written, and it is
//! guarded by the venture's *own* client credentials over HTTP Basic —
//! there is no separate admin token. What is asserted here is the
//! contract an operator depends on:
//!
//! - a connection is created, listed, read back and patched, and never
//!   carries its client secret in a response;
//! - the stored column holds a sealed blob, not the plaintext;
//! - every query is scoped by the authenticated client id, so another
//!   client cannot see, read or change a connection — it is a 404, not a
//!   403, and it is not in the list;
//! - a domain belongs to at most one *active* connection of a client, and
//!   freeing it is a matter of disabling the connection that holds it;
//! - a missing header, a malformed one and a wrong secret are one 401
//!   with the `WWW-Authenticate` challenge.

use axum::http::{Method, StatusCode, header};
use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use cratefield_auth_core::{AuthCore, mint_refresh_token};
use cratefield_core::{MapConfig, Statement, UlidIdGen};
use cratefield_testing::TestHarness;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const BASE: &str = "/v1/auth-core";
/// 32 bytes of `A`, base64. A fixed key, because the only thing under test
/// is that a blob written under it can be read back under it.
const SEAL_KEY: &str = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=";
const PLAINTEXT: &str = "acme-oidc-client-secret";

fn kit() -> TestHarness {
    let config = MapConfig::from_pairs([
        ("ADMIN_TOKEN", ADMIN),
        ("AUTH_CORE_SSO_TOKEN_KEY", SEAL_KEY),
    ]);
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = Arc::new(config);
    })
}

struct Reply {
    status: StatusCode,
    headers: header::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// The problem slug the harness rendered, without the base URL, so a
    /// test names the stable code rather than its deployment base.
    fn problem_slug(&self) -> String {
        self.json()["type"]
            .as_str()
            .unwrap_or_default()
            .rsplit("/problems/")
            .next()
            .unwrap_or_default()
            .to_owned()
    }
}

async fn send(
    kit: &TestHarness,
    method: Method,
    path: &str,
    authorization: Option<&str>,
    body: Option<&str>,
) -> Reply {
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    let body = match body {
        Some(payload) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(payload.to_owned())
        }
        None => axum::body::Body::empty(),
    };
    let response = kit
        .router
        .clone()
        .oneshot(builder.body(body).expect("request builds"))
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

fn basic(client_id: &str, secret: &str) -> String {
    let encoded = Base64::encode_string(format!("{client_id}:{secret}").as_bytes());
    format!("Basic {encoded}")
}

async fn create_client(kit: &TestHarness, name: &str) -> (String, String) {
    let body = json!({
        "name": name,
        "kind": "confidential",
        "redirect_uris": ["https://app.example/auth/callback"],
    })
    .to_string();
    let reply = send(
        kit,
        Method::POST,
        &format!("{BASE}/admin/clients"),
        Some(&format!("Bearer {ADMIN}")),
        Some(&body),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.text());
    let json = reply.json();
    (
        json["id"].as_str().expect("a client id").to_owned(),
        json["client_secret"]
            .as_str()
            .expect("the secret is returned once")
            .to_owned(),
    )
}

fn connection_body(org: &str, issuer: &str, domains: &[&str]) -> String {
    json!({
        "org_ref": org,
        "issuer": issuer,
        "oidc_client_id": "acme-oidc-client",
        "oidc_client_secret": PLAINTEXT,
        "domains": domains,
    })
    .to_string()
}

async fn create_connection(kit: &TestHarness, client_id: &str, secret: &str, body: &str) -> Reply {
    send(
        kit,
        Method::POST,
        &format!("{BASE}/sso/connections"),
        Some(&basic(client_id, secret)),
        Some(body),
    )
    .await
}

/// The sealed blob as it sits on disk, read around the module rather than
/// through it, so the assertion is about the database and not about a
/// struct that has already redacted the value.
fn sealed_on_disk(kit: &TestHarness, id: &str) -> String {
    let sql =
        format!("SELECT oidc_client_secret_sealed AS s FROM sso_connections WHERE id = '{id}'");
    let rows = pollster::block_on(kit.db.query(&Statement::new(sql))).expect("query");
    rows.first()
        .and_then(|row| row.get::<String>("s"))
        .expect("the row exists")
}

#[pollster::test]
async fn a_connection_is_created_read_back_and_never_carries_its_secret() {
    let kit = kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;

    // The issuer is normalized (trailing slash gone), the domains are
    // lowercased and deduplicated.
    let reply = create_connection(
        &kit,
        &client,
        &secret,
        &connection_body(
            "acme",
            "https://idp.acme.example/",
            &["Acme.Example", "acme.example"],
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.text());
    let connection = reply.json();
    let id = connection["id"].as_str().expect("an id").to_owned();
    assert!(id.starts_with("ssoc_"), "{id}");
    assert_eq!(connection["org_ref"], "acme");
    assert_eq!(connection["issuer"], "https://idp.acme.example");
    assert_eq!(connection["oidc_client_id"], "acme-oidc-client");
    assert_eq!(connection["domains"], json!(["acme.example"]));
    assert_eq!(connection["status"], "active");

    // Neither the secret nor the sealed blob is ever in a response.
    let body = reply.text();
    assert!(!body.contains(PLAINTEXT), "{body}");
    assert!(!body.contains("oidc_client_secret"), "{body}");

    // Read it back, and list it, by the client that owns it.
    let one = send(
        &kit,
        Method::GET,
        &format!("{BASE}/sso/connections/{id}"),
        Some(&basic(&client, &secret)),
        None,
    )
    .await;
    assert_eq!(one.status, StatusCode::OK);
    assert_eq!(one.json()["id"], id.as_str());
    assert!(!one.text().contains(PLAINTEXT));

    let list = send(
        &kit,
        Method::GET,
        &format!("{BASE}/sso/connections"),
        Some(&basic(&client, &secret)),
        None,
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.json().as_array().expect("an array").len(), 1);

    // The `?org_ref=` filter narrows the list, and a ref nobody uses is empty.
    let filtered = send(
        &kit,
        Method::GET,
        &format!("{BASE}/sso/connections?org_ref=acme"),
        Some(&basic(&client, &secret)),
        None,
    )
    .await;
    assert_eq!(filtered.json().as_array().expect("an array").len(), 1);
    let miss = send(
        &kit,
        Method::GET,
        &format!("{BASE}/sso/connections?org_ref=someone-else"),
        Some(&basic(&client, &secret)),
        None,
    )
    .await;
    assert!(miss.json().as_array().expect("an array").is_empty());
}

#[pollster::test]
async fn the_stored_column_is_a_sealed_blob_not_the_plaintext() {
    let kit = kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let created = create_connection(
        &kit,
        &client,
        &secret,
        &connection_body("acme", "https://idp.acme.example", &["acme.example"]),
    )
    .await;
    let id = created.json()["id"].as_str().expect("an id").to_owned();

    let stored = sealed_on_disk(&kit, &id);
    assert_ne!(stored, PLAINTEXT);
    assert!(!stored.contains(PLAINTEXT), "{stored}");
}

#[pollster::test]
async fn one_client_cannot_see_or_change_another_clients_connection() {
    let kit = kit();
    let (a, a_secret) = create_client(&kit, "Undercover Rockstars").await;
    let (b, b_secret) = create_client(&kit, "Somebody Else").await;
    let created = create_connection(
        &kit,
        &a,
        &a_secret,
        &connection_body("acme", "https://idp.acme.example", &["acme.example"]),
    )
    .await;
    let id = created.json()["id"].as_str().expect("an id").to_owned();

    // B's list does not hold A's connection, even filtered by its ref.
    let list = send(
        &kit,
        Method::GET,
        &format!("{BASE}/sso/connections"),
        Some(&basic(&b, &b_secret)),
        None,
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    assert!(
        list.json().as_array().expect("an array").is_empty(),
        "{}",
        list.text()
    );

    // Reading and changing it are the same 404 an id that does not exist
    // gets: B cannot tell A's connection from one that was never made.
    for (method, body) in [
        (Method::GET, None),
        (Method::PATCH, Some(r#"{"status":"disabled"}"#)),
    ] {
        let reply = send(
            &kit,
            method.clone(),
            &format!("{BASE}/sso/connections/{id}"),
            Some(&basic(&b, &b_secret)),
            body,
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{method} {}",
            reply.text()
        );
    }

    // A's connection is untouched.
    let one = send(
        &kit,
        Method::GET,
        &format!("{BASE}/sso/connections/{id}"),
        Some(&basic(&a, &a_secret)),
        None,
    )
    .await;
    assert_eq!(one.json()["status"], "active");

    // A domain is claimed per client, not globally: B may route the same
    // domain for its own organization.
    let b_same_domain = create_connection(
        &kit,
        &b,
        &b_secret,
        &connection_body("acme", "https://idp-other.example", &["acme.example"]),
    )
    .await;
    assert_eq!(
        b_same_domain.status,
        StatusCode::CREATED,
        "{}",
        b_same_domain.text()
    );
}

#[pollster::test]
async fn an_active_connection_claims_its_domains_and_freeing_one_is_disabling_it() {
    let kit = kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let first = create_connection(
        &kit,
        &client,
        &secret,
        &connection_body("acme", "https://idp.acme.example", &["acme.example"]),
    )
    .await;
    let id = first.json()["id"].as_str().expect("an id").to_owned();

    let clash = create_connection(
        &kit,
        &client,
        &secret,
        &connection_body("acme-us", "https://idp-us.example", &["ACME.example"]),
    )
    .await;
    assert_eq!(clash.status, StatusCode::CONFLICT, "{}", clash.text());
    assert_eq!(clash.problem_slug(), "auth/sso-domain-claimed");

    // Patching a connection against its own domain is not a clash.
    let patch = send(
        &kit,
        Method::PATCH,
        &format!("{BASE}/sso/connections/{id}"),
        Some(&basic(&client, &secret)),
        Some(r#"{"domains":["acme.example","acme-corp.example"]}"#),
    )
    .await;
    assert_eq!(patch.status, StatusCode::OK, "{}", patch.text());
    assert_eq!(
        patch.json()["domains"],
        json!(["acme.example", "acme-corp.example"])
    );

    // Disabling it frees the domain for another active connection.
    let disabled = send(
        &kit,
        Method::PATCH,
        &format!("{BASE}/sso/connections/{id}"),
        Some(&basic(&client, &secret)),
        Some(r#"{"status":"disabled"}"#),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK);
    assert_eq!(disabled.json()["status"], "disabled");

    let now_free = create_connection(
        &kit,
        &client,
        &secret,
        &connection_body("acme-us", "https://idp-us.example", &["acme.example"]),
    )
    .await;
    assert_eq!(now_free.status, StatusCode::CREATED, "{}", now_free.text());
}

#[pollster::test]
async fn a_patch_rotates_the_secret_and_the_new_blob_is_still_sealed() {
    let kit = kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let created = create_connection(
        &kit,
        &client,
        &secret,
        &connection_body("acme", "https://idp.acme.example", &["acme.example"]),
    )
    .await;
    let id = created.json()["id"].as_str().expect("an id").to_owned();
    let before = sealed_on_disk(&kit, &id);

    let reply = send(
        &kit,
        Method::PATCH,
        &format!("{BASE}/sso/connections/{id}"),
        Some(&basic(&client, &secret)),
        Some(r#"{"oidc_client_secret":"a-rotated-secret"}"#),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert!(
        !reply.text().contains("a-rotated-secret"),
        "{}",
        reply.text()
    );

    let after = sealed_on_disk(&kit, &id);
    assert_ne!(before, after, "the sealed blob changed");
    assert!(!after.contains("a-rotated-secret"), "{after}");

    // A patch with nothing in it is a validation failure, not a silent no-op.
    let empty = send(
        &kit,
        Method::PATCH,
        &format!("{BASE}/sso/connections/{id}"),
        Some(&basic(&client, &secret)),
        Some("{}"),
    )
    .await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST, "{}", empty.text());

    // A status outside the CHECK list is refused before it reaches SQL.
    let bad_status = send(
        &kit,
        Method::PATCH,
        &format!("{BASE}/sso/connections/{id}"),
        Some(&basic(&client, &secret)),
        Some(r#"{"status":"deleted"}"#),
    )
    .await;
    assert_eq!(bad_status.status, StatusCode::BAD_REQUEST);
}

#[pollster::test]
async fn the_admin_api_answers_one_challenge_for_every_bad_credential() {
    let kit = kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;
    let body = connection_body("acme", "https://idp.acme.example", &["acme.example"]);

    for authorization in [
        None,
        Some("Bearer not-basic".to_owned()),
        Some("Basic !!!not-base64!!!".to_owned()),
        Some(basic(&client, "the-wrong-secret")),
        Some(basic("a-client-that-does-not-exist", "whatever")),
    ] {
        let reply = send(
            &kit,
            Method::POST,
            &format!("{BASE}/sso/connections"),
            authorization.as_deref(),
            Some(&body),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{authorization:?}");
        assert_eq!(reply.problem_slug(), "auth/sso-unauthorized");
        let challenge = reply
            .headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(challenge.starts_with("Basic"), "{challenge:?}");
    }

    // The right credentials still work, so the loop above proved the guard
    // and not a broken route.
    let ok = send(
        &kit,
        Method::POST,
        &format!("{BASE}/sso/connections"),
        Some(&basic(&client, &secret)),
        Some(&body),
    )
    .await;
    assert_eq!(ok.status, StatusCode::CREATED, "{}", ok.text());
}

#[pollster::test]
async fn an_issuer_that_is_not_https_and_domains_that_are_not_domains_are_refused() {
    let kit = kit();
    let (client, secret) = create_client(&kit, "Undercover Rockstars").await;

    let cases = [
        connection_body("acme", "http://idp.acme.example", &["acme.example"]),
        connection_body("acme", "not a url", &["acme.example"]),
        connection_body("acme", "https://idp.acme.example", &[]),
        connection_body("acme", "https://idp.acme.example", &["com"]),
        connection_body("", "https://idp.acme.example", &["acme.example"]),
    ];
    for body in cases {
        let reply = create_connection(&kit, &client, &secret, &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
        assert_eq!(
            reply.problem_slug(),
            "validation-failed",
            "{}",
            reply.text()
        );
    }

    // Nothing was written by any of them.
    let list = send(
        &kit,
        Method::GET,
        &format!("{BASE}/sso/connections"),
        Some(&basic(&client, &secret)),
        None,
    )
    .await;
    assert!(list.json().as_array().expect("an array").is_empty());
}

#[pollster::test]
async fn an_sso_identity_subject_and_a_session_column_are_admitted_by_the_schema() {
    let kit = kit();
    let now = "2026-10-04T00:00:00Z";
    let run =
        |sql: String| pollster::block_on(kit.db.execute(&Statement::new(sql))).expect("statement");
    run(format!(
        "INSERT INTO users (id, primary_email, primary_email_verified, status, created_at, updated_at) \
         VALUES ('u1', 'ada@acme.example', 1, 'active', '{now}', '{now}')"
    ));
    // The provider CHECK gained `sso` in migration 0010, and the subject is
    // the connection id joined to the IdP's own subject.
    run(format!(
        "INSERT INTO identities (id, user_id, provider, provider_subject, email, email_verified, created_at) \
         VALUES ('i1', 'u1', 'sso', 'ssoc_1:idp-subject-1', 'ada@acme.example', 1, '{now}')"
    ));
    run(format!(
        "INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at, amr, sso_connection) \
         VALUES ('s1', 'u1', 'hash', '{now}', '{now}', '2026-11-04T00:00:00Z', '[\"sso\"]', 'ssoc_1')"
    ));

    let rows = pollster::block_on(kit.db.query(&Statement::new(
        "SELECT sso_connection AS c FROM sessions WHERE id = 's1'",
    )))
    .expect("query");
    assert_eq!(
        rows.first()
            .and_then(|row| row.get::<String>("c"))
            .as_deref(),
        Some("ssoc_1")
    );

    // And a provider outside the list is still refused.
    let statement = Statement::new(format!(
        "INSERT INTO identities (id, user_id, provider, provider_subject, created_at) \
         VALUES ('i2', 'u1', 'nope', 'x', '{now}')"
    ));
    assert!(pollster::block_on(kit.db.execute(&statement)).is_err());
}

// ---------------------------------------------------------------------------
// the access-token claim

/// A throwaway P-256 key in the JSON shape `AUTH_CORE_SIGNING_KEYS` takes.
fn signing_key_json(kid: &str) -> Value {
    let secret = p256::SecretKey::from_slice(&[7u8; 32]).expect("a valid scalar");
    let d = Base64UrlUnpadded::encode_string(&secret.to_bytes());
    json!({ "kty": "EC", "crv": "P-256", "kid": kid, "d": d })
}

/// The admin-and-sealing kit with signing keys, so `/token` mints a real
/// token whose claims a test can read.
fn signed_kit() -> TestHarness {
    let keys = serde_json::to_string(&vec![signing_key_json("k1")]).expect("keys json");
    let config = MapConfig::from_pairs([
        ("ADMIN_TOKEN", ADMIN),
        ("AUTH_CORE_SSO_TOKEN_KEY", SEAL_KEY),
        ("AUTH_CORE_SIGNING_KEYS", keys.as_str()),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE", "k1"),
        ("AUTH_CORE_ISSUER", "https://auth.test.example"),
    ]);
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = Arc::new(config);
    })
}

fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a payload segment");
    let bytes = Base64UrlUnpadded::decode_vec(payload).expect("base64url");
    serde_json::from_slice(&bytes).expect("claims are JSON")
}

/// A form-encoded `POST`, which is how an OAuth token request arrives.
async fn post_form(kit: &TestHarness, path: &str, form: &str) -> Reply {
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form.to_owned()))
        .expect("request builds");
    let response = kit
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

#[pollster::test]
async fn the_sso_claim_is_only_on_tokens_minted_for_the_connections_own_client() {
    let kit = signed_kit();
    let (owner, owner_secret) = create_client(&kit, "Undercover Rockstars").await;
    let (other, other_secret) = create_client(&kit, "Somebody Else").await;
    let created = create_connection(
        &kit,
        &owner,
        &owner_secret,
        &connection_body("acme", "https://idp.acme.example", &["acme.example"]),
    )
    .await;
    let connection = created.json()["id"].as_str().expect("an id").to_owned();

    // A session that came in through that connection.
    let run =
        |sql: String| pollster::block_on(kit.db.execute(&Statement::new(sql))).expect("statement");
    run(
        "INSERT INTO users (id, primary_email, primary_email_verified, status, created_at, updated_at) \
         VALUES ('u1', 'ada@acme.example', 1, 'active', '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z')"
            .to_owned(),
    );
    run(format!(
        "INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at, amr, sso_connection) \
         VALUES ('s1', 'u1', 'hash', '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z', '2099-01-01T00:00:00Z', '[\"sso\"]', '{connection}')"
    ));

    let id_gen = UlidIdGen;
    let clock = &kit.clock;
    let db = &*kit.db;

    let form = |client: &str, secret: &str, refresh: &str| {
        format!(
            "grant_type=refresh_token&refresh_token={refresh}&client_id={client}&client_secret={secret}"
        )
    };

    // The connection's own client gets the claim, and the `amr` from the session.
    let mine = mint_refresh_token(db, clock, &id_gen, "s1", "u1", &owner)
        .await
        .expect("a refresh token");
    let response = post_form(
        &kit,
        "/v1/auth-core/token",
        &form(&owner, &owner_secret, &mine),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let access = response.json()["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned();
    assert_eq!(claims_of(&access)["sso_connection"], connection.as_str());
    assert_eq!(claims_of(&access)["amr"], json!(["sso"]));

    // The same session, a token minted for somebody else's client: the
    // claim is dropped, because a connection is one venture's fact.
    let theirs = mint_refresh_token(db, clock, &id_gen, "s1", "u1", &other)
        .await
        .expect("a refresh token");
    let response = post_form(
        &kit,
        "/v1/auth-core/token",
        &form(&other, &other_secret, &theirs),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let access = response.json()["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned();
    assert!(
        claims_of(&access)["sso_connection"].is_null(),
        "{}",
        claims_of(&access)
    );

    // A connection that has since been disabled stops vouching: the claim
    // is dropped on refresh too, not only for a foreign client.
    let disabled = send(
        &kit,
        Method::PATCH,
        &format!("/v1/auth-core/sso/connections/{connection}"),
        Some(&basic(&owner, &owner_secret)),
        Some(r#"{"status":"disabled"}"#),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text());

    let after = mint_refresh_token(db, clock, &id_gen, "s1", "u1", &owner)
        .await
        .expect("a refresh token");
    let response = post_form(
        &kit,
        "/v1/auth-core/token",
        &form(&owner, &owner_secret, &after),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let access = response.json()["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned();
    assert!(
        claims_of(&access)["sso_connection"].is_null(),
        "a disabled connection still vouched: {}",
        claims_of(&access)
    );
}
