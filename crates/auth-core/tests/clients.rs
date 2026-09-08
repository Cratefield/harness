//! Issue #6 acceptance, HTTP half: the admin API behind the harness
//! `admin_auth` layer — create returns the plaintext secret exactly
//! once, rotation keeps the old secret working for the overlap,
//! patching changes redirect URIs and status, disabled clients fail
//! the stable problem, and no admin response ever carries a hash.

use axum::http::{Method, StatusCode, header};
use axum::response::Response;
use cratefield_core::Statement;
use cratefield_testing::TestHarness;
use factory0_auth_core::AuthCore;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const BASE: &str = "/v1/auth-core";

struct Reply {
    status: StatusCode,
    json: Value,
}

async fn reply(response: Response) -> Reply {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("body is JSON")
    };
    Reply { status, json }
}

fn admin_kit() -> TestHarness {
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = Arc::new(cratefield_core::MapConfig::from_pairs([(
            "ADMIN_TOKEN",
            ADMIN,
        )]));
    })
}

async fn admin(kit: &TestHarness, method: Method, path: &str, body: Option<&str>) -> Reply {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"));
    let request = match body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            builder.body(axum::body::Body::from(json.to_owned()))
        }
        None => builder.body(axum::body::Body::empty()),
    }
    .expect("request builds");
    reply(kit.router.clone().oneshot(request).await.expect("answers")).await
}

async fn admin_with_token(kit: &TestHarness, token: &str) -> Reply {
    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/v1/auth-core/admin/clients")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .expect("request builds");
    reply(kit.router.clone().oneshot(request).await.expect("answers")).await
}

fn create_body() -> String {
    r#"{
        "name": "Undercover Rockstars",
        "kind": "confidential",
        "redirect_uris": ["https://undercoverrockstars.com/auth/callback"]
    }"#
    .to_owned()
}

async fn create_client(kit: &TestHarness) -> (String, String) {
    let response = admin(
        kit,
        Method::POST,
        &format!("{BASE}/admin/clients"),
        Some(&create_body()),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);
    let body = response.json;
    (
        body["id"].as_str().expect("id").to_owned(),
        body["client_secret"]
            .as_str()
            .expect("secret once")
            .to_owned(),
    )
}

#[pollster::test]
async fn admin_routes_without_a_token_are_disabled() {
    let kit = admin_kit();
    for (method, path) in [
        (Method::POST, "/v1/auth-core/admin/clients"),
        (Method::GET, "/v1/auth-core/admin/clients"),
        (Method::PATCH, "/v1/auth-core/admin/clients/app1"),
        (
            Method::POST,
            "/v1/auth-core/admin/clients/app1/rotate-secret",
        ),
    ] {
        let response = cratefield_testing::request(&kit.router, method.clone(), path, None).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/admin-unauthorized"
        );
    }

    let wrong = admin_with_token(&kit, "definitely-wrong").await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    assert_eq!(
        wrong.json["type"],
        "https://factory0.ventures/problems/admin-forbidden"
    );
}

#[pollster::test]
async fn create_returns_the_secret_once_and_stores_only_a_hash() {
    let kit = admin_kit();
    let (id, secret) = create_client(&kit).await;
    assert!(id.len() > 10, "ids are ULIDs: {id}");
    assert_eq!(secret.len(), 43, "32 bytes, base64url, no padding");

    let row = kit
        .db
        .query(&Statement::with_values(
            "SELECT secret_hash, previous_secret_hash FROM clients WHERE id = ?".to_owned(),
            vec![id.clone().into()],
        ))
        .await
        .expect("select client");
    let stored = row
        .first()
        .and_then(|row| row.get::<String>("secret_hash"))
        .expect("hash stored");
    assert!(
        stored.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
        "ADR 0200 parameters: {stored}"
    );
    assert!(
        row.first()
            .unwrap()
            .get::<Option<String>>("previous_secret_hash")
            .flatten()
            .is_none()
    );
    assert!(factory0_auth_core::verify_secret(&secret, &stored));
    assert!(!factory0_auth_core::verify_secret("wrong-secret", &stored));

    let listed = admin(&kit, Method::GET, &format!("{BASE}/admin/clients"), None).await;
    assert_eq!(listed.status, StatusCode::OK);
    let clients = listed.json.as_array().cloned().unwrap_or_default();
    assert_eq!(clients.len(), 1);
    assert!(clients[0].get("client_secret").is_none());
    assert!(clients[0].get("secret_hash").is_none());
}

#[pollster::test]
async fn public_clients_get_no_secret() {
    let kit = admin_kit();
    let response = admin(
        &kit,
        Method::POST,
        &format!("{BASE}/admin/clients"),
        Some(
            r#"{
                "name": "Native app",
                "kind": "public",
                "redirect_uris": ["com.example.app:/callback"]
            }"#,
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(response.json["kind"], "public");
    assert!(
        response.json.get("client_secret").is_none(),
        "public clients have no secret to hand out"
    );
    let id = response.json["id"].as_str().unwrap().to_owned();

    let row = kit
        .db
        .query(&Statement::with_values(
            "SELECT secret_hash FROM clients WHERE id = ?".to_owned(),
            vec![id.clone().into()],
        ))
        .await
        .unwrap();
    let stored = row.first().unwrap().get::<String>("secret_hash").unwrap();
    assert!(
        stored.starts_with("$argon2id$"),
        "the NOT NULL column holds a discarded secret's hash"
    );

    let rotate = admin(
        &kit,
        Method::POST,
        &format!("{BASE}/admin/clients/{id}/rotate-secret"),
        None,
    )
    .await;
    assert_eq!(rotate.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        rotate.json["type"],
        "https://factory0.ventures/problems/validation-failed"
    );
}

#[pollster::test]
async fn rotation_keeps_the_old_secret_for_the_overlap() {
    let kit = admin_kit();
    let (id, old_secret) = create_client(&kit).await;

    let rotated = admin(
        &kit,
        Method::POST,
        &format!("{BASE}/admin/clients/{id}/rotate-secret"),
        None,
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let new_secret = rotated.json["client_secret"].as_str().unwrap().to_owned();
    assert_eq!(new_secret.len(), 43);
    let overlap_end = rotated.json["previous_hash_expires_at"]
        .as_str()
        .expect("overlap instant")
        .to_owned();
    assert_eq!(overlap_end, "2027-01-15T09:00:00Z", "fixed clock + 1 h");

    let row = factory0_auth_core::client_by_id(&*kit.db, &id)
        .await
        .unwrap()
        .expect("client");
    assert!(factory0_auth_core::verify_client_secret(
        &row,
        &new_secret,
        "2027-01-15T08:30:00Z"
    ));
    assert!(
        factory0_auth_core::verify_client_secret(&row, &old_secret, "2027-01-15T08:30:00Z"),
        "the old secret still verifies inside the overlap"
    );
    assert!(factory0_auth_core::verify_client_secret(
        &row,
        &old_secret,
        "2027-01-15T08:59:59Z"
    ));
    assert!(
        !factory0_auth_core::verify_client_secret(&row, &old_secret, "2027-01-15T09:00:00Z"),
        "the overlap ends exactly at previous_hash_expires_at"
    );
    assert!(factory0_auth_core::verify_client_secret(
        &row,
        &new_secret,
        "2027-01-15T09:00:00Z"
    ));
}

#[pollster::test]
async fn patch_changes_uris_and_status_and_disabled_fails_the_stable_problem() {
    let kit = admin_kit();
    let (id, _) = create_client(&kit).await;

    let patched = admin(
        &kit,
        Method::PATCH,
        &format!("{BASE}/admin/clients/{id}"),
        Some(
            r#"{
                "redirect_uris": [
                    "https://undercoverrockstars.com/auth/callback",
                    "https://undercoverrockstars.com/v2/callback"
                ]
            }"#,
        ),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK);
    assert_eq!(
        patched.json["redirect_uris"].as_array().map(Vec::len),
        Some(2),
        "URIs are replaced wholesale"
    );
    assert!(patched.json.get("secret_hash").is_none());

    let disabled = admin(
        &kit,
        Method::PATCH,
        &format!("{BASE}/admin/clients/{id}"),
        Some(r#"{"status": "disabled"}"#),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK);
    assert_eq!(disabled.json["status"], "disabled");

    let row = factory0_auth_core::client_by_id(&*kit.db, &id)
        .await
        .unwrap()
        .expect("client");
    let problem = factory0_auth_core::ensure_client_usable(&row).expect_err("disabled");
    assert_eq!(problem.slug, "auth/client-disabled");
    assert_eq!(problem.status, StatusCode::FORBIDDEN);

    let revived = admin(
        &kit,
        Method::PATCH,
        &format!("{BASE}/admin/clients/{id}"),
        Some(r#"{"status": "active"}"#),
    )
    .await;
    assert_eq!(revived.json["status"], "active");
    let row = factory0_auth_core::client_by_id(&*kit.db, &id)
        .await
        .unwrap()
        .unwrap();
    assert!(factory0_auth_core::ensure_client_usable(&row).is_ok());
}

#[pollster::test]
async fn validation_and_not_found_paths() {
    let kit = admin_kit();

    for (body, why) in [
        (
            r#"{"name": "", "kind": "confidential", "redirect_uris": ["https://a.example/cb"]}"#,
            "empty name",
        ),
        (
            r#"{"name": "X", "kind": "web", "redirect_uris": ["https://a.example/cb"]}"#,
            "unknown kind",
        ),
        (
            r#"{"name": "X", "kind": "confidential", "redirect_uris": []}"#,
            "no redirect URIs",
        ),
    ] {
        let response = admin(
            &kit,
            Method::POST,
            &format!("{BASE}/admin/clients"),
            Some(body),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{why}");
    }

    let ghost = admin(
        &kit,
        Method::PATCH,
        &format!("{BASE}/admin/clients/ghost"),
        Some(r#"{"status": "disabled"}"#),
    )
    .await;
    assert_eq!(ghost.status, StatusCode::NOT_FOUND);

    let ghost_rotate = admin(
        &kit,
        Method::POST,
        &format!("{BASE}/admin/clients/ghost/rotate-secret"),
        None,
    )
    .await;
    assert_eq!(ghost_rotate.status, StatusCode::NOT_FOUND);

    let bad_status = admin(
        &kit,
        Method::PATCH,
        &format!("{BASE}/admin/clients/ghost"),
        Some(r#"{"status": "paused"}"#),
    )
    .await;
    assert_eq!(bad_status.status, StatusCode::BAD_REQUEST);

    let nothing = admin(
        &kit,
        Method::PATCH,
        &format!("{BASE}/admin/clients/ghost"),
        Some("{}"),
    )
    .await;
    assert_eq!(nothing.status, StatusCode::BAD_REQUEST);
}

#[pollster::test]
async fn ids_are_ulids_and_listing_orders_by_creation() {
    let kit = admin_kit();
    for name in ["First", "Second"] {
        let response = admin(
            &kit,
            Method::POST,
            &format!("{BASE}/admin/clients"),
            Some(&format!(
                r#"{{"name": "{name}", "kind": "public", "redirect_uris": ["https://{name}.example/cb"]}}"#
            )),
        )
        .await;
        assert_eq!(response.status, StatusCode::CREATED);
        let id = response.json["id"].as_str().unwrap();
        assert!(
            id.chars().all(|c| c.is_ascii_alphanumeric()),
            "ULID alphabet: {id}"
        );
    }

    let listed = admin(&kit, Method::GET, &format!("{BASE}/admin/clients"), None).await;
    let clients = listed.json.as_array().cloned().unwrap_or_default();
    assert_eq!(clients.len(), 2);
    assert!(
        clients[0]["created_at"].as_str() <= clients[1]["created_at"].as_str(),
        "oldest first"
    );
}
