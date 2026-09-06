//! Issue #7 acceptance, HTTP half: registration (create and patch)
//! rejects URIs the matcher would never accept — fragments, wildcards,
//! relative references, userinfo, plain http off localhost, custom
//! schemes on confidential clients — and accepts the legal shapes per
//! client kind. The `/authorize` render-don't-redirect half lands with
//! issue #10, which is where `/authorize` exists.

use axum::http::{Method, StatusCode, header};
use factory0_auth_core::AuthCore;
use factory0_testing::TestHarness;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";

fn kit() -> TestHarness {
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = Arc::new(factory0_core::MapConfig::from_pairs([(
            "ADMIN_TOKEN",
            ADMIN,
        )]));
    })
}

async fn admin(
    kit: &TestHarness,
    method: Method,
    path: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
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
    let response = kit.router.clone().oneshot(request).await.expect("answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

fn body_for(kind: &str, uris_json: &str) -> String {
    format!(r#"{{"name": "App", "kind": "{kind}", "redirect_uris": {uris_json}}}"#)
}

#[pollster::test]
async fn create_rejects_what_the_matcher_would_never_accept() {
    let kit = kit();
    for (uris, why) in [
        (r#"["https://undercoverrockstars.com/cb#frag"]"#, "fragment"),
        (r#"["https://*.example.com/cb"]"#, "wildcard"),
        (r#"["/callback"]"#, "relative"),
        (r#"["undercoverrockstars.com/cb"]"#, "no scheme"),
        (
            r#"["https://user:pass@undercoverrockstars.com/cb"]"#,
            "userinfo",
        ),
        (r#"["myapp:"]"#, "bare custom scheme"),
        (r#"["http://example.com/cb"]"#, "http off localhost, public"),
        (
            r#"["http://localhost:3000/cb"]"#,
            "http localhost, confidential",
        ),
        (r#"["com.example.app:/cb"]"#, "custom scheme, confidential"),
    ] {
        let kind = if why.ends_with("confidential") {
            "confidential"
        } else {
            "public"
        };
        let (status, body) = admin(
            &kit,
            Method::POST,
            "/v1/auth-core/admin/clients",
            Some(&body_for(kind, uris)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{why}: {body}");
        assert_eq!(
            body["type"], "https://factory0.ventures/problems/validation-failed",
            "{why}"
        );
    }
}

#[pollster::test]
async fn create_accepts_the_legal_shapes_per_kind() {
    let kit = kit();
    for (kind, uri) in [
        (
            "confidential",
            "https://undercoverrockstars.com/auth/callback",
        ),
        ("public", "https://kontinuum.audio/cb"),
        ("public", "http://localhost:3000/cb"),
        ("public", "http://127.0.0.1/cb"),
        ("public", "com.example.app:/callback"),
        ("public", "myapp://callback/x"),
    ] {
        let (status, body) = admin(
            &kit,
            Method::POST,
            "/v1/auth-core/admin/clients",
            Some(&body_for(kind, &format!("[\"{uri}\"]"))),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{uri}: {body}");
        assert_eq!(body["redirect_uris"][0], uri);
    }
}

#[pollster::test]
async fn patch_revalidates_and_leaves_the_client_untouched_on_reject() {
    let kit = kit();
    let (_, created) = admin(
        &kit,
        Method::POST,
        "/v1/auth-core/admin/clients",
        Some(&body_for("public", r#"["https://kontinuum.audio/cb"]"#)),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_owned();

    let (status, body) = admin(
        &kit,
        Method::PATCH,
        &format!("/v1/auth-core/admin/clients/{id}"),
        Some(
            r#"{"redirect_uris": ["https://kontinuum.audio/cb", "https://kontinuum.audio/cb#f"]}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let uris = factory0_auth_core::redirect_uris_for_client(&*kit.db, &id)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.uri)
        .collect::<Vec<_>>();
    assert_eq!(
        uris,
        vec!["https://kontinuum.audio/cb".to_owned()],
        "the rejected patch wrote nothing"
    );

    let (status, body) = admin(
        &kit,
        Method::PATCH,
        &format!("/v1/auth-core/admin/clients/{id}"),
        Some(r#"{"redirect_uris": ["https://kontinuum.audio/cb", "http://localhost:9/cb"]}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["redirect_uris"].as_array().map(Vec::len), Some(2));
}

#[pollster::test]
async fn the_matcher_table_over_the_wire_shape() {
    let registered = vec![
        "https://undercoverrockstars.com/auth/callback".to_owned(),
        "com.example.app:/callback".to_owned(),
    ];
    assert!(factory0_auth_core::redirect_uri::matches_any(
        &registered,
        "https://undercoverrockstars.com/auth/callback"
    ));
    assert!(factory0_auth_core::redirect_uri::matches_any(
        &registered,
        "com.example.app:/callback"
    ));
    assert!(!factory0_auth_core::redirect_uri::matches_any(
        &registered,
        "https://undercoverrockstars.com/auth/callback/"
    ));
    assert!(!factory0_auth_core::redirect_uri::matches_any(
        &registered,
        "https://evil.example/auth/callback"
    ));
}
