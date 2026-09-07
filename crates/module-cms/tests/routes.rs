//! Behaviour of the CMS module through its router, across dialects: the
//! draft/publish/read lifecycle, versioning, the admin gate, the collection
//! allowlist, and unpublish/delete.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use cratefield_core::MapConfig;
use cratefield_module_cms::Cms;
use cratefield_testing::{TestHarness, TestResponse, request};
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";

fn kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || vec![Box::new(Cms::new().collections(["pages"]))],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
        },
    )
}

/// An authenticated admin POST with a JSON body, returned as raw parts.
async fn admin_post(kit: &TestHarness, path: &str, body: &str) -> (StatusCode, String) {
    let response = kit
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_owned()))
                .expect("request"),
        )
        .await
        .expect("answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn get(kit: &TestHarness, path: &str) -> TestResponse {
    request(&kit.router, Method::GET, path, None).await
}

#[pollster::test]
async fn the_draft_publish_read_lifecycle() {
    for kit in kits() {
        // Nothing published yet.
        let before = get(&kit, "/v1/cms/pages/about").await;
        assert_eq!(before.status, StatusCode::NOT_FOUND);

        // Save a draft.
        let (status, body) = admin_post(
            &kit,
            "/v1/cms/admin/save",
            r#"{"collection":"pages","slug":"about","title":"About","body":"Hello","data":{"hero":"x"}}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("\"status\":\"draft\""), "{body}");

        // A draft is not publicly readable.
        assert_eq!(
            get(&kit, "/v1/cms/pages/about").await.status,
            StatusCode::NOT_FOUND
        );

        // Publish it.
        let (status, body) = admin_post(
            &kit,
            "/v1/cms/admin/publish",
            r#"{"collection":"pages","slug":"about"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("\"version\":1"), "{body}");

        // Now the public read resolves the published content.
        let read = get(&kit, "/v1/cms/pages/about").await;
        assert_eq!(read.status, StatusCode::OK);
        let json = read.json();
        assert_eq!(json["title"], "About");
        assert_eq!(json["body"], "Hello");
        assert_eq!(json["data"]["hero"], "x");
        assert_eq!(json["version"], 1);

        // It appears in the collection listing.
        let collection = get(&kit, "/v1/cms/pages").await;
        assert_eq!(collection.status, StatusCode::OK);
        assert_eq!(collection.json()["items"].as_array().unwrap().len(), 1);
    }
}

#[pollster::test]
async fn editing_after_publish_keeps_the_old_version_public_until_republished() {
    for kit in kits() {
        admin_post(
            &kit,
            "/v1/cms/admin/save",
            r#"{"collection":"pages","slug":"about","title":"V1","body":"one"}"#,
        )
        .await;
        admin_post(
            &kit,
            "/v1/cms/admin/publish",
            r#"{"collection":"pages","slug":"about"}"#,
        )
        .await;

        // Edit the draft; the public read still serves version 1.
        admin_post(
            &kit,
            "/v1/cms/admin/save",
            r#"{"collection":"pages","slug":"about","title":"V2","body":"two"}"#,
        )
        .await;
        let read = get(&kit, "/v1/cms/pages/about").await;
        assert_eq!(
            read.json()["title"],
            "V1",
            "the published version is unchanged"
        );

        // Republish; now version 2 is public.
        let (_, body) = admin_post(
            &kit,
            "/v1/cms/admin/publish",
            r#"{"collection":"pages","slug":"about"}"#,
        )
        .await;
        assert!(body.contains("\"version\":2"), "{body}");
        assert_eq!(get(&kit, "/v1/cms/pages/about").await.json()["title"], "V2");
    }
}

#[pollster::test]
async fn unpublish_hides_the_public_read_but_keeps_the_item() {
    for kit in kits() {
        admin_post(
            &kit,
            "/v1/cms/admin/save",
            r#"{"collection":"pages","slug":"about","title":"About","body":"x"}"#,
        )
        .await;
        admin_post(
            &kit,
            "/v1/cms/admin/publish",
            r#"{"collection":"pages","slug":"about"}"#,
        )
        .await;
        assert_eq!(
            get(&kit, "/v1/cms/pages/about").await.status,
            StatusCode::OK
        );

        let (status, _) = admin_post(
            &kit,
            "/v1/cms/admin/unpublish",
            r#"{"collection":"pages","slug":"about"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            get(&kit, "/v1/cms/pages/about").await.status,
            StatusCode::NOT_FOUND
        );
    }
}

#[pollster::test]
async fn writes_require_the_admin_token() {
    for kit in kits() {
        // No bearer token: unauthorized, and nothing is created.
        let denied = request(
            &kit.router,
            Method::POST,
            "/v1/cms/admin/save",
            Some(r#"{"collection":"pages","slug":"about","title":"x"}"#),
        )
        .await;
        assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            get(&kit, "/v1/cms/pages/about").await.status,
            StatusCode::NOT_FOUND
        );
    }
}

#[pollster::test]
async fn a_collection_the_venture_did_not_allow_is_refused() {
    for kit in kits() {
        // `posts` is not in the allowlist (only `pages`).
        let (status, _) = admin_post(
            &kit,
            "/v1/cms/admin/save",
            r#"{"collection":"posts","slug":"hello","title":"x"}"#,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an unlisted collection is refused"
        );
        assert_eq!(
            get(&kit, "/v1/cms/posts").await.status,
            StatusCode::NOT_FOUND
        );
    }
}

#[pollster::test]
async fn save_rejects_a_non_object_data_and_an_empty_slug() {
    for kit in kits() {
        let (status, _) = admin_post(
            &kit,
            "/v1/cms/admin/save",
            r#"{"collection":"pages","slug":"about","data":[1,2,3]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "data must be an object");

        let (status, _) = admin_post(
            &kit,
            "/v1/cms/admin/save",
            r#"{"collection":"pages","slug":"   "}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "slug must not be empty");
    }
}
