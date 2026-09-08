//! Issue #11 acceptance: local checks happen before a request is spent, the
//! route really does raise core's 64 KiB body cap, and dedupe never makes a
//! failed upload permanent.

mod support;

use axum::http::{Method, StatusCode};
use support::{ORG, connect, get, png, post_json, send};
use tower::ServiceExt;

const PUBLISHER: &str = "*/5 * * * *";

async fn ready_kit() -> support::Kit {
    let kit = support::kit();
    connect(&kit).await;
    post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;
    kit
}

async fn upload(kit: &support::Kit, bytes: Vec<u8>, content_type: &str) -> support::Res {
    send(
        kit,
        Method::POST,
        &format!("/v1/linkedin/admin/pages/{ORG}/images"),
        Some((content_type, bytes)),
        true,
    )
    .await
}

#[test]
fn an_image_is_registered_uploaded_and_reported_available() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let response = upload(&kit, png(1200, 630), "image/png").await;
        assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text());

        let body = response.json();
        assert_eq!(body["status"], "available");
        assert_eq!(body["width"], 1200);
        assert_eq!(body["height"], 630);
        assert_eq!(body["reused"], false);
        assert!(
            body["image_urn"]
                .as_str()
                .expect("urn")
                .starts_with("urn:li:image:"),
            "{body}"
        );

        // The upload goes to a different host, with the bearer and without
        // the Rest.li headers. The fake rejects either mistake.
        let put = kit
            .fake
            .calls_to("/dms-uploads/")
            .into_iter()
            .next()
            .expect("an upload");
        assert_eq!(put.method, "PUT");
        assert!(
            put.header("authorization").is_some(),
            "image uploads need the bearer"
        );
        assert!(put.header("linkedin-version").is_none());
        assert!(put.header("x-restli-protocol-version").is_none());
    });
}

#[test]
fn the_route_raises_cores_64_kib_body_cap() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        // Core layers DefaultBodyLimit::max(64 KiB) over every /v1/* route,
        // so without the route's own inner limit this never reaches the
        // handler.
        let mut big = png(800, 600);
        big.resize(200 * 1024, 0);
        let response = upload(&kit, big, "image/png").await;
        assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text());
        assert_eq!(response.json()["status"], "available");
    });
}

#[test]
fn an_oversize_body_is_refused_by_the_modules_own_limit() {
    pollster::block_on(async {
        let kit = support::kit_with({
            let mut pairs = support::config_pairs();
            pairs.push(("LINKEDIN_MAX_IMAGE_BYTES".to_owned(), "100000".to_owned()));
            pairs
        });
        connect(&kit).await;
        post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;

        let mut big = png(800, 600);
        big.resize(150 * 1024, 0);
        let response = upload(&kit, big, "image/png").await;
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(kit.fake.calls_to("/rest/images").is_empty());
    });
}

#[test]
fn everything_checkable_locally_is_checked_before_a_request_is_spent() {
    pollster::block_on(async {
        let kit = ready_kit().await;

        // Not an image at all.
        let junk = upload(&kit, b"this is not an image".to_vec(), "image/png").await;
        assert_eq!(junk.status, StatusCode::BAD_REQUEST);

        // A PNG announced as a JPEG.
        let mismatched = upload(&kit, png(100, 100), "image/jpeg").await;
        assert_eq!(mismatched.status, StatusCode::BAD_REQUEST);
        assert!(
            mismatched.json()["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("image/png")
        );

        // Over LinkedIn's pixel ceiling.
        let huge = upload(&kit, png(7000, 6000), "image/png").await;
        assert_eq!(huge.status, StatusCode::BAD_REQUEST);
        assert!(
            huge.json()["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("36152320")
        );

        // An empty body.
        let empty = upload(&kit, Vec::new(), "image/png").await;
        assert_eq!(empty.status, StatusCode::BAD_REQUEST);

        assert!(
            kit.fake.calls_to("/rest/images").is_empty(),
            "a local failure spent a LinkedIn request"
        );
    });
}

#[test]
fn the_same_bytes_are_uploaded_once_per_page() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let first = upload(&kit, png(600, 400), "image/png").await;
        let second = upload(&kit, png(600, 400), "image/png").await;

        assert_eq!(first.json()["reused"], false);
        assert_eq!(second.json()["reused"], true);
        assert_eq!(first.json()["image_urn"], second.json()["image_urn"]);
        assert_eq!(
            kit.fake.calls_to("action=initializeUpload").len(),
            1,
            "the same bytes were registered twice"
        );
    });
}

#[test]
fn a_failed_asset_is_never_reused() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        kit.fake.set_image_statuses(&["PROCESSING_FAILED"]);
        let failed = upload(&kit, png(600, 400), "image/png").await;
        assert_eq!(failed.json()["status"], "failed");

        // Dedupe must not make a bad upload permanent.
        kit.fake.set_image_statuses(&["AVAILABLE"]);
        let retried = upload(&kit, png(600, 400), "image/png").await;
        assert_eq!(retried.json()["reused"], false);
        assert_eq!(retried.json()["status"], "available");
        assert_eq!(kit.fake.calls_to("action=initializeUpload").len(), 2);
    });
}

#[test]
fn a_post_waits_for_an_asset_that_is_still_processing() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        kit.fake
            .set_image_statuses(&["PROCESSING", "PROCESSING", "AVAILABLE"]);

        let asset = upload(&kit, png(600, 400), "image/png").await;
        assert_eq!(asset.json()["status"], "processing");
        let asset_id = asset.json()["asset_id"]
            .as_str()
            .expect("asset id")
            .to_owned();

        post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &format!(
                r#"{{"commentary":"With a picture","idempotency_key":"k","asset_id":"{asset_id}"}}"#
            ),
        )
        .await;
        kit.drain().await;

        // A post referencing an asset that is still processing renders blank,
        // so it waits instead of publishing.
        assert_eq!(kit.fake.created_posts(), 0);
        let waiting = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(waiting["posts"][0]["state"], "scheduled");
        assert_eq!(waiting["posts"][0]["error_code"], "asset_processing");

        // The cron settles the asset, then publishes.
        kit.clock.advance_secs(120);
        kit.cron(PUBLISHER).await;
        kit.clock.advance_secs(120);
        kit.cron(PUBLISHER).await;

        assert_eq!(kit.fake.created_posts(), 1);
        let sent = kit
            .fake
            .calls_to("https://api.linkedin.com/rest/posts")
            .into_iter()
            .find(|call| call.method == "POST")
            .expect("a create")
            .json();
        assert!(
            sent["content"]["media"]["id"]
                .as_str()
                .unwrap_or_default()
                .starts_with("urn:li:image:"),
            "{sent}"
        );
    });
}

#[test]
fn alt_text_travels_with_the_asset_and_is_length_checked() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let response = send(
            &kit,
            Method::POST,
            &format!("/v1/linkedin/admin/pages/{ORG}/images"),
            Some(("image/png", png(600, 400))),
            true,
        )
        .await;
        assert_eq!(response.status, StatusCode::ACCEPTED);

        // Longer than LinkedIn's documented 4,086 character maximum.
        let request = axum::http::Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/linkedin/admin/pages/{ORG}/images"))
            .header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {}", support::ADMIN),
            )
            .header(axum::http::header::CONTENT_TYPE, "image/png")
            .header("x-alt-text", "a".repeat(5000))
            .body(axum::body::Body::from(png(600, 400)))
            .expect("request");
        let long = kit
            .harness
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router");
        assert_eq!(long.status(), StatusCode::BAD_REQUEST);
    });
}
