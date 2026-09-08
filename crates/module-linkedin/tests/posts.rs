//! Issue #12 and #13 acceptance. The important one is
//! `a_lost_create_response_is_reconciled_not_reposted`: LinkedIn has no
//! idempotency key on create, so without reconciliation a dropped response
//! posts the same thing publicly twice.

mod support;

use axum::http::StatusCode;
use support::{ORG, connect, delete, get, patch_json, post_json};

const PUBLISHER: &str = "*/5 * * * *";

fn create_body(commentary: &str, key: &str) -> String {
    format!(r#"{{"commentary":"{commentary}","idempotency_key":"{key}"}}"#)
}

async fn ready_kit() -> support::Kit {
    let kit = support::kit();
    connect(&kit).await;
    let synced = post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;
    assert_eq!(synced.status, StatusCode::OK, "{}", synced.text());
    kit
}

#[test]
fn a_post_is_created_then_published_and_confirmed() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let created = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &create_body("Hello from the harness", "key-1"),
        )
        .await;
        assert_eq!(created.status, StatusCode::ACCEPTED, "{}", created.text());
        assert_eq!(created.json()["post"]["state"], "scheduled");
        assert_eq!(created.json()["duplicate"], false);

        // Nothing has reached LinkedIn yet: publishing is never inline.
        assert_eq!(kit.fake.created_posts(), 0);

        kit.drain().await;

        assert_eq!(kit.fake.created_posts(), 1);
        let listed = get(&kit, "/v1/linkedin/admin/posts").await.json();
        let post = &listed["posts"][0];
        assert_eq!(post["state"], "published");
        assert!(
            post["permalink"]
                .as_str()
                .expect("permalink")
                .starts_with("https://www.linkedin.com/feed/update/urn:li:share:"),
            "{post}"
        );

        // The create carried what LinkedIn requires, with both versioning
        // headers.
        let create = kit
            .fake
            .calls_to("/rest/posts")
            .into_iter()
            .next()
            .expect("a create");
        assert_eq!(create.header("linkedin-version"), Some("202608"));
        assert_eq!(create.header("x-restli-protocol-version"), Some("2.0.0"));
        let sent = create.json();
        assert_eq!(sent["author"], format!("urn:li:organization:{ORG}"));
        assert_eq!(sent["lifecycleState"], "PUBLISHED");
        assert_eq!(sent["distribution"]["feedDistribution"], "MAIN_FEED");
        assert_eq!(sent["visibility"], "PUBLIC");
    });
}

#[test]
fn a_repeated_idempotency_key_never_posts_twice() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let path = format!("/v1/linkedin/admin/pages/{ORG}/posts");

        let first = post_json(&kit, &path, &create_body("Only once", "key-1")).await;
        kit.drain().await;
        let second = post_json(&kit, &path, &create_body("Only once", "key-1")).await;
        kit.drain().await;

        assert_eq!(second.json()["duplicate"], true);
        assert_eq!(
            first.json()["post"]["id"],
            second.json()["post"]["id"],
            "the retry got a different row"
        );
        assert_eq!(kit.fake.created_posts(), 1);
    });
}

#[test]
fn a_lost_create_response_is_reconciled_not_reposted() {
    pollster::block_on(async {
        let kit = ready_kit().await;

        // LinkedIn creates the post and the response never arrives. Without
        // reconciliation the next pass posts it again, publicly.
        kit.fake.lose_next_create();
        post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &create_body("A post that will be published once", "key-1"),
        )
        .await;
        kit.drain().await;

        assert_eq!(kit.fake.created_posts(), 1, "linkedin should hold one post");
        let after_loss = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(after_loss["posts"][0]["state"], "scheduled");
        assert!(after_loss["posts"][0]["post_urn"].is_null());

        // Past the retry clock, the publisher runs again.
        kit.clock.advance_secs(301);
        kit.cron(PUBLISHER).await;

        assert_eq!(
            kit.fake.created_posts(),
            1,
            "the retry created a second public post: {:?}",
            kit.fake.post_commentaries()
        );
        let recovered = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(recovered["posts"][0]["state"], "published");
        assert!(
            recovered["posts"][0]["post_urn"]
                .as_str()
                .expect("adopted urn")
                .starts_with("urn:li:share:")
        );
    });
}

#[test]
fn a_live_publish_lease_keeps_a_second_pass_out() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &create_body("Leased", "key-1"),
        )
        .await;

        // Pretend another pass is mid-publish and holding a fresh lease.
        let now = support::column(&kit, "SELECT created_at FROM linkedin_posts").expect("row");
        pollster::block_on(kit.db.execute(&cratefield_core::Statement::new(format!(
            "UPDATE linkedin_posts SET state = 'publishing', publishing_since = '{now}'"
        ))))
        .expect("update");

        kit.cron(PUBLISHER).await;
        assert_eq!(
            kit.fake.created_posts(),
            0,
            "a leased row was published anyway"
        );

        // Once the lease goes stale the row is reclaimed, reconciled (nothing
        // to adopt) and published exactly once.
        kit.clock.advance_secs(601);
        kit.cron(PUBLISHER).await;
        assert_eq!(kit.fake.created_posts(), 1);
    });
}

#[test]
fn one_pass_publishes_each_due_post_exactly_once() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let path = format!("/v1/linkedin/admin/pages/{ORG}/posts");
        // Two rows, so a claim that was not scoped to one post would show up
        // as a row that never publishes or as a duplicate.
        for index in 0..2 {
            post_json(
                &kit,
                &path,
                &create_body(&format!("Post {index}"), &format!("key-{index}")),
            )
            .await;
        }

        kit.cron(PUBLISHER).await;

        assert_eq!(kit.fake.created_posts(), 2);
        let mut published = kit.fake.post_commentaries();
        published.sort();
        assert_eq!(published, ["Post 0", "Post 1"]);
        let listed = get(&kit, "/v1/linkedin/admin/posts").await.json();
        for post in listed["posts"].as_array().expect("posts") {
            assert_eq!(post["state"], "published", "{post}");
        }
    });
}

#[test]
fn a_201_is_not_treated_as_published() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        kit.fake.set_lifecycle("PUBLISH_REQUESTED");

        post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &create_body("Still processing", "key-1"),
        )
        .await;
        kit.drain().await;

        let pending = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(pending["posts"][0]["state"], "publish_requested");

        // LinkedIn finishes processing; the next pass confirms it.
        kit.fake.settle_posts("PUBLISHED");
        kit.cron(PUBLISHER).await;

        let settled = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(settled["posts"][0]["state"], "published");
        assert_eq!(kit.fake.created_posts(), 1);
    });
}

#[test]
fn a_publish_failure_is_terminal_and_not_retried() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        kit.fake.set_lifecycle("PUBLISH_FAILED");

        post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &create_body("Doomed", "key-1"),
        )
        .await;
        kit.drain().await;

        let failed = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(failed["posts"][0]["state"], "failed");
        assert_eq!(failed["posts"][0]["error_code"], "publish_failed");

        // LinkedIn's own note is that an edit is required before publishing
        // can be re-attempted, so no pass may quietly try again.
        kit.clock.advance_secs(3600);
        kit.cron(PUBLISHER).await;
        assert_eq!(kit.fake.created_posts(), 1);
    });
}

#[test]
fn a_rate_limited_publish_waits_for_the_retry_after() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        kit.fake.rate_limit_next("/rest/posts", "900");

        post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &create_body("Too fast", "key-1"),
        )
        .await;
        kit.drain().await;

        let deferred = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(deferred["posts"][0]["state"], "scheduled");
        assert_eq!(deferred["posts"][0]["error_code"], "rate_limited");
        assert_eq!(kit.fake.created_posts(), 0);

        // Still inside the window LinkedIn asked for.
        kit.clock.advance_secs(600);
        kit.cron(PUBLISHER).await;
        assert_eq!(kit.fake.created_posts(), 0);

        kit.clock.advance_secs(400);
        kit.cron(PUBLISHER).await;
        assert_eq!(kit.fake.created_posts(), 1);
    });
}

#[test]
fn plain_commentary_is_escaped_for_every_reserved_character() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            r#"{"commentary":"a_b*c~d #tag (x) <y> {z} |p| @me [q] \\","idempotency_key":"key-1"}"#,
        )
        .await;
        kit.drain().await;

        let sent = kit
            .fake
            .calls_to("/rest/posts")
            .into_iter()
            .next()
            .expect("a create")
            .json();
        let commentary = sent["commentary"].as_str().expect("commentary");
        for reserved in [
            '_', '*', '~', '#', '(', ')', '<', '>', '{', '}', '|', '@', '[', ']',
        ] {
            let escaped = format!("\\{reserved}");
            assert!(
                commentary.contains(&escaped),
                "{reserved} was not escaped in {commentary}"
            );
        }
    });
}

#[test]
fn pre_formatted_commentary_is_passed_through() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            r#"{"commentary":"Hello @[DevTestCo](urn:li:organization:2414183)","commentary_format":"little","idempotency_key":"key-1"}"#,
        )
        .await;
        kit.drain().await;

        let sent = kit
            .fake
            .calls_to("/rest/posts")
            .into_iter()
            .next()
            .expect("a create")
            .json();
        assert_eq!(
            sent["commentary"],
            "Hello @[DevTestCo](urn:li:organization:2414183)"
        );
    });
}

#[test]
fn an_edit_that_linkedin_forbids_is_refused_here_with_a_reason() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let created = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &create_body("Original", "key-1"),
        )
        .await;
        kit.drain().await;
        let id = created.json()["post"]["id"]
            .as_str()
            .expect("id")
            .to_owned();

        let refused = patch_json(
            &kit,
            &format!("/v1/linkedin/admin/posts/{id}"),
            r#"{"asset_id":"whatever"}"#,
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        let detail = refused.json()["detail"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(detail.contains("media"), "{detail}");
        assert!(detail.contains("Delete the post"), "{detail}");

        let visibility = patch_json(
            &kit,
            &format!("/v1/linkedin/admin/posts/{id}"),
            r#"{"visibility":"LOGGED_IN"}"#,
        )
        .await;
        assert_eq!(visibility.status, StatusCode::BAD_REQUEST);

        // Nothing was sent for either refusal.
        assert!(kit.fake.calls_to("X-RestLi").is_empty());
    });
}

#[test]
fn an_allowed_edit_is_a_partial_update_post() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let created = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &create_body("Original", "key-1"),
        )
        .await;
        kit.drain().await;
        let id = created.json()["post"]["id"]
            .as_str()
            .expect("id")
            .to_owned();

        let edited = patch_json(
            &kit,
            &format!("/v1/linkedin/admin/posts/{id}"),
            r#"{"commentary":"Corrected","content_call_to_action_label":"LEARN_MORE"}"#,
        )
        .await;
        assert_eq!(edited.status, StatusCode::OK, "{}", edited.text());
        assert_eq!(edited.json()["sent_to_linkedin"], true);
        assert_eq!(edited.json()["post"]["previous_commentary"], "Original");

        let update = kit
            .fake
            .calls()
            .into_iter()
            .find(|call| call.header("x-restli-method") == Some("PARTIAL_UPDATE"))
            .expect("a partial update");
        // On LinkedIn's side this is a POST, not an HTTP PATCH.
        assert_eq!(update.method, "POST");
        assert_eq!(update.json()["patch"]["$set"]["commentary"], "Corrected");
        assert_eq!(
            update.json()["patch"]["$set"]["contentCallToActionLabel"],
            "LEARN_MORE"
        );
    });
}

#[test]
fn deleting_twice_succeeds_and_calls_linkedin_once() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let created = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &create_body("Regrettable", "key-1"),
        )
        .await;
        kit.drain().await;
        let id = created.json()["post"]["id"]
            .as_str()
            .expect("id")
            .to_owned();

        let first = delete(&kit, &format!("/v1/linkedin/admin/posts/{id}")).await;
        assert_eq!(first.status, StatusCode::OK);
        assert_eq!(first.json()["already_deleted"], false);

        let second = delete(&kit, &format!("/v1/linkedin/admin/posts/{id}")).await;
        assert_eq!(second.status, StatusCode::OK);
        assert_eq!(second.json()["already_deleted"], true);

        let deletes = kit
            .fake
            .calls()
            .into_iter()
            .filter(|call| call.method == "DELETE")
            .count();
        assert_eq!(deletes, 1, "the second delete spent a request");
    });
}

#[test]
fn a_scheduled_post_waits_for_its_time() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let later = "2026-09-08T09:00:00Z";
        let created = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &format!(
                r#"{{"commentary":"Tomorrow","idempotency_key":"key-1","scheduled_at":"{later}"}}"#
            ),
        )
        .await;
        assert_eq!(created.status, StatusCode::ACCEPTED);

        // A scheduled post is not deferred: only the cron may publish it.
        kit.drain().await;
        kit.cron(PUBLISHER).await;
        assert_eq!(kit.fake.created_posts(), 0);

        kit.clock.advance_days(1);
        kit.cron(PUBLISHER).await;
        assert_eq!(kit.fake.created_posts(), 1);
    });
}

#[test]
fn a_create_is_validated_before_anything_is_stored() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let path = format!("/v1/linkedin/admin/pages/{ORG}/posts");
        for (body, why) in [
            (
                r#"{"commentary":"","idempotency_key":"k"}"#,
                "empty commentary",
            ),
            (r#"{"commentary":"x","idempotency_key":""}"#, "empty key"),
            (
                r#"{"commentary":"x","idempotency_key":"k","visibility":"FRIENDS"}"#,
                "unknown visibility",
            ),
            (
                r#"{"commentary":"x","idempotency_key":"k","scheduled_at":"tomorrow"}"#,
                "unparseable scheduled_at",
            ),
            (
                r#"{"commentary":"x","idempotency_key":"k","asset_id":"nope"}"#,
                "unknown asset",
            ),
        ] {
            let response = post_json(&kit, &path, body).await;
            assert_eq!(
                response.status,
                StatusCode::BAD_REQUEST,
                "{why} was accepted"
            );
        }
        assert_eq!(support::count(&kit, "linkedin_posts", "1=1"), 0);
    });
}

#[test]
fn a_page_the_account_cannot_publish_to_is_refused_locally() {
    pollster::block_on(async {
        let kit = support::kit();
        // A direct-sponsored-content role can upload media but cannot put a
        // post in the feed.
        kit.fake
            .set_acls(&[(ORG, "DIRECT_SPONSORED_CONTENT_POSTER")]);
        connect(&kit).await;
        post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;

        let refused = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            &create_body("Not allowed", "key-1"),
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.text());
        assert!(
            refused.json()["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("DIRECT_SPONSORED_CONTENT_POSTER")
        );
        assert_eq!(kit.fake.created_posts(), 0);
    });
}
