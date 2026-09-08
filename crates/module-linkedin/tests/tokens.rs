//! Issue #9 acceptance: the refresh TTL is stored, not recomputed; only
//! LinkedIn's expiry wording flips an account; a 401 mid-publish refreshes
//! once and succeeds; and a dead connection blocks writes with a 409 that
//! names the fix.

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{ORG, connect, get, post_json};

const DAILY: &str = "0 3 * * *";
const PUBLISHER: &str = "*/5 * * * *";

/// LinkedIn's documented wording for a refresh token that is gone.
fn dead_refresh_token() -> serde_json::Value {
    json!({
        "error": "invalid_request",
        "error_description":
            "The provided authorization grant or refresh token is invalid, expired or revoked",
    })
}

async fn connected_kit() -> support::Kit {
    let kit = support::kit();
    connect(&kit).await;
    post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;
    kit
}

#[test]
fn an_access_token_is_refreshed_before_it_lapses() {
    pollster::block_on(async {
        let kit = connected_kit().await;
        let before = get(&kit, "/v1/linkedin/admin/status").await.json();
        assert_eq!(before["access_expires_in_days"], 60);

        // Day 50: ten days left, outside the seven-day lead, so nothing
        // happens.
        kit.clock.advance_days(50);
        kit.cron(DAILY).await;
        assert_eq!(
            kit.fake.calls_to("/oauth/v2/accessToken").len(),
            1,
            "refreshed outside the lead window"
        );

        // Day 55: five days left, inside it.
        kit.clock.advance_days(5);
        kit.cron(DAILY).await;
        assert_eq!(kit.fake.calls_to("/oauth/v2/accessToken").len(), 2);

        let after = get(&kit, "/v1/linkedin/admin/status").await.json();
        assert_eq!(after["access_expires_in_days"], 60);
        assert_eq!(after["status"], "connected");
    });
}

#[test]
fn the_refresh_ttl_comes_from_linkedin_and_is_never_recomputed() {
    pollster::block_on(async {
        let kit = connected_kit().await;

        // Day 300 of a 365-day refresh token: LinkedIn says 65 days are
        // left, and refreshing does not extend that.
        kit.clock.advance_days(300);
        kit.fake.set_token_response(json!({
            "access_token": "new-access-token",
            "expires_in": 5_184_000i64,
            "refresh_token": "refresh-token-value",
            "refresh_token_expires_in": 5_616_000i64,
            "scope": "rw_organization_admin r_organization_admin r_organization_social w_organization_social",
        }));
        kit.cron(DAILY).await;

        let status = get(&kit, "/v1/linkedin/admin/status").await.json();
        assert_eq!(
            status["refresh_expires_in_days"], 65,
            "the refresh TTL was recomputed instead of stored: {status}"
        );
        assert_eq!(status["access_expires_in_days"], 60);
    });
}

#[test]
fn a_dead_refresh_token_blocks_writes_with_a_reconnect_problem() {
    pollster::block_on(async {
        let kit = connected_kit().await;
        kit.clock.advance_days(366);
        kit.fake.set_token_error(400, dead_refresh_token());

        kit.cron(DAILY).await;

        let status = get(&kit, "/v1/linkedin/admin/status").await.json();
        assert_eq!(status["status"], "needs_reconnect");
        assert_eq!(status["connected"], false);

        let refused = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            r#"{"commentary":"hi","idempotency_key":"k"}"#,
        )
        .await;
        assert_eq!(refused.status, StatusCode::CONFLICT);
        assert_eq!(
            refused.json()["type"],
            "https://factory0.ventures/problems/linkedin-reconnect-required"
        );

        // Flipping happens once, not on every pass.
        kit.cron(DAILY).await;
        assert_eq!(
            get(&kit, "/v1/linkedin/admin/status").await.json()["status"],
            "needs_reconnect"
        );
    });
}

#[test]
fn a_missing_parameter_is_our_bug_and_never_costs_the_connection() {
    pollster::block_on(async {
        let kit = connected_kit().await;
        kit.clock.advance_days(59);

        // Same status, same error code, entirely different meaning: this one
        // is a malformed request of ours, not an expiry.
        kit.fake.set_token_error(
            400,
            json!({
                "error": "invalid_request",
                "error_description": "A required parameter \"grant_type\" is missing",
            }),
        );
        kit.cron(DAILY).await;

        let status = get(&kit, "/v1/linkedin/admin/status").await.json();
        assert_eq!(
            status["status"], "connected",
            "a bug in our request self-inflicted a reconnect: {status}"
        );
    });
}

#[test]
fn a_401_mid_publish_refreshes_once_and_succeeds() {
    pollster::block_on(async {
        let kit = connected_kit().await;

        // LinkedIn may revoke a token at any time, which its documentation
        // reserves the right to do. A scheduled post must survive that.
        kit.fake.fail_next(
            "https://api.linkedin.com/rest/posts",
            401,
            json!({ "message": "Empty or invalid oauth2 access token" }),
        );

        post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            r#"{"commentary":"Survives a revoked token","idempotency_key":"k"}"#,
        )
        .await;
        kit.drain().await;

        assert_eq!(kit.fake.created_posts(), 1, "the post was lost to a 401");
        let posted = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(posted["posts"][0]["state"], "published");

        // Exactly one extra token call: the connect, then the one refresh.
        assert_eq!(kit.fake.calls_to("/oauth/v2/accessToken").len(), 2);
        assert_eq!(
            get(&kit, "/v1/linkedin/admin/status").await.json()["status"],
            "connected"
        );
    });
}

#[test]
fn a_401_that_a_refresh_cannot_fix_ends_in_reconnect_not_a_lost_post() {
    pollster::block_on(async {
        let kit = connected_kit().await;
        kit.fake.fail_next(
            "https://api.linkedin.com/rest/posts",
            401,
            json!({ "message": "Empty or invalid oauth2 access token" }),
        );
        kit.fake.set_token_error(400, dead_refresh_token());

        post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            r#"{"commentary":"Waits for a human","idempotency_key":"k"}"#,
        )
        .await;
        kit.drain().await;

        assert_eq!(kit.fake.created_posts(), 0);
        assert_eq!(
            get(&kit, "/v1/linkedin/admin/status").await.json()["status"],
            "needs_reconnect"
        );

        // The post is not burned: it waits for someone to reconnect.
        let waiting = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(waiting["posts"][0]["state"], "scheduled");
    });
}

#[test]
fn the_expiry_warning_is_emitted_once() {
    pollster::block_on(async {
        let kit = connected_kit().await;

        // Day 340 of 365: 25 days left on a token that cannot be renewed.
        kit.clock.advance_days(340);
        kit.cron(DAILY).await;
        let notified = support::column(&kit, "SELECT expiring_notified_at FROM linkedin_accounts");
        assert!(notified.is_some(), "no expiry warning was recorded");

        kit.clock.advance_days(1);
        kit.cron(DAILY).await;
        let again = support::column(&kit, "SELECT expiring_notified_at FROM linkedin_accounts");
        assert_eq!(notified, again, "the warning fired twice");
    });
}

#[test]
fn a_publisher_only_deployment_still_keeps_its_token_alive() {
    pollster::block_on(async {
        let kit = connected_kit().await;
        kit.clock.advance_days(59);

        // A venture that wires only the frequent cron must not lose its
        // connection, so token upkeep runs on both triggers.
        kit.cron(PUBLISHER).await;
        assert_eq!(kit.fake.calls_to("/oauth/v2/accessToken").len(), 2);
        assert_eq!(
            get(&kit, "/v1/linkedin/admin/status").await.json()["access_expires_in_days"],
            60
        );
    });
}

#[test]
fn work_before_a_connection_answers_not_connected() {
    pollster::block_on(async {
        let kit = support::kit();
        let status = get(&kit, "/v1/linkedin/admin/status").await;
        assert_eq!(status.json()["connected"], false);

        let synced = post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;
        assert_eq!(synced.status, StatusCode::CONFLICT);
        assert_eq!(
            synced.json()["type"],
            "https://factory0.ventures/problems/linkedin-not-connected"
        );
    });
}
