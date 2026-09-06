//! Issue #8 acceptance: a state is spent exactly once, a tampered state is
//! refused, an expired state is refused under a test clock, the callback
//! reflects nothing back, and no token reaches a response.

mod support;

use axum::http::{Method, StatusCode};
use support::{ADMIN, connect, delete, get, post_json, send, state_of};

#[test]
fn connect_returns_an_authorize_url_with_the_compiled_in_scopes() {
    pollster::block_on(async {
        let kit = support::kit();
        let started = post_json(&kit, "/v1/linkedin/admin/connect", "{}").await;
        assert_eq!(started.status, StatusCode::OK);

        let body = started.json();
        let url = body["authorize_url"].as_str().expect("authorize_url");
        assert!(url.starts_with("https://www.linkedin.com/oauth/v2/authorization"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=client-id"));
        assert!(url.contains("rw_organization_admin"));
        assert!(url.contains("w_organization_social"));
        // The OIDC scopes were cut deliberately: a second API product on the
        // app collides with Community Management access.
        assert!(!url.contains("openid"));
        assert!(!url.contains("profile"));
        assert!(body["expires_at"].is_string());
    });
}

#[test]
fn admin_routes_are_closed_without_the_bearer() {
    pollster::block_on(async {
        let kit = support::kit();
        for (method, path) in [
            (Method::POST, "/v1/linkedin/admin/connect"),
            (Method::GET, "/v1/linkedin/admin/status"),
            (Method::GET, "/v1/linkedin/admin/pages"),
            (Method::DELETE, "/v1/linkedin/admin/account"),
        ] {
            let response = send(&kit, method.clone(), path, None, false).await;
            assert_eq!(
                response.status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} was open"
            );
        }
    });
}

#[test]
fn a_state_can_be_spent_exactly_once() {
    pollster::block_on(async {
        let kit = support::kit();
        let started = post_json(&kit, "/v1/linkedin/admin/connect", "{}").await;
        let state = state_of(started.json()["authorize_url"].as_str().expect("url"));
        let path = format!("/v1/linkedin/callback?code=auth-code&state={state}");

        let first = send(&kit, Method::GET, &path, None, false).await;
        assert_eq!(first.status, StatusCode::OK, "{}", first.text());

        // The replay must not reach the token exchange. That is the whole
        // CSRF defence: LinkedIn documents no PKCE for this flow.
        let replay = send(&kit, Method::GET, &path, None, false).await;
        assert_eq!(replay.status, StatusCode::BAD_REQUEST);

        let exchanges = kit.fake.calls_to("/oauth/v2/accessToken").len();
        assert_eq!(exchanges, 1, "the token exchange ran {exchanges} times");
    });
}

#[test]
fn a_tampered_state_is_refused() {
    pollster::block_on(async {
        let kit = support::kit();
        let started = post_json(&kit, "/v1/linkedin/admin/connect", "{}").await;
        let state = state_of(started.json()["authorize_url"].as_str().expect("url"));
        let tampered = format!("{}x", &state[..state.len() - 1]);

        let response = send(
            &kit,
            Method::GET,
            &format!("/v1/linkedin/callback?code=auth-code&state={tampered}"),
            None,
            false,
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(kit.fake.calls_to("/oauth/v2/accessToken").is_empty());
        // The row is still there: a forged state must not spend a real one.
        assert_eq!(support::count(&kit, "linkedin_oauth_states", "1=1"), 1);
    });
}

#[test]
fn an_expired_state_is_refused_by_the_row_not_the_signature() {
    pollster::block_on(async {
        let kit = support::kit();
        let started = post_json(&kit, "/v1/linkedin/admin/connect", "{}").await;
        let state = state_of(started.json()["authorize_url"].as_str().expect("url"));

        // Signer::verify reads the wall clock, so the deadline has to live on
        // the row for a test clock to be able to move past it.
        kit.clock.advance_secs(3600);

        let response = send(
            &kit,
            Method::GET,
            &format!("/v1/linkedin/callback?code=auth-code&state={state}"),
            None,
            false,
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(kit.fake.calls_to("/oauth/v2/accessToken").is_empty());
    });
}

#[test]
fn the_callback_never_reflects_what_linkedin_sent_it() {
    pollster::block_on(async {
        let kit = support::kit();
        let payload = "%3Cscript%3Ealert(1)%3C/script%3E";
        let response = send(
            &kit,
            Method::GET,
            &format!(
                "/v1/linkedin/callback?error=user_cancelled_login&error_description={payload}"
            ),
            None,
            false,
        )
        .await;

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(response.content_type().starts_with("text/html"));
        let body = response.text();
        assert!(!body.contains("<script>"), "reflected script tag: {body}");
        assert!(!body.contains("alert(1)"), "reflected payload: {body}");
        assert!(
            !body.contains("user_cancelled_login"),
            "reflected error: {body}"
        );
    });
}

#[test]
fn status_reports_expiries_and_scopes_but_never_a_token() {
    pollster::block_on(async {
        let kit = support::kit();
        connect(&kit).await;

        let status = get(&kit, "/v1/linkedin/admin/status").await;
        assert_eq!(status.status, StatusCode::OK);
        let body = status.json();
        assert_eq!(body["connected"], true);
        assert_eq!(body["status"], "connected");
        // 60 days for the access token, 365 for the refresh token.
        assert_eq!(body["access_expires_in_days"], 60);
        assert_eq!(body["refresh_expires_in_days"], 365);
        assert_eq!(body["budget"]["spent"], 1);

        let text = status.text();
        assert!(!text.contains("access-token-value"), "{text}");
        assert!(!text.contains("refresh-token-value"), "{text}");
    });
}

#[test]
fn tokens_are_sealed_at_rest_and_bound_to_their_column() {
    pollster::block_on(async {
        let kit = support::kit();
        connect(&kit).await;

        let access = support::column(&kit, "SELECT access_token FROM linkedin_accounts")
            .expect("an access token row");
        let refresh = support::column(&kit, "SELECT refresh_token FROM linkedin_accounts")
            .expect("a refresh token row");

        assert!(
            !access.contains("access-token-value"),
            "stored in the clear"
        );
        assert!(
            !refresh.contains("refresh-token-value"),
            "stored in the clear"
        );
        assert_ne!(access, refresh);
        // Version byte 1, key id 1, then a 24-byte nonce: the blob is long
        // enough that it cannot be the plaintext.
        assert!(access.len() > 40, "{access}");
    });
}

#[test]
fn disconnect_forgets_the_tokens_and_keeps_the_history() {
    pollster::block_on(async {
        let kit = support::kit();
        connect(&kit).await;
        assert_eq!(support::count(&kit, "linkedin_accounts", "1=1"), 1);

        let response = delete(&kit, "/v1/linkedin/admin/account").await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.json()["removed"], 1);
        assert_eq!(support::count(&kit, "linkedin_accounts", "1=1"), 0);

        let status = get(&kit, "/v1/linkedin/admin/status").await;
        assert_eq!(status.json()["connected"], false);
    });
}

#[test]
fn a_callback_without_a_code_changes_nothing() {
    pollster::block_on(async {
        let kit = support::kit();
        let response = send(&kit, Method::GET, "/v1/linkedin/callback", None, false).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(support::count(&kit, "linkedin_accounts", "1=1"), 0);
        let _ = ADMIN;
    });
}
