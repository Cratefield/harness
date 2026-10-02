//! The callback route and the open-redirect boundary (issue #624).
//!
//! The callback is the module's only route and it is public, so the tests
//! here are about what it refuses: a `state` that was never issued, one
//! already spent, one whose `return_to` is not on an allowed origin — and the
//! three shapes of URL that look allowed and are not.

mod support;

use axum::http::StatusCode;

use cratefield_module_connections::{AccessToken, ConnectionError, ConnectionStatus};

use support::{
    INVALID_GRANT, REFRESHED_BODY, RETURN_TO, Spec, begin, callback_url, connect, fixture,
};

/// A `return_to` on an allowed origin comes back with `connection=<id>`, and
/// the id names a row that exists.
#[pollster::test]
async fn a_callback_redirects_to_the_allowed_origin_with_the_connection() {
    for kit in fixture(&Spec::default()).kits {
        kit.fresh();

        let (_authorize, state) = begin(&kit, "alice", "x", RETURN_TO).await;
        let response = kit.get(&callback_url("x", &state, "code-1")).await;
        kit.drain().await;

        assert_eq!(response.status, StatusCode::SEE_OTHER);
        let location = response.location().expect("a redirect carries Location");
        assert!(
            location.starts_with("https://app.example.com/settings?"),
            "the redirect stays on the return_to: {location}"
        );
        let id = support::query_of(&location, "connection").expect("the id is on the redirect");
        let connection = kit.api.get(&id).await.expect("the connection exists");
        assert_eq!(connection.subject, "alice");
        assert_eq!(connection.provider, "x");
        assert_eq!(connection.status, ConnectionStatus::Active);
        assert!(kit.events.has("connections.connected"));
    }
}

/// A `return_to` off the allowed origin is refused before a state is written,
/// and the refusal is the typed error rather than a redirect.
#[pollster::test]
async fn start_refuses_a_return_to_off_the_allowed_origins() {
    let spec = Spec::default();
    for kit in fixture(&spec).kits {
        kit.fresh();
        for hostile in [
            // A host that merely starts with the allowed one.
            "https://app.example.com.evil.com/settings",
            // Protocol-relative: no scheme at all.
            "//evil.com/settings",
            // Not a web scheme.
            "javascript:alert(1)",
            // Userinfo: the host is `evil.com`.
            "https://app.example.com@evil.com/settings",
            // A different port is a different origin.
            "https://app.example.com:8443/settings",
            // Plain http is not the origin that was allowed.
            "http://app.example.com/settings",
        ] {
            let error = kit
                .api
                .start("alice", "x", hostile)
                .await
                .expect_err("the module refuses the return_to");
            assert!(
                matches!(error, ConnectionError::OriginNotAllowed(_)),
                "{hostile} was not refused: {error:?}"
            );
        }
        assert_eq!(
            kit.http.token_calls().len(),
            0,
            "a refused start must not reach the provider"
        );
    }
}

/// A `state` that was never issued, one already spent, and one that has aged
/// out all answer a problem — and none is ever a redirect.
#[pollster::test]
async fn an_unknown_spent_or_expired_state_answers_a_problem() {
    for kit in fixture(&Spec::default()).kits {
        kit.fresh();

        let unknown = kit.get(&callback_url("x", "never-issued", "code-1")).await;
        assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
        assert_eq!(unknown.problem_slug(), "connections-bad-state");
        assert!(
            unknown.location().is_none(),
            "a bad state must never redirect"
        );

        let (_authorize, state) = begin(&kit, "alice", "x", RETURN_TO).await;
        let first = kit.get(&callback_url("x", &state, "code-1")).await;
        assert_eq!(first.status, StatusCode::SEE_OTHER);

        let replay = kit.get(&callback_url("x", &state, "code-2")).await;
        assert_eq!(replay.status, StatusCode::BAD_REQUEST);
        assert_eq!(replay.problem_slug(), "connections-bad-state");
        assert!(replay.location().is_none(), "a replay must never redirect");

        // A fresh state, aged past its own ten-minute deadline plus a margin.
        let (_authorize, aged) = begin(&kit, "alice", "x", RETURN_TO).await;
        kit.clock.advance_secs(601);
        let expired = kit.get(&callback_url("x", &aged, "code-3")).await;
        assert_eq!(expired.status, StatusCode::BAD_REQUEST);
        assert_eq!(expired.problem_slug(), "connections-bad-state");
    }
}

/// An unconfigured provider is refused by name.
#[pollster::test]
async fn an_unconfigured_provider_is_refused() {
    for kit in fixture(&Spec::default()).kits {
        let response = kit
            .get("/v1/connections/callback/dropbox?state=x&code=y")
            .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert_eq!(response.problem_slug(), "connections-unknown-provider");
    }
}

/// The redirect target is re-checked on the way out, not only on the way in.
///
/// A state row can outlive the configuration it was written under (a venture
/// narrows `allowed_origin` between a person starting the flow and the
/// provider sending them back), so the callback runs the same origin check
/// again. This plants a row whose `return_to` is off the allowed origins —
/// the state an old configuration would have accepted — and asserts the
/// callback answers a problem instead of writing a `Location`.
#[pollster::test]
async fn a_return_to_off_the_allowed_origins_never_becomes_a_redirect() {
    use cratefield_core::Statement;
    use sha2::Digest as _;

    for kit in fixture(&Spec::default()).kits {
        kit.fresh();

        let state = "planted-state-value";
        let hash = hex::encode(sha2::Sha256::digest(state.as_bytes()));
        kit.harness
            .db
            .execute(&Statement::with_values(
                "INSERT INTO connection_state \
                 (state_hash, subject, provider, return_to, verifier_sealed, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
                    .to_owned(),
                vec![
                    hash.clone().into(),
                    "alice".into(),
                    "x".into(),
                    "https://evil.example.com/steal".into(),
                    Option::<String>::None.into(),
                    "2099-01-01T00:00:00Z".into(),
                    "2026-01-01T00:00:00Z".into(),
                ],
            ))
            .await
            .expect("plants the state row");

        let response = kit.get(&callback_url("x", state, "code-1")).await;
        assert_ne!(
            response.status,
            StatusCode::SEE_OTHER,
            "the callback redirected to a URL the venture does not vouch for"
        );
        assert_eq!(response.problem_slug(), "connections-bad-state");
        assert!(response.location().is_none());

        // The code was never redeemed: the state was spent, but the exchange
        // is only reached for a row whose redirect target is allowed.
        assert_eq!(
            kit.http.token_calls().len(),
            0,
            "a redirect that cannot be made must not redeem the code either"
        );
    }
}

/// `access_token` on a connection that needs a reconnect says so, and on an
/// unknown id says that instead of inventing one.
#[pollster::test]
async fn reading_a_token_names_the_failure() {
    for kit in fixture(&Spec::default()).kits {
        kit.fresh();

        let missing = kit
            .api
            .access_token("no-such-id")
            .await
            .expect_err("unknown id");
        assert!(matches!(missing, ConnectionError::NotFound(_)));

        let connection = connect(&kit, "alice", "x").await;
        // A provider that refuses the refresh: the row moves to
        // `needs_reconnect` and the caller is told.
        kit.http.set_response(400, INVALID_GRANT);
        kit.clock.advance_secs(3600);
        let error = kit
            .api
            .access_token(&connection.id)
            .await
            .expect_err("the refresh was refused");
        kit.drain().await;
        assert!(
            matches!(error, ConnectionError::NeedsReconnect(_)),
            "{error:?}"
        );
        assert_eq!(error.problem().status, StatusCode::CONFLICT);
        assert_eq!(
            kit.api.get(&connection.id).await.expect("the row").status,
            ConnectionStatus::NeedsReconnect
        );
        assert!(kit.events.has("connections.needs_reconnect"));

        let again = kit
            .api
            .access_token(&connection.id)
            .await
            .expect_err("still refused");
        assert!(matches!(again, ConnectionError::NeedsReconnect(_)));
    }
}

/// Revoking clears the tokens and answers `revoked` from then on.
#[pollster::test]
async fn revoking_clears_the_tokens() {
    for kit in fixture(&Spec::default()).kits {
        kit.fresh();

        let connection = connect(&kit, "alice", "x").await;
        kit.api.revoke(&connection.id).await.expect("revokes");
        kit.drain().await;

        let after = kit.api.get(&connection.id).await.expect("the row");
        assert_eq!(after.status, ConnectionStatus::Revoked);
        assert!(kit.events.has("connections.revoked"));

        let error = kit
            .api
            .access_token(&connection.id)
            .await
            .expect_err("a revoked connection has no token");
        assert!(matches!(error, ConnectionError::Revoked));

        // The provider was asked, with both tokens.
        let hints: Vec<String> = kit
            .http
            .revoke_calls()
            .iter()
            .filter_map(|call| call.field("token_type_hint"))
            .collect();
        assert!(hints.contains(&"access_token".to_owned()), "{hints:?}");
        assert!(hints.contains(&"refresh_token".to_owned()), "{hints:?}");
    }
}

/// A connection is listed for its subject and nobody else's.
#[pollster::test]
async fn listing_is_per_subject() {
    for kit in fixture(&Spec::default()).kits {
        kit.fresh();

        connect(&kit, "alice", "x").await;
        connect(&kit, "bob", "x").await;

        assert_eq!(kit.api.list("alice").await.expect("lists").len(), 1);
        assert_eq!(kit.api.list("bob").await.expect("lists").len(), 1);
        assert_eq!(kit.api.list("carol").await.expect("lists").len(), 0);
    }
}

/// The document a caller gets back never carries a token, and neither does
/// its `Debug` form.
#[pollster::test]
async fn a_connection_never_carries_a_token() {
    for kit in fixture(&Spec::default()).kits {
        kit.fresh();
        kit.http.set_response(200, REFRESHED_BODY);

        let connection = connect(&kit, "alice", "x").await;
        let rendered = format!("{connection:?}");
        for secret in ["AT-connected-1", "RT-connected-1", "test-client-secret"] {
            assert!(
                !rendered.contains(secret),
                "a token reached Debug: {rendered}"
            );
        }
        assert!(!rendered.contains("sealed"));

        // And the access token's own Debug redacts it.
        let token: AccessToken = kit.api.access_token(&connection.id).await.expect("a token");
        assert!(!format!("{token:?}").contains(token.expose()));
        assert!(token.expose().starts_with("AT-"));
    }
}

/// The `state` reaches the database only as a SHA-256 hash.
#[pollster::test]
async fn the_state_is_stored_only_as_a_hash() {
    use cratefield_core::Statement;
    for kit in fixture(&Spec::default()).kits {
        kit.fresh();

        let (_authorize, state) = begin(&kit, "alice", "x", RETURN_TO).await;
        let rows = kit
            .harness
            .db
            .query(&Statement::new(
                "SELECT state_hash FROM connection_state".to_owned(),
            ))
            .await
            .expect("reads the state rows");
        assert_eq!(rows.len(), 1);
        let stored: String = rows
            .first()
            .expect("one state row")
            .get("state_hash")
            .expect("a hash");
        assert_ne!(stored, state, "the raw state must not be stored");
        assert_eq!(stored.len(), 64, "a SHA-256 hash is 64 hex characters");
        assert!(stored.chars().all(|ch| ch.is_ascii_hexdigit()));

        // And the fake's config never carried it either.
        assert_eq!(kit.http.calls().len(), 0, "no provider call yet");
    }
}
