//! Refreshing, per preset (issue #624).
//!
//! A refresh is only correct if the request the provider sees is the one its
//! documentation describes: the right endpoint, the right client-auth method
//! (HTTP Basic or form body), `grant_type=refresh_token` and the stored
//! refresh token. And the write is only correct if a rotating provider's new
//! refresh token replaces the old one while a non-rotating provider keeps
//! its own. Both are asserted against the request bodies the fake records,
//! for every preset the crate ships.

mod support;

use cratefield_module_connections::{ConnectionError, ConnectionStatus, Provider, presets};

use support::{
    CLIENT_ID, CLIENT_SECRET, CONNECTED_BODY, INVALID_GRANT, REFRESHED_BODY, REFRESHED_NO_EXPIRY,
    REFRESHED_NO_ROTATION, Spec, connect, fixture,
};

/// One preset and the wire facts a refresh turns on.
struct Case {
    provider: Provider,
    key: &'static str,
    token_url: &'static str,
    /// HTTP Basic (`true`) or `client_id`/`client_secret` in the body.
    basic: bool,
    /// Whether the preset says the provider rotates its refresh token.
    rotates: bool,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            provider: presets::x(),
            key: "x",
            token_url: "https://api.x.com/2/oauth2/token",
            basic: true,
            rotates: true,
        },
        Case {
            provider: presets::google(),
            key: "google",
            token_url: "https://oauth2.googleapis.com/token",
            basic: true,
            rotates: false,
        },
        Case {
            provider: presets::linkedin(),
            key: "linkedin",
            token_url: "https://www.linkedin.com/oauth/v2/accessToken",
            basic: false,
            rotates: false,
        },
        Case {
            provider: presets::vercel(),
            key: "vercel",
            token_url: "https://api.vercel.com/login/oauth/token",
            basic: false,
            rotates: true,
        },
        Case {
            provider: presets::gitlab(),
            key: "gitlab",
            token_url: "https://gitlab.com/oauth/token",
            basic: false,
            rotates: true,
        },
        Case {
            provider: presets::linear(),
            key: "linear",
            token_url: "https://api.linear.app/oauth/token",
            basic: false,
            rotates: true,
        },
    ]
}

/// The refreshed token a rotating response yields, and the one a stable
/// response leaves in place.
fn refresh_body(rotates: bool) -> &'static str {
    if rotates {
        REFRESHED_BODY
    } else {
        REFRESHED_NO_ROTATION
    }
}

/// A due token is refreshed with the request shape the provider documents,
/// and the rotated-or-stable refresh token is what the *next* refresh sends —
/// the stored value made observable without reading a ciphertext. Then a
/// provider that refuses with `invalid_grant` means a human must authorize
/// again: the row moves to `needs_reconnect` and the event fires.
#[pollster::test]
async fn refreshing_follows_the_preset_and_an_invalid_grant_asks_for_a_reconnect() {
    for case in cases() {
        for kit in fixture(&Spec::only(case.provider.clone())).kits {
            kit.fresh();
            assert_eq!(
                case.provider.rotates_refresh(),
                case.rotates,
                "{}",
                case.key
            );
            let connection = connect(&kit, "alice", case.key).await;

            // The first refresh: the request shape.
            kit.http.reset();
            kit.clock.advance_secs(3600);
            kit.http.set_response(200, refresh_body(case.rotates));
            let token = kit
                .api
                .access_token(&connection.id)
                .await
                .expect("the refresh succeeds");
            kit.drain().await;
            assert_eq!(token.expose(), "AT-refreshed-2", "{}", case.key);
            assert!(kit.events.has("connections.refreshed"), "{}", case.key);

            let call = kit.http.last_token_call().expect("a token call");
            assert_eq!(
                call.uri, case.token_url,
                "{} posted to the wrong endpoint",
                case.key
            );
            assert_eq!(
                call.content_type.as_deref(),
                Some("application/x-www-form-urlencoded"),
                "{} did not form-encode the refresh",
                case.key
            );
            assert_eq!(call.field("grant_type").as_deref(), Some("refresh_token"));
            assert_eq!(
                call.field("refresh_token").as_deref(),
                Some("RT-connected-1"),
                "{} sent the wrong refresh token",
                case.key
            );
            if case.basic {
                assert!(
                    call.authorization
                        .as_deref()
                        .is_some_and(|header| header.starts_with("Basic ")),
                    "{} must authenticate with HTTP Basic: {:?}",
                    case.key,
                    call.authorization
                );
                assert_eq!(
                    call.field("client_secret"),
                    None,
                    "{} put the secret in the body as well as the header",
                    case.key
                );
            } else {
                assert_eq!(
                    call.authorization, None,
                    "{} must not send a Basic header",
                    case.key
                );
                assert_eq!(
                    call.field("client_id").as_deref(),
                    Some(CLIENT_ID),
                    "{}",
                    case.key
                );
                assert_eq!(
                    call.field("client_secret").as_deref(),
                    Some(CLIENT_SECRET),
                    "{}",
                    case.key
                );
            }

            // What is stored now is what the *next* refresh presents: the
            // rotated token for a rotating provider, the original for a
            // stable one.
            kit.clock.advance_secs(3600);
            kit.http.set_response(200, refresh_body(case.rotates));
            kit.api
                .access_token(&connection.id)
                .await
                .expect("the second refresh succeeds");
            let second = kit.http.last_token_call().expect("a second token call");
            let expected = if case.rotates {
                "RT-refreshed-2"
            } else {
                "RT-connected-1"
            };
            assert_eq!(
                second.field("refresh_token").as_deref(),
                Some(expected),
                "{} stored the wrong refresh token after a refresh",
                case.key
            );

            // And a refusal: a second connection, whose refresh the provider
            // answers with `invalid_grant`.
            kit.http.set_response(200, CONNECTED_BODY);
            let refused = connect(&kit, "bob", case.key).await;
            kit.clock.advance_secs(3600);
            kit.http.set_response(400, INVALID_GRANT);
            let error = kit
                .api
                .access_token(&refused.id)
                .await
                .expect_err("the provider refused the refresh");
            kit.drain().await;
            assert!(
                matches!(error, ConnectionError::NeedsReconnect(_)),
                "{}: {error:?}",
                case.key
            );
            assert_eq!(
                kit.api.get(&refused.id).await.expect("the row").status,
                ConnectionStatus::NeedsReconnect,
                "{}",
                case.key
            );
            assert!(
                kit.events.has("connections.needs_reconnect"),
                "{} did not emit needs_reconnect",
                case.key
            );
        }
    }
}

/// A refresh whose response states no lifetime keeps the recorded expiry
/// rather than wiping it — the same rule the refresh lifetime already had,
/// and what keeps `access_expires_at` (and the refresh scan over it) honest
/// for a provider that omits `expires_in`.
#[pollster::test]
async fn a_refresh_without_an_expiry_keeps_the_recorded_one() {
    for kit in fixture(&Spec::default()).kits {
        kit.fresh();
        let connection = connect(&kit, "alice", "x").await;
        let recorded = connection.access_expires_at.clone();
        assert!(recorded.is_some(), "the connect stated an expiry");

        kit.clock.advance_secs(3600);
        kit.http.set_response(200, REFRESHED_NO_EXPIRY);
        let token = kit
            .api
            .access_token(&connection.id)
            .await
            .expect("the refresh succeeds");
        assert_eq!(token.expose(), "AT-refreshed-2");
        assert_eq!(
            token.expires_at().map(str::to_owned),
            recorded,
            "the refresh wiped the recorded expiry"
        );
        assert_eq!(
            kit.api
                .get(&connection.id)
                .await
                .expect("the row")
                .access_expires_at,
            recorded,
            "the stored row lost the expiry the connect recorded"
        );
    }
}

/// A transport failure is not evidence about the connection: the row keeps
/// its tokens and the same refresh token works on the next attempt.
#[pollster::test]
async fn a_transport_failure_leaves_the_connection_untouched() {
    for kit in fixture(&Spec::default()).kits {
        kit.fresh();

        let connection = connect(&kit, "alice", "x").await;
        kit.http.reset();
        kit.clock.advance_secs(3600);
        kit.http.fail_transport("the provider timed out");

        let error = kit
            .api
            .access_token(&connection.id)
            .await
            .expect_err("the provider is unreachable");
        assert!(
            matches!(error, ConnectionError::Provider(_)),
            "a timeout is reported as an upstream failure: {error:?}"
        );
        assert_eq!(
            kit.api.get(&connection.id).await.expect("the row").status,
            ConnectionStatus::Active,
            "a timeout must not mark the connection for a reconnect"
        );
        assert!(!kit.events.has("connections.needs_reconnect"));

        // The retry presents the same refresh token it always held.
        kit.http.set_response(200, REFRESHED_BODY);
        let token = kit
            .api
            .access_token(&connection.id)
            .await
            .expect("the retry succeeds");
        assert_eq!(token.expose(), "AT-refreshed-2");
        assert_eq!(
            kit.http
                .last_token_call()
                .expect("a token call")
                .field("refresh_token")
                .as_deref(),
            Some("RT-connected-1")
        );
    }
}
