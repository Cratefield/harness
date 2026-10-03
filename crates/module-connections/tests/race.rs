//! The two guarded writes, raced (issue #624).
//!
//! Both `state` and the refresh token are consumed with a single guarded
//! `UPDATE ... WHERE <the value I read>`, so two callers presenting the same
//! value cannot both win. These tests run the losers for real rather than
//! arguing about it: two `complete` calls for one state, and two refreshes
//! that both read the same stored refresh token.

mod support;

use cratefield_module_connections::ConnectionError;

use support::{REFRESHED_BODY, RETURN_TO, Spec, begin, connect, fixture};

/// One `state` completes at most once, even when two callbacks present it at
/// the same time: exactly one wins, one connection row is written, and the
/// authorization code is redeemed once.
#[pollster::test]
async fn a_state_completes_at_most_once() {
    for kit in fixture(&Spec::default()).kits {
        kit.clock.reset();
        kit.http.reset();
        kit.events.reset();

        let (_authorize, state) = begin(&kit, "alice", "x", RETURN_TO).await;

        let (first, second) = futures_util::future::join(
            kit.api.complete(&state, "code-one"),
            kit.api.complete(&state, "code-two"),
        )
        .await;
        kit.drain().await;

        assert_eq!(
            [&first, &second]
                .iter()
                .filter(|outcome| outcome.is_ok())
                .count(),
            1,
            "exactly one completion may win: {first:?} / {second:?}"
        );
        let loser = if first.is_ok() { &second } else { &first };
        assert!(
            matches!(loser, Err(ConnectionError::BadState)),
            "the loser must be told the state was already spent: {loser:?}"
        );

        // One row, one redemption, one event: the guarded spend is the only
        // thing standing between a replay and a second connection.
        assert_eq!(
            kit.rows("connection").await,
            1,
            "a replay wrote a second row"
        );
        assert_eq!(
            kit.http.token_calls().len(),
            1,
            "the code was exchanged twice"
        );
        assert_eq!(kit.events.count("connections.connected"), 1);
    }
}

/// Two refreshes that read the same stored refresh token: one writes, the
/// other adopts the winner's token, and the rotated refresh token is what
/// ends up stored — never the one that was consumed.
#[pollster::test]
async fn a_concurrent_refresh_keeps_one_winner_and_the_rotated_token() {
    for kit in fixture(&Spec::default()).kits {
        kit.clock.reset();
        kit.http.reset();
        kit.events.reset();

        let connection = connect(&kit, "alice", "x").await;
        assert_eq!(kit.rows("connection").await, 1);
        // Forget the connect's own token call, so the count below is the
        // refreshes alone.
        kit.http.reset();

        // Both refreshes must read the same stored row, so they are held at
        // the token endpoint until each has arrived; then both write.
        kit.clock.advance_secs(3600);
        kit.http.set_response(200, REFRESHED_BODY);
        kit.http.rendezvous(2);

        let (first, second) = futures_util::future::join(
            kit.api.access_token(&connection.id),
            kit.api.access_token(&connection.id),
        )
        .await;
        kit.drain().await;

        let first = first.expect("the first refresh succeeds");
        let second = second.expect("the second refresh adopts the winner");
        assert_eq!(
            kit.http.token_calls().len(),
            2,
            "both refreshes must have reached the provider for the race to be real"
        );
        assert_eq!(
            first.expose(),
            second.expose(),
            "the loser must hand back the winner's token, not overwrite it"
        );
        assert_eq!(first.expose(), "AT-refreshed-2");
        // Only the writer emits; the adopter is not a second refresh.
        assert_eq!(kit.events.count("connections.refreshed"), 1);

        // The stored refresh token is the rotated one. Revoking sends both
        // tokens to the provider, so the request body is where the stored
        // value becomes observable: it holds the new token and not the old.
        kit.api.revoke(&connection.id).await.expect("revokes");
        let sent: Vec<String> = kit
            .http
            .revoke_calls()
            .iter()
            .filter_map(|call| call.field("token"))
            .collect();
        assert!(
            sent.contains(&"RT-refreshed-2".to_owned()),
            "the rotated refresh token was not stored: {sent:?}"
        );
        assert!(
            !sent.contains(&"RT-connected-1".to_owned()),
            "the consumed refresh token is still stored: {sent:?}"
        );
    }
}
