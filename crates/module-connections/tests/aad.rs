//! Sealed tokens are bound to their row, proved through the module's own API
//! (issue #624).
//!
//! The sealing AAD names the table, the row id and the column, so a ciphertext
//! lifted out of one row and pasted into another must not open. `seal.rs` has
//! the unit-level proof; this drives it through `access_token`, where the
//! consequence lives: a copied blob must not become someone else's token.

mod support;

use cratefield_core::Statement;

use cratefield_module_connections::ConnectionError;

use support::{Spec, connect, fixture};

/// A ciphertext copied from one connection's row into another's fails to open
/// — and the row it was taken from still opens its own.
#[pollster::test]
async fn a_copied_ciphertext_does_not_open() {
    for kit in fixture(&Spec::default()).kits {
        kit.clock.reset();
        kit.http.reset();

        let alice = connect(&kit, "alice", "x").await;
        let bob = connect(&kit, "bob", "x").await;

        // Read the ciphertext the module actually stored for alice…
        let alice_sealed: String = kit
            .harness
            .db
            .query(&Statement::with_values(
                "SELECT access_token_sealed FROM connection WHERE id = ?".to_owned(),
                vec![alice.id.clone().into()],
            ))
            .await
            .expect("reads alice's row")
            .first()
            .and_then(|row| row.get("access_token_sealed"))
            .expect("alice has a sealed access token");

        // …and paste it, verbatim, into bob's row.
        kit.harness
            .db
            .execute(&Statement::with_values(
                "UPDATE connection SET access_token_sealed = ? WHERE id = ?".to_owned(),
                vec![alice_sealed.into(), bob.id.clone().into()],
            ))
            .await
            .expect("copies the ciphertext into bob's row");

        // Bob's row must not hand back alice's token: the AAD it is opened
        // under names the row, and the ciphertext was sealed for another one.
        let error = kit
            .api
            .access_token(&bob.id)
            .await
            .expect_err("a ciphertext from another row must not open");
        assert!(
            matches!(error, ConnectionError::Config(_)),
            "the copy must fail as an unreadable sealed value: {error:?}"
        );

        // The binding is what failed, not the bytes: alice's own row still
        // opens its access token.
        let token = kit
            .api
            .access_token(&alice.id)
            .await
            .expect("alice's own row still opens");
        assert!(token.expose().starts_with("AT-"));
    }
}
