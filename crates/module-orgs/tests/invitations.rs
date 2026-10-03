//! Invitations: what the mail carries, who may send them, and the two
//! guarantees the accept route makes — the invitation is spent exactly once,
//! and only by the address it was sent to (issue #652).

mod support;

use axum::http::StatusCode;
use cratefield_testing::MailerMode;

use support::{Spec, fixture};

/// An invitation is spent on the first accept, by the one address it was
/// written to, and the raw token never appears in an HTTP response.
#[pollster::test]
async fn an_invitation_is_single_use_and_the_response_never_carries_the_token() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;

        let invited = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "alice",
                r#"{"email":"Bob@Example.test","role":"staff"}"#,
            )
            .await;
        assert_eq!(invited.status, StatusCode::ACCEPTED, "{:?}", invited.text());

        let mail = kit.harness.mailer.last_message().expect("a mail was sent");
        assert_eq!(mail.to, "bob@example.test", "the address is normalized");
        assert!(mail.text.contains("/v1/orgs/invitations/accept?token="));
        let token = kit.invitation_token();
        // The token reached the invitee, not the caller.
        assert!(
            !invited.text().contains(&token),
            "the response body carried the raw token: {}",
            invited.text()
        );

        let accepted = kit
            .post(
                "/v1/orgs/invitations/accept",
                "bob|bob@example.test",
                &format!(r#"{{"token":"{token}"}}"#),
            )
            .await;
        assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.text());
        assert_eq!(accepted.json()["id"], id.as_str());

        let me = kit.get(&format!("/v1/orgs/{id}/members/me"), "bob").await;
        assert_eq!(me.json()["role"], "staff");
        assert_eq!(kit.rows_for("org_members", "user_sub", "bob").await, 1);

        // The second accept finds the row stamped, and answers what a
        // stranger's unknown token would.
        let replay = kit
            .post(
                "/v1/orgs/invitations/accept",
                "bob|bob@example.test",
                &format!(r#"{{"token":"{token}"}}"#),
            )
            .await;
        assert_eq!(replay.status, StatusCode::GONE);
        assert_eq!(replay.problem_slug(), "orgs-invitation-gone");
        assert_eq!(kit.rows_for("org_members", "user_sub", "bob").await, 1);
    }
}

/// The invitation row holds only hashes: nothing in the table can be replayed
/// as a token or read back as an address, so a database dump is inert.
#[pollster::test]
async fn the_invitation_row_holds_only_hashes() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;
        let invited = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "alice",
                r#"{"email":"Bob@Example.test","role":"staff"}"#,
            )
            .await;
        assert_eq!(invited.status, StatusCode::ACCEPTED, "{:?}", invited.text());
        let token = kit.invitation_token();

        let rows = kit
            .harness
            .db
            .query(&cratefield_core::Statement::new(
                "SELECT * FROM org_invitations",
            ))
            .await
            .expect("reads the invitation row");
        let row = rows.first().expect("one invitation");
        // Every column, not a chosen few: the guarantee is about the whole
        // row, and a column added later must not be able to break it quietly.
        for column in [
            "id",
            "org_id",
            "token_hash",
            "email_hash",
            "role",
            "invited_by",
            "expires_at",
            "created_at",
        ] {
            let value: String = row.get(column).unwrap_or_default();
            assert!(
                !value.contains(&token),
                "`{column}` carries the raw token: {value}"
            );
            assert!(
                !value.to_lowercase().contains("bob@example.test"),
                "`{column}` carries the raw address: {value}"
            );
        }
        assert!(
            row.get::<Option<String>>("accepted_at")
                .unwrap_or(None)
                .is_none(),
            "a fresh invitation is not yet spent"
        );
    }
}

/// An invitation is refused for any address but the one it was sent to, and
/// that refusal does not spend it: the person it was meant for can still
/// accept.
#[pollster::test]
async fn an_invitation_is_refused_for_another_address_without_spending_it() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;
        let _ = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "alice",
                r#"{"email":"carol@example.test","role":"staff"}"#,
            )
            .await;
        let token = kit.invitation_token();

        let wrong = kit
            .post(
                "/v1/orgs/invitations/accept",
                "bob|bob@example.test",
                &format!(r#"{{"token":"{token}"}}"#),
            )
            .await;
        assert_eq!(wrong.status, StatusCode::FORBIDDEN);
        assert_eq!(wrong.problem_slug(), "orgs-invitation-for-someone-else");

        // Carol can still accept the invitation Bob could not.
        let right = kit
            .post(
                "/v1/orgs/invitations/accept",
                "carol|carol@example.test",
                &format!(r#"{{"token":"{token}"}}"#),
            )
            .await;
        assert_eq!(right.status, StatusCode::OK, "{:?}", right.text());
        let me = kit.get(&format!("/v1/orgs/{id}/members/me"), "carol").await;
        assert_eq!(me.json()["role"], "staff");
    }
}

/// A credential that proved no address cannot match an invitation, so it is
/// refused rather than accepted as whoever happens to be signed in.
#[pollster::test]
async fn an_unverified_address_cannot_accept() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;
        let _ = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "alice",
                r#"{"email":"bob@example.test","role":"staff"}"#,
            )
            .await;
        let token = kit.invitation_token();

        // `bob` alone: signed in, no verified address.
        let unverified = kit
            .post(
                "/v1/orgs/invitations/accept",
                "bob",
                &format!(r#"{{"token":"{token}"}}"#),
            )
            .await;
        assert_eq!(unverified.status, StatusCode::FORBIDDEN);
        assert_eq!(unverified.problem_slug(), "orgs-email-unverified");

        let verified = kit
            .post(
                "/v1/orgs/invitations/accept",
                "bob|bob@example.test",
                &format!(r#"{{"token":"{token}"}}"#),
            )
            .await;
        assert_eq!(verified.status, StatusCode::OK, "{:?}", verified.text());
    }
}

/// An invitation that has lapsed is gone, the same as one already spent.
#[pollster::test]
async fn an_invitation_that_lapses_is_gone() {
    let spec = Spec {
        invitation_ttl_secs: 3_600,
        ..Spec::default()
    };
    for kit in fixture(&spec).kits {
        let id = kit.create_org("alice", "Acme").await;
        let _ = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "alice",
                r#"{"email":"bob@example.test","role":"staff"}"#,
            )
            .await;
        let token = kit.invitation_token();

        kit.clock.advance_secs(3_601);
        let response = kit
            .post(
                "/v1/orgs/invitations/accept",
                "bob|bob@example.test",
                &format!(r#"{{"token":"{token}"}}"#),
            )
            .await;
        assert_eq!(response.status, StatusCode::GONE);
        assert_eq!(response.problem_slug(), "orgs-invitation-gone");
        assert_eq!(kit.rows_for("org_members", "user_sub", "bob").await, 0);
    }
}

/// An invitation the mailer cannot deliver leaves nothing behind: a venture
/// with no sending domain does not accumulate invitations nobody can accept.
#[pollster::test]
async fn an_invitation_the_mailer_cannot_send_leaves_nothing_behind() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;

        kit.harness.mailer.set_mode(MailerMode::NotConfigured);
        let no_mail = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "alice",
                r#"{"email":"bob@example.test","role":"staff"}"#,
            )
            .await;
        assert_eq!(no_mail.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(no_mail.problem_slug(), "mail-not-configured");
        assert_eq!(kit.rows("org_invitations").await, 0);

        kit.harness.mailer.set_mode(MailerMode::Fail);
        let refused = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "alice",
                r#"{"email":"bob@example.test","role":"staff"}"#,
            )
            .await;
        assert_eq!(refused.status, StatusCode::BAD_GATEWAY);
        assert_eq!(refused.problem_slug(), "orgs-mail-failed");
        assert_eq!(kit.rows("org_invitations").await, 0);
    }
}

/// Inviting is managing: an owner may always, a manager role may, and an
/// ordinary member may not. The role offered is checked the same way, and an
/// address that is not one is refused before anything is written.
#[pollster::test]
async fn inviting_is_managing_and_the_role_is_checked() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;
        let _ = kit.add_member(&id, "alice", "bob", "manager").await;
        let _ = kit.add_member(&id, "alice", "carol", "staff").await;

        let not_a_manager = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "carol",
                r#"{"email":"dave@example.test","role":"staff"}"#,
            )
            .await;
        assert_eq!(not_a_manager.status, StatusCode::FORBIDDEN);
        assert_eq!(not_a_manager.problem_slug(), "orgs-forbidden");

        // A manager may invite, but not with the owner role.
        let owner_role = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "bob",
                r#"{"email":"dave@example.test","role":"owner"}"#,
            )
            .await;
        assert_eq!(owner_role.status, StatusCode::FORBIDDEN);

        let unknown_role = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "bob",
                r#"{"email":"dave@example.test","role":"wizard"}"#,
            )
            .await;
        assert_eq!(unknown_role.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(unknown_role.problem_slug(), "orgs-unknown-role");

        let bad_address = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "bob",
                r#"{"email":"not-an-address","role":"staff"}"#,
            )
            .await;
        assert_eq!(bad_address.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(bad_address.problem_slug(), "orgs-invalid-email");

        assert_eq!(kit.rows("org_invitations").await, 0, "nothing was written");

        // The owner may invite with the role a manager may not.
        let owner_invite = kit
            .post(
                &format!("/v1/orgs/{id}/invitations"),
                "alice",
                r#"{"email":"erin@example.test","role":"owner"}"#,
            )
            .await;
        assert_eq!(owner_invite.status, StatusCode::ACCEPTED);
        assert_eq!(kit.rows("org_invitations").await, 1);
    }
}
