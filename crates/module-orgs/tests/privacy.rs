//! The personal-data declaration, proved against the module that reads it
//! (issue #652, after the pattern issue #265 established).
//!
//! `Module::personal_data()` is a promise about another crate's behaviour:
//! `cratefield-module-privacy` publishes the manifest and plans erasures from
//! it, so asserting the list against itself would prove nothing. These compose
//! the two modules the way a venture does and drive the routes: the manifest
//! must publish the membership and the invitation as erased, the organization
//! as retained, and the inviter's id as redacted on other people's membership
//! rows; an erasure keyed on a subject must delete exactly their memberships —
//! and the invitations they sent — while leaving the organization and
//! everybody else's membership in place.

mod support;

use axum::http::{Method, StatusCode};
use cratefield_module_privacy::Privacy;

use support::{ADMIN, Spec, fixture_with, send};

/// A fixture with Privacy mounted alongside Orgs, on every dialect.
fn privacy_fixture() -> support::Fixture {
    fixture_with(&Spec::default(), || vec![Box::new(Privacy::new())])
}

/// The manifest is the promise: the membership and the invitation are erased,
/// the organization is retained with its reason, and the inviter's id is named
/// as redacted on the membership — a column an export will not copy, said out
/// loud rather than left to be discovered.
#[pollster::test]
async fn the_manifest_publishes_what_is_erased_retained_and_redacted() {
    for kit in privacy_fixture().kits {
        let response = send(&kit, Method::GET, "/v1/privacy/manifest", None, None).await;
        assert_eq!(response.status, StatusCode::OK, "{:?}", response.text());
        let manifest = response.json();

        let holds = manifest["holds"].as_array().expect("holds").clone();
        let members = holds
            .iter()
            .find(|entry| entry["table"] == "org_members")
            .unwrap_or_else(|| panic!("`org_members` is not published under holds: {holds:?}"));
        assert_eq!(members["module"], "orgs");
        assert_eq!(members["kind"], "identifier");
        assert_eq!(members["on_erasure"]["action"], "erase");
        assert!(
            members["redacted"]
                .as_array()
                .expect("redacted")
                .iter()
                .any(|column| column == "invited_by"),
            "the inviter's id on a member's row must be declared redacted: {members}"
        );

        let orgs = holds
            .iter()
            .find(|entry| entry["table"] == "orgs")
            .unwrap_or_else(|| panic!("`orgs` is not published under holds: {holds:?}"));
        assert_eq!(orgs["module"], "orgs");
        assert_eq!(orgs["on_erasure"]["action"], "retain");
        assert!(
            orgs["on_erasure"]["reason"]
                .as_str()
                .expect("a retain reason")
                .contains("member"),
            "the retain reason must say why the organization outlives its creator: {orgs}"
        );

        // The invitation is the inviter's, and it is erased with them — not
        // parked in `unreachable` behind a reason that was never true of it.
        let invitations = holds
            .iter()
            .find(|entry| entry["table"] == "org_invitations")
            .unwrap_or_else(|| panic!("`org_invitations` is not published under holds: {holds:?}"));
        assert_eq!(invitations["module"], "orgs");
        assert_eq!(invitations["kind"], "contact");
        assert_eq!(invitations["on_erasure"]["action"], "erase");
        assert!(
            manifest["unreachable"]
                .as_array()
                .expect("unreachable")
                .is_empty(),
            "nothing in orgs is beyond reach any more: {manifest}"
        );
        assert_eq!(manifest["holds_personal_data"], true);
    }
}

/// The erasure the declaration promises: keyed on a subject it deletes
/// exactly their memberships and leaves the organization and another
/// member's row untouched.
#[pollster::test]
async fn an_erasure_keyed_on_the_subject_deletes_only_their_memberships() {
    for kit in privacy_fixture().kits {
        kit.clock.reset();

        let id = kit.create_org("alice", "Acme").await;
        let _ = kit.add_member(&id, "alice", "bob", "staff").await;

        assert_eq!(kit.rows_for("org_members", "user_sub", "alice").await, 1);
        assert_eq!(kit.rows_for("org_members", "user_sub", "bob").await, 1);

        let preview = send(
            &kit,
            Method::POST,
            "/v1/privacy/erase",
            Some(ADMIN),
            Some(r#"{"subject":"alice"}"#),
        )
        .await;
        assert_eq!(preview.status, StatusCode::OK, "{:?}", preview.text());
        let plan = preview.json()["plan"].as_array().expect("plan").clone();
        let members = plan
            .iter()
            .find(|row| row["table"] == "org_members")
            .unwrap_or_else(|| panic!("`org_members` is not in the plan: {plan:?}"));
        assert_eq!(members["action"], "erase", "{members}");
        let orgs = plan
            .iter()
            .find(|row| row["table"] == "orgs")
            .unwrap_or_else(|| panic!("`orgs` is not in the plan: {plan:?}"));
        assert_eq!(orgs["action"], "retain", "{orgs}");

        let token = preview.json()["confirm_token"].clone();
        let confirmed = send(
            &kit,
            Method::POST,
            "/v1/privacy/erase/confirm",
            Some(ADMIN),
            Some(&format!(r#"{{"token":{token}}}"#)),
        )
        .await;
        assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.text());
        assert_eq!(confirmed.json()["verified"], true, "{:?}", confirmed.text());

        assert_eq!(
            kit.rows_for("org_members", "user_sub", "alice").await,
            0,
            "the erasure left alice's membership behind"
        );
        assert_eq!(
            kit.rows_for("org_members", "user_sub", "bob").await,
            1,
            "the erasure took another member's membership"
        );
        assert_eq!(
            kit.rows("orgs").await,
            1,
            "the retained organization must survive its creator's erasure"
        );
    }
}

/// The invitations a person sent are theirs, and the erasure follows them: it
/// removes the invitations they sent, and an export of a member they added
/// shows the `invited_by` column with `[redacted]` for a value.
///
/// The id itself stays on that member's row in storage — the framework blanks
/// columns only on the rows a subject's own value matches, so a *second*
/// person's id on somebody else's row cannot be reached by any disposition.
/// That is exactly why the column is declared `redacted`: the export is the
/// one place the framework can honour it, and the last assertion here pins the
/// state the declaration is honest about.
#[pollster::test]
async fn erasing_an_inviter_takes_their_invitations_and_redacts_their_id() {
    for kit in privacy_fixture().kits {
        kit.clock.reset();
        let id = kit.create_org("alice", "Acme").await;
        let _ = kit.add_member(&id, "alice", "bob", "staff").await;
        let invited = send(
            &kit,
            Method::POST,
            &format!("/v1/orgs/{id}/invitations"),
            Some("alice"),
            Some(r#"{"email":"carol@example.test","role":"staff"}"#),
        )
        .await;
        assert_eq!(invited.status, StatusCode::ACCEPTED, "{:?}", invited.text());
        assert_eq!(kit.rows("org_invitations").await, 1);

        let export = send(
            &kit,
            Method::GET,
            "/v1/privacy/export?subject=bob",
            Some(ADMIN),
            None,
        )
        .await;
        assert_eq!(export.status, StatusCode::OK, "{:?}", export.text());
        let row = export.json()["tables"]
            .as_array()
            .expect("tables")
            .iter()
            .find(|table| table["table"] == "org_members")
            .and_then(|table| table["rows"].as_array())
            .and_then(|rows| rows.first())
            .cloned()
            .unwrap_or_else(|| panic!("bob's membership row is missing: {}", export.text()));
        assert_eq!(
            row["invited_by"], "[redacted]",
            "an export leaked the inviter's id: {row}"
        );

        confirm_erase(&kit, "alice").await;
        assert_eq!(
            kit.rows("org_invitations").await,
            0,
            "the invitation alice sent survived her erasure"
        );
        assert_eq!(kit.rows("orgs").await, 1, "the organization is retained");
        assert_eq!(
            kit.rows_for("org_members", "invited_by", "alice").await,
            1,
            "the framework reaches invited_by only through an export, not erasure \
             (the membership of bob, who did not ask to be erased, keeps its record)"
        );
    }
}

/// Runs the preview-then-confirm erasure for one subject, asserting both steps
/// succeed. The `confirm_token` is the only proof the two are one request.
async fn confirm_erase(kit: &support::Kit, subject: &str) {
    let preview = send(
        kit,
        Method::POST,
        "/v1/privacy/erase",
        Some(ADMIN),
        Some(&format!(r#"{{"subject":"{subject}"}}"#)),
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK, "{:?}", preview.text());
    let token = preview.json()["confirm_token"].clone();
    let confirmed = send(
        kit,
        Method::POST,
        "/v1/privacy/erase/confirm",
        Some(ADMIN),
        Some(&format!(r#"{{"token":{token}}}"#)),
    )
    .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.text());
    assert_eq!(confirmed.json()["verified"], true, "{:?}", confirmed.text());
}
