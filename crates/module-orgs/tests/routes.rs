//! The organization and membership routes (issue #652).
//!
//! The tests here are about who may do what, and about the two answers that
//! are deliberately the same: a non-member gets the 404 an organization that
//! does not exist gets, and the last owner cannot be removed or demoted out
//! of existence.

mod support;

use axum::http::{Method, StatusCode};

use support::{Spec, fixture, send};

/// Creating an organization is one write: the row and the creator's owner
/// membership land together, so no organization exists that nobody owns.
#[pollster::test]
async fn creating_an_organization_makes_the_caller_its_owner() {
    for kit in fixture(&Spec::default()).kits {
        let response = kit.post("/v1/orgs", "alice", r#"{"name":"Acme"}"#).await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{:?}",
            response.text()
        );
        let org = response.json();
        let id = org["id"].as_str().expect("an id").to_owned();
        assert_eq!(org["name"], "Acme");
        assert_eq!(org["created_by"], "alice");

        assert_eq!(kit.rows("orgs").await, 1);
        assert_eq!(kit.rows("org_members").await, 1);
        let me = kit.get(&format!("/v1/orgs/{id}/members/me"), "alice").await;
        assert_eq!(me.status, StatusCode::OK);
        assert_eq!(me.json()["role"], "owner");
    }
}

/// A blank name is refused and writes nothing — not an organization with an
/// empty name, and not a membership pointing at one.
#[pollster::test]
async fn a_blank_name_is_refused_and_writes_nothing() {
    for kit in fixture(&Spec::default()).kits {
        for body in [r#"{"name":""}"#, r#"{"name":"   "}"#] {
            let response = kit.post("/v1/orgs", "alice", body).await;
            assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(response.problem_slug(), "orgs-invalid-name");
        }
        assert_eq!(kit.rows("orgs").await, 0);
        assert_eq!(kit.rows("org_members").await, 0);
    }
}

/// A stranger is told nothing: they cannot read the organization, their own
/// membership in it, its roster, nor add themselves to it. Every refusal is
/// the 404 an unknown id would get, so ids cannot be enumerated.
#[pollster::test]
async fn a_non_member_gets_the_same_404_an_unknown_id_gets() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;

        for path in [
            format!("/v1/orgs/{id}"),
            format!("/v1/orgs/{id}/members"),
            format!("/v1/orgs/{id}/members/me"),
        ] {
            let response = kit.get(&path, "carol").await;
            assert_eq!(response.status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(response.problem_slug(), "orgs-not-found", "{path}");
        }

        let added = kit.add_member(&id, "carol", "carol", "staff").await;
        assert_eq!(added.status, StatusCode::NOT_FOUND);
        assert_eq!(added.problem_slug(), "orgs-not-found");
        assert_eq!(kit.rows("org_members").await, 1, "only alice's membership");

        // The same id, read by a stranger who has no way to tell it from one
        // that was never issued.
        let unknown = kit.get("/v1/orgs/does-not-exist", "carol").await;
        assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    }
}

/// A manager may add and remove members, but the owner role is not theirs to
/// grant, and an owner's membership is not theirs to touch.
#[pollster::test]
async fn a_manager_may_not_grant_owner_or_touch_an_owner() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;
        let added = kit.add_member(&id, "alice", "bob", "manager").await;
        assert_eq!(added.status, StatusCode::CREATED, "{:?}", added.text());
        assert_eq!(added.json()["role"], "manager");

        // A manager adds an ordinary member: allowed.
        let staff = kit.add_member(&id, "bob", "carol", "staff").await;
        assert_eq!(staff.status, StatusCode::CREATED, "{:?}", staff.text());

        // A manager grants owner: refused.
        let grant = kit.add_member(&id, "bob", "dave", "owner").await;
        assert_eq!(grant.status, StatusCode::FORBIDDEN);
        assert_eq!(grant.problem_slug(), "orgs-forbidden");

        // A manager demotes or removes the owner: refused.
        let demote = kit
            .patch(
                &format!("/v1/orgs/{id}/members/alice"),
                "bob",
                r#"{"role":"staff"}"#,
            )
            .await;
        assert_eq!(demote.status, StatusCode::FORBIDDEN);
        let remove = kit
            .delete(&format!("/v1/orgs/{id}/members/alice"), "bob")
            .await;
        assert_eq!(remove.status, StatusCode::FORBIDDEN);

        // And an owner may still do all three.
        let promoted = kit
            .patch(
                &format!("/v1/orgs/{id}/members/carol"),
                "alice",
                r#"{"role":"manager"}"#,
            )
            .await;
        assert_eq!(promoted.status, StatusCode::OK, "{:?}", promoted.text());
        assert_eq!(promoted.json()["role"], "manager");
    }
}

/// The last owner cannot leave or be demoted — the organization would be left
/// with nobody who can administer it — and can do both once a second owner
/// exists.
#[pollster::test]
async fn the_last_owner_cannot_leave_or_be_demoted() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;

        let leave = kit.post(&format!("/v1/orgs/{id}/leave"), "alice", "").await;
        assert_eq!(leave.status, StatusCode::CONFLICT, "{:?}", leave.text());
        assert_eq!(leave.problem_slug(), "orgs-last-owner");

        let demote = kit
            .patch(
                &format!("/v1/orgs/{id}/members/alice"),
                "alice",
                r#"{"role":"manager"}"#,
            )
            .await;
        assert_eq!(demote.status, StatusCode::CONFLICT);
        assert_eq!(demote.problem_slug(), "orgs-last-owner");

        // A second owner, and the guard lifts.
        let second = kit.add_member(&id, "alice", "bob", "owner").await;
        assert_eq!(second.status, StatusCode::CREATED, "{:?}", second.text());

        let leave = kit.post(&format!("/v1/orgs/{id}/leave"), "alice", "").await;
        assert_eq!(leave.status, StatusCode::OK, "{:?}", leave.text());
        assert_eq!(kit.rows_for("org_members", "user_sub", "alice").await, 0);
        assert_eq!(kit.rows_for("org_members", "user_sub", "bob").await, 1);

        // The one owner who is left is now the guarded one.
        let last = kit.post(&format!("/v1/orgs/{id}/leave"), "bob", "").await;
        assert_eq!(last.status, StatusCode::CONFLICT);
        assert_eq!(last.problem_slug(), "orgs-last-owner");
    }
}

/// An unknown role is refused before anything is written, an existing member
/// is a conflict, and adding an owner is the owner's to do.
#[pollster::test]
async fn roles_are_checked_against_the_configured_set() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;

        let unknown = kit.add_member(&id, "alice", "bob", "wizard").await;
        assert_eq!(unknown.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(unknown.problem_slug(), "orgs-unknown-role");
        assert_eq!(kit.rows("org_members").await, 1, "nothing was written");

        let added = kit.add_member(&id, "alice", "bob", "staff").await;
        assert_eq!(added.status, StatusCode::CREATED);
        let again = kit.add_member(&id, "alice", "bob", "manager").await;
        assert_eq!(again.status, StatusCode::CONFLICT);
        assert_eq!(again.problem_slug(), "orgs-already-member");

        // An owner may grant owner — the shared manager role may not.
        let owner = kit.add_member(&id, "alice", "carol", "owner").await;
        assert_eq!(owner.status, StatusCode::CREATED);
        assert_eq!(owner.json()["role"], "owner");
    }
}

/// The listing is per caller: it holds the organizations they belong to,
/// each with their own role.
#[pollster::test]
async fn the_listing_carries_my_role_in_each_organization() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;
        let _ = kit.add_member(&id, "alice", "bob", "staff").await;
        let _ = kit.create_org("alice", "Other").await;

        let mine = kit.get("/v1/orgs", "alice").await;
        assert_eq!(mine.status, StatusCode::OK);
        let orgs = mine.json()["orgs"].as_array().expect("orgs").clone();
        assert_eq!(orgs.len(), 2);
        assert!(
            orgs.iter().all(|entry| entry["role"] == "owner"),
            "{orgs:?}"
        );

        let theirs = kit.get("/v1/orgs", "bob").await;
        let theirs = theirs.json()["orgs"].as_array().expect("orgs").clone();
        assert_eq!(theirs.len(), 1);
        assert_eq!(theirs[0]["role"], "staff");
        assert_eq!(theirs[0]["org"]["id"], id.as_str());

        // A stranger belongs to nothing, and the listing says so without a 404.
        let empty = kit.get("/v1/orgs", "carol").await;
        assert_eq!(empty.status, StatusCode::OK);
        assert!(empty.json()["orgs"].as_array().expect("orgs").is_empty());
    }
}

/// Every route but the admin listing acts for the account a credential
/// proves; without one there is no account, and the answer is a 401.
#[pollster::test]
async fn every_route_but_the_admin_listing_needs_a_credential() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;
        for (method, path) in [
            (Method::GET, "/v1/orgs".to_owned()),
            (Method::POST, "/v1/orgs".to_owned()),
            (Method::GET, format!("/v1/orgs/{id}")),
            (Method::GET, format!("/v1/orgs/{id}/members")),
            (Method::POST, format!("/v1/orgs/{id}/leave")),
        ] {
            let response = send(&kit, method.clone(), &path, None, Some("{}")).await;
            assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{method} {path}");
            assert_eq!(
                response.problem_slug(),
                "unauthenticated",
                "{method} {path}"
            );
        }
    }
}

/// `member_role` and the routes agree: the typed call is the same read the
/// roster is built from, and both refuse an unknown organization and a
/// stranger with the same silence.
#[pollster::test]
async fn the_member_role_api_matches_the_routes() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;
        let _ = kit.add_member(&id, "alice", "bob", "manager").await;
        let db = &*kit.harness.db;

        assert_eq!(
            cratefield_module_orgs::member_role(db, &id, "alice")
                .await
                .expect("the read succeeds"),
            Some("owner".to_owned())
        );
        assert_eq!(
            cratefield_module_orgs::member_role(db, &id, "bob")
                .await
                .expect("the read succeeds"),
            Some("manager".to_owned())
        );
        // A stranger and an organization that does not exist are one answer.
        assert_eq!(
            cratefield_module_orgs::member_role(db, &id, "carol")
                .await
                .expect("the read succeeds"),
            None
        );
        assert_eq!(
            cratefield_module_orgs::member_role(db, "no-such-org", "alice")
                .await
                .expect("the read succeeds"),
            None
        );
    }
}

/// A listing is a page, walked by cursor: a full page hands back where the
/// next begins, a short one ends the walk, and every row is seen exactly once.
/// `limit` is clamped rather than rejected.
#[pollster::test]
async fn a_listing_pages_with_a_cursor() {
    for kit in fixture(&Spec::default()).kits {
        let id = kit.create_org("alice", "Acme").await;
        for sub in ["bob", "carol", "dave"] {
            let _ = kit.add_member(&id, "alice", sub, "staff").await;
        }

        // Four members, two to a page. The rows share a `created_at` (the
        // test clock does not move), so the tie-break is what makes the walk
        // land on each row once.
        let first = kit
            .get(&format!("/v1/orgs/{id}/members?limit=2"), "alice")
            .await;
        assert_eq!(first.status, StatusCode::OK, "{:?}", first.text());
        assert_eq!(
            first.json()["members"].as_array().expect("members").len(),
            2
        );

        let cursor = first.json()["cursor"]
            .as_str()
            .expect("a full page hands back a cursor")
            .to_owned();
        let second = kit
            .get(
                &format!("/v1/orgs/{id}/members?limit=2&cursor={cursor}"),
                "alice",
            )
            .await;
        assert_eq!(second.status, StatusCode::OK, "{:?}", second.text());
        assert_eq!(
            second.json()["members"].as_array().expect("members").len(),
            2
        );
        assert_ne!(
            cursor,
            second.json()["cursor"].as_str().unwrap_or_default(),
            "the second page must move the cursor on"
        );

        let cursor = second.json()["cursor"]
            .as_str()
            .expect("a cursor")
            .to_owned();
        let third = kit
            .get(
                &format!("/v1/orgs/{id}/members?limit=2&cursor={cursor}"),
                "alice",
            )
            .await;
        assert_eq!(third.status, StatusCode::OK, "{:?}", third.text());
        assert!(
            third.json()["members"]
                .as_array()
                .expect("members")
                .is_empty(),
            "the walk is over"
        );
        assert!(
            third.json()["cursor"].is_null(),
            "a short page ends the walk: {}",
            third.text()
        );

        let mut seen: Vec<String> = Vec::new();
        for page in [&first, &second] {
            for member in page.json()["members"].as_array().expect("members") {
                seen.push(member["sub"].as_str().expect("a sub").to_owned());
            }
        }
        seen.sort();
        assert_eq!(seen, ["alice", "bob", "carol", "dave"], "each row once");

        // A limit past the ceiling is clamped, not refused.
        let all = kit.get("/v1/orgs?limit=100000", "alice").await;
        assert_eq!(all.status, StatusCode::OK, "{:?}", all.text());
        assert_eq!(all.json()["orgs"].as_array().expect("orgs").len(), 1);
        assert!(all.json()["cursor"].is_null());
    }
}
