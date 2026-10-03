//! The admin listing: a machine holding `ADMIN_TOKEN`, or a person in the
//! venture's staff organization holding a staff role — and nobody else
//! (issue #652).

mod support;

use axum::http::{Method, StatusCode};

use support::{ADMIN, Spec, fixture, fixture_without_admin, send};

/// The listing opens for the machine token and for a staff member, and gives
/// both the same rows.
#[pollster::test]
async fn the_admin_listing_opens_for_the_token_and_for_a_staff_member() {
    // The staff organization is named in the builder; the row is seeded with
    // that id so the two agree.
    let spec = Spec::with_staff("org-staff", "admin");
    for kit in fixture(&spec).kits {
        kit.seed_org("org-staff", "Staff", "bob", "admin").await;
        let _ = kit.create_org("alice", "Acme").await;

        let machine = send(&kit, Method::GET, "/v1/orgs/admin/orgs", Some(ADMIN), None).await;
        assert_eq!(machine.status, StatusCode::OK, "{:?}", machine.text());
        assert_eq!(machine.json()["orgs"].as_array().expect("orgs").len(), 2);

        let staff = kit.get("/v1/orgs/admin/orgs", "bob").await;
        assert_eq!(staff.status, StatusCode::OK, "{:?}", staff.text());
        assert_eq!(staff.json()["orgs"].as_array().expect("orgs").len(), 2);
    }
}

/// A signed-in person who is not staff is refused with a 403 — not the 401
/// that would tell them to sign in again — and a caller with no credential at
/// all gets the 401 the token path gives.
#[pollster::test]
async fn a_non_staff_person_is_refused_and_an_anonymous_caller_is_unauthorized() {
    let spec = Spec::with_staff("org-staff", "admin");
    for kit in fixture(&spec).kits {
        kit.seed_org("org-staff", "Staff", "bob", "admin").await;
        kit.seed_member("org-staff", "carol", "staff").await;

        let stranger = kit.get("/v1/orgs/admin/orgs", "carol").await;
        assert_eq!(
            stranger.status,
            StatusCode::FORBIDDEN,
            "{:?}",
            stranger.text()
        );
        assert_eq!(stranger.problem_slug(), "admin-forbidden");
        assert_eq!(
            kit.get("/v1/orgs/admin/orgs", "dave").await.status,
            StatusCode::FORBIDDEN,
            "someone outside the staff organization is refused too"
        );

        let anonymous = send(&kit, Method::GET, "/v1/orgs/admin/orgs", None, None).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
        assert_eq!(anonymous.problem_slug(), "admin-unauthorized");

        // A presented-but-wrong token is a 403, the answer `require_admin`
        // gives one — it is a credential that did not earn the route, not a
        // caller who failed to present one.
        let bad_token = send(
            &kit,
            Method::GET,
            "/v1/orgs/admin/orgs",
            Some("not-the-admin-token"),
            None,
        )
        .await;
        assert_eq!(bad_token.status, StatusCode::FORBIDDEN);
        assert_eq!(bad_token.problem_slug(), "admin-forbidden");
    }
}

/// A deployment that set no `ADMIN_TOKEN` has no machine path: the listing
/// refuses a token where a token would have worked, and a staff member alone
/// opens it. The move off the shared secret is complete when the secret is
/// gone.
#[pollster::test]
async fn without_an_admin_token_only_the_staff_path_opens_the_listing() {
    let spec = Spec::with_staff("org-staff", "admin");
    for kit in fixture_without_admin(&spec).kits {
        kit.seed_org("org-staff", "Staff", "bob", "admin").await;
        let _ = kit.create_org("alice", "Acme").await;

        // The token that opens the listing in every other fixture buys nothing
        // here: nothing is configured to compare it against, so it is just a
        // bearer that belongs to no member, and it is refused as the person it
        // is not — the 403 a non-staff stranger gets.
        let machine = send(&kit, Method::GET, "/v1/orgs/admin/orgs", Some(ADMIN), None).await;
        assert_eq!(
            machine.status,
            StatusCode::FORBIDDEN,
            "{:?}",
            machine.text()
        );
        assert_eq!(machine.problem_slug(), "admin-forbidden");

        // With no credential at all there is no person to judge, and the
        // answer is the 401 `require_admin` gives when nothing is configured.
        let anonymous = send(&kit, Method::GET, "/v1/orgs/admin/orgs", None, None).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
        assert_eq!(anonymous.problem_slug(), "admin-unauthorized");

        let staff = kit.get("/v1/orgs/admin/orgs", "bob").await;
        assert_eq!(staff.status, StatusCode::OK, "{:?}", staff.text());
        assert_eq!(staff.json()["orgs"].as_array().expect("orgs").len(), 2);

        let outsider = kit.get("/v1/orgs/admin/orgs", "alice").await;
        assert_eq!(outsider.status, StatusCode::FORBIDDEN);
        assert_eq!(outsider.problem_slug(), "admin-forbidden");
    }
}

/// Without a staff organization the machine path is the only one: a person's
/// credential is judged by the token check alone, and buys nothing — the
/// deployment that has not moved yet.
#[pollster::test]
async fn without_a_staff_organization_a_person_is_not_staff() {
    for kit in fixture(&Spec::default()).kits {
        let machine = send(&kit, Method::GET, "/v1/orgs/admin/orgs", Some(ADMIN), None).await;
        assert_eq!(machine.status, StatusCode::OK, "{:?}", machine.text());
        assert!(machine.json()["orgs"].as_array().expect("orgs").is_empty());

        // The person's token is not the admin token, so the token check
        // refuses it exactly as it refuses any other wrong bearer.
        let person = kit.get("/v1/orgs/admin/orgs", "alice").await;
        assert_eq!(person.status, StatusCode::FORBIDDEN);
        assert_eq!(person.problem_slug(), "admin-forbidden");

        let anonymous = send(&kit, Method::GET, "/v1/orgs/admin/orgs", None, None).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
        assert_eq!(anonymous.problem_slug(), "admin-unauthorized");
    }
}
