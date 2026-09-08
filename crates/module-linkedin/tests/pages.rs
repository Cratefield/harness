//! Issue #10 and #15 acceptance: the directory is built from the ACLs, a
//! partial batch failure does not lose the rest, showcase pages are found
//! through their parent, and a role that cannot publish is recorded as such.

mod support;

use axum::http::StatusCode;
use support::{ORG, SHOWCASE, connect, get, organization, post_json};

const DAILY: &str = "0 3 * * *";

#[test]
fn connecting_builds_the_page_directory_through_the_event() {
    pollster::block_on(async {
        let kit = support::kit();
        kit.fake
            .add_showcase(ORG, organization(SHOWCASE, "Showcase", "BRAND", Some(ORG)));
        kit.fake
            .set_acls(&[(ORG, "ADMINISTRATOR"), (SHOWCASE, "ADMINISTRATOR")]);
        kit.fake.set_organizations(vec![
            organization(ORG, "DevTestCo", "NONE", None),
            organization(SHOWCASE, "Showcase", "BRAND", Some(ORG)),
        ]);

        connect(&kit).await;
        // The sync is not called from the callback: it listens for
        // linkedin.connected, which runs through the request's defer.
        assert_eq!(support::count(&kit, "linkedin_pages", "1=1"), 0);

        kit.drain().await;

        let pages = get(&kit, "/v1/linkedin/admin/pages").await.json();
        let listed = pages["pages"].as_array().expect("pages");
        assert_eq!(listed.len(), 2, "{pages}");
        let company = listed
            .iter()
            .find(|page| page["org_id"] == ORG)
            .expect("company");
        let showcase = listed
            .iter()
            .find(|page| page["org_id"] == SHOWCASE)
            .expect("showcase");
        assert_eq!(company["kind"], "company");
        assert_eq!(company["can_post_organic"], true);
        assert_eq!(showcase["kind"], "showcase");
        assert_eq!(showcase["parent_org_id"], ORG);
    });
}

#[test]
fn the_acl_walk_reads_both_spellings_of_the_organization_field() {
    pollster::block_on(async {
        let kit = support::kit();
        connect(&kit).await;
        post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;

        // The fake answers with `organizationTarget`, which is the spelling
        // the module has to cope with alongside `organization`.
        let acl_call = kit
            .fake
            .calls_to("/rest/organizationAcls")
            .into_iter()
            .next()
            .expect("an acl call");
        assert!(acl_call.url.contains("q=roleAssignee"));
        assert!(acl_call.url.contains("state=APPROVED"));
        assert_eq!(acl_call.header("x-restli-method"), Some("FINDER"));
        assert_eq!(
            support::count(&kit, "linkedin_pages", "org_id = '2414183'"),
            1
        );
    });
}

#[test]
fn a_403_on_one_id_does_not_lose_the_rest_of_the_batch() {
    pollster::block_on(async {
        let kit = support::kit();
        // Two roles, but the organizations lookup can only see one of them.
        kit.fake
            .set_acls(&[(ORG, "ADMINISTRATOR"), ("99999999", "ADMINISTRATOR")]);
        kit.fake
            .set_organizations(vec![organization(ORG, "DevTestCo", "NONE", None)]);

        connect(&kit).await;
        let synced = post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;
        assert_eq!(synced.status, StatusCode::OK, "{}", synced.text());
        assert_eq!(synced.json()["pages"], 1);
        assert_eq!(
            support::count(&kit, "linkedin_pages", "org_id = '2414183'"),
            1
        );
    });
}

#[test]
fn a_showcase_we_do_not_administer_is_recorded_but_not_postable() {
    pollster::block_on(async {
        let kit = support::kit();
        // The parent's ACL says nothing about the showcase: a role on the
        // parent is not a role on the showcase.
        kit.fake.set_acls(&[(ORG, "ADMINISTRATOR")]);
        kit.fake
            .set_organizations(vec![organization(ORG, "DevTestCo", "NONE", None)]);
        kit.fake
            .add_showcase(ORG, organization(SHOWCASE, "Showcase", "BRAND", Some(ORG)));

        connect(&kit).await;
        post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;

        let pages = get(&kit, "/v1/linkedin/admin/pages?kind=showcase")
            .await
            .json();
        let showcase = &pages["pages"][0];
        assert_eq!(showcase["org_id"], SHOWCASE);
        assert_eq!(showcase["role"], "UNKNOWN");
        assert_eq!(showcase["can_post_organic"], false);

        // Posting to it fails locally, before a request is spent.
        let refused = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{SHOWCASE}/posts"),
            r#"{"commentary":"hi","idempotency_key":"k"}"#,
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        assert_eq!(kit.fake.created_posts(), 0);
    });
}

#[test]
fn a_showcase_we_do_administer_can_be_posted_to_by_its_organization_urn() {
    pollster::block_on(async {
        let kit = support::kit();
        kit.fake
            .set_acls(&[(ORG, "ADMINISTRATOR"), (SHOWCASE, "ADMINISTRATOR")]);
        kit.fake.set_organizations(vec![
            organization(ORG, "DevTestCo", "NONE", None),
            organization(SHOWCASE, "Showcase", "BRAND", Some(ORG)),
        ]);
        connect(&kit).await;
        post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;

        let created = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{SHOWCASE}/posts"),
            r#"{"commentary":"From the showcase","idempotency_key":"k"}"#,
        )
        .await;
        assert_eq!(created.status, StatusCode::ACCEPTED, "{}", created.text());
        kit.drain().await;

        let sent = kit
            .fake
            .calls_to("/rest/posts")
            .into_iter()
            .next()
            .expect("a create")
            .json();
        // A showcase is addressed by its own organization URN, not the
        // parent's and not an organizationBrand URN.
        assert_eq!(sent["author"], format!("urn:li:organization:{SHOWCASE}"));
    });
}

#[test]
fn the_legacy_brand_urn_names_the_same_page() {
    pollster::block_on(async {
        let kit = support::kit();
        kit.fake
            .set_acls(&[(ORG, "ADMINISTRATOR"), (SHOWCASE, "ADMINISTRATOR")]);
        kit.fake.set_organizations(vec![
            organization(ORG, "DevTestCo", "NONE", None),
            organization(SHOWCASE, "Showcase", "BRAND", Some(ORG)),
        ]);
        connect(&kit).await;
        post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;

        // Old links and old notes carry urn:li:organizationBrand:{id}, which
        // has addressed the same entity since January 2024.
        let created = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/urn:li:organizationBrand:{SHOWCASE}/posts"),
            r#"{"commentary":"Legacy urn","idempotency_key":"k"}"#,
        )
        .await;
        assert_eq!(created.status, StatusCode::ACCEPTED, "{}", created.text());
        kit.drain().await;
        assert_eq!(kit.fake.created_posts(), 1);
    });
}

#[test]
fn a_role_that_disappears_marks_the_page_revoked() {
    pollster::block_on(async {
        let kit = support::kit();
        connect(&kit).await;
        post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;
        assert_eq!(
            support::count(&kit, "linkedin_pages", "state = 'active'"),
            1
        );

        // The role is gone at LinkedIn's end.
        kit.fake.set_acls(&[]);
        kit.clock.advance_secs(60);
        let synced = post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;
        assert_eq!(synced.json()["revoked"], 1);

        // The row survives so a post that references it still resolves.
        assert_eq!(
            support::count(&kit, "linkedin_pages", "state = 'revoked'"),
            1
        );
        let refused = post_json(
            &kit,
            &format!("/v1/linkedin/admin/pages/{ORG}/posts"),
            r#"{"commentary":"hi","idempotency_key":"k"}"#,
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
    });
}

#[test]
fn the_daily_cron_syncs_the_directory() {
    pollster::block_on(async {
        let kit = support::kit();
        connect(&kit).await;
        assert_eq!(support::count(&kit, "linkedin_pages", "1=1"), 0);

        kit.cron(DAILY).await;
        assert_eq!(support::count(&kit, "linkedin_pages", "1=1"), 1);
    });
}

#[test]
fn an_unknown_kind_filter_is_a_validation_error() {
    pollster::block_on(async {
        let kit = support::kit();
        let response = get(&kit, "/v1/linkedin/admin/pages?kind=galaxy").await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    });
}
