//! Removing a sign-in identity from a venture account, and the single-use
//! link intent that a Factory Zero link resumes from.
//!
//! The load-bearing claim is the last one: removing an identity never leaves
//! an account with no way in. The same rule [`cratefield_auth_core::linking`]
//! applies is the one the endpoint answers with, so the venture cannot be
//! locked out by its own "unlink" button.

use axum::http::{Method, StatusCode};
use cratefield_auth_core::{
    AuthCore, IdentityRow, Login, UserRow, identities_by_user, insert_identity, insert_user, issue,
    link_intent,
};
use cratefield_core::UlidIdGen;
use cratefield_testing::{FixedClock, TestHarness};
use serde_json::Value;
use std::sync::Arc;
use time::OffsetDateTime;
use tower::ServiceExt;

const EPOCH: i64 = 1_800_000_000;
const BASE: &str = "/v1/auth-core";

fn at(secs: i64) -> FixedClock {
    FixedClock(OffsetDateTime::from_unix_timestamp(secs).expect("epoch in range"))
}

fn iso(secs: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::from_unix_timestamp(secs)
        .expect("in range")
        .format(&Rfc3339)
        .expect("rfc3339")
}

fn harness() -> TestHarness {
    let config = Arc::new(cratefield_core::MapConfig::from_pairs(Vec::<(
        String,
        String,
    )>::new()));
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], move |ports| {
        ports.config = config;
    })
}

async fn person_with_identities(
    kit: &TestHarness,
    providers: &[&str],
) -> (String, String, Vec<String>) {
    insert_user(
        &*kit.db,
        &UserRow {
            id: "u1".to_owned(),
            display_name: None,
            primary_email: Some("u1@example.com".to_owned()),
            primary_email_verified: true,
            locale: None,
            status: "active".to_owned(),
            created_at: iso(EPOCH),
            updated_at: iso(EPOCH),
        },
    )
    .await
    .expect("user");
    let mut ids = Vec::new();
    for (n, provider) in providers.iter().enumerate() {
        let id = format!("identity-{n}");
        insert_identity(
            &*kit.db,
            &IdentityRow {
                id: id.clone(),
                user_id: "u1".to_owned(),
                provider: (*provider).to_owned(),
                provider_subject: format!("subject-{n}"),
                email: Some("u1@example.com".to_owned()),
                email_verified: true,
                name_at_link: None,
                created_at: iso(EPOCH),
                last_login_at: None,
            },
        )
        .await
        .expect("identity");
        ids.push(id);
    }
    let cookie = issue(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        Login {
            user_id: "u1",
            ip: None,
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr: &["email"],
        },
    )
    .await
    .expect("session")
    .value;
    ("u1".to_owned(), cookie, ids)
}

async fn send(kit: &TestHarness, method: Method, uri: &str, cookie: &str) -> (StatusCode, Value) {
    let request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header(
            axum::http::header::COOKIE,
            format!("__Host-session={cookie}"),
        )
        .body(axum::body::Body::empty())
        .expect("request");
    let response = kit.router.clone().oneshot(request).await.expect("answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[test]
fn an_identity_can_be_removed_but_never_the_last_way_in() {
    pollster::block_on(async {
        let kit = harness();
        let (_user, cookie, ids) = person_with_identities(&kit, &["google", "factory-zero"]).await;

        let (status, list) = send(&kit, Method::GET, &format!("{BASE}/identities"), &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list["identities"].as_array().map(Vec::len), Some(2));

        // Two identities, so one may go.
        let (status, _) = send(
            &kit,
            Method::DELETE,
            &format!("{BASE}/identities/{}", ids[1]),
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The last one is the only way in: refused, and it stays.
        let (status, body) = send(
            &kit,
            Method::DELETE,
            &format!("{BASE}/identities/{}", ids[0]),
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let left = identities_by_user(&*kit.db, "u1").await.expect("rows");
        assert_eq!(left.len(), 1);
    });
}

#[test]
fn another_persons_identity_is_not_addressable() {
    pollster::block_on(async {
        let kit = harness();
        let (_user, cookie, _ids) = person_with_identities(&kit, &["google", "factory-zero"]).await;
        insert_user(
            &*kit.db,
            &UserRow {
                id: "someone-else".to_owned(),
                display_name: None,
                primary_email: Some("else@example.com".to_owned()),
                primary_email_verified: true,
                locale: None,
                status: "active".to_owned(),
                created_at: iso(EPOCH),
                updated_at: iso(EPOCH),
            },
        )
        .await
        .expect("the other person");
        insert_identity(
            &*kit.db,
            &IdentityRow {
                id: "theirs".to_owned(),
                user_id: "someone-else".to_owned(),
                provider: "google".to_owned(),
                provider_subject: "x".to_owned(),
                email: None,
                email_verified: false,
                name_at_link: None,
                created_at: iso(EPOCH),
                last_login_at: None,
            },
        )
        .await
        .expect("another person's identity");
        let (status, _) = send(
            &kit,
            Method::DELETE,
            &format!("{BASE}/identities/theirs"),
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

#[test]
fn a_link_intent_is_spent_once_and_lapses() {
    pollster::block_on(async {
        let kit = harness();
        link_intent::issue(&*kit.db, &at(EPOCH), "intent-a")
            .await
            .expect("the kind is admitted");
        assert!(
            link_intent::spend(&*kit.db, &at(EPOCH + 1), "intent-a")
                .await
                .expect("spend")
        );
        assert!(
            !link_intent::spend(&*kit.db, &at(EPOCH + 2), "intent-a")
                .await
                .expect("spend"),
            "a second spend won"
        );

        link_intent::issue(&*kit.db, &at(EPOCH), "intent-b")
            .await
            .expect("issue");
        let lapsed = at(EPOCH + link_intent::LINK_INTENT_TTL_SECS + 1);
        assert!(
            !link_intent::spend(&*kit.db, &lapsed, "intent-b")
                .await
                .expect("spend"),
            "an expired intent spent"
        );
        assert!(
            !link_intent::spend(&*kit.db, &at(EPOCH), "never-issued")
                .await
                .expect("spend")
        );
    });
}
