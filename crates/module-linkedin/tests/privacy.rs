//! Issue #265: the declarations, proved against the module that reads them.
//!
//! `Module::personal_data()` is a promise about behaviour that lives in
//! another crate — `cratefield-module-privacy` plans an export and an erasure
//! from it — so asserting the list against itself would prove nothing. These
//! compose the two modules the way a venture does and drive the routes.
//!
//! The one that matters here is the redaction. `linkedin_accounts` stores a
//! LinkedIn access token and refresh token in the clear, because it has to
//! present them; `GET /v1/privacy/export` is a `SELECT *` written to a file
//! people forward, so a token in the row would be a token in that file.

use axum::http::{Method, StatusCode, header};
use cratefield_core::{Config, MapConfig, Statement};
use cratefield_module_privacy::Privacy;
use cratefield_testing::TestHarness;
use fz_module_linkedin::Linkedin;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const PERSON: &str = "urn:li:person:AbC123";

/// Bearer credentials. Whoever holds one can post as the venture until it
/// expires (ADR 0015).
const ACCESS: &str = "linkedin-access-token-bearer-capability";
const REFRESH: &str = "linkedin-refresh-token-bearer-capability";

fn privacy_kit() -> TestHarness {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
        (
            "HARNESS_SECRET".to_owned(),
            "cratefield-testing-dummy-secret-0123456789".to_owned(),
        ),
    ]));
    TestHarness::with_ports(
        vec![Box::new(Linkedin::new()), Box::new(Privacy::new())],
        move |ports| {
            ports.config = Arc::clone(&config);
        },
    )
}

async fn seed(kit: &TestHarness) {
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO linkedin_accounts (id, singleton, person_urn, access_token, \
             access_expires_at, refresh_token, refresh_expires_at, scopes, status, created_at, \
             updated_at) VALUES (?, 1, ?, ?, ?, ?, ?, 'w_organization_social', 'connected', ?, ?)"
                .to_owned(),
            vec![
                "01HCLINKEDINACCOUNT00000001".into(),
                PERSON.into(),
                ACCESS.into(),
                "2027-01-01T00:00:00Z".into(),
                REFRESH.into(),
                "2027-06-01T00:00:00Z".into(),
                "2026-01-01T00:00:00Z".into(),
                "2026-01-01T00:00:00Z".into(),
            ],
        ))
        .await
        .expect("seeding a linkedin account");
}

async fn accounts(kit: &TestHarness) -> i64 {
    let rows = kit
        .db
        .query(&Statement::new(
            "SELECT COUNT(*) AS n FROM linkedin_accounts".to_owned(),
        ))
        .await
        .expect("counting accounts");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or(-1)
}

struct Answer {
    status: StatusCode,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {}", self.text()))
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn send(
    kit: &TestHarness,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Answer {
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let payload = match body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(json.to_owned())
        }
        None => axum::body::Body::empty(),
    };
    let response = kit
        .router
        .clone()
        .oneshot(builder.body(payload).expect("request builds"))
        .await
        .expect("router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads")
        .to_vec();
    Answer { status, body }
}

#[pollster::test]
async fn an_export_names_the_two_tokens_and_copies_neither() {
    let kit = privacy_kit();
    seed(&kit).await;

    let response = send(
        &kit,
        Method::GET,
        &format!("/v1/privacy/export?subject={PERSON}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let raw = response.text();
    assert!(
        !raw.contains(ACCESS) && !raw.contains(REFRESH),
        "the export copied a LinkedIn bearer token into a file people forward"
    );

    let body = response.json();
    let tables = body["tables"].as_array().expect("tables");
    // Only the one table has a subject column; the other five are `none`.
    let listed: Vec<&str> = tables.iter().filter_map(|t| t["table"].as_str()).collect();
    assert_eq!(listed, ["linkedin_accounts"], "{listed:?}");

    let row = &tables[0]["rows"][0];
    // Named, not dropped: "we hold nothing there" is the one answer a subject
    // access request must not give untruthfully.
    assert_eq!(row["access_token"], "[redacted]", "{row}");
    assert_eq!(row["refresh_token"], "[redacted]", "{row}");
    // What the permission actually is stays visible: it is the answer they
    // asked for.
    assert_eq!(row["scopes"], "w_organization_social", "{row}");
    assert_eq!(row["person_urn"], PERSON, "{row}");
}

#[pollster::test]
async fn an_erasure_takes_the_connection_and_its_tokens_with_it() {
    let kit = privacy_kit();
    seed(&kit).await;

    let preview = send(
        &kit,
        Method::POST,
        "/v1/privacy/erase",
        Some(ADMIN),
        Some(&format!(r#"{{"subject":"{PERSON}"}}"#)),
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text());
    let body = preview.json();
    let entry = body["plan"]
        .as_array()
        .expect("plan")
        .iter()
        .find(|row| row["table"] == "linkedin_accounts")
        .expect("linkedin_accounts planned")
        .clone();
    assert_eq!(entry["action"], "erase", "{entry}");
    assert_eq!(entry["rows"], 1, "{entry}");
    assert_eq!(accounts(&kit).await, 1, "the preview wrote something");

    let confirm = send(
        &kit,
        Method::POST,
        "/v1/privacy/erase/confirm",
        Some(ADMIN),
        Some(&format!(r#"{{"token":{}}}"#, body["confirm_token"])),
    )
    .await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.text());
    assert_eq!(confirm.json()["verified"], true);
    assert_eq!(accounts(&kit).await, 0, "a live credential survived");
}

#[pollster::test]
async fn the_manifest_says_why_the_other_five_tables_hold_nobody() {
    // Four of the five would otherwise look exactly like the omission this
    // rule exists to catch. "No declaration" and "nothing here" must not look
    // the same.
    let kit = privacy_kit();
    let response = send(&kit, Method::GET, "/v1/privacy/manifest", None, None).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();

    let not_personal = body["not_personal"].as_array().expect("not_personal");
    let listed: Vec<&str> = not_personal
        .iter()
        .filter_map(|entry| entry["table"].as_str())
        .collect();
    assert_eq!(
        listed,
        [
            "linkedin_pages",
            "linkedin_posts",
            "linkedin_assets",
            "linkedin_oauth_states",
            "linkedin_request_budget",
        ],
        "every table is accounted for one way or the other"
    );
    for entry in not_personal {
        let reason = entry["reason"].as_str().unwrap_or_default();
        assert!(
            reason.len() > 40,
            "{} is declared with no real reason: {reason:?}",
            entry["table"]
        );
    }

    let accounts = body["holds"]
        .as_array()
        .expect("holds")
        .iter()
        .find(|entry| entry["table"] == "linkedin_accounts")
        .expect("linkedin_accounts published")
        .clone();
    assert_eq!(
        accounts["redacted"],
        serde_json::json!(["access_token", "refresh_token"]),
        "{accounts}"
    );
    assert_eq!(accounts["on_erasure"]["action"], "erase", "{accounts}");
}
