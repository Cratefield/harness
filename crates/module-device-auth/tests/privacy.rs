//! The personal-data declaration, proved against the module that reads it
//! (issue #587, after the pattern issue #265 established).
//!
//! `Module::personal_data()` is a promise about another crate's behaviour:
//! `cratefield-module-privacy` publishes the manifest and plans erasures
//! from it, so asserting the list against itself would prove nothing. These
//! compose the two modules the way a venture does and drive the routes —
//! the manifest must publish `device_auth_codes` under `holds` with an
//! `erase`, and an erasure keyed on the approver's subject must delete
//! exactly that person's rows.

mod support;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use cratefield_core::{Config, MapConfig, Statement};
use cratefield_module_device_auth::{DeviceAuth, DeviceClient};
use cratefield_module_privacy::Privacy;
use cratefield_testing::{TestHarness, request, request_as};

use support::{
    ApproverKind, CLIENT_A, CountingIssuer, SeqRandom, TestApprover, issue, post_form_with,
};

const ADMIN: &str = "test-admin-token-0123456789abcdef";

fn privacy_kit() -> TestHarness {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
        (
            "HARNESS_SECRET".to_owned(),
            "cratefield-testing-dummy-secret-0123456789".to_owned(),
        ),
    ]));
    TestHarness::with_ports(
        vec![
            Box::new(
                DeviceAuth::builder()
                    .client(DeviceClient::new(CLIENT_A).scopes(["read", "write"]))
                    .approver(TestApprover {
                        kind: ApproverKind::HeaderSubject,
                    })
                    .issuer(CountingIssuer::new())
                    .random(SeqRandom::new())
                    .build(),
            ),
            Box::new(Privacy::new()),
        ],
        move |ports| {
            ports.config = Arc::clone(&config);
        },
    )
}

/// Creates a request and approves it as `subject`, so the row carries that
/// approver.
async fn approved_by(kit: &TestHarness, subject: &str, name: &str) {
    let codes = issue(kit, CLIENT_A, "read", Some(name)).await;
    let bearer = format!("Bearer {subject}");
    let response = post_form_with(
        kit,
        "/v1/device-auth/approve",
        &format!("user_code={}", codes.user_code),
        &[("authorization", &bearer)],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
}

async fn rows_for(kit: &TestHarness, subject: &str) -> i64 {
    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT COUNT(*) AS n FROM device_auth_codes WHERE approver_subject = ?".to_owned(),
            vec![subject.into()],
        ))
        .await
        .expect("counting approver rows");
    rows.first().and_then(|row| row.get("n")).unwrap_or(0)
}

/// The manifest is the promise: the table is published under `holds`, as an
/// identifier, erased on request — never quietly in `not_personal`.
#[pollster::test]
async fn the_manifest_publishes_the_table_as_an_erased_identifier() {
    let kit = privacy_kit();
    let response = request(&kit.router, Method::GET, "/v1/privacy/manifest", None).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body());
    let manifest = response.json();
    let holds = manifest["holds"].as_array().expect("holds");
    let entry = holds
        .iter()
        .find(|entry| entry["table"] == "device_auth_codes")
        .unwrap_or_else(|| panic!("the table is not published under holds: {holds:?}"));
    assert_eq!(entry["module"], "device-auth", "{entry}");
    assert_eq!(entry["kind"], "identifier", "{entry}");
    assert_eq!(entry["on_erasure"]["action"], "erase", "{entry}");
    let description = entry["description"].as_str().expect("description");
    assert!(
        description.contains("hash"),
        "the entry has to say the codes are only hashes: {description}"
    );
    assert_eq!(manifest["holds_personal_data"], true);
    assert!(
        !manifest["not_personal"]
            .as_array()
            .expect("not_personal")
            .iter()
            .any(|entry| entry["table"] == "device_auth_codes"),
        "the table must not be declared not personal: {}",
        manifest["not_personal"]
    );
}

/// The erasure the declaration promises: keyed on the approver's subject it
/// deletes exactly their rows and leaves another approver's untouched.
#[pollster::test]
async fn an_erasure_keyed_on_the_approver_deletes_exactly_their_rows() {
    let kit = privacy_kit();
    approved_by(&kit, "alice", "Alice's laptop").await;
    approved_by(&kit, "alice", "Alice's phone").await;
    approved_by(&kit, "bob", "Bob's desktop").await;
    assert_eq!(rows_for(&kit, "alice").await, 2);
    assert_eq!(rows_for(&kit, "bob").await, 1);

    // The preview names the table and plans an erase.
    let preview = request_as(
        &kit.router,
        Method::POST,
        "/v1/privacy/erase",
        ADMIN,
        Some(r#"{"subject":"alice"}"#),
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK, "{:?}", preview.body());
    let plan = preview.json()["plan"].as_array().expect("plan").clone();
    let entry = plan
        .iter()
        .find(|row| row["table"] == "device_auth_codes")
        .unwrap_or_else(|| panic!("the table is not in the plan: {plan:?}"));
    assert_eq!(entry["action"], "erase", "{entry}");

    let token = preview.json()["confirm_token"].clone();
    let confirmed = request_as(
        &kit.router,
        Method::POST,
        "/v1/privacy/erase/confirm",
        ADMIN,
        Some(&format!(r#"{{"token":{token}}}"#)),
    )
    .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.body());
    assert_eq!(confirmed.json()["verified"], true, "{:?}", confirmed.body());

    assert_eq!(
        rows_for(&kit, "alice").await,
        0,
        "the erasure removed alice's rows"
    );
    assert_eq!(
        rows_for(&kit, "bob").await,
        1,
        "the erasure took another approver's row with it"
    );
}
