//! The personal-data declarations, proved against the module that reads
//! them: `cratefield-module-privacy` composes with the sealed store the way
//! a venture would, and its export and erasure run over the three sealed
//! tables — the wraps exportable, the wrapped key redacted, the erasure the
//! crypto-shred, the audit chain retained.

mod support;

use axum::http::{Method, StatusCode};
use cratefield_core::{Config, MapConfig, Statement};
use cratefield_module_privacy::Privacy;
use cratefield_module_sealed::Sealed;
use cratefield_testing::{FakeAuth, MemoryBlob, TestHarness, request, request_as};
use serde_json::{Value, json};
use std::sync::Arc;
use support::{FakeKms, record};

const SUBJECT: &str = "user-alice";
const OTHER: &str = "user-mallory";
const ADMIN: &str = "test-admin-token-0123456789abcdef";
const BLOBS: &str = "/v1/sealed/blobs";

fn kit() -> TestHarness {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
        (
            "HARNESS_SECRET".to_owned(),
            "cratefield-testing-dummy-secret-0123456789".to_owned(),
        ),
    ]));
    let auth: Arc<dyn cratefield_core::Auth> = Arc::new(FakeAuth::subjects());
    TestHarness::with_ports(
        vec![
            Box::new(Sealed::new(
                Arc::new(FakeKms::new()),
                Arc::new(cratefield_module_sealed::NoopNotifier),
            )),
            Box::new(Privacy::new()),
        ],
        move |ports| {
            ports.config = Arc::clone(&config);
            ports.auth = Some(Arc::clone(&auth));
            ports.blob = Some(Arc::new(MemoryBlob::new()));
        },
    )
}

async fn count(kit: &TestHarness, table: &str) -> i64 {
    kit.db
        .query(&Statement::new(format!(
            "SELECT COUNT(*) AS n FROM {table}"
        )))
        .await
        .expect("count")
        .first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or(-1)
}

async fn create_blob(kit: &TestHarness, subject: &str, blob_id: &str) {
    let response = request_as(
        &kit.router,
        Method::POST,
        BLOBS,
        subject,
        Some(&serde_json::to_string(&record(blob_id, 1, "vault")).expect("record serialises")),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "{:?}",
        response.body()
    );
}

/// The export's entry for one table.
fn table_of<'a>(export: &'a Value, name: &str) -> &'a Value {
    export["tables"]
        .as_array()
        .expect("tables")
        .iter()
        .find(|entry| entry["table"] == name)
        .unwrap_or_else(|| panic!("{name} is in the export: {export}"))
}

#[pollster::test]
async fn the_manifest_declares_the_three_tables() {
    let kit = kit();
    let response = request(&kit.router, Method::GET, "/v1/privacy/manifest", None).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    let tables: Vec<&str> = body["holds"]
        .as_array()
        .expect("holds is an array")
        .iter()
        .filter_map(|entry| entry["table"].as_str())
        .collect();
    assert!(tables.contains(&"sealed_blobs"), "{tables:?}");
    assert!(tables.contains(&"sealed_deks"), "{tables:?}");
    // The audit chain is declared too — held, but retained on erasure
    // rather than deleted, and the manifest says so out loud.
    let audit_entry = body["holds"]
        .as_array()
        .expect("holds is an array")
        .iter()
        .find(|entry| entry["table"] == "sealed_audit")
        .expect("sealed_audit is declared");
    assert_eq!(audit_entry["on_erasure"]["action"], "retain");
    assert!(
        audit_entry["on_erasure"]["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "the retain reason is published: {audit_entry}"
    );
}

#[pollster::test]
async fn the_export_holds_the_wraps_and_never_the_wrapped_key() {
    let kit = kit();
    create_blob(&kit, SUBJECT, "export-1").await;

    let response = request_as(
        &kit.router,
        Method::GET,
        &format!("/v1/privacy/export?subject={SUBJECT}"),
        ADMIN,
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body());
    let export = response.json();

    // The blob row: the wraps and the credential come along, the body is
    // reported by its size.
    let blobs = table_of(&export, "sealed_blobs");
    let row = &blobs["rows"][0];
    assert_eq!(row["blob_id"], "export-1");
    assert_eq!(row["created_by_credential"], "test-credential-1");
    assert!(
        row["wraps"]
            .as_str()
            .is_some_and(|wraps| wraps.contains("passkey-1")),
        "the wrap set is exportable: {:?}",
        row["wraps"]
    );
    assert!(
        row["outer_ct"]["bytes"].is_u64(),
        "the body is reported, not inlined: {:?}",
        row["outer_ct"]
    );

    // The key table: named, with its key material redacted.
    let deks = table_of(&export, "sealed_deks");
    assert_eq!(deks["rows"][0]["wrapped_dek"], json!("[redacted]"));

    // Another subject's export does not see the blob at all.
    let other = request_as(
        &kit.router,
        Method::GET,
        &format!("/v1/privacy/export?subject={OTHER}"),
        ADMIN,
        None,
    )
    .await
    .json();
    assert!(
        table_of(&other, "sealed_blobs")["rows"]
            .as_array()
            .expect("rows")
            .is_empty(),
        "another subject's export holds nothing of Alice's: {other}"
    );
}

#[pollster::test]
async fn erasure_is_the_crypto_shred_and_keeps_the_chain() {
    let kit = kit();
    create_blob(&kit, SUBJECT, "gone-1").await;
    create_blob(&kit, OTHER, "stays-1").await;
    assert_eq!(count(&kit, "sealed_blobs").await, 2);
    assert_eq!(count(&kit, "sealed_deks").await, 2);
    let audit_rows = count(&kit, "sealed_audit").await;

    let preview = request_as(
        &kit.router,
        Method::POST,
        "/v1/privacy/erase",
        ADMIN,
        Some(&json!({ "subject": SUBJECT }).to_string()),
    )
    .await;
    assert!(preview.status.is_success(), "{:?}", preview.body());
    let confirmed = request_as(
        &kit.router,
        Method::POST,
        "/v1/privacy/erase/confirm",
        ADMIN,
        Some(&json!({ "token": preview.json()["confirm_token"] }).to_string()),
    )
    .await;
    assert!(confirmed.status.is_success(), "{:?}", confirmed.body());
    assert_eq!(confirmed.json()["verified"], true);

    // Alice's blob and its key are gone; Mallory's survive untouched; the
    // audit chain keeps every row, Alice's included (declared Retain).
    assert_eq!(count(&kit, "sealed_blobs").await, 1);
    assert_eq!(count(&kit, "sealed_deks").await, 1);
    assert_eq!(count(&kit, "sealed_audit").await, audit_rows);

    // And the chain still verifies after the erasure walked it.
    cratefield_module_sealed::audit::verify(kit.db.as_ref())
        .await
        .expect("the chain verifies across an erasure");
}
