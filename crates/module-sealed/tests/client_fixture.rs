//! The `@cratefield/sealed` half of the contract, played back against this
//! server: the shared fixture in `tests/fixtures/client-record.json` is a
//! record the TypeScript client produced (`packages/sealed` generated it),
//! and the server must take it verbatim — and hold it without ever seeing
//! the line inside.

mod support;

use cratefield_testing::{FakeAuth, MemoryBlob, TestHarness, request_as};
use std::sync::Arc;
use support::SUBJECT_ID;

const PLAINTEXT: &str = "sealed-fixture: the server must never see this line";
const PATH: &str = "/v1/sealed/blobs";

fn kit() -> TestHarness {
    let auth: Arc<dyn cratefield_core::Auth> = Arc::new(FakeAuth::subjects());
    TestHarness::with_ports(
        vec![Box::new(cratefield_module_sealed::Sealed::new(
            Arc::new(support::FakeKms::new()),
            Arc::new(cratefield_module_sealed::NoopNotifier),
        ))],
        move |ports| {
            ports.auth = Some(Arc::clone(&auth));
            ports.blob = Some(Arc::new(MemoryBlob::new()));
        },
    )
}

/// Every byte the server now holds: one string per text column, one blob per
/// binary column and store object — the whole of the server's view.
async fn all_server_bytes(kit: &TestHarness) -> Vec<Vec<u8>> {
    let mut held = Vec::new();
    for table in ["sealed_blobs", "sealed_deks", "sealed_audit"] {
        let rows = kit
            .db
            .query(&cratefield_core::Statement::new(format!(
                "SELECT * FROM {table}"
            )))
            .await
            .expect("table scan");
        for row in &rows.rows {
            for (column, _) in row.columns() {
                if let Some(text) = row.get::<String>(column) {
                    held.push(text.into_bytes());
                }
                if let Some(bytes) = row.get::<Vec<u8>>(column) {
                    held.push(bytes);
                }
            }
        }
    }
    held
}

#[pollster::test]
async fn the_client_record_is_taken_verbatim_and_stays_opaque() {
    let fixture = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/client-record.json"
    ))
    .expect("the shared fixture is in the crate");
    let record: serde_json::Value = serde_json::from_str(&fixture).expect("fixture parses");

    let kit = kit();
    let created = request_as(
        &kit.router,
        axum::http::Method::POST,
        PATH,
        SUBJECT_ID,
        Some(&fixture),
    )
    .await;
    assert_eq!(
        created.status,
        axum::http::StatusCode::CREATED,
        "{:?}",
        created.body()
    );

    // The wire record comes back byte-identical in the fields that matter:
    // the payload string and every wrap, exactly as the client sent them.
    let served = request_as(
        &kit.router,
        axum::http::Method::GET,
        &format!("{PATH}/{}", record["blob_id"].as_str().expect("blob_id")),
        SUBJECT_ID,
        None,
    )
    .await;
    assert_eq!(served.status, axum::http::StatusCode::OK);
    let body = served.json();
    assert_eq!(body["ciphertext"], record["ciphertext"]);
    assert_eq!(body["wraps"], record["wraps"]);
    assert_eq!(body["purpose"], record["purpose"]);
    assert_eq!(body["alg"], record["alg"]);
    assert_eq!(
        body["created_by_credential"],
        record["created_by_credential"]
    );
    assert_eq!(body["subject"], SUBJECT_ID);

    // And the line the client sealed appears nowhere in the server's state.
    for held in all_server_bytes(&kit).await {
        assert!(
            !held
                .windows(PLAINTEXT.len())
                .any(|window| window == PLAINTEXT.as_bytes()),
            "the server's bytes contain the fixture plaintext: {}",
            String::from_utf8_lossy(&held)
        );
    }
}
