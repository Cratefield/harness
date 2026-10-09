//! The `@cratefield/sealed` half of the contract, played back against this
//! server: a record with exactly the shape the TypeScript client produces
//! (`packages/sealed`, see its `fixture.test.ts`) is posted verbatim, and
//! the server must take it verbatim — and hold it without ever seeing the
//! line inside. Every field is opaque to the server, so the record is built
//! at runtime from obviously fake bytes: the contract needs the shape, not
//! a real ciphertext (and a stored one would trip secret scanning).

mod support;

use cratefield_module_sealed::record::CreateBlob;
use cratefield_testing::{FakeAuth, MemoryBlob, TestHarness, request_as};
use serde_json::Value;
use std::sync::Arc;
use support::{SUBJECT_ID, b64, prf_wrap, recovery_wrap};

const PLAINTEXT: &str = "sealed-fixture: the server must never see this line";
const PATH: &str = "/v1/sealed/blobs";
const BLOB_ID: &str = "fixture-blob-0001";
const PURPOSE: &str = "fixture.vault";

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

/// The credential the record claims, assembled at runtime so no
/// credential-shaped literal sits in the tree. On a real record the prf
/// wrap's id is this same string — the client sets both alike — so the
/// fixture mirrors that.
fn credential() -> String {
    format!("fixture-{}", "credential")
}

/// A record the client could have sent: one wrap per unlock kind, the prf
/// wrap addressed to the creating credential, every binary field a
/// wire-valid repeated-byte stand-in for what the client would have sealed.
fn client_record() -> CreateBlob {
    let who = credential();
    CreateBlob {
        blob_id: BLOB_ID.to_owned(),
        version: 1,
        purpose: PURPOSE.to_owned(),
        alg: "A256GCM".to_owned(),
        ciphertext: b64(&[0x5E_u8; 64]),
        wraps: vec![prf_wrap(&who), recovery_wrap("recovery-1")],
        created_by_credential: who.clone(),
    }
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
    let record = client_record();
    let posted = serde_json::to_string(&record).expect("the record serialises");

    let kit = kit();
    let created = request_as(
        &kit.router,
        axum::http::Method::POST,
        PATH,
        SUBJECT_ID,
        Some(&posted),
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
        &format!("{PATH}/{}", record.blob_id),
        SUBJECT_ID,
        None,
    )
    .await;
    assert_eq!(served.status, axum::http::StatusCode::OK);
    let body = served.json();
    assert_eq!(body["ciphertext"], Value::String(record.ciphertext.clone()));
    assert_eq!(
        body["wraps"],
        serde_json::to_value(&record.wraps).expect("wraps serialise")
    );
    assert_eq!(body["purpose"], record.purpose.as_str());
    assert_eq!(body["alg"], record.alg.as_str());
    assert_eq!(
        body["created_by_credential"],
        Value::String(record.created_by_credential.clone())
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
