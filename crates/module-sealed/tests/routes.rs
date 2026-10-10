//! The sealed store through its router, across dialects: the wire round
//! trip, the wrap edit, rotation, the blob-store threshold, rate limiting,
//! the audit chain, the unlock notice, and the two properties the module
//! exists for — the server cannot decrypt what it holds, and erasure
//! crypto-shreds.

mod support;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit};
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use cratefield_core::{Blob as _, Database, DbError, Decision, Rows, Statement};
use cratefield_kms::Kms as _;
use cratefield_module_sealed::audit;
use cratefield_module_sealed::notify::RecordingNotifier;
use cratefield_module_sealed::store;
use cratefield_module_sealed::store::INLINE_BODY_MAX_BYTES;
use cratefield_module_sealed::{NoopNotifier, Sealed};
use cratefield_testing::{
    Dialect, FakeAuth, FakeRateLimiter, MemoryBlob, TestHarness, TestResponse, request, request_as,
};
use sea_query::Value as SeaValue;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use support::{CreateBlob, FakeKms, FixedAuth, b64, fill, nonce, record};

const SUBJECT: &str = "user-alice";
const OTHER: &str = "user-mallory";
const PATH: &str = "/v1/sealed";

/// A kit per available dialect: the module with its fake KMS, the shared
/// recorder for the notice assertions, and the ports the routes need. The
/// blob-store handle comes back too, so tests can check what the store
/// itself holds.
struct Kit {
    harness: TestHarness,
    notifier: RecordingNotifier,
    blob_store: Arc<MemoryBlob>,
}

fn kits_with(make_auth: impl Fn() -> Arc<dyn cratefield_core::Auth>) -> Vec<Kit> {
    Dialect::available()
        .into_iter()
        .map(|dialect| {
            let notifier = RecordingNotifier::new();
            let blob_store = Arc::new(MemoryBlob::new());
            let auth = make_auth();
            let harness = TestHarness::with_database_and_ports(
                vec![Box::new(Sealed::new(
                    Arc::new(FakeKms::new()),
                    Arc::new(notifier.clone()),
                ))],
                dialect,
                |ports| {
                    ports.auth = Some(auth);
                    ports.blob = Some(Arc::clone(&blob_store) as Arc<dyn cratefield_core::Blob>);
                },
            );
            Kit {
                harness,
                notifier,
                blob_store,
            }
        })
        .collect()
}

fn kits() -> Vec<Kit> {
    kits_with(|| Arc::new(FakeAuth::subjects()))
}

/// A kit whose verifier carries a verified address, for the notice test.
fn kits_with_email() -> Vec<Kit> {
    kits_with(|| Arc::new(FixedAuth::with_email("alice@example.test")))
}

async fn post_blob(kit: &TestHarness, subject: &str, blob: &CreateBlob) -> TestResponse {
    request_as(
        &kit.router,
        Method::POST,
        &format!("{PATH}/blobs"),
        subject,
        Some(&serde_json::to_string(blob).expect("record serialises")),
    )
    .await
}

/// Creates one stored blob, asserting the `201`.
async fn seeded(kit: &TestHarness, blob_id: &str) -> CreateBlob {
    let blob = record(blob_id, 1, "vault");
    let response = post_blob(kit, SUBJECT, &blob).await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "{:?}",
        response.body()
    );
    blob
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

/// The inline outer ciphertext of a small stored blob.
async fn outer_ct_of(kit: &TestHarness, blob_id: &str) -> Vec<u8> {
    kit.db
        .query(&Statement::with_values(
            "SELECT outer_ct FROM sealed_blobs WHERE blob_id = ?",
            vec![SeaValue::String(Some(Box::new(blob_id.to_owned())))],
        ))
        .await
        .expect("row")
        .first()
        .and_then(|row| row.get::<Vec<u8>>("outer_ct"))
        .expect("the body is inline at this size")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The client-side half the no-decryption test simulates: what
/// `@cratefield/sealed` produces before it ever calls the server. The
/// content key `ck` never leaves the test.
fn client_seal(ck: &[u8; 32], subject: &str, blob: &CreateBlob, plaintext: &[u8]) -> String {
    let cipher = Aes256Gcm::new_from_slice(ck).expect("the content key is 32 bytes");
    let mut nonce_bytes = vec![0_u8; 12];
    fill(&mut nonce_bytes);
    let mut body = plaintext.to_vec();
    let aad = format!(
        "{subject}|{}|{}|{}",
        blob.blob_id, blob.version, blob.purpose
    );
    cipher
        .encrypt_in_place(&nonce(&nonce_bytes), aad.as_bytes(), &mut body)
        .expect("the client seal answers");
    let mut out = nonce_bytes;
    out.extend_from_slice(&body);
    b64(&out)
}

/// The server's own outer layer, opened by hand: the most the whole of the
/// server's state can answer with, given its DEKs.
fn outer_open(dek: &[u8], sealed: &[u8], subject: &str, blob_id: &str, version: u32) -> Vec<u8> {
    outer_open_result(dek, sealed, subject, blob_id, version)
        .expect("the outer layer opens with its own DEK and row binding")
}

/// The same, answering `None` instead of panicking.
fn outer_open_result(
    dek: &[u8],
    sealed: &[u8],
    subject: &str,
    blob_id: &str,
    version: u32,
) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(dek).ok()?;
    let aad = format!("cratefield-sealed-outer-v1|{subject}|{blob_id}|{version}");
    let mut body = sealed.get(12..)?.to_vec();
    cipher
        .decrypt_in_place(&nonce(&sealed[..12]), aad.as_bytes(), &mut body)
        .ok()?;
    Some(body)
}

/// A PUT carrying (or deliberately omitting) an `If-Match` header, which the
/// kit's request helpers cannot set. Answers the status, the headers and the
/// JSON body.
async fn put_if_match(
    kit: &TestHarness,
    path: &str,
    subject: &str,
    body: &str,
    if_match: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    use tower::ServiceExt as _;
    let mut builder = Request::builder()
        .method(Method::PUT)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {subject}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(etag) = if_match {
        builder = builder.header(header::IF_MATCH, etag);
    }
    let response = kit
        .router
        .clone()
        .oneshot(
            builder
                .body(axum::body::Body::from(body.to_owned()))
                .expect("request builds"),
        )
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("test body reads");
    let json = serde_json::from_slice(&bytes).expect("body is JSON");
    (parts.status, parts.headers, json)
}

/// The `ETag` a record response carried: the revision the next guarded
/// write must echo back.
fn etag(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::ETAG)
        .expect("record responses carry an ETag")
        .to_str()
        .expect("an ASCII ETag")
        .to_owned()
}

fn etag_of(response: &TestResponse) -> String {
    etag(&response.headers)
}

#[pollster::test]
async fn a_record_round_trips_byte_identically() {
    for kit in &kits() {
        let blob = seeded(&kit.harness, "round-trip-1").await;

        let read = request_as(
            &kit.harness.router,
            Method::GET,
            &format!("{PATH}/blobs/round-trip-1"),
            SUBJECT,
            None,
        )
        .await;
        assert_eq!(read.status, StatusCode::OK);
        let served = read.json();

        // The payload and every wrap come back exactly as they went in.
        assert_eq!(served["ciphertext"], Value::String(blob.ciphertext.clone()));
        assert_eq!(
            served["wraps"],
            serde_json::to_value(&blob.wraps).expect("wraps serialise")
        );
        assert_eq!(served["blob_id"], "round-trip-1");
        assert_eq!(served["version"], 1);
        assert_eq!(served["purpose"], "vault");
        assert_eq!(served["alg"], "A256GCM");
        assert_eq!(served["created_by_credential"], "test-credential-1");
        assert_eq!(served["subject"], SUBJECT);
        assert!(served["created_at"].is_string());

        // The list endpoint carries metadata, never a body.
        let list = request_as(
            &kit.harness.router,
            Method::GET,
            &format!("{PATH}/blobs"),
            SUBJECT,
            None,
        )
        .await;
        assert_eq!(list.status, StatusCode::OK);
        let entry = &list.json()["blobs"][0];
        assert_eq!(entry["blob_id"], "round-trip-1");
        assert!(entry.get("ciphertext").is_none());
        assert!(entry.get("wraps").is_none());
    }
}

#[pollster::test]
async fn fewer_than_two_wraps_is_refused() {
    for kit in &kits() {
        let mut blob = record("under-wrapped", 1, "vault");
        blob.wraps.remove(1);
        let response = post_blob(&kit.harness, SUBJECT, &blob).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(
            response.json()["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("2 wraps")),
            "{:?}",
            response.body()
        );
        // Nothing was written.
        assert_eq!(count(&kit.harness, "sealed_blobs").await, 0);
        assert_eq!(count(&kit.harness, "sealed_deks").await, 0);
    }
}

#[pollster::test]
async fn a_wrap_edit_never_touches_the_payload() {
    for kit in &kits() {
        seeded(&kit.harness, "wrap-edit-1").await;
        let path = format!("{PATH}/blobs/wrap-edit-1");
        let read = request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await;
        let original_etag = etag_of(&read);
        let original = read.json();

        // Swap the wrap set for a differently-keyed one — the first of two
        // writers who read the same ETag.
        let wraps = vec![
            support::prf_wrap("passkey-2"),
            support::recovery_wrap("recovery-2"),
        ];
        let edit = json!({ "version": 1, "wraps": wraps });
        let (status, headers, served) = put_if_match(
            &kit.harness,
            &format!("{path}/wraps"),
            SUBJECT,
            &edit.to_string(),
            Some(&original_etag),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{served}");
        assert_eq!(served["ciphertext"], original["ciphertext"]);
        assert_eq!(
            served["version"], 1,
            "a wrap edit does not bump the version"
        );
        assert_eq!(served["wraps"][0]["id"], "passkey-2");
        let fresh_etag = etag(&headers);
        assert_ne!(
            fresh_etag, original_etag,
            "the edit moved the server-side revision"
        );

        // The second writer still holds the first ETag: 412, and the wrap it
        // would have installed stays uninstalled — the first edit's removal
        // sticks.
        let rival = json!({ "version": 1, "wraps": vec![
            support::prf_wrap("passkey-3"),
            support::recovery_wrap("recovery-3"),
        ]});
        let (rival_status, _, _) = put_if_match(
            &kit.harness,
            &format!("{path}/wraps"),
            SUBJECT,
            &rival.to_string(),
            Some(&original_etag),
        )
        .await;
        assert_eq!(rival_status, StatusCode::PRECONDITION_FAILED);

        // And so is a wrap set below the floor, judged before the guard.
        let mut thin = wraps.clone();
        thin.pop();
        let (under_status, _, _) = put_if_match(
            &kit.harness,
            &format!("{path}/wraps"),
            SUBJECT,
            &json!({ "version": 1, "wraps": thin }).to_string(),
            Some(&fresh_etag),
        )
        .await;
        assert_eq!(under_status, StatusCode::BAD_REQUEST);
        let served = request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None)
            .await
            .json();
        assert_eq!(served["ciphertext"], original["ciphertext"]);
        assert_eq!(
            served["wraps"][0]["id"], "passkey-2",
            "the lost writer's wrap never landed"
        );
    }
}

#[pollster::test]
async fn a_rotation_bumps_the_version_under_a_fresh_key() {
    for kit in &kits() {
        seeded(&kit.harness, "rotate-1").await;
        let path = format!("{PATH}/blobs/rotate-1");
        let original_etag =
            etag_of(&request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await);

        let mut next = record("rotate-1", 2, "vault");
        next.wraps = vec![
            support::prf_wrap("passkey-3"),
            support::recovery_wrap("recovery-3"),
        ];
        let (status, _, served) = put_if_match(
            &kit.harness,
            &path,
            SUBJECT,
            &serde_json::to_string(&next).expect("record serialises"),
            Some(&original_etag),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{served}");
        assert_eq!(served["version"], 2);
        assert_eq!(served["ciphertext"], Value::String(next.ciphertext.clone()));
        assert_eq!(served["wraps"][0]["id"], "passkey-3");

        // A write at the old version now conflicts.
        assert_eq!(
            post_blob(&kit.harness, SUBJECT, &record("rotate-1", 1, "vault"))
                .await
                .status,
            StatusCode::CONFLICT
        );

        // A body whose blob_id disagrees with the path is refused outright —
        // before the guard, so a misaddressed rotation is a 400 even
        // headerless.
        let mut elsewhere = record("rotate-1", 3, "vault");
        elsewhere.blob_id = "rotate-2".to_owned();
        assert_eq!(
            request_as(
                &kit.harness.router,
                Method::PUT,
                &path,
                SUBJECT,
                Some(&serde_json::to_string(&elsewhere).expect("record serialises")),
            )
            .await
            .status,
            StatusCode::BAD_REQUEST
        );
    }
}

#[pollster::test]
async fn a_guarded_write_carries_the_record_etag() {
    for kit in &kits() {
        seeded(&kit.harness, "guarded-1").await;
        let path = format!("{PATH}/blobs/guarded-1");
        let wraps = vec![
            support::prf_wrap("passkey-4"),
            support::recovery_wrap("recovery-4"),
        ];
        let edit = json!({ "version": 1, "wraps": wraps });
        let rotation =
            serde_json::to_string(&record("guarded-1", 2, "vault")).expect("record serialises");

        // No `If-Match` at all: 428, on both guarded routes, nothing written.
        let (status, _, _) = put_if_match(
            &kit.harness,
            &format!("{path}/wraps"),
            SUBJECT,
            &edit.to_string(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
        let (status, _, _) = put_if_match(&kit.harness, &path, SUBJECT, &rotation, None).await;
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
        assert_eq!(count(&kit.harness, "sealed_blobs").await, 1);

        // A revision that was never the row's: 412, not a silent overwrite.
        let (status, _, _) =
            put_if_match(&kit.harness, &path, SUBJECT, &rotation, Some("\"999\"")).await;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);

        // `*` ("any state will do") and garbage are refused outright.
        let (status, _, _) = put_if_match(
            &kit.harness,
            &format!("{path}/wraps"),
            SUBJECT,
            &edit.to_string(),
            Some("*"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = put_if_match(
            &kit.harness,
            &format!("{path}/wraps"),
            SUBJECT,
            &edit.to_string(),
            Some("\"soon\""),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // And with the ETag a read handed out, the write lands.
        let current = request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await;
        let (status, _, served) = put_if_match(
            &kit.harness,
            &format!("{path}/wraps"),
            SUBJECT,
            &edit.to_string(),
            Some(&etag_of(&current)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{served}");
        assert_eq!(served["wraps"][0]["id"], "passkey-4");
    }
}

#[pollster::test]
async fn a_rotated_large_record_still_reads() {
    for kit in &kits() {
        // A body over the inline threshold: the record's life now runs
        // through blob-store object keys, where a rotation that parks the
        // new body onto the live key and then frees "the old" one bricks
        // the record instead.
        let mut payload = vec![0_u8; INLINE_BODY_MAX_BYTES + 512];
        fill(&mut payload);
        let first = CreateBlob {
            ciphertext: b64(&payload),
            ..record("large-rot-1", 1, "vault")
        };
        let created = post_blob(&kit.harness, SUBJECT, &first).await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body());
        assert_eq!(kit.blob_store.len(), 1);

        let path = format!("{PATH}/blobs/large-rot-1");
        let original_etag =
            etag_of(&request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await);

        let mut next_payload = vec![0_u8; INLINE_BODY_MAX_BYTES + 1024];
        fill(&mut next_payload);
        let next = CreateBlob {
            ciphertext: b64(&next_payload),
            ..record("large-rot-1", 2, "vault")
        };
        let (status, _, served) = put_if_match(
            &kit.harness,
            &path,
            SUBJECT,
            &serde_json::to_string(&next).expect("record serialises"),
            Some(&original_etag),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{served}");

        // Exactly one live object remains — the new key; the old body's key
        // was freed only after the commit named the new one.
        assert_eq!(kit.blob_store.len(), 1, "one live body, not zero, not two");

        // And the record reads back: the new ciphertext, under the new DEK.
        let read = request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await;
        assert_eq!(read.status, StatusCode::OK, "{:?}", read.body());
        let served = read.json();
        assert_eq!(served["version"], 2);
        assert_eq!(served["ciphertext"], Value::String(next.ciphertext.clone()));
    }
}

#[pollster::test]
async fn a_refused_create_never_touches_the_live_body() {
    for kit in &kits() {
        let mut payload = vec![0_u8; INLINE_BODY_MAX_BYTES + 512];
        fill(&mut payload);
        let blob = CreateBlob {
            ciphertext: b64(&payload),
            ..record("retry-1", 1, "vault")
        };
        let created = post_blob(&kit.harness, SUBJECT, &blob).await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body());
        let path = format!("{PATH}/blobs/retry-1");
        let original = request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await;
        assert_eq!(original.status, StatusCode::OK);

        // A retried create with the same blob_id is refused — and the
        // refusal must not unpark the body the live record shares this
        // route's key space with.
        assert_eq!(
            post_blob(&kit.harness, SUBJECT, &blob).await.status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            kit.blob_store.len(),
            1,
            "the refused create left exactly the live body's object"
        );
        let after = request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await;
        assert_eq!(after.status, StatusCode::OK, "{:?}", after.body());
        assert_eq!(after.json()["ciphertext"], original.json()["ciphertext"]);
    }
}

#[pollster::test]
async fn two_rotations_from_one_etag_leave_one_consistent_record() {
    for kit in &kits() {
        seeded(&kit.harness, "race-1").await;
        let path = format!("{PATH}/blobs/race-1");
        let shared_etag =
            etag_of(&request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await);

        // Two rotations, both built on the same view of the record.
        let mut winner = record("race-1", 2, "vault");
        winner.ciphertext = client_seal(&[3_u8; 32], SUBJECT, &winner, b"winner body");
        let mut loser = record("race-1", 2, "vault");
        loser.ciphertext = client_seal(&[4_u8; 32], SUBJECT, &loser, b"loser body");

        let (first, _, served) = put_if_match(
            &kit.harness,
            &path,
            SUBJECT,
            &serde_json::to_string(&winner).expect("record serialises"),
            Some(&shared_etag),
        )
        .await;
        assert_eq!(first, StatusCode::OK, "{served}");
        let (second, _, _) = put_if_match(
            &kit.harness,
            &path,
            SUBJECT,
            &serde_json::to_string(&loser).expect("record serialises"),
            Some(&shared_etag),
        )
        .await;
        assert_eq!(second, StatusCode::PRECONDITION_FAILED);

        // The record opens with the winner's body, its DEK matching its
        // ciphertext: the loser's body and the winner's key never meet.
        let read = request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await;
        assert_eq!(read.status, StatusCode::OK, "{:?}", read.body());
        assert_eq!(
            read.json()["ciphertext"],
            Value::String(winner.ciphertext.clone())
        );
        let dek = FakeKms::new()
            .unwrap(&wrapped_dek_of(&kit.harness, "race-1").await)
            .await
            .expect("the winner's DEK unwraps");
        let recovered = outer_open(
            dek.expose(),
            &outer_ct_of(&kit.harness, "race-1").await,
            SUBJECT,
            "race-1",
            2,
        );
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&winner.ciphertext)
            .expect("the winner's ciphertext decodes");
        assert_eq!(recovered, expected, "the stored body opens under its DEK");

        // The same, one layer down and past the handler's pre-checks: the
        // store itself refuses a rotation whose revision no longer matches,
        // and the loser's parked body is all it leaves behind.
        let loser_body = store::decode_body(&loser).expect("the loser's body decodes");
        let sealed = store::seal_body(&FakeKms::new(), &loser_body, SUBJECT, "race-1", 2)
            .await
            .expect("the loser seals");
        let err = store::rotate(
            kit.harness.db.as_ref(),
            SUBJECT,
            &loser,
            &sealed,
            "2026-01-01T00:00:00Z",
            1, // the stale revision — the winner already moved past it
            Some(kit.blob_store.as_ref() as &dyn cratefield_core::Blob),
        )
        .await
        .expect_err("the stale rotation loses");
        assert!(
            matches!(err, store::StoreError::Stale),
            "the store refuses the loser: {err}"
        );
        let read = request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await;
        assert_eq!(
            read.json()["ciphertext"],
            Value::String(winner.ciphertext.clone())
        );
    }
}

#[pollster::test]
async fn a_create_that_already_exists_is_a_conflict() {
    for kit in &kits() {
        seeded(&kit.harness, "dupe-1").await;
        assert_eq!(
            post_blob(&kit.harness, SUBJECT, &record("dupe-1", 1, "vault"))
                .await
                .status,
            StatusCode::CONFLICT
        );
    }
}

#[pollster::test]
async fn a_large_body_lands_in_the_blob_store() {
    for kit in &kits() {
        // Just over the inline threshold, so the outer body has to move.
        let mut payload = vec![0_u8; INLINE_BODY_MAX_BYTES + 512];
        fill(&mut payload);
        let blob = CreateBlob {
            ciphertext: b64(&payload),
            ..record("large-1", 1, "vault")
        };
        let response = post_blob(&kit.harness, SUBJECT, &blob).await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{:?}",
            response.body()
        );

        // The row carries no inline body: the store object does.
        assert_eq!(kit.blob_store.len(), 1);
        let inline = kit
            .harness
            .db
            .query(&Statement::new(
                "SELECT outer_ct, object_key FROM sealed_blobs WHERE blob_id = 'large-1'",
            ))
            .await
            .expect("row");
        let row = inline.first().expect("the row exists");
        assert!(
            row.get::<Vec<u8>>("outer_ct").is_none(),
            "a large body must not live inline in the row"
        );
        let key = row.get::<String>("object_key").expect("the object key");
        // Module-relative; the harness scopes it under `sealed/`.
        assert!(key.starts_with("blobs/"), "{key}");
        assert!(!key.contains("sealed/"), "{key}");

        // And it round trips.
        let served = request_as(
            &kit.harness.router,
            Method::GET,
            &format!("{PATH}/blobs/large-1"),
            SUBJECT,
            None,
        )
        .await
        .json();
        assert_eq!(served["ciphertext"], Value::String(blob.ciphertext.clone()));
    }
}

#[pollster::test]
async fn a_read_can_be_rate_limited() {
    for dialect in Dialect::available() {
        let denial = Decision {
            ok: false,
            retry_after: Some(Duration::from_secs(30)),
            quota: None,
        };
        let allowed = Decision {
            ok: true,
            retry_after: None,
            quota: None,
        };
        let harness = TestHarness::with_database_and_ports(
            vec![Box::new(Sealed::new(
                Arc::new(FakeKms::new()),
                Arc::new(NoopNotifier),
            ))],
            dialect,
            |ports| {
                ports.auth = Some(Arc::new(FakeAuth::subjects()));
                ports.blob = Some(Arc::new(MemoryBlob::new()));
                ports.rate_limiter =
                    Some(Arc::new(FakeRateLimiter::scripted(vec![denial], allowed)));
            },
        );
        let blob = record("limited-1", 1, "vault");
        let created = post_blob(&harness, SUBJECT, &blob).await;
        assert_eq!(created.status, StatusCode::CREATED);

        // The first read hits the scripted denial.
        let denied = request_as(
            &harness.router,
            Method::GET,
            &format!("{PATH}/blobs/limited-1"),
            SUBJECT,
            None,
        )
        .await;
        assert_eq!(denied.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            denied
                .headers
                .get("retry-after")
                .is_some_and(|value| value == "30"),
            "the 429 carries the limiter's pause: {:?}",
            denied.headers
        );

        // The next read passes: the denial was a quota answer, not an outage.
        let second = request_as(
            &harness.router,
            Method::GET,
            &format!("{PATH}/blobs/limited-1"),
            SUBJECT,
            None,
        )
        .await;
        assert_eq!(second.status, StatusCode::OK);
    }
}

#[pollster::test]
async fn every_action_is_audited_and_the_chain_detects_tampering() {
    for kit in &kits() {
        seeded(&kit.harness, "audited-1").await;
        // A read and a wrap edit, so three action kinds have rows.
        let path = format!("{PATH}/blobs/audited-1");
        let read = request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await;
        let wraps = vec![
            support::prf_wrap("passkey-9"),
            support::recovery_wrap("recovery-9"),
        ];
        let (_, _, served) = put_if_match(
            &kit.harness,
            &format!("{path}/wraps"),
            SUBJECT,
            &json!({ "version": 1, "wraps": wraps }).to_string(),
            Some(&etag_of(&read)),
        )
        .await;
        assert_eq!(served["wraps"][0]["id"], "passkey-9");
        let anchor = audit::verify(kit.harness.db.as_ref())
            .await
            .expect("the chain verifies after honest writes");
        assert_eq!(anchor.seq, 3, "create, read, wrap edit");

        // The append-only triggers refuse to rewrite history.
        let rewrite = kit
            .harness
            .db
            .execute(&Statement::new(
                "UPDATE sealed_audit SET action = 'read' WHERE seq = 1",
            ))
            .await;
        assert!(rewrite.is_err(), "sealed_audit refuses UPDATE");
        let remove = kit
            .harness
            .db
            .execute(&Statement::new("DELETE FROM sealed_audit WHERE seq = 1"))
            .await;
        assert!(remove.is_err(), "sealed_audit refuses DELETE");

        // A forged row — right prev_hash, invented hash — names itself when
        // the chain is next walked.
        let tail = kit
            .harness
            .db
            .query(&Statement::new(
                "SELECT seq, prev_hash FROM sealed_audit ORDER BY seq DESC LIMIT 1",
            ))
            .await
            .expect("tail");
        let (seq, prev_hash) = tail
            .first()
            .map(|row| {
                (
                    row.get::<i64>("seq").expect("seq"),
                    row.get::<Vec<u8>>("prev_hash").expect("prev_hash"),
                )
            })
            .expect("a tail row");
        kit.harness
            .db
            .execute(&Statement::with_values(
                "INSERT INTO sealed_audit (seq, ts, subject, action, blob_id, version, \
                 prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    SeaValue::BigInt(Some(seq + 1)),
                    SeaValue::String(Some(Box::new("2026-01-01T00:00:00Z".to_owned()))),
                    SeaValue::String(Some(Box::new(SUBJECT.to_owned()))),
                    SeaValue::String(Some(Box::new("read".to_owned()))),
                    SeaValue::String(Some(Box::new("audited-1".to_owned()))),
                    SeaValue::BigInt(Some(1)),
                    SeaValue::Bytes(Some(Box::new(prev_hash))),
                    SeaValue::Bytes(Some(Box::new(vec![0_u8; 32]))),
                ],
            ))
            .await
            .expect("the forged row lands (the triggers only refuse rewrites)");
        let message = audit::verify(kit.harness.db.as_ref())
            .await
            .expect_err("a forged row breaks the chain")
            .to_string();
        assert!(
            message.contains(&format!("row {}", seq + 1)),
            "the walk names the first broken link: {message}"
        );
    }
}

#[pollster::test]
async fn the_server_cannot_decrypt_what_it_holds() {
    for kit in &kits() {
        const PLAINTEXT: &[u8] = b"sealed-fixture: the server must never see this line";

        // A client-style record: the payload is a real client encryption of
        // PLAINTEXT under a content key that stays in the test.
        let ck = [7_u8; 32];
        let mut blob = record("sealed-1", 1, "vault");
        blob.ciphertext = client_seal(&ck, SUBJECT, &blob, PLAINTEXT);
        let created = post_blob(&kit.harness, SUBJECT, &blob).await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body());

        // Dump every byte the server holds: the three tables' columns and
        // the blob-store object, when the body went to one.
        let mut bytes_server_holds: Vec<Vec<u8>> = Vec::new();
        for table in ["sealed_blobs", "sealed_deks", "sealed_audit"] {
            let rows = kit
                .harness
                .db
                .query(&Statement::new(format!("SELECT * FROM {table}")))
                .await
                .expect("table scan");
            for row in &rows.rows {
                for column in [
                    "outer_ct",
                    "wrapped_dek",
                    "prev_hash",
                    "hash",
                    "wraps",
                    "subject",
                    "blob_id",
                    "purpose",
                    "alg",
                    "created_by_credential",
                    "ts",
                    "action",
                    "object_key",
                    "kms_provider",
                    "kms_key_ref",
                    "created_at",
                    "updated_at",
                ] {
                    if let Some(text) = row.get::<String>(column) {
                        bytes_server_holds.push(text.into_bytes());
                    }
                    if let Some(bytes) = row.get::<Vec<u8>>(column) {
                        bytes_server_holds.push(bytes);
                    }
                }
            }
        }
        let object_key = kit
            .harness
            .db
            .query(&Statement::new(
                "SELECT object_key FROM sealed_blobs WHERE blob_id = 'sealed-1'",
            ))
            .await
            .expect("row")
            .first()
            .and_then(|row| row.get::<String>("object_key"));
        if let Some(key) = object_key {
            let object = kit
                .blob_store
                .get(&key)
                .await
                .expect("the store answers")
                .expect("the object exists");
            bytes_server_holds.push(object.bytes);
        }

        // The strongest arm: unwrap the DEK (the test holds the KMS master)
        // and open the outer layer. What comes out is the client ciphertext
        // — and nothing more, because no key that opens the client layer
        // exists on the server.
        let dek = FakeKms::new()
            .unwrap(&wrapped_dek_of(&kit.harness, "sealed-1").await)
            .await
            .expect("the KMS opens its own wrap");
        let recovered = outer_open(
            dek.expose(),
            &outer_ct_of(&kit.harness, "sealed-1").await,
            SUBJECT,
            "sealed-1",
            1,
        );
        assert_eq!(
            recovered,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&blob.ciphertext)
                .expect("the stored ciphertext decodes"),
            "the best the server's state can recover is the client ciphertext"
        );
        bytes_server_holds.push(recovered);

        // And the plaintext appears nowhere in any of it — not raw, not
        // base64url.
        let encoded = b64(PLAINTEXT);
        for held in &bytes_server_holds {
            assert!(
                !contains(held, PLAINTEXT),
                "the server's bytes contain the plaintext: {}",
                String::from_utf8_lossy(held)
            );
            assert!(
                !contains(held, encoded.as_bytes()),
                "the server's bytes contain the base64 of the plaintext"
            );
        }
    }
}

async fn wrapped_dek_of(kit: &TestHarness, blob_id: &str) -> Vec<u8> {
    kit.db
        .query(&Statement::with_values(
            "SELECT wrapped_dek FROM sealed_deks WHERE blob_id = ?",
            vec![SeaValue::String(Some(Box::new(blob_id.to_owned())))],
        ))
        .await
        .expect("dek row")
        .first()
        .and_then(|row| row.get::<Vec<u8>>("wrapped_dek"))
        .expect("the DEK row exists")
}

#[pollster::test]
async fn erasure_crypto_shreds() {
    for kit in &kits() {
        let mut blob = record("shred-1", 1, "vault");
        blob.ciphertext = client_seal(&[9_u8; 32], SUBJECT, &blob, b"shred me");
        let created = post_blob(&kit.harness, SUBJECT, &blob).await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body());

        // The snapshot: the outer ciphertext exactly as the server held it.
        let snapshot = outer_ct_of(&kit.harness, "shred-1").await;

        let erased = request_as(
            &kit.harness.router,
            Method::DELETE,
            &format!("{PATH}/blobs/shred-1"),
            SUBJECT,
            None,
        )
        .await;
        assert_eq!(erased.status, StatusCode::OK, "{:?}", erased.body());

        // The key row and the body row are gone; the audit row (declared
        // Retain) stays.
        assert_eq!(count(&kit.harness, "sealed_deks").await, 0);
        assert_eq!(count(&kit.harness, "sealed_blobs").await, 0);
        assert!(count(&kit.harness, "sealed_audit").await > 0);
        assert_eq!(
            request_as(
                &kit.harness.router,
                Method::GET,
                &format!("{PATH}/blobs/shred-1"),
                SUBJECT,
                None,
            )
            .await
            .status,
            StatusCode::NOT_FOUND
        );

        // Nothing that remains can open the snapshot: every DEK still in
        // the database fails against it, and so does a fresh one. The only
        // key that ever did is not in any state the server keeps.
        let leftovers = kit
            .harness
            .db
            .query(&Statement::new("SELECT wrapped_dek FROM sealed_deks"))
            .await
            .expect("leftovers");
        for row in &leftovers.rows {
            if let Some(wrapped) = row.get::<Vec<u8>>("wrapped_dek")
                && let Ok(dek) = FakeKms::new().unwrap(&wrapped).await
            {
                assert!(
                    outer_open_result(dek.expose(), &snapshot, SUBJECT, "shred-1", 1).is_none(),
                    "a remaining key opened an erased body"
                );
            }
        }
        let fresh = cratefield_kms::Dek::generate().expect("the OS RNG answers");
        assert!(
            outer_open_result(fresh.expose(), &snapshot, SUBJECT, "shred-1", 1).is_none(),
            "a fresh key opened an erased body"
        );
    }
}

#[pollster::test]
async fn a_download_notifies_the_verified_address() {
    for kit in &kits_with_email() {
        seeded(&kit.harness, "noticed-1").await;
        let path = format!("{PATH}/blobs/noticed-1");
        request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await;
        let notices = kit.notifier.recorded();
        assert_eq!(notices.len(), 1, "one download, one notice: {notices:?}");
        assert_eq!(notices[0].subject, SUBJECT);
        assert_eq!(notices[0].email, "alice@example.test");
        assert_eq!(notices[0].blob_id, "noticed-1");
        assert_eq!(notices[0].purpose, "vault");

        // A second download is a second notice.
        request_as(&kit.harness.router, Method::GET, &path, SUBJECT, None).await;
        assert_eq!(kit.notifier.recorded().len(), 2);
    }
}

#[pollster::test]
async fn without_a_verified_address_there_is_no_notice() {
    for kit in &kits() {
        seeded(&kit.harness, "quiet-1").await;
        request_as(
            &kit.harness.router,
            Method::GET,
            &format!("{PATH}/blobs/quiet-1"),
            SUBJECT,
            None,
        )
        .await;
        assert!(kit.notifier.recorded().is_empty());
    }
}

#[pollster::test]
async fn a_blob_is_invisible_to_anyone_who_is_not_its_subject() {
    for kit in &kits() {
        seeded(&kit.harness, "private-1").await;

        // No credential at all: 401.
        assert_eq!(
            request(
                &kit.harness.router,
                Method::GET,
                &format!("{PATH}/blobs/private-1"),
                None,
            )
            .await
            .status,
            StatusCode::UNAUTHORIZED
        );
        // Another subject: the same 404 an unknown id gets.
        assert_eq!(
            request_as(
                &kit.harness.router,
                Method::GET,
                &format!("{PATH}/blobs/private-1"),
                OTHER,
                None,
            )
            .await
            .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            request_as(
                &kit.harness.router,
                Method::DELETE,
                &format!("{PATH}/blobs/private-1"),
                OTHER,
                None,
            )
            .await
            .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(count(&kit.harness, "sealed_blobs").await, 1);
    }
}

/// A `Database` that, on its first audit INSERT, makes the race the append
/// must survive real: a competing writer claims the next `seq` before the
/// caller's insert commits, so that insert collides on the primary key and
/// can only win by re-reading the head and retrying.
struct SeqRacer {
    inner: Arc<dyn Database>,
    raced: AtomicBool,
}

#[async_trait::async_trait]
impl Database for SeqRacer {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        if !self.raced.swap(true, Ordering::SeqCst)
            && stmt.sql.starts_with("INSERT INTO sealed_audit")
        {
            audit::append(
                self.inner.as_ref(),
                "2026-01-01T00:00:00Z",
                &audit::Event {
                    subject: SUBJECT,
                    action: audit::Action::Create,
                    blob_id: "the-race-winner",
                    version: 1,
                },
            )
            .await
            .expect("the competing append commits");
        }
        self.inner.execute(stmt).await
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        self.inner.query(stmt).await
    }

    async fn batch_atomic(&self, stmts: &[Statement]) -> Result<(), DbError> {
        self.inner.batch_atomic(stmts).await
    }
}

#[pollster::test]
async fn an_audit_append_that_loses_the_seq_race_retries_on_the_new_head() {
    for kit in &kits() {
        seeded(&kit.harness, "seq-race-1").await;
        let before = count(&kit.harness, "sealed_audit").await;

        // This append reads the head, is overtaken by the competing writer,
        // collides on `seq` — and retries onto the new head instead of
        // failing a mutation that already committed.
        let racer = SeqRacer {
            inner: Arc::clone(&kit.harness.db),
            raced: AtomicBool::new(false),
        };
        audit::append(
            &racer,
            "2026-01-01T00:00:00Z",
            &audit::Event {
                subject: SUBJECT,
                action: audit::Action::Read,
                blob_id: "seq-race-1",
                version: 1,
            },
        )
        .await
        .expect("the loser retries and lands");

        // Both rows are on the chain, in order, and the hash chain still
        // verifies across the retry — a collision produced a retry, never a
        // gap or a fork.
        assert_eq!(count(&kit.harness, "sealed_audit").await, before + 2);
        let anchor = audit::verify(kit.harness.db.as_ref())
            .await
            .expect("the chain verifies across the retried append");
        assert_eq!(anchor.seq, before + 2);
    }
}
