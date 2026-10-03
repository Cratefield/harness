//! Issue #650 part B acceptance, HTTP half: the admin user-import routes.
//!
//! A re-run changes nothing; a duplicate address is a conflict, and a merge
//! only with the flag; a hash this crate cannot verify is refused rather
//! than written; a dry run writes nothing; and no response ever carries an
//! email or a hash.

use axum::body::Body;
use axum::http::{Method, StatusCode, header};
use cratefield_core::Statement;
use cratefield_testing::TestHarness;
use factory0_auth_core::AuthCore;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const BASE: &str = "/v1/auth-core";
const IMPORT: &str = "/v1/auth-core/admin/users/import";

fn kit(pairs: Vec<(&str, &str)>) -> TestHarness {
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], move |ports| {
        let mut all = vec![("ADMIN_TOKEN", ADMIN)];
        all.extend(pairs);
        ports.config = Arc::new(cratefield_core::MapConfig::from_pairs(all));
    })
}

async fn post(
    kit: &TestHarness,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> (StatusCode, String) {
    let mut builder = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder
        .body(Body::from(body.to_owned()))
        .expect("request builds");
    read(kit.router.clone().oneshot(request).await.expect("answers")).await
}

async fn get(kit: &TestHarness, path: &str) -> (StatusCode, String) {
    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .body(Body::empty())
        .expect("request builds");
    read(kit.router.clone().oneshot(request).await.expect("answers")).await
}

async fn read(response: axum::response::Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body reads");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn body(dry_run: bool, merge_by_email: bool, users: Vec<Value>) -> String {
    // Built by moving `users` into the document, so the array is consumed
    // rather than borrowed through the json! macro.
    let mut document = json!({
        "dry_run": dry_run,
        "merge_by_email": merge_by_email,
    });
    document["users"] = Value::Array(users);
    document.to_string()
}

fn user(provider: &str, id: &str, email: &str) -> Value {
    json!({
        "external_provider": provider,
        "external_id": id,
        "email": email,
        "email_verified": true,
    })
}

fn user_with_hash(provider: &str, id: &str, email: &str, hash: &str) -> Value {
    let mut value = user(provider, id, email);
    value["password_hash"] = json!(hash);
    value
}

async fn import(kit: &TestHarness, request: &str) -> Value {
    let (status, raw) = post(kit, IMPORT, Some(ADMIN), request).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    serde_json::from_str(&raw).expect("response is JSON")
}

/// The raw response string, for the substring privacy checks.
async fn import_raw(kit: &TestHarness, request: &str) -> (StatusCode, String) {
    post(kit, IMPORT, Some(ADMIN), request).await
}

fn results(doc: &Value) -> &Vec<Value> {
    doc["results"].as_array().expect("results array")
}

async fn rows(kit: &TestHarness, table: &str) -> usize {
    kit.db
        .query(&Statement::new(format!("SELECT id FROM {table}")))
        .await
        .expect("query")
        .rows
        .len()
}

/// A well-formed argon2id PHC string this crate writes.
fn argon_hash() -> String {
    factory0_auth_core::hash_password("a long enough password").expect("hash")
}

/// A deterministic cost-4 bcrypt hash, obviously fake test material.
const BCRYPT_OK: &str = "$2b$04$.OGB/.SE/ueHAeqKBO2NC.Idt9kRB2ygG15erMmtNyb.8scW/Kmw2";
/// The same shape at cost 15 — above `BCRYPT_MAX_COST`; never verified.
const BCRYPT_TOO_EXPENSIVE: &str = "$2b$15$.OGB/.SE/ueHAeqKBO2NC.Idt9kRB2ygG15erMmtNyb.8scW/Kmw2";

#[pollster::test]
async fn re_running_the_same_import_changes_nothing() {
    let kit = kit(vec![]);
    let request = body(
        false,
        false,
        vec![
            user_with_hash("legacy", "1", "ada@example.com", &argon_hash()),
            user_with_hash("legacy", "2", "grace@example.com", &argon_hash()),
        ],
    );

    let first = import(&kit, &request).await;
    assert_eq!(first["dry_run"], json!(false));
    let first_subs: Vec<Option<String>> = results(&first)
        .iter()
        .map(|row| row["sub"].as_str().map(str::to_owned))
        .collect();
    assert!(first_subs.iter().all(Option::is_some), "{first}");
    assert_eq!(
        results(&first)[0]["status"].as_str(),
        Some("created"),
        "{first}"
    );
    let users = rows(&kit, "users").await;
    let identities = rows(&kit, "identities").await;
    let credentials = rows(&kit, "credentials").await;
    assert_eq!((users, identities, credentials), (2, 4, 2));

    let second = import(&kit, &request).await;
    for row in results(&second) {
        assert_eq!(row["status"].as_str(), Some("unchanged"), "{second}");
    }
    let second_subs: Vec<Option<String>> = results(&second)
        .iter()
        .map(|row| row["sub"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(first_subs, second_subs, "the same subs come back");
    assert_eq!(
        (
            rows(&kit, "users").await,
            rows(&kit, "identities").await,
            rows(&kit, "credentials").await
        ),
        (users, identities, credentials),
        "a second run writes nothing"
    );
}

#[pollster::test]
async fn a_duplicate_email_conflicts_and_merges_only_with_the_flag() {
    let kit = kit(vec![]);
    let first = import(
        &kit,
        &body(false, false, vec![user("legacy", "1", "dup@example.com")]),
    )
    .await;
    let sub = results(&first)[0]["sub"].as_str().expect("sub").to_owned();

    let conflict = import(
        &kit,
        &body(false, false, vec![user("legacy", "2", "dup@example.com")]),
    )
    .await;
    assert_eq!(results(&conflict)[0]["status"].as_str(), Some("conflict"));
    assert_eq!(
        results(&conflict)[0]["reason"].as_str(),
        Some("email-exists")
    );
    assert!(results(&conflict)[0]["sub"].is_null());
    assert_eq!(rows(&kit, "users").await, 1, "a conflict creates no user");

    let merged = import(
        &kit,
        &body(false, true, vec![user("legacy", "2", "dup@example.com")]),
    )
    .await;
    assert_eq!(results(&merged)[0]["status"].as_str(), Some("merged"));
    assert_eq!(results(&merged)[0]["sub"].as_str(), Some(sub.as_str()));
    assert_eq!(rows(&kit, "users").await, 1, "a merge creates no user");
    assert_eq!(
        rows(&kit, "identities").await,
        2,
        "the import identity lands"
    );
}

#[pollster::test]
async fn an_earlier_row_owns_its_email_in_the_same_request() {
    let kit = kit(vec![]);
    // Two rows, same address, in one request: the first creates, the second
    // sees the address taken by the first.
    let dry = import(
        &kit,
        &body(
            true,
            false,
            vec![
                user("legacy", "1", "same@example.com"),
                user("legacy", "2", "same@example.com"),
            ],
        ),
    )
    .await;
    assert_eq!(results(&dry)[0]["status"].as_str(), Some("created"));
    assert!(results(&dry)[0]["sub"].is_null(), "dry run: no sub yet");
    assert_eq!(results(&dry)[1]["status"].as_str(), Some("conflict"));
    assert_eq!(results(&dry)[1]["reason"].as_str(), Some("email-exists"));
    assert_eq!(rows(&kit, "users").await, 0, "the dry run wrote nothing");

    let merged = import(
        &kit,
        &body(
            false,
            true,
            vec![
                user("legacy", "1", "same@example.com"),
                user("legacy", "2", "same@example.com"),
            ],
        ),
    )
    .await;
    assert_eq!(results(&merged)[0]["status"].as_str(), Some("created"));
    assert_eq!(results(&merged)[1]["status"].as_str(), Some("merged"));
    assert_eq!(
        results(&merged)[0]["sub"].as_str(),
        results(&merged)[1]["sub"].as_str(),
        "the second row joined the first row's account"
    );
    assert_eq!(rows(&kit, "users").await, 1);
    assert_eq!(rows(&kit, "identities").await, 2);
}

#[pollster::test]
async fn a_too_expensive_bcrypt_hash_is_refused() {
    let kit = kit(vec![("AUTH_LEGACY_HASHES", "bcrypt")]);
    let doc = import(
        &kit,
        &body(
            false,
            false,
            vec![user_with_hash(
                "legacy",
                "1",
                "ada@example.com",
                BCRYPT_TOO_EXPENSIVE,
            )],
        ),
    )
    .await;
    assert_eq!(results(&doc)[0]["status"].as_str(), Some("invalid"));
    assert_eq!(
        results(&doc)[0]["reason"].as_str(),
        Some("bcrypt-cost-too-high")
    );
    assert_eq!(rows(&kit, "users").await, 0);
}

#[pollster::test]
async fn an_unknown_hash_format_is_refused() {
    let kit = kit(vec![("AUTH_LEGACY_HASHES", "bcrypt")]);
    for bad in [
        // MD5-crypt: a `$1$` PHC, neither argon2id nor bcrypt.
        "$1$abcdefgh$0123456789abcdefghijklmnop",
        "plain",
    ] {
        let doc = import(
            &kit,
            &body(
                false,
                false,
                vec![user_with_hash("legacy", "1", "ada@example.com", bad)],
            ),
        )
        .await;
        assert_eq!(
            results(&doc)[0]["status"].as_str(),
            Some("invalid"),
            "{bad}"
        );
        assert_eq!(
            results(&doc)[0]["reason"].as_str(),
            Some("unsupported-hash")
        );
    }
    assert_eq!(rows(&kit, "users").await, 0);
}

#[pollster::test]
async fn bcrypt_without_the_legacy_flag_is_refused() {
    let bare = kit(vec![]);
    let doc = import(
        &bare,
        &body(
            false,
            false,
            vec![user_with_hash("legacy", "1", "ada@example.com", BCRYPT_OK)],
        ),
    )
    .await;
    assert_eq!(results(&doc)[0]["status"].as_str(), Some("invalid"));
    assert_eq!(
        results(&doc)[0]["reason"].as_str(),
        Some("legacy-hashes-disabled")
    );
    assert_eq!(rows(&bare, "users").await, 0);

    // With the flag, the same hash is accepted and stored verbatim.
    let flagged = kit(vec![("AUTH_LEGACY_HASHES", "bcrypt")]);
    let doc = import(
        &flagged,
        &body(
            false,
            false,
            vec![user_with_hash("legacy", "1", "ada@example.com", BCRYPT_OK)],
        ),
    )
    .await;
    assert_eq!(results(&doc)[0]["status"].as_str(), Some("created"));
    let stored: String = flagged
        .db
        .query(&Statement::new(
            "SELECT password_hash FROM credentials".to_owned(),
        ))
        .await
        .expect("query")
        .first()
        .and_then(|row| row.get::<String>("password_hash"))
        .expect("stored hash");
    assert_eq!(stored, BCRYPT_OK, "the hash is stored verbatim");
}

#[pollster::test]
async fn more_than_a_thousand_users_is_refused_whole() {
    let kit = kit(vec![]);
    let users: Vec<Value> = (0..1001)
        .map(|n| user("legacy", &n.to_string(), "a@b.co"))
        .collect();
    let (status, raw) = import_raw(&kit, &body(false, false, users)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{raw}");
    assert!(
        raw.contains("problems/auth/import-too-large"),
        "the stable slug comes back: {raw}"
    );
    assert_eq!(rows(&kit, "users").await, 0, "nothing was written");
}

#[pollster::test]
async fn the_response_never_carries_an_email_or_a_hash() {
    let kit = kit(vec![]);
    let email = "private-address@example.com";
    let hash = argon_hash();
    let (status, raw) = import_raw(
        &kit,
        &body(
            false,
            false,
            vec![user_with_hash("legacy", "42", email, &hash)],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    assert!(!raw.contains(email), "the response carries no email: {raw}");
    assert!(!raw.contains(&hash), "the response carries no hash: {raw}");
    // The hash is looked for by its own digest body too, not only whole.
    let digest = hash.rsplit('$').next().unwrap_or_default();
    assert!(!raw.contains(digest), "no digest fragment either: {raw}");
}

#[pollster::test]
async fn a_dry_run_writes_nothing() {
    let kit = kit(vec![]);
    let doc = import(
        &kit,
        &body(
            true,
            false,
            vec![
                user_with_hash("legacy", "1", "ada@example.com", &argon_hash()),
                user("legacy", "2", "grace@example.com"),
            ],
        ),
    )
    .await;
    assert_eq!(doc["dry_run"], json!(true));
    for row in results(&doc) {
        assert_eq!(row["status"].as_str(), Some("created"), "{doc}");
        assert!(
            row["sub"].is_null(),
            "a would-be user has no sub yet: {doc}"
        );
    }
    assert_eq!(rows(&kit, "users").await, 0);
    assert_eq!(rows(&kit, "identities").await, 0);
    assert_eq!(rows(&kit, "credentials").await, 0);

    // The lookup finds nothing, because nothing was written.
    let (status, _) = get(
        &kit,
        &format!("{BASE}/admin/users/by-external-id?provider=legacy&external_id=1"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[pollster::test]
async fn by_external_id_finds_the_sub_or_404s() {
    let kit = kit(vec![]);
    let first = import(
        &kit,
        &body(false, false, vec![user("legacy", "42", "ada@example.com")]),
    )
    .await;
    let sub = results(&first)[0]["sub"].as_str().expect("sub").to_owned();

    let (status, raw) = get(
        &kit,
        &format!("{BASE}/admin/users/by-external-id?provider=legacy&external_id=42"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    let doc: Value = serde_json::from_str(&raw).expect("JSON");
    assert_eq!(doc["sub"].as_str(), Some(sub.as_str()));

    let (status, _) = get(
        &kit,
        &format!("{BASE}/admin/users/by-external-id?provider=legacy&external_id=nope"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[pollster::test]
async fn a_malformed_body_is_a_validation_problem() {
    let kit = kit(vec![]);
    let (status, raw) = import_raw(&kit, "{not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{raw}");
    assert!(
        raw.contains("problems/validation-failed"),
        "expected problem+json: {raw}"
    );

    // A body missing the required envelope fields is a validation problem
    // too, not a write.
    let (status, raw) = import_raw(&kit, r#"{"users": []}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{raw}");
    assert!(raw.contains("problems/validation-failed"), "{raw}");
}

#[pollster::test]
async fn import_routes_without_a_token_are_unauthorized() {
    let kit = kit(vec![]);
    for (method, path) in [
        (Method::POST, IMPORT),
        (
            Method::GET,
            "/v1/auth-core/admin/users/by-external-id?provider=legacy&external_id=1",
        ),
    ] {
        let response = cratefield_testing::request(&kit.router, method.clone(), path, None).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            response.json()["type"],
            "https://test.example/problems/admin-unauthorized"
        );
    }
}

#[pollster::test]
async fn a_created_at_offset_is_normalised_to_utc() {
    let kit = kit(vec![]);
    let mut value = user("legacy", "1", "ada@example.com");
    value["created_at"] = json!("2024-01-15T10:30:00+05:00");
    let doc = import(&kit, &body(false, false, vec![value])).await;
    assert_eq!(results(&doc)[0]["status"].as_str(), Some("created"));

    // Stored in UTC, the shape `now_iso` writes, so lexicographic order is
    // chronological and a `+05:00` row does not sort after a `Z` one.
    let created: String = kit
        .db
        .query(&Statement::new("SELECT created_at FROM users".to_owned()))
        .await
        .expect("query")
        .first()
        .and_then(|row| row.get::<String>("created_at"))
        .expect("created_at");
    assert_eq!(created, "2024-01-15T05:30:00Z", "normalised to UTC");
}
