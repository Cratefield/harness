//! Issue #572 acceptance for the CRM's admin routes: every route is
//! admin-gated, the upserts are idempotent on their natural key, a stale
//! `generation` is a `409`, a merge folds one contact into another, and the
//! CSV exports page.

use axum::http::{Method, StatusCode, header};
use cratefield_core::{MapConfig, Statement};
use cratefield_module_crm::Crm;
use cratefield_testing::{TestHarness, TestResponse, request, request_as};
use serde_json::{Value, json};
use std::sync::Arc;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const WRONG: &str = "not-the-admin-token-0123456789ab";
const CONTACTS: &str = "/v1/crm/admin/contacts";
const TAGS: &str = "/v1/crm/admin/tags";

fn kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || vec![Box::new(Crm::new())],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
        },
    )
}

fn text(response: &TestResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

/// A request with no body, for the tests that assert a status of their own.
async fn raw(kit: &TestHarness, method: Method, path: &str, body: Option<&str>) -> TestResponse {
    request_as(&kit.router, method, path, ADMIN, body).await
}

/// A request carrying one; its status is the test's to assert.
async fn send(kit: &TestHarness, method: Method, path: &str, body: &str) -> TestResponse {
    raw(kit, method, path, Some(body)).await
}

/// A request that must succeed, answered as JSON.
async fn ok(kit: &TestHarness, method: Method, path: &str, body: &str) -> Value {
    let response = send(kit, method, path, body).await;
    assert!(response.status.is_success(), "{path}: {}", text(&response));
    response.json()
}

/// A create, which must answer `201`.
async fn created(kit: &TestHarness, path: &str, body: &str) -> Value {
    let response = send(kit, Method::POST, path, body).await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "{path}: {}",
        text(&response)
    );
    response.json()
}

async fn get(kit: &TestHarness, path: &str) -> TestResponse {
    raw(kit, Method::GET, path, None).await
}

async fn delete(kit: &TestHarness, path: &str) -> TestResponse {
    raw(kit, Method::DELETE, path, None).await
}

/// Files a contact and returns its JSON.
async fn create_contact(kit: &TestHarness, email: &str) -> Value {
    created(kit, CONTACTS, &json!({ "email": email }).to_string()).await
}

async fn row_count(kit: &TestHarness, table: &str) -> i64 {
    let rows = kit
        .db
        .query(&Statement::new(format!(
            "SELECT COUNT(*) AS n FROM {table}"
        )))
        .await
        .expect("count");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or(-1)
}

/// Files a tag and returns its id.
async fn create_tag(kit: &TestHarness, name: &str, color: Option<&str>) -> String {
    let body = match color {
        Some(color) => json!({ "name": name, "color": color }).to_string(),
        None => json!({ "name": name }).to_string(),
    };
    ok(kit, Method::POST, TAGS, &body).await["id"]
        .as_str()
        .expect("tag id")
        .to_owned()
}

/// Files a tag against a subject.
async fn tag(kit: &TestHarness, tag_id: &str, subject_id: &str) -> Value {
    ok(
        kit,
        Method::POST,
        "/v1/crm/admin/tags/tag",
        &json!({ "tag_id": tag_id, "subject_type": "contact", "subject_id": subject_id })
            .to_string(),
    )
    .await
}

/// The `subject_id` of every tagging of one tag, as the database has it.
async fn tagged_subjects(kit: &TestHarness, tag_id: &str) -> Vec<String> {
    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT subject_id FROM crm_taggings WHERE tag_id = ?",
            vec![tag_id.into()],
        ))
        .await
        .expect("taggings");
    rows.rows
        .iter()
        .filter_map(|row| row.get::<String>("subject_id"))
        .collect()
}

/// The routes a caller with no bearer must not reach.
///
/// The bodies are valid for their route on purpose: axum's `Json` extractor
/// runs before the handler, so a malformed body would be refused with a 400
/// and the admin gate would never be reached — proving nothing about the
/// gate.
const GUARDED: &[(Method, &str, Option<&str>)] = &[
    (Method::GET, "/v1/crm/admin/contacts.csv", None),
    (Method::GET, "/v1/crm/admin/organisations.csv", None),
    (Method::POST, CONTACTS, Some(r#"{"email":"a@example.com"}"#)),
    (
        Method::POST,
        "/v1/crm/admin/contacts/merge",
        Some(r#"{"keep":"a","merge":"b"}"#),
    ),
    (
        Method::PATCH,
        "/v1/crm/admin/contacts/some-id",
        Some(r#"{"generation":1}"#),
    ),
    (Method::DELETE, "/v1/crm/admin/contacts/some-id", None),
    (
        Method::POST,
        "/v1/crm/admin/organisations",
        Some(r#"{"name":"Astra"}"#),
    ),
    (
        Method::PATCH,
        "/v1/crm/admin/organisations/some-id",
        Some(r#"{"generation":1}"#),
    ),
    (Method::DELETE, "/v1/crm/admin/organisations/some-id", None),
    (Method::POST, TAGS, Some(r#"{"name":"vip"}"#)),
    (
        Method::POST,
        "/v1/crm/admin/tags/tag",
        Some(r#"{"tag_id":"t","subject_type":"contact","subject_id":"s"}"#),
    ),
    (
        Method::POST,
        "/v1/crm/admin/tags/untag",
        Some(r#"{"tag_id":"t","subject_type":"contact","subject_id":"s"}"#),
    ),
];

#[pollster::test]
async fn every_admin_route_needs_a_bearer() {
    for kit in kits() {
        for (method, path, body) in GUARDED {
            let missing = request(&kit.router, method.clone(), path, *body).await;
            assert_eq!(
                missing.status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} without a bearer: {}",
                text(&missing)
            );
            let wrong = request_as(&kit.router, method.clone(), path, WRONG, *body).await;
            assert_eq!(
                wrong.status,
                StatusCode::FORBIDDEN,
                "{method} {path} with the wrong bearer: {}",
                text(&wrong)
            );
        }
    }
}

#[pollster::test]
async fn the_same_email_twice_is_one_contact() {
    for kit in kits() {
        let first = create_contact(&kit, " Ada@Example.COM ").await;
        let second = ok(
            &kit,
            Method::POST,
            CONTACTS,
            r#"{"email":"ada@example.com","name":"Ada"}"#,
        )
        .await;
        assert_eq!(second["id"], first["id"], "the address is the key");
        assert_eq!(second["emailNormalized"], "ada@example.com");
        assert_eq!(second["name"], "Ada");
        assert_eq!(second["generation"], 2, "the write bumped the generation");
        assert_eq!(row_count(&kit, "crm_contacts").await, 1, "one contact");
    }
}

#[pollster::test]
async fn a_stale_generation_is_refused_and_changes_nothing() {
    for kit in kits() {
        let created = create_contact(&kit, "ada@example.com").await;
        let id = created["id"].as_str().unwrap();
        assert_eq!(created["generation"], 1);
        let url = format!("{CONTACTS}/{id}");

        let first = ok(
            &kit,
            Method::PATCH,
            &url,
            r#"{"generation":1,"name":"Ada Lovelace"}"#,
        )
        .await;
        assert_eq!(first["generation"], 2);

        let stale = send(
            &kit,
            Method::PATCH,
            &url,
            r#"{"generation":1,"name":"Overwritten"}"#,
        )
        .await;
        assert_eq!(stale.status, StatusCode::CONFLICT, "{}", text(&stale));
        let problem = stale.json();
        assert!(
            problem["type"]
                .as_str()
                .unwrap_or_default()
                .ends_with("/problems/crm-stale-generation"),
            "{problem}"
        );
        // Nothing changed: the record still says what the first write wrote.
        let current = ok(
            &kit,
            Method::PATCH,
            &url,
            r#"{"generation":2,"phone":"1234"}"#,
        )
        .await;
        assert_eq!(current["name"], "Ada Lovelace");
        assert_eq!(current["phone"], "1234");

        // A PATCH of a contact that is not there is a 404, not a conflict.
        let missing = send(
            &kit,
            Method::PATCH,
            &format!("{CONTACTS}/no-such-contact"),
            r#"{"generation":1,"name":"X"}"#,
        )
        .await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
    }
}

#[pollster::test]
async fn a_merge_fills_blanks_moves_tags_and_deletes_the_loser() {
    for kit in kits() {
        let keep = create_contact(&kit, "keep@example.com").await;
        let loser = ok(
            &kit,
            Method::POST,
            CONTACTS,
            r#"{"email":"loser@example.com","phone":"555","data":{"tier":"bronze","note":"from the loser"}}"#,
        )
        .await;
        let keep_id = keep["id"].as_str().unwrap().to_owned();
        let loser_id = loser["id"].as_str().unwrap().to_owned();

        // Tag the loser; the keeper keeps its own blank fields until then.
        let tag_id = create_tag(&kit, "vip", Some("gold")).await;
        assert_eq!(tag(&kit, &tag_id, &loser_id).await["ok"], true);

        let merged = ok(
            &kit,
            Method::POST,
            &format!("{CONTACTS}/merge"),
            &json!({ "keep": keep_id, "merge": loser_id }).to_string(),
        )
        .await;
        assert_eq!(merged["id"], keep_id);
        // The blank phone came from the loser; the key both shared is the
        // keeper's to keep.
        assert_eq!(merged["phone"], "555");
        assert_eq!(merged["data"]["note"], "from the loser");
        assert_eq!(merged["generation"], 2);
        assert_eq!(row_count(&kit, "crm_contacts").await, 1);

        // The loser is gone, and its tag now labels the survivor.
        let gone = send(
            &kit,
            Method::PATCH,
            &format!("{CONTACTS}/{loser_id}"),
            r#"{"generation":1,"name":"X"}"#,
        )
        .await;
        assert_eq!(gone.status, StatusCode::NOT_FOUND);
        assert_eq!(
            tagged_subjects(&kit, &tag_id).await,
            vec![keep_id],
            "the tag moved to the survivor"
        );
    }
}

#[pollster::test]
async fn the_contacts_export_pages_as_csv() {
    for kit in kits() {
        create_contact(&kit, "a@example.com").await;
        create_contact(&kit, "b@example.com").await;

        let page = get(&kit, "/v1/crm/admin/contacts.csv").await;
        assert_eq!(page.status, StatusCode::OK, "{}", text(&page));
        assert_eq!(
            page.headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/csv; charset=utf-8")
        );
        assert!(page.headers.get("x-cf-export-more").is_none());
        let body = text(&page);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3, "a header and two rows: {body}");
        assert!(
            lines[0].starts_with("id,email,email_normalized"),
            "{}",
            lines[0]
        );
        // The two rows are the two contacts, in either order: both were
        // written under the harness's frozen clock, so they share a
        // `created_at` and the `id` tie-break is a ULID's random tail, not
        // insertion order (`Ulid::generate` is not monotonic).
        let rows = &lines[1..];
        assert!(
            rows.iter().any(|row| row.contains("a@example.com")),
            "{body}"
        );
        assert!(
            rows.iter().any(|row| row.contains("b@example.com")),
            "{body}"
        );

        // A page of one says there is more.
        let first = get(&kit, "/v1/crm/admin/contacts.csv?limit=1").await;
        assert_eq!(
            first
                .headers
                .get("x-cf-export-more")
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(text(&first).lines().count(), 2);
    }
}

#[pollster::test]
async fn organisations_upsert_by_domain_and_always_insert_without_one() {
    for kit in kits() {
        let first = created(
            &kit,
            "/v1/crm/admin/organisations",
            r#"{"name":"Astra","domain":"  ASTRA.example "}"#,
        )
        .await;
        let second = ok(
            &kit,
            Method::POST,
            "/v1/crm/admin/organisations",
            r#"{"name":"Astra Ltd","domain":"astra.example","website":"https://astra.example"}"#,
        )
        .await;
        assert_eq!(second["id"], first["id"]);
        assert_eq!(second["domain"], "astra.example");
        assert_eq!(second["website"], "https://astra.example");
        assert_eq!(row_count(&kit, "crm_organisations").await, 1);

        // No domain is no key: each call is a new company.
        for _ in 0..2 {
            created(
                &kit,
                "/v1/crm/admin/organisations",
                r#"{"name":"No Domain Ltd"}"#,
            )
            .await;
        }
        assert_eq!(row_count(&kit, "crm_organisations").await, 3);

        // A blank name is refused.
        let blank = send(
            &kit,
            Method::POST,
            "/v1/crm/admin/organisations",
            r#"{"name":"   "}"#,
        )
        .await;
        assert_eq!(blank.status, StatusCode::BAD_REQUEST, "{}", text(&blank));
    }
}

#[pollster::test]
async fn deleting_a_contact_takes_its_taggings_with_it() {
    for kit in kits() {
        let id = create_contact(&kit, "gone@example.com").await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let tag_id = create_tag(&kit, "lead", None).await;
        tag(&kit, &tag_id, &id).await;

        let url = format!("{CONTACTS}/{id}");
        let deleted = delete(&kit, &url).await;
        assert_eq!(deleted.status, StatusCode::OK, "{}", text(&deleted));
        assert_eq!(row_count(&kit, "crm_contacts").await, 0);
        assert_eq!(
            row_count(&kit, "crm_taggings").await,
            0,
            "taggings went too"
        );
        // The tag itself is not a subject's data and stays.
        assert_eq!(row_count(&kit, "crm_tags").await, 1);

        assert_eq!(delete(&kit, &url).await.status, StatusCode::NOT_FOUND);
    }
}

#[pollster::test]
async fn tagging_validates_the_subject_type_and_the_tag() {
    for kit in kits() {
        let id = create_contact(&kit, "tagged@example.com").await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let tag_id = create_tag(&kit, "vip", None).await;

        let unknown = send(
            &kit,
            Method::POST,
            "/v1/crm/admin/tags/tag",
            &json!({"tag_id": "no-such-tag", "subject_type": "contact", "subject_id": id})
                .to_string(),
        )
        .await;
        assert_eq!(unknown.status, StatusCode::NOT_FOUND, "{}", text(&unknown));

        let bad_type = send(
            &kit,
            Method::POST,
            "/v1/crm/admin/tags/tag",
            &json!({"tag_id": tag_id, "subject_type": "customer", "subject_id": id}).to_string(),
        )
        .await;
        assert_eq!(
            bad_type.status,
            StatusCode::BAD_REQUEST,
            "{}",
            text(&bad_type)
        );

        // Tagging twice is one tagging, not an error.
        for _ in 0..2 {
            tag(&kit, &tag_id, &id).await;
        }
        assert_eq!(row_count(&kit, "crm_taggings").await, 1);

        let untagged = ok(
            &kit,
            Method::POST,
            "/v1/crm/admin/tags/untag",
            &json!({ "tag_id": tag_id, "subject_type": "contact", "subject_id": id }).to_string(),
        )
        .await;
        assert_eq!(untagged["removed"], 1);
        assert_eq!(row_count(&kit, "crm_taggings").await, 0);
    }
}

#[pollster::test]
async fn a_blank_tag_name_is_refused() {
    for kit in kits() {
        let blank = send(&kit, Method::POST, TAGS, r#"{"name":"  "}"#).await;
        assert_eq!(blank.status, StatusCode::BAD_REQUEST, "{}", text(&blank));
    }
}

#[pollster::test]
async fn creating_a_tag_is_201_and_refiling_it_is_200() {
    for kit in kits() {
        let first = created(&kit, TAGS, r#"{"name":"vip","color":"gold"}"#).await;
        let id = first["id"].as_str().unwrap().to_owned();

        // The name is the key: the same name (trimmed) re-files the tag and
        // answers `200`, not `201`.
        let again = send(
            &kit,
            Method::POST,
            TAGS,
            r#"{"name":"  vip  ","color":"blue"}"#,
        )
        .await;
        assert_eq!(again.status, StatusCode::OK, "{}", text(&again));
        assert_eq!(again.json()["id"], id);
        assert_eq!(again.json()["color"], "blue");
        assert_eq!(row_count(&kit, "crm_tags").await, 1);
    }
}

#[pollster::test]
async fn a_contact_patch_stores_its_email_trimmed_and_refuses_a_taken_one() {
    for kit in kits() {
        create_contact(&kit, "ada@example.com").await;
        let bob = create_contact(&kit, "bob@example.com").await;
        let id = bob["id"].as_str().unwrap().to_owned();
        let url = format!("{CONTACTS}/{id}");

        // The stored `email` is trimmed exactly as the upsert stores it, case
        // and all; `email_normalized` is the lowercased form.
        let moved = ok(
            &kit,
            Method::PATCH,
            &url,
            r#"{"generation":1,"email":"  Bob.New@Example.COM "}"#,
        )
        .await;
        assert_eq!(moved["email"], "Bob.New@Example.COM");
        assert_eq!(moved["emailNormalized"], "bob.new@example.com");

        // Moving onto another contact's address is a conflict, not a 500.
        let clash = send(
            &kit,
            Method::PATCH,
            &url,
            r#"{"generation":2,"email":" ADA@example.com "}"#,
        )
        .await;
        assert_eq!(clash.status, StatusCode::CONFLICT, "{}", text(&clash));
        assert!(
            clash.json()["type"]
                .as_str()
                .unwrap_or_default()
                .ends_with("/problems/crm-already-exists"),
            "{}",
            text(&clash)
        );
        assert_eq!(
            row_count(&kit, "crm_contacts").await,
            2,
            "the clash wrote nothing"
        );

        // Null clears both the address and its normalized form.
        let cleared = ok(
            &kit,
            Method::PATCH,
            &url,
            r#"{"generation":2,"email":null}"#,
        )
        .await;
        assert!(cleared["email"].is_null(), "{cleared}");
        assert!(cleared["emailNormalized"].is_null(), "{cleared}");
    }
}

#[pollster::test]
async fn an_org_patch_normalizes_its_domain_and_refuses_a_taken_one() {
    for kit in kits() {
        created(
            &kit,
            "/v1/crm/admin/organisations",
            r#"{"name":"Astra","domain":"astra.example"}"#,
        )
        .await;
        let beta = created(
            &kit,
            "/v1/crm/admin/organisations",
            r#"{"name":"Beta","domain":"beta.example"}"#,
        )
        .await;
        let id = beta["id"].as_str().unwrap().to_owned();
        let url = format!("/v1/crm/admin/organisations/{id}");

        // The domain is normalized (trimmed and lowercased) like the upsert's.
        let moved = ok(
            &kit,
            Method::PATCH,
            &url,
            r#"{"generation":1,"domain":"  Beta2.Example "}"#,
        )
        .await;
        assert_eq!(moved["domain"], "beta2.example");

        let clash = send(
            &kit,
            Method::PATCH,
            &url,
            r#"{"generation":2,"domain":" ASTRA.example "}"#,
        )
        .await;
        assert_eq!(clash.status, StatusCode::CONFLICT, "{}", text(&clash));
        assert_eq!(
            row_count(&kit, "crm_organisations").await,
            2,
            "the clash wrote nothing"
        );

        // Null clears it.
        let cleared = ok(
            &kit,
            Method::PATCH,
            &url,
            r#"{"generation":2,"domain":null}"#,
        )
        .await;
        assert!(cleared["domain"].is_null(), "{cleared}");
    }
}

#[pollster::test]
async fn a_contact_naming_an_unknown_organisation_is_a_validation_error() {
    for kit in kits() {
        let bad = send(
            &kit,
            Method::POST,
            CONTACTS,
            r#"{"email":"x@example.com","organisation_id":"no-such-org"}"#,
        )
        .await;
        assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", text(&bad));
        assert!(
            bad.json()["type"]
                .as_str()
                .unwrap_or_default()
                .ends_with("/problems/validation-failed"),
            "{}",
            text(&bad)
        );

        // Filed against a real organisation it is a plain create.
        let org = created(&kit, "/v1/crm/admin/organisations", r#"{"name":"Astra"}"#).await;
        let org_id = org["id"].as_str().unwrap().to_owned();
        let good = created(
            &kit,
            CONTACTS,
            &json!({ "email": "ok@example.com", "organisation_id": org_id }).to_string(),
        )
        .await;

        // A PATCH onto a missing organisation is refused the same way.
        let id = good["id"].as_str().unwrap().to_owned();
        let patched = send(
            &kit,
            Method::PATCH,
            &format!("{CONTACTS}/{id}"),
            r#"{"generation":1,"organisation_id":"no-such-org"}"#,
        )
        .await;
        assert_eq!(
            patched.status,
            StatusCode::BAD_REQUEST,
            "{}",
            text(&patched)
        );
        assert_eq!(row_count(&kit, "crm_contacts").await, 1);
    }
}
