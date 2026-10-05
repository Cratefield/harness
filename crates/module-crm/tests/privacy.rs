//! Issue #265: the declarations, proved against the module that reads them.
//!
//! `Module::personal_data()` is a promise about behaviour that lives in
//! another crate — `cratefield-module-privacy` plans an export and an erasure
//! from it — so asserting the list against itself would prove nothing. These
//! compose the two modules the way a venture does and drive the routes.
//!
//! The order of the declarations is the part worth proving: `crm_taggings`
//! reaches its contact through a join, so erasing the contact first would
//! leave its taggings matched by nothing.

use axum::http::{Method, StatusCode};
use cratefield_core::{Config, MapConfig, Statement};
use cratefield_module_crm::Crm;
use cratefield_module_privacy::Privacy;
use cratefield_testing::{TestHarness, request, request_as};
use serde_json::{Value, json};
use std::sync::Arc;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const CONTACTS: &str = "/v1/crm/admin/contacts";

fn privacy_kit() -> TestHarness {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
        (
            "HARNESS_SECRET".to_owned(),
            "cratefield-testing-dummy-secret-0123456789".to_owned(),
        ),
    ]));
    TestHarness::with_ports(
        vec![Box::new(Crm::new()), Box::new(Privacy::new())],
        move |ports| {
            ports.config = Arc::clone(&config);
        },
    )
}

/// An admin `POST` that must succeed, answered as JSON.
async fn post(kit: &TestHarness, path: &str, body: &str) -> Value {
    let response = request_as(&kit.router, Method::POST, path, ADMIN, Some(body)).await;
    assert!(
        response.status.is_success(),
        "{path}: {} {}",
        response.status,
        String::from_utf8_lossy(response.body())
    );
    response.json()
}

async fn create_contact(kit: &TestHarness, email: &str, organisation_id: Option<&str>) -> String {
    let body = match organisation_id {
        Some(organisation) => {
            json!({ "email": email, "organisation_id": organisation }).to_string()
        }
        None => json!({ "email": email }).to_string(),
    };
    post(kit, CONTACTS, &body).await["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

async fn count(kit: &TestHarness, table: &str) -> i64 {
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

/// The `subject_id` of every tagging, as the database has it.
async fn tagged_subjects(kit: &TestHarness) -> Vec<String> {
    let rows = kit
        .db
        .query(&Statement::new("SELECT subject_id FROM crm_taggings"))
        .await
        .expect("taggings");
    rows.rows
        .iter()
        .filter_map(|row| row.get::<String>("subject_id"))
        .collect()
}

/// Runs the two-step erasure and returns the confirm answer.
async fn erase(kit: &TestHarness, subject: &str) -> Value {
    let preview = post(
        kit,
        "/v1/privacy/erase",
        &json!({ "subject": subject }).to_string(),
    )
    .await;
    post(
        kit,
        "/v1/privacy/erase/confirm",
        &json!({ "token": preview["confirm_token"] }).to_string(),
    )
    .await
}

#[pollster::test]
async fn erasing_a_contact_takes_its_row_and_its_taggings_and_nothing_else() {
    let kit = privacy_kit();

    // One organisation, two contacts, one tag on each of them.
    let organisation_id =
        post(&kit, "/v1/crm/admin/organisations", r#"{"name":"Astra"}"#).await["id"]
            .as_str()
            .unwrap()
            .to_owned();
    let alice = create_contact(&kit, "alice@example.com", Some(&organisation_id)).await;
    let bob = create_contact(&kit, "bob@example.com", None).await;
    let tag_id = post(
        &kit,
        "/v1/crm/admin/tags",
        r#"{"name":"vip","color":"gold"}"#,
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for subject in [&alice, &bob] {
        post(
            &kit,
            "/v1/crm/admin/tags/tag",
            &json!({ "tag_id": tag_id, "subject_type": "contact", "subject_id": subject })
                .to_string(),
        )
        .await;
    }
    assert_eq!(count(&kit, "crm_contacts").await, 2);
    assert_eq!(count(&kit, "crm_taggings").await, 2);

    let confirmed = erase(&kit, &alice).await;
    assert_eq!(confirmed["verified"], true, "{confirmed}");

    // Alice's row and her tagging are gone; Bob's tagging, the tag, the
    // organisation and the other contact all survive.
    assert_eq!(
        count(&kit, "crm_contacts").await,
        1,
        "one contact was erased"
    );
    assert_eq!(
        count(&kit, "crm_taggings").await,
        1,
        "the taggings of both contacts were reachable through the join"
    );
    assert_eq!(
        count(&kit, "crm_tags").await,
        1,
        "the label is not personal"
    );
    assert_eq!(
        count(&kit, "crm_organisations").await,
        1,
        "the business record survives"
    );

    // Bob's tagging is the one left, and it still names Bob.
    assert_eq!(
        tagged_subjects(&kit).await,
        vec![bob],
        "Bob's tag was erased with Alice's"
    );
}

#[pollster::test]
async fn every_table_is_declared() {
    let kit = privacy_kit();
    let response = request(&kit.router, Method::GET, "/v1/privacy/manifest", None).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();

    let names = |key: &str| -> Vec<String> {
        body[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} is an array: {body}"))
            .iter()
            .filter_map(|entry| entry["table"].as_str().map(str::to_owned))
            .collect()
    };
    let holds = names("holds");
    let not_personal = names("not_personal");

    // The two tables that hold a person are exportable and erasable...
    assert!(holds.contains(&"crm_contacts".to_owned()), "{holds:?}");
    assert!(holds.contains(&"crm_taggings".to_owned()), "{holds:?}");
    // ...and the two that do not are declared as such rather than silent.
    assert!(
        not_personal.contains(&"crm_organisations".to_owned()),
        "{not_personal:?}"
    );
    assert!(
        not_personal.contains(&"crm_tags".to_owned()),
        "{not_personal:?}"
    );
    assert_eq!(body["holds_personal_data"], true);

    // The organisation's reason has to flag its address columns rather than
    // claim the table names nobody.
    let reason = body["not_personal"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["table"] == "crm_organisations")
        })
        .and_then(|entry| entry["reason"].as_str())
        .unwrap_or_default();
    assert!(reason.contains("email"), "{reason}");
    assert!(reason.contains("phone"), "{reason}");
    assert!(reason.to_lowercase().contains("review"), "{reason}");
}
