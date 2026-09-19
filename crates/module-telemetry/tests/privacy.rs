//! Issue #413: the declarations, proved against the module that reads them.
//!
//! `Module::personal_data()` is a promise about behaviour that lives in
//! another crate — `cratefield-module-privacy` publishes the manifest and
//! plans erasures from it — so asserting the list against itself would
//! prove nothing. These compose the two modules the way a venture does and
//! drive the routes: the manifest must publish both telemetry tables under
//! `holds` with `erase`, and an erasure keyed on an install id must delete
//! exactly that install's rows and nothing else.

use axum::http::{Method, StatusCode};
use cratefield_core::{Config, MapConfig, Statement};
use cratefield_module_privacy::Privacy;
use cratefield_module_telemetry::Telemetry;
use cratefield_testing::{TestHarness, request, request_as};
use std::sync::Arc;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const ALICE: &str = "7b0a1f2c3d4e5f60718293a4b5c6d7e8";
const BOB: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

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
                Telemetry::new()
                    .events(["run", "build"])
                    .modules(["telemetry"]),
            ),
            Box::new(Privacy::new()),
        ],
        move |ports| {
            ports.config = Arc::clone(&config);
        },
    )
}

/// One batch, sent the way a client sends it — through the public ingest
/// route, so the rows under test are the rows the module itself writes.
async fn report(kit: &TestHarness, install: &str, event: &str, count: i64) {
    let body = format!(
        r#"{{"schema":1,"install":"{install}","client":{{"kind":"cli","version":"0.4.1","platform":"linux","arch":"aarch64"}},"modules":["telemetry"],"events":[{{"name":"{event}","outcome":"ok","error":"none","duration":"unknown","count":{count}}}]}}"#
    );
    let accepted = request(
        &kit.router,
        Method::POST,
        "/v1/telemetry/events",
        Some(&body),
    )
    .await;
    assert_eq!(
        accepted.status,
        StatusCode::ACCEPTED,
        "{:?}",
        accepted.body()
    );
}

async fn rows_for(kit: &TestHarness, install: &str) -> (i64, i64) {
    let events = kit
        .db
        .query(&Statement::with_values(
            "SELECT COUNT(*) AS n FROM telemetry_events WHERE install_id = ?".to_owned(),
            vec![install.into()],
        ))
        .await
        .expect("counting event buckets");
    let modules = kit
        .db
        .query(&Statement::with_values(
            "SELECT COUNT(*) AS n FROM telemetry_modules WHERE install_id = ?".to_owned(),
            vec![install.into()],
        ))
        .await
        .expect("counting module rows");
    (
        events.first().and_then(|row| row.get("n")).unwrap_or(0),
        modules.first().and_then(|row| row.get("n")).unwrap_or(0),
    )
}

/// Runs the two-step erasure, asserting each step.
async fn erase(kit: &TestHarness, subject: &str) {
    let preview = request_as(
        &kit.router,
        Method::POST,
        "/v1/privacy/erase",
        ADMIN,
        Some(&format!(r#"{{"subject":"{subject}"}}"#)),
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK, "{:?}", preview.body());
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
}

/// The manifest is the promise: both telemetry tables published under
/// `holds`, as usage, erased on request — never quietly in `not_personal`.
#[pollster::test]
async fn the_manifest_lists_both_tables_under_holds_as_erase() {
    let kit = privacy_kit();
    // The manifest is unauthenticated, like the notice: a disclosure
    // behind a login is not a disclosure.
    let response = request(&kit.router, Method::GET, "/v1/privacy/manifest", None).await;
    assert_eq!(response.status, StatusCode::OK);
    let manifest = response.json();
    let holds = manifest["holds"].as_array().expect("holds");
    for table in ["telemetry_events", "telemetry_modules"] {
        let entry = holds
            .iter()
            .find(|entry| entry["table"] == table)
            .unwrap_or_else(|| panic!("{table} is not published under holds: {holds:?}"));
        assert_eq!(entry["module"], "telemetry", "{entry}");
        assert_eq!(entry["kind"], "usage", "{entry}");
        assert_eq!(entry["on_erasure"]["action"], "erase", "{entry}");
        let description = entry["description"].as_str().expect("description");
        assert!(
            description.contains("install id"),
            "the entry has to say the subject is the install id: {description}"
        );
    }
    assert_eq!(manifest["holds_personal_data"], true);
}

/// The erasure the declarations promise: keyed on the install id the
/// person's own client prints, it deletes exactly their rows and leaves
/// another install untouched.
#[pollster::test]
async fn an_erasure_keyed_on_an_install_id_deletes_exactly_that_installs_rows() {
    let kit = privacy_kit();
    report(&kit, ALICE, "run", 3).await;
    report(&kit, ALICE, "build", 1).await;
    report(&kit, BOB, "run", 5).await;

    assert_eq!(
        rows_for(&kit, ALICE).await,
        (2, 1),
        "two event buckets, one module row"
    );
    assert_eq!(rows_for(&kit, BOB).await, (1, 1));

    // The preview names both tables and both plans an erase.
    let preview = request_as(
        &kit.router,
        Method::POST,
        "/v1/privacy/erase",
        ADMIN,
        Some(&format!(r#"{{"subject":"{ALICE}"}}"#)),
    )
    .await;
    let plan = preview.json()["plan"].as_array().expect("plan").clone();
    for table in ["telemetry_events", "telemetry_modules"] {
        let entry = plan
            .iter()
            .find(|row| row["table"] == table)
            .unwrap_or_else(|| panic!("{table} is not in the plan: {plan:?}"));
        assert_eq!(entry["action"], "erase", "{entry}");
    }

    erase(&kit, ALICE).await;

    assert_eq!(
        rows_for(&kit, ALICE).await,
        (0, 0),
        "the erasure removed every row keyed on the install id"
    );
    assert_eq!(
        rows_for(&kit, BOB).await,
        (1, 1),
        "the erasure took another install's rows with it"
    );
}
