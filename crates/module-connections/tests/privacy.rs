//! The personal-data declaration, proved against the module that reads it
//! (issue #624, after the pattern issue #265 established).
//!
//! `Module::personal_data()` is a promise about another crate's behaviour:
//! `cratefield-module-privacy` publishes the manifest and plans erasures from
//! it, so asserting the list against itself would prove nothing. These compose
//! the two modules the way a venture does and drive the routes — the manifest
//! must publish both tables under `holds` with an `erase`, and an erasure
//! keyed on a person's subject must delete exactly their rows across both
//! tables and nobody else's.

mod support;

use axum::http::{Method, StatusCode};
use cratefield_core::Statement;
use cratefield_module_privacy::Privacy;
use cratefield_testing::{request, request_as};

use support::{ADMIN, RETURN_TO, Spec, begin, connect, fixture_with};

/// A fixture with Privacy mounted alongside Connections, on every dialect.
fn privacy_fixture() -> support::Fixture {
    fixture_with(&Spec::default(), || vec![Box::new(Privacy::new())])
}

/// How many rows a table holds for one subject.
async fn rows_for(kit: &support::Kit, table: &str, subject: &str) -> i64 {
    let rows = kit
        .harness
        .db
        .query(&Statement::with_values(
            format!("SELECT COUNT(*) AS n FROM {table} WHERE subject = ?"),
            vec![subject.into()],
        ))
        .await
        .expect("counting subject rows");
    rows.first().and_then(|row| row.get("n")).unwrap_or(0)
}

/// The manifest is the promise: both tables are published under `holds`, as
/// identifiers, erased on request — never quietly in `not_personal`.
#[pollster::test]
async fn the_manifest_publishes_both_tables_as_erased_identifiers() {
    for kit in privacy_fixture().kits {
        let response = request(
            &kit.harness.router,
            Method::GET,
            "/v1/privacy/manifest",
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{:?}", response.body());
        let manifest = response.json();
        let holds = manifest["holds"].as_array().expect("holds").clone();
        for table in ["connection", "connection_state"] {
            let entry = holds
                .iter()
                .find(|entry| entry["table"] == table)
                .unwrap_or_else(|| panic!("`{table}` is not published under holds: {holds:?}"));
            assert_eq!(entry["module"], "connections", "{entry}");
            assert_eq!(entry["kind"], "identifier", "{entry}");
            assert_eq!(entry["on_erasure"]["action"], "erase", "{entry}");
            assert!(
                !manifest["not_personal"]
                    .as_array()
                    .expect("not_personal")
                    .iter()
                    .any(|entry| entry["table"] == table),
                "`{table}` must not be declared not personal"
            );
        }
        // The promises the descriptions make are the ones the schema keeps.
        let connection = holds
            .iter()
            .find(|entry| entry["table"] == "connection")
            .expect("the connection entry");
        assert!(
            connection["description"]
                .as_str()
                .expect("description")
                .contains("ciphertext"),
            "the connection entry must say the tokens are only ciphertext: {connection}"
        );
        assert_eq!(manifest["holds_personal_data"], true);
    }
}

/// The erasure the declaration promises: keyed on a subject it deletes
/// exactly their rows across both the connections and the states in flight,
/// and leaves another person's untouched.
#[pollster::test]
async fn an_erasure_keyed_on_the_subject_deletes_exactly_their_rows() {
    for kit in privacy_fixture().kits {
        kit.clock.reset();
        kit.http.reset();

        // Alice: two connections and one attempt still in flight. Bob: one of
        // each, which the erasure must not touch. Each `connect` also leaves
        // its spent state row behind until the purge pass sweeps it, so both
        // people carry one state per connection plus the in-flight one.
        connect(&kit, "alice", "x").await;
        connect(&kit, "alice", "x").await;
        connect(&kit, "bob", "x").await;
        let _ = begin(&kit, "alice", "x", RETURN_TO).await;
        let _ = begin(&kit, "bob", "x", RETURN_TO).await;

        assert_eq!(rows_for(&kit, "connection", "alice").await, 2);
        assert_eq!(rows_for(&kit, "connection_state", "alice").await, 3);
        assert_eq!(rows_for(&kit, "connection", "bob").await, 1);
        assert_eq!(rows_for(&kit, "connection_state", "bob").await, 2);

        let preview = request_as(
            &kit.harness.router,
            Method::POST,
            "/v1/privacy/erase",
            ADMIN,
            Some(r#"{"subject":"alice"}"#),
        )
        .await;
        assert_eq!(preview.status, StatusCode::OK, "{:?}", preview.body());
        let plan = preview.json()["plan"].as_array().expect("plan").clone();
        for table in ["connection", "connection_state"] {
            let entry = plan
                .iter()
                .find(|row| row["table"] == table)
                .unwrap_or_else(|| panic!("`{table}` is not in the plan: {plan:?}"));
            assert_eq!(entry["action"], "erase", "{entry}");
        }

        let token = preview.json()["confirm_token"].clone();
        let confirmed = request_as(
            &kit.harness.router,
            Method::POST,
            "/v1/privacy/erase/confirm",
            ADMIN,
            Some(&format!(r#"{{"token":{token}}}"#)),
        )
        .await;
        assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.body());
        assert_eq!(confirmed.json()["verified"], true, "{:?}", confirmed.body());

        assert_eq!(
            rows_for(&kit, "connection", "alice").await,
            0,
            "the erasure left alice's connection behind"
        );
        assert_eq!(
            rows_for(&kit, "connection_state", "alice").await,
            0,
            "the erasure left alice's state behind"
        );
        assert_eq!(
            rows_for(&kit, "connection", "bob").await,
            1,
            "the erasure took another person's connection"
        );
        assert_eq!(
            rows_for(&kit, "connection_state", "bob").await,
            2,
            "the erasure took another person's state"
        );
    }
}
