//! Issue #265: the declarations, proved against the module that reads them.
//!
//! `Module::personal_data()` is a promise about behaviour that lives in
//! another crate — `cratefield-module-privacy` plans an export and an erasure
//! from it — so asserting the list against itself would prove nothing. These
//! compose the two modules the way a venture does and drive the routes.
//!
//! The entry is the one table in the harness that is **anonymised** rather
//! than erased, and migration `0005` exists for it: `email` and
//! `email_normalized` were `NOT NULL`, so the `SET … = NULL` the declaration
//! promises would have failed on the first request anybody made.

use axum::http::{Method, StatusCode, header};
use cratefield_core::{Config, MapConfig, Statement};
use cratefield_module_privacy::Privacy;
use cratefield_module_waitlist::Waitlist;
use cratefield_testing::TestHarness;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const ALICE: &str = "01HCWAITLISTALICE0000000001";
const BOB: &str = "01HCWAITLISTBOB000000000002";

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
            Box::new(Waitlist::new().products(["launch"])),
            Box::new(Privacy::new()),
        ],
        move |ports| {
            ports.config = Arc::clone(&config);
        },
    )
}

/// One confirmed entry, written straight to the database: the point under test
/// is what the declaration reaches, not how the row got there.
#[allow(clippy::too_many_arguments)]
async fn seed(
    kit: &TestHarness,
    id: &str,
    email: &str,
    position: i64,
    referral_code: &str,
    referred_by: Option<&str>,
    referrals: i64,
) {
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO waitlist_entries (id, email, email_normalized, product, status, \
             position, referral_code, referred_by, referrals, answers, created_at, confirmed_at, \
             generation) VALUES (?, ?, ?, 'launch', 'confirmed', ?, ?, ?, ?, ?, ?, ?, 1)"
                .to_owned(),
            vec![
                id.into(),
                email.into(),
                email.into(),
                position.into(),
                referral_code.into(),
                referred_by.map(str::to_owned).into(),
                referrals.into(),
                r#"{"role":"founder"}"#.into(),
                "2026-01-01T00:00:00Z".into(),
                "2026-01-01T00:00:00Z".into(),
            ],
        ))
        .await
        .expect("seeding a waitlist entry");
}

/// One entry, as a JSON object, so an assertion can name the column.
async fn entry(kit: &TestHarness, id: &str) -> Value {
    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT email, email_normalized, answers, position, referral_code, referred_by, \
             referrals, product, status FROM waitlist_entries WHERE id = ?"
                .to_owned(),
            vec![id.into()],
        ))
        .await
        .expect("reading the entry");
    let row = rows.first().unwrap_or_else(|| panic!("{id} is gone"));
    let mut object = serde_json::Map::new();
    for column in [
        "email",
        "email_normalized",
        "answers",
        "referral_code",
        "referred_by",
        "product",
        "status",
    ] {
        object.insert(
            column.to_owned(),
            row.get::<String>(column).map_or(Value::Null, Value::String),
        );
    }
    for column in ["position", "referrals"] {
        object.insert(
            column.to_owned(),
            row.get::<i64>(column).map_or(Value::Null, Value::from),
        );
    }
    Value::Object(object)
}

struct Answer {
    status: StatusCode,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {}", self.text()))
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn send(
    kit: &TestHarness,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Answer {
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let payload = match body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(json.to_owned())
        }
        None => axum::body::Body::empty(),
    };
    let response = kit
        .router
        .clone()
        .oneshot(builder.body(payload).expect("request builds"))
        .await
        .expect("router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads")
        .to_vec();
    Answer { status, body }
}

/// Runs the two-step erasure and returns the confirm answer.
async fn erase(kit: &TestHarness, subject: &str) -> Answer {
    let preview = send(
        kit,
        Method::POST,
        "/v1/privacy/erase",
        Some(ADMIN),
        Some(&format!(r#"{{"subject":"{subject}"}}"#)),
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text());
    let token = preview.json()["confirm_token"].clone();
    send(
        kit,
        Method::POST,
        "/v1/privacy/erase/confirm",
        Some(ADMIN),
        Some(&format!(r#"{{"token":{token}}}"#)),
    )
    .await
}

#[pollster::test]
async fn an_erasure_takes_the_person_out_of_the_entry_and_leaves_the_queue_intact() {
    // The whole reason `Disposition::Anonymise` and migration 0005 exist.
    // Deleting the row would take a number out of a dense join order that is
    // never recomputed and orphan the referral Bob was credited through.
    let kit = privacy_kit();
    seed(&kit, ALICE, "alice@example.com", 1, "ALICECODE", None, 2).await;
    seed(
        &kit,
        BOB,
        "bob@example.com",
        2,
        "BOBCODE00",
        Some("ALICECODE"),
        0,
    )
    .await;

    let confirm = erase(&kit, ALICE).await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.text());
    assert_eq!(confirm.json()["verified"], true);

    let alice = entry(&kit, ALICE).await;
    // The person is gone from the row.
    assert_eq!(alice["email"], Value::Null, "{alice}");
    assert_eq!(alice["email_normalized"], Value::Null, "{alice}");
    assert_eq!(alice["answers"], Value::Null, "{alice}");
    // The row, and everybody else's arithmetic, is not.
    assert_eq!(alice["position"], 1, "the queue lost a number: {alice}");
    assert_eq!(alice["referrals"], 2, "a credit was rewritten: {alice}");
    assert_eq!(
        alice["referral_code"], "ALICECODE",
        "Bob's referral now points at nothing: {alice}"
    );
    assert_eq!(alice["product"], "launch", "{alice}");

    let bob = entry(&kit, BOB).await;
    assert_eq!(bob["email"], "bob@example.com", "Bob was erased too: {bob}");
    assert_eq!(bob["referred_by"], "ALICECODE", "{bob}");
    assert_eq!(bob["position"], 2, "{bob}");
}

#[pollster::test]
async fn the_preview_says_anonymise_and_names_the_columns() {
    // An operator about to erase reads what will happen before it happens,
    // and "three columns are nulled" is a different promise from "the row
    // goes".
    let kit = privacy_kit();
    seed(&kit, ALICE, "alice@example.com", 1, "ALICECODE", None, 0).await;

    let preview = send(
        &kit,
        Method::POST,
        "/v1/privacy/erase",
        Some(ADMIN),
        Some(&format!(r#"{{"subject":"{ALICE}"}}"#)),
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text());
    let body = preview.json();
    let plan = body["plan"].as_array().expect("plan");
    let entries = plan
        .iter()
        .find(|row| row["table"] == "waitlist_entries")
        .expect("waitlist_entries planned");
    assert_eq!(entries["action"], "anonymise", "{entries}");
    assert_eq!(entries["rows"], 1, "{entries}");
    assert_eq!(
        entries["columns"],
        serde_json::json!(["email", "email_normalized", "answers"]),
        "{entries}"
    );

    // The two tables with no subject column are not in the plan at all.
    let planned: Vec<&str> = plan
        .iter()
        .filter_map(|row| row["table"].as_str())
        .collect();
    assert_eq!(planned, ["waitlist_entries"], "{plan:?}");
}

#[pollster::test]
async fn an_export_carries_the_entry() {
    let kit = privacy_kit();
    seed(&kit, ALICE, "alice@example.com", 1, "ALICECODE", None, 2).await;

    let response = send(
        &kit,
        Method::GET,
        &format!("/v1/privacy/export?subject={ALICE}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    let table = body["tables"]
        .as_array()
        .expect("tables")
        .iter()
        .find(|t| t["table"] == "waitlist_entries")
        .expect("waitlist_entries exported")
        .clone();
    let row = &table["rows"][0];
    assert_eq!(row["email"], "alice@example.com", "{row}");
    assert_eq!(row["position"], 1, "{row}");
    assert_eq!(row["answers"], r#"{"role":"founder"}"#, "{row}");
    // Nothing in this table is a bearer capability, so nothing is withheld.
    assert_eq!(table["kind"], "contact");
}

#[pollster::test]
async fn the_manifest_says_what_the_two_keyless_tables_hold() {
    // "No declaration", "nothing reachable here" and "holds data erasure
    // cannot reach" are three different claims, and the manifest must not
    // merge the last two (issue #274): the cooldown holds the address, the
    // lock names nobody.
    let kit = privacy_kit();
    let response = send(&kit, Method::GET, "/v1/privacy/manifest", None, None).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();

    let not_personal = body["not_personal"].as_array().expect("not_personal");
    let reason = |table: &str| -> String {
        not_personal
            .iter()
            .find(|entry| entry["table"] == table)
            .unwrap_or_else(|| panic!("{table} is not published at all: {not_personal:?}"))["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };

    // The cooldown holds an address, so it must never sit in this bucket —
    // that would tell the subject a table keyed on their address holds
    // nothing about anybody (issue #274). It is published as unreachable.
    assert!(
        not_personal
            .iter()
            .all(|entry| entry["table"] != "waitlist_send_cooldown"),
        "the cooldown holds the address; it cannot be published as not personal: {not_personal:?}"
    );
    let unreachable = body["unreachable"].as_array().expect("unreachable");
    let cooldown = unreachable
        .iter()
        .find(|entry| entry["table"] == "waitlist_send_cooldown")
        .unwrap_or_else(|| panic!("cooldown not published as unreachable: {unreachable:?}"))
        .clone();
    assert_eq!(cooldown["kind"], "contact");
    assert!(
        cooldown["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot match"),
        "the cooldown reason has to say why erasure cannot reach it: {cooldown}"
    );

    let lock = reason("waitlist_position_lock");
    assert!(
        lock.contains("nobody is named"),
        "the lock reason has to say it names nobody: {lock}"
    );

    let entries = body["holds"]
        .as_array()
        .expect("holds")
        .iter()
        .find(|entry| entry["table"] == "waitlist_entries")
        .expect("waitlist_entries published")
        .clone();
    assert_eq!(entries["on_erasure"]["action"], "anonymise", "{entries}");
    assert_eq!(body["holds_personal_data"], true);
}
