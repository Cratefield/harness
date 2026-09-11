//! Issue #265: the declaration, proved against the module that reads it.
//!
//! `Module::personal_data()` is a promise about behaviour that lives in
//! another crate — `cratefield-module-privacy` plans an export and an erasure
//! from it — so asserting the list against itself would prove nothing. These
//! compose the two modules the way a venture does and drive the routes.

use axum::http::{Method, StatusCode, header};
use cratefield_core::{Config, MapConfig, Statement};
use cratefield_module_email_signup::EmailSignup;
use cratefield_module_privacy::Privacy;
use cratefield_testing::TestHarness;
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";

/// The revocable unsubscribe token (issue #137, ADR 0014). Whoever holds the
/// value can unsubscribe that subscription, which is exactly why an export
/// must name the column and not copy it.
const TOKEN: &str = "01HCUNSUBSCRIBEBEARERCAPABILITY";

fn privacy_kit() -> TestHarness {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
        (
            "HARNESS_SECRET".to_owned(),
            "cratefield-testing-dummy-secret-0123456789".to_owned(),
        ),
    ]));
    TestHarness::with_ports(
        vec![Box::new(EmailSignup::new()), Box::new(Privacy::new())],
        move |ports| {
            ports.config = Arc::clone(&config);
        },
    )
}

/// One subscriber, written straight to the database: the point under test is
/// what the declaration reaches, not how the row got there.
async fn seed(kit: &TestHarness, id: &str, email: &str, token: &str) {
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO subscribers (id, email, email_normalized, status, source, locale, \
             confirmed_at, unsubscribed_at, created_at, updated_at, generation, \
             unsubscribe_token) VALUES (?, ?, ?, 'confirmed', 'launch', 'en', ?, NULL, ?, ?, 1, ?)"
                .to_owned(),
            vec![
                id.into(),
                email.into(),
                email.into(),
                "2026-01-01T00:00:00Z".into(),
                "2026-01-01T00:00:00Z".into(),
                "2026-01-01T00:00:00Z".into(),
                token.into(),
            ],
        ))
        .await
        .expect("seeding a subscriber");
}

async fn rows_for(kit: &TestHarness, id: &str) -> i64 {
    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT COUNT(*) AS n FROM subscribers WHERE id = ?".to_owned(),
            vec![id.into()],
        ))
        .await
        .expect("counting subscribers");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or(-1)
}

/// A response, read into memory. `TestResponse::of` is crate-private, so the
/// two lines it would have saved are here instead.
struct Answer {
    status: StatusCode,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {}", self.text()))
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A request, optionally carrying the admin bearer token.
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

#[pollster::test]
async fn an_export_carries_the_subscription_and_never_the_unsubscribe_token() {
    let kit = privacy_kit();
    seed(
        &kit,
        "01HCSUBSCRIBER0000000000001",
        "nick@example.com",
        TOKEN,
    )
    .await;

    let response = send(
        &kit,
        Method::GET,
        "/v1/privacy/export?subject=01HCSUBSCRIBER0000000000001",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    let raw = response.text();
    assert!(
        !raw.contains(TOKEN),
        "the export copied the revocable unsubscribe token, which is a bearer capability"
    );

    let body = response.json();
    let table = body["tables"]
        .as_array()
        .expect("tables")
        .iter()
        .find(|t| t["table"] == "subscribers")
        .expect("subscribers exported")
        .clone();
    let row = &table["rows"][0];
    // Named, not dropped: "we hold nothing there" is the one answer a subject
    // access request must not give untruthfully.
    assert_eq!(row["unsubscribe_token"], "[redacted]", "{row}");
    // Everything else in the row is the subscriber's own, and is theirs.
    assert_eq!(row["email"], "nick@example.com", "{row}");
    assert_eq!(row["source"], "launch", "{row}");
    assert_eq!(row["locale"], "en", "{row}");
}

#[pollster::test]
async fn an_erasure_removes_the_subscriber_and_leaves_everyone_else() {
    let kit = privacy_kit();
    seed(
        &kit,
        "01HCSUBSCRIBER0000000000001",
        "nick@example.com",
        TOKEN,
    )
    .await;
    seed(
        &kit,
        "01HCSUBSCRIBER0000000000002",
        "other@example.com",
        "01HCOTHERTOKEN00000000000000",
    )
    .await;

    let preview = send(
        &kit,
        Method::POST,
        "/v1/privacy/erase",
        Some(ADMIN),
        Some(r#"{"subject":"01HCSUBSCRIBER0000000000001"}"#),
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK);
    let body = preview.json();
    let plan = body["plan"].as_array().expect("plan");
    let entry = plan
        .iter()
        .find(|row| row["table"] == "subscribers")
        .expect("subscribers planned");
    assert_eq!(entry["action"], "erase", "{entry}");
    assert_eq!(entry["rows"], 1, "{entry}");
    // The preview writes nothing.
    assert_eq!(rows_for(&kit, "01HCSUBSCRIBER0000000000001").await, 1);

    let confirm = send(
        &kit,
        Method::POST,
        "/v1/privacy/erase/confirm",
        Some(ADMIN),
        Some(&format!(r#"{{"token":{}}}"#, body["confirm_token"])),
    )
    .await;
    assert_eq!(confirm.status, StatusCode::OK);
    assert_eq!(confirm.json()["verified"], true);

    assert_eq!(rows_for(&kit, "01HCSUBSCRIBER0000000000001").await, 0);
    assert_eq!(
        rows_for(&kit, "01HCSUBSCRIBER0000000000002").await,
        1,
        "the other subscriber was erased too"
    );
}

#[pollster::test]
async fn the_manifest_names_the_column_it_refuses_to_copy() {
    // A column an export will not copy is still something the deployment
    // holds, so the published page names it. A reader learns "held, not
    // handed over" rather than learning nothing.
    let kit = privacy_kit();
    let response = send(&kit, Method::GET, "/v1/privacy/manifest", None, None).await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();

    let subscribers = body["holds"]
        .as_array()
        .expect("holds")
        .iter()
        .find(|entry| entry["table"] == "subscribers")
        .expect("subscribers published")
        .clone();
    assert_eq!(subscribers["module"], "email-signup");
    assert_eq!(subscribers["kind"], "contact");
    assert_eq!(subscribers["on_erasure"]["action"], "erase");
    assert_eq!(subscribers["redacted"][0], "unsubscribe_token");
    assert!(
        subscribers["description"]
            .as_str()
            .is_some_and(|text| text.contains("address")),
        "the published sentence has to say what is held: {subscribers}"
    );
    assert_eq!(body["holds_personal_data"], true);
}
