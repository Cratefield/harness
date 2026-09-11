//! Issue #288: the `venture` declaration proved against the module that
//! reads it.
//!
//! `venture.account_id` is a ULID pointing at `account (id)`, while the
//! request is made with the operator's Google-verified address — the value
//! `allowlist.value` and `account.identity` hold. The declaration reaches
//! the rows through a `subject_via` join, and these tests compose the
//! console with `module-privacy` the way a venture does, so a removed join
//! turns them red instead of leaving a receipt that lies.

use axum::http::{Method, StatusCode, header};
use cratefield_console::Console;
use cratefield_core::{Config, MapConfig, Statement};
use cratefield_module_privacy::Privacy;
use cratefield_testing::TestHarness;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
const AT: &str = "2026-01-01T00:00:00Z";

fn privacy_kit() -> TestHarness {
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs([
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
        (
            "HARNESS_SECRET".to_owned(),
            "cratefield-testing-dummy-secret-0123456789".to_owned(),
        ),
    ]));
    TestHarness::with_ports(
        vec![Box::new(Console), Box::new(Privacy::new())],
        move |ports| {
            ports.config = Arc::clone(&config);
        },
    )
}

/// Two operators, each with an allowlist entry, an account and one venture,
/// written straight to the database: the point under test is what the
/// declarations reach, not how the rows got there. Requests are made with
/// the **address**, because that is the identifier every other set in the
/// module matches — the ULID in `venture.account_id` is never in the request.
async fn seed(kit: &TestHarness, email: &str) {
    let rows: Vec<(&str, &str, Vec<_>)> = vec![
        (
            "allowlist",
            "INSERT INTO allowlist (value, kind, note, added_by, added_at) \
             VALUES (?, 'email', '', 'root', ?)",
            vec![email.into(), AT.into()],
        ),
        (
            "allowlist_audit",
            "INSERT INTO allowlist_audit (id, action, value, kind, actor, at) \
             VALUES (?, 'allow', ?, 'email', 'root', ?)",
            vec![format!("aud-{email}").into(), email.into(), AT.into()],
        ),
        (
            "account",
            "INSERT INTO account (id, identity, name, status, created_at) \
             VALUES (?, ?, 'Alex', 'active', ?)",
            vec![format!("acc-{email}").into(), email.into(), AT.into()],
        ),
        (
            "venture",
            "INSERT INTO venture (id, account_id, slug, subdomain, module_set, status, \
             tenant_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?, 'cms', 'live', ?, ?, ?)",
            vec![
                format!("ven-{email}").into(),
                format!("acc-{email}").into(),
                format!("slug-{email}").into(),
                format!("sub-{email}").into(),
                format!("ten-{email}").into(),
                AT.into(),
                AT.into(),
            ],
        ),
    ];
    for (table, sql, values) in rows {
        kit.db
            .execute(&Statement::with_values(sql.to_owned(), values))
            .await
            .unwrap_or_else(|err| panic!("seeding {table} failed: {err}"));
    }
}

async fn scalar(kit: &TestHarness, sql: &str, value: &str) -> i64 {
    let rows = kit
        .db
        .query(&Statement::with_values(sql.to_owned(), vec![value.into()]))
        .await
        .unwrap_or_else(|err| panic!("counting failed: {err}"));
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or(-1)
}

async fn venture_count(kit: &TestHarness, email: &str) -> i64 {
    scalar(
        kit,
        "SELECT COUNT(*) AS n FROM venture \
         WHERE account_id IN (SELECT id FROM account WHERE identity = ?)",
        email,
    )
    .await
}

async fn count(kit: &TestHarness, sql: &str, value: &str) -> i64 {
    scalar(kit, sql, value).await
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

fn table<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["tables"]
        .as_array()
        .expect("tables")
        .iter()
        .find(|t| t["table"] == name)
        .unwrap_or_else(|| panic!("{name} missing from the export: {body}"))
}

/// A request made with the operator's address must reach the venture rows
/// keyed on the account's ULID. Before the join, the declaration promised
/// "the backends you created" and the export answered with an empty set.
#[pollster::test]
async fn an_export_made_with_the_operators_address_returns_their_ventures() {
    let kit = privacy_kit();
    seed(&kit, ALICE).await;
    seed(&kit, BOB).await;

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
    let ventures = table(&body, "venture")["rows"]
        .as_array()
        .expect("venture rows is an array");
    assert_eq!(ventures.len(), 1, "{}", response.text());
    assert_eq!(ventures[0]["slug"], format!("slug-{ALICE}"));
    assert_eq!(ventures[0]["subdomain"], format!("sub-{ALICE}"));

    // The join must not leak across accounts: Bob's address reaches his
    // venture and only his.
    let bob = send(
        &kit,
        Method::GET,
        &format!("/v1/privacy/export?subject={BOB}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(bob.status, StatusCode::OK, "{}", bob.text());
    let bob_body = bob.json();
    let bob_ventures = table(&bob_body, "venture")["rows"]
        .as_array()
        .expect("venture rows is an array");
    assert_eq!(bob_ventures.len(), 1);
    assert_eq!(bob_ventures[0]["slug"], format!("slug-{BOB}"));
}

/// The erasure plan counts the venture through the same join the delete
/// runs, and the delete runs **before** the account delete — the catalogue
/// order that the join makes load-bearing.
#[pollster::test]
async fn an_erasure_with_the_operators_address_removes_the_ventures_before_the_account() {
    let kit = privacy_kit();
    seed(&kit, ALICE).await;
    seed(&kit, BOB).await;

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
    let entry = |name: &str| {
        body["plan"]
            .as_array()
            .expect("plan")
            .iter()
            .find(|row| row["table"] == name)
            .unwrap_or_else(|| panic!("{name} missing from the preview: {body}"))
    };
    assert_eq!(
        entry("venture")["rows"],
        1,
        "the plan did not count the venture through the join"
    );
    assert_eq!(entry("venture")["action"], "erase");
    assert_eq!(entry("account")["rows"], 1);
    // The preview writes nothing.
    assert_eq!(venture_count(&kit, ALICE).await, 1);

    let confirm = send(
        &kit,
        Method::POST,
        "/v1/privacy/erase/confirm",
        Some(ADMIN),
        Some(&format!(r#"{{"token":{}}}"#, body["confirm_token"])),
    )
    .await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.text());
    assert_eq!(
        confirm.json()["verified"],
        true,
        "verify did not accept the erasure"
    );

    // Order, not just end state. The statements run as one batch; both
    // dialects let a statement see its own transaction's writes, so if the
    // account delete ran first, the join's subquery —
    // `account_id IN (SELECT id FROM account WHERE identity = ?)` — would
    // find no account rows and the venture delete would remove nothing.
    // Venture rows at zero here can only mean the venture delete found its
    // rows while the account row was still there.
    assert_eq!(
        venture_count(&kit, ALICE).await,
        0,
        "the venture rows survived: the account delete ran first, and the \
         verify receipt above is lying"
    );
    assert_eq!(
        count(
            &kit,
            "SELECT COUNT(*) AS n FROM account WHERE identity = ?",
            ALICE
        )
        .await,
        0,
        "the account row survived"
    );
    // verify reported nothing remaining: `verified: true` above is only
    // reachable when the re-count through the join came back empty. A verify
    // that matched `venture.account_id` against the address directly would
    // count zero through the join it ignored, so the receipt is only trusted
    // alongside the counts here.

    // Another subject loses nothing.
    assert_eq!(venture_count(&kit, BOB).await, 1);
    assert_eq!(
        count(
            &kit,
            "SELECT COUNT(*) AS n FROM account WHERE identity = ?",
            BOB
        )
        .await,
        1
    );

    // The audit row is Retain, and retention is honest: the record of who
    // let Alice in outlives the erasure on purpose.
    assert_eq!(
        count(
            &kit,
            "SELECT COUNT(*) AS n FROM allowlist_audit WHERE value = ?",
            ALICE
        )
        .await,
        1
    );
}
