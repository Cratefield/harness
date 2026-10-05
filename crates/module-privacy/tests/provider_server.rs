//! The provider server (issue #656): this deployment answering the signed
//! protocol it also calls out on.
//!
//! Every request below is signed the way a real caller signs it — with
//! `cratefield_testing::sign_stripe_style`, an independent implementation of
//! the same scheme the client writes — and sent with no admin token, because
//! the HMAC is the whole authorisation and a bearer the caller cannot hold
//! would prove nothing. The refusals are asserted on the status and on what
//! the body does *not* say: an endpoint that says "your signature was stale"
//! and "your signature was wrong" has told a prober which of the two it got
//! right.

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use cratefield_core::MapConfig;
use cratefield_core::{
    ConfigError, DataKind, Disposition, Migrations, Module, ModuleContext, PersonalDataSet, Port,
    SqlMigration, Statement,
};
use cratefield_module_privacy::{HttpProvider, Privacy, SIGNATURE_HEADER};
use cratefield_testing::{FakePrivacyProvider, TestHarness, request_as, sign_stripe_style};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
/// The shared secret this deployment serves with. The same value the outbound
/// side would put in a provider's own configuration.
const SECRET: &str = "privacy-server-secret-0123456789";
const SECRET_ENV: &str = "PRIVACY_SERVER_SECRET";
const WRONG_SECRET: &str = "a-different-secret-0123456789abcdef";
const SUBJECT: &str = "acct-1";

const EXPORT: &str = "/v1/privacy/provider/export";
const PLAN: &str = "/v1/privacy/provider/erase/plan";
const APPLY: &str = "/v1/privacy/provider/erase/apply";

/// A module holding three tables with three different dispositions, so the
/// protocol's whole action vocabulary is exercised against real
/// declarations rather than a hand-written fixture list.
#[derive(Clone, Default)]
struct Ledger;

const MIGRATION: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    "CREATE TABLE accounts (
              id TEXT PRIMARY KEY,
              email TEXT NOT NULL
          );
          CREATE TABLE sessions (
              id TEXT PRIMARY KEY,
              account_id TEXT NOT NULL,
              device_token TEXT NOT NULL
          );
          CREATE TABLE invoices (
              id TEXT PRIMARY KEY,
              account_id TEXT NOT NULL,
              total INTEGER NOT NULL
          );",
);

const PERSONAL: &[PersonalDataSet] = &[
    PersonalDataSet {
        table: "accounts",
        subject: "id",
        kind: DataKind::Identifier,
        disposition: Disposition::Erase,
        description: "The account itself.",
        redacted: &[],
        subject_via: None,
    },
    PersonalDataSet {
        table: "sessions",
        subject: "account_id",
        kind: DataKind::Usage,
        disposition: Disposition::Erase,
        description: "Devices signed into the account.",
        // The device token is a bearer capability: named, never copied.
        redacted: &["device_token"],
        subject_via: None,
    },
    PersonalDataSet {
        table: "invoices",
        subject: "account_id",
        kind: DataKind::Financial,
        disposition: Disposition::Retain("Tax law requires seven years."),
        description: "Invoices raised to the account.",
        redacted: &[],
        subject_via: None,
    },
];

impl Module for Ledger {
    fn name(&self) -> &'static str {
        "ledger"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["accounts", "sessions", "invoices"]
    }
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        PERSONAL
    }
    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION];
        Migrations::sqlite(&MIGRATIONS)
    }
    fn validate_config(&self, _cfg: &dyn cratefield_core::Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

/// A kit whose privacy module serves the protocol. `Privacy::serve_provider`
/// records the variable; the kit supplies the value.
fn kit() -> TestHarness {
    kit_with_secret(SECRET)
}

/// [`kit`] over a configured secret of the caller's choosing.
fn kit_with_secret(secret: &str) -> TestHarness {
    TestHarness::with_ports(
        vec![
            Box::new(Ledger),
            Box::new(Privacy::new().serve_provider(SECRET_ENV)),
        ],
        move |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("ADMIN_TOKEN", ADMIN),
                (SECRET_ENV, secret),
            ]));
        },
    )
}

/// A deployment whose composed modules declare no personal data at all — a
/// venture that composed the privacy module and has not yet had a module
/// that says anything.
fn empty_kit() -> TestHarness {
    TestHarness::with_ports(
        vec![Box::new(Privacy::new().serve_provider(SECRET_ENV))],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("ADMIN_TOKEN", ADMIN),
                (SECRET_ENV, SECRET),
            ]));
        },
    )
}

/// Wall-clock seconds, for a signature a test signs *now*.
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs()),
    )
    .unwrap_or(i64::MAX)
}

/// The `Cratefield-Signature` headers a caller sends for `body` at `at`,
/// signed by `secret` — the same shape `crate::provider` writes.
fn signature(secret: &str, at: i64, body: &[u8]) -> HeaderMap {
    sign_stripe_style(SIGNATURE_HEADER, secret, at, body)
}

/// A POST through the router with no network, carrying `headers` and a raw
/// `body` — the bytes the signature covers, never re-serialised.
async fn post(kit: &TestHarness, path: &str, body: &str, headers: HeaderMap) -> (StatusCode, String) {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in &headers {
        request = request.header(name, value);
    }
    let response = kit
        .router
        .clone()
        .oneshot(request.body(Body::from(body.to_owned())).expect("request builds"))
        .await
        .expect("router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A correctly signed call to `path`.
async fn signed(kit: &TestHarness, path: &str, body: &str) -> (StatusCode, String) {
    post(kit, path, body, signature(SECRET, now(), body.as_bytes())).await
}

/// The body the client's `request_body` writes for every one of the three
/// calls.
fn call(subject: &str) -> String {
    json!({ "subject": subject, "request_id": "erase_abc123" }).to_string()
}

async fn seed(kit: &TestHarness) {
    for (table, columns, values) in [
        ("accounts", "id, email", "'acct-1', 'a@example.test'"),
        ("accounts", "id, email", "'acct-2', 'b@example.test'"),
        (
            "sessions",
            "id, account_id, device_token",
            "'s1', 'acct-1', 'tok-live-0123'",
        ),
        (
            "sessions",
            "id, account_id, device_token",
            "'s2', 'acct-2', 'tok-live-4567'",
        ),
        ("invoices", "id, account_id, total", "'i1', 'acct-1', 42"),
        ("invoices", "id, account_id, total", "'i2', 'acct-2', 17"),
    ] {
        kit.db
            .execute(&Statement::new(format!(
                "INSERT INTO {table} ({columns}) VALUES ({values})"
            )))
            .await
            .expect("seed");
    }
}

async fn count(kit: &TestHarness, table: &str, subject: &str) -> i64 {
    let column = if table == "accounts" { "id" } else { "account_id" };
    let rows = kit
        .db
        .query(&Statement::with_values(
            format!("SELECT COUNT(*) AS n FROM {table} WHERE {column} = ?"),
            vec![subject.into()],
        ))
        .await
        .expect("count");
    rows.first().and_then(|row| row.get("n")).unwrap_or(0)
}

/// The plan or export section for `table`, or a panic naming what the answer
/// actually held.
fn section<'a>(sections: &'a [Value], table: &str) -> &'a Value {
    sections
        .iter()
        .find(|section| section["name"] == table)
        .unwrap_or_else(|| panic!("no section for `{table}` in {sections:?}"))
}

// -------------------------------------------------------------- the export

/// The point of the server: a signed caller gets an answer, and it is the
/// same one an operator gets — every declared table, the declared redaction,
/// and no row belonging to somebody else.
#[pollster::test]
async fn a_signed_export_returns_every_declared_table_for_that_subject() {
    let kit = kit();
    seed(&kit).await;

    let (status, raw) = signed(&kit, EXPORT, &call(SUBJECT)).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    let body: Value = serde_json::from_str(&raw).expect("json");
    let sections = body["sections"].as_array().expect("sections").clone();

    // Every declaration, in the catalog's order.
    assert_eq!(sections.len(), 3, "{sections:?}");
    for (table, section) in [
        ("accounts", &sections[0]),
        ("sessions", &sections[1]),
        ("invoices", &sections[2]),
    ] {
        assert_eq!(section["name"], table);
        assert_eq!(
            section["data"]["rows"].as_array().expect("rows").len(),
            1,
            "{table}: {section:?}"
        );
    }

    // The description is the owning module's own sentence.
    assert_eq!(section(&sections, "accounts")["description"], "The account itself.");
    // The declared credential column is named and not copied.
    let row = &section(&sections, "sessions")["data"]["rows"][0];
    assert_eq!(row["device_token"], "[redacted]", "{row:?}");
    assert_eq!(row["id"], "s1");
    assert!(!raw.contains("tok-live-0123"), "the credential was copied: {raw}");
    assert!(!raw.contains("b@example.test"), "another subject's row: {raw}");

    // The body this deployment's own `/export` renders, for the same subject,
    // over the same catalog — one answer behind two doors.
    let admin = request_as(
        &kit.router,
        Method::GET,
        "/v1/privacy/export?subject=acct-1",
        ADMIN,
        None,
    )
    .await;
    assert_eq!(admin.status, StatusCode::OK);
    let local = admin.json();
    assert_eq!(local["tables"].as_array().expect("tables").len(), 3);
    assert_eq!(local["tables"][1]["rows"][0]["device_token"], "[redacted]");
}

/// An unsigned request, a request signed with somebody else's secret, and
/// two signed with a timestamp outside the 300 s window are the same answer:
/// refused, with nothing in the body about which of the four failed.
#[pollster::test]
async fn an_unsigned_wrongly_signed_or_out_of_window_call_is_refused() {
    let kit = kit();
    seed(&kit).await;
    let body = call(SUBJECT);

    let refused = [
        ("no signature at all", HeaderMap::new()),
        ("the wrong secret", signature(WRONG_SECRET, now(), body.as_bytes())),
        ("an empty secret", signature("", now(), body.as_bytes())),
        (
            "a timestamp 301 s old",
            signature(SECRET, now() - 301, body.as_bytes()),
        ),
        (
            "a timestamp 301 s ahead",
            signature(SECRET, now() + 301, body.as_bytes()),
        ),
        (
            "a signature over a different body",
            signature(SECRET, now(), br#"{"subject":"acct-2"}"#),
        ),
    ];

    for (why, headers) in refused {
        for path in [EXPORT, PLAN, APPLY] {
            let (status, raw) = post(&kit, path, &body, headers.clone()).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{path} accepted a call with {why}: {raw}"
            );
            // Nothing about the secret, the timestamp or the verification.
            assert!(!raw.contains(SECRET), "{path} echoed the secret: {raw}");
            assert!(!raw.contains(WRONG_SECRET), "{path} echoed a secret: {raw}");
            assert!(!raw.contains(SUBJECT), "{path} echoed the subject: {raw}");
        }
    }

    // Refused means refused: nothing was read out and nothing erased.
    assert_eq!(count(&kit, "sessions", SUBJECT).await, 1);
    assert_eq!(count(&kit, "accounts", SUBJECT).await, 1);
}

/// Just inside the window still answers — 300 s is the tolerance, not a
/// round number somebody rounded down.
#[pollster::test]
async fn a_signature_inside_the_window_is_accepted() {
    let kit = kit();
    seed(&kit).await;
    let body = call(SUBJECT);
    for at in [now() - 300, now(), now() + 300] {
        let (status, raw) = post(&kit, EXPORT, &body, signature(SECRET, at, body.as_bytes())).await;
        assert_eq!(status, StatusCode::OK, "a signature at {at} was refused: {raw}");
    }
}

/// A deployment that enabled the server before the secret existed refuses
/// every call rather than opening: an absent secret is not a key that
/// matches everything.
#[pollster::test]
async fn a_deployment_with_no_secret_refuses_every_call() {
    for missing in ["", "   ", "\t\n"] {
        let kit = kit_with_secret(missing);
        seed(&kit).await;
        let body = call(SUBJECT);
        // Even a correctly shaped signature: there is nothing to check it
        // against, so the answer is `not_ready` and the operator learns which
        // variable to set.
        let (status, raw) = post(&kit, EXPORT, &body, signature(SECRET, now(), body.as_bytes())).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "secret {missing:?} opened the door: {raw}"
        );
        let body: Value = serde_json::from_str(&raw).expect("json");
        assert!(
            body["type"].as_str().unwrap_or_default().ends_with("/not-ready"),
            "not a not-ready problem: {raw}"
        );
        assert_eq!(count(&kit, "sessions", SUBJECT).await, 1);
    }

    // And a variable that is absent altogether, rather than set to nothing.
    let kit = TestHarness::with_ports(
        vec![
            Box::new(Ledger),
            Box::new(Privacy::new().serve_provider(SECRET_ENV)),
        ],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
        },
    );
    seed(&kit).await;
    let (status, _) = signed(&kit, EXPORT, &call(SUBJECT)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// The routes exist only where the deployment opted in.
#[pollster::test]
async fn a_deployment_that_did_not_opt_in_has_no_provider_routes() {
    let kit = TestHarness::with_ports(
        vec![Box::new(Ledger), Box::new(Privacy::new())],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("ADMIN_TOKEN", ADMIN),
                (SECRET_ENV, SECRET),
            ]));
        },
    );
    let (status, _) = signed(&kit, EXPORT, &call(SUBJECT)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A malformed body is a `400`, never a `401`: the signature was good, and
/// saying otherwise would tell the caller their signing is broken.
#[pollster::test]
async fn a_signed_but_malformed_body_is_a_bad_request() {
    let kit = kit();
    seed(&kit).await;
    for body in [
        "not json",
        "[]",
        r#"{"request_id":"erase_abc123"}"#,
        r#"{"subject":"   ","request_id":"erase_abc123"}"#,
        r#"{"subject":42}"#,
    ] {
        let (status, raw) = signed(&kit, EXPORT, body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "body {body:?} was not a validation failure: {raw}"
        );
    }
    // `erase/apply` additionally needs the id it is idempotent on.
    let (status, _) = signed(&kit, APPLY, r#"{"subject":"acct-1"}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------- the plan

/// Every declared table, with the action this protocol's vocabulary gives its
/// disposition — and a reason on the one that is kept, because the calling
/// module's validator refuses a `retain` without one and a subject is most
/// entitled to be told what is being kept.
#[pollster::test]
async fn a_plan_reports_every_declared_table_with_its_action() {
    let kit = kit();
    seed(&kit).await;

    let (status, raw) = signed(&kit, PLAN, &call(SUBJECT)).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    let body: Value = serde_json::from_str(&raw).expect("json");
    let sections = body["sections"].as_array().expect("sections").clone();
    assert_eq!(sections.len(), 3, "{sections:?}");

    assert_eq!(section(&sections, "accounts")["action"], "delete");
    assert_eq!(section(&sections, "sessions")["action"], "delete");
    assert_eq!(section(&sections, "invoices")["action"], "retain");
    assert_eq!(
        section(&sections, "invoices")["reason"],
        "Tax law requires seven years."
    );
    // The counts are here for an operator reading the endpoint directly; the
    // protocol itself does not require them.
    assert_eq!(section(&sections, "accounts")["rows"], 1);

    // A preview. Nothing was touched.
    assert_eq!(count(&kit, "accounts", SUBJECT).await, 1);
    assert_eq!(count(&kit, "sessions", SUBJECT).await, 1);
}

/// The exact shapes the *calling* module's validator accepts, fed by this
/// server's answer: `provider_sections` and `plan_sections` in
/// `crate::provider` reject anything else, so the shapes the client requires
/// are what this asserts.
#[pollster::test]
async fn a_whole_answer_carries_only_the_fields_the_client_reads() {
    let kit = kit();
    seed(&kit).await;

    let (_, raw) = signed(&kit, EXPORT, &call(SUBJECT)).await;
    let body: Value = serde_json::from_str(&raw).expect("json");
    for section in body["sections"].as_array().expect("sections") {
        assert!(section["name"].is_string(), "{section:?}");
        assert!(section.get("data").is_some(), "{section:?}");
        assert!(
            matches!(
                section.get("description"),
                None | Some(Value::String(_))
            ),
            "a non-string description is an invalid response: {section:?}"
        );
    }

    let (_, raw) = signed(&kit, PLAN, &call(SUBJECT)).await;
    let body: Value = serde_json::from_str(&raw).expect("json");
    for section in body["sections"].as_array().expect("sections") {
        assert!(section["name"].is_string(), "{section:?}");
        match section["action"].as_str() {
            Some("delete" | "anonymise") => {}
            Some("retain") => assert!(
                section["reason"].as_str().is_some_and(|r| !r.is_empty()),
                "a retain with no reason is an invalid plan section: {section:?}"
            ),
            other => panic!("an action the client rejects: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------- the apply

#[pollster::test]
async fn an_apply_erases_what_the_plan_described_and_verifies_it() {
    let kit = kit();
    seed(&kit).await;

    let (status, raw) = signed(&kit, APPLY, &call(SUBJECT)).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    let body: Value = serde_json::from_str(&raw).expect("json");
    assert_eq!(body["applied"], Value::Bool(true));
    assert_eq!(body["request_id"], "erase_abc123");

    // The `erase` sets are gone; the retained one is not, and nobody else's
    // rows were.
    assert_eq!(count(&kit, "accounts", SUBJECT).await, 0);
    assert_eq!(count(&kit, "sessions", SUBJECT).await, 0);
    assert_eq!(
        count(&kit, "invoices", SUBJECT).await,
        1,
        "a retained row was erased"
    );
    assert_eq!(count(&kit, "accounts", "acct-2").await, 1);
    assert_eq!(count(&kit, "sessions", "acct-2").await, 1);
}

/// The same `request_id` twice is one erasure applied once, and the second
/// call is a `200` — a caller retrying after a dropped connection must not
/// be told the deployment is broken.
#[pollster::test]
async fn a_repeated_apply_with_the_same_request_id_answers_twenty_ok() {
    let kit = kit();
    seed(&kit).await;

    for attempt in 1..=3 {
        let (status, raw) = signed(&kit, APPLY, &call(SUBJECT)).await;
        assert_eq!(status, StatusCode::OK, "attempt {attempt} failed: {raw}");
        assert_eq!(serde_json::from_str::<Value>(&raw).expect("json")["applied"], Value::Bool(true));
    }
    assert_eq!(count(&kit, "accounts", SUBJECT).await, 0);
    assert_eq!(count(&kit, "sessions", SUBJECT).await, 0);
    // And the retained row is still there: a repeat erased it too.
    assert_eq!(count(&kit, "invoices", SUBJECT).await, 1);
}

/// Idempotence is not a cache that short-circuits a genuinely new request:
/// a different id for a different subject erases that subject too.
#[pollster::test]
async fn a_new_request_id_still_does_the_work() {
    let kit = kit();
    seed(&kit).await;

    assert_eq!(signed(&kit, APPLY, &call(SUBJECT)).await.0, StatusCode::OK);
    assert_eq!(count(&kit, "accounts", SUBJECT).await, 0);

    let other = json!({ "subject": "acct-2", "request_id": "erase_def456" }).to_string();
    let (status, raw) = signed(&kit, APPLY, &other).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    assert_eq!(
        serde_json::from_str::<Value>(&raw).expect("json")["request_id"],
        "erase_def456"
    );
    assert_eq!(count(&kit, "accounts", "acct-2").await, 0);
    assert_eq!(count(&kit, "invoices", "acct-2").await, 1);
}

/// A deployment whose composed modules declare nothing answers with empty
/// sections rather than an error: "we hold nothing about you" is an answer,
/// and an absent one reads as a failure to answer.
#[pollster::test]
async fn a_deployment_with_nothing_declared_answers_empty_rather_than_failing() {
    let kit = empty_kit();
    let body = call(SUBJECT);

    for path in [EXPORT, PLAN] {
        let (status, raw) = signed(&kit, path, &body).await;
        assert_eq!(status, StatusCode::OK, "{path}: {raw}");
        let answer: Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(answer["sections"], json!([]), "{path}: {raw}");
    }

    // Nothing to erase is not a failure to erase.
    let (status, raw) = signed(&kit, APPLY, &body).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    assert_eq!(serde_json::from_str::<Value>(&raw).expect("json")["applied"], Value::Bool(true));
}

// ------------------------------------------------- what erasure cannot reach

/// Why the budget window cannot be reached, in the owning module's own words.
/// The test asserts this string survives the round trip byte for byte, so it
/// is deliberately not a short placeholder.
const BUDGET_REASON: &str = "the row is a counter keyed by email-or-ip plus the window it \
                             started in, so no equality predicate on your address reaches it, \
                             and the scheduled handler deletes it a day after its window closes";

/// A module holding one table of personal data erasure **cannot reach**,
/// declared the way `auth-passkeys` declares its challenge budget: the struct
/// literal with a real subject column, not `PersonalDataSet::unreachable`.
///
/// That shape matters, and it is why this fixture is not the `unreachable`
/// constructor. The constructor leaves the subject column blank, so the
/// declaration is skipped by `subject_sets` and never reaches an erasure plan
/// at all. A module that names the column — as `auth-passkeys` does, and as
/// the `Unreachable` variant's own documentation contemplates — *is* in the
/// plan, and a `plan_section` without an arm for it answers `500` to every
/// caller. The bug this pins was invisible in `auth-worker` until then.
#[derive(Clone, Default)]
struct Budgets;

const BUDGET_MIGRATION: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    "CREATE TABLE signin_budget (
              id TEXT PRIMARY KEY,
              subject TEXT NOT NULL,
              attempts INTEGER NOT NULL
          );",
);

const BUDGET_PERSONAL: &[PersonalDataSet] = &[PersonalDataSet {
    table: "signin_budget",
    // A real column, so this declaration is a `subject_set` and the plan
    // really counts it. What cannot be reached is the row: the value stored
    // here is `email:<address>` or `ip:<address>`, which no equality
    // predicate on a harness subject id matches.
    subject: "subject",
    kind: DataKind::Usage,
    disposition: Disposition::Unreachable(BUDGET_REASON),
    description: "How many sign-in attempts your address or network made lately.",
    redacted: &[],
    subject_via: None,
}];

impl Module for Budgets {
    fn name(&self) -> &'static str {
        "budgets"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["signin_budget"]
    }
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        BUDGET_PERSONAL
    }
    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [BUDGET_MIGRATION];
        Migrations::sqlite(&MIGRATIONS)
    }
    fn validate_config(&self, _cfg: &dyn cratefield_core::Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

fn budget_kit() -> TestHarness {
    TestHarness::with_ports(
        vec![
            Box::new(Ledger),
            Box::new(Budgets),
            Box::new(Privacy::new().serve_provider(SECRET_ENV)),
        ],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("ADMIN_TOKEN", ADMIN),
                (SECRET_ENV, SECRET),
            ]));
        },
    )
}

async fn seed_budget(kit: &TestHarness) {
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO signin_budget (id, subject, attempts) VALUES (?, ?, ?)",
            vec!["b1".into(), "email:alice@example.test".into(), 3.into()],
        ))
        .await
        .expect("seed the budget row");
}

async fn budget_rows(kit: &TestHarness) -> i64 {
    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT COUNT(*) AS n FROM signin_budget WHERE id = ?",
            vec!["b1".into()],
        ))
        .await
        .expect("count");
    rows.first().and_then(|row| row.get("n")).unwrap_or(0)
}

/// **The defect, in one test.** A deployment holding data erasure cannot reach
/// answers a signed plan — with `retain`, and with the owning module's reason
/// verbatim, because the calling module's validator refuses a `retain` that
/// does not say why and the reason is the only honest answer available.
///
/// Before this, `plan_section` had no arm for `Disposition::Unreachable`: the
/// catch-all turned every plan of every venture mounting `auth-passkeys` into
/// a `500`, which `crates/auth-worker/tests/privacy_provider.rs` had to
/// downgrade to "the route is mounted" to get past.
#[pollster::test]
async fn data_erasure_cannot_reach_is_retained_with_the_reason_it_gave() {
    let kit = budget_kit();
    seed(&kit).await;
    seed_budget(&kit).await;

    let (status, raw) = signed(&kit, PLAN, &call(SUBJECT)).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    let body: Value = serde_json::from_str(&raw).expect("json");
    let sections = body["sections"].as_array().expect("sections").clone();

    let budget = section(&sections, "signin_budget");
    assert_eq!(budget["action"], "retain", "{budget:?}");
    assert_eq!(
        budget["reason"], BUDGET_REASON,
        "the declaration's reason did not survive verbatim: {budget:?}"
    );
    // The other declarations are unaffected: one unreachable table must not
    // change what the plan says about the rest.
    assert_eq!(section(&sections, "accounts")["action"], "delete");

    // And the apply keeps it, because the plan said so. `erase::statements`
    // reads the same `disposition`, so an apply that deleted this row would
    // be contradicting the answer it gave a moment earlier.
    let (status, raw) = signed(&kit, APPLY, &call(SUBJECT)).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    assert_eq!(
        budget_rows(&kit).await,
        1,
        "an apply erased a table its own plan said it retains"
    );
    // The tables it did say it would erase are gone.
    assert_eq!(count(&kit, "accounts", SUBJECT).await, 0);
    assert_eq!(count(&kit, "sessions", SUBJECT).await, 0);
    // And the retained invoice is untouched.
    assert_eq!(count(&kit, "invoices", SUBJECT).await, 1);
}

// ------------------------------------------- the client and the server, live

/// The `HttpClient` port backed by another deployment's real router, so the
/// round trip runs over the port rather than over a socket.
///
/// This is the seam the protocol has, not a stub standing in for one: the
/// request that arrives here was built, signed and bounded by
/// `crate::provider`, and the response that leaves is the one
/// `crate::provider`'s validator parses. Only the socket is replaced, because
/// `wasm32` — where this module actually runs — has none.
#[derive(Clone)]
struct InProcessProvider {
    router: axum::Router,
}

#[async_trait::async_trait]
impl cratefield_core::HttpClient for InProcessProvider {
    async fn send(
        &self,
        request: Request<bytes::Bytes>,
    ) -> Result<axum::http::Response<bytes::Bytes>, cratefield_core::HttpError> {
        let (parts, body) = request.into_parts();
        let response = self
            .router
            .clone()
            .oneshot(Request::from_parts(parts, Body::from(body)))
            .await
            .map_err(|error| cratefield_core::HttpError::Transport(error.to_string()))?;
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|error| cratefield_core::HttpError::Transport(error.to_string()))?;
        Ok(axum::http::Response::from_parts(parts, bytes))
    }
}

/// The `HttpProvider` a deployment registers to reach another one, pointed at
/// the *real* path this module mounts its own provider routes on. The client
/// appends `/export`, `/erase/plan` and `/erase/apply` to it, exactly as it
/// would over a socket.
fn remote_provider() -> HttpProvider {
    HttpProvider::new("ledger", "https://ledger.test/v1/privacy/provider").secret_env(SECRET_ENV)
}

/// **The round trip, closed.** The shipped client drives the real
/// `/export`, `/erase` and `/erase/confirm` routes over the `HttpClient`
/// port, and the answers it accepts come from a second deployment serving
/// `serve_provider` out of its own declarations and its own database.
///
/// Two fakes agreeing by construction would prove nothing; this has one side
/// real (the server) and one side real (the client), joined at the only port
/// between them. If the server's body drifted from what the validator reads —
/// a field the client drops, a shape it rejects, an action it has no word
/// for — the client's `ProviderError` would surface here as a `failed`
/// provider line rather than as the data.
#[pollster::test]
async fn the_shipped_client_parses_what_this_server_answers() {
    // The deployment being reached: real module, real protocol server.
    let served = budget_kit();
    seed(&served).await;
    seed_budget(&served).await;
    let served_router = served.router.clone();

    // The deployment reaching out: real client, same secret, no server of
    // its own.
    let caller = TestHarness::with_ports(
        vec![Box::new(Privacy::new().provider(remote_provider()))],
        move |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("ADMIN_TOKEN", ADMIN),
                (SECRET_ENV, SECRET),
            ]));
            ports.http = Some(Arc::new(InProcessProvider {
                router: served_router.clone(),
            }));
        },
    );

    // --- export: the client's `provider_sections` reads this answer.
    let exported = request_as(
        &caller.router,
        Method::GET,
        "/v1/privacy/export?subject=acct-1",
        ADMIN,
        None,
    )
    .await;
    assert_eq!(exported.status, StatusCode::OK);
    let body = exported.json();
    assert_eq!(
        body["complete"],
        Value::Bool(true),
        "the real client rejected the real server's export: {:?}",
        body["providers"]
    );
    let sections = body["providers"][0]["sections"].as_array().expect("sections");
    assert_eq!(body["providers"][0]["provider"], "ledger");
    // The rows came out of the *other* deployment's database.
    let account = section(sections, "accounts");
    assert_eq!(account["description"], "The account itself.");
    assert_eq!(account["data"]["rows"][0]["id"], "acct-1");
    assert_eq!(account["data"]["module"], "ledger");
    // The declared credential column is named, not copied, across the seam.
    assert_eq!(
        section(sections, "sessions")["data"]["rows"][0]["device_token"],
        "[redacted]"
    );

    // --- plan: the client's `plan_sections` reads this one, including the
    // `retain` that must carry a reason.
    let planned = request_as(
        &caller.router,
        Method::POST,
        "/v1/privacy/erase",
        ADMIN,
        Some(&json!({ "subject": SUBJECT }).to_string()),
    )
    .await;
    assert_eq!(planned.status, StatusCode::OK);
    let body = planned.json();
    let request_id = body["request_id"].as_str().expect("request id").to_owned();
    let sections = body["providers"][0]["sections"].as_array().expect("sections");
    assert_eq!(section(sections, "accounts")["action"], "delete");
    assert_eq!(section(sections, "sessions")["action"], "delete");
    assert_eq!(section(sections, "invoices")["action"], "retain");
    assert_eq!(section(sections, "invoices")["reason"], "Tax law requires seven years.");
    // The `Unreachable` table survives the client's validator too, which is
    // the whole reason it is emitted with a reason at all.
    assert_eq!(section(sections, "signin_budget")["action"], "retain");
    assert_eq!(section(sections, "signin_budget")["reason"], BUDGET_REASON);

    // --- apply: the erasure actually reaches the other deployment.
    let confirmed = request_as(
        &caller.router,
        Method::POST,
        "/v1/privacy/erase/confirm",
        ADMIN,
        Some(&json!({ "token": body["confirm_token"] }).to_string()),
    )
    .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json());
    let body = confirmed.json();
    assert_eq!(body["complete"], Value::Bool(true), "{body}");
    assert_eq!(body["providers"][0]["status"], "applied");
    assert_eq!(body["request_id"], request_id);

    // The rows are gone from the serving deployment's own database — not
    // from the caller's, which never held them.
    assert_eq!(count(&served, "accounts", SUBJECT).await, 0);
    assert_eq!(count(&served, "sessions", SUBJECT).await, 0);
    assert_eq!(count(&served, "accounts", "acct-2").await, 1);
    // Both `retain`s held: the one for tax law, and the one erasure could
    // not reach in the first place.
    assert_eq!(count(&served, "invoices", SUBJECT).await, 1);
    assert_eq!(budget_rows(&served).await, 1);
    // The caller held none of them: its own export named no local table, and
    // the rows it can show came from the deployment that answered.
    let exported = request_as(
        &caller.router,
        Method::GET,
        "/v1/privacy/export?subject=acct-1",
        ADMIN,
        None,
    )
    .await;
    assert_eq!(
        exported.json()["tables"],
        json!([]),
        "the caller reported local rows it never held"
    );
}

/// The server's own idempotence, seen from the caller: confirming twice with
/// the same token answers `200` both times and the second confirm erases
/// nothing new, while a fresh token for a different subject does its work.
///
/// Driven through the caller rather than by hand-signing, because the id both
/// sides share is derived from the token — a server that keyed idempotence off
/// anything else would still pass a hand-signed test.
#[pollster::test]
async fn confirming_twice_through_the_client_erases_once() {
    let served = kit();
    seed(&served).await;
    let served_router = served.router.clone();

    let caller = TestHarness::with_ports(
        vec![Box::new(Privacy::new().provider(remote_provider()))],
        move |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("ADMIN_TOKEN", ADMIN),
                (SECRET_ENV, SECRET),
            ]));
            ports.http = Some(Arc::new(InProcessProvider {
                router: served_router.clone(),
            }));
        },
    );

    let planned = request_as(
        &caller.router,
        Method::POST,
        "/v1/privacy/erase",
        ADMIN,
        Some(&json!({ "subject": SUBJECT }).to_string()),
    )
    .await;
    let token = planned.json()["confirm_token"].as_str().expect("token").to_owned();

    for attempt in 1..=2 {
        let confirmed = request_as(
            &caller.router,
            Method::POST,
            "/v1/privacy/erase/confirm",
            ADMIN,
            Some(&json!({ "token": token }).to_string()),
        )
        .await;
        assert_eq!(
            confirmed.status,
            StatusCode::OK,
            "confirm {attempt}: {:?}",
            confirmed.json()
        );
        assert_eq!(confirmed.json()["complete"], Value::Bool(true));
        assert_eq!(
            confirmed.json()["providers"][0]["status"],
            "applied",
            "confirm {attempt}"
        );
    }
    assert_eq!(count(&served, "accounts", SUBJECT).await, 0);
    // A repeat did not reach past the plan into the retained row.
    assert_eq!(count(&served, "invoices", SUBJECT).await, 1);

    // A genuinely new erasure, for another subject, does the work again.
    let planned = request_as(
        &caller.router,
        Method::POST,
        "/v1/privacy/erase",
        ADMIN,
        Some(&json!({ "subject": "acct-2" }).to_string()),
    )
    .await;
    let token = planned.json()["confirm_token"].as_str().expect("token").to_owned();
    let confirmed = request_as(
        &caller.router,
        Method::POST,
        "/v1/privacy/erase/confirm",
        ADMIN,
        Some(&json!({ "token": token }).to_string()),
    )
    .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json());
    assert_eq!(count(&served, "accounts", "acct-2").await, 0);
    assert_eq!(count(&served, "invoices", "acct-2").await, 1);
}

/// Every refusal this server can answer is one the shipped client reads as
/// the refusal it means, checked through the client rather than by reading
/// `check_status`.
///
/// The three cases are the three statuses the protocol produces for different
/// causes, and they must not collapse into one: a `4xx` means the provider
/// said no and a retry with the same request will say no again, while a `5xx`
/// means this deployment is broken and the caller's deferred retry is worth
/// making. A server that answered `503` to a wrong signature would strand
/// every caller's erasure in `pending` for a refusal that will never lift.
#[pollster::test]
async fn every_refusal_the_server_answers_reaches_the_client_as_its_own_word() {
    // A deployment serving the protocol under a secret the caller does not
    // hold, one serving it with no secret at all, and one that never opted
    // in — a `401`, a `503` and a `404`.
    let wrong_secret = kit_with_secret(WRONG_SECRET);
    let unconfigured = kit_with_secret("");
    let not_serving = TestHarness::with_ports(
        vec![Box::new(Ledger), Box::new(Privacy::new())],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("ADMIN_TOKEN", ADMIN),
                (SECRET_ENV, SECRET),
            ]));
        },
    );
    let routers = [
        ("a wrong secret", wrong_secret.router.clone()),
        ("no secret configured", unconfigured.router.clone()),
        ("a deployment that never opted in", not_serving.router.clone()),
    ];

    for (why, router) in routers {
        let caller = TestHarness::with_ports(
            vec![Box::new(Privacy::new().provider(remote_provider()))],
            {
                let router = router.clone();
                move |ports| {
                    ports.config = Arc::new(MapConfig::from_pairs([
                        ("ADMIN_TOKEN", ADMIN),
                        (SECRET_ENV, SECRET),
                    ]));
                    ports.http = Some(Arc::new(InProcessProvider { router }));
                }
            },
        );

        let exported = request_as(
            &caller.router,
            Method::GET,
            "/v1/privacy/export?subject=acct-1",
            ADMIN,
            None,
        )
        .await;
        assert_eq!(exported.status, StatusCode::OK);
        let body = exported.json();
        assert_eq!(body["complete"], Value::Bool(false), "{why}");
        let error = body["providers"][0]["error"].as_str().expect("an error word");
        // `401` and `404` are the provider refusing; `503` is this
        // deployment being not-ready, which the client reads as an outage
        // worth retrying rather than a refusal.
        let expected = if why == "no secret configured" {
            "unavailable"
        } else {
            "rejected"
        };
        assert_eq!(error, expected, "{why} reached the caller as {error}");
        // Neither the server's body nor its status text rides through: the
        // client renders a word, never an upstream's words about a subject.
        assert!(
            !body["providers"][0].to_string().contains("privacy-provider-unverified"),
            "{why}"
        );
    }
}

// ------------------------------------------------------- the account order

/// A kit with three outbound providers, the **first** of which holds the
/// identity — the ordinary way a build gets this wrong, and the case the
/// marking exists for. The fake records the order the calls arrived in,
/// which is the only place the claim is checkable from outside.
fn order_kit(providers: Privacy) -> (TestHarness, FakePrivacyProvider) {
    let provider = FakePrivacyProvider::new(SECRET).with_subject(SUBJECT, json!([]));
    let served = provider.clone();
    let kit = TestHarness::with_ports(
        vec![Box::new(Ledger), Box::new(providers)],
        move |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("ADMIN_TOKEN", ADMIN),
                (SECRET_ENV, SECRET),
            ]));
            ports.http = Some(Arc::new(served.clone()));
        },
    );
    (kit, provider)
}

/// The host each of a sequence of calls went to, in order. Each provider is
/// registered under its own URL, so the path prefix tells them apart.
fn called_hosts(provider: &FakePrivacyProvider, suffix: &str) -> Vec<String> {
    provider
        .calls()
        .into_iter()
        .filter(|call| call.path.ends_with(suffix))
        .map(|call| {
            call.path
                .trim_start_matches('/')
                .split('/')
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

#[pollster::test]
async fn an_account_provider_is_called_after_the_others_on_export() {
    let (kit, provider) = order_kit(
        Privacy::new()
            .provider(
                HttpProvider::new("accounts-db", "https://provider.test/accounts-db")
                    .secret_env(SECRET_ENV)
                    .account(),
            )
            .provider(
                HttpProvider::new("warehouse", "https://provider.test/warehouse").secret_env(SECRET_ENV),
            )
            .provider(HttpProvider::new("crm", "https://provider.test/crm").secret_env(SECRET_ENV)),
    );
    seed(&kit).await;

    let response = request_as(
        &kit.router,
        Method::GET,
        "/v1/privacy/export?subject=acct-1",
        ADMIN,
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json());
    assert_eq!(
        called_hosts(&provider, "/export"),
        vec!["warehouse", "crm", "accounts-db"],
        "the account provider was not called last"
    );
}

#[pollster::test]
async fn an_account_provider_is_called_after_the_others_on_plan() {
    let (kit, provider) = order_kit(
        Privacy::new()
            .provider(
                HttpProvider::new("accounts-db", "https://provider.test/accounts-db")
                    .secret_env(SECRET_ENV)
                    .account(),
            )
            .provider(
                HttpProvider::new("warehouse", "https://provider.test/warehouse").secret_env(SECRET_ENV),
            )
            .provider(HttpProvider::new("crm", "https://provider.test/crm").secret_env(SECRET_ENV)),
    );
    seed(&kit).await;

    let response = request_as(
        &kit.router,
        Method::POST,
        "/v1/privacy/erase",
        ADMIN,
        Some(&json!({ "subject": SUBJECT }).to_string()),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json());
    assert_eq!(
        called_hosts(&provider, "/erase/plan"),
        vec!["warehouse", "crm", "accounts-db"],
        "the account provider was not called last"
    );
}

#[pollster::test]
async fn an_account_provider_is_called_after_the_others_on_apply() {
    let (kit, provider) = order_kit(
        Privacy::new()
            .provider(
                HttpProvider::new("accounts-db", "https://provider.test/accounts-db")
                    .secret_env(SECRET_ENV)
                    .account(),
            )
            .provider(
                HttpProvider::new("warehouse", "https://provider.test/warehouse").secret_env(SECRET_ENV),
            )
            .provider(HttpProvider::new("crm", "https://provider.test/crm").secret_env(SECRET_ENV)),
    );
    seed(&kit).await;

    let planned = request_as(
        &kit.router,
        Method::POST,
        "/v1/privacy/erase",
        ADMIN,
        Some(&json!({ "subject": SUBJECT }).to_string()),
    )
    .await;
    let token = planned.json()["confirm_token"].as_str().expect("token").to_owned();

    let response = request_as(
        &kit.router,
        Method::POST,
        "/v1/privacy/erase/confirm",
        ADMIN,
        Some(&json!({ "token": token }).to_string()),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json());
    assert_eq!(
        called_hosts(&provider, "/erase/apply"),
        vec!["warehouse", "crm", "accounts-db"],
        "the account provider was not called last"
    );
}

/// The marking moves one group, not the whole sequence: unmarked providers
/// keep the order they were registered in.
#[pollster::test]
async fn unmarked_providers_keep_their_registration_order() {
    let (kit, provider) = order_kit(
        Privacy::new()
            .provider(
                HttpProvider::new("first", "https://provider.test/first").secret_env(SECRET_ENV),
            )
            .provider(
                HttpProvider::new("second", "https://provider.test/second").secret_env(SECRET_ENV),
            )
            .provider(
                HttpProvider::new("third", "https://provider.test/third")
                    .secret_env(SECRET_ENV)
                    .account(),
            ),
    );
    seed(&kit).await;

    let response = request_as(
        &kit.router,
        Method::GET,
        "/v1/privacy/export?subject=acct-1",
        ADMIN,
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json());
    assert_eq!(
        called_hosts(&provider, "/export"),
        vec!["first", "second", "third"]
    );
}