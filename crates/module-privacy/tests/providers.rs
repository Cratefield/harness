//! External provider integration (issue #653): what a registered provider
//! holds is merged into export and erase, and erasure reaches it — signed,
//! idempotent, and never leaking the provider's own words.
//!
//! The fixture module is a stand-in for any module holding a subject's rows;
//! the assertions would be identical for a venture composing modules this
//! crate has never heard of.

use axum::http::{Method, StatusCode};
use cratefield_core::MapConfig;
use cratefield_core::{
    ConfigError, DataKind, Disposition, Migrations, Module, ModuleContext, PersonalDataSet, Port,
    SqlMigration, Statement,
};
use cratefield_module_privacy::{HttpProvider, Privacy};
use cratefield_testing::{FakePrivacyProvider, TestHarness, TestResponse, request_as};
use serde_json::{Value, json};
use std::sync::Arc;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const SECRET: &str = "privacy-provider-secret-0123456789";
const SECRET_ENV: &str = "PRIVACY_PROVIDER_SECRET";
const SUBJECT: &str = "acct-1";

/// A module holding one personal table, so a provider merge has a local half
/// to sit beside.
#[derive(Clone, Default)]
struct Contact;

const MIGRATION: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    "CREATE TABLE contacts (
              id TEXT PRIMARY KEY,
              account_id TEXT NOT NULL,
              email TEXT NOT NULL
          );",
);

const PERSONAL: &[PersonalDataSet] = &[PersonalDataSet {
    table: "contacts",
    subject: "account_id",
    kind: DataKind::Identifier,
    disposition: Disposition::Erase,
    description: "The contact's email.",
    redacted: &[],
    subject_via: None,
}];

impl Module for Contact {
    fn name(&self) -> &'static str {
        "contact"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["contacts"]
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

/// A kit with `Contact` and a `Privacy` carrying one provider. The fake
/// answers over the `HttpClient` port, so nothing touches a socket.
fn kit(provider: &FakePrivacyProvider, http_provider: HttpProvider) -> TestHarness {
    let provider = provider.clone();
    TestHarness::with_ports(
        vec![
            Box::new(Contact),
            Box::new(Privacy::new().provider(http_provider)),
        ],
        move |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("ADMIN_TOKEN", ADMIN),
                (SECRET_ENV, SECRET),
            ]));
            ports.http = Some(Arc::new(provider));
        },
    )
}

/// The provider configuration a test registers unless it needs its own.
fn default_provider() -> HttpProvider {
    HttpProvider::new("vault", "https://vault.test").secret_env(SECRET_ENV)
}

async fn seed(kit: &TestHarness) {
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO contacts (id, account_id, email) VALUES (?, ?, ?)",
            vec!["c1".into(), SUBJECT.into(), "a@example.test".into()],
        ))
        .await
        .expect("seed");
}

async fn local_rows(kit: &TestHarness) -> i64 {
    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT COUNT(*) AS n FROM contacts WHERE account_id = ?",
            vec![SUBJECT.into()],
        ))
        .await
        .expect("count");
    rows.first().and_then(|row| row.get("n")).unwrap_or(0)
}

/// An admin request through `cratefield_testing::request_as`.
async fn send(kit: &TestHarness, method: Method, path: &str, json: Option<&str>) -> TestResponse {
    request_as(&kit.router, method, path, ADMIN, json).await
}

async fn export(kit: &TestHarness) -> Value {
    let response = send(kit, Method::GET, "/v1/privacy/export?subject=acct-1", None).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json());
    response.json()
}

/// A preview, returning the whole body.
async fn plan(kit: &TestHarness) -> Value {
    let response = send(
        kit,
        Method::POST,
        "/v1/privacy/erase",
        Some(&json!({ "subject": SUBJECT }).to_string()),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json());
    response.json()
}

/// The `(confirm_token, request_id)` a plan issued, which a confirm reuses.
async fn planned(kit: &TestHarness) -> (String, String) {
    let body = plan(kit).await;
    (
        body["confirm_token"].as_str().expect("token").to_owned(),
        body["request_id"].as_str().expect("request id").to_owned(),
    )
}

async fn confirm(kit: &TestHarness, token: &str) -> TestResponse {
    send(
        kit,
        Method::POST,
        "/v1/privacy/erase/confirm",
        Some(&json!({ "token": token }).to_string()),
    )
    .await
}

#[pollster::test]
async fn a_wrong_secret_is_rejected_and_no_provider_body_leaks() {
    const WRONG: &str = "a-different-secret-0123456789abcdef";
    let provider = FakePrivacyProvider::new(WRONG).with_subject(
        SUBJECT,
        json!([{ "name": "profile", "data": { "tier": "gold" } }]),
    );
    let kit = kit(&provider, default_provider());
    seed(&kit).await;

    let response = send(&kit, Method::GET, "/v1/privacy/export?subject=acct-1", None).await;
    assert_eq!(response.status, StatusCode::OK);
    let raw = String::from_utf8_lossy(response.body());
    let body = response.json();
    assert_eq!(body["providers"][0]["status"], "failed");
    assert_eq!(body["providers"][0]["error"], "rejected");
    assert_eq!(body["complete"], Value::Bool(false));
    assert_eq!(
        provider.signature_failures(),
        1,
        "the provider saw a bad signature"
    );
    // Neither secret, nor the provider's own payload, reached the caller.
    assert!(!raw.contains(SECRET), "the configured secret leaked: {raw}");
    assert!(!raw.contains(WRONG), "the provider's secret leaked: {raw}");
    assert!(
        !raw.contains("gold"),
        "a provider body reached the caller: {raw}"
    );
}

#[pollster::test]
async fn an_export_merges_the_providers_sections() {
    let provider = FakePrivacyProvider::new(SECRET).with_subject(
        SUBJECT,
        json!([{
            "name": "profile",
            "description": "Account profile.",
            "data": { "tier": "gold" }
        }]),
    );
    let kit = kit(&provider, default_provider());
    seed(&kit).await;

    let body = export(&kit).await;
    assert_eq!(body["complete"], Value::Bool(true));

    let providers = body["providers"].as_array().expect("providers");
    assert_eq!(providers.len(), 1, "{providers:?}");
    assert_eq!(providers[0]["provider"], "vault");
    assert_eq!(providers[0]["status"], "ok");
    assert_eq!(providers[0]["sections"][0]["name"], "profile");
    assert_eq!(
        providers[0]["sections"][0]["description"],
        "Account profile."
    );
    assert_eq!(providers[0]["sections"][0]["data"]["tier"], "gold");

    // The local tables are unchanged beside the provider's.
    assert_eq!(body["tables"][0]["table"], "contacts");
    assert_eq!(body["tables"][0]["rows"].as_array().expect("rows").len(), 1);
}

#[pollster::test]
async fn an_erase_plan_merges_provider_sections_and_shares_the_request_id() {
    let provider = FakePrivacyProvider::new(SECRET)
        .with_subject(
            SUBJECT,
            json!([
                { "name": "profile", "data": {} },
                { "name": "invoices", "data": {} }
            ]),
        )
        .retain_section("invoices", "Tax law requires seven years.");
    let kit = kit(&provider, default_provider());
    seed(&kit).await;

    let body = plan(&kit).await;
    let request_id = body["request_id"].as_str().expect("request id");
    assert!(request_id.starts_with("erase_"), "{request_id}");

    let sections = body["providers"][0]["sections"]
        .as_array()
        .expect("sections");
    assert_eq!(sections[0]["action"], "delete");
    assert_eq!(sections[1]["action"], "retain");
    assert_eq!(sections[1]["reason"], "Tax law requires seven years.");

    // The id the provider saw is the one the caller was given.
    let call = provider
        .calls()
        .into_iter()
        .find(|call| call.path.ends_with("/erase/plan"))
        .expect("a plan call arrived");
    assert_eq!(call.request_id, request_id);
}

#[pollster::test]
async fn an_erasure_reaches_the_provider() {
    let provider = FakePrivacyProvider::new(SECRET)
        .with_subject(SUBJECT, json!([{ "name": "profile", "data": {} }]));
    let kit = kit(&provider, default_provider());
    seed(&kit).await;

    let (token, request_id) = planned(&kit).await;
    let response = confirm(&kit, &token).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json());
    let body = response.json();
    assert_eq!(body["complete"], Value::Bool(true));
    assert_eq!(body["providers"][0]["status"], "applied");
    assert_eq!(body["request_id"], request_id);

    assert_eq!(local_rows(&kit).await, 0, "local rows survived erasure");
    assert!(
        !provider.holds(SUBJECT),
        "the provider still holds the subject"
    );
    assert_eq!(provider.applies(&request_id), 1);
}

#[pollster::test]
async fn a_reposted_confirm_reuses_the_request_id_and_applies_once() {
    let provider = FakePrivacyProvider::new(SECRET)
        .with_subject(SUBJECT, json!([{ "name": "profile", "data": {} }]));
    let kit = kit(&provider, default_provider());
    seed(&kit).await;

    let (token, request_id) = planned(&kit).await;
    assert_eq!(confirm(&kit, &token).await.status, StatusCode::OK);
    let response = confirm(&kit, &token).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json());
    let body = response.json();
    assert_eq!(body["complete"], Value::Bool(true));

    // Two apply calls arrived, both carrying the same id; the provider
    // applied the erase exactly once.
    let applies: Vec<_> = provider
        .calls()
        .into_iter()
        .filter(|call| call.path.ends_with("/erase/apply"))
        .collect();
    assert_eq!(applies.len(), 2, "{applies:?}");
    assert!(applies.iter().all(|call| call.request_id == request_id));
    assert_eq!(provider.applies(&request_id), 1, "a repeat applied twice");
}

#[pollster::test]
async fn a_down_provider_leaves_the_erasure_pending_and_a_retry_completes_it() {
    let provider = FakePrivacyProvider::new(SECRET)
        .with_subject(SUBJECT, json!([{ "name": "profile", "data": {} }]));
    let kit = kit(&provider, default_provider());
    seed(&kit).await;

    let (token, request_id) = planned(&kit).await;

    provider.set_down(true);
    let response = confirm(&kit, &token).await;
    assert_eq!(
        response.status,
        StatusCode::ACCEPTED,
        "{:?}",
        response.json()
    );
    let body = response.json();
    assert_eq!(body["complete"], Value::Bool(false));
    assert_eq!(body["providers"][0]["status"], "pending");
    assert_eq!(body["providers"][0]["error"], "unavailable");
    // The local half is already proved even while the provider is down.
    assert_eq!(local_rows(&kit).await, 0);
    assert!(provider.holds(SUBJECT));

    provider.set_down(false);
    kit.defer.drain().await;
    assert!(
        !provider.holds(SUBJECT),
        "the deferred retry did not reach the provider"
    );
    assert_eq!(provider.applies(&request_id), 1);

    // A re-POST of the same confirm completes it, the local half a no-op.
    let response = confirm(&kit, &token).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json());
    assert_eq!(response.json()["complete"], Value::Bool(true));
    assert_eq!(provider.applies(&request_id), 1);
}

#[pollster::test]
async fn a_provider_failure_body_never_reaches_the_caller() {
    const LEAK: &str = "leaked-secret-token-0123456789";
    let provider = FakePrivacyProvider::new(SECRET).with_subject(SUBJECT, json!([]));
    let kit = kit(&provider, default_provider());
    seed(&kit).await;

    provider.set_failure(500, &format!(r#"{{"detail":"{LEAK}"}}"#));
    let response = send(&kit, Method::GET, "/v1/privacy/export?subject=acct-1", None).await;
    assert_eq!(response.status, StatusCode::OK);
    let raw = String::from_utf8_lossy(response.body());
    assert!(
        !raw.contains(LEAK),
        "a provider body reached the caller: {raw}"
    );
    let body = response.json();
    assert_eq!(body["providers"][0]["status"], "failed");
    assert_eq!(body["providers"][0]["error"], "unavailable");
}

#[pollster::test]
async fn an_oversize_response_is_an_invalid_response() {
    let provider = FakePrivacyProvider::new(SECRET).with_subject(
        SUBJECT,
        json!([{ "name": "big", "data": "x".repeat(4_096) }]),
    );
    let kit = kit(&provider, default_provider().max_response_bytes(128));
    seed(&kit).await;

    let body = export(&kit).await;
    assert_eq!(body["providers"][0]["status"], "failed");
    assert_eq!(body["providers"][0]["error"], "invalid_response");
    assert_eq!(body["complete"], Value::Bool(false));
}
