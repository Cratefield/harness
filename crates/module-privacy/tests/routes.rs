//! The module answers from what other modules declared, over a real database.
//!
//! The fixture module below is the whole point of the design: it is not the
//! privacy module's business what it holds, only that it said so. Everything
//! asserted here would be identical for a venture composing five modules the
//! privacy crate has never heard of.

use axum::http::{Method, StatusCode, header};
use cratefield_core::MapConfig;
use cratefield_core::{
    ConfigError, DataKind, Disposition, Migrations, Module, ModuleContext, PersonalDataSet, Port,
    SqlMigration, Statement,
};
use cratefield_module_privacy::Privacy;
use cratefield_testing::{TestHarness, request};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";

/// A module that holds two tables: one with a person in it, one without.
#[derive(Clone, Default)]
struct Practice;

const MIGRATION: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    "CREATE TABLE practice_sessions (
              id TEXT PRIMARY KEY,
              account_id TEXT NOT NULL,
              pose TEXT NOT NULL,
              score INTEGER NOT NULL,
              device_token TEXT NOT NULL
          );
          CREATE TABLE pose_library (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL
          );",
);

const PERSONAL: &[PersonalDataSet] = &[
    PersonalDataSet {
        table: "practice_sessions",
        subject: "account_id",
        kind: DataKind::Fitness,
        disposition: Disposition::Erase,
        description: "Joint angles and scores for one practice, with its date.",
        // The row is the member's and erasure must reach it, but this one
        // column is a credential: whoever holds the token can reach the
        // device, so an export names it and does not copy it.
        redacted: &["device_token"],
        subject_via: None,
    },
    PersonalDataSet::none(
        "pose_library",
        "Reference poses, identical for every member.",
    ),
];

impl Module for Practice {
    fn name(&self) -> &'static str {
        "practice"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["practice_sessions", "pose_library"]
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

fn kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || vec![Box::new(Practice), Box::new(Privacy::new())],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
        },
    )
}

/// The value the export must never print. A literal rather than a fixture
/// constant so a grep for it finds both the seed and the assertion.
const DEVICE_TOKEN: &str = "tok-live-device-0123456789";

async fn seed(kit: &TestHarness) {
    for (id, account, pose, score) in [
        ("s1", "acct-1", "mountain", 91),
        ("s2", "acct-1", "tree", 78),
        ("s3", "acct-2", "chair", 64),
    ] {
        kit.db
            .execute(&Statement::with_values(
                "INSERT INTO practice_sessions (id, account_id, pose, score, device_token) \
                 VALUES (?, ?, ?, ?, ?)",
                vec![
                    id.into(),
                    account.into(),
                    pose.into(),
                    score.into(),
                    DEVICE_TOKEN.into(),
                ],
            ))
            .await
            .expect("seed");
    }
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO pose_library (id, name) VALUES (?, ?)",
            vec!["p1".into(), "Mountain".into()],
        ))
        .await
        .expect("seed library");
}

#[pollster::test]
async fn the_manifest_publishes_what_each_module_declared() {
    for kit in kits() {
        let response = request(&kit.router, Method::GET, "/v1/privacy/manifest", None).await;
        assert_eq!(response.status, StatusCode::OK);
        let body: Value = response.json();

        assert_eq!(body["holds_personal_data"], Value::Bool(true));

        let holds = body["holds"].as_array().expect("holds");
        assert_eq!(holds.len(), 1, "{holds:?}");
        assert_eq!(holds[0]["module"], "practice");
        assert_eq!(holds[0]["table"], "practice_sessions");
        assert_eq!(holds[0]["kind"], "fitness");
        assert_eq!(holds[0]["on_erasure"]["action"], "erase");
        // The sentence a member reads is the one the owning module wrote.
        assert_eq!(
            holds[0]["description"],
            "Joint angles and scores for one practice, with its date."
        );

        // A table holding nothing personal is published as such, with its
        // reason: an omission and a decision must not look the same.
        let not_personal = body["not_personal"].as_array().expect("not_personal");
        assert_eq!(not_personal.len(), 1);
        assert_eq!(not_personal[0]["table"], "pose_library");
        assert_eq!(
            not_personal[0]["reason"],
            "Reference poses, identical for every member."
        );
    }
}

#[pollster::test]
async fn the_manifest_needs_no_credentials() {
    // A privacy disclosure behind a login is not a disclosure.
    for kit in kits() {
        let response = request(&kit.router, Method::GET, "/v1/privacy/manifest", None).await;
        assert_eq!(response.status, StatusCode::OK);
    }
}

#[pollster::test]
async fn an_export_returns_only_that_subjects_rows() {
    for kit in kits() {
        seed(&kit).await;
        let (status, raw) = admin_get(&kit, "/v1/privacy/export?subject=acct-1").await;
        assert_eq!(status, StatusCode::OK, "{raw}");
        let body: Value = serde_json::from_str(&raw).expect("json");

        assert_eq!(body["subject"], "acct-1");
        let tables = body["tables"].as_array().expect("tables");
        // Only the declared set: `pose_library` holds nobody and is not read.
        assert_eq!(tables.len(), 1, "{tables:?}");
        assert_eq!(tables[0]["table"], "practice_sessions");

        let rows = tables[0]["rows"].as_array().expect("rows");
        assert_eq!(rows.len(), 2, "{rows:?}");
        for row in rows {
            assert_eq!(row["account_id"], "acct-1", "another subject's row leaked");
        }
        // Values keep their types rather than all becoming strings.
        assert!(rows[0]["score"].is_number(), "{:?}", rows[0]);
        assert_eq!(tables[0]["truncated"], Value::Bool(false));
    }
}

#[pollster::test]
async fn an_export_names_a_credential_column_and_never_copies_it() {
    // A push token or a Web Push endpoint is a bearer capability: an export
    // file that carries one hands whoever reads it the ability to reach the
    // device. The column is still listed, because "we hold nothing there" is
    // the one answer a subject access request must not give untruthfully.
    for kit in kits() {
        seed(&kit).await;
        let (status, raw) = admin_get(&kit, "/v1/privacy/export?subject=acct-1").await;
        assert_eq!(status, StatusCode::OK, "{raw}");
        assert!(
            !raw.contains(DEVICE_TOKEN),
            "the export copied the credential column"
        );
        let body: Value = serde_json::from_str(&raw).expect("json");
        let rows = body["tables"][0]["rows"].as_array().expect("rows");
        for row in rows {
            assert_eq!(row["device_token"], "[redacted]", "{row:?}");
            // Everything else is untouched: redaction is per declared column,
            // not a blanket.
            assert!(row["pose"].is_string(), "{row:?}");
        }
    }
}

#[pollster::test]
async fn the_manifest_says_which_columns_it_will_not_hand_over() {
    for kit in kits() {
        let response = request(&kit.router, Method::GET, "/v1/privacy/manifest", None).await;
        assert_eq!(response.status, StatusCode::OK);
        let body: Value = response.json();
        assert_eq!(body["holds"][0]["redacted"][0], "device_token");
    }
}

#[pollster::test]
async fn an_export_for_a_subject_with_nothing_is_empty_rather_than_missing() {
    for kit in kits() {
        seed(&kit).await;
        let (status, raw) = admin_get(&kit, "/v1/privacy/export?subject=nobody").await;
        assert_eq!(status, StatusCode::OK, "{raw}");
        let body: Value = serde_json::from_str(&raw).expect("json");
        let tables = body["tables"].as_array().expect("tables");
        // The table is still listed, with no rows: "we hold nothing about you"
        // is an answer, and an absent section is not.
        assert_eq!(tables.len(), 1);
        assert!(tables[0]["rows"].as_array().expect("rows").is_empty());
    }
}

#[pollster::test]
async fn an_export_without_admin_credentials_is_refused() {
    for kit in kits() {
        seed(&kit).await;
        let response = request(
            &kit.router,
            Method::GET,
            "/v1/privacy/export?subject=acct-1",
            None,
        )
        .await;
        assert_ne!(
            response.status,
            StatusCode::OK,
            "an unauthenticated export returned somebody's data"
        );
    }
}

#[pollster::test]
async fn an_export_needs_a_subject() {
    for kit in kits() {
        let (status, raw) = admin_get(&kit, "/v1/privacy/export?subject=%20").await;
        // 400 is this harness's status for `validation-failed` (SLUGS), not 422.
        assert_eq!(status, StatusCode::BAD_REQUEST, "{raw}");
    }
}

/// A GET carrying the admin bearer. The kit's `request` helper takes no
/// headers, so this is the same call with one added.
async fn admin_get(kit: &TestHarness, path: &str) -> (StatusCode, String) {
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .body(axum::body::Body::empty())
        .expect("request builds");
    let response = kit
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

// ---------------------------------------------------------------- erasure

async fn admin_post(kit: &TestHarness, path: &str, body: &str) -> (StatusCode, String) {
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_owned()))
        .expect("request builds");
    let response = kit
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn count(kit: &TestHarness, account: &str) -> i64 {
    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT COUNT(*) AS n FROM practice_sessions WHERE account_id = ?",
            vec![account.into()],
        ))
        .await
        .expect("count");
    rows.first().and_then(|r| r.get("n")).unwrap_or(0)
}

#[pollster::test]
async fn the_preview_writes_nothing() {
    for kit in kits() {
        seed(&kit).await;
        let (status, raw) = admin_post(&kit, "/v1/privacy/erase", r#"{"subject":"acct-1"}"#).await;
        assert_eq!(status, StatusCode::OK, "{raw}");
        let body: Value = serde_json::from_str(&raw).expect("json");

        assert_eq!(body["plan"][0]["table"], "practice_sessions");
        assert_eq!(body["plan"][0]["action"], "erase");
        assert_eq!(body["plan"][0]["rows"], 2);
        assert!(
            body["confirm_token"]
                .as_str()
                .is_some_and(|t| !t.is_empty())
        );

        // The whole point of a preview.
        assert_eq!(count(&kit, "acct-1").await, 2, "the preview deleted rows");
    }
}

#[pollster::test]
async fn a_confirmed_erasure_removes_the_rows_and_leaves_other_subjects_alone() {
    for kit in kits() {
        seed(&kit).await;
        let (_, raw) = admin_post(&kit, "/v1/privacy/erase", r#"{"subject":"acct-1"}"#).await;
        let token = serde_json::from_str::<Value>(&raw).expect("json")["confirm_token"]
            .as_str()
            .expect("token")
            .to_owned();

        let (status, raw) = admin_post(
            &kit,
            "/v1/privacy/erase/confirm",
            &format!(r#"{{"token":"{token}"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{raw}");
        let body: Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(body["verified"], Value::Bool(true));
        assert_eq!(body["subject"], "acct-1");

        assert_eq!(count(&kit, "acct-1").await, 0, "rows survived erasure");
        assert_eq!(count(&kit, "acct-2").await, 1, "another subject was erased");
    }
}

#[pollster::test]
async fn a_confirmation_cannot_name_its_own_subject() {
    // The subject comes from the signed token. A body naming one is ignored,
    // or the two-step is a one-step wearing a costume.
    for kit in kits() {
        seed(&kit).await;
        let (_, raw) = admin_post(&kit, "/v1/privacy/erase", r#"{"subject":"acct-1"}"#).await;
        let token = serde_json::from_str::<Value>(&raw).expect("json")["confirm_token"]
            .as_str()
            .expect("token")
            .to_owned();

        let (status, _) = admin_post(
            &kit,
            "/v1/privacy/erase/confirm",
            &format!(r#"{{"token":"{token}","subject":"acct-2"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(count(&kit, "acct-2").await, 1, "the body chose the victim");
    }
}

#[pollster::test]
async fn a_forged_or_expired_token_erases_nothing() {
    for kit in kits() {
        seed(&kit).await;
        for token in ["", "not-a-token", "aaaa.bbbb.cccc"] {
            let (status, _) = admin_post(
                &kit,
                "/v1/privacy/erase/confirm",
                &format!(r#"{{"token":"{token}"}}"#),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "token {token:?} was accepted"
            );
        }
        assert_eq!(count(&kit, "acct-1").await, 2);
    }
}

#[pollster::test]
async fn erasure_without_admin_credentials_is_refused() {
    for kit in kits() {
        seed(&kit).await;
        let response = request(
            &kit.router,
            Method::POST,
            "/v1/privacy/erase",
            Some(r#"{"subject":"acct-1"}"#),
        )
        .await;
        assert_ne!(response.status, StatusCode::OK);
        assert_eq!(count(&kit, "acct-1").await, 2);
    }
}

// ------------------------------------------------------------- unreachable

/// A module whose ONLY declaration is one erasure cannot reach — the exact
/// composition where `holds_personal_data` used to read `false`, because
/// `subject_sets` skipped the table and nothing else counted it (issue #274).
struct OutboxOnly;

const OUTBOX_MIGRATION: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    "CREATE TABLE send_outbox (
              id TEXT PRIMARY KEY,
              payload TEXT NOT NULL
          );",
);

const OUTBOX_SETS: &[PersonalDataSet] = &[PersonalDataSet::unreachable(
    "send_outbox",
    DataKind::Content,
    "A message waiting to be sent, holding the text it was queued with.",
    "The message is filed under the send, not under a subject column, so an \
     erasure request cannot match the row.",
)];

impl Module for OutboxOnly {
    fn name(&self) -> &'static str {
        "outbox-only"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["send_outbox"]
    }
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        OUTBOX_SETS
    }
    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [OUTBOX_MIGRATION];
        Migrations::sqlite(&MIGRATIONS)
    }
    fn validate_config(&self, _cfg: &dyn cratefield_core::Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

fn outbox_only_kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || vec![Box::new(OutboxOnly), Box::new(Privacy::new())],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
        },
    )
}

#[pollster::test]
async fn a_deployment_holding_only_unreachable_data_says_it_holds_data() {
    for kit in outbox_only_kits() {
        let response = request(&kit.router, Method::GET, "/v1/privacy/manifest", None).await;
        assert_eq!(response.status, StatusCode::OK);
        let body: Value = response.json();

        // The export over this catalog is empty — `subject_sets` skips the
        // table, and that is correct: there is no predicate to build. The
        // deployment still holds data, and must say so.
        assert_eq!(body["holds_personal_data"], Value::Bool(true));

        let not_personal = body["not_personal"].as_array().expect("not_personal");
        assert!(
            not_personal.is_empty(),
            "a table holding a message was published as not personal: {not_personal:?}"
        );
        let unreachable = body["unreachable"].as_array().expect("unreachable");
        assert_eq!(unreachable.len(), 1, "{unreachable:?}");
        assert_eq!(unreachable[0]["table"], "send_outbox");
        assert_eq!(unreachable[0]["kind"], "content");
        assert!(
            unreachable[0]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("cannot match"),
            "{unreachable:?}"
        );
    }
}

#[pollster::test]
async fn an_export_over_unreachable_data_is_empty_not_an_error() {
    // The table is skipped, not queried: there is no predicate. The export
    // route must answer with an empty set of tables rather than failing or,
    // worse, reporting the table as erased.
    for kit in outbox_only_kits() {
        let (status, raw) = admin_get(&kit, "/v1/privacy/export?subject=acct-1").await;
        assert_eq!(status, StatusCode::OK, "{raw}");
        let body: Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(body["tables"].as_array().expect("tables").len(), 0, "{raw}");
    }
}
