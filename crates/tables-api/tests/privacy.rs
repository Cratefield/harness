//! A declared table's privacy declaration, end to end.
//!
//! The generated module emits a `PersonalDataSet` per declared table and
//! the privacy module reads the composed catalog. Nothing proved the two
//! meet: a declaration that never reaches an export is decoration, and it
//! is decoration that reads as compliance.
//!
//! So this mounts a declared-tables module beside `cratefield-privacy`
//! and asks the questions a subject would.

use std::sync::Arc;

use axum::http::Method;
use cratefield_core::{
    Config, ConfigError, Disposition, MapConfig, Migrations, Module, ModuleContext,
    PersonalDataSet, Port, SqlMigration,
};
use cratefield_manifest::Access;
use cratefield_tables::{Schema, TableDef};
use cratefield_tables_api::{TableApi, Tables};
use cratefield_testing::{AuthMode, FakeAuth, TestHarness};

const ADMIN: &str = "test-admin-token-0123456789abcdef";

#[derive(serde::Deserialize)]
struct Fragment {
    tables: Schema,
}

const DECLARED: &str = r#"
[tables.note]
primary_key = "id"

[[tables.note.fields]]
name = "id"
kind = "text"
required = true

[[tables.note.fields]]
name = "author"
kind = "text"
required = true

[[tables.note.fields]]
name = "body"
kind = "text"

[tables.tier]
primary_key = "slug"

[[tables.tier.fields]]
name = "slug"
kind = "text"
required = true

[[tables.tier.fields]]
name = "label"
kind = "text"
required = true
"#;

const DDL: &str = "CREATE TABLE IF NOT EXISTS note (id TEXT PRIMARY KEY NOT NULL, author TEXT NOT NULL, body TEXT); \
     CREATE TABLE IF NOT EXISTS tier (slug TEXT PRIMARY KEY NOT NULL, label TEXT NOT NULL)";

const MIGRATIONS: [SqlMigration; 1] = [SqlMigration::new("0001", "tables", DDL)];

/// What `fz build` emits for the manifest above: `note` holds somebody's
/// content and is erased; `tier` holds nobody and says why.
const SETS: &[PersonalDataSet] = &[
    PersonalDataSet {
        table: "note",
        subject: "author",
        kind: cratefield_core::DataKind::Content,
        disposition: Disposition::Erase,
        description: "The notes you wrote, and who wrote them.",
        redacted: &[],
        subject_via: None,
    },
    PersonalDataSet::none("tier", "Plan tiers; nobody is in them."),
];

fn declared(name: &str) -> TableDef {
    toml::from_str::<Fragment>(DECLARED)
        .expect("parses")
        .tables
        .table(name)
        .expect("declared")
        .clone()
}

struct DeclaredTables;

impl Module for DeclaredTables {
    fn name(&self) -> &'static str {
        "tables"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Auth]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["note", "tier"]
    }
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        SETS
    }
    fn migrations(&self) -> Migrations {
        Migrations::sqlite(&MIGRATIONS)
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, ctx: ModuleContext) -> axum::Router {
        cratefield_tables_api::router(Arc::new(Tables {
            tables: vec![
                TableApi {
                    table: declared("note"),
                    access: Access::Owner,
                    subject: Some("author".to_owned()),
                },
                TableApi {
                    table: declared("tier"),
                    access: Access::PublicRead,
                    subject: None,
                },
            ],
            ctx: Arc::new(ctx),
        }))
    }
}

fn kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || {
            vec![
                Box::new(DeclaredTables) as Box<dyn Module>,
                Box::new(cratefield_module_privacy::Privacy::new()),
            ]
        },
        |ports| {
            ports.auth = Some(Arc::new(FakeAuth::new(AuthMode::TokenIsTheSubject)));
            ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
        },
    )
}

struct Answer {
    status: axum::http::StatusCode,
    body: String,
}

async fn send(
    kit: &TestHarness,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> Answer {
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(json) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json.to_owned())),
        None => builder.body(Body::empty()),
    }
    .expect("request");
    let response = kit.router.clone().oneshot(request).await.expect("answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    Answer {
        status,
        body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
    }
}

/// Two notes of ada's, one of grace's, and a tier belonging to nobody.
async fn seed(kit: &TestHarness) {
    use cratefield_core::Statement;
    for (id, author, body) in [
        ("n1", "ada", "first"),
        ("n2", "grace", "hers"),
        ("n3", "ada", "second"),
    ] {
        kit.db
            .execute(&Statement::with_values(
                "INSERT INTO note (id, author, body) VALUES (?, ?, ?)".to_owned(),
                vec![id.into(), author.into(), body.into()],
            ))
            .await
            .expect("seeded");
    }
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO tier (slug, label) VALUES (?, ?)".to_owned(),
            vec!["gold".into(), "Gold".into()],
        ))
        .await
        .expect("seeded");
}

fn export_of(body: &str) -> serde_json::Value {
    serde_json::from_str(body).expect("json")
}

#[pollster::test]
async fn a_subjects_export_carries_their_rows_from_a_declared_table() {
    // The declaration says `note` holds somebody's content and names the
    // column. If the export does not read it, the declaration is a
    // sentence in a manifest that nothing acts on.
    for kit in kits() {
        seed(&kit).await;
        let answer = send(
            &kit,
            Method::GET,
            "/v1/privacy/export?subject=ada",
            Some(ADMIN),
            None,
        )
        .await;
        assert_eq!(answer.status, 200, "{}", answer.body);

        let export = export_of(&answer.body);
        let note = export["tables"]
            .as_array()
            .expect("tables")
            .iter()
            .find(|entry| entry["table"] == "note")
            .unwrap_or_else(|| panic!("the declared table is not in the export: {}", answer.body));

        let ids: Vec<&str> = note["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .map(|row| row["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["n1", "n3"], "ada's rows, and only hers");

        // And the sentence the author wrote is published with them.
        assert_eq!(
            note["description"],
            "The notes you wrote, and who wrote them."
        );
    }
}

#[pollster::test]
async fn a_table_that_holds_nobody_is_not_in_anybodys_export() {
    for kit in kits() {
        seed(&kit).await;
        let answer = send(
            &kit,
            Method::GET,
            "/v1/privacy/export?subject=ada",
            Some(ADMIN),
            None,
        )
        .await;
        let export = export_of(&answer.body);
        assert!(
            !export["tables"]
                .as_array()
                .expect("tables")
                .iter()
                .any(|entry| entry["table"] == "tier"),
            "a table declared to hold nobody appeared in a subject's export: {}",
            answer.body
        );
    }
}

#[pollster::test]
async fn the_privacy_manifest_names_every_declared_table() {
    // `/v1/privacy/manifest` is what a deployment publishes about what it
    // holds. A declared table missing from it is a table nobody can find
    // out about.
    for kit in kits() {
        let answer = send(&kit, Method::GET, "/v1/privacy/manifest", None, None).await;
        assert_eq!(answer.status, 200, "{}", answer.body);
        assert!(answer.body.contains("\"note\""), "{}", answer.body);
        assert!(answer.body.contains("\"tier\""), "{}", answer.body);
        assert!(
            answer.body.contains("Plan tiers; nobody is in them."),
            "the reason a table holds nobody is published too: {}",
            answer.body
        );
    }
}

#[pollster::test]
async fn erasure_removes_a_subjects_rows_from_a_declared_table() {
    // The half that matters most. A declaration saying `disposition =
    // "erase"` that nothing erases is worse than none: somebody is told
    // their data is gone and it is not.
    for kit in kits() {
        seed(&kit).await;

        let planned = send(
            &kit,
            Method::POST,
            "/v1/privacy/erase",
            Some(ADMIN),
            Some(r#"{"subject":"ada"}"#),
        )
        .await;
        assert_eq!(planned.status, 200, "{}", planned.body);
        let plan = export_of(&planned.body);
        assert!(
            planned.body.contains("note"),
            "the declared table is not in the plan: {}",
            planned.body
        );
        let token = plan["confirm_token"].as_str().expect("a confirm token");

        let done = send(
            &kit,
            Method::POST,
            "/v1/privacy/erase/confirm",
            Some(ADMIN),
            // Only the token: the subject comes from inside it, never
            // from the body, so a confirm cannot be pointed at somebody
            // else.
            Some(&format!(r#"{{"token":"{token}"}}"#)),
        )
        .await;
        assert_eq!(done.status, 200, "{}", done.body);

        // Ada's rows are gone and grace's are not. Asserting both,
        // because "the call succeeded" and "the right rows went" are
        // different facts.
        let remaining = send(
            &kit,
            Method::GET,
            "/v1/privacy/export?subject=ada",
            Some(ADMIN),
            None,
        )
        .await;
        let export = export_of(&remaining.body);
        let note = export["tables"]
            .as_array()
            .expect("tables")
            .iter()
            .find(|entry| entry["table"] == "note")
            .expect("still declared");
        assert!(
            note["rows"].as_array().expect("rows").is_empty(),
            "erasure left rows behind: {}",
            remaining.body
        );

        let hers = send(
            &kit,
            Method::GET,
            "/v1/privacy/export?subject=grace",
            Some(ADMIN),
            None,
        )
        .await;
        assert!(
            hers.body.contains("n2"),
            "erasing one subject took another's rows: {}",
            hers.body
        );
    }
}

#[pollster::test]
async fn erasure_leaves_a_table_that_holds_nobody_alone() {
    // `tier` is reference data. An erasure that swept it would delete a
    // venture's plan tiers the first time anybody asked.
    for kit in kits() {
        seed(&kit).await;
        let planned = send(
            &kit,
            Method::POST,
            "/v1/privacy/erase",
            Some(ADMIN),
            Some(r#"{"subject":"ada"}"#),
        )
        .await;
        let token = export_of(&planned.body)["confirm_token"]
            .as_str()
            .expect("a confirm token")
            .to_owned();
        send(
            &kit,
            Method::POST,
            "/v1/privacy/erase/confirm",
            Some(ADMIN),
            // Only the token: the subject comes from inside it, never
            // from the body, so a confirm cannot be pointed at somebody
            // else.
            Some(&format!(r#"{{"token":"{token}"}}"#)),
        )
        .await;

        let tier = send(&kit, Method::GET, "/v1/tables/tier/gold", None, None).await;
        assert_eq!(
            tier.status, 200,
            "an erasure took reference data with it: {}",
            tier.body
        );
    }
}
