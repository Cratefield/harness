//! The declared-table routes, over a real harness.
//!
//! The module here is what `fz build` will generate: it declares the
//! tables, requires `Port::Auth` because one of them is not public, and
//! its `router()` is `cratefield_tables_api::router`. Writing it by hand
//! is what makes this an end-to-end test rather than a test of the
//! handlers with the routing assumed.

use std::sync::Arc;

use axum::http::Method;
use cratefield_core::{Config, ConfigError, Migrations, Module, ModuleContext, Port, SqlMigration};
use cratefield_manifest::Access;
use cratefield_tables::{Schema, TableDef};
use cratefield_tables_api::{TableApi, Tables};
use cratefield_testing::{AuthMode, FakeAuth, TestHarness};

#[derive(serde::Deserialize)]
struct Fragment {
    tables: Schema,
}

const NOTE: &str = r#"
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

# A second table whose primary key is *not* called `id`. Without it a
# route that ignored `key_from_path` and hardcoded `{"id": segment}`
# passed every test, because `note`'s key happens to be `id`.
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

fn note() -> TableDef {
    declared("note")
}

fn declared(name: &str) -> TableDef {
    toml::from_str::<Fragment>(NOTE)
        .expect("parses")
        .tables
        .table(name)
        .expect("declared")
        .clone()
}

/// What `fz build` generates, written by hand.
struct DeclaredTables {
    access: Access,
}

impl Module for DeclaredTables {
    fn name(&self) -> &'static str {
        "tables"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        // What the generator emits for a venture whose tables are not all
        // public: the level is a question about who is asking.
        &[Port::Db, Port::Auth]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["note", "tier"]
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
                    table: note(),
                    access: self.access,
                    subject: Some("author".to_owned()),
                },
                TableApi {
                    table: declared("tier"),
                    access: self.access,
                    subject: None,
                },
            ],
            ctx: Arc::new(ctx),
        }))
    }
}

fn kits(access: Access) -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        move || vec![Box::new(DeclaredTables { access }) as Box<dyn Module>],
        |ports| {
            ports.auth = Some(Arc::new(FakeAuth::new(AuthMode::TokenIsTheSubject)));
        },
    )
}

async fn seed(kit: &TestHarness) {
    use cratefield_core::Statement;
    let db = kit.db.as_ref();
    for (id, author, body) in [
        ("n1", "ada", "first"),
        ("n2", "grace", "hers"),
        ("n3", "ada", "second"),
    ] {
        db.execute(&Statement::with_values(
            "INSERT INTO note (id, author, body) VALUES (?, ?, ?)".to_owned(),
            vec![id.into(), author.into(), body.into()],
        ))
        .await
        .expect("seeded");
    }
}

/// What a driven request answered. `TestResponse` has private fields, so
/// a test that builds its own request (this one needs a bearer header)
/// reads the parts itself.
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

async fn get_as(kit: &TestHarness, path: &str, bearer: Option<&str>) -> Answer {
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;
    let mut builder = Request::builder().method(Method::GET).uri(path);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = kit
        .router
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    Answer {
        status,
        body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
    }
}

fn ids(body: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(body).expect("json")["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["id"].as_str().expect("id").to_owned())
        .collect()
}

#[pollster::test]
async fn a_declared_table_is_served_at_its_own_path() {
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let response = get_as(&kit, "/v1/tables/note", None).await;
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(ids(&response.body), ["n1", "n2", "n3"]);
    }
}

#[pollster::test]
async fn an_owner_table_serves_a_caller_only_their_own_rows() {
    // The whole chain, over HTTP: the extractor resolves the tenant's
    // database, the `Auth` port names the caller, the access decision
    // scopes the read, and the scope reaches the `WHERE`.
    for kit in kits(Access::Owner) {
        seed(&kit).await;
        let response = get_as(&kit, "/v1/tables/note", Some("ada")).await;
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(ids(&response.body), ["n1", "n3"]);
    }
}

#[pollster::test]
async fn one_row_is_served_by_its_key_in_the_path() {
    for kit in kits(Access::Owner) {
        seed(&kit).await;
        let response = get_as(&kit, "/v1/tables/note/n1", Some("ada")).await;
        assert_eq!(response.status, 200, "{}", response.body);
        assert!(response.body.contains("first"), "{}", response.body);
    }
}

#[pollster::test]
async fn someone_elses_row_is_a_404_over_http_too() {
    for kit in kits(Access::Owner) {
        seed(&kit).await;
        let theirs = get_as(&kit, "/v1/tables/note/n2", Some("ada")).await;
        let absent = get_as(&kit, "/v1/tables/note/nope", Some("ada")).await;
        assert_eq!(theirs.status, 404, "{}", theirs.body);
        assert_eq!(absent.status, theirs.status);
        assert_eq!(absent.body, theirs.body, "the two 404s must be identical");
    }
}

#[pollster::test]
async fn an_anonymous_caller_is_told_to_sign_in() {
    for kit in kits(Access::Owner) {
        seed(&kit).await;
        let response = get_as(&kit, "/v1/tables/note", None).await;
        assert_eq!(response.status, 401, "{}", response.body);
    }
}

#[pollster::test]
async fn a_table_the_venture_does_not_declare_is_a_404() {
    for kit in kits(Access::PublicRead) {
        let response = get_as(&kit, "/v1/tables/ledger", None).await;
        assert_eq!(response.status, 404, "{}", response.body);
        assert!(response.body.contains("no-such-table"), "{}", response.body);
    }
}

#[pollster::test]
async fn a_cursor_resumes_after_the_row_it_names() {
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let response = get_as(&kit, "/v1/tables/note?after=n1", None).await;
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(ids(&response.body), ["n2", "n3"]);
    }
}

#[pollster::test]
async fn the_body_is_problem_json_rather_than_a_bare_status() {
    // A refusal a client can act on: the slug is the thing it branches
    // on, and a bare 401 would leave it guessing which of several
    // refusals it hit.
    for kit in kits(Access::Owner) {
        let response = get_as(&kit, "/v1/tables/note", None).await;
        assert!(
            response.body.contains("unauthenticated"),
            "{}",
            response.body
        );
    }
}

/// A table keyed by two columns, and one keyed by a kind no path segment
/// can carry.
const ODD_KEYS: &str = r#"
[tables.membership]
primary_key = ["tenant", "member"]

[[tables.membership.fields]]
name = "tenant"
kind = "text"
required = true

[[tables.membership.fields]]
name = "member"
kind = "text"
required = true

[tables.reading]
primary_key = "at"

[[tables.reading.fields]]
name = "at"
kind = "real"
required = true

[tables.counter]
primary_key = "n"

[[tables.counter.fields]]
name = "n"
kind = "integer"
required = true
"#;

fn odd(name: &str) -> TableDef {
    toml::from_str::<Fragment>(ODD_KEYS)
        .expect("parses")
        .tables
        .table(name)
        .expect("declared")
        .clone()
}

#[test]
fn a_composite_key_is_refused_rather_than_joined_with_a_separator() {
    // Inventing a separator makes a key containing that separator
    // unaddressable — silently, and only for the rows that contain it.
    let refusal = cratefield_tables_api::key_from_path(&odd("membership"), "acme:ada")
        .err()
        .expect("two columns, one segment");
    assert_eq!(refusal.slug, "composite-key");
    assert_eq!(refusal.status.as_u16(), 400);
}

#[test]
fn an_integer_key_is_parsed_and_a_non_number_is_refused() {
    let key = cratefield_tables_api::key_from_path(&odd("counter"), "42").expect("a number");
    assert_eq!(key.0, serde_json::json!({ "n": 42 }));
    assert!(
        cratefield_tables_api::key_from_path(&odd("counter"), "forty-two").is_err(),
        "a path segment that is not a number is not this table's key"
    );
}

#[test]
fn a_float_key_is_refused_rather_than_compared_for_equality() {
    // A key compared with `=` on a float is a key that sometimes matches
    // nothing, for reasons the caller cannot see.
    let refusal = cratefield_tables_api::key_from_path(&odd("reading"), "1.5")
        .err()
        .expect("not addressable");
    assert_eq!(refusal.slug, "bad-key");
}

#[test]
fn a_text_key_is_taken_as_written() {
    let key = cratefield_tables_api::key_from_path(&note(), "n1").expect("text");
    assert_eq!(key.0, serde_json::json!({ "id": "n1" }));
}

#[pollster::test]
async fn a_row_is_created_changed_and_deleted_over_http() {
    // The three routes the surface publishes and nothing served. A
    // published action whose route does not exist is worse than an
    // unpublished one: a generated UI renders the form and the
    // submission 404s.
    for kit in kits(Access::Owner) {
        seed(&kit).await;

        let created = send(
            &kit,
            Method::POST,
            "/v1/tables/note",
            Some("ada"),
            Some(r#"{"id":"n9","body":"mine"}"#),
        )
        .await;
        assert_eq!(created.status, 201, "{}", created.body);
        // The harness filled in whose row it is; the body never said.
        assert!(
            created.body.contains("\"author\":\"ada\""),
            "{}",
            created.body
        );

        let replaced = send(
            &kit,
            Method::PUT,
            "/v1/tables/note/n9",
            Some("ada"),
            Some(r#"{"id":"n9","body":"edited"}"#),
        )
        .await;
        assert_eq!(replaced.status, 200, "{}", replaced.body);

        let read = get_as(&kit, "/v1/tables/note/n9", Some("ada")).await;
        assert!(read.body.contains("edited"), "{}", read.body);

        let removed = send(
            &kit,
            Method::DELETE,
            "/v1/tables/note/n9",
            Some("ada"),
            None,
        )
        .await;
        assert_eq!(removed.status, 204, "{}", removed.body);
        assert!(
            removed.body.is_empty(),
            "a 204 carries no body: {}",
            removed.body
        );

        assert_eq!(
            get_as(&kit, "/v1/tables/note/n9", Some("ada")).await.status,
            404
        );
    }
}

#[pollster::test]
async fn a_caller_cannot_write_over_somebody_elses_row_through_the_routes() {
    // The access decision reaching the write routes, not just the
    // handlers: grace's row survives ada's PUT and her DELETE.
    for kit in kits(Access::Owner) {
        seed(&kit).await;

        let put = send(
            &kit,
            Method::PUT,
            "/v1/tables/note/n2",
            Some("ada"),
            Some(r#"{"id":"n2","body":"taken over"}"#),
        )
        .await;
        assert_eq!(put.status, 404, "{}", put.body);

        let del = send(
            &kit,
            Method::DELETE,
            "/v1/tables/note/n2",
            Some("ada"),
            None,
        )
        .await;
        assert_eq!(del.status, 404, "{}", del.body);

        // The row itself, which is the part that matters.
        let still = get_as(&kit, "/v1/tables/note/n2", Some("grace")).await;
        assert_eq!(still.status, 200, "{}", still.body);
        assert!(
            still.body.contains("hers"),
            "grace's row was changed: {}",
            still.body
        );
    }
}

#[pollster::test]
async fn a_public_table_refuses_every_write() {
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let created = send(
            &kit,
            Method::POST,
            "/v1/tables/note",
            None,
            Some(r#"{"id":"n9","author":"ada","body":"mine"}"#),
        )
        .await;
        assert_eq!(created.status, 403, "{}", created.body);
        assert!(created.body.contains("table-read-only"), "{}", created.body);
    }
}

#[pollster::test]
async fn every_published_action_is_a_route_that_exists() {
    // The cross-check that was missing. The surface published creates,
    // replaces and deletes while the router served two GETs, so the
    // published contract promised routes that answered 405.
    //
    // "Exists" is the question here, not "succeeds": a refusal is a route
    // answering. A 405 is the router saying the method is not mounted.
    use cratefield_tables_api::{TableApi, surface};

    for kit in kits(Access::Owner) {
        seed(&kit).await;
        let published = surface(&[TableApi {
            table: note(),
            access: Access::Owner,
            subject: Some("author".to_owned()),
        }]);
        assert!(!published.actions.is_empty(), "nothing was published");

        for action in &published.actions {
            let path = format!("/v1/tables{}", action.path.replace("{key}", "n1"));
            let body = matches!(action.method, Method::POST | Method::PUT)
                .then_some(r#"{"id":"n1","body":"x"}"#);
            let answer = send(&kit, action.method.clone(), &path, Some("ada"), body).await;
            assert_ne!(
                answer.status, 405,
                "`{}` is published as {} {} and the router does not serve it",
                action.name, action.method, path
            );
            assert_ne!(
                answer.status, 404,
                "`{}` is published as {} {} and the route is not there: {}",
                action.name, action.method, path, answer.body
            );
        }
    }
}

#[pollster::test]
async fn a_table_whose_key_is_not_called_id_is_addressed_by_its_own_key() {
    // `note`'s primary key is `id`, so a route that ignored
    // `key_from_path` and hardcoded `{"id": segment}` passed every test
    // here. `tier` is keyed by `slug`, which tells the two apart.
    for kit in kits(Access::TenantMembers) {
        {
            use cratefield_core::Statement;
            kit.db
                .execute(&Statement::with_values(
                    "INSERT INTO tier (slug, label) VALUES (?, ?)".to_owned(),
                    vec!["gold".into(), "Gold".into()],
                ))
                .await
                .expect("seeded");
        }

        let read = get_as(&kit, "/v1/tables/tier/gold", Some("ada")).await;
        assert_eq!(read.status, 200, "{}", read.body);
        assert!(read.body.contains("Gold"), "{}", read.body);

        // A PUT too: each route parses the key itself, so each needs a
        // table whose key is not called `id` to be checked against.
        let replaced = send(
            &kit,
            Method::PUT,
            "/v1/tables/tier/gold",
            Some("ada"),
            Some(r#"{"slug":"gold","label":"Gold tier"}"#),
        )
        .await;
        assert_eq!(replaced.status, 200, "{}", replaced.body);
        assert!(
            get_as(&kit, "/v1/tables/tier/gold", Some("ada"))
                .await
                .body
                .contains("Gold tier"),
            "the replacement did not land"
        );

        let removed = send(
            &kit,
            Method::DELETE,
            "/v1/tables/tier/gold",
            Some("ada"),
            None,
        )
        .await;
        assert_eq!(removed.status, 204, "{}", removed.body);
        assert_eq!(
            get_as(&kit, "/v1/tables/tier/gold", Some("ada"))
                .await
                .status,
            404
        );
    }
}
