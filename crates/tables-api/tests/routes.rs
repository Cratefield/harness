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

# A non-text column, so a filter's *value* can be checked and not only
# its name. Every other column here is text, which accepts anything.
[[tables.tier.fields]]
name = "rank"
kind = "integer"

# A composite key. `select_page` builds a lexicographic cursor over every
# key column; a route that parsed `after` as a path key refused one
# outright, so the query layer could express the page and the HTTP layer
# could not ask for it.
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

[[tables.membership.fields]]
name = "role"
kind = "text"
required = true

# Kinds no path segment and no `__by` query parameter can carry as a key:
# the `__by` query parses its values through the same coercion
# `key_from_path` uses, so a `real`, `boolean` or `json` key is refused
# wherever it is named.
[tables.reading]
primary_key = "at"

[[tables.reading.fields]]
name = "at"
kind = "real"
required = true

[tables.flipped]
primary_key = "enabled"

[[tables.flipped.fields]]
name = "enabled"
kind = "boolean"
required = true

[tables.payload]
primary_key = "doc"

[[tables.payload.fields]]
name = "doc"
kind = "json"
required = true

# `after` and `sort` are the harness's parameters on the `__by` sub-path,
# so a key that uses them can never be completed there — the reservation
# is the strand, and this table is what pins it as stated rather than
# discovered.
[tables.staged]
primary_key = ["after", "sort"]

[[tables.staged.fields]]
name = "after"
kind = "text"
required = true

[[tables.staged.fields]]
name = "sort"
kind = "text"
required = true
"#;

const DDL: &str = "CREATE TABLE IF NOT EXISTS note (id TEXT PRIMARY KEY NOT NULL, author TEXT NOT NULL, body TEXT); \
     CREATE TABLE IF NOT EXISTS tier (slug TEXT PRIMARY KEY NOT NULL, label TEXT NOT NULL, rank INTEGER); \
     CREATE TABLE IF NOT EXISTS membership (tenant TEXT NOT NULL, member TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY (tenant, member)); \
     CREATE TABLE IF NOT EXISTS reading (at REAL PRIMARY KEY NOT NULL); \
     CREATE TABLE IF NOT EXISTS flipped (enabled BOOLEAN PRIMARY KEY NOT NULL); \
     CREATE TABLE IF NOT EXISTS payload (doc TEXT PRIMARY KEY NOT NULL); \
     CREATE TABLE IF NOT EXISTS staged (\"after\" TEXT NOT NULL, \"sort\" TEXT NOT NULL, PRIMARY KEY (\"after\", \"sort\"))";

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
        &[
            "note",
            "tier",
            "membership",
            "reading",
            "flipped",
            "payload",
            "staged",
        ]
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
                // `member` is the subject column, so the composite table
                // has an `owner` shape too: a membership row belongs to
                // its member, which is what makes the `__by` leak test a
                // leak test rather than a 500.
                TableApi {
                    table: declared("membership"),
                    access: self.access,
                    subject: Some("member".to_owned()),
                },
                TableApi {
                    table: declared("reading"),
                    access: self.access,
                    subject: None,
                },
                TableApi {
                    table: declared("flipped"),
                    access: self.access,
                    subject: None,
                },
                TableApi {
                    table: declared("payload"),
                    access: self.access,
                    subject: None,
                },
                TableApi {
                    table: declared("staged"),
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
        let response = get_as(
            &kit,
            &format!(
                "/v1/tables/note?after={}",
                cursor_param(&serde_json::json!({ "id": "n1" }))
            ),
            None,
        )
        .await;
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
        // Both arities: the path spelling for a single-column key and the
        // `__by` spelling the composite-key table publishes against.
        let published = surface(&[
            TableApi {
                table: note(),
                access: Access::Owner,
                subject: Some("author".to_owned()),
            },
            TableApi {
                table: declared("membership"),
                access: Access::Owner,
                subject: Some("member".to_owned()),
            },
        ]);
        assert!(!published.actions.is_empty(), "nothing was published");

        for action in &published.actions {
            let path = format!("/v1/tables{}", action.path.replace("{key}", "n1"));
            let body = matches!(action.method, Method::POST | Method::PUT)
                .then_some(r#"{"id":"n1","body":"x"}"#);
            let answer = send(&kit, action.method.clone(), &path, Some("ada"), body).await;
            // A `__by` action sent without its query answers
            // `400 partial-key` — which is the route answering, which is
            // all "exists" asks. The query's own behaviour is the tests
            // above.
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

// ------------------------------------------------ the `__by` sub-path
//
// ADR 0018: `/{table}/__by?<column>=<value>&…` answers `GET`, `PUT` and
// `DELETE` with the bodies and statuses the path routes answer, the key
// named in the query. One route whatever the key's arity, no separator
// to escape, and the columns named rather than positional.

#[pollster::test]
async fn a_composite_key_row_is_served_by_its_key_named_in_the_query() {
    // The columns are named, not positional: the parameters in an order
    // the declaration does not list still name the same row, which is
    // the property no separator spelling has.
    for kit in kits(Access::TenantMembers) {
        {
            use cratefield_core::Statement;
            for (tenant, member) in [("acme", "ada"), ("acme", "grace")] {
                kit.db
                    .execute(&Statement::with_values(
                        "INSERT INTO membership (tenant, member, role) VALUES (?, ?, ?)".to_owned(),
                        vec![tenant.into(), member.into(), "member".into()],
                    ))
                    .await
                    .expect("seeded");
            }
        }

        let row = get_as(
            &kit,
            "/v1/tables/membership/__by?member=ada&tenant=acme",
            Some("ada"),
        )
        .await;
        assert_eq!(row.status, 200, "{}", row.body);
        let body = serde_json::from_str::<serde_json::Value>(&row.body).expect("json");
        assert_eq!(body["tenant"], "acme", "one row, not a page: {}", row.body);
        assert_eq!(body["member"], "ada");

        let other = get_as(
            &kit,
            "/v1/tables/membership/__by?tenant=acme&member=grace",
            Some("ada"),
        )
        .await;
        assert_eq!(other.status, 200, "{}", other.body);
        assert!(other.body.contains("grace"), "{}", other.body);
    }
}

#[pollster::test]
async fn a_composite_key_row_is_replaced_and_removed_through_by_query() {
    // The same statuses and bodies the path routes answer: a replace
    // answers the row it replaced, a remove answers `204` and nothing,
    // and both change the row the query named.
    for kit in kits(Access::TenantMembers) {
        {
            use cratefield_core::Statement;
            kit.db
                .execute(&Statement::with_values(
                    "INSERT INTO membership (tenant, member, role) VALUES (?, ?, ?)".to_owned(),
                    vec!["acme".into(), "ada".into(), "member".into()],
                ))
                .await
                .expect("seeded");
        }

        let replaced = send(
            &kit,
            Method::PUT,
            "/v1/tables/membership/__by?tenant=acme&member=ada",
            Some("ada"),
            Some(r#"{"tenant":"acme","member":"ada","role":"admin"}"#),
        )
        .await;
        assert_eq!(replaced.status, 200, "{}", replaced.body);
        assert!(replaced.body.contains("admin"), "{}", replaced.body);

        let read = get_as(
            &kit,
            "/v1/tables/membership/__by?tenant=acme&member=ada",
            Some("ada"),
        )
        .await;
        assert!(read.body.contains("admin"), "the replacement did not land");

        let removed = send(
            &kit,
            Method::DELETE,
            "/v1/tables/membership/__by?tenant=acme&member=ada",
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

        let gone = get_as(
            &kit,
            "/v1/tables/membership/__by?tenant=acme&member=ada",
            Some("ada"),
        )
        .await;
        assert_eq!(gone.status, 404, "{}", gone.body);
    }
}

#[pollster::test]
async fn a_complete_key_for_a_row_that_was_never_seeded_is_a_404_through_by() {
    // The direct answer, not the incidental one a delete leaves behind:
    // a key that is well formed and names every column, for a row that
    // does not exist, is a `no-such-row` — the same answer, byte for
    // byte, that the path route gives a single-column table for an
    // absent row. A refusal about the spelling would make the two
    // spellings of one address disagree about the same empty result.
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let absent = get_as(
            &kit,
            "/v1/tables/membership/__by?tenant=acme&member=nope",
            None,
        )
        .await;
        assert_eq!(absent.status, 404, "{}", absent.body);
        assert!(absent.body.contains("no-such-row"), "{}", absent.body);

        let by_path = get_as(&kit, "/v1/tables/note/nope", None).await;
        assert_eq!(by_path.status, 404, "{}", by_path.body);
        assert_eq!(
            absent.body, by_path.body,
            "the two spellings must answer an absent row identically"
        );
    }
}

#[pollster::test]
async fn a_partial_key_through_by_is_refused_and_says_what_is_missing() {
    // `select_one` refuses a half key rather than matching every row
    // that shares the given prefix, and the route refuses before it
    // asks. The detail names the column, so the fix is in the answer.
    for kit in kits(Access::TenantMembers) {
        let half = get_as(&kit, "/v1/tables/membership/__by?tenant=acme", Some("ada")).await;
        assert_eq!(half.status, 400, "{}", half.body);
        assert!(half.body.contains("partial-key"), "{}", half.body);
        assert!(half.body.contains("member"), "say which: {}", half.body);

        let none = get_as(&kit, "/v1/tables/membership/__by", Some("ada")).await;
        assert_eq!(none.status, 400, "{}", none.body);
        assert!(none.body.contains("partial-key"), "{}", none.body);
    }
}

#[pollster::test]
async fn a_query_naming_a_column_outside_the_key_is_refused_through_by() {
    // Ignoring it would answer a question the caller did not ask — the
    // page is where a table is narrowed, and `__by` names one row. A
    // misspelled key column is answered as the mistake it is, naming the
    // column, rather than as a key that happens to be short.
    for kit in kits(Access::TenantMembers) {
        let extra = get_as(
            &kit,
            "/v1/tables/membership/__by?tenant=acme&member=ada&role=member",
            Some("ada"),
        )
        .await;
        assert_eq!(extra.status, 400, "{}", extra.body);
        assert!(extra.body.contains("not-a-key-column"), "{}", extra.body);
        assert!(extra.body.contains("role"), "say which: {}", extra.body);

        let misspelled = get_as(
            &kit,
            "/v1/tables/membership/__by?tennat=acme&member=ada",
            Some("ada"),
        )
        .await;
        assert_eq!(misspelled.status, 400, "{}", misspelled.body);
        assert!(
            misspelled.body.contains("tennat"),
            "say which: {}",
            misspelled.body
        );
    }
}

#[pollster::test]
async fn a_real_boolean_and_json_key_are_refused_when_named_in_the_by_query() {
    // The `__by` query parses its values through the same coercion
    // `key_from_path` uses, so a kind no address can carry stays refused
    // on the route that was built for the keys the path could not.
    for kit in kits(Access::TenantMembers) {
        for (table, column) in [
            ("reading", "at"),
            ("flipped", "enabled"),
            ("payload", "doc"),
        ] {
            let answer = get_as(
                &kit,
                &format!("/v1/tables/{table}/__by?{column}=1"),
                Some("ada"),
            )
            .await;
            assert_eq!(answer.status, 400, "{table}: {}", answer.body);
            assert!(
                answer.body.contains("bad-key"),
                "{table} refused as something else: {}",
                answer.body
            );
        }
    }
}

#[pollster::test]
async fn a_single_column_table_is_addressed_through_by_as_well() {
    // The route answers for every declared table, not only composite-key
    // ones. For everybody else it is the longhand of the path spelling —
    // and, the next test says, the only address the reserved segment
    // leaves one particular row.
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let row = get_as(&kit, "/v1/tables/note/__by?id=n2", None).await;
        assert_eq!(row.status, 200, "{}", row.body);
        assert!(row.body.contains("hers"), "{}", row.body);
    }
}

#[pollster::test]
async fn the_row_whose_key_is_the_reserved_segment_is_reached_through_by() {
    // The strand the reservation ties, and the way back. `__by` is a
    // static segment and a static segment beats `{key}`, so the row of
    // `note` whose id is literally `__by` is no longer reachable by
    // path — that URL is the harness's route now, answering 400 for a
    // key that is not there rather than the row. Serving `__by` for
    // single-column tables too is what gives the row an address:
    // `?id=__by`.
    for kit in kits(Access::PublicRead) {
        {
            use cratefield_core::Statement;
            kit.db
                .execute(&Statement::with_values(
                    "INSERT INTO note (id, author, body) VALUES (?, ?, ?)".to_owned(),
                    vec!["__by".into(), "ada".into(), "reserved".into()],
                ))
                .await
                .expect("seeded");
        }

        let stranded = get_as(&kit, "/v1/tables/note/__by", None).await;
        assert_eq!(stranded.status, 400, "{}", stranded.body);
        assert!(
            stranded.body.contains("partial-key"),
            "the strand is stated, not discovered: {}",
            stranded.body
        );

        let reached = get_as(&kit, "/v1/tables/note/__by?id=__by", None).await;
        assert_eq!(reached.status, 200, "{}", reached.body);
        assert!(reached.body.contains("reserved"), "{}", reached.body);
    }
}

#[pollster::test]
async fn a_key_column_named_after_or_sort_has_no_address_on_by() {
    // `after` and `sort` are the harness's parameters on this sub-path,
    // read into their own fields before the key is — so a table whose
    // key uses one of those names can never complete its key here.
    // Naming both reserved words still leaves the key empty, and the
    // refusal says which column is missing rather than quietly reading
    // the reserved parameter as a value.
    for kit in kits(Access::TenantMembers) {
        let both = get_as(
            &kit,
            "/v1/tables/staged/__by?after=soon&sort=later",
            Some("ada"),
        )
        .await;
        assert_eq!(both.status, 400, "{}", both.body);
        assert!(both.body.contains("partial-key"), "{}", both.body);
        assert!(both.body.contains("after"), "say which: {}", both.body);
        assert!(both.body.contains("sort"), "say which: {}", both.body);

        let one = get_as(&kit, "/v1/tables/staged/__by?after=soon", Some("ada")).await;
        assert_eq!(one.status, 400, "{}", one.body);
        assert!(one.body.contains("sort"), "say which: {}", one.body);
    }
}

#[pollster::test]
async fn an_owner_table_serves_only_the_callers_own_row_through_by() {
    // The scope and the key are in the same `WHERE` on this route as on
    // the path one: ada naming grace's row by its full key is answered
    // not-found — the same answer an absent row gets — and naming her
    // own is answered with it.
    for kit in kits(Access::Owner) {
        {
            use cratefield_core::Statement;
            for member in ["ada", "grace"] {
                kit.db
                    .execute(&Statement::with_values(
                        "INSERT INTO membership (tenant, member, role) VALUES (?, ?, ?)".to_owned(),
                        vec!["acme".into(), member.into(), "member".into()],
                    ))
                    .await
                    .expect("seeded");
            }
        }

        let theirs = get_as(
            &kit,
            "/v1/tables/membership/__by?tenant=acme&member=grace",
            Some("ada"),
        )
        .await;
        assert_eq!(theirs.status, 404, "{}", theirs.body);
        assert!(theirs.body.contains("no-such-row"), "{}", theirs.body);

        let hers = get_as(
            &kit,
            "/v1/tables/membership/__by?tenant=acme&member=ada",
            Some("ada"),
        )
        .await;
        assert_eq!(hers.status, 200, "{}", hers.body);
    }
}

#[pollster::test]
async fn a_table_the_caller_may_not_read_is_refused_through_by() {
    // The key parses before the access decision runs, so a well-formed
    // key buys nobody the row. An anonymous caller is told to sign in —
    // the same answer the path route gives, from the same decision — and
    // a caller who does sign in is refused by that decision as well:
    // `tier` declares `owner` with no subject column, which is
    // `table-misdeclared` for whoever asks, verified or not. The row is
    // seeded, so a `200` here would take a skipped decision to explain.
    for kit in kits(Access::Owner) {
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

        let anonymous = get_as(&kit, "/v1/tables/tier/__by?slug=gold", None).await;
        assert_eq!(anonymous.status, 401, "{}", anonymous.body);
        assert!(
            anonymous.body.contains("unauthenticated"),
            "{}",
            anonymous.body
        );

        let signed_in = get_as(&kit, "/v1/tables/tier/__by?slug=gold", Some("ada")).await;
        assert_eq!(signed_in.status, 500, "{}", signed_in.body);
        assert!(
            signed_in.body.contains("table-misdeclared"),
            "{}",
            signed_in.body
        );
    }
}

#[pollster::test]
async fn a_filter_narrows_a_page() {
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let mine = get_as(&kit, "/v1/tables/note?author=ada", None).await;
        assert_eq!(mine.status, 200, "{}", mine.body);
        assert_eq!(ids(&mine.body), ["n1", "n3"]);
    }
}

#[pollster::test]
async fn a_filter_cannot_widen_an_owner_scope() {
    // The one that matters. Under `owner` the subject condition and the
    // filter are both in the `WHERE`, so filtering on the subject column
    // narrows the caller's own rows and reaches nobody else's. A filter
    // that *replaced* the scope would hand ada grace's row for the asking.
    for kit in kits(Access::Owner) {
        seed(&kit).await;

        let theirs = get_as(&kit, "/v1/tables/note?author=grace", Some("ada")).await;
        assert_eq!(theirs.status, 200, "{}", theirs.body);
        assert!(
            ids(&theirs.body).is_empty(),
            "a filter reached another subject's rows: {}",
            theirs.body
        );

        // And her own filter still narrows her own rows.
        let hers = get_as(&kit, "/v1/tables/note?author=ada", Some("ada")).await;
        assert_eq!(ids(&hers.body), ["n1", "n3"]);
    }
}

#[pollster::test]
async fn a_filter_on_a_column_the_table_does_not_have_is_refused() {
    // Not ignored. Ignoring it answers a question the caller did not ask,
    // with more rows than they asked for — and a client that misspells a
    // column would get a page that looks right.
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let answer = get_as(&kit, "/v1/tables/note?auther=ada", None).await;
        assert_eq!(answer.status, 400, "{}", answer.body);
        assert!(answer.body.contains("bad-filter"), "{}", answer.body);
        assert!(answer.body.contains("auther"), "say which: {}", answer.body);
    }
}

#[pollster::test]
async fn a_filter_whose_value_is_not_the_columns_kind_is_refused() {
    // The column name being declared is not enough: a query string is
    // text, and what that text means is the column's kind. `rank` is an
    // integer, so `gold` is not a value of it.
    for kit in kits(Access::TenantMembers) {
        let answer = get_as(&kit, "/v1/tables/tier?rank=gold", Some("ada")).await;
        assert_eq!(answer.status, 400, "{}", answer.body);
        assert!(answer.body.contains("bad-filter"), "{}", answer.body);
        assert!(answer.body.contains("rank"), "say which: {}", answer.body);

        // And a number is.
        let fine = get_as(&kit, "/v1/tables/tier?rank=1", Some("ada")).await;
        assert_eq!(fine.status, 200, "{}", fine.body);
    }
}

#[pollster::test]
async fn an_empty_filter_value_is_a_legal_text_value() {
    // Worth pinning rather than leaving to chance: `?body=` is a filter
    // for the empty string, not an absent filter. Treating it as absent
    // would widen the page on a query the caller meant to narrow it.
    for kit in kits(Access::TenantMembers) {
        seed(&kit).await;
        let answer = get_as(&kit, "/v1/tables/note?body=", Some("ada")).await;
        assert_eq!(answer.status, 200, "{}", answer.body);
        assert!(
            ids(&answer.body).is_empty(),
            "an empty filter value was dropped: {}",
            answer.body
        );
    }
}

#[pollster::test]
async fn the_cursor_and_a_filter_hold_together() {
    // Both conditions stand: the filter says which rows and the cursor
    // says where in them. Dropping either is a different bug — without
    // the filter the page widens, without the cursor it repeats.
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let answer = get_as(
            &kit,
            &format!(
                "/v1/tables/note?author=ada&after={}",
                cursor_param(&serde_json::json!({ "id": "n1" }))
            ),
            None,
        )
        .await;
        assert_eq!(answer.status, 200, "{}", answer.body);
        assert_eq!(ids(&answer.body), ["n3"]);
    }
}

/// The `?after=` value for a cursor the server handed back.
///
/// Percent-encoded, because the cursor is JSON and a query string is not
/// a place to put braces and quotes unescaped.
fn cursor_param(next: &serde_json::Value) -> String {
    next.to_string()
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

#[pollster::test]
async fn a_composite_key_table_is_served_and_says_when_there_is_no_more() {
    for kit in kits(Access::TenantMembers) {
        {
            use cratefield_core::Statement;
            for (tenant, member) in [("acme", "ada"), ("acme", "grace"), ("beta", "ada")] {
                kit.db
                    .execute(&Statement::with_values(
                        "INSERT INTO membership (tenant, member, role) VALUES (?, ?, ?)".to_owned(),
                        vec![tenant.into(), member.into(), "member".into()],
                    ))
                    .await
                    .expect("seeded");
            }
        }
        let first = get_as(&kit, "/v1/tables/membership", Some("ada")).await;
        assert_eq!(first.status, 200, "{}", first.body);
        let body = serde_json::from_str::<serde_json::Value>(&first.body).expect("json");
        assert_eq!(body["rows"].as_array().expect("rows").len(), 3);
        assert!(
            body["next"].is_null(),
            "a short page claimed more: {}",
            first.body
        );
    }
}

#[pollster::test]
async fn a_full_page_of_a_composite_key_table_round_trips_its_cursor() {
    // The whole point: whatever `next` is, sending it back works. A
    // composite key could not be expressed at all through the old path
    // parser, so this page was unreachable over HTTP.
    for kit in kits(Access::TenantMembers) {
        {
            use cratefield_core::Statement;
            for n in 0..(cratefield_tables_api::PAGE + 2) {
                kit.db
                    .execute(&Statement::with_values(
                        "INSERT INTO membership (tenant, member, role) VALUES (?, ?, ?)".to_owned(),
                        vec!["acme".into(), format!("m{n:03}").into(), "member".into()],
                    ))
                    .await
                    .expect("seeded");
            }
        }
        let first = get_as(&kit, "/v1/tables/membership", Some("ada")).await;
        let next =
            serde_json::from_str::<serde_json::Value>(&first.body).expect("json")["next"].clone();
        assert!(
            !next.is_null(),
            "a full page has more after it: {}",
            first.body
        );

        let second = get_as(
            &kit,
            &format!("/v1/tables/membership?after={}", cursor_param(&next)),
            Some("ada"),
        )
        .await;
        assert_eq!(
            second.status, 200,
            "the cursor was refused: {}",
            second.body
        );
        let rows = serde_json::from_str::<serde_json::Value>(&second.body).expect("json");
        assert!(
            !rows["rows"].as_array().expect("rows").is_empty(),
            "the second page is empty: {}",
            second.body
        );
    }
}

#[pollster::test]
async fn a_cursor_that_is_not_this_tables_is_refused_with_a_reason() {
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        // Not JSON at all — the shape a client would send if it had
        // guessed the old bare-value form.
        let bare = get_as(&kit, "/v1/tables/note?after=n1", None).await;
        assert_eq!(bare.status, 400, "{}", bare.body);
        assert!(bare.body.contains("bad-cursor"), "{}", bare.body);

        // An object naming the key, with a value that is not its kind.
        let wrong_kind = get_as(
            &kit,
            &format!(
                "/v1/tables/note?after={}",
                cursor_param(&serde_json::json!({ "id": 42 }))
            ),
            None,
        )
        .await;
        assert_eq!(wrong_kind.status, 400, "{}", wrong_kind.body);
        assert!(
            wrong_kind.body.contains("is text"),
            "say what it should be: {}",
            wrong_kind.body
        );

        // An object that does not name the key at all.
        let missing = get_as(
            &kit,
            &format!(
                "/v1/tables/note?after={}",
                cursor_param(&serde_json::json!({ "slug": "x" }))
            ),
            None,
        )
        .await;
        assert_eq!(missing.status, 400, "{}", missing.body);
        assert!(missing.body.contains("`id`"), "say which: {}", missing.body);
    }
}

/// A `POST /v1/tables/__batch` with a JSON body.
async fn batch(kit: &TestHarness, bearer: Option<&str>, body: &str) -> Answer {
    send(kit, Method::POST, "/v1/tables/__batch", bearer, Some(body)).await
}

#[pollster::test]
async fn a_batch_answers_several_reads_in_request_order() {
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let answer = batch(
            &kit,
            None,
            r#"{"reads":[{"table":"tier"},{"table":"note"},{"table":"tier"}]}"#,
        )
        .await;
        assert_eq!(answer.status, 200, "{}", answer.body);
        let results = serde_json::from_str::<serde_json::Value>(&answer.body).expect("json");
        let tables: Vec<&str> = results["results"]
            .as_array()
            .expect("results")
            .iter()
            .map(|entry| entry["table"].as_str().expect("table"))
            .collect();
        assert_eq!(tables, ["tier", "note", "tier"], "order is the caller's");
    }
}

#[pollster::test]
async fn a_batch_cannot_ask_for_what_the_caller_could_not_ask_alone() {
    // The rule that matters. Each read is decided on its own, against
    // this caller — a batch is a way to ask several questions in one
    // request, never a way to ask one that would be refused singly.
    for kit in kits(Access::Owner) {
        seed(&kit).await;
        let refused = batch(&kit, None, r#"{"reads":[{"table":"note"}]}"#).await;
        assert_eq!(refused.status, 401, "{}", refused.body);

        // And signed in, the same batch is scoped to the caller's rows.
        let mine = batch(&kit, Some("ada"), r#"{"reads":[{"table":"note"}]}"#).await;
        assert_eq!(mine.status, 200, "{}", mine.body);
        let results = serde_json::from_str::<serde_json::Value>(&mine.body).expect("json");
        let ids: Vec<&str> = results["results"][0]["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .map(|row| row["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["n1", "n3"], "a batch widened an owner scope");
    }
}

#[pollster::test]
async fn one_refused_read_refuses_the_whole_batch_and_says_which() {
    // Not a 200 carrying a refusal per result: a success that is not one,
    // which every client would have to remember to look inside.
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let answer = batch(
            &kit,
            None,
            r#"{"reads":[{"table":"note"},{"table":"ledger"},{"table":"tier"}]}"#,
        )
        .await;
        assert_eq!(answer.status, 404, "{}", answer.body);
        assert!(
            answer.body.contains("read 1") && answer.body.contains("ledger"),
            "say which read it was: {}",
            answer.body
        );
    }
}

#[pollster::test]
async fn a_batch_filters_and_pages_each_read_on_its_own() {
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let answer = batch(
            &kit,
            None,
            r#"{"reads":[{"table":"note","where":{"author":"ada"}},{"table":"note"}]}"#,
        )
        .await;
        assert_eq!(answer.status, 200, "{}", answer.body);
        let results = serde_json::from_str::<serde_json::Value>(&answer.body).expect("json");
        assert_eq!(
            results["results"][0]["rows"]
                .as_array()
                .expect("rows")
                .len(),
            2
        );
        assert_eq!(
            results["results"][1]["rows"]
                .as_array()
                .expect("rows")
                .len(),
            3
        );
    }
}

#[pollster::test]
async fn a_batch_with_no_reads_or_too_many_is_refused() {
    for kit in kits(Access::PublicRead) {
        let empty = batch(&kit, None, r#"{"reads":[]}"#).await;
        assert_eq!(empty.status, 400, "{}", empty.body);
        assert!(empty.body.contains("no-reads"), "{}", empty.body);

        let many = format!(
            r#"{{"reads":[{}]}}"#,
            std::iter::repeat_n(r#"{"table":"note"}"#, cratefield_tables_api::MAX_READS + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        let over = batch(&kit, None, &many).await;
        assert_eq!(over.status, 400, "{}", over.body);
        assert!(over.body.contains("too-many-reads"), "{}", over.body);
    }
}

#[test]
fn the_batch_path_can_never_be_a_table_name() {
    // The route is registered before `/{table}`, but the reason it cannot
    // collide is upstream of the router: a declared name starts with a
    // lowercase letter and may not contain `__`.
    let name = cratefield_tables_api::batch::PATH.trim_start_matches('/');
    assert!(
        !cratefield_tables::is_identifier(name),
        "`{name}` is a legal table name, so a venture could shadow the batch route"
    );
}

#[pollster::test]
async fn a_page_can_be_sorted_and_reversed() {
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let up = get_as(&kit, "/v1/tables/note?sort=id", None).await;
        assert_eq!(up.status, 200, "{}", up.body);
        assert_eq!(ids(&up.body), ["n1", "n2", "n3"]);

        let down = get_as(&kit, "/v1/tables/note?sort=-id", None).await;
        assert_eq!(down.status, 200, "{}", down.body);
        assert_eq!(ids(&down.body), ["n3", "n2", "n1"]);
    }
}

#[pollster::test]
async fn sorting_by_an_optional_column_is_refused_rather_than_answered_differently() {
    // SQLite sorts `NULL` first and Postgres sorts it last, so a page
    // ordered by a nullable column is a different page on each engine.
    // Refusing is the only answer that is the same on both.
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let answer = get_as(&kit, "/v1/tables/note?sort=body", None).await;
        assert_eq!(answer.status, 400, "{}", answer.body);
        assert!(
            answer.body.contains("bad-sort"),
            "a sort problem labelled as something else: {}",
            answer.body
        );
        assert!(answer.body.contains("body"), "say which: {}", answer.body);
    }
}

#[pollster::test]
async fn a_sorted_page_hands_back_a_cursor_that_resumes_the_same_order() {
    // The cursor carries the sort column as well as the key. One with
    // only the key resumes in key order, which silently reshuffles
    // everything after the first page — and every row of page two would
    // look plausible.
    for kit in kits(Access::TenantMembers) {
        {
            use cratefield_core::Statement;
            for n in 0..(cratefield_tables_api::PAGE + 2) {
                kit.db
                    .execute(&Statement::with_values(
                        "INSERT INTO membership (tenant, member, role) VALUES (?, ?, ?)".to_owned(),
                        vec![
                            "acme".into(),
                            format!("m{n:03}").into(),
                            format!("r{:03}", 999 - n).into(),
                        ],
                    ))
                    .await
                    .expect("seeded");
            }
        }
        let first = get_as(&kit, "/v1/tables/membership?sort=role", Some("ada")).await;
        assert_eq!(first.status, 200, "{}", first.body);
        let body = serde_json::from_str::<serde_json::Value>(&first.body).expect("json");
        let next = body["next"].clone();
        assert!(!next.is_null(), "a full page has more: {}", first.body);
        assert!(
            next.get("role").is_some(),
            "the cursor has to carry the sort column: {next}"
        );

        let second = get_as(
            &kit,
            &format!(
                "/v1/tables/membership?sort=role&after={}",
                cursor_param(&next)
            ),
            Some("ada"),
        )
        .await;
        assert_eq!(second.status, 200, "{}", second.body);
        let rows = serde_json::from_str::<serde_json::Value>(&second.body).expect("json");
        let roles: Vec<String> = rows["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .map(|row| row["role"].as_str().expect("role").to_owned())
            .collect();
        assert!(
            !roles.is_empty(),
            "the second page is empty: {}",
            second.body
        );
        let last_of_first = next["role"].as_str().expect("a role");
        assert!(
            roles.iter().all(|role| role.as_str() > last_of_first),
            "page two went back over page one: {roles:?} after {last_of_first}"
        );
    }
}

#[pollster::test]
async fn a_cursor_without_the_sort_column_is_refused() {
    // A client that sorted and then sent back a key-only cursor is asking
    // to resume an ordering it has not named a place in.
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let answer = get_as(
            &kit,
            &format!(
                "/v1/tables/note?sort=author&after={}",
                cursor_param(&serde_json::json!({ "id": "n1" }))
            ),
            None,
        )
        .await;
        assert_eq!(answer.status, 400, "{}", answer.body);
        assert!(answer.body.contains("author"), "say which: {}", answer.body);
        // A cursor short of a column the page is ordered by is a *cursor*
        // problem, not a sort one — the sort is fine, the place to resume
        // is not. Asserting the slug is what makes the route's own check
        // worth having: without it the query layer refuses too, and calls
        // it `bad-sort`.
        assert!(
            answer.body.contains("bad-cursor"),
            "labelled as something else: {}",
            answer.body
        );
    }
}

#[pollster::test]
async fn a_batch_read_can_be_sorted_too() {
    // Or the batch is a second-class way to ask the same question.
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let answer = batch(&kit, None, r#"{"reads":[{"table":"note","sort":"-id"}]}"#).await;
        assert_eq!(answer.status, 200, "{}", answer.body);
        let results = serde_json::from_str::<serde_json::Value>(&answer.body).expect("json");
        let ids: Vec<&str> = results["results"][0]["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .map(|row| row["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["n3", "n2", "n1"]);
    }
}

#[pollster::test]
async fn a_sort_column_the_table_does_not_have_is_refused_as_a_sort() {
    for kit in kits(Access::PublicRead) {
        seed(&kit).await;
        let answer = get_as(&kit, "/v1/tables/note?sort=nope", None).await;
        assert_eq!(answer.status, 400, "{}", answer.body);
        assert!(answer.body.contains("bad-sort"), "{}", answer.body);
    }
}
