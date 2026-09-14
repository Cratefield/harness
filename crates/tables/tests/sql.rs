//! The statements that read and write a declared table's rows.
//!
//! Two of these are the reason the module exists rather than the handlers
//! building SQL themselves: a value that looks like SQL is bound and
//! never rendered, and a key that names half a composite primary key is
//! refused rather than matching every row that shares the half.

use cratefield_core::Row;
use cratefield_tables::{
    DecodeError, Schema, UpdateError, delete, from_sql, insert, row_json, select_one, select_page,
    to_sql, update,
};
use sea_query::Value as SeaValue;
use serde_json::{Value, json};

#[derive(serde::Deserialize)]
struct Manifest {
    tables: Schema,
}

fn schema(fragment: &str) -> Schema {
    toml::from_str::<Manifest>(fragment)
        .expect("the fragment parses")
        .tables
}

const NOTE: &str = r#"
[tables.note]
primary_key = "id"

[[tables.note.fields]]
name = "id"
kind = "uuid"
required = true

[[tables.note.fields]]
name = "body"
kind = "text"
max_len = 400

[[tables.note.fields]]
name = "pinned"
kind = "boolean"

[[tables.note.fields]]
name = "weight"
kind = "real"

[[tables.note.fields]]
name = "views"
kind = "integer"

[[tables.note.fields]]
name = "meta"
kind = "json"
"#;

/// A table whose primary key is two columns — the shape a partial key is
/// dangerous for.
const MEMBERSHIP: &str = r#"
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
"#;

fn note() -> cratefield_tables::TableDef {
    schema(NOTE).table("note").expect("declared").clone()
}

fn membership() -> cratefield_tables::TableDef {
    schema(MEMBERSHIP)
        .table("membership")
        .expect("declared")
        .clone()
}

const ID: &str = "0f3f8a5e-9c4c-4a3e-8b2e-1d6f0c9a7b21";

#[test]
fn a_value_that_looks_like_sql_is_bound_and_never_rendered() {
    // The reason the handlers do not build SQL by formatting: a row's
    // values arrive from an HTTP request, and this one is written to
    // close the statement and start another.
    let hostile = "'); DROP TABLE note; --";
    let statement = insert(&note(), &json!({ "id": ID, "body": hostile })).expect("a legal row");

    assert!(
        !statement.sql.contains("DROP"),
        "the value reached the SQL text: {}",
        statement.sql
    );
    assert!(
        statement
            .values
            .0
            .iter()
            .any(|value| matches!(value, SeaValue::String(Some(text)) if text.as_str() == hostile)),
        "the value should be bound, and it is not among {:?}",
        statement.values.0
    );
}

/// Every quoted identifier in `sql`.
fn identifiers(sql: &str) -> std::collections::BTreeSet<String> {
    sql.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_row_key_cannot_become_an_identifier() {
    // The statement builders walk the table's declared fields, never the
    // row's keys, so a key the table does not declare has no path into
    // the SQL whatever it contains. Asserted as the property rather than
    // as "the hostile string is absent": an assertion that one particular
    // string does not appear passes for every string nobody thought of.
    let table = note();
    let mut allowed: std::collections::BTreeSet<String> = table
        .fields
        .iter()
        .map(|field| field.name.clone())
        .collect();
    allowed.insert(table.name.clone());

    let row = json!({ "id": ID, "body": "hello" });
    let key = json!({ "id": ID });
    let statements = [
        insert(&table, &row).expect("insert").sql,
        select_one(&table, &key).expect("select one").sql,
        select_page(&table, 10, Some(&key)).expect("page").sql,
        update(&table, &key, &row).expect("update").sql,
        delete(&table, &key).expect("delete").sql,
    ];
    for sql in statements {
        let used = identifiers(&sql);
        assert!(
            used.is_subset(&allowed),
            "an identifier that is not declared reached the SQL: {:?} in {sql}",
            used.difference(&allowed).collect::<Vec<_>>()
        );
        assert!(!used.is_empty(), "nothing was quoted at all: {sql}");
    }

    // And the row validator refuses the undeclared key first, which is
    // the message the caller gets.
    let hostile = "body\") VALUES (\"x";
    let errors = insert(&table, &json!({ "id": ID, hostile: "anything" }))
        .expect_err("an undeclared key is not a legal row");
    assert_eq!(
        errors
            .errors()
            .iter()
            .map(|error| error.code)
            .collect::<Vec<_>>(),
        vec![cratefield_tables::ErrorCode::UnknownField],
        "{errors}"
    );
}

#[test]
fn half_a_composite_key_is_refused_rather_than_matching_every_row_sharing_it() {
    // `DELETE FROM membership WHERE tenant = 'acme'` removes every member
    // of the tenant. The key has to be complete or there is no statement.
    let table = membership();
    let half = json!({ "tenant": "acme" });

    let error = delete(&table, &half).expect_err("half a key");
    assert_eq!(error.column, "member", "{error}");
    assert!(error.to_string().contains("does not give it"), "{error}");

    assert!(select_one(&table, &half).is_err(), "select too");

    let whole = json!({ "tenant": "acme", "member": "ada" });
    let statement = delete(&table, &whole).expect("a whole key");
    assert_eq!(statement.values.0.len(), 2, "{}", statement.sql);
}

#[test]
fn a_null_key_column_is_not_a_key() {
    // `WHERE member = NULL` is never true, so a null key would delete
    // nothing and report success. It is a missing key, not a value.
    let error = delete(
        &membership(),
        &json!({ "tenant": "acme", "member": Value::Null }),
    )
    .expect_err("a null is not a key");
    assert_eq!(error.column, "member", "{error}");
}

#[test]
fn a_key_value_of_the_wrong_kind_is_refused_rather_than_bound_as_a_null() {
    // The route that does not go through the row validator: a key comes
    // from a URL, not from a body. Binding `42` for a `uuid` column as a
    // null would make `WHERE id = NULL` — never true — so the delete
    // would remove nothing and report success.
    let table = note();
    let error = delete(&table, &json!({ "id": 42 })).expect_err("not a uuid");
    assert_eq!(error.column, "id", "{error}");
    assert!(error.to_string().contains("is not uuid"), "{error}");

    assert!(
        select_one(&table, &json!({ "id": 42 })).is_err(),
        "select too"
    );
    assert!(
        select_page(&table, 10, Some(&json!({ "id": 42 }))).is_err(),
        "and the cursor"
    );
    assert!(
        update(
            &table,
            &json!({ "id": 42 }),
            &json!({ "id": ID, "body": "x" })
        )
        .is_err(),
        "and the update's key"
    );
}

#[test]
fn a_value_of_the_wrong_kind_never_becomes_a_null_column() {
    // `to_sql` answers `None` rather than the typed null, so no caller
    // can turn "the wrong kind" into "absent" by accident.
    let table = note();
    let views = table
        .fields
        .iter()
        .find(|field| field.name == "views")
        .expect("declared");
    assert_eq!(to_sql(views, Some(&json!("seven"))), None);
    assert_eq!(
        to_sql(views, Some(&json!(7))),
        Some(SeaValue::BigInt(Some(7)))
    );
    // An absent or explicitly null value is still the typed null.
    assert_eq!(to_sql(views, None), Some(SeaValue::BigInt(None)));
    assert_eq!(
        to_sql(views, Some(&Value::Null)),
        Some(SeaValue::BigInt(None))
    );
}

#[test]
fn a_row_survives_the_round_trip_to_the_database_and_back() {
    let table = note();
    let row = json!({
        "id": ID,
        "body": "hello",
        "pinned": true,
        "weight": 1.5,
        "views": 42,
        "meta": { "tag": ["a", "b"] },
    });
    // What the adapter would hand back: the same values, under the same
    // column names.
    let returned = Row::new(
        table
            .fields
            .iter()
            .map(|field| {
                (
                    field.name.clone(),
                    to_sql(field, row.get(&field.name)).expect("the row is legal"),
                )
            })
            .collect(),
    );
    assert_eq!(row_json(&table, &returned).expect("decodes"), row);
}

#[test]
fn sqlite_answers_a_boolean_with_an_integer_and_a_real_with_one_too() {
    // SQLite has no boolean type — the DDL renders the column as INTEGER
    // there — and its column affinity stores a whole number in a REAL
    // column as an integer. Postgres answers with the declared types.
    // Both have to decode to the declared JSON kind, or the same
    // declaration serves different JSON from two deployments.
    let table = note();
    let returned = Row::new(vec![
        (
            "id".to_owned(),
            SeaValue::String(Some(Box::new(ID.to_owned()))),
        ),
        ("body".to_owned(), SeaValue::String(None)),
        ("pinned".to_owned(), SeaValue::Int(Some(1))),
        ("weight".to_owned(), SeaValue::BigInt(Some(2))),
        ("views".to_owned(), SeaValue::Int(Some(7))),
        ("meta".to_owned(), SeaValue::String(None)),
    ]);
    assert_eq!(
        row_json(&table, &returned).expect("decodes"),
        json!({
            "id": ID,
            "body": null,
            "pinned": true,
            "weight": 2.0,
            "views": 7,
            "meta": null,
        })
    );
}

#[test]
fn a_column_that_is_not_the_declared_kind_is_an_error_and_not_a_null() {
    // Turning it into `null` would publish wrong data through an API that
    // promises the declared JSON Schema. The database has drifted from
    // the declaration, which is a finding.
    let table = note();
    let body = table
        .fields
        .iter()
        .find(|field| field.name == "body")
        .expect("declared");
    let error = from_sql("note", body, &SeaValue::BigInt(Some(3))).expect_err("not text");
    assert_eq!(
        error,
        DecodeError {
            table: "note".to_owned(),
            column: "body".to_owned(),
            detail: "declared text, and the database did not answer with text".to_owned(),
        }
    );
}

#[test]
fn stored_text_that_is_not_json_is_an_error_that_does_not_quote_it() {
    let table = note();
    let meta = table
        .fields
        .iter()
        .find(|field| field.name == "meta")
        .expect("declared");
    let stored = "{not json, and a secret: hunter2";
    let error = from_sql(
        "note",
        meta,
        &SeaValue::String(Some(Box::new(stored.to_owned()))),
    )
    .expect_err("not json");
    assert!(
        !error.to_string().contains("hunter2"),
        "a venture's row content must not reach a log: {error}"
    );
}

#[test]
fn a_column_the_row_does_not_carry_is_an_error() {
    let table = note();
    let returned = Row::new(vec![(
        "id".to_owned(),
        SeaValue::String(Some(Box::new(ID.to_owned()))),
    )]);
    let error = row_json(&table, &returned).expect_err("short a column");
    assert_eq!(error.column, "body", "{error}");
}

#[test]
fn a_field_the_row_leaves_out_is_left_out_of_the_insert() {
    // So the column's DDL default applies. Binding an explicit null would
    // overwrite the default with nothing.
    let statement = insert(&note(), &json!({ "id": ID })).expect("a legal row");
    assert_eq!(statement.values.0.len(), 1, "{}", statement.sql);
    assert!(!statement.sql.contains("body"), "{}", statement.sql);
}

#[test]
fn a_null_is_bound_with_the_column_type_rather_than_untyped() {
    // Postgres binds parameters by type and cannot infer one for a bare
    // null; SQLite does not care. An untyped null passes every local test
    // and fails on the deployed Postgres.
    let table = note();
    let statement = insert(
        &table,
        &json!({ "id": ID, "body": Value::Null, "views": Value::Null }),
    )
    .expect("a legal row");
    assert!(
        statement.values.0.contains(&SeaValue::String(None)),
        "the text null should carry its type: {:?}",
        statement.values.0
    );
    assert!(
        statement.values.0.contains(&SeaValue::BigInt(None)),
        "and the integer null its own: {:?}",
        statement.values.0
    );
}

#[test]
fn an_update_never_writes_the_primary_key() {
    // Changing a row's identity is a delete and an insert: rows
    // referencing it by foreign key would follow it or be orphaned
    // depending on the constraint, which an edit must not decide.
    let statement = update(
        &note(),
        &json!({ "id": ID }),
        &json!({ "id": "0f3f8a5e-9c4c-4a3e-8b2e-1d6f0c9a7b99", "body": "edited" }),
    )
    .expect("a legal row");
    let set = statement
        .sql
        .split_once("WHERE")
        .expect("there is a where")
        .0;
    assert!(!set.contains("\"id\""), "{}", statement.sql);
}

#[test]
fn an_update_to_an_illegal_row_is_refused_before_the_database_sees_it() {
    let error = update(&note(), &json!({ "id": ID }), &json!({ "body": "no id" }))
        .expect_err("no primary key in the row");
    assert!(matches!(error, UpdateError::Row(_)), "{error:?}");
}

#[test]
fn a_page_is_ordered_by_the_primary_key_so_two_requests_agree() {
    // A LIMIT with no ORDER BY is whatever the engine felt like, and two
    // requests for "the first ten" may then share rows or skip them.
    let statement = select_page(&note(), 10, None).expect("no cursor");
    assert!(statement.sql.contains("ORDER BY"), "{}", statement.sql);
    assert!(statement.sql.contains("LIMIT"), "{}", statement.sql);
}

#[test]
fn a_composite_cursor_is_lexicographic_and_uses_no_row_value_comparison() {
    // `(a, b) > (x, y)` is standard SQL that SQLite does not have, so a
    // cursor written that way would work on Postgres and not on D1 —
    // a difference between two deployments of one declaration.
    let statement = select_page(
        &membership(),
        10,
        Some(&json!({ "tenant": "acme", "member": "ada" })),
    )
    .expect("a whole cursor");
    assert!(statement.sql.contains(" OR "), "{}", statement.sql);
    assert_eq!(
        statement.values.0.len(),
        4,
        "tenant >, then tenant = and member >, and the bound LIMIT: {}",
        statement.sql
    );
}

#[test]
fn half_a_cursor_is_refused_like_half_a_key() {
    let error = select_page(&membership(), 10, Some(&json!({ "tenant": "acme" })))
        .expect_err("half a cursor");
    assert_eq!(error.column, "member", "{error}");
}
