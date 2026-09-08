//! Row validation beyond the corpus: how a rejection becomes a
//! problem+json response, and the shape of the structured list.
//!
//! The verdicts themselves live in `corpus/rows.json`, because a second
//! implementation has to be able to run them.

use cratefield_tables::{ErrorCode, MAX_DETAIL_ERRORS, Schema, validate_row};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Manifest {
    tables: Schema,
}

fn schema(fragment: &str) -> Schema {
    toml::from_str::<Manifest>(fragment)
        .expect("the fragment parses")
        .tables
}

const POST: &str = r#"
[tables.post]
primary_key = "id"

[[tables.post.fields]]
name = "id"
kind = "text"
required = true

[[tables.post.fields]]
name = "title"
kind = "text"
min_len = 1
max_len = 5
required = true

[[tables.post.fields]]
name = "status"
kind = "enum"
values = ["draft", "published"]
"#;

#[test]
fn a_rejection_becomes_the_validation_failed_problem_core_already_publishes() {
    let schema = schema(POST);
    let table = schema.table("post").unwrap();
    let errors =
        validate_row(table, &json!({"id": "x", "title": "far too long"})).expect_err("too long");

    let problem = errors.problem();
    assert_eq!(problem.slug, "validation-failed");
    assert_eq!(problem.status.as_u16(), 400);
    assert_eq!(
        problem.detail.as_deref(),
        Some("title is 12 characters, longer than the maximum of 5")
    );
    assert_eq!(
        problem.type_uri(),
        "https://factory0.ventures/problems/validation-failed"
    );

    // The `From` impl is the same problem, so `?` in a handler works.
    let converted: cratefield_core::Problem = errors.into();
    assert_eq!(converted.slug, "validation-failed");
}

#[test]
fn the_detail_joins_every_reason_in_order() {
    let schema = schema(POST);
    let table = schema.table("post").unwrap();
    let errors =
        validate_row(table, &json!({"status": "archived", "extra": 1})).expect_err("three reasons");
    assert_eq!(
        errors.detail(),
        "id is required; title is required; status is not one of draft, published; \
         extra is not a declared field of `post`"
    );
}

#[test]
fn a_row_that_is_not_an_object_is_reported_against_the_row_itself() {
    let schema = schema(POST);
    let table = schema.table("post").unwrap();
    let errors = validate_row(table, &json!([1, 2])).expect_err("not an object");
    assert_eq!(errors.errors().len(), 1);
    assert_eq!(errors.errors()[0].field, "");
    assert_eq!(errors.errors()[0].code, ErrorCode::NotAnObject);
    assert_eq!(
        errors.detail(),
        "the row must be a JSON object, not an array"
    );
}

#[test]
fn a_long_list_is_summarised_in_the_detail_but_never_truncated_in_the_list() {
    let schema = schema(POST);
    let table = schema.table("post").unwrap();
    let mut row = serde_json::Map::new();
    row.insert("id".to_owned(), json!("x"));
    row.insert("title".to_owned(), json!("ok"));
    for index in 0..20 {
        row.insert(format!("extra{index:02}"), json!(1));
    }
    let errors =
        validate_row(table, &serde_json::Value::Object(row)).expect_err("twenty unknown keys");

    assert_eq!(errors.errors().len(), 20, "the list keeps every reason");
    assert_eq!(
        errors.detail().matches("is not a declared field").count(),
        MAX_DETAIL_ERRORS
    );
    assert!(errors.detail().ends_with("(and 10 more)"), "{errors}");
}

#[test]
fn uniqueness_is_not_a_row_check() {
    // A unique field is not read against other rows here; that is the
    // database's job, and it is the line between a field and a function.
    let schema = schema(
        r#"
[tables.post]
[[tables.post.fields]]
name = "id"
kind = "text"
[[tables.post.fields]]
name = "slug"
kind = "text"
unique = true
"#,
    );
    let table = schema.table("post").unwrap();
    for _ in 0..2 {
        validate_row(table, &json!({"id": "x", "slug": "same"})).expect("no uniqueness check here");
    }
}
