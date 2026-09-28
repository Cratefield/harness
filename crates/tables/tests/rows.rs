//! Row validation beyond the corpus: how a rejection becomes a
//! problem+json response, and the shape of the structured list.
//!
//! The verdicts themselves live in `corpus/rows.json`, because a second
//! implementation has to be able to run them.

use cratefield_tables::{
    ErrorCode, MAX_DETAIL_ERRORS, MAX_UNKNOWN_KEY_CHARS, Schema, normalize_row, validate_row,
};
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

/// A table with the kinds the new tests need: an integer to push past
/// `i64`, a declared email to normalise, and a plain text field beside it
/// that must be left alone.
const TYPED: &str = r#"
[tables.thing]
primary_key = "id"

[[tables.thing.fields]]
name = "id"
kind = "text"
required = true

[[tables.thing.fields]]
name = "count"
kind = "integer"

[[tables.thing.fields]]
name = "email"
kind = "text"
format = "email"

[[tables.thing.fields]]
name = "site"
kind = "text"
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
        problem.type_uri("https://test.example/problems/"),
        "https://test.example/problems/validation-failed"
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
required = true
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

#[test]
fn an_integer_outside_i64_is_refused_rather_than_truncated() {
    // `i64::MAX as f64` rounds up to 2^63, so the old range check admitted
    // 2^63 and the saturating cast wrote i64::MAX: a row that said
    // 9223372036854775809 was accepted and stored as 9223372036854775807.
    // A number one off is worse than a rejection, because nothing says so.
    let schema = schema(TYPED);
    let table = schema.table("thing").expect("declared");
    for raw in [
        "9223372036854775808",
        "9223372036854775809",
        "-9223372036854775809",
        "-9223372036854775808.0",
        "1e19",
        "-1e19",
    ] {
        let row: serde_json::Value =
            serde_json::from_str(&format!(r#"{{"id":"a","count":{raw}}}"#)).expect("json");
        let errors = validate_row(table, &row)
            .expect_err(&format!("{raw} is not representable and must be refused"));
        assert_eq!(errors.errors()[0].code, ErrorCode::WrongType, "{raw}");
    }
    // The ends of the range still pass, and so does a float spelling
    // inside it: this is a range check, not a ban on writing 42.0.
    for raw in [
        "9223372036854775807",
        "-9223372036854775808",
        "42.0",
        "1e18",
        "0",
    ] {
        let row: serde_json::Value =
            serde_json::from_str(&format!(r#"{{"id":"a","count":{raw}}}"#)).expect("json");
        assert!(validate_row(table, &row).is_ok(), "{raw} must be accepted");
    }
}

#[test]
fn an_unknown_key_is_echoed_back_bounded() {
    // The key is whatever the caller sent. Unbounded, a megabyte key name
    // came back in the 400 body, and MAX_DETAIL_ERRORS of them per
    // request.
    let schema = schema(POST);
    let table = schema.table("post").expect("declared");
    let long = "x".repeat(5000);
    let row = json!({ "id": "a", "title": "t", &long: 1 });
    let errors = validate_row(table, &row).expect_err("an unknown key is an error");
    let echoed = &errors.errors()[0].field;
    assert_eq!(errors.errors()[0].code, ErrorCode::UnknownField);
    assert_eq!(
        echoed.chars().count(),
        MAX_UNKNOWN_KEY_CHARS + 1,
        "the cut key plus its marker"
    );
    assert!(echoed.starts_with("xxxx") && echoed.ends_with('…'));
    assert!(
        errors.detail().len() < 500,
        "the problem detail is still {} bytes",
        errors.detail().len()
    );

    // Cut on a character boundary, never a byte one: a multi-byte key
    // must not come back as invalid UTF-8 or a split code point.
    let wide = "\u{1f680}".repeat(200);
    let row = json!({ "id": "a", "title": "t", &wide: 1 });
    let errors = validate_row(table, &row).expect_err("an unknown key is an error");
    let echoed = &errors.errors()[0].field;
    assert_eq!(echoed.chars().count(), MAX_UNKNOWN_KEY_CHARS + 1);
    assert!(
        echoed
            .chars()
            .take(MAX_UNKNOWN_KEY_CHARS)
            .all(|c| c == '\u{1f680}'),
        "a code point was split: {echoed:?}"
    );

    // A key that just fits is echoed whole, with no marker.
    let exact = "y".repeat(MAX_UNKNOWN_KEY_CHARS);
    let row = json!({ "id": "a", "title": "t", &exact: 1 });
    let errors = validate_row(table, &row).expect_err("an unknown key is an error");
    assert_eq!(errors.errors()[0].field, exact);
}

#[test]
fn normalize_row_makes_unique_mean_what_it_means_everywhere_else() {
    // `unique` is enforced by the database on the bytes it is handed, so
    // without this Alice@Example.COM and alice@example.com are two rows
    // while every module in the harness treats them as one address.
    let schema = schema(TYPED);
    let table = schema.table("thing").expect("declared");

    let written = normalize_row(
        table,
        json!({ "id": "a", "email": "  Alice@Example.COM  " }),
    );
    assert_eq!(written["email"], json!("alice@example.com"));

    // Idempotent, like core's own normaliser: running it twice on a row
    // that has already been through it changes nothing.
    assert_eq!(normalize_row(table, written.clone()), written);

    // Only declared email fields are touched. A text field that happens
    // to hold an address keeps its bytes, because `unique` on it means
    // what the caller wrote.
    let untouched = normalize_row(table, json!({ "id": "  A  ", "site": "HTTPS://X.COM" }));
    assert_eq!(untouched["id"], json!("  A  "));
    assert_eq!(untouched["site"], json!("HTTPS://X.COM"));

    // A non-string is left for the validator to reject rather than
    // rewritten into something that would pass.
    let wrong = normalize_row(table, json!({ "id": "a", "email": 42 }));
    assert_eq!(wrong["email"], json!(42));
    assert!(validate_row(table, &wrong).is_err());

    // And normalising does not launder an invalid address into a valid
    // one: the validator still has the last word.
    let bad = normalize_row(table, json!({ "id": "a", "email": "NOT AN ADDRESS" }));
    assert!(validate_row(table, &bad).is_err());
}
