//! `Schema::validate`: the declaration itself, before any row exists.

use cratefield_tables::{FieldDef, FieldKind, ForeignKey, Schema, TableDef, TextFormat};
use serde_json::json;

fn id() -> FieldDef {
    FieldDef::new("id", FieldKind::Uuid).required()
}

fn table(fields: Vec<FieldDef>) -> TableDef {
    TableDef::new("post", "id", fields)
}

fn problems(schema: &Schema) -> Vec<String> {
    match schema.validate() {
        Ok(()) => Vec::new(),
        Err(error) => error.problems,
    }
}

fn assert_rejects(schema: &Schema, fragment: &str) {
    let found = problems(schema);
    assert!(
        found.iter().any(|line| line.contains(fragment)),
        "no problem mentioned {fragment:?}; got {found:#?}"
    );
}

#[test]
fn a_plain_declaration_is_valid() {
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new(
            "title",
            FieldKind::Text {
                min_len: Some(1),
                max_len: Some(200),
                format: None,
            },
        )
        .required(),
        FieldDef::new("views", FieldKind::integer()).default_value(json!(0)),
        FieldDef::new("published", FieldKind::Boolean).default_value(json!(false)),
        FieldDef::new("body", FieldKind::Json),
        FieldDef::new("created_at", FieldKind::Timestamp)
            .required()
            .indexed(),
    ])]);
    assert_eq!(problems(&schema), Vec::<String>::new());
}

#[test]
fn a_duplicate_field_name_is_rejected() {
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new("title", FieldKind::text()),
        FieldDef::new("title", FieldKind::text()),
    ])]);
    assert_rejects(&schema, "field `title` is declared twice");
}

#[test]
fn a_duplicate_table_name_is_rejected() {
    let schema = Schema {
        tables: vec![table(vec![id()]), table(vec![id()])],
    };
    assert_rejects(&schema, "declared twice");
}

#[test]
fn a_non_identifier_name_is_rejected() {
    for bad in [
        "Title",
        "1st",
        "with space",
        "trailing_",
        "double__underscore",
        "",
    ] {
        let schema = Schema::new(vec![table(vec![
            id(),
            FieldDef::new(bad, FieldKind::text()),
        ])]);
        assert_rejects(&schema, "must match [a-z][a-z0-9_]*");
    }
}

#[test]
fn a_reserved_word_is_rejected() {
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new("order", FieldKind::text()),
    ])]);
    assert_rejects(&schema, "`order` is a reserved SQL word");
}

#[test]
fn a_reserved_prefix_is_rejected() {
    let schema = Schema::new(vec![TableDef::new("harness_migrations", "id", vec![id()])]);
    assert_rejects(&schema, "the `harness_` prefix is reserved");
}

#[test]
fn a_card_data_name_is_rejected() {
    // The harness never stores card data; a declared table is exactly
    // where it would otherwise turn up.
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new("card_number", FieldKind::text()),
    ])]);
    assert_rejects(&schema, "looks like card data");
}

#[test]
fn an_over_long_name_is_rejected() {
    let long = "a".repeat(64);
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new(&long, FieldKind::text()),
    ])]);
    assert_rejects(&schema, "at most 63 characters");
}

#[test]
fn a_foreign_key_to_an_undeclared_table_is_rejected() {
    let schema = Schema::new(vec![
        table(vec![id(), FieldDef::new("author_id", FieldKind::Uuid)])
            .foreign_key(ForeignKey::new("author_id", "author")),
    ]);
    assert_rejects(&schema, "references table `author`, which is not declared");
}

#[test]
fn a_foreign_key_to_a_declared_table_is_valid() {
    let schema = Schema::new(vec![
        table(vec![id(), FieldDef::new("author_id", FieldKind::Uuid)])
            .foreign_key(ForeignKey::new("author_id", "author")),
        TableDef::new("author", "id", vec![id()]),
    ]);
    assert_eq!(problems(&schema), Vec::<String>::new());
}

#[test]
fn a_foreign_key_on_an_undeclared_field_is_rejected() {
    let schema = Schema::new(vec![
        table(vec![id()]).foreign_key(ForeignKey::new("author_id", "author")),
        TableDef::new("author", "id", vec![id()]),
    ]);
    assert_rejects(&schema, "which is not a declared field");
}

#[test]
fn a_foreign_key_of_the_wrong_kind_is_rejected() {
    let schema = Schema::new(vec![
        table(vec![id(), FieldDef::new("author_id", FieldKind::integer())])
            .foreign_key(ForeignKey::new("author_id", "author")),
        TableDef::new("author", "id", vec![id()]),
    ]);
    assert_rejects(&schema, "is integer but `author.id` is uuid");
}

#[test]
fn an_enum_with_no_members_is_rejected() {
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new("status", FieldKind::Enum { values: Vec::new() }),
    ])]);
    assert_rejects(&schema, "an enum must declare at least one value");
}

#[test]
fn a_duplicate_enum_member_is_rejected() {
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new(
            "status",
            FieldKind::Enum {
                values: vec!["draft".to_owned(), "draft".to_owned()],
            },
        ),
    ])]);
    assert_rejects(&schema, "enum value `draft` is declared twice");
}

#[test]
fn a_primary_key_naming_an_undeclared_field_is_rejected() {
    let mut table = table(vec![id()]);
    table.primary_key = vec!["missing".to_owned()];
    assert_rejects(&Schema::new(vec![table]), "primary key names `missing`");
}

#[test]
fn a_table_with_no_primary_key_is_rejected() {
    let mut table = table(vec![id()]);
    table.primary_key.clear();
    assert_rejects(&Schema::new(vec![table]), "no primary key");
}

#[test]
fn a_table_with_no_fields_is_rejected() {
    let schema = Schema::new(vec![TableDef::new("post", "id", Vec::new())]);
    assert_rejects(&schema, "declares no fields");
}

#[test]
fn inverted_bounds_are_rejected() {
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new(
            "title",
            FieldKind::Text {
                min_len: Some(10),
                max_len: Some(2),
                format: None,
            },
        ),
        FieldDef::new(
            "views",
            FieldKind::Integer {
                min: Some(10),
                max: Some(2),
            },
        ),
        FieldDef::new(
            "score",
            FieldKind::Real {
                min: Some(1.0),
                max: Some(0.5),
            },
        ),
    ])]);
    let found = problems(&schema);
    assert_eq!(
        found
            .iter()
            .filter(|line| line.contains("greater than"))
            .count(),
        3,
        "{found:#?}"
    );
}

#[test]
fn a_default_of_the_wrong_kind_is_rejected() {
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new("views", FieldKind::integer()).default_value(json!("0")),
    ])]);
    assert_rejects(&schema, "the default \"0\" must be a number");
}

#[test]
fn a_default_outside_an_enum_is_rejected() {
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new(
            "status",
            FieldKind::Enum {
                values: vec!["draft".to_owned(), "published".to_owned()],
            },
        )
        .default_value(json!("archived")),
    ])]);
    assert_rejects(&schema, "is not one of draft, published");
}

#[test]
fn every_violation_is_reported_together() {
    let schema = Schema::new(vec![table(vec![
        FieldDef::new("Id", FieldKind::Uuid),
        FieldDef::new("order", FieldKind::text()),
        FieldDef::new("status", FieldKind::Enum { values: Vec::new() }),
    ])]);
    // A non-identifier `Id`, a reserved `order`, an empty enum, and a
    // primary key naming a field that is therefore not declared.
    assert!(problems(&schema).len() >= 4, "{:#?}", problems(&schema));
}

#[test]
fn an_email_format_reuses_the_core_address_rule() {
    let schema = Schema::new(vec![table(vec![
        id(),
        FieldDef::new(
            "email",
            FieldKind::Text {
                min_len: None,
                max_len: None,
                format: Some(TextFormat::Email),
            },
        )
        .default_value(json!("not-an-address")),
    ])]);
    assert_rejects(&schema, "email must contain exactly one @");
}
