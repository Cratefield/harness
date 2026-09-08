//! `Schema::validate`: the declaration itself, before any row exists.

use cratefield_tables::{
    FieldDef, FieldKind, ForeignKey, RESERVED_WORDS, Schema, TableDef, TextFormat,
};
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
fn the_reserved_word_list_stays_sorted_and_has_no_duplicate() {
    let mut sorted: Vec<&str> = RESERVED_WORDS.to_vec();
    sorted.sort_unstable();
    assert_eq!(RESERVED_WORDS, sorted.as_slice(), "the list is not sorted");
    sorted.dedup();
    assert_eq!(RESERVED_WORDS.len(), sorted.len(), "a word is listed twice");
}

#[test]
fn every_reserved_word_is_rejected_in_every_position() {
    // A word that reaches the DDL unquoted breaks the script, and the
    // three positions a declared name reaches it from are a table name, a
    // field name, and the name of an enum field, which the CHECK
    // constraint repeats.
    for word in RESERVED_WORDS {
        let as_table = Schema::new(vec![TableDef::new(*word, "id", vec![id()])]);
        assert_rejects(&as_table, &format!("`{word}` is a reserved SQL word"));

        let as_field = Schema::new(vec![table(vec![
            id(),
            FieldDef::new(*word, FieldKind::text()),
        ])]);
        assert_rejects(&as_field, &format!("`{word}` is a reserved SQL word"));

        let as_enum_field = Schema::new(vec![table(vec![
            id(),
            FieldDef::new(
                *word,
                FieldKind::Enum {
                    values: vec!["on".to_owned(), "off".to_owned()],
                },
            ),
        ])]);
        assert_rejects(&as_enum_field, &format!("`{word}` is a reserved SQL word"));
    }
}

#[test]
fn the_words_postgres_reserves_and_the_old_list_missed_are_rejected() {
    // The 44 the review reproduced against PostgreSQL 15.13 and SQLite
    // 3.51, spelled out so a shrunken list fails here rather than in a
    // venture's first deploy.
    for word in [
        "any",
        "array",
        "asymmetric",
        "both",
        "current_catalog",
        "current_date",
        "current_role",
        "current_time",
        "current_timestamp",
        "current_user",
        "deferrable",
        "do",
        "fetch",
        "for",
        "grant",
        "initially",
        "lateral",
        "leading",
        "localtime",
        "localtimestamp",
        "only",
        "placing",
        "session_user",
        "some",
        "symmetric",
        "trailing",
        "variadic",
        "window",
        "analyse",
        "analyze",
        "authorization",
        "binary",
        "collation",
        "concurrently",
        "freeze",
        "ilike",
        "isnull",
        "notnull",
        "overlaps",
        "similar",
        "tablesample",
        "verbose",
        "xmin",
        "ctid",
        "autoincrement",
    ] {
        assert!(
            RESERVED_WORDS.contains(&word),
            "`{word}` is not on the reserved list"
        );
    }
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
fn a_reference_cycle_is_rejected() {
    // Neither table can be created first, so no script exists. Postgres
    // refuses the inline REFERENCES either way round.
    let schema = Schema::new(vec![
        TableDef::new(
            "author",
            "id",
            vec![id(), FieldDef::new("post_id", FieldKind::Uuid)],
        )
        .foreign_key(ForeignKey::new("post_id", "post")),
        table(vec![id(), FieldDef::new("author_id", FieldKind::Uuid)])
            .foreign_key(ForeignKey::new("author_id", "author")),
    ]);
    assert_rejects(&schema, "reference cycle");
    assert_rejects(&schema, "author -> post -> author");
}

#[test]
fn a_self_reference_is_not_a_cycle() {
    // A table pointing at its own primary key is one CREATE TABLE that
    // both engines accept, so it is neither a dependency nor a cycle.
    let schema = Schema::new(vec![
        table(vec![id(), FieldDef::new("parent_id", FieldKind::Uuid)])
            .foreign_key(ForeignKey::new("parent_id", "post")),
    ]);
    assert_eq!(problems(&schema), Vec::<String>::new());
}

#[test]
fn two_tables_that_generate_the_same_index_name_are_rejected() {
    // `{table}_{field}_idx` is ambiguous because an underscore is legal
    // in both halves. Without this check the second CREATE INDEX IF NOT
    // EXISTS exits 0 and the index is simply absent.
    let schema = Schema::new(vec![
        table(vec![
            id(),
            FieldDef::new("author_id", FieldKind::Uuid).indexed(),
        ]),
        // `post_author` keys on `pair_id`, so its `id` is an ordinary
        // indexed column and does get a CREATE INDEX of its own.
        TableDef::new(
            "post_author",
            "pair_id",
            vec![
                FieldDef::new("pair_id", FieldKind::Uuid).required(),
                FieldDef::new("id", FieldKind::Uuid).indexed(),
            ],
        ),
    ]);
    assert_rejects(
        &schema,
        "the generated index name `post_author_id_idx` is already generated by table `post`, \
         field `author_id`",
    );
}

#[test]
fn a_generated_index_name_that_is_a_declared_table_name_is_rejected() {
    // Indexes and tables share one namespace in both engines: Postgres
    // exits 0 with the table silently absent, SQLite aborts.
    let schema = Schema::new(vec![
        table(vec![
            id(),
            FieldDef::new("slug", FieldKind::text()).indexed(),
        ]),
        TableDef::new("post_slug_idx", "id", vec![id()]),
    ]);
    assert_rejects(
        &schema,
        "the generated index name `post_slug_idx` is also a declared table name",
    );
}

#[test]
fn a_primary_key_that_is_neither_required_nor_defaulted_is_rejected() {
    // The rendered column is NOT NULL either way, so a primary key the
    // row validator treats as optional is a row the insert rejects.
    let schema = Schema::new(vec![table(vec![FieldDef::new("id", FieldKind::Uuid)])]);
    assert_rejects(
        &schema,
        "primary key `id` must be required or have a default",
    );
}

#[test]
fn a_primary_key_is_accepted_when_it_is_required_or_defaulted() {
    let required = Schema::new(vec![table(vec![
        FieldDef::new("id", FieldKind::Uuid).required(),
    ])]);
    assert_eq!(problems(&required), Vec::<String>::new());

    // A default is the other way the column is never null: the database
    // supplies the value, so the write need not carry it.
    let defaulted = Schema::new(vec![table(vec![
        FieldDef::new("id", FieldKind::text()).default_value(json!("only")),
    ])]);
    assert_eq!(problems(&defaulted), Vec::<String>::new());
}

#[test]
fn every_column_of_a_composite_primary_key_has_to_hold_a_value() {
    let mut composite = table(vec![
        FieldDef::new("post_id", FieldKind::Uuid).required(),
        FieldDef::new("label", FieldKind::text()),
    ]);
    composite.primary_key = vec!["post_id".to_owned(), "label".to_owned()];
    assert_rejects(
        &Schema::new(vec![composite]),
        "primary key `label` must be required or have a default",
    );
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
