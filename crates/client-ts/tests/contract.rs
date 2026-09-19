//! The input side: what the generator reads a `/__surface` document as,
//! and what reading it produces.
//!
//! The action names, methods, paths, audiences and row schemas here are
//! spelled exactly the way `cratefield_tables_api::surface` and
//! `cratefield_tables::json_schema` publish them, so a test failure
//! means the reader drifted from the contract, not from a shorthand.

use cratefield_client_ts::GenerateError;
use cratefield_client_ts::contract::{self, ColumnKind};
use cratefield_core::{Audience, SURFACE_API, SurfaceDocument};
use serde_json::{Value, json};

/// The document a harness serves at `/__surface`, with the `tables`
/// module's actions given. One action object per entry, spelled as the
/// wire spells it: `method` upper-case, `audience` kebab-case,
/// `outcome` tagged with `kind`, `captcha` always present, `input` only
/// when the action carries one.
fn document(actions: &Value) -> SurfaceDocument {
    let document = json!({
        "surface_api": SURFACE_API,
        "harness_api": 1,
        "venture": {
            "name": "waitlist",
            "public_url": "https://waitlist.example.com",
        },
        "modules": [
            {
                "name": "tables",
                "version": "0.1.0",
                "actions": actions.clone(),
                "views": [],
            }
        ],
    });
    serde_json::from_value(document)
        .expect("a document in the published shape must deserialize as a SurfaceDocument")
}

/// One action, as the Tables module publishes it.
fn action(name: &str, method: &str, path: &str, audience: &str, input: Option<Value>) -> Value {
    let mut action = json!({
        "name": name,
        "method": method,
        "path": path,
        "audience": audience,
        "outcome": { "kind": "json" },
        "captcha": false,
    });
    if let Some(input) = input {
        action["input"] = input;
    }
    action
}

/// The row schema exactly as `cratefield_tables::json_schema` renders
/// it: draft 2020-12, everything inlined, `additionalProperties: false`.
fn row_schema(title: &str, properties: &Value, required: &Value) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        "type": "object",
        "properties": properties.clone(),
        "required": required.clone(),
        "additionalProperties": false,
    })
}

fn extract(document: &SurfaceDocument) -> contract::Contract {
    contract::extract(document).expect("the tables module must extract without an error")
}

/// The document deserializes straight into the core type. This is the
/// load-bearing fact of the input side: `Action::policy` is
/// `#[serde(skip)]`, which serde can only deserialize when the field's
/// type implements `Default` — and `cratefield_core::RoutePolicy`
/// derives it (`crates/core/src/route_policy.rs`).
#[test]
#[allow(clippy::too_many_lines)]
fn a_surface_document_deserializes_as_the_core_type() {
    let document = json!({
        "surface_api": SURFACE_API,
        "harness_api": 1,
        "venture": {
            "name": "waitlist",
            "public_url": "https://waitlist.example.com",
        },
        "modules": [
            {
                "name": "tables",
                "version": "0.1.0",
                "actions": [
                    {
                        "name": "list-note",
                        "method": "GET",
                        "path": "/note",
                        "audience": "public",
                        "outcome": { "kind": "json" },
                        "captcha": false,
                    },
                    {
                        "name": "create-note",
                        "method": "POST",
                        "path": "/note",
                        "audience": "public",
                        "input": {
                            "$schema": "https://json-schema.org/draft/2020-12/schema",
                            "title": "note",
                            "type": "object",
                            "properties": {
                                "body": { "type": "string", "minLength": 1 }
                            },
                            "required": ["body"],
                            "additionalProperties": false,
                        },
                        "outcome": { "kind": "json" },
                        "captcha": false,
                    }
                ],
                "views": [],
            }
        ],
    });
    let parsed: SurfaceDocument = serde_json::from_value(document).expect(
        "the /__surface JSON a harness serves must deserialize as \
         cratefield_core::SurfaceDocument: RoutePolicy derives Default, so the \
         skipped `policy` field deserializes",
    );

    assert_eq!(parsed.surface_api, SURFACE_API, "the contract version");
    assert_eq!(parsed.harness_api, 1, "the harness version");
    assert_eq!(
        parsed.venture.name, "waitlist",
        "the venture the client speaks for"
    );
    assert_eq!(
        parsed.venture.public_url, "https://waitlist.example.com",
        "where the generated client points"
    );
    assert_eq!(parsed.modules.len(), 1, "one module composed in");
    let module = &parsed.modules[0];
    assert_eq!(module.name, "tables", "the Tables module's mount name");
    assert_eq!(module.version, "0.1.0", "the module's declared version");
    assert_eq!(
        module.surface.actions.len(),
        2,
        "the surface flattens onto the module, so the actions sit directly on it"
    );
    assert_eq!(
        module.surface.actions[0].name, "list-note",
        "the action names travel"
    );
    assert_eq!(
        module.surface.actions[0].method.as_str(),
        "GET",
        "the method serializes as its upper-case name"
    );
    assert_eq!(
        module.surface.actions[0].audience,
        Audience::Public,
        "the audience reads back as the kebab-case variant it serialized from"
    );
    assert!(
        module.surface.actions[1].input.is_some(),
        "the write carries the row schema as its input"
    );
    assert!(
        module.surface.actions[0].input.is_none(),
        "a read carries no input"
    );

    // Round-trip: back out to the wire and in again. `policy` is skipped
    // in both directions, so the document survives the trip unchanged.
    let wire =
        serde_json::to_value(&parsed).expect("a composed document serializes back to the wire");
    let again: SurfaceDocument =
        serde_json::from_value(wire.clone()).expect("and what it serves parses again");
    assert_eq!(
        serde_json::to_value(&again).expect("re-serialize"),
        wire,
        "the document round-trips through the wire unchanged"
    );
}

/// A single-primary-key table with every column kind the Tables module
/// can declare normalizes to the model the generator reads.
#[test]
#[allow(clippy::too_many_lines)]
fn a_single_key_table_normalizes_every_column_kind() {
    let schema = row_schema(
        "invoice",
        &json!({
            "id": {
                "type": "string",
                "minLength": 26,
                "maxLength": 26,
                "description": "Primary key of `invoice`.",
            },
            "email": {
                "type": "string",
                "minLength": 3,
                "maxLength": 254,
                "format": "email",
                "not": { "pattern": "\u{0}" },
            },
            "note": { "type": ["string", "null"] },
            "quantity": { "type": "integer", "minimum": 1 },
            "amount": { "type": "number" },
            "paid": { "type": "boolean" },
            "created": { "type": "string", "format": "date-time" },
            "receipt": { "type": ["string", "null"], "format": "uuid" },
            "metadata": { "title": "metadata" },
        }),
        &json!(["id", "email", "quantity", "amount", "paid", "created"]),
    );
    let contract = extract(&document(&json!([
        action("list-invoice", "GET", "/invoice", "subject", None),
        action("read-invoice", "GET", "/invoice/{key}", "subject", None),
        action(
            "create-invoice",
            "POST",
            "/invoice",
            "subject",
            Some(schema.clone()),
        ),
        action(
            "replace-invoice",
            "PUT",
            "/invoice/{key}",
            "subject",
            Some(schema),
        ),
        action(
            "delete-invoice",
            "DELETE",
            "/invoice/{key}",
            "subject",
            None
        ),
    ])));

    assert_eq!(contract.venture, "waitlist", "the venture travels");
    assert_eq!(contract.mount, "/v1/tables", "the module's mount");
    assert_eq!(contract.tables.len(), 1, "one table, five actions");
    let table = &contract.tables[0];
    assert_eq!(table.name, "invoice", "the name comes from the paths");
    assert_eq!(
        table.audience,
        Audience::Subject,
        "the audience comes from the actions"
    );
    assert_eq!(table.list_path, Some("/invoice".to_owned()), "the page");
    assert_eq!(
        table.key_path,
        Some("/invoice/{key}".to_owned()),
        "the single-row route the key substitutes into"
    );
    assert!(
        table.has_read && table.has_create && table.has_replace && table.has_delete,
        "all four beyond the page are published"
    );
    assert!(
        table.row_shape_known,
        "the write carries a schema, so the row shape is known"
    );
    assert_eq!(
        table.columns.len(),
        9,
        "one column per property, in the schema's order"
    );

    let column = |name: &str| {
        table
            .columns
            .iter()
            .find(|column| column.name == name)
            .unwrap_or_else(|| panic!("the schema declares `{name}`"))
    };
    let id = column("id");
    assert_eq!(id.kind, ColumnKind::Text, "a key column is a string");
    assert!(id.is_primary_key, "the description marks the key");
    assert!(id.required, "the key is required");
    assert!(id.sortable, "the key is sortable whether or not required");
    assert!(id.filterable, "a string key takes an equality filter");

    assert_eq!(column("email").kind, ColumnKind::Text, "text with bounds");
    assert!(
        column("email").filterable && column("email").sortable,
        "required text filters and sorts"
    );

    let note = column("note");
    assert_eq!(note.kind, ColumnKind::Text, "nullable text is still text");
    assert!(note.nullable, "the type array carries null");
    assert!(!note.required, "absent from `required`");
    assert!(
        !note.sortable,
        "an optional column is no sort key: nulls have no order"
    );
    assert!(note.filterable, "it still takes an equality filter");

    assert_eq!(
        column("quantity").kind,
        ColumnKind::Integer,
        "integer stays integer"
    );
    assert_eq!(
        column("amount").kind,
        ColumnKind::Real,
        "a real is a number"
    );
    assert_eq!(column("paid").kind, ColumnKind::Boolean, "boolean");
    assert_eq!(
        column("created").kind,
        ColumnKind::Text,
        "a timestamp is a string on the wire (format: date-time)"
    );
    let receipt = column("receipt");
    assert_eq!(
        receipt.kind,
        ColumnKind::Text,
        "a uuid is a string on the wire (format: uuid)"
    );
    assert!(receipt.nullable, "the type array carries null");
    let metadata = column("metadata");
    assert_eq!(
        metadata.kind,
        ColumnKind::Opaque,
        "a json column names no type at all"
    );
    assert!(
        !metadata.filterable,
        "the wire cannot compare a json value, so it takes no filter"
    );
}

/// A composite-key table publishes only the page and the write: the key
/// is two columns and cannot travel one path segment, so no single-row
/// route exists and the model carries no key.
#[test]
fn a_composite_key_table_has_no_single_row_routes() {
    let schema = row_schema(
        "membership",
        &json!({
            "user_id": {
                "type": "string",
                "description": "Primary key of `membership`.",
            },
            "org_id": {
                "type": "string",
                "description": "Primary key of `membership`.",
            },
            "role": { "type": "string" },
        }),
        &json!(["user_id", "org_id", "role"]),
    );
    let contract = extract(&document(&json!([
        action("list-membership", "GET", "/membership", "admin", None),
        action(
            "create-membership",
            "POST",
            "/membership",
            "admin",
            Some(schema),
        ),
    ])));

    let table = &contract.tables[0];
    assert_eq!(table.name, "membership", "the table is there");
    assert!(
        table.row_shape_known,
        "the write carries a schema, so the row shape is known"
    );
    assert_eq!(
        table.primary_key, None,
        "two marked columns are a composite key: no single column names a row"
    );
    assert!(
        table.key_path.is_none() && !table.has_read,
        "no `read` is published: a two-column key cannot travel the path"
    );
    assert!(
        !table.has_replace && !table.has_delete,
        "nor replace, nor delete"
    );
    assert!(table.has_create, "the write is still published");
    assert!(
        table.list_path.is_some(),
        "the page is still published: listing needs no key"
    );
    assert!(
        table.columns.iter().filter(|c| c.is_primary_key).count() == 2,
        "both marked columns stay marked, for the doc comments"
    );
}

/// The `public-read` gap: a read-only table publishes `list` and `read`
/// and no write, and the write is where a row schema travels — so the
/// contract says nothing about the row's shape. That must extract as a
/// usable table with an unknown shape, not as an error.
#[test]
fn a_read_only_table_has_an_unknown_row_shape_and_no_writes() {
    let contract = extract(&document(&json!([
        action("list-note", "GET", "/note", "public", None),
        action("read-note", "GET", "/note/{key}", "public", None),
    ])));

    let table = &contract.tables[0];
    assert_eq!(table.name, "note", "the table is there");
    assert_eq!(table.audience, Audience::Public, "anyone may read");
    assert!(
        table.has_read && table.list_path.is_some() && table.key_path.is_some(),
        "both reads are published"
    );
    assert!(
        !table.has_create && !table.has_replace && !table.has_delete,
        "no write is published, so no schema travelled"
    );
    assert!(table.schema.is_none(), "no action carried an input schema");
    assert!(
        !table.row_shape_known,
        "nothing in the contract describes the row: the gap, flagged"
    );
    assert!(
        table.columns.is_empty(),
        "no columns can be read from a schema that does not exist"
    );
    assert!(
        table.primary_key.is_none(),
        "and no key column either — the reader marks the shape unknown rather than guessing"
    );
}

/// An enum column carries its literal values — the closed list the
/// contract publishes, with the `null` member read as nullability
/// rather than as a literal.
#[test]
fn an_enum_column_carries_its_literals() {
    let schema = row_schema(
        "task",
        &json!({
            "id": {
                "type": "string",
                "description": "Primary key of `task`.",
            },
            "status": {
                "type": "string",
                "enum": ["todo", "doing", "done"],
            },
            "priority": {
                "type": "string",
                "enum": ["low", "high", null],
            },
        }),
        &json!(["id", "status"]),
    );
    let contract = extract(&document(&json!([
        action("list-task", "GET", "/task", "public", None),
        action("read-task", "GET", "/task/{key}", "public", None),
        action("create-task", "POST", "/task", "public", Some(schema)),
    ])));

    let table = &contract.tables[0];
    let status = &table.columns[1];
    assert_eq!(status.name, "status", "the schema's order");
    assert_eq!(
        status.kind,
        ColumnKind::Enum(vec![
            "todo".to_owned(),
            "doing".to_owned(),
            "done".to_owned()
        ]),
        "the literals travel, in the order the contract declares them"
    );
    assert!(!status.nullable, "the list carries no null member");
    assert!(status.required, "and the column is required");
    assert!(status.filterable, "an enum takes an equality filter");
    assert!(status.sortable, "it is required");

    let priority = &table.columns[2];
    assert_eq!(
        priority.kind,
        ColumnKind::Enum(vec!["low".to_owned(), "high".to_owned()]),
        "null is not a literal: it is the nullability"
    );
    assert!(priority.nullable, "the list carries null");
    assert!(!priority.required, "an optional column");
    assert!(!priority.sortable, "so it is no sort key");
}

/// A `json` column — the schema names no `type` at all — is opaque: the
/// wire cannot compare it, so it takes no filter, and it is no sort key
/// unless the schema requires it.
#[test]
fn a_json_column_is_opaque_and_takes_no_filter() {
    let schema = row_schema(
        "doc",
        &json!({
            "id": {
                "type": "string",
                "description": "Primary key of `doc`.",
            },
            "title": { "type": "string" },
            "content": { "title": "content" },
        }),
        &json!(["id", "title"]),
    );
    let contract = extract(&document(&json!([
        action("list-doc", "GET", "/doc", "public", None),
        action("create-doc", "POST", "/doc", "public", Some(schema)),
    ])));

    let table = &contract.tables[0];
    let content = &table.columns[2];
    assert_eq!(
        content.kind,
        ColumnKind::Opaque,
        "no `type` key: the schema's word for any JSON value"
    );
    assert!(!content.filterable, "no filter on the incomparable");
    assert!(!content.sortable, "not required, not the key: no sort");
    assert!(!content.nullable, "it carries no nullability either");

    let title = &table.columns[1];
    assert!(
        title.filterable && title.sortable,
        "a required text column filters and sorts, as the contrast"
    );
}

/// A document that speaks a different contract version is refused, with
/// a message that says what to do about it.
#[test]
fn a_foreign_contract_version_is_refused() {
    let document = json!({
        "surface_api": SURFACE_API + 7,
        "harness_api": 1,
        "venture": {
            "name": "waitlist",
            "public_url": "https://waitlist.example.com",
        },
        "modules": [],
    });
    let parsed: SurfaceDocument = serde_json::from_value(document)
        .expect("a future version still deserializes: the wire shape is stable");
    let error =
        contract::extract(&parsed).expect_err("a newer contract is not this generator's to read");
    let message = error.to_string();

    let GenerateError::UnsupportedSurfaceApi { found, expected } = error else {
        panic!("a wrong surface_api is UnsupportedSurfaceApi, got {message}");
    };
    assert_eq!(found, SURFACE_API + 7, "what the document declared");
    assert_eq!(expected, SURFACE_API, "what this generator reads");
    assert!(
        message.contains(&format!("contract {found}")),
        "the message names the version it found: {message}"
    );
}

/// A table whose name is not a safe identifier is refused, not renamed:
/// the `/__surface` document is untrusted input (the documented usage is
/// `curl -s https://venture/__surface | fz client-ts`), and the name is
/// interpolated into the generated TypeScript — a `*/` would break out of
/// a doc comment, a space or a leading digit would not compile, and a
/// silently renamed table would call the wrong route.
#[test]
fn an_unsafe_table_name_is_refused() {
    for table in ["ta*/le", "my table", "123", "a..b"] {
        let actions = json!([
            action(
                &format!("list-{table}"),
                "GET",
                &format!("/{table}"),
                "public",
                None,
            ),
            action(
                &format!("create-{table}"),
                "POST",
                &format!("/{table}"),
                "public",
                None,
            ),
        ]);
        let error = contract::extract(&document(&actions))
            .expect_err("a name the generated TypeScript cannot carry must be refused");
        let message = error.to_string();

        let GenerateError::UnsupportedTableName { table: named } = error else {
            panic!("an unsafe table name is UnsupportedTableName, got {message}");
        };
        assert_eq!(named, table, "the error names the offending table");
        assert!(
            message.contains(table) && message.contains("[a-z][a-z0-9_]*"),
            "the message names the table and what is allowed: {message}"
        );
    }

    // The normal name the refusal exists to protect.
    let actions = json!([action("list-note", "GET", "/note", "public", None)]);
    assert!(
        contract::extract(&document(&actions)).is_ok(),
        "a legal table name still extracts"
    );
}

/// The table-name rule this generator applies is the rule the Tables
/// module holds a declaration to — `cratefield_tables::is_identifier`
/// (`crates/tables/src/schema.rs:894`) — so a name a venture declares
/// always extracts, and anything else in a `/__surface` document is
/// refused. Duplicated rather than depended on (the tables crate pulls
/// `sea-query`); this test is what keeps the copy honest.
#[test]
fn the_table_name_rule_agrees_with_the_tables_module() {
    for name in [
        "note",
        "waitlist_send",
        "a",
        "a1_b2",
        "",
        "Note",
        "MY_TABLE",
        "my table",
        "123",
        "9table",
        "a__b",
        "trailing_",
        "_leading",
        "a-b",
        "a.b",
        "ta*/le",
        "café",
    ] {
        let actions = json!([action(
            &format!("list-{name}"),
            "GET",
            &format!("/{name}"),
            "public",
            None,
        )]);
        let accepted = contract::extract(&document(&actions)).is_ok();
        assert_eq!(
            accepted,
            cratefield_tables::is_identifier(name),
            "the generator and the declaration rule must agree on `{name}`"
        );
    }
}

/// The two readers of nullability used to disagree: the contract model
/// saw a nullable enum, the emitter did not, so the row type lost its
/// `| null` and the sort union offered a column the server answers
/// `400 bad-sort` for. Both now read one parser, and this pins it.
#[test]
fn a_nullable_enum_column_is_null_in_the_row_and_no_sort_key() {
    // `level` is *required* and nullable — the shape whose sort-ability
    // the emitter used to get wrong, since `required` alone would admit it.
    let schema = row_schema(
        "task",
        &json!({
            "id": {
                "type": "string",
                "description": "Primary key of `task`.",
            },
            "level": {
                "type": "string",
                "enum": ["low", "high", null],
            },
        }),
        &json!(["id", "level"]),
    );
    let actions = json!([
        action("list-task", "GET", "/task", "public", None),
        action("read-task", "GET", "/task/{key}", "public", None),
        action("create-task", "POST", "/task", "public", Some(schema)),
    ]);
    let package =
        cratefield_client_ts::generate(&document(&actions)).expect("the contract must generate");
    let types = &package
        .files
        .iter()
        .find(|file| file.path == "src/types.ts")
        .expect("the package carries src/types.ts")
        .contents;

    assert!(
        types.contains("  level: \"low\" | \"high\" | null;\n"),
        "the row type carries the null arm: {types}"
    );
    let sort = types
        .lines()
        .find(|line| line.starts_with("export type TaskSort = "))
        .expect("a typed table carries a sort union");
    assert_eq!(
        sort, "export type TaskSort = \"id\" | \"-id\";",
        "the nullable column is absent from the sort union"
    );
}

/// Enum members dedupe to their first-seen order, in the model and in the
/// emitted union: `Vec::dedup` only removed *adjacent* duplicates, so a
/// non-adjacent repeat used to reach the TypeScript union twice.
#[test]
fn an_enum_dedupes_to_first_seen_order() {
    let schema = row_schema(
        "task",
        &json!({
            "id": {
                "type": "string",
                "description": "Primary key of `task`.",
            },
            "flag": {
                "type": "string",
                "enum": ["off", "on", "off", "on", "off"],
            },
        }),
        &json!(["id", "flag"]),
    );
    let actions = json!([
        action("list-task", "GET", "/task", "public", None),
        action(
            "create-task",
            "POST",
            "/task",
            "public",
            Some(schema.clone())
        ),
    ]);
    let contract = extract(&document(&actions));
    assert_eq!(
        contract.tables[0].columns[1].kind,
        ColumnKind::Enum(vec!["off".to_owned(), "on".to_owned()]),
        "first-seen order, each literal once"
    );

    let package =
        cratefield_client_ts::generate(&document(&actions)).expect("the contract must generate");
    let types = &package
        .files
        .iter()
        .find(|file| file.path == "src/types.ts")
        .expect("the package carries src/types.ts")
        .contents;
    assert!(
        types.contains("  flag: \"off\" | \"on\";\n"),
        "the emitted union carries each literal once: {types}"
    );
}
