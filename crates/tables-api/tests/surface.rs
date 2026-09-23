//! What a venture publishes about the tables it declares.
//!
//! A declared table that is served and absent from `/__surface` is a
//! venture whose published contract is smaller than the venture. The
//! subtler failure is publishing the wrong thing about it — a write on a
//! table nobody may write, or a public form for rows only their owner can
//! reach.

use cratefield_core::{Audience, Surface, WriteGuards};
use cratefield_manifest::Access;
use cratefield_tables::{Schema, TableDef};
use cratefield_tables_api::{TableApi, surface};

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
"#;

fn note() -> TableDef {
    toml::from_str::<Fragment>(NOTE)
        .expect("parses")
        .tables
        .table("note")
        .expect("declared")
        .clone()
}

fn for_access(access: Access) -> Surface {
    surface(&[TableApi {
        table: note(),
        access,
        subject: Some("author".to_owned()),
    }])
}

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

fn membership() -> TableDef {
    toml::from_str::<Fragment>(MEMBERSHIP)
        .expect("parses")
        .tables
        .table("membership")
        .expect("declared")
        .clone()
}

fn names(surface: &Surface) -> Vec<String> {
    surface
        .actions
        .iter()
        .map(|action| action.name.clone())
        .collect()
}

#[test]
fn a_declared_table_publishes_its_reads() {
    let published = for_access(Access::PublicRead);
    assert_eq!(names(&published), ["list-note", "read-note"]);
}

#[test]
fn a_public_read_table_publishes_no_writes() {
    // There are none — the level is exactly that. Publishing a create
    // would advertise a form whose every submission is refused.
    let published = for_access(Access::PublicRead);
    assert!(
        !names(&published)
            .iter()
            .any(|name| name.starts_with("create-")),
        "{:?}",
        names(&published)
    );
}

#[test]
fn a_writable_table_publishes_all_five() {
    let published = for_access(Access::Owner);
    assert_eq!(
        names(&published),
        [
            "list-note",
            "read-note",
            "create-note",
            "replace-note",
            "delete-note"
        ]
    );
}

#[test]
fn a_table_whose_rows_belong_to_someone_is_not_published_as_public() {
    // Publishing `owner` as public would render a form for rows the
    // caller cannot reach; publishing it as admin would hide it from the
    // person whose rows they are.
    for access in [Access::Owner, Access::TenantMembers] {
        let published = for_access(access);
        for action in &published.actions {
            assert_eq!(
                action.audience,
                Audience::Subject,
                "{access} published `{}` as {:?}",
                action.name,
                action.audience
            );
        }
    }
}

#[test]
fn a_public_table_is_published_as_public_and_an_admin_one_as_admin() {
    for action in &for_access(Access::PublicRead).actions {
        assert_eq!(action.audience, Audience::Public, "{}", action.name);
    }
    for action in &for_access(Access::Admin).actions {
        assert_eq!(action.audience, Audience::Admin, "{}", action.name);
    }
}

#[test]
fn a_write_publishes_the_tables_own_schema_as_its_body() {
    // The same bytes the row validator enforces, so a generated form and
    // the route it posts to cannot disagree about what a row is.
    let published = for_access(Access::Owner);
    let create = published
        .actions
        .iter()
        .find(|action| action.name == "create-note")
        .expect("a create");
    let schema = create.input.as_ref().expect("a body schema");
    let published_json = serde_json::to_value(schema).expect("serializes");
    assert_eq!(published_json, cratefield_tables::json_schema(&note()));
}

#[test]
fn the_paths_are_the_ones_the_router_serves() {
    // `/{table}` and `/{table}/{key}`, mounted under the module's name.
    // A surface naming a path nothing serves is worse than no surface.
    let published = for_access(Access::Owner);
    let paths: Vec<&str> = published
        .actions
        .iter()
        .map(|action| action.path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "/note",
            "/note/{key}",
            "/note",
            "/note/{key}",
            "/note/{key}"
        ]
    );
}

#[test]
fn a_venture_with_no_declared_tables_publishes_nothing() {
    assert!(surface(&[]).actions.is_empty());
}

#[test]
fn a_writable_table_does_not_make_a_venture_demand_a_captcha() {
    // `WriteGuards` reads a module's surface to decide what protects its
    // writes, and a production venture with captcha-guarded writes and no
    // effective Captcha port is refused at build. So if these actions
    // read as human forms, a venture with one writable declared table
    // could not boot in production without a captcha adapter — for writes
    // its own handlers authenticate.
    //
    // They do not, because `RoutePolicy`'s default is "no gateway-level
    // protection, correct for anything the handler authenticates itself".
    // That is two defaults lining up rather than a decision anybody wrote
    // down, which is why this is a test and not a comment.
    for access in [Access::Owner, Access::TenantMembers, Access::Admin] {
        let published = for_access(access);
        let guards = WriteGuards::from_surface("tables", &published);
        assert!(
            guards.captcha_modules.is_empty(),
            "{access} makes the venture demand a captcha for writes it authenticates itself"
        );
        assert!(
            guards.signature_modules.is_empty(),
            "{access} reads as a webhook receiver"
        );
    }
}

#[test]
fn a_public_table_demands_nothing_because_it_has_no_writes() {
    let guards = WriteGuards::from_surface("tables", &for_access(Access::PublicRead));
    assert!(guards.captcha_modules.is_empty());
    assert!(guards.signature_modules.is_empty());
}

#[test]
fn the_published_json_does_not_ask_a_reader_for_a_captcha_widget() {
    // `Action::policy` is `#[serde(skip)]`: what reaches a consumer of
    // the surface document is the legacy `captcha` bool, and a renderer
    // reads that to decide whether to draw the widget. So the in-process
    // guard being right is not the whole answer — the serialized form has
    // to say the same thing.
    let published = for_access(Access::Owner);
    let document = serde_json::to_value(&published).expect("serializes");
    for action in document["actions"].as_array().expect("actions") {
        assert_eq!(
            action["captcha"],
            serde_json::json!(false),
            "`{}` asks a renderer for a captcha widget",
            action["name"]
        );
    }
}

#[test]
fn a_composite_key_table_publishes_only_the_routes_it_has() {
    // ADR 0018: the three actions return, against the harness's reserved
    // `__by` sub-path — the key named in the query, where the path could
    // carry only one segment and refused to invent a separator. The
    // contract lists what is there, and what is there now is five.
    let published = surface(&[TableApi {
        table: membership(),
        access: Access::TenantMembers,
        subject: None,
    }]);
    assert_eq!(
        names(&published),
        [
            "list-membership",
            "read-membership",
            "create-membership",
            "replace-membership",
            "delete-membership"
        ],
        "a composite-key table publishes all five again"
    );

    let read = &published.actions[1];
    assert_eq!(read.path, "/membership/__by");
    let query = read
        .input
        .as_ref()
        .expect("a GET's input is its query, and this one names the key");
    let query = serde_json::to_value(query).expect("serializes");
    assert_eq!(
        query["required"],
        serde_json::json!(["tenant", "member"]),
        "the key columns, all of them"
    );
    assert_eq!(query["properties"]["tenant"]["type"], "string");

    let replace = &published.actions[3];
    assert_eq!(replace.path, "/membership/__by");
    // A PUT's input is still its body — the row — so a form renders from
    // the table's own schema exactly as it does for a single-column key;
    // the key columns it must also send ride beside the body as
    // `x-cf-query`, pinned in full by
    // `a_composite_key_tables_replace_publishes_which_key_columns_go_in_the_query`.
    let body = replace.input.as_ref().expect("the body schema");
    let body = serde_json::to_value(body).expect("serializes");
    let row = cratefield_tables::json_schema(&membership());
    assert_eq!(body["properties"], row["properties"]);
    assert_eq!(body["required"], row["required"]);

    let delete = &published.actions[4];
    assert_eq!(delete.path, "/membership/__by");
    let query = delete
        .input
        .as_ref()
        .expect("a delete has no body, so its input is its query");
    let query = serde_json::to_value(query).expect("serializes");
    assert_eq!(query["required"], serde_json::json!(["tenant", "member"]));
}

#[test]
fn a_single_column_key_still_publishes_all_five() {
    // The other half of the pair: the test above passes for a surface
    // that had moved *every* table's single-row actions to `__by`, and
    // that is not what changed. A key of one column is a path segment
    // and stays one; the composite-key spelling is for the keys the path
    // could not carry.
    let published = for_access(Access::TenantMembers);
    assert_eq!(
        names(&published),
        vec![
            "list-note",
            "read-note",
            "create-note",
            "replace-note",
            "delete-note"
        ]
    );
    assert_eq!(
        published
            .actions
            .iter()
            .find(|action| action.name == "read-note")
            .expect("a read")
            .path,
        "/note/{key}",
        "the single-column spelling is the path"
    );
}

#[test]
fn the_published_shape_tells_a_path_parameter_from_a_query_parameter() {
    // A consumer generating a client has to know where the key goes, and
    // the published shape says so: a `{key}` placeholder in the path is
    // a path parameter carrying one value; an `__by` path carries no
    // placeholder at all, and the input schema — a GET's input is its
    // query — names the key columns instead.
    let single = for_access(Access::TenantMembers);
    let read = single
        .actions
        .iter()
        .find(|action| action.name == "read-note")
        .expect("a read");
    assert_eq!(read.path, "/note/{key}");
    assert!(
        read.input.is_none(),
        "a path key takes no query: {:?}",
        read.input
    );

    let composite = surface(&[TableApi {
        table: membership(),
        access: Access::TenantMembers,
        subject: None,
    }]);
    let read = composite
        .actions
        .iter()
        .find(|action| action.name == "read-membership")
        .expect("a read");
    assert!(
        !read.path.contains('{'),
        "no placeholder in the query spelling: {}",
        read.path
    );
    let query =
        serde_json::to_value(read.input.as_ref().expect("the query schema")).expect("serializes");
    assert_eq!(query["type"], "object");
    assert_eq!(query["required"], serde_json::json!(["tenant", "member"]));
    assert_eq!(
        query["additionalProperties"], false,
        "the query names key columns only, as the route refuses the rest"
    );
}

#[test]
fn a_composite_key_tables_replace_publishes_which_key_columns_go_in_the_query() {
    // The defect this pins: `replace-` published the row body alone, so a
    // client generated from the contract knew the PUT route and not that
    // it must append `?<col>=<value>&…` — and learned it from a
    // `400 partial-key` instead of from the document. `input` has one
    // slot and a PUT's is its body, so the query rides beside the body as
    // an `x-cf-query` extension on the same schema — riding under the
    // `x-cf-*` namespace the harness defines, whose forward-compatibility
    // guarantee it borrows (a keyword the consumer does not know is
    // ignored, never an error); the keyword itself is introduced by this
    // crate and appears nowhere in the harness.
    let published = surface(&[TableApi {
        table: membership(),
        access: Access::TenantMembers,
        subject: None,
    }]);
    let replace = published
        .actions
        .iter()
        .find(|action| action.name == "replace-membership")
        .expect("a replace");
    assert_eq!(replace.path, "/membership/__by");
    let input =
        serde_json::to_value(replace.input.as_ref().expect("the body schema")).expect("serializes");
    // The body is still the row the form renders from.
    let row = cratefield_tables::json_schema(&membership());
    assert_eq!(input["properties"], row["properties"]);
    assert_eq!(input["required"], row["required"]);
    // And the query names every key column, each described as the row
    // describes it, and nothing else — the same schema the read's and the
    // delete's inputs publish outright.
    let query = &input["x-cf-query"];
    assert_eq!(query["type"], "object");
    assert_eq!(query["required"], serde_json::json!(["tenant", "member"]));
    assert_eq!(query["properties"]["tenant"]["type"], "string");
    assert_eq!(query["properties"]["member"]["type"], "string");
    assert_eq!(
        query["additionalProperties"], false,
        "the query names key columns only, as the route refuses the rest"
    );
}

#[test]
fn a_public_read_table_publishes_what_its_reads_answer() {
    // A `public-read` table publishes no write, so no action carries the
    // row as its input; without an output a consumer would know the
    // routes and not what a row is.
    let published = for_access(Access::PublicRead);
    let output = |name: &str| {
        let action = published
            .actions
            .iter()
            .find(|action| action.name == name)
            .expect("published");
        serde_json::to_value(action.output.as_ref().expect("an output")).expect("serializes")
    };
    let row = cratefield_tables::json_schema(&note());
    assert_eq!(output("read-note"), row, "a single read answers the row");

    let page = output("list-note");
    assert_eq!(page["type"], "object");
    assert_eq!(page["required"], serde_json::json!(["rows", "next"]));
    assert_eq!(page["properties"]["rows"]["type"], "array");
    let mut items = row;
    items
        .as_object_mut()
        .expect("an object schema")
        .remove("$schema");
    assert_eq!(page["properties"]["rows"]["items"], items);
    assert_eq!(
        page["properties"]["next"]["type"],
        serde_json::json!(["object", "null"]),
        "the last page's cursor is null"
    );
}
