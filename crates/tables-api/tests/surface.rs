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
    // `/{table}/{key}` refuses a key of several columns rather than
    // joining them with a separator that could occur inside one, so those
    // three routes do not exist for this table (#387). Publishing them
    // would put three methods in every generated client that answer 400
    // whatever they are called with — which is the argument `public-read`
    // already wins by publishing its reads and not a create.
    let published = surface(&[TableApi {
        table: membership(),
        access: Access::TenantMembers,
        subject: None,
    }]);
    assert_eq!(
        names(&published),
        vec!["list-membership", "create-membership"],
        "a composite-key table has a page and a create, and no route naming one row"
    );
}

#[test]
fn a_single_column_key_still_publishes_all_five() {
    // The other half of the pair: the check above passes for a surface
    // that had simply stopped publishing single-row actions for
    // everything, and that is not what was asked for.
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
}
