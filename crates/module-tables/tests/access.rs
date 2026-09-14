//! Who may reach a declared table's rows, and which of them.
//!
//! Every case is a value here rather than a request, which is the reason
//! the decision is a function and not something the handlers do inline.

use cratefield_core::{Caller, Problem, Subject};
use cratefield_manifest::Access;
use cratefield_module_tables::{Reach, TableApi, may_read};
use cratefield_tables::{Schema, TableDef};

#[derive(serde::Deserialize)]
struct Manifest {
    tables: Schema,
}

const NOTE: &str = r#"
[tables.note]
primary_key = "id"

[[tables.note.fields]]
name = "id"
kind = "uuid"
required = true

[[tables.note.fields]]
name = "author"
kind = "text"
required = true

[[tables.note.fields]]
name = "body"
kind = "text"
"#;

fn note() -> TableDef {
    toml::from_str::<Manifest>(NOTE)
        .expect("the fragment parses")
        .tables
        .table("note")
        .expect("declared")
        .clone()
}

fn api(access: Access, subject: Option<&str>) -> TableApi {
    TableApi {
        table: note(),
        access,
        subject: subject.map(str::to_owned),
    }
}

fn ada() -> Caller {
    Caller::Subject(Subject::new("ada"))
}

/// The admin check's own refusal, which must survive unchanged.
fn admin_refused(def: &'static cratefield_core::ProblemDef) -> Result<(), Problem> {
    Err(Problem::new(def))
}

#[test]
fn a_public_table_serves_a_caller_who_never_signed_in() {
    let reach = may_read(&api(Access::PublicRead, None), &Caller::Anonymous, Ok(()))
        .expect("public-read is public");
    assert_eq!(reach, Reach::Everything);
}

#[test]
fn a_tenant_table_tells_an_anonymous_caller_to_sign_in() {
    // 401 and not an empty page: "no rows" and "you are not signed in"
    // are different answers, and only one of them is actionable.
    let refusal = may_read(
        &api(Access::TenantMembers, None),
        &Caller::Anonymous,
        Ok(()),
    )
    .expect_err("not public");
    assert_eq!(refusal.status.as_u16(), 401);
    assert_eq!(refusal.slug, "unauthenticated");
}

#[test]
fn a_tenant_table_serves_every_row_to_a_member() {
    let reach =
        may_read(&api(Access::TenantMembers, None), &ada(), Ok(())).expect("a member reaches it");
    assert_eq!(reach, Reach::Everything);
}

#[test]
fn an_owner_table_tells_an_anonymous_caller_to_sign_in() {
    let refusal = may_read(
        &api(Access::Owner, Some("author")),
        &Caller::Anonymous,
        Ok(()),
    )
    .expect_err("nobody owns nothing");
    assert_eq!(refusal.status.as_u16(), 401);
}

#[test]
fn an_owner_table_is_scoped_to_the_callers_own_rows() {
    // The scope, not a post-filter. Filtering after the fetch would pair
    // a `LIMIT` with a discard and hand back a short page, which leaks
    // how many rows the caller did not get.
    let reach =
        may_read(&api(Access::Owner, Some("author")), &ada(), Ok(())).expect("ada owns hers");
    assert_eq!(
        reach,
        Reach::OwnedBy {
            column: "author".to_owned(),
            subject: "ada".to_owned(),
        }
    );
}

#[test]
fn two_callers_are_scoped_to_different_rows() {
    let grace = Caller::Subject(Subject::new("grace"));
    let for_ada = may_read(&api(Access::Owner, Some("author")), &ada(), Ok(())).expect("ada");
    let for_grace = may_read(&api(Access::Owner, Some("author")), &grace, Ok(())).expect("grace");
    assert_ne!(for_ada, for_grace, "one scope served two callers");
}

#[test]
fn owner_without_a_subject_column_refuses_rather_than_guessing() {
    // `fz build` refuses this manifest (#359), so reaching it means a
    // deployment is running a composition its manifest would not have
    // produced. With no column to match, "everything" and "nothing" are
    // both wrong and one of them is a leak — so it is neither.
    let refusal = may_read(&api(Access::Owner, None), &ada(), Ok(()))
        .expect_err("there is nothing to match against");
    assert_eq!(refusal.slug, "table-misdeclared");
    // 500 and not 403: nothing the caller did is wrong.
    assert_eq!(refusal.status.as_u16(), 500);
}

#[test]
fn a_subject_column_that_is_not_a_field_is_the_same_refusal() {
    // The declaration and the table have to agree at the moment of the
    // request, not only at the moment of the build: a table edited under
    // a stale privacy block would otherwise produce `WHERE nope = 'ada'`,
    // which is a database error at best and a match on nothing at worst.
    let refusal = may_read(&api(Access::Owner, Some("nope")), &ada(), Ok(()))
        .expect_err("the column is not there");
    assert_eq!(refusal.slug, "table-misdeclared");
}

#[test]
fn an_admin_table_keeps_the_admin_checks_own_answer() {
    // "Admin endpoints are disabled or you sent no token" and "the token
    // you sent is wrong" are different facts, and re-deciding them here
    // would collapse a 401 and a 403 into one.
    let unauthorized = may_read(
        &api(Access::Admin, None),
        &Caller::Anonymous,
        admin_refused(&cratefield_core::SLUGS.admin_unauthorized),
    )
    .expect_err("no token");
    assert_eq!(unauthorized.status.as_u16(), 401);
    assert_eq!(unauthorized.slug, "admin-unauthorized");

    let forbidden = may_read(
        &api(Access::Admin, None),
        &ada(),
        admin_refused(&cratefield_core::SLUGS.admin_forbidden),
    )
    .expect_err("wrong token");
    assert_eq!(forbidden.status.as_u16(), 403);
    assert_eq!(forbidden.slug, "admin-forbidden");
}

#[test]
fn an_admin_table_serves_everything_to_an_admin() {
    let reach = may_read(&api(Access::Admin, None), &Caller::Anonymous, Ok(()))
        .expect("the token checked out");
    assert_eq!(reach, Reach::Everything);
}

#[test]
fn being_signed_in_is_not_being_an_admin() {
    // The one that would be easy to get wrong by reading `Caller` first
    // and the admin token second.
    let refusal = may_read(
        &api(Access::Admin, None),
        &ada(),
        admin_refused(&cratefield_core::SLUGS.admin_unauthorized),
    )
    .expect_err("a session is not an admin token");
    assert_eq!(refusal.status.as_u16(), 401);
}
