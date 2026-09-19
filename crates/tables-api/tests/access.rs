//! Who may reach a declared table's rows, and which of them.
//!
//! Every case is a value here rather than a request, which is the reason
//! the decision is a function and not something the handlers do inline.

use cratefield_core::{Caller, Problem, Subject, Tenancy};
use cratefield_manifest::Access;
use cratefield_tables::{Schema, TableDef};
use cratefield_tables_api::{Reach, TableApi, may_read, may_write};

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
    let reach = may_read(
        &api(Access::PublicRead, None),
        Tenancy::Sole,
        &Caller::Anonymous,
        Ok(()),
    )
    .expect("public-read is public");
    assert_eq!(reach, Reach::Everything);
}

#[test]
fn a_tenant_table_tells_an_anonymous_caller_to_sign_in() {
    // 401 and not an empty page: "no rows" and "you are not signed in"
    // are different answers, and only one of them is actionable. The
    // sole tenancy is the shape where signing in is an answer that can
    // work — under `FromRegistry` even a signed-in caller is refused,
    // and anonymous gets the deployment fault, not the 401.
    let refusal = may_read(
        &api(Access::TenantMembers, None),
        Tenancy::Sole,
        &Caller::Anonymous,
        Ok(()),
    )
    .expect_err("not public");
    assert_eq!(refusal.status.as_u16(), 401);
    assert_eq!(refusal.slug, "unauthenticated");
}

#[test]
fn a_tenant_table_serves_every_row_to_any_verified_caller() {
    // Named for what it establishes, and now about one tenancy shape
    // only. Nothing here makes Ada a member of anything, and nothing in
    // `may_read` could check it if it did: there is no membership fact
    // on a `Subject`. `Tenancy::Sole` is the shape where that does not
    // matter — no registry, one tenant, so "any verified caller" and
    // "a member of this tenant" are the same set and the level serves
    // (issue #385). Under `Tenancy::FromRegistry` the same call refuses.
    //
    // The name it had, `..._to_a_member`, asserted a fact the test never
    // supplied, which is the way a test stops being able to fail.
    let reach = may_read(
        &api(Access::TenantMembers, None),
        Tenancy::Sole,
        &ada(),
        Ok(()),
    )
    .expect("a verified caller reaches it");
    assert_eq!(reach, Reach::Everything);
}

#[test]
fn a_tenant_table_refuses_a_verified_caller_when_a_registry_resolved_the_tenant() {
    // The fail-closed half of #385. Ada is verified and the answer is
    // still no: on a registry deployment the verifier is the
    // deployment's while the tenant is the host's, so "a member of this
    // tenant" is a fact the harness does not have, and serving "any
    // verified caller" as it would hand tenant B's database to a
    // signer-in of tenant A.
    let refusal = may_read(
        &api(Access::TenantMembers, None),
        Tenancy::FromRegistry,
        &ada(),
        Ok(()),
    )
    .expect_err("membership cannot be established here");
    assert_eq!(refusal.slug, "no-membership-fact");
    // 500 and not 403: nothing the caller did is wrong, and signing in
    // as somebody else fixes nothing.
    assert_eq!(refusal.status.as_u16(), 500);
}

#[test]
fn a_tenant_table_refuses_a_verified_writer_when_a_registry_resolved_the_tenant() {
    // The write half of the same refusal. `may_read` closing without
    // `may_write` following would leave the level writable by everybody
    // the verifier accepts — the same set, on the same missing fact.
    let refusal = may_write(
        &api(Access::TenantMembers, None),
        Tenancy::FromRegistry,
        &ada(),
        Ok(()),
    )
    .expect_err("the same refusal, for writes");
    assert_eq!(refusal.slug, "no-membership-fact");
    assert_eq!(refusal.status.as_u16(), 500);
}

#[test]
fn the_registry_refusal_is_answered_before_the_callers_credential_is_read() {
    // The ordering is the point. The level cannot be honoured on this
    // deployment whoever is asking, so an anonymous caller gets the same
    // 500 — not `unauthenticated`, which would send them off to sign in
    // and blame them for a fault of the deployment's composition.
    let refusal = may_read(
        &api(Access::TenantMembers, None),
        Tenancy::FromRegistry,
        &Caller::Anonymous,
        Ok(()),
    )
    .expect_err("nobody can be served by the level here");
    assert_eq!(refusal.slug, "no-membership-fact");
    assert_eq!(refusal.status.as_u16(), 500);
}

#[test]
fn an_owner_table_whose_subject_column_cannot_hold_an_id_is_misdeclared() {
    // Not a 400. The caller sent nothing wrong: the deployment declared a
    // subject column a caller's id does not fit in, and `fz build`
    // refuses that. Answered further down, it became `400 bad-filter`
    // naming the subject column — blaming the caller for a filter they
    // never sent, and telling them part of the table's shape.
    let mut table = note();
    for field in &mut table.fields {
        if field.name == "author" {
            field.kind = cratefield_tables::FieldKind::Integer {
                min: None,
                max: None,
            };
        }
    }
    let api = TableApi {
        table,
        access: Access::Owner,
        subject: Some("author".to_owned()),
    };
    let refusal = may_read(&api, Tenancy::Sole, &ada(), Ok(()))
        .expect_err("nothing can be scoped to an integer");
    assert_eq!(refusal.status.as_u16(), 500);
    assert_eq!(refusal.slug, "table-misdeclared");
    assert!(
        !format!("{:?}", refusal.detail).contains("author"),
        "the subject column reached the caller: {:?}",
        refusal.detail
    );
}

#[test]
fn an_owner_table_tells_an_anonymous_caller_to_sign_in() {
    let refusal = may_read(
        &api(Access::Owner, Some("author")),
        Tenancy::Sole,
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
    let reach = may_read(
        &api(Access::Owner, Some("author")),
        Tenancy::Sole,
        &ada(),
        Ok(()),
    )
    .expect("ada owns hers");
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
    let for_ada = may_read(
        &api(Access::Owner, Some("author")),
        Tenancy::Sole,
        &ada(),
        Ok(()),
    )
    .expect("ada");
    let for_grace = may_read(
        &api(Access::Owner, Some("author")),
        Tenancy::Sole,
        &grace,
        Ok(()),
    )
    .expect("grace");
    assert_ne!(for_ada, for_grace, "one scope served two callers");
}

#[test]
fn owner_without_a_subject_column_refuses_rather_than_guessing() {
    // `fz build` refuses this manifest (#359), so reaching it means a
    // deployment is running a composition its manifest would not have
    // produced. With no column to match, "everything" and "nothing" are
    // both wrong and one of them is a leak — so it is neither.
    let refusal = may_read(&api(Access::Owner, None), Tenancy::Sole, &ada(), Ok(()))
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
    let refusal = may_read(
        &api(Access::Owner, Some("nope")),
        Tenancy::Sole,
        &ada(),
        Ok(()),
    )
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
        Tenancy::Sole,
        &Caller::Anonymous,
        admin_refused(&cratefield_core::SLUGS.admin_unauthorized),
    )
    .expect_err("no token");
    assert_eq!(unauthorized.status.as_u16(), 401);
    assert_eq!(unauthorized.slug, "admin-unauthorized");

    let forbidden = may_read(
        &api(Access::Admin, None),
        Tenancy::Sole,
        &ada(),
        admin_refused(&cratefield_core::SLUGS.admin_forbidden),
    )
    .expect_err("wrong token");
    assert_eq!(forbidden.status.as_u16(), 403);
    assert_eq!(forbidden.slug, "admin-forbidden");
}

#[test]
fn an_admin_table_serves_everything_to_an_admin() {
    let reach = may_read(
        &api(Access::Admin, None),
        Tenancy::Sole,
        &Caller::Anonymous,
        Ok(()),
    )
    .expect("the token checked out");
    assert_eq!(reach, Reach::Everything);
}

#[test]
fn being_signed_in_is_not_being_an_admin() {
    // The one that would be easy to get wrong by reading `Caller` first
    // and the admin token second.
    let refusal = may_read(
        &api(Access::Admin, None),
        Tenancy::Sole,
        &ada(),
        admin_refused(&cratefield_core::SLUGS.admin_unauthorized),
    )
    .expect_err("a session is not an admin token");
    assert_eq!(refusal.status.as_u16(), 401);
}
