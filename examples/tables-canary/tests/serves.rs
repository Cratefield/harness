//! The generated venture answers a request.
//!
//! `boots.rs` proves the composition succeeds. That is not the same as
//! serving: a module can compose and mount a router that answers nothing,
//! which is exactly what the generated module did before #370.
//!
//! It is also the first test written *as a venture author would write
//! one* — through `cratefield::testing`, the kit the generated
//! `[dev-dependencies]` now carry. Before that a venture had no
//! dev-dependencies at all, so an author's first `#[test]` needed a hand
//! edit to a file whose first line says not to edit it by hand.

use std::sync::Arc;

use cratefield::testing::{request, request_as, AuthMode, FakeAuth, TestHarness};
use cratefield::Module;

fn kit() -> TestHarness {
    TestHarness::with_ports(
        vec![Box::new(tables_canary::tables::DeclaredTables::new()) as Box<dyn Module>],
        |ports| {
            // The module requires `Port::Auth` because one of the
            // venture's tables is not `public-read`.
            ports.auth = Some(Arc::new(FakeAuth::new(AuthMode::TokenIsTheSubject)));
        },
    )
}

/// A read as nobody, and as somebody. Both through the kit: a venture
/// has no `tower` to drive a router with, and telling an author to add
/// one to test the routes the harness generated would be telling them to
/// work around the kit.
async fn get(kit: &TestHarness, path: &str) -> (u16, String) {
    let response = request(&kit.router, cratefield::axum::http::Method::GET, path, None).await;
    (
        response.status.as_u16(),
        String::from_utf8_lossy(response.body()).into_owned(),
    )
}

async fn get_as(kit: &TestHarness, path: &str, bearer: &str) -> (u16, String) {
    let response = request_as(
        &kit.router,
        cratefield::axum::http::Method::GET,
        path,
        bearer,
        None,
    )
    .await;
    (
        response.status.as_u16(),
        String::from_utf8_lossy(response.body()).into_owned(),
    )
}

#[pollster::test]
async fn the_public_table_is_served() {
    // `tier` is `public-read`, so an anonymous request reaches it — and
    // the table exists, which means the generated migration ran.
    let kit = kit();
    let (status, body) = get(&kit, "/v1/tables/tier").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"rows\""), "{body}");
}

#[pollster::test]
async fn the_owner_table_tells_an_anonymous_caller_to_sign_in() {
    // `note` is `owner`. The whole chain in one request: the generated
    // module's declaration, the access decision, and the `Auth` port the
    // generated runtime wires.
    let kit = kit();
    let (status, body) = get(&kit, "/v1/tables/note").await;
    assert_eq!(status, 401, "{body}");
}

#[pollster::test]
async fn the_owner_table_serves_a_signed_in_caller() {
    let kit = kit();
    let (status, body) = get_as(&kit, "/v1/tables/note", "ada").await;
    assert_eq!(status, 200, "{body}");
}

#[pollster::test]
async fn a_table_the_venture_does_not_declare_is_not_served() {
    let kit = kit();
    let (status, _) = get(&kit, "/v1/tables/ledger").await;
    assert_eq!(status, 404);
}
