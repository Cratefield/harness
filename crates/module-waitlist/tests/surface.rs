//! The waitlist's UI surface (ADR 0010, issue #71): declared from the
//! handlers' own body types, product as a `select` over the configured
//! list, admin export hidden from the public subset.

use cratefield_core::{Audience, Module, View};
use cratefield_module_waitlist::Waitlist;

#[test]
fn join_form_offers_the_configured_products_as_a_select() {
    let surface = Waitlist::new()
        .products(["kontinuum", "undercover"])
        .surface();
    let join = surface
        .actions
        .iter()
        .find(|a| a.name == "join")
        .expect("join action");
    assert_eq!(join.method, http::Method::POST);
    assert_eq!(join.path, "/");
    assert!(join.captcha);
    let input = join.input.as_ref().expect("input schema").as_value();
    assert_eq!(input["type"], "object");
    assert_eq!(
        input["properties"]["product"]["enum"],
        serde_json::json!(["kontinuum", "undercover"])
    );
    assert_eq!(input["properties"]["product"]["x-cf-widget"], "select");
    assert!(
        input["properties"]["product"].get("description").is_none(),
        "developer notes must not leak into the surface"
    );
    assert_eq!(input["properties"]["email"]["x-cf-widget"], "email");
    for hidden in ["ref", "answers", "locale", "captchaToken"] {
        assert_eq!(
            input["properties"][hidden]["x-cf-hidden"], true,
            "{hidden} must be hidden"
        );
    }
    assert!(
        surface
            .views
            .iter()
            .any(|v| matches!(v, View::Form { action } if action == "join"))
    );
}

#[test]
fn any_product_keeps_product_as_free_text() {
    let surface = Waitlist::new().any_product().surface();
    let join = surface.actions.iter().find(|a| a.name == "join").unwrap();
    let input = join.input.as_ref().unwrap().as_value();
    assert!(input["properties"]["product"].get("enum").is_none());
}

#[test]
fn public_subset_hides_the_admin_export_and_its_table() {
    let surface = Waitlist::new().products(["kontinuum"]).surface();
    assert!(
        surface
            .actions
            .iter()
            .any(|a| a.audience == Audience::Admin)
    );
    let public = surface.public();
    assert!(public.actions.iter().all(|a| a.audience != Audience::Admin));
    assert!(!public.views.iter().any(|v| matches!(v, View::Table { .. })));
    assert!(
        public
            .views
            .iter()
            .any(|v| matches!(v, View::Status { .. }))
    );
}
