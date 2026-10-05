//! The CRM's admin surface: every action is an admin action under
//! `/admin/`, both CSV exports have a table view, and the public subset is
//! empty because the module serves no public route.

use axum::http::Method;
use cratefield_core::{Audience, Column, ConfigError, Module, Outcome, Surface, View};
use cratefield_module_crm::Crm;

fn surface() -> Surface {
    Crm::new().surface()
}

/// The table views' sources, in declaration order.
fn sources(surface: &Surface) -> Vec<&str> {
    surface
        .views
        .iter()
        .filter_map(|view| match view {
            View::Table { source, .. } => Some(source.as_str()),
            _ => None,
        })
        .collect()
}

/// One table view's columns.
fn columns<'a>(surface: &'a Surface, wanted: &str) -> Option<&'a [Column]> {
    surface.views.iter().find_map(|view| match view {
        View::Table { source, columns } if source == wanted => Some(columns.as_slice()),
        _ => None,
    })
}

#[test]
fn the_surface_is_valid_and_entirely_admin() {
    let surface = surface();
    let mut errors = ConfigError::default();
    surface.validate("crm", &mut errors);
    assert!(errors.is_empty(), "{errors}");

    assert_eq!(surface.actions.len(), 12, "{:?}", surface.actions);
    for action in &surface.actions {
        assert_eq!(action.audience, Audience::Admin, "{}", action.name);
        assert_eq!(action.outcome, Outcome::Json, "{}", action.name);
        assert!(
            action.path.starts_with("/admin/"),
            "{} is not under /admin/",
            action.path
        );
    }
}

#[test]
fn the_exports_carry_a_table_view() {
    let surface = surface();
    let tables = sources(&surface);
    assert!(tables.contains(&"contacts-export"), "{tables:?}");
    assert!(tables.contains(&"organisations-export"), "{tables:?}");

    let contacts = columns(&surface, "contacts-export").expect("contacts table");
    assert!(
        contacts.iter().any(|column| column.key == "email"),
        "{contacts:?}"
    );
    assert!(
        contacts
            .iter()
            .any(|column| column.key == "organisation_id"),
        "{contacts:?}"
    );
}

#[test]
fn a_patch_carries_its_generation() {
    let surface = surface();
    let update = surface
        .actions
        .iter()
        .find(|action| action.name == "contact-update")
        .expect("contact-update");
    assert_eq!(update.method, Method::PATCH);
    assert_eq!(update.path, "/admin/contacts/{id}");
    let input = update.input.as_ref().expect("input schema").as_value();
    assert_eq!(input["type"], "object");
    assert!(
        input["properties"]["generation"].is_object(),
        "the generation guard is part of the documented body: {input}"
    );
    // A PATCH field is nullable in the schema (null clears it) even though it
    // is optional in the body (absent leaves it).
    assert!(
        input["properties"]["name"].to_string().contains("null"),
        "{input}"
    );
}

#[test]
fn the_public_subset_is_empty() {
    let surface = surface();
    assert!(
        surface
            .actions
            .iter()
            .any(|a| a.audience == Audience::Admin)
    );
    let public = surface.public();
    assert!(public.actions.is_empty(), "{:?}", public.actions);
    assert!(public.views.is_empty(), "{:?}", public.views);
}
