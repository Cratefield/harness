//! The curated detail, checked against the modules it describes.
//!
//! [`ModuleDetail`](cratefield_catalog::ModuleDetail) is hand-written
//! customer-facing copy, and hand-written copy about code drifts from the
//! code the first time somebody changes one and not the other. Everything
//! here that *can* be derived from the module is derived and compared: a
//! module that grows a port, a table, or a UI surface and does not update
//! the catalog fails this suite.
//!
//! What is deliberately not checked, because nothing here can reach it:
//! the prose, and the route *set* — an axum `Router` exposes no list of
//! its paths. The paths' prefix is checked, which is the part a rename
//! would silently break.

use cratefield_catalog::{CatalogModule, curated};
use cratefield_core::{Module, Port};

fn port_names(ports: &[Port]) -> Vec<String> {
    ports.iter().map(|p| p.name().to_owned()).collect()
}

/// Every curated module, paired with the module it claims to describe.
fn pairs() -> Vec<(CatalogModule, Box<dyn Module>)> {
    let modules: Vec<Box<dyn Module>> = vec![
        Box::new(cratefield_module_email_signup::EmailSignup::new()),
        Box::new(cratefield_module_waitlist::Waitlist::new()),
        Box::new(cratefield_module_cms::Cms::new()),
        Box::new(cratefield_module_notifications::Notifications::new()),
        Box::new(cratefield_module_privacy::Privacy::new()),
    ];
    let catalog = curated();
    assert_eq!(
        catalog.modules.len(),
        modules.len(),
        "a module was added to the curated catalog without being described here"
    );
    modules
        .into_iter()
        .map(|module| {
            let entry = catalog
                .modules
                .iter()
                .find(|m| m.slug == module.name())
                .unwrap_or_else(|| panic!("no catalog entry for `{}`", module.name()))
                .clone();
            (entry, module)
        })
        .collect()
}

#[test]
fn the_detail_names_the_ports_the_module_actually_requires() {
    for (entry, module) in pairs() {
        assert_eq!(
            entry.detail.needs,
            port_names(module.requires()),
            "`{}` requires different ports than the catalog says",
            entry.slug
        );
        assert_eq!(
            entry.detail.optional,
            port_names(module.optional()),
            "`{}` has different optional ports than the catalog says",
            entry.slug
        );
    }
}

#[test]
fn the_detail_names_the_tables_the_module_actually_creates() {
    for (entry, module) in pairs() {
        assert_eq!(
            entry.detail.tables,
            module.tables(),
            "`{}` creates different tables than the catalog says",
            entry.slug
        );
    }
}

#[test]
fn a_surface_is_claimed_exactly_when_the_module_renders_one() {
    for (entry, module) in pairs() {
        let surface = module.surface();
        let renders = !surface.actions.is_empty() || !surface.views.is_empty();
        assert_eq!(
            entry.detail.surface.is_some(),
            renders,
            "`{}` claims a UI surface it does not render, or renders one it does not claim",
            entry.slug
        );
    }
}

#[test]
fn every_route_is_mounted_under_the_module_it_belongs_to() {
    // `Harness::build` nests a module at `/v1/{name}`, so a path that does
    // not start there is one a caller cannot reach.
    for (entry, module) in pairs() {
        let prefix = format!("/v1/{}", module.name());
        assert!(
            !entry.detail.routes.is_empty(),
            "`{}` lists no routes",
            entry.slug
        );
        for route in &entry.detail.routes {
            assert!(
                route.path == prefix || route.path.starts_with(&format!("{prefix}/")),
                "`{}` lists `{}`, which is not under `{prefix}`",
                entry.slug,
                route.path
            );
            assert!(
                !route.note.is_empty(),
                "`{}` has a route with no note",
                entry.slug
            );
            assert_eq!(
                route.method,
                route.method.to_uppercase(),
                "a method is written in lower case"
            );
        }
    }
}

#[test]
fn the_detail_names_the_crate_the_module_ships_as() {
    for (entry, _) in pairs() {
        assert_eq!(
            entry.detail.crate_name,
            format!("cratefield-module-{}", entry.slug),
            "`{}` names a crate that does not follow the convention",
            entry.slug
        );
        assert!(
            !entry.detail.what_it_is.is_empty(),
            "`{}` has no description",
            entry.slug
        );
    }
}
