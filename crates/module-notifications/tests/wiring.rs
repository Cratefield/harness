//! The production readiness check, wired the way a venture wires it.
//!
//! The push environment has exactly one reader — `cratefield-push-wiring`
//! (#191) — so the module takes the answer as a probe rather than naming
//! the variables itself. This is the test that the probe a venture actually
//! passes gives the answer the check needs; the module's own unit tests use
//! stubs, and a stub could agree with a probe that does not exist.

use cratefield_core::{MapConfig, Module};
use cratefield_module_notifications::{Category, Notifications};
use cratefield_push_wiring::inspect_push;

fn production() -> MapConfig {
    MapConfig::from_pairs([
        ("ENV", "production"),
        ("NOTIFICATIONS_AUTH_ISSUER", "https://auth.example.test"),
        ("NOTIFICATIONS_AUTH_CLIENT_ID", "client-x"),
    ])
}

#[test]
fn the_real_probe_refuses_a_production_deployment_with_no_transport() {
    let module = Notifications::new()
        .categories(["booking"])
        .transport_probe(|cfg| inspect_push(cfg).any_routed());
    let err = module
        .validate_config(&production())
        .expect_err("no transport is wired, so every send would dead-letter");
    assert!(err.to_string().contains("wired no push transport"), "{err}");
}

#[test]
fn the_same_module_without_the_probe_says_nothing_about_transports() {
    // A module that cannot see the environment must not guess. The check
    // is the venture's to enable, and `fz doctor` is the other half.
    Notifications::new()
        .categories(["booking"])
        .validate_config(&production())
        .expect("auth is configured and nothing else is claimed");
}

#[test]
fn a_category_opted_into_email_refuses_production_with_no_mailer() {
    // Every one of those notifications would dead-letter as
    // `not_configured`, which is the failure that looks like nothing
    // happening at all.
    let module = Notifications::new()
        .category(Category::new("booking").email(true))
        .mailer_probe(|cfg| cfg.get("RESEND_API_KEY").is_some());
    let err = module
        .validate_config(&production())
        .expect_err("a category asks for email and no mailer is wired");
    assert!(err.to_string().contains("wired no Mailer port"), "{err}");
    assert!(err.to_string().contains("booking"), "and names it: {err}");
}

#[test]
fn a_venture_with_no_email_category_does_not_need_a_mailer() {
    // The check is about what the venture actually asked to send.
    Notifications::new()
        .category(Category::new("booking"))
        .mailer_probe(|_| false)
        .validate_config(&production())
        .expect("no category asks for email, so no mailer is needed");
}

#[test]
fn a_wired_mailer_satisfies_an_email_category() {
    let config = MapConfig::from_pairs([
        ("ENV", "production"),
        ("NOTIFICATIONS_AUTH_ISSUER", "https://auth.example.test"),
        ("NOTIFICATIONS_AUTH_CLIENT_ID", "client-x"),
        ("RESEND_API_KEY", "re_test"),
    ]);
    Notifications::new()
        .category(Category::new("booking").email(true))
        .mailer_probe(|cfg| cfg.get("RESEND_API_KEY").is_some())
        .validate_config(&config)
        .expect("the mailer is wired");
}
