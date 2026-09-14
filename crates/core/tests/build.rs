//! `Harness::build` failure modes (issue #2 acceptance): every mode, with
//! its message. All problems are reported together.

mod common;

use common::*;
use cratefield_core::{Harness, Venture};

fn failure_lines(builder: cratefield_core::HarnessBuilder) -> Vec<String> {
    builder.build().expect_err("build must fail").problems
}

#[test]
fn happy_path_builds() {
    harness_with_sample();
}

#[test]
fn missing_venture_is_reported() {
    let problems = failure_lines(
        Harness::builder()
            .module(SampleModule::default())
            .runtime(FakeRuntime(all_ports())),
    );
    assert!(problems.iter().any(|p| p.contains("missing venture")));
}

#[test]
fn invalid_venture_name_is_reported() {
    let problems =
        failure_lines(Harness::builder().venture(
            Venture::new("Not Kebab", "test.example").cors_origins(["https://test.example"]),
        ));
    assert!(problems.iter().any(|p| p.contains("kebab-case")));
}

#[test]
fn empty_domain_is_reported() {
    let problems = failure_lines(
        Harness::builder()
            .venture(Venture::new("test-venture", "").cors_origins(["https://test.example"])),
    );
    assert!(problems.iter().any(|p| p.contains("domain")));
}

#[test]
fn no_cors_origins_is_reported() {
    let problems =
        failure_lines(Harness::builder().venture(Venture::new("test-venture", "test.example")));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("at least one CORS origin"))
    );
}

#[test]
fn wildcard_cors_origin_is_reported() {
    let problems = failure_lines(
        Harness::builder()
            .venture(Venture::new("test-venture", "test.example").cors_origins(["*"])),
    );
    assert!(problems.iter().any(|p| p.contains("wildcard")));
}

#[test]
fn duplicate_module_names_are_reported() {
    let problems = failure_lines(
        Harness::builder()
            .venture(base_venture())
            .module(SampleModule::default())
            .module(SampleModule::default())
            .runtime(FakeRuntime(all_ports())),
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("duplicate module name `sample`")),
        "problems: {problems:?}"
    );
}

#[test]
fn duplicate_tables_are_reported_with_both_owners() {
    let problems = failure_lines(
        Harness::builder()
            .venture(base_venture())
            .module(SampleModule {
                tables: &["subscribers"],
                ..SampleModule::default()
            })
            .module(SampleModule {
                tables: &["subscribers"],
                ..SampleModule::default()
            })
            .runtime(FakeRuntime(all_ports())),
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("duplicate table `subscribers`") && p.contains("sample")),
        "problems: {problems:?}"
    );
}

#[test]
fn harness_api_mismatch_is_reported() {
    // Issue #17 acceptance: a module targeting harness API 2 fails at
    // build with the full message — module, both versions, both APIs and
    // the core crate. (HARNESS_API is 1 today.)
    let problems = failure_lines(
        Harness::builder()
            .venture(base_venture())
            .module(SampleModule {
                harness_api: 2,
                ..SampleModule::default()
            })
            .runtime(FakeRuntime(all_ports())),
    );
    // The fixture's version is core's own package version.
    let expected = format!(
        "module `sample` v{v} targets harness API 2, but cratefield-core v{v} provides harness \
         API 1: rebuild `sample` against this core — the supported ranges are in \
         docs/COMPATIBILITY.md",
        v = env!("CARGO_PKG_VERSION")
    );
    assert_eq!(problems, vec![expected], "exact message required");
}

#[test]
fn port_in_both_requires_and_optional_is_reported() {
    let problems = failure_lines(
        Harness::builder()
            .venture(base_venture())
            .module(SampleModule {
                requires: &[cratefield_core::Port::Db],
                optional: &[cratefield_core::Port::Db],
                ..SampleModule::default()
            })
            .runtime(FakeRuntime(all_ports())),
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("in both requires() and optional()") && p.contains("Database")),
        "problems: {problems:?}"
    );
}

#[test]
fn required_port_not_provided_is_reported() {
    let problems = failure_lines(
        Harness::builder()
            .venture(base_venture())
            .module(SampleModule {
                requires: &[cratefield_core::Port::Db],
                ..SampleModule::default()
            })
            .runtime(FakeRuntime(vec![cratefield_core::Port::Mailer])),
    );
    assert!(
        problems.iter().any(|p| p
            .contains("requires port Database which the runtime does not provide")
            && p.contains("sample")),
        "problems: {problems:?}"
    );
}

#[test]
fn a_module_that_must_know_who_is_calling_will_not_boot_without_the_auth_port() {
    // The guarantee the `Auth` port exists for (issue #153). A venture
    // declaring a table whose access is `owner` composes a module that
    // requires this port; a deployment with no verifier must refuse to
    // start rather than mount that table and serve it to everyone.
    let problems = failure_lines(
        Harness::builder()
            .venture(base_venture())
            .module(SampleModule {
                requires: &[cratefield_core::Port::Auth],
                ..SampleModule::default()
            })
            .runtime(FakeRuntime(vec![cratefield_core::Port::Db])),
    );
    assert!(
        problems.iter().any(|p| p
            .contains("requires port Auth which the runtime does not provide")
            && p.contains("sample")),
        "problems: {problems:?}"
    );
}

/// A surface whose action sits under `/admin/` with `audience`.
fn under_admin(audience: cratefield_core::Audience) -> cratefield_core::Surface {
    cratefield_core::Surface::new().action(
        cratefield_core::Action::new("peek", http::Method::GET, "/admin/peek")
            .audience(audience)
            .outcome(cratefield_core::Outcome::Json),
    )
}

#[test]
fn an_action_under_admin_whose_audience_is_not_admin_is_reported() {
    // The rule had no test at all — not for `Public`, not for `Link`, and
    // not for `Subject` when that was added. A published action under
    // `/admin/` that the admin gate does not guard is a route the surface
    // advertises as reachable and the router refuses, or worse.
    for audience in [
        cratefield_core::Audience::Public,
        cratefield_core::Audience::Link,
        cratefield_core::Audience::Subject,
    ] {
        let problems = failure_lines(
            Harness::builder()
                .venture(base_venture())
                .module(SampleModule {
                    surface: Some(match audience {
                        cratefield_core::Audience::Public => {
                            || under_admin(cratefield_core::Audience::Public)
                        }
                        cratefield_core::Audience::Link => {
                            || under_admin(cratefield_core::Audience::Link)
                        }
                        _ => || under_admin(cratefield_core::Audience::Subject),
                    }),
                    ..SampleModule::default()
                })
                .runtime(FakeRuntime(all_ports())),
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("is under /admin/ but its audience is not admin")),
            "{audience:?}: {problems:?}"
        );
    }
}

#[test]
fn an_admin_action_that_is_not_under_admin_is_reported() {
    let problems = failure_lines(
        Harness::builder()
            .venture(base_venture())
            .module(SampleModule {
                surface: Some(|| {
                    cratefield_core::Surface::new().action(
                        cratefield_core::Action::new("peek", http::Method::GET, "/peek")
                            .audience(cratefield_core::Audience::Admin)
                            .outcome(cratefield_core::Outcome::Json),
                    )
                }),
                ..SampleModule::default()
            })
            .runtime(FakeRuntime(all_ports())),
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("is admin but its path") && p.contains("/peek")),
        "{problems:?}"
    );
}

#[test]
fn template_override_naming_unknown_module_is_reported() {
    let problems = failure_lines(
        Harness::builder()
            .venture(base_venture())
            .module(SampleModule::default())
            .runtime(FakeRuntime(all_ports()))
            .template("nope/confirm", Box::new(StaticTemplate)),
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("template `nope/confirm` names module `nope`")),
        "problems: {problems:?}"
    );
}

#[test]
fn all_problems_reported_together() {
    static REQUIRES_DB: [cratefield_core::Port; 1] = [cratefield_core::Port::Db];
    let problems = failure_lines(
        Harness::builder()
            .venture(Venture::new("Bad Name", ""))
            .module(SampleModule {
                harness_api: cratefield_core::HARNESS_API + 1,
                tables: &["t"],
                ..SampleModule::default()
            })
            .module(SampleModule {
                tables: &["t"],
                requires: &REQUIRES_DB,
                ..SampleModule::default()
            }),
    );
    let joined = problems.join("\n");
    assert!(joined.contains("kebab-case"));
    assert!(joined.contains("domain"));
    assert!(joined.contains("harness API"));
    assert!(joined.contains("duplicate table"));
    assert!(
        joined.contains("does not provide"),
        "runtime absent should flag required ports: {joined}"
    );
}

struct StaticTemplate;

impl cratefield_core::Template for StaticTemplate {
    fn render(
        &self,
        _data: &serde_json::Value,
        _locale: &str,
    ) -> Result<cratefield_core::Rendered, cratefield_core::TemplateError> {
        Ok(cratefield_core::Rendered {
            subject: "s".to_string(),
            html: "h".to_string(),
            text: "t".to_string(),
        })
    }
}
