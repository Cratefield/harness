//! `TemplateRegistry` tests (issue #4): override precedence, locale
//! fallback, unknown ids.

use factory0_core::{Harness, Rendered, Template, TemplateError};

fn fixed(subject: &'static str) -> Box<dyn Template> {
    struct Fixed(&'static str);
    impl Template for Fixed {
        fn render(
            &self,
            _data: &serde_json::Value,
            _locale: &str,
        ) -> Result<Rendered, TemplateError> {
            Ok(Rendered {
                subject: self.0.to_string(),
                html: format!("<p>{}</p>", self.0),
                text: self.0.to_string(),
            })
        }
    }
    Box::new(Fixed(subject))
}

#[test]
fn override_wins_over_module_default() {
    let mut registry = factory0_core::TemplateRegistry::new();
    registry.register("email-signup/confirm", fixed("default subject"));
    registry.register("email-signup/confirm", fixed("venture override"));

    let rendered = registry
        .render("email-signup/confirm", &serde_json::json!({}), "en")
        .expect("renders");
    assert_eq!(rendered.subject, "venture override");
}

#[test]
fn builder_override_wins_when_registered_last() {
    let harness = Harness::builder()
        .venture(
            factory0_core::Venture::new("test-venture", "test.example")
                .cors_origins(["https://test.example"]),
        )
        .template("email-signup/confirm", fixed("module default"))
        .template("email-signup/confirm", fixed("venture override"))
        .build()
        .expect("harness builds");
    let rendered = harness
        .templates()
        .render("email-signup/confirm", &serde_json::json!({}), "en")
        .expect("renders");
    assert_eq!(rendered.subject, "venture override");
}

#[test]
fn locale_variant_tried_first_then_base() {
    let mut registry = factory0_core::TemplateRegistry::new();
    registry.register("email-signup/confirm", fixed("english subject"));
    registry.register("email-signup/confirm@de", fixed("deutscher betreff"));

    let de = registry
        .render("email-signup/confirm", &serde_json::json!({}), "de")
        .expect("renders");
    assert_eq!(de.subject, "deutscher betreff");

    let en = registry
        .render("email-signup/confirm", &serde_json::json!({}), "en")
        .expect("renders");
    assert_eq!(en.subject, "english subject");

    // Unknown locale falls back to the base id.
    let fr = registry
        .render("email-signup/confirm", &serde_json::json!({}), "fr")
        .expect("renders");
    assert_eq!(fr.subject, "english subject");
}

#[test]
fn unknown_template_is_an_error_naming_id_and_locale() {
    let registry = factory0_core::TemplateRegistry::new();
    let err = registry
        .render("email-signup/missing", &serde_json::json!({}), "de")
        .expect_err("must fail");
    match err {
        TemplateError::UnknownTemplate { id, locale } => {
            assert_eq!(id, "email-signup/missing");
            assert_eq!(locale, "de");
        }
        other @ TemplateError::RenderFailed { .. } => panic!("wrong error: {other}"),
    }
}

#[test]
fn contains_follows_locale_fallback() {
    let mut registry = factory0_core::TemplateRegistry::new();
    registry.register("email-signup/confirm@de", fixed("de"));
    assert!(registry.contains("email-signup/confirm", "de"));
    assert!(!registry.contains("email-signup/confirm", "en"));
}
