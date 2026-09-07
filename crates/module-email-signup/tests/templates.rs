//! Issue #12 acceptance for `email-signup`: askama snapshot tests per
//! template, links equal between text and html, and `<script>` escaping.

use cratefield_core::{Brand, Rendered};
use cratefield_module_email_signup::{ConfirmMailData, WelcomeMailData, default_templates};
use serde_json::json;

fn render(id: &str, data: &serde_json::Value) -> Rendered {
    default_templates()
        .into_iter()
        .find(|(template_id, _)| template_id == id)
        .unwrap_or_else(|| panic!("{id} registered"))
        .1
        .render(data, "en")
        .expect("renders")
}

fn sample_brand() -> Brand {
    Brand {
        accent: "#FF5A36".to_owned(),
        logo_url: Some("https://factory0.ventures/logo.png".to_owned()),
        footer: Some("Factory Zero · factory0.ventures".to_owned()),
    }
}

fn confirm_data() -> serde_json::Value {
    json!(ConfirmMailData {
        venture: "factory0".to_owned(),
        email: "nick@example.com".to_owned(),
        confirm_url: "https://api.factory0.ventures/v1/email-signup/confirm?token=abc".to_owned(),
        unsubscribe_url: "https://api.factory0.ventures/v1/email-signup/unsubscribe?token=def"
            .to_owned(),
        brand: sample_brand(),
    })
}

fn welcome_data() -> serde_json::Value {
    json!(WelcomeMailData {
        venture: "factory0".to_owned(),
        email: "nick@example.com".to_owned(),
        unsubscribe_url: "https://api.factory0.ventures/v1/email-signup/unsubscribe?token=def"
            .to_owned(),
        brand: sample_brand(),
    })
}

fn links_from_text(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| line.starts_with("https://"))
        .collect()
}

fn hrefs_from_html(html: &str) -> Vec<String> {
    html.split("href=\"")
        .skip(1)
        .map(|rest| rest.split('"').next().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn confirm_template_snapshots() {
    let rendered = render("email-signup/confirm", &confirm_data());
    insta::assert_snapshot!("confirm_subject", rendered.subject);
    insta::assert_snapshot!("confirm_html", rendered.html);
    insta::assert_snapshot!("confirm_text", rendered.text);
}

#[test]
fn welcome_template_snapshots() {
    let rendered = render("email-signup/welcome", &welcome_data());
    insta::assert_snapshot!("welcome_subject", rendered.subject);
    insta::assert_snapshot!("welcome_html", rendered.html);
    insta::assert_snapshot!("welcome_text", rendered.text);
}

#[test]
fn text_links_equal_html_links() {
    // The button repeats the confirm link in html; compare link *sets*.
    let sets_equal = |rendered: &Rendered| {
        let text_links: std::collections::BTreeSet<String> = links_from_text(&rendered.text)
            .into_iter()
            .map(str::to_owned)
            .collect();
        let html_links: std::collections::BTreeSet<String> =
            hrefs_from_html(&rendered.html).into_iter().collect();
        text_links == html_links
    };
    let confirm = render("email-signup/confirm", &confirm_data());
    assert!(
        sets_equal(&confirm),
        "confirm: same link set in text and html"
    );
    let welcome = render("email-signup/welcome", &welcome_data());
    assert!(
        sets_equal(&welcome),
        "welcome: same link set in text and html"
    );
}

#[test]
fn script_in_email_is_escaped() {
    let mut data = confirm_data();
    data["email"] = json!("<script>alert('x')</script>@example.com");
    let rendered = render("email-signup/confirm", &data);
    assert!(
        !rendered.html.contains("<script>"),
        "raw <script> must not survive: {}",
        rendered.html
    );
    // askama escapes to numeric character references (&#60;script&#62;).
    assert!(
        rendered.html.contains("&#60;script") || rendered.html.contains("&lt;script"),
        "escaped form present: {}",
        rendered.html
    );
    assert!(rendered.text.contains("<script>alert"), "text stays raw");
}

#[test]
fn defaults_render_without_a_registry() {
    // The fallback path: registry misses, module renders its compiled
    // default directly (conformance kit registers nothing).
    let registry = cratefield_core::TemplateRegistry::new();
    let err = registry
        .render("email-signup/confirm", &confirm_data(), "en")
        .expect_err("registry is empty");
    assert!(matches!(
        err,
        cratefield_core::TemplateError::UnknownTemplate { .. }
    ));
    let rendered = render("email-signup/confirm", &confirm_data());
    assert!(rendered.subject.contains("factory0"));
}
