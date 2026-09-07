//! Issue #12 acceptance for `waitlist`: askama snapshot tests per
//! template, links equal between text and html, and `<script>` escaping.

use cratefield_core::{Brand, Rendered};
use cratefield_module_waitlist::{ConfirmMailData, ConfirmedMailData, default_templates};
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
        product: "kontinuum".to_owned(),
        email: "nick@example.com".to_owned(),
        confirm_url: "https://api.factory0.ventures/v1/waitlist/confirm?token=abc".to_owned(),
        brand: sample_brand(),
    })
}

fn confirmed_data() -> serde_json::Value {
    json!(ConfirmedMailData {
        venture: "factory0".to_owned(),
        product: "kontinuum".to_owned(),
        email: "nick@example.com".to_owned(),
        position: 42,
        status_url: "https://api.factory0.ventures/v1/waitlist/status?token=def".to_owned(),
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
    let rendered = render("waitlist/confirm", &confirm_data());
    insta::assert_snapshot!("confirm_subject", rendered.subject);
    insta::assert_snapshot!("confirm_html", rendered.html);
    insta::assert_snapshot!("confirm_text", rendered.text);
}

#[test]
fn confirmed_template_snapshots() {
    let rendered = render("waitlist/confirmed", &confirmed_data());
    insta::assert_snapshot!("confirmed_subject", rendered.subject);
    insta::assert_snapshot!("confirmed_html", rendered.html);
    insta::assert_snapshot!("confirmed_text", rendered.text);
}

#[test]
fn text_links_equal_html_links() {
    for id in ["waitlist/confirm", "waitlist/confirmed"] {
        let data = if id.ends_with("confirm") && !id.ends_with("confirmed") {
            confirm_data()
        } else {
            confirmed_data()
        };
        let rendered = render(id, &data);
        let text_links: std::collections::BTreeSet<String> = links_from_text(&rendered.text)
            .into_iter()
            .map(str::to_owned)
            .collect();
        let html_links: std::collections::BTreeSet<String> =
            hrefs_from_html(&rendered.html).into_iter().collect();
        assert_eq!(text_links, html_links, "{id}: same link set");
    }
}

#[test]
fn script_in_email_is_escaped() {
    let mut data = confirm_data();
    data["email"] = json!("<script>alert('x')</script>@example.com");
    let rendered = render("waitlist/confirm", &data);
    assert!(
        !rendered.html.contains("<script>"),
        "raw <script> must not survive"
    );
    // askama escapes to numeric character references (&#60;script&#62;).
    assert!(
        rendered.html.contains("&#60;script") || rendered.html.contains("&lt;script"),
        "escaped form present: {}",
        rendered.html
    );
}
