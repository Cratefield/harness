//! `UiSpec` applied end to end (issue #75): copy, order, hidden fields,
//! landing pages, the theme stylesheet, `spec.json`, the surface's `ui`
//! entry, and every way a bad spec fails loudly.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use cratefield_core::MapConfig;
use cratefield_module_waitlist::Waitlist;
use cratefield_testing::TestHarness;
use cratefield_ui::{Ui, UiSpec};
use tower::ServiceExt;

const SPEC: &str = r##"{
  "version": 1,
  "theme": { "tokens": { "--cf-accent": "#0a7", "--cf-radius": "0" }, "css_url": "https://cdn.test.example/theme.css" },
  "modules": {
    "waitlist": {
      "title": "The list",
      "actions": {
        "join": {
          "title": "Get on the list",
          "intro": "We open the doors in small batches.",
          "submit": "Count me in",
          "success": "You're on the list. Check your inbox.",
          "fields": {
            "email": { "label": "Your email", "placeholder": "ada@lovelace.example", "help": "We never share it." },
            "product": { "hidden": true }
          },
          "order": ["product", "email"]
        },
        "confirm": {
          "pages": { "done": { "title": "You're in", "message": "Welcome aboard." } }
        }
      }
    }
  }
}"##;

fn kit(ui: Ui, runtime_spec: Option<&'static str>) -> TestHarness {
    TestHarness::with_builder(
        vec![Box::new(
            Waitlist::new().products(["kontinuum", "undercover"]),
        )],
        move |builder| builder.ui(ui),
        move |ports| {
            let mut pairs = vec![("HARNESS_SECRET", cratefield_testing::TEST_HARNESS_SECRET)];
            if let Some(spec) = runtime_spec {
                pairs.push(("UI_SPEC", spec));
            }
            ports.config = Arc::new(MapConfig::from_pairs(pairs));
        },
    )
}

async fn get(kit: &TestHarness, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = kit
        .router
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    (
        parts.status,
        parts.headers,
        String::from_utf8(bytes.to_vec()).unwrap(),
    )
}

async fn post(kit: &TestHarness, uri: &str, form: &str) -> (StatusCode, String) {
    let response = kit
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    (parts.status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[pollster::test]
async fn spec_copy_order_and_hidden_apply_to_the_form() {
    let kit = kit(Ui::from_spec(SPEC).unwrap(), None);
    let (status, headers, html) = get(&kit, "/ui/waitlist/join").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("<title>Get on the list · test-venture</title>"),
        "{html}"
    );
    assert!(html.contains(r#"<p class="cf-intro">We open the doors in small batches.</p>"#));
    assert!(html.contains(r#"<button class="cf-submit" type="submit">Count me in</button>"#));
    assert!(html.contains(r#"Your email<span class="cf-required""#));
    assert!(html.contains(r#"placeholder="ada@lovelace.example""#));
    assert!(html.contains(r#"<p class="cf-help">We never share it.</p>"#));
    assert!(!html.contains("<select"), "product hidden by the spec");
    // Theme: tokens stylesheet linked after cf.css, then the spec's URL.
    let css = html.find(r#"href="/ui/cf.css""#).unwrap();
    let tokens = html.find(r#"href="/ui/theme.css""#).unwrap();
    let theme = html
        .find(r#"href="https://cdn.test.example/theme.css""#)
        .unwrap();
    assert!(css < tokens && tokens < theme);
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        csp.contains("style-src 'self' https://cdn.test.example;"),
        "{csp}"
    );

    // Order: with `product` first and hidden (no value), email is the only
    // control; give product a value and the hidden input comes first.
    let (_, _, html) = get(&kit, "/ui/waitlist/join?fragment=1&product=kontinuum").await;
    let hidden = html.find(r#"name="product""#).unwrap();
    let email = html.find(r#"name="email""#).unwrap();
    assert!(
        hidden < email,
        "spec order puts product before email: {html}"
    );
}

#[pollster::test]
async fn spec_success_and_landing_copy_apply() {
    let kit = kit(Ui::from_spec(SPEC).unwrap(), None);
    let (status, html) = post(
        &kit,
        "/ui/waitlist/join?fragment=1",
        "email=ada%40example.com&product=kontinuum&cf-turnstile-response=tok",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(
        html.contains("You&#39;re on the list. Check your inbox.")
            || html.contains("You're on the list. Check your inbox."),
        "{html}"
    );
    let (_, _, done) = get(&kit, "/ui/waitlist/confirm/done?fragment=1").await;
    assert!(
        done.contains(r#"<h2 class="cf-notice-title">You&#39;re in</h2>"#)
            || done.contains("You're in"),
        "{done}"
    );
    assert!(done.contains("Welcome aboard."));
    // A page the spec does not name keeps the default.
    let (_, _, expired) = get(&kit, "/ui/waitlist/confirm/expired?fragment=1").await;
    assert!(expired.contains("Link expired"));
}

#[pollster::test]
async fn theme_css_and_spec_json_are_served_and_the_surface_carries_the_spec() {
    let kit = kit(Ui::from_spec(SPEC).unwrap(), None);
    let (status, headers, css) = get(&kit, "/ui/theme.css").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/css")
    );
    assert_eq!(css, ":root {\n  --cf-accent: #0a7;\n  --cf-radius: 0;\n}\n");
    let (status, _, json) = get(&kit, "/ui/spec.json").await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["modules"]["waitlist"]["actions"]["join"]["submit"],
        "Count me in"
    );
    let (_, _, surface) = get(&kit, "/__surface").await;
    let surface: serde_json::Value = serde_json::from_str(&surface).unwrap();
    assert_eq!(surface["ui"]["theme"]["tokens"]["--cf-accent"], "#0a7");
}

#[pollster::test]
async fn no_spec_means_no_theme_and_no_ui_entry() {
    let kit = kit(Ui::new(), None);
    let (_, _, html) = get(&kit, "/ui/waitlist/join").await;
    assert!(!html.contains("theme.css"));
    let (_, _, css) = get(&kit, "/ui/theme.css").await;
    assert!(css.is_empty());
    let (_, _, surface) = get(&kit, "/__surface").await;
    assert!(!surface.contains("\"ui\""));
}

#[test]
fn unknown_references_fail_the_build_with_their_path() {
    let bad = r##"{"modules":{"waitlist":{"actions":{"join":{"fields":{"emial":{"label":"x"}},"order":["nope"],"pages":{"later":{}}},"leave":{}}},"ghost":{}},"theme":{"tokens":{"accent":"#000"},"css_url":"http://plain.example/x.css"}}"##;
    let ui = Ui::from_spec(bad).unwrap();
    let err = cratefield_core::Harness::builder()
        .venture(cratefield_core::Venture::new("v", "v.test"))
        .module(Waitlist::new().products(["kontinuum"]))
        .ui(ui)
        .runtime(NoRuntime)
        .build()
        .expect_err("must fail");
    let text = err.to_string();
    for needle in [
        "modules.waitlist.actions.join.fields.emial: action `join` has no field with that name (it has: email, product, ref, answers, locale, captchaToken)",
        "modules.waitlist.actions.join.order: `nope` is not a field of `join`",
        "modules.waitlist.actions.join.pages.later: landing pages are `done` and `expired`",
        "modules.waitlist.actions.leave: module `waitlist` declares no such action",
        "modules.ghost: no module with that name declares a surface",
        "theme.tokens.accent: custom property names must start with --cf-",
        "theme.css_url: \"http://plain.example/x.css\" must be an https:// URL",
    ] {
        assert!(text.contains(needle), "missing `{needle}` in:\n{text}");
    }
    assert!(UiSpec::parse(r#"{"modules":{"waitlist":{"colour":1}}}"#).is_err());
}

struct NoRuntime;
impl cratefield_core::Runtime for NoRuntime {
    fn provides(&self) -> Vec<cratefield_core::Port> {
        cratefield_core::Port::ALL.to_vec()
    }
}

#[pollster::test]
async fn a_valid_runtime_spec_replaces_the_builder_spec() {
    let kit = kit(
        Ui::from_spec(SPEC).unwrap(),
        Some(r#"{"modules":{"waitlist":{"actions":{"join":{"submit":"Runtime wins"}}}}}"#),
    );
    let (_, _, html) = get(&kit, "/ui/waitlist/join?fragment=1").await;
    assert!(html.contains(">Runtime wins</button>"), "{html}");
    assert!(!html.contains("Count me in"));
}

#[pollster::test]
async fn a_broken_runtime_spec_disables_ui_loudly() {
    let kit = kit(
        Ui::new(),
        Some(r#"{"modules":{"waitlist":{"actions":{"nope":{}}}}}"#),
    );
    let (status, headers, body) = get(&kit, "/ui/waitlist/join").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    assert!(body.contains("modules.waitlist.actions.nope"), "{body}");
    // The API is untouched.
    let (status, _, _) = get(&kit, "/__health").await;
    assert_eq!(status, StatusCode::OK);
}
