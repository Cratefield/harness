//! The renderer against the real waitlist module (ADR 0010, issue #72):
//! form pages and fragments, in-process dispatch of a submit, errors on
//! their fields, status and signed-link passthrough, landing pages, and
//! the markup contract snapshot.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use factory0_module_waitlist::Waitlist;
use factory0_testing::TestHarness;
use factory0_ui::Ui;
use tower::ServiceExt;

fn kit() -> TestHarness {
    TestHarness::with_builder(
        vec![Box::new(
            Waitlist::new().products(["kontinuum", "undercover"]),
        )],
        |builder| builder.ui(Ui::new().theme_css("https://cdn.test.example/theme.css")),
        |ports| {
            ports.config = Arc::new(factory0_core::MapConfig::from_pairs([
                ("HARNESS_SECRET", factory0_testing::TEST_HARNESS_SECRET),
                ("TURNSTILE_SITE_KEY", "0x4AAAAAAA-site"),
            ]));
        },
    )
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

async fn send(kit: &TestHarness, method: Method, uri: &str, form: Option<&str>) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cf-connecting-ip", "203.0.113.7");
    let body = match form {
        Some(form) => {
            builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(form.to_owned())
        }
        None => Body::empty(),
    };
    let response = kit
        .router
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

#[pollster::test]
async fn form_page_renders_fields_in_order_with_csp_and_captcha() {
    let kit = kit();
    let reply = send(&kit, Method::GET, "/ui/waitlist/join", None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply
            .headers
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let csp = reply
        .headers
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        csp.contains("script-src https://challenges.cloudflare.com;"),
        "{csp}"
    );
    assert!(
        csp.contains("style-src 'self' https://cdn.test.example;"),
        "{csp}"
    );
    let html = &reply.body;
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("<title>Join · test-venture</title>"));
    assert!(html.contains(r#"<link rel="stylesheet" href="/ui/cf.css">"#));
    assert!(html.contains(r#"href="https://cdn.test.example/theme.css""#));
    assert!(html.contains("challenges.cloudflare.com/turnstile/v0/api.js"));
    assert!(html.contains(r#"<form class="cf-form" data-cf-module="waitlist" data-cf-action="join" method="post" action="/ui/waitlist/join" novalidate>"#));
    let email = html.find(r#"data-cf-field="email""#).unwrap();
    let product = html.find(r#"data-cf-field="product""#).unwrap();
    assert!(email < product, "fields keep struct order");
    assert!(html.contains(r#"<option value="kontinuum">Kontinuum</option>"#));
    assert!(html.contains(r#"class="cf-turnstile" data-sitekey="0x4AAAAAAA-site""#));
    assert!(
        !html.contains(r#"name="captchaToken""#),
        "hidden fields without a value are omitted"
    );
    // Turnstile's is the only script tag on the page: none of ours.
    assert_eq!(html.matches("<script").count(), 1);
    assert_eq!(html.matches("turnstile/v0/api.js").count(), 1);
}

#[pollster::test]
async fn fragment_prefills_and_hides_from_the_query() {
    let kit = kit();
    let reply = send(
        &kit,
        Method::GET,
        "/ui/waitlist/join?fragment=1&product=kontinuum&ref=ABCD1234",
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply.headers.get(header::CONTENT_SECURITY_POLICY).is_none(),
        "fragments carry no CSP"
    );
    let html = &reply.body;
    assert!(!html.contains("<!DOCTYPE"));
    assert!(html.starts_with(r#"<form class="cf-form""#));
    assert!(html.contains(r#"<option value="kontinuum" selected>Kontinuum</option>"#));
    assert!(html.contains(r#"<input type="hidden" name="ref" value="ABCD1234">"#));

    // `hide=` (what the embed sends for attribute-supplied fields) turns
    // the pre-filled control into a hidden input, on GET and on the
    // re-render after a failed POST.
    let hidden = send(
        &kit,
        Method::GET,
        "/ui/waitlist/join?fragment=1&product=kontinuum&hide=product",
        None,
    )
    .await;
    assert!(!hidden.body.contains("<select"), "{}", hidden.body);
    assert!(
        hidden
            .body
            .contains(r#"<input type="hidden" name="product" value="kontinuum">"#)
    );
    let failed = send(
        &kit,
        Method::POST,
        "/ui/waitlist/join?fragment=1&hide=product",
        Some("email=bad&product=kontinuum&cf-turnstile-response=tok"),
    )
    .await;
    assert_eq!(failed.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!failed.body.contains("<select"));
    assert!(
        failed
            .body
            .contains(r#"<input type="hidden" name="product" value="kontinuum">"#)
    );
}

#[pollster::test]
async fn submit_dispatches_in_process_and_renders_the_notice() {
    let kit = kit();
    let reply = send(
        &kit,
        Method::POST,
        "/ui/waitlist/join",
        Some("email=ada%40example.com&product=kontinuum&cf-turnstile-response=tok"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(
        reply.headers.get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert!(reply.body.contains(r#"<div class="cf-notice cf-notice--success" data-cf-module="waitlist" data-cf-action="join" role="status">"#));
    assert!(
        reply
            .body
            .contains("Check your inbox to confirm your spot.")
    );
    // The module ran: it sent the confirmation mail through the fake.
    let mail = kit.mailer.last_message().expect("confirmation mail sent");
    assert_eq!(mail.to, "ada@example.com");
}

#[pollster::test]
async fn invalid_email_re_renders_the_form_with_the_error_on_its_field() {
    let kit = kit();
    let reply = send(
        &kit,
        Method::POST,
        "/ui/waitlist/join?fragment=1",
        Some("email=not-an-email&product=kontinuum&cf-turnstile-response=tok"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    let html = &reply.body;
    assert!(
        html.contains(r#"<div class="cf-field cf-field--invalid" data-cf-field="email">"#),
        "{html}"
    );
    assert!(html.contains(r#"value="not-an-email""#), "value preserved");
    assert!(
        html.contains(r#"<p class="cf-error" role="alert">email must contain exactly one @</p>"#),
        "{html}"
    );
    assert!(
        !html.contains(r#"name="captchaToken""#),
        "a used captcha token is never re-posted"
    );
    assert!(
        html.contains(r#"<option value="kontinuum" selected>"#),
        "select preserved"
    );
    assert!(kit.mailer.last_message().is_none());
}

#[pollster::test]
async fn unknown_product_attributes_by_slug() {
    let kit = kit();
    let reply = send(
        &kit,
        Method::POST,
        "/ui/waitlist/join?fragment=1",
        Some("email=ada%40example.com&product=nope&cf-turnstile-response=tok"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        reply
            .body
            .contains(r#"<div class="cf-field cf-field--invalid" data-cf-field="product">"#),
        "{}",
        reply.body
    );
}

#[pollster::test]
async fn signed_link_redirect_passes_through_and_status_renders_a_list() {
    let kit = kit();
    // Join, then take the confirm link out of the mail like a person would.
    let _ = send(
        &kit,
        Method::POST,
        "/ui/waitlist/join",
        Some("email=ada%40example.com&product=kontinuum&cf-turnstile-response=tok"),
    )
    .await;
    let mail = kit.mailer.last_message().expect("mail");
    let text = format!("{}\n{}", mail.text, mail.html);
    let start = text
        .find("/v1/waitlist/confirm?token=")
        .expect("confirm link in mail");
    let token: String = text[start + "/v1/waitlist/confirm?token=".len()..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
        .collect();

    let confirm = send(
        &kit,
        Method::GET,
        &format!("/ui/waitlist/confirm?token={token}"),
        None,
    )
    .await;
    assert_eq!(confirm.status, StatusCode::SEE_OTHER, "{}", confirm.body);
    let location = confirm
        .headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        location.contains("/ui/waitlist/status?token="),
        "UI mounted: status lands on the UI page, got {location}"
    );

    let status_token = location.rsplit("token=").next().unwrap().to_owned();
    let status = send(
        &kit,
        Method::GET,
        &format!("/ui/waitlist/status?token={status_token}"),
        None,
    )
    .await;
    assert_eq!(status.status, StatusCode::OK, "{}", status.body);
    assert!(
        status.body.contains(
            r#"<dl class="cf-status" data-cf-module="waitlist" data-cf-action="status">"#
        )
    );
    assert!(status.body.contains(r#"data-cf-field="position""#));
    assert!(
        status.body.contains(
            r#"<dt class="cf-status-key">Position</dt><dd class="cf-status-value">1</dd>"#
        ),
        "{}",
        status.body
    );
}

#[pollster::test]
async fn landing_pages_and_not_found() {
    let kit = kit();
    let done = send(&kit, Method::GET, "/ui/waitlist/confirm/done", None).await;
    assert_eq!(done.status, StatusCode::OK);
    assert!(done.body.contains("cf-notice--success"));
    assert!(done.body.contains("Your email address is confirmed."));
    let expired = send(
        &kit,
        Method::GET,
        "/ui/waitlist/confirm/expired?fragment=1",
        None,
    )
    .await;
    assert!(
        expired
            .body
            .starts_with(r#"<div class="cf-notice cf-notice--warning""#)
    );

    for uri in [
        "/ui/nope/join",
        "/ui/waitlist/nope",
        "/ui/waitlist/export",
        "/ui/waitlist/join/nope",
    ] {
        let reply = send(&kit, Method::GET, uri, None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(
            reply.headers.get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
    }
    let bad_form = send(&kit, Method::POST, "/ui/waitlist/status", Some("token=x")).await;
    assert_eq!(bad_form.status, StatusCode::NOT_FOUND);
}

#[pollster::test]
async fn assets_are_served_with_the_layer_contract() {
    let kit = kit();
    let css = send(&kit, Method::GET, "/ui/cf.css", None).await;
    assert_eq!(css.status, StatusCode::OK);
    assert!(
        css.headers
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/css")
    );
    assert!(css.body.trim_start().starts_with("/*"));
    assert!(css.body.contains("@layer cf {"));
    assert!(!css.body.contains("!important"));
    assert!(
        css.body.len() < 6144,
        "cf.css is {} bytes; keep it under 6 KB (about 1.5 KB gzipped)",
        css.body.len()
    );
    let js = send(&kit, Method::GET, "/ui/cf.js", None).await;
    assert_eq!(js.status, StatusCode::OK);
}

/// The markup contract. A class rename fails here first; update
/// `docs/UI.md` and the snapshot together, never one without the other.
#[pollster::test]
async fn form_fragment_matches_the_contract_snapshot() {
    let kit = kit();
    let reply = send(
        &kit,
        Method::GET,
        "/ui/waitlist/join?fragment=1&ref=R1",
        None,
    )
    .await;
    insta::assert_snapshot!("waitlist_join_fragment", reply.body);
    let failed = send(
        &kit,
        Method::POST,
        "/ui/waitlist/join?fragment=1",
        Some("email=bad&product=kontinuum&cf-turnstile-response=tok"),
    )
    .await;
    insta::assert_snapshot!("waitlist_join_fragment_invalid", failed.body);
}

#[pollster::test]
async fn email_signup_confirm_lands_on_the_ui_done_page() {
    let kit = TestHarness::with_builder(
        vec![Box::new(factory0_module_email_signup::EmailSignup::new())],
        |builder| builder.ui(Ui::new()),
        |ports| {
            ports.config = Arc::new(factory0_core::MapConfig::from_pairs([(
                "HARNESS_SECRET",
                factory0_testing::TEST_HARNESS_SECRET,
            )]));
        },
    );
    let reply = send(
        &kit,
        Method::POST,
        "/ui/email-signup/subscribe?fragment=1",
        Some("email=ada%40example.com&cf-turnstile-response=tok"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(reply.body.contains("Check your inbox"));
    let mail = kit.mailer.last_message().expect("confirmation mail");
    let text = format!("{}\n{}", mail.text, mail.html);
    let marker = "/v1/email-signup/confirm?token=";
    let start = text.find(marker).expect("confirm link");
    let token: String = text[start + marker.len()..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
        .collect();
    let confirm = send(
        &kit,
        Method::GET,
        &format!("/ui/email-signup/confirm?token={token}"),
        None,
    )
    .await;
    assert_eq!(confirm.status, StatusCode::SEE_OTHER);
    let location = confirm
        .headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        location,
        "https://api.test.example/ui/email-signup/confirm/done"
    );
    let done = send(&kit, Method::GET, "/ui/email-signup/confirm/done", None).await;
    assert!(done.body.contains("Your email address is confirmed."));
}

/// Render cost, for `docs/UI.md`: run with `--nocapture --ignored`.
#[pollster::test]
#[ignore = "timing, not a check"]
async fn render_timing() {
    let kit = kit();
    let rounds = 2000;
    let start = std::time::Instant::now();
    for _ in 0..rounds {
        let reply = send(&kit, Method::GET, "/ui/waitlist/join", None).await;
        assert_eq!(reply.status, StatusCode::OK);
    }
    let per = start.elapsed() / rounds;
    eprintln!("full page through the router: {per:?} per request");
    let start = std::time::Instant::now();
    for _ in 0..rounds {
        let reply = send(&kit, Method::GET, "/ui/waitlist/join?fragment=1", None).await;
        assert_eq!(reply.status, StatusCode::OK);
    }
    let per = start.elapsed() / rounds;
    eprintln!("fragment through the router: {per:?} per request");
}

/// `schemas/ui-spec-v1.schema.json` is generated from the `UiSpec` types
/// and committed. Run with `UPDATE_SCHEMAS=1` to regenerate; CI fails on
/// drift so the file is never hand-edited.
#[test]
fn ui_spec_schema_is_committed_and_current() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/ui-spec-v1.schema.json"
    );
    let generated = serde_json::to_string_pretty(&factory0_ui::UiSpec::schema()).unwrap() + "\n";
    if std::env::var("UPDATE_SCHEMAS").is_ok() {
        std::fs::write(path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(path).unwrap_or_default();
    assert_eq!(
        committed, generated,
        "schemas/ui-spec-v1.schema.json is stale: run UPDATE_SCHEMAS=1 cargo test -p factory0-ui"
    );
}
