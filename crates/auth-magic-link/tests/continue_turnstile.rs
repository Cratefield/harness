//! The Continue screen's email form carries the Turnstile widget when the
//! instance has a captcha, and the widget's answer is what lets the mail go
//! out. Without the widget the form posts with no answer and is refused
//! silently, which is the failure this file pins down.

use async_trait::async_trait;
use cratefield_auth_core::{
    AuthCore, ClientRedirectUriRow, ClientRow, Redacted, insert_client, insert_redirect_uri,
};
use cratefield_auth_magic_link::MagicLink;
use cratefield_core::{Config, MailError, Mailer, MapConfig, Message, SendOutcome};
use cratefield_testing::{FakeCaptcha, TestHarness};
use http::{Method, Request, StatusCode, header};
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

const CLIENT: &str = "client-continue";
const REDIRECT: &str = "https://app.example.test/callback";
const SITE_KEY: &str = "0x4AAAAAAA-site-key";
const ANSWER: &str = "solved-by-the-widget";
const CHALLENGE: &str = "EPwQ4wOmdeLdRT_qVRLtHkGWqL8ZvH-U1vwEyhD6-So";

#[derive(Clone, Default)]
struct Outbox(Arc<RwLock<Vec<Message>>>);

#[async_trait]
impl Mailer for Outbox {
    async fn send(&self, message: Message) -> Result<SendOutcome, MailError> {
        self.0.write().expect("lock").push(message);
        Ok(SendOutcome::Sent {
            id: "test".to_owned(),
        })
    }
}

fn kit(captcha: bool) -> (TestHarness, Outbox) {
    kit_with_logo(captcha, None)
}

fn kit_with_logo(captcha: bool, logo: Option<&str>) -> (TestHarness, Outbox) {
    let mut pairs = vec![
        ("AUTH_CORE_LOGIN_METHODS", "magic-link,google".to_owned()),
        (
            "AUTH_MAGIC_LINK_PUBLIC_BASE",
            "https://auth.example.test".to_owned(),
        ),
        (
            "AUTH_MAGIC_LINK_MAIL_FROM",
            "sign-in@example.test".to_owned(),
        ),
        ("AUTH_MAGIC_LINK_ALLOW_REGISTRATION", "true".to_owned()),
    ];
    if captcha {
        pairs.push(("TURNSTILE_SITE_KEY", SITE_KEY.to_owned()));
    }
    if let Some(logo) = logo {
        pairs.push(("AUTH_BRAND_LOGO_URL", logo.to_owned()));
    }
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(
        pairs.into_iter().map(|(k, v)| (k.to_owned(), v)),
    ));
    let outbox = Outbox::default();
    let mailer = outbox.clone();
    let port: Option<Arc<FakeCaptcha>> =
        captcha.then(|| Arc::new(FakeCaptcha::with_tokens([ANSWER])));
    let harness = TestHarness::with_ports(
        vec![Box::new(AuthCore::new()), Box::new(MagicLink::new())],
        move |ports| {
            ports.mailer = Some(Arc::new(mailer));
            ports.rate_limiter =
                Some(Arc::new(cratefield_testing::FakeRateLimiter::always_allow()));
            ports.config = config;
            if let Some(port) = port {
                ports.captcha = Some(port);
            }
        },
    );
    (harness, outbox)
}

async fn seed_client(kit: &TestHarness) {
    insert_client(
        &*kit.db,
        &ClientRow {
            id: CLIENT.to_owned(),
            name: "Continue test app".to_owned(),
            secret_hash: Redacted("unused".to_owned()),
            previous_secret_hash: None,
            previous_hash_expires_at: None,
            kind: "public".to_owned(),
            status: "active".to_owned(),
            created_at: "2026-10-01T00:00:00Z".to_owned(),
        },
    )
    .await
    .expect("client");
    insert_redirect_uri(
        &*kit.db,
        &ClientRedirectUriRow {
            client_id: CLIENT.to_owned(),
            uri: REDIRECT.to_owned(),
        },
    )
    .await
    .expect("redirect uri");
}

fn return_to() -> String {
    format!(
        "/v1/auth-core/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256&scope=openid"
    )
}

async fn get_chooser(kit: &TestHarness) -> (StatusCode, Option<String>, String) {
    let request = Request::builder()
        .method(Method::GET)
        .uri(return_to())
        .body(axum::body::Body::empty())
        .expect("request");
    let response = kit.router.clone().oneshot(request).await.expect("answers");
    let status = response.status();
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    (status, csp, String::from_utf8_lossy(&bytes).to_string())
}

/// What the Continue form posts: the address, the path it returns to, and
/// (when the widget rendered) the answer the widget adds.
async fn post_email(kit: &TestHarness, answer: Option<&str>) -> StatusCode {
    let mut body = format!(
        "email=ada%40example.com&return_to={}",
        url::form_urlencoded::byte_serialize(return_to().as_bytes()).collect::<String>()
    );
    if let Some(answer) = answer {
        body = format!("{body}&cf-turnstile-response={answer}");
    }
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/auth-magic-link/start")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .expect("request");
    kit.router
        .clone()
        .oneshot(request)
        .await
        .expect("answers")
        .status()
}

#[pollster::test]
async fn the_chooser_renders_the_widget_inside_the_email_form_with_its_own_policy() {
    let (harness, _outbox) = kit(true);
    seed_client(&harness).await;
    let (status, csp, page) = get_chooser(&harness).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(&format!("data-sitekey=\"{SITE_KEY}\"")),
        "{page}"
    );
    assert!(
        page.contains("challenges.cloudflare.com/turnstile/v0/api.js"),
        "{page}"
    );
    // The widget sits in the email form, above the email button.
    let widget = page.find("class=\"cf-turnstile\"").expect("widget");
    let button = page.find("Email me a sign-in link").expect("button");
    let form_start = page.find("id=\"cf-continue\"").expect("form");
    assert!(
        form_start < widget && widget < button,
        "widget is outside the form"
    );
    let csp = csp.expect("the chooser answers with a policy when it carries the widget");
    assert!(csp.contains("https://challenges.cloudflare.com"), "{csp}");
    assert!(csp.contains("script-src 'self' 'unsafe-inline'"), "{csp}");
}

#[pollster::test]
async fn the_widgets_answer_lets_the_sign_in_mail_go_and_no_answer_does_not() {
    let (harness, outbox) = kit(true);
    seed_client(&harness).await;

    // No answer: the widget was not solved, so no mail is sent. The response
    // is the same one a sent mail gets, as the magic link always answers.
    let refused = post_email(&harness, None).await;
    assert_eq!(refused, StatusCode::ACCEPTED);
    assert!(
        outbox.0.read().expect("lock").is_empty(),
        "no mail without an answer"
    );

    // The widget's answer: the mail goes out.
    let sent = post_email(&harness, Some(ANSWER)).await;
    assert_eq!(sent, StatusCode::ACCEPTED);
    assert_eq!(
        outbox.0.read().expect("lock").len(),
        1,
        "the solved form sends the mail"
    );
}

#[pollster::test]
async fn an_instance_without_a_captcha_renders_no_widget_and_no_policy() {
    let (harness, _outbox) = kit(false);
    seed_client(&harness).await;
    let (status, csp, page) = get_chooser(&harness).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!page.contains("class=\"cf-turnstile\""), "{page}");
    assert!(!page.contains("challenges.cloudflare.com"), "{page}");
    assert!(
        !csp.unwrap_or_default()
            .contains("challenges.cloudflare.com"),
        "the widget's origin is only opened when there is a widget"
    );
}

#[pollster::test]
async fn the_policy_opens_the_logo_origin_for_images_and_nothing_more() {
    let logo = "https://factory0.ventures/assets/icon-512.png";
    let (harness, _outbox) = kit_with_logo(true, Some(logo));
    seed_client(&harness).await;
    let (_status, csp, _page) = get_chooser(&harness).await;
    let csp = csp.expect("a policy");
    assert!(
        csp.contains("img-src 'self' data: https://factory0.ventures;"),
        "{csp}"
    );
    assert!(!csp.contains("img-src *"), "{csp}");

    // The start page (a hosted page with the widget) gets the same origin.
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/auth-magic-link/start")
        .body(axum::body::Body::empty())
        .expect("request");
    let start = harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("answers");
    let start_csp = start
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .expect("a policy")
        .to_owned();
    assert!(
        start_csp.contains("img-src 'self' data: https://factory0.ventures;"),
        "{start_csp}"
    );

    // Without a logo the policy is exactly the one it was: images from self only.
    let (plain, _outbox) = kit_with_logo(true, None);
    seed_client(&plain).await;
    let (_status, plain_csp, _page) = get_chooser(&plain).await;
    let plain_csp = plain_csp.expect("a policy");
    assert!(plain_csp.contains("img-src 'self' data:;"), "{plain_csp}");
    assert!(!plain_csp.contains("factory0"), "{plain_csp}");
}
