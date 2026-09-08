//! The admin pages against the real modules (issue #74): login with the
//! token, the signed session cookie, the index, a table over the export,
//! the two-step delete, logout, and the switched-off state.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use cratefield_module_email_signup::EmailSignup;
use cratefield_module_waitlist::Waitlist;
use cratefield_testing::TestHarness;
use cratefield_ui::Ui;
use tower::ServiceExt;

const TOKEN: &str = "test-admin-token-with-enough-entropy";

fn kit(with_token: bool) -> TestHarness {
    TestHarness::with_builder(
        vec![
            Box::new(EmailSignup::new().double_opt_in(false)),
            Box::new(Waitlist::new().products(["kontinuum"])),
        ],
        |builder| builder.ui(Ui::new()),
        move |ports| {
            let mut pairs = vec![("HARNESS_SECRET", cratefield_testing::TEST_HARNESS_SECRET)];
            if with_token {
                pairs.push(("ADMIN_TOKEN", TOKEN));
            }
            ports.config = Arc::new(cratefield_core::MapConfig::from_pairs(pairs));
        },
    )
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Reply {
    fn header(&self, name: header::HeaderName) -> String {
        self.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default()
    }
}

async fn send(
    kit: &TestHarness,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    form: Option<&str>,
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "api.test.example")
        .header("cf-connecting-ip", "203.0.113.7");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
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

const ORIGIN: (&str, &str) = ("origin", "https://api.test.example");

/// Logs in and returns the `Cookie` header value to send back.
async fn login(kit: &TestHarness) -> String {
    let reply = send(
        kit,
        Method::POST,
        "/ui/admin/login",
        &[ORIGIN],
        Some(&format!("token={TOKEN}")),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.header(header::LOCATION), "/ui/admin");
    let set = reply.header(header::SET_COOKIE);
    for attr in [
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Path=/ui/admin",
        "Max-Age=43200",
    ] {
        assert!(set.contains(attr), "cookie lacks {attr}: {set}");
    }
    set.split(';').next().unwrap().to_owned()
}

#[pollster::test]
async fn unauthenticated_admin_pages_redirect_to_login() {
    let kit = kit(true);
    for uri in ["/ui/admin", "/ui/admin/waitlist/export"] {
        let reply = send(&kit, Method::GET, uri, &[], None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{uri}");
        assert_eq!(reply.header(header::LOCATION), "/ui/admin/login");
    }
    // A tampered cookie is no session either.
    let reply = send(
        &kit,
        Method::GET,
        "/ui/admin",
        &[("cookie", "cf_admin=eyJ.forged")],
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    // Posting an admin action without a session goes to login too.
    let reply = send(
        &kit,
        Method::POST,
        "/ui/admin/email-signup/delete",
        &[ORIGIN],
        Some("email=a%40b.co"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
}

#[pollster::test]
async fn login_form_and_failures() {
    let kit = kit(true);
    let page = send(&kit, Method::GET, "/ui/admin/login", &[], None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains(r#"<input class="cf-input" type="password" id="cf-admin-login-token" name="token" required autocomplete="off">"#), "{}", page.body);
    assert_eq!(page.header(header::CACHE_CONTROL), "private, no-store");
    assert_eq!(
        page.header(header::HeaderName::from_static("x-frame-options")),
        "DENY"
    );
    assert!(!page.body.contains("cf-logout"), "no nav before login");

    let wrong = send(
        &kit,
        Method::POST,
        "/ui/admin/login",
        &[ORIGIN],
        Some("token=nope"),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    assert!(
        wrong
            .body
            .contains(r#"cf-field--invalid" data-cf-field="token""#)
    );
    assert!(wrong.header(header::SET_COOKIE).is_empty());

    let cross = send(
        &kit,
        Method::POST,
        "/ui/admin/login",
        &[("origin", "https://evil.example")],
        Some(&format!("token={TOKEN}")),
    )
    .await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN);
    assert_eq!(
        cross.header(header::CONTENT_TYPE),
        "application/problem+json"
    );

    let no_origin = send(
        &kit,
        Method::POST,
        "/ui/admin/login",
        &[],
        Some(&format!("token={TOKEN}")),
    )
    .await;
    assert_eq!(no_origin.status, StatusCode::FORBIDDEN);
}

#[pollster::test]
async fn index_lists_tables_and_a_session_reaches_them() {
    let kit = kit(true);
    let cookie = login(&kit).await;
    let index = send(&kit, Method::GET, "/ui/admin", &[("cookie", &cookie)], None).await;
    assert_eq!(index.status, StatusCode::OK);
    assert!(
        index.body.contains(
            r#"<a class="cf-admin-link" href="/ui/admin/email-signup/export">Export table</a>"#
        ),
        "{}",
        index.body
    );
    assert!(index.body.contains(r#"href="/ui/admin/waitlist/export""#));
    assert!(
        index
            .body
            .contains(r#"<form class="cf-logout" method="post" action="/ui/admin/logout">"#)
    );
    // The public page keeps admin actions off its map.
    let public = send(&kit, Method::GET, "/ui/email-signup/export", &[], None).await;
    assert_eq!(public.status, StatusCode::NOT_FOUND);
}

#[pollster::test]
async fn table_shows_rows_and_delete_takes_two_posts() {
    let kit = kit(true);
    let cookie = login(&kit).await;
    // A subscriber through the public API (single opt-in: confirmed at once).
    let reply = cratefield_testing::request(
        &kit.router,
        Method::POST,
        "/v1/email-signup",
        Some(r#"{"email":"ada@example.com","captchaToken":"tok"}"#),
    )
    .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let table = send(
        &kit,
        Method::GET,
        "/ui/admin/email-signup/export",
        &[("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(table.status, StatusCode::OK, "{}", table.body);
    assert!(table.body.contains(
        r#"<table class="cf-table" data-cf-module="email-signup" data-cf-action="export">"#
    ));
    assert!(
        table
            .body
            .contains(r#"<th class="cf-table-head" scope="col">Email</th>"#)
    );
    assert!(
        table
            .body
            .contains(r#"<td class="cf-table-cell">ada@example.com</td>"#)
    );
    assert!(table.body.contains(r#"<form class="cf-row-action" method="post" action="/ui/admin/email-signup/delete"><input type="hidden" name="email" value="ada@example.com"><button class="cf-submit cf-submit--row" type="submit">Delete</button></form>"#), "{}", table.body);

    // First post: the confirm step, nothing deleted.
    let confirm = send(
        &kit,
        Method::POST,
        "/ui/admin/email-signup/delete",
        &[ORIGIN, ("cookie", &cookie)],
        Some("email=ada%40example.com"),
    )
    .await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.body);
    assert!(confirm.body.contains("Delete ada@example.com?"));
    assert!(
        confirm
            .body
            .contains(r#"<input type="hidden" name="confirm" value="1">"#)
    );
    assert!(
        confirm
            .body
            .contains(r#"<a class="cf-cancel" href="/ui/admin/email-signup/export">Cancel</a>"#)
    );
    let still = send(
        &kit,
        Method::GET,
        "/ui/admin/email-signup/export",
        &[("cookie", &cookie)],
        None,
    )
    .await;
    assert!(still.body.contains("ada@example.com"));

    // Second post: deleted, back to the table, row gone.
    let done = send(
        &kit,
        Method::POST,
        "/ui/admin/email-signup/delete",
        &[ORIGIN, ("cookie", &cookie)],
        Some("email=ada%40example.com&confirm=1"),
    )
    .await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    assert_eq!(
        done.header(header::LOCATION),
        "/ui/admin/email-signup/export"
    );
    let after = send(
        &kit,
        Method::GET,
        "/ui/admin/email-signup/export",
        &[("cookie", &cookie)],
        None,
    )
    .await;
    assert!(!after.body.contains("ada@example.com"));
    assert!(after.body.contains(r#"<td class="cf-table-empty""#));

    // Cross-origin posts are refused even with a session.
    let cross = send(
        &kit,
        Method::POST,
        "/ui/admin/email-signup/delete",
        &[("origin", "https://evil.example"), ("cookie", &cookie)],
        Some("email=x%40y.z&confirm=1"),
    )
    .await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN);
}

#[pollster::test]
async fn logout_clears_the_cookie() {
    let kit = kit(true);
    let cookie = login(&kit).await;
    let out = send(
        &kit,
        Method::POST,
        "/ui/admin/logout",
        &[ORIGIN, ("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert_eq!(out.header(header::LOCATION), "/ui/admin/login");
    assert!(out.header(header::SET_COOKIE).contains("Max-Age=0"));
}

#[pollster::test]
async fn without_admin_token_the_admin_ui_is_off() {
    let kit = kit(false);
    let page = send(&kit, Method::GET, "/ui/admin/login", &[], None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Admin is switched off"));
    assert!(!page.body.contains(r#"type="password""#));
    let post = send(
        &kit,
        Method::POST,
        "/ui/admin/login",
        &[ORIGIN],
        Some("token=anything"),
    )
    .await;
    assert!(post.header(header::SET_COOKIE).is_empty());
    assert!(post.body.contains("Admin is switched off"));
}

/// Issue #130: hiding an admin action from the public UI is visibility,
/// not authorization — invoking it directly on the public route must not
/// reach the module, and presenting the admin token there must not
/// unlock it either. The doors to an admin action are the session-gated
/// admin UI and a direct `/v1` request with the bearer.
#[pollster::test]
async fn hidden_admin_actions_are_not_executable_through_the_public_ui() {
    let kit = kit(true);
    // A subscriber a successful delete would remove.
    let reply = cratefield_testing::request(
        &kit.router,
        Method::POST,
        "/v1/email-signup",
        Some(r#"{"email":"ada@example.com","captchaToken":"tok"}"#),
    )
    .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // The destructive row action posted to the public route: 404 like
    // any unknown action, session or no session.
    let posted = send(
        &kit,
        Method::POST,
        "/ui/email-signup/delete",
        &[],
        Some("email=ada%40example.com&confirm=1"),
    )
    .await;
    assert_eq!(posted.status, StatusCode::NOT_FOUND, "{}", posted.body);
    assert_eq!(
        posted.header(header::CONTENT_TYPE),
        "application/problem+json"
    );

    // The admin export is hidden the same way, for GET and POST.
    let exported = send(&kit, Method::GET, "/ui/email-signup/export", &[], None).await;
    assert_eq!(exported.status, StatusCode::NOT_FOUND);
    let posted_export = send(&kit, Method::POST, "/ui/email-signup/export", &[], Some("")).await;
    assert_eq!(posted_export.status, StatusCode::NOT_FOUND);

    // A valid admin bearer on the public route changes nothing: the
    // action stays hidden there.
    let with_bearer = send(
        &kit,
        Method::POST,
        "/ui/email-signup/delete",
        &[("authorization", &format!("Bearer {TOKEN}"))],
        Some("email=ada%40example.com&confirm=1"),
    )
    .await;
    assert_eq!(with_bearer.status, StatusCode::NOT_FOUND);

    // Proof nothing executed: the direct admin export still lists the
    // subscriber, and the bearer works on the real `/v1` route.
    let export = send(
        &kit,
        Method::GET,
        "/v1/email-signup/admin/export.csv",
        &[("authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert_eq!(export.status, StatusCode::OK);
    assert!(export.body.contains("ada@example.com"), "{}", export.body);
}

/// Issue #130: the session is a cookie credential, so every admin POST
/// needs its same-origin proof — a missing `Origin`/`Referer` is refused
/// like a foreign one (the browsers that strip `Origin`), and a matching
/// `Referer` is accepted. The check runs before any dispatch, so a
/// refused post cannot have side effects.
#[pollster::test]
async fn admin_posts_need_same_origin_proof_beyond_the_cookie() {
    let kit = kit(true);
    let cookie = login(&kit).await;

    let no_proof = send(
        &kit,
        Method::POST,
        "/ui/admin/email-signup/delete",
        &[("cookie", &cookie)],
        Some("email=ada%40example.com&confirm=1"),
    )
    .await;
    assert_eq!(no_proof.status, StatusCode::FORBIDDEN);
    assert_eq!(
        no_proof.header(header::CONTENT_TYPE),
        "application/problem+json"
    );

    // The same post with a matching Referer reaches the confirm step.
    let referer = send(
        &kit,
        Method::POST,
        "/ui/admin/email-signup/delete",
        &[
            ("cookie", &cookie),
            (
                "referer",
                "https://api.test.example/ui/admin/email-signup/export",
            ),
        ],
        Some("email=ada%40example.com"),
    )
    .await;
    assert_eq!(referer.status, StatusCode::OK, "{}", referer.body);
    assert!(
        referer.body.contains("Delete ada@example.com?"),
        "{}",
        referer.body
    );
}
