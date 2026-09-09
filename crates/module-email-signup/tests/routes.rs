//! Issue #10 acceptance: double opt-in, the hourly re-mail throttle,
//! confirm replay/expiry, unsubscribe, admin auth and CSV escaping,
//! captcha denial, rate limiting, the no-enumeration byte-identity, and
//! the scheduled retention purge.

use axum::http::{Method, StatusCode, header};
use cratefield_core::{
    Clock, Decision, Kid, MapConfig, Payload, Ports, Scope, Signer, Statement, SystemClock,
    UlidIdGen,
};
use cratefield_module_email_signup::EmailSignup;
use cratefield_testing::{MailerMode, TestHarness, request};
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const BASE: &str = "https://api.test.example";
const CONFIRMED_PAGE: &str = "https://test.example/confirmed";
const EXPIRED_PAGE: &str = "https://test.example/confirm-expired";
const UNSUBSCRIBED_PAGE: &str = "https://test.example/unsubscribed";
const ADMIN: &str = "test-admin-token-0123456789abcdef";

fn kits() -> Vec<TestHarness> {
    TestHarness::all_dialects(|| vec![Box::new(EmailSignup::new())])
}

fn signup_json(email: &str) -> String {
    format!(r#"{{"email":"{email}","captchaToken":"x"}}"#)
}

async fn signup(kit: &TestHarness, email: &str) -> cratefield_testing::TestResponse {
    request(
        &kit.router,
        Method::POST,
        "/v1/email-signup",
        Some(&signup_json(email)),
    )
    .await
}

fn now_iso() -> String {
    SystemClock
        .now()
        .replace_nanosecond(0)
        .expect("truncate")
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn iso_ago(secs: i64) -> String {
    SystemClock
        .now()
        .replace_nanosecond(0)
        .expect("truncate")
        .saturating_sub(time::Duration::seconds(secs))
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn seed(kit: &TestHarness, id: &str, email: &str, status: &str, updated_at: &str, source: &str) {
    let now = now_iso();
    let sql = format!(
        "INSERT INTO subscribers (id, email, email_normalized, status, source, locale, \
         confirmed_at, unsubscribed_at, created_at, updated_at) VALUES \
         ('{id}', '{email}', '{email}', '{status}', '{source}', NULL, NULL, NULL, '{now}', '{updated_at}')"
    );
    pollster::block_on(kit.db.execute(&Statement::new(sql))).expect("seed insert");
}

fn column(kit: &TestHarness, email: &str, column: &str) -> Option<String> {
    let stmt = Statement::with_values(
        format!("SELECT {column} FROM subscribers WHERE email_normalized = ?"),
        vec![email.into()],
    );
    let rows = pollster::block_on(kit.db.query(&stmt)).expect("seed select");
    rows.first().and_then(|row| row.get::<String>(column))
}

fn column_i64(kit: &TestHarness, email: &str, column: &str) -> Option<i64> {
    let stmt = Statement::with_values(
        format!("SELECT {column} FROM subscribers WHERE email_normalized = ?"),
        vec![email.into()],
    );
    let rows = pollster::block_on(kit.db.query(&stmt)).expect("select");
    rows.first().and_then(|row| row.get::<i64>(column))
}

fn age_row(kit: &TestHarness, email: &str, secs: i64) {
    let sql = format!(
        "UPDATE subscribers SET updated_at = '{}' WHERE email_normalized = '{email}'",
        iso_ago(secs)
    );
    pollster::block_on(kit.db.execute(&Statement::new(sql))).expect("age update");
}

/// The mail's text body puts every link on its own line.
fn links(kit: &TestHarness) -> Vec<String> {
    let message = kit.mailer.last_message().expect("a mail was sent");
    message
        .text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("https://"))
        .map(str::to_owned)
        .collect()
}

fn path_of(url: &str) -> String {
    url.strip_prefix(BASE)
        .expect("link targets the api")
        .to_owned()
}

#[pollster::test]
async fn new_signup_sends_one_mail_with_two_valid_links() {
    for kit in kits() {
        let response = signup(&kit, "nick@example.com").await;
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(response.body().as_ref(), b"{\"ok\":true}");

        let sent = kit.mailer.sent();
        assert_eq!(sent.len(), 1, "exactly one mail");
        assert_eq!(
            sent[0].idempotency_key.as_deref().map(|key| {
                let mut parts = key.split(':');
                parts.next();
                (parts.next().is_some(), parts.next().is_some())
            }),
            Some((true, true)),
            "idempotency key is signup:<id>:<updated_at>"
        );

        let urls = links(&kit);
        assert_eq!(urls.len(), 2, "confirm + unsubscribe links");
        let confirm_token = urls[0].split("token=").nth(1).expect("confirm token");
        let unsub_token = urls[1].split("token=").nth(1).expect("unsubscribe token");
        assert!(
            kit.signer
                .verify(confirm_token, "email-signup.confirm")
                .is_some()
        );
        // The unsubscribe link is the row's opaque token (issue #137),
        // not a signature: dot-free by construction and persisted so the
        // next mail can rotate it. Clicking it must unsubscribe.
        assert!(
            !unsub_token.contains('.'),
            "opaque tokens carry no signature separator"
        );
        assert_eq!(
            column(&kit, "nick@example.com", "unsubscribe_token").as_deref(),
            Some(unsub_token),
            "the mailed link is exactly the stored revocable token"
        );
        let gone = request(&kit.router, Method::GET, &path_of(&urls[1]), None).await;
        assert_eq!(gone.status, StatusCode::SEE_OTHER);
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("unsubscribed"),
            "the opaque link unsubscribes through the same endpoint"
        );
    }
}

#[pollster::test]
async fn second_post_within_an_hour_sends_nothing() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        signup(&kit, "nick@example.com").await;
        assert_eq!(kit.mailer.sent().len(), 1);
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("pending")
        );
    }
}

#[pollster::test]
async fn stale_pending_row_is_remailed_and_refreshed() {
    for kit in kits() {
        seed(
            &kit,
            "01HC00000000000000000000000",
            "stale@example.com",
            "pending",
            &iso_ago(2 * 3600),
            "launch",
        );
        let response = signup(&kit, "stale@example.com").await;
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(kit.mailer.sent().len(), 1, "older than an hour: re-mailed");
        let updated = column(&kit, "stale@example.com", "updated_at").expect("updated_at");
        assert!(updated > iso_ago(60), "updated_at refreshed: {updated}");
    }
}

#[pollster::test]
async fn unsubscribed_row_older_than_an_hour_rejoins_as_pending() {
    for kit in kits() {
        seed(
            &kit,
            "01HC00000000000000000000001",
            "back@example.com",
            "unsubscribed",
            &iso_ago(3 * 3600),
            "launch",
        );
        signup(&kit, "back@example.com").await;
        assert_eq!(kit.mailer.sent().len(), 1);
        assert_eq!(
            column(&kit, "back@example.com", "status").as_deref(),
            Some("pending")
        );
    }
}

#[pollster::test]
async fn four_post_responses_are_byte_identical() {
    for kit in kits() {
        // new
        let new = signup(&kit, "fresh@example.com").await;
        // pending, mailed within the hour
        seed(
            &kit,
            "01HC00000000000000000000002",
            "pending@example.com",
            "pending",
            &now_iso(),
            "launch",
        );
        let pending = signup(&kit, "pending@example.com").await;
        // confirmed
        seed(
            &kit,
            "01HC00000000000000000000003",
            "confirmed@example.com",
            "confirmed",
            &now_iso(),
            "launch",
        );
        let confirmed = signup(&kit, "confirmed@example.com").await;
        // unsubscribed, stale: the re-mail branch
        seed(
            &kit,
            "01HC00000000000000000000004",
            "unsubbed@example.com",
            "unsubscribed",
            &iso_ago(2 * 3600),
            "launch",
        );
        let unsubscribed = signup(&kit, "unsubbed@example.com").await;

        for response in [&new, &pending, &confirmed, &unsubscribed] {
            assert_eq!(response.status, StatusCode::ACCEPTED);
        }
        let canonical: [&[u8]; 4] = [
            new.body(),
            pending.body(),
            confirmed.body(),
            unsubscribed.body(),
        ];
        assert!(
            canonical.iter().all(|body| *body == canonical[0]),
            "byte-identical bodies: {canonical:?}"
        );
        assert_eq!(
            kit.mailer.sent().len(),
            2,
            "only the new + stale branches mail"
        );
    }
}

#[pollster::test]
async fn confirm_flips_once_and_replay_is_a_noop_redirect() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        let confirm_path = path_of(&links(&kit)[0]);

        let first = request(&kit.router, Method::GET, &confirm_path, None).await;
        assert_eq!(first.status, StatusCode::SEE_OTHER);
        assert_eq!(first.headers.get(header::LOCATION).unwrap(), CONFIRMED_PAGE);
        let confirmed_at = column(&kit, "nick@example.com", "confirmed_at").expect("confirmed_at");

        let replay = request(&kit.router, Method::GET, &confirm_path, None).await;
        assert_eq!(replay.status, StatusCode::SEE_OTHER);
        assert_eq!(
            replay.headers.get(header::LOCATION).unwrap(),
            CONFIRMED_PAGE
        );
        assert_eq!(
            column(&kit, "nick@example.com", "confirmed_at").as_deref(),
            Some(confirmed_at.as_str()),
            "replay does not rewrite confirmed_at"
        );
    }
}

#[pollster::test]
async fn expired_token_redirects_to_the_expired_page() {
    for kit in kits() {
        let token = kit.signer.sign(&Payload {
            purpose: "email-signup.confirm".to_owned(),
            subject: "01HC00000000000000000000005".to_owned(),
            exp: Some(1),
            kid: Kid::Cur,
        });
        let response = request(
            &kit.router,
            Method::GET,
            &format!("/v1/email-signup/confirm?token={token}"),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers.get(header::LOCATION).unwrap(),
            EXPIRED_PAGE
        );
    }
}

#[pollster::test]
async fn unsubscribe_from_confirmed_and_from_pending() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        let confirm_path = path_of(&links(&kit)[0]);
        request(&kit.router, Method::GET, &confirm_path, None).await;
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("confirmed")
        );

        let unsub_path = path_of(&links(&kit)[1]);
        let gone = request(&kit.router, Method::GET, &unsub_path, None).await;
        assert_eq!(gone.status, StatusCode::SEE_OTHER);
        assert_eq!(
            gone.headers.get(header::LOCATION).unwrap(),
            UNSUBSCRIBED_PAGE
        );
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("unsubscribed")
        );
        assert!(column(&kit, "nick@example.com", "unsubscribed_at").is_some());

        // pending rows unsubscribe the same way.
        signup(&kit, "soon@example.com").await;
        let pending_unsub = path_of(&links(&kit)[1]);
        let response = request(&kit.router, Method::GET, &pending_unsub, None).await;
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        assert_eq!(
            column(&kit, "soon@example.com", "status").as_deref(),
            Some("unsubscribed")
        );
    }
}

#[pollster::test]
async fn resubscribe_rotates_the_opaque_token_and_retires_the_old_link() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        let first = column(&kit, "nick@example.com", "unsubscribe_token")
            .expect("first mail stored its token");

        age_row(&kit, "nick@example.com", 2 * 3600);
        signup(&kit, "nick@example.com").await;
        let second = column(&kit, "nick@example.com", "unsubscribe_token")
            .expect("second mail stored its token");
        assert_ne!(first, second, "each mail rotates the revocable link");

        let stale = request(
            &kit.router,
            Method::GET,
            &format!("/v1/email-signup/unsubscribe?token={first}"),
            None,
        )
        .await;
        assert_eq!(
            stale.status,
            StatusCode::BAD_REQUEST,
            "the retired link from an older mail must not unsubscribe"
        );
        assert_ne!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("unsubscribed"),
            "a stale token leaves the subscription untouched"
        );

        let current = request(
            &kit.router,
            Method::GET,
            &format!("/v1/email-signup/unsubscribe?token={second}"),
            None,
        )
        .await;
        assert_eq!(current.status, StatusCode::SEE_OTHER);
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("unsubscribed"),
            "the newest mailed link still works"
        );
    }
}

#[pollster::test]
async fn legacy_signed_unsubscribe_links_still_unsubscribe() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        let id = column(&kit, "nick@example.com", "id").expect("row id");
        // Exactly the link format mailed before issue #137: a signed
        // payload with no expiry. Links already in the wild keep working.
        let signed = kit.signer.sign(&Payload {
            purpose: "email-signup.unsubscribe".to_owned(),
            subject: id,
            exp: None,
            kid: Kid::Cur,
        });
        assert!(signed.contains('.'), "signed form keeps its separator");
        let response = request(
            &kit.router,
            Method::POST,
            "/v1/email-signup/unsubscribe",
            Some(&format!(r#"{{"token":"{signed}"}}"#)),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("unsubscribed")
        );
    }
}

#[pollster::test]
async fn unsubscribe_post_returns_200_and_invalid_token_is_400() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        let unsub_token = links(&kit)[1]
            .split("token=")
            .nth(1)
            .expect("token")
            .to_owned();
        let ok = request(
            &kit.router,
            Method::POST,
            "/v1/email-signup/unsubscribe",
            Some(&format!(r#"{{"token":"{unsub_token}"}}"#)),
        )
        .await;
        assert_eq!(ok.status, StatusCode::OK);
        assert_eq!(ok.json()["ok"], true);

        let bad = request(
            &kit.router,
            Method::POST,
            "/v1/email-signup/unsubscribe",
            Some(r#"{"token":"not-a-token"}"#),
        )
        .await;
        assert_eq!(bad.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            bad.json()["type"],
            "https://factory0.ventures/problems/invalid-token"
        );
    }
}

#[pollster::test]
async fn admin_routes_are_disabled_without_admin_token() {
    for kit in kits() {
        let response = request(
            &kit.router,
            Method::GET,
            "/v1/email-signup/admin/export.csv",
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/admin-unauthorized"
        );
    }
}

fn admin_kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || vec![Box::new(EmailSignup::new())],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
        },
    )
}

#[pollster::test]
async fn admin_wrong_token_is_403_and_right_token_is_200() {
    for kit in admin_kits() {
        let no_header = request(
            &kit.router,
            Method::GET,
            "/v1/email-signup/admin/export.csv",
            None,
        )
        .await;
        assert_eq!(no_header.status, StatusCode::UNAUTHORIZED);

        let wrong = kit
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/v1/email-signup/admin/export.csv")
                    .header(header::AUTHORIZATION, "Bearer definitely-wrong")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("answers");
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);

        let good = kit
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/v1/email-signup/admin/export.csv")
                    .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("answers");
        assert_eq!(good.status(), StatusCode::OK);
        assert_eq!(
            good.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/csv; charset=utf-8"
        );
    }
}

#[pollster::test]
async fn admin_export_escapes_formula_leading_cells() {
    for kit in admin_kits() {
        seed(
            &kit,
            "01HC00000000000000000000006",
            "evil@example.com",
            "pending",
            &now_iso(),
            "=HYPERLINK(\"http://evil\",\"click\")",
        );

        let response = kit
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri("/v1/email-signup/admin/export.csv")
                    .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("answers");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("id,email,status"), "header row: {body}");
        assert!(
            body.contains("'=HYPERLINK"),
            "formula-guarded source cell: {body}"
        );
        assert!(!body.contains(",=HYPERLINK"), "no raw formula cell: {body}");
    }
}

#[pollster::test]
async fn admin_delete_is_a_hard_delete() {
    for kit in admin_kits() {
        signup(&kit, "gone@example.com").await;
        let id = column(&kit, "gone@example.com", "id").expect("signed-up row has an id");

        let response = kit
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/v1/email-signup/admin/subscribers/{id}"))
                    .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("answers");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(column(&kit, "gone@example.com", "id").is_none(), "row gone");
    }
}

/// The delete path takes the opaque row id, never the email (issue #135):
/// an email in a URL outlives the request in access logs, proxies and
/// browser history. Deleting "by email" now matches nothing — the path
/// value is treated strictly as an id — and the row survives.
#[pollster::test]
async fn admin_delete_with_an_email_in_the_path_is_a_no_op() {
    for kit in admin_kits() {
        signup(&kit, "gone@example.com").await;

        let response = kit
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::DELETE)
                    .uri("/v1/email-signup/admin/subscribers/gone@example.com")
                    .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("answers");
        assert_eq!(response.status(), StatusCode::OK);
        let (parts, body) = response.into_parts();
        drop(parts);
        let bytes = pollster::block_on(axum::body::to_bytes(body, usize::MAX)).expect("body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(json["deleted"], 0, "nothing matches an email as id");
        assert!(
            column(&kit, "gone@example.com", "id").is_some(),
            "row survives the email-in-path delete"
        );
    }
}

#[pollster::test]
async fn captcha_denial_is_400_captcha_failed() {
    for kit in TestHarness::all_dialects_with_ports(
        || vec![Box::new(EmailSignup::new())],
        |ports| {
            ports.captcha = Some(Arc::new(cratefield_testing::FakeCaptcha::with_tokens([
                "good",
            ])));
        },
    ) {
        let missing = request(
            &kit.router,
            Method::POST,
            "/v1/email-signup",
            Some(r#"{"email":"nick@example.com"}"#),
        )
        .await;
        assert_eq!(missing.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            missing.json()["type"],
            "https://factory0.ventures/problems/captcha-failed"
        );

        let rejected = request(
            &kit.router,
            Method::POST,
            "/v1/email-signup",
            Some(r#"{"email":"nick@example.com","captchaToken":"bad"}"#),
        )
        .await;
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.json()["type"],
            "https://factory0.ventures/problems/captcha-failed"
        );

        let accepted = request(
            &kit.router,
            Method::POST,
            "/v1/email-signup",
            Some(r#"{"email":"nick@example.com","captchaToken":"good"}"#),
        )
        .await;
        assert_eq!(accepted.status, StatusCode::ACCEPTED);
    }
}

#[pollster::test]
async fn rate_limit_denial_is_429_with_retry_after() {
    let deny = Decision {
        ok: false,
        retry_after: Some(Duration::from_secs(42)),
    };
    for kit in TestHarness::all_dialects_with_ports(
        || vec![Box::new(EmailSignup::new())],
        move |ports| {
            ports.rate_limiter = Some(Arc::new(cratefield_testing::FakeRateLimiter::scripted(
                vec![deny.clone()],
                deny.clone(),
            )));
        },
    ) {
        let response = signup(&kit, "nick@example.com").await;
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers.get("retry-after").unwrap(), "42");
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/rate-limited"
        );
    }
}

#[pollster::test]
async fn mailer_not_configured_is_503_and_writes_nothing() {
    for kit in kits() {
        kit.mailer.set_mode(MailerMode::NotConfigured);
        let response = signup(&kit, "nick@example.com").await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/mail-not-configured"
        );
        assert!(
            column(&kit, "nick@example.com", "id").is_none(),
            "no row written"
        );
    }
}

#[pollster::test]
async fn invalid_email_is_a_validation_problem() {
    for kit in kits() {
        let response = signup(&kit, "not-an-email").await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/validation-failed"
        );
    }
}

#[pollster::test]
async fn double_opt_in_off_confirms_immediately_without_mail() {
    for kit in TestHarness::all_dialects(|| vec![Box::new(EmailSignup::new().double_opt_in(false))])
    {
        let response = signup(&kit, "nick@example.com").await;
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(kit.mailer.sent().len(), 0);
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("confirmed")
        );
    }
}

#[pollster::test]
async fn welcome_mail_is_sent_on_confirm_when_enabled() {
    for kit in
        TestHarness::all_dialects(|| vec![Box::new(EmailSignup::new().welcome_on_confirm(true))])
    {
        signup(&kit, "nick@example.com").await;
        assert_eq!(kit.mailer.sent().len(), 1);
        let confirm_path = path_of(&links(&kit)[0]);
        request(&kit.router, Method::GET, &confirm_path, None).await;
        kit.defer.drain().await;
        assert_eq!(kit.mailer.sent().len(), 2, "welcome mail after the flip");
        let welcome = kit.mailer.sent()[1].clone();
        assert!(welcome.text.contains("/v1/email-signup/unsubscribe?token="));
    }
}

fn module_ports(kit: &TestHarness) -> Ports {
    let mut ports = Ports::with_config(Arc::new(MapConfig::default()));
    ports.db = Some(kit.db.clone());
    ports.signer = Some(kit.signer.clone());
    ports.mailer = Some(Arc::new(kit.mailer.clone()));
    ports.captcha = Some(Arc::new(kit.captcha.clone()));
    ports.rate_limiter = Some(Arc::new(kit.rate_limiter.clone()));
    ports.clock = Some(Arc::new(kit.clock.clone()));
    ports.id_gen = Some(Arc::new(UlidIdGen));
    ports.defer = Some(Arc::new(kit.defer.clone()));
    ports
}

#[pollster::test]
async fn scheduled_purge_removes_only_stale_pending_rows() {
    for kit in kits() {
        seed(
            &kit,
            "01HC00000000000000000000007",
            "stale@example.com",
            "pending",
            &iso_ago(40 * 86_400),
            "launch",
        );
        seed(
            &kit,
            "01HC00000000000000000000008",
            "fresh@example.com",
            "pending",
            &now_iso(),
            "launch",
        );
        seed(
            &kit,
            "01HC00000000000000000000009",
            "old-but-confirmed@example.com",
            "confirmed",
            &iso_ago(40 * 86_400),
            "launch",
        );

        let ports = module_ports(&kit);
        let module = kit.modules[0].clone();
        let ctx = kit.harness.module_context(module.as_ref(), &ports);
        module
            .scheduled(&ctx, "0 3 * * *")
            .await
            .expect("scheduled run");

        assert!(column(&kit, "stale@example.com", "id").is_none());
        assert!(column(&kit, "fresh@example.com", "id").is_some());
        assert!(column(&kit, "old-but-confirmed@example.com", "id").is_some());
    }
}

#[pollster::test]
async fn waitlist_confirmed_event_subscribes_the_address() {
    for kit in TestHarness::all_dialects(|| {
        vec![Box::new(
            EmailSignup::new().subscribe_on_waitlist_confirm(true),
        )]
    }) {
        let scope = Scope {
            request_id: "event-test-0001".to_owned(),
            defer: Arc::new(kit.defer.clone()),
            span: tracing::Span::none(),
        };
        kit.harness.events().emit_in(
            &scope,
            "waitlist.confirmed",
            serde_json::json!({ "email": "waiter@example.com", "product": "kontinuum" }),
        );
        kit.defer.drain().await;

        assert_eq!(
            column(&kit, "waiter@example.com", "status").as_deref(),
            Some("confirmed")
        );
        assert_eq!(
            column(&kit, "waiter@example.com", "source").as_deref(),
            Some("waitlist:kontinuum")
        );

        // Already subscribed: the handler is a no-op.
        kit.harness.events().emit_in(
            &scope,
            "waitlist.confirmed",
            serde_json::json!({ "email": "waiter@example.com", "product": "kontinuum" }),
        );
        kit.defer.drain().await;
        assert_eq!(
            column(&kit, "waiter@example.com", "source").as_deref(),
            Some("waitlist:kontinuum")
        );
    }
}

#[pollster::test]
async fn redirect_params_are_ignored() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        let confirm_path = path_of(&links(&kit)[0]);
        let plain = request(&kit.router, Method::GET, &confirm_path, None).await;
        for param in ["redirect", "return", "next"] {
            let baited = request(
                &kit.router,
                Method::GET,
                &format!("{confirm_path}&{param}=https://evil.example"),
                None,
            )
            .await;
            assert_eq!(
                plain.headers.get(header::LOCATION).unwrap(),
                baited.headers.get(header::LOCATION).unwrap(),
                "no route reads a {param} query parameter"
            );
        }
    }
}

/// Issue #127, the core regression: a token from an earlier subscription
/// generation must never become usable again when an unauthenticated
/// signup refreshes the row back to pending — not the module's own
/// `id.generation` token, and not a legacy bare-id token from before the
/// generation binding existed.
#[pollster::test]
async fn old_generation_tokens_die_after_unsubscribe_and_resubscribe() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        let id = column(&kit, "nick@example.com", "id").expect("id");
        assert_eq!(column_i64(&kit, "nick@example.com", "generation"), Some(1));
        let first = links(&kit);
        let confirm1 = path_of(&first[0]);
        let unsub1 = path_of(&first[1]);
        // A pre-#127 in-flight mail: bare-id subject, no generation.
        let legacy = kit.signer.sign(&Payload {
            purpose: "email-signup.confirm".to_owned(),
            subject: id.clone(),
            exp: None,
            kid: Kid::Cur,
        });

        request(&kit.router, Method::GET, &confirm1, None).await;
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("confirmed")
        );
        request(&kit.router, Method::GET, &unsub1, None).await;
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("unsubscribed")
        );

        // Replay straight after the unsubscribe: dead link, state untouched.
        let replay = request(&kit.router, Method::GET, &confirm1, None).await;
        assert_eq!(replay.headers.get(header::LOCATION).unwrap(), EXPIRED_PAGE);
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("unsubscribed"),
            "a replayed token cannot resurrect an unsubscribed row"
        );

        // Resubscribe past the hourly throttle: a new generation.
        age_row(&kit, "nick@example.com", 2 * 3600);
        signup(&kit, "nick@example.com").await;
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("pending")
        );
        assert_eq!(
            column_i64(&kit, "nick@example.com", "generation"),
            Some(2),
            "resubscription is a new generation"
        );
        let confirm2 = path_of(&links(&kit)[0]);

        for stale in [
            &confirm1,
            &format!("/v1/email-signup/confirm?token={legacy}"),
        ] {
            let response = request(&kit.router, Method::GET, stale, None).await;
            assert_eq!(
                response.headers.get(header::LOCATION).unwrap(),
                EXPIRED_PAGE,
                "an old-generation token is a dead link"
            );
            assert_eq!(
                column(&kit, "nick@example.com", "status").as_deref(),
                Some("pending"),
                "the old token left the new generation pending"
            );
            assert!(column(&kit, "nick@example.com", "confirmed_at").is_none());
        }

        // The new generation's own token confirms.
        let fresh = request(&kit.router, Method::GET, &confirm2, None).await;
        assert_eq!(fresh.headers.get(header::LOCATION).unwrap(), CONFIRMED_PAGE);
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("confirmed")
        );
    }
}

/// Issue #127, the liveness side of the state machine: re-mailing a
/// pending row is the SAME subscription lifecycle, so a confirmation
/// link already in flight stays valid and the generation does not move.
#[pollster::test]
async fn pending_remail_keeps_the_earlier_link_valid() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        let confirm1 = path_of(&links(&kit)[0]);

        age_row(&kit, "nick@example.com", 2 * 3600);
        signup(&kit, "nick@example.com").await;
        assert_eq!(kit.mailer.sent().len(), 2, "stale pending row re-mailed");
        assert_eq!(
            column_i64(&kit, "nick@example.com", "generation"),
            Some(1),
            "a pending re-mail keeps the generation"
        );

        let response = request(&kit.router, Method::GET, &confirm1, None).await;
        assert_eq!(
            response.headers.get(header::LOCATION).unwrap(),
            CONFIRMED_PAGE,
            "the first mail's link still confirms"
        );
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("confirmed")
        );
    }
}

/// Issue #127: an unauthenticated signup can never reset a confirmed
/// record — no re-mail, no rewrite, generation untouched.
#[pollster::test]
async fn signup_never_resets_a_confirmed_row() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        let confirm1 = path_of(&links(&kit)[0]);
        request(&kit.router, Method::GET, &confirm1, None).await;
        let confirmed_at = column(&kit, "nick@example.com", "confirmed_at").expect("confirmed_at");

        age_row(&kit, "nick@example.com", 2 * 3600);
        let response = signup(&kit, "nick@example.com").await;
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(
            kit.mailer.sent().len(),
            1,
            "a confirmed row is never re-mailed"
        );
        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("confirmed")
        );
        assert_eq!(
            column(&kit, "nick@example.com", "confirmed_at").as_deref(),
            Some(confirmed_at.as_str())
        );
        assert_eq!(column_i64(&kit, "nick@example.com", "generation"), Some(1));
    }
}

/// Issue #127, delete/recreate: a hard-deleted row's tokens target the
/// immutable id, so they die with the row and cannot confirm the fresh
/// row a later signup creates.
#[pollster::test]
async fn deleted_row_tokens_do_not_confirm_a_recreated_row() {
    for kit in admin_kits() {
        signup(&kit, "gone@example.com").await;
        let old_id = column(&kit, "gone@example.com", "id").expect("id");
        let confirm1 = path_of(&links(&kit)[0]);

        let deleted = kit
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/v1/email-signup/admin/subscribers/{old_id}"))
                    .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("answers");
        assert_eq!(deleted.status(), StatusCode::OK);

        signup(&kit, "gone@example.com").await;
        let new_id = column(&kit, "gone@example.com", "id").expect("id");
        assert_ne!(old_id, new_id, "recreation is a new immutable record");
        let confirm2 = path_of(&links(&kit)[0]);

        let stale = request(&kit.router, Method::GET, &confirm1, None).await;
        assert_eq!(
            stale.headers.get(header::LOCATION).unwrap(),
            EXPIRED_PAGE,
            "the deleted row's token is dead"
        );
        assert_eq!(
            column(&kit, "gone@example.com", "status").as_deref(),
            Some("pending"),
            "the recreated row is untouched"
        );

        let fresh = request(&kit.router, Method::GET, &confirm2, None).await;
        assert_eq!(fresh.headers.get(header::LOCATION).unwrap(), CONFIRMED_PAGE);
    }
}

/// Issue #127, concurrent confirmation: two hits on one link (a mail
/// scanner prefetching while the human clicks) flip the row exactly once
/// and both land on the confirmed page.
#[pollster::test]
async fn concurrent_confirms_flip_the_row_once() {
    for kit in kits() {
        signup(&kit, "nick@example.com").await;
        let confirm_path = path_of(&links(&kit)[0]);

        let mut handles = Vec::new();
        for _ in 0..2 {
            let router = kit.router.clone();
            let path = confirm_path.clone();
            handles.push(std::thread::spawn(move || {
                let req = axum::http::Request::builder()
                    .method(Method::GET)
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .expect("request");
                let response = pollster::block_on(router.oneshot(req)).expect("answers");
                assert_eq!(response.status(), StatusCode::SEE_OTHER);
                assert_eq!(
                    response.headers().get(header::LOCATION).unwrap(),
                    CONFIRMED_PAGE
                );
            }));
        }
        for handle in handles {
            handle.join().expect("confirm thread");
        }

        assert_eq!(
            column(&kit, "nick@example.com", "status").as_deref(),
            Some("confirmed")
        );
        assert_eq!(column_i64(&kit, "nick@example.com", "generation"), Some(1));
    }
}

/// Issue #127, migration grace: a legacy bare-id token (signed before
/// the generation binding shipped) still confirms a first-generation
/// pending row — and only one, see
/// `old_generation_tokens_die_after_unsubscribe_and_resubscribe`.
#[pollster::test]
async fn legacy_bare_subject_token_confirms_a_first_generation_row() {
    for kit in kits() {
        seed(
            &kit,
            "01HC00000000000000000000010",
            "legacy@example.com",
            "pending",
            &now_iso(),
            "launch",
        );
        assert_eq!(
            column_i64(&kit, "legacy@example.com", "generation"),
            Some(1),
            "the migration default is generation 1"
        );
        let token = kit.signer.sign(&Payload {
            purpose: "email-signup.confirm".to_owned(),
            subject: "01HC00000000000000000000010".to_owned(),
            exp: None,
            kid: Kid::Cur,
        });
        let response = request(
            &kit.router,
            Method::GET,
            &format!("/v1/email-signup/confirm?token={token}"),
            None,
        )
        .await;
        assert_eq!(
            response.headers.get(header::LOCATION).unwrap(),
            CONFIRMED_PAGE
        );
        assert_eq!(
            column(&kit, "legacy@example.com", "status").as_deref(),
            Some("confirmed")
        );
    }
}
