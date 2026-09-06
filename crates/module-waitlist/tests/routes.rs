//! Issue #11 acceptance: dense per-product positions in join order,
//! atomic positions under five concurrent confirms, referral credit only
//! from confirmed same-product referrers, unknown product, status round
//! trip, export, and the no-enumeration byte-identity.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use factory0_core::{Clock, Database, Decision, MapConfig, Statement, SystemClock};
use factory0_module_waitlist::Waitlist;
use factory0_testing::{MailerMode, TestHarness, request};
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const BASE: &str = "https://api.test.example";
const ADMIN: &str = "test-admin-token-0123456789abcdef";

fn kit() -> TestHarness {
    TestHarness::new(vec![Box::new(
        Waitlist::new().products(["kontinuum", "undercover"]),
    )])
}

fn join_json(email: &str, product: &str) -> String {
    format!(r#"{{"email":"{email}","product":"{product}","captchaToken":"x"}}"#)
}

async fn join(kit: &TestHarness, email: &str, product: &str) -> factory0_testing::TestResponse {
    request(
        &kit.router,
        Method::POST,
        "/v1/waitlist",
        Some(&join_json(email, product)),
    )
    .await
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

/// The i-th sent mail's confirm link as a router path.
fn confirm_path(kit: &TestHarness, index: usize) -> String {
    let message = kit.mailer.sent()[index].clone();
    let url = message
        .text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("https://"))
        .expect("confirm link in text body");
    url.strip_prefix(BASE).expect("api link").to_owned()
}

fn column_int(kit: &TestHarness, email: &str, column: &str) -> Option<i64> {
    let stmt = Statement::with_values(
        format!("SELECT {column} FROM waitlist_entries WHERE email_normalized = ?"),
        vec![email.into()],
    );
    let rows = pollster::block_on(kit.db.query(&stmt)).expect("select");
    rows.first().and_then(|row| row.get::<i64>(column))
}

fn column_text(kit: &TestHarness, email: &str, column: &str) -> Option<String> {
    let stmt = Statement::with_values(
        format!("SELECT {column} FROM waitlist_entries WHERE email_normalized = ?"),
        vec![email.into()],
    );
    let rows = pollster::block_on(kit.db.query(&stmt)).expect("select");
    rows.first().and_then(|row| row.get::<String>(column))
}

#[pollster::test]
async fn join_then_confirm_assigns_positions_in_order() {
    let kit = kit();
    for email in ["a@example.com", "b@example.com", "c@example.com"] {
        let response = join(&kit, email, "kontinuum").await;
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(response.body().as_ref(), b"{\"ok\":true}");
    }
    assert_eq!(kit.mailer.sent().len(), 3);

    for (index, email, expected) in [
        (0, "a@example.com", 1),
        (1, "b@example.com", 2),
        (2, "c@example.com", 3),
    ] {
        let response = request(&kit.router, Method::GET, &confirm_path(&kit, index), None).await;
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        let location = response
            .headers
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(
            location.starts_with("https://test.example/waitlist/status?token="),
            "status redirect: {location}"
        );
        assert_eq!(
            column_int(&kit, email, "position"),
            Some(expected),
            "{email} position"
        );
    }
}

#[pollster::test]
async fn five_concurrent_confirms_get_distinct_positions() {
    let kit = kit();
    let emails: Vec<String> = (1..=5).map(|n| format!("racer{n}@example.com")).collect();
    for email in &emails {
        join(&kit, email, "kontinuum").await;
    }
    assert_eq!(kit.mailer.sent().len(), 5);

    let mut handles = Vec::new();
    for index in 0..5 {
        let router = kit.router.clone();
        let path = confirm_path(&kit, index);
        handles.push(std::thread::spawn(move || {
            let request = Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(Body::empty())
                .expect("request");
            let response = pollster::block_on(router.oneshot(request)).expect("answers");
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
        }));
    }
    for handle in handles {
        handle.join().expect("confirm thread");
    }

    let mut positions: Vec<i64> = emails
        .iter()
        .map(|email| column_int(&kit, email, "position").expect("position"))
        .collect();
    positions.sort_unstable();
    assert_eq!(positions, [1, 2, 3, 4, 5], "distinct, dense positions");
}

#[pollster::test]
async fn referral_credit_only_from_confirmed_same_product_referrers() {
    let kit = kit();
    join(&kit, "first@example.com", "kontinuum").await;
    request(&kit.router, Method::GET, &confirm_path(&kit, 0), None).await;
    let referrer_code =
        column_text(&kit, "first@example.com", "referral_code").expect("code assigned");
    let referrer_id = column_text(&kit, "first@example.com", "id").expect("id");
    assert_eq!(referrer_code.len(), 8);

    // A confirmed entry on the OTHER product: code must not count.
    join(&kit, "other@example.com", "undercover").await;
    request(&kit.router, Method::GET, &confirm_path(&kit, 1), None).await;
    let other_code =
        column_text(&kit, "other@example.com", "referral_code").expect("code assigned");

    let referral_join = format!(
        r#"{{"email":"second@example.com","product":"kontinuum","ref":"{referrer_code}","captchaToken":"x"}}"#
    );
    request(
        &kit.router,
        Method::POST,
        "/v1/waitlist",
        Some(&referral_join),
    )
    .await;

    // Unknown codes are silently ignored: still 202, no referred_by.
    let bogus_join = r#"{"email":"third@example.com","product":"kontinuum","ref":"nope9999","captchaToken":"x"}"#;
    let bogus = request(&kit.router, Method::POST, "/v1/waitlist", Some(bogus_join)).await;
    assert_eq!(bogus.status, StatusCode::ACCEPTED);
    assert!(column_text(&kit, "third@example.com", "referred_by").is_none());

    // Cross-product code ignored too.
    let cross_join = format!(
        r#"{{"email":"fourth@example.com","product":"kontinuum","ref":"{other_code}","captchaToken":"x"}}"#
    );
    request(&kit.router, Method::POST, "/v1/waitlist", Some(&cross_join)).await;
    assert!(column_text(&kit, "fourth@example.com", "referred_by").is_none());

    // Credit lands only when the referred entry confirms.
    assert_eq!(column_int(&kit, "first@example.com", "referrals"), Some(0));
    request(&kit.router, Method::GET, &confirm_path(&kit, 2), None).await;
    assert_eq!(column_int(&kit, "first@example.com", "referrals"), Some(1));
    assert_eq!(
        column_text(&kit, "second@example.com", "referred_by").as_deref(),
        Some(referrer_id.as_str())
    );
}

#[pollster::test]
async fn referrals_can_be_disabled() {
    let kit = TestHarness::new(vec![Box::new(
        Waitlist::new().products(["kontinuum"]).referrals(false),
    )]);
    join(&kit, "first@example.com", "kontinuum").await;
    request(&kit.router, Method::GET, &confirm_path(&kit, 0), None).await;
    let code = column_text(&kit, "first@example.com", "referral_code").expect("code");

    let body = format!(
        r#"{{"email":"second@example.com","product":"kontinuum","ref":"{code}","captchaToken":"x"}}"#
    );
    request(&kit.router, Method::POST, "/v1/waitlist", Some(&body)).await;
    request(&kit.router, Method::GET, &confirm_path(&kit, 1), None).await;
    assert_eq!(column_int(&kit, "first@example.com", "referrals"), Some(0));
}

#[pollster::test]
async fn unknown_product_is_a_400_problem() {
    let kit = kit();
    let response = join(&kit, "nick@example.com", "no-such-product").await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json()["type"],
        "https://factory0.ventures/problems/unknown-product"
    );
    assert_eq!(kit.mailer.sent().len(), 0);
}

#[pollster::test]
async fn status_token_round_trip() {
    let kit = kit();
    join(&kit, "nick@example.com", "kontinuum").await;
    let confirmed = request(&kit.router, Method::GET, &confirm_path(&kit, 0), None).await;
    let location = confirmed
        .headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let token = location.split("token=").nth(1).expect("status token");

    let status = request(
        &kit.router,
        Method::GET,
        &format!("/v1/waitlist/status?token={token}"),
        None,
    )
    .await;
    assert_eq!(status.status, StatusCode::OK);
    let body = status.json();
    assert_eq!(body["product"], "kontinuum");
    assert_eq!(body["position"], 1);
    assert_eq!(body["referrals"], 0);
    let code = body["referralCode"].as_str().expect("code");
    assert_eq!(code.len(), 8);
    assert_eq!(
        body["shareUrl"],
        format!("https://test.example/waitlist/kontinuum?ref={code}")
    );

    let invalid = request(
        &kit.router,
        Method::GET,
        "/v1/waitlist/status?token=garbage",
        None,
    )
    .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid.json()["type"],
        "https://factory0.ventures/problems/invalid-token"
    );
}

#[pollster::test]
async fn confirmed_mail_is_sent_after_confirm() {
    let kit = kit();
    join(&kit, "nick@example.com", "kontinuum").await;
    request(&kit.router, Method::GET, &confirm_path(&kit, 0), None).await;
    kit.defer.drain().await;
    assert_eq!(kit.mailer.sent().len(), 2, "confirm + confirmed mails");
    let confirmed = kit.mailer.sent()[1].clone();
    assert!(
        confirmed
            .text
            .contains("https://api.test.example/v1/waitlist/status?token=")
    );
}

#[pollster::test]
async fn byte_identical_join_responses_across_states() {
    let kit = kit();

    let new = join(&kit, "fresh@example.com", "kontinuum").await;

    // pending, mailed within the hour
    let fresh_pending = join(&kit, "pending@example.com", "kontinuum").await;
    let pending = join(&kit, "pending@example.com", "kontinuum").await;

    // confirmed
    join(&kit, "done@example.com", "kontinuum").await;
    request(&kit.router, Method::GET, &confirm_path(&kit, 2), None).await;
    let confirmed = join(&kit, "done@example.com", "kontinuum").await;

    // pending + stale: the re-mail branch (seeded past the hour)
    let stale = format!(
        "INSERT INTO waitlist_entries (id, email, email_normalized, product, status, referrals, created_at) \
         VALUES ('01HW00000000000000000000000', 'stale@example.com', 'stale@example.com', \
         'kontinuum', 'pending', 0, '{}')",
        iso_ago(2 * 3600)
    );
    pollster::block_on(kit.db.execute(&Statement::new(stale))).expect("seed");
    let remail = join(&kit, "stale@example.com", "kontinuum").await;

    for response in [&new, &pending, &fresh_pending, &confirmed, &remail] {
        assert_eq!(response.status, StatusCode::ACCEPTED);
    }
    let canonical: [&[u8]; 5] = [
        new.body(),
        pending.body(),
        fresh_pending.body(),
        confirmed.body(),
        remail.body(),
    ];
    assert!(
        canonical.iter().all(|body| *body == canonical[0]),
        "byte-identical bodies: {canonical:?}"
    );
    assert_eq!(
        kit.mailer.sent().len(),
        4,
        "new + pending + done + stale-re-mail"
    );
}

#[pollster::test]
async fn mailer_not_configured_is_503_and_writes_nothing() {
    let kit = kit();
    kit.mailer.set_mode(MailerMode::NotConfigured);
    let response = join(&kit, "nick@example.com", "kontinuum").await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.json()["type"],
        "https://factory0.ventures/problems/mail-not-configured"
    );
    assert!(column_text(&kit, "nick@example.com", "id").is_none());
}

#[pollster::test]
async fn answers_schema_is_enforced() {
    let kit = TestHarness::new(vec![Box::new(
        Waitlist::new()
            .products(["kontinuum"])
            .answers_schema(|answers| {
                answers
                    .get("size")
                    .and_then(|v| v.as_str())
                    .is_some_and(|size| ["s", "m", "l"].contains(&size))
                    .then_some(())
                    .ok_or_else(|| "size must be one of s|m|l".to_string())
            }),
    )]);
    let bad = request(
        &kit.router,
        Method::POST,
        "/v1/waitlist",
        Some(r#"{"email":"nick@example.com","product":"kontinuum","answers":{"size":"xxl"},"captchaToken":"x"}"#),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        bad.json()["type"],
        "https://factory0.ventures/problems/validation-failed"
    );

    let good = request(
        &kit.router,
        Method::POST,
        "/v1/waitlist",
        Some(r#"{"email":"nick@example.com","product":"kontinuum","answers":{"size":"m"},"captchaToken":"x"}"#),
    )
    .await;
    assert_eq!(good.status, StatusCode::ACCEPTED);
    assert_eq!(
        column_text(&kit, "nick@example.com", "answers").as_deref(),
        Some(r#"{"size":"m"}"#)
    );
}

fn admin_kit() -> TestHarness {
    TestHarness::with_ports(
        vec![Box::new(Waitlist::new().products(["kontinuum"]))],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
        },
    )
}

#[pollster::test]
async fn admin_export_requires_token_and_filters_by_product() {
    let kit = admin_kit();
    join(&kit, "nick@example.com", "kontinuum").await;

    let denied = request(
        &kit.router,
        Method::GET,
        "/v1/waitlist/admin/export.csv",
        None,
    )
    .await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);

    let allowed = kit
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/waitlist/admin/export.csv?product=kontinuum")
                .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("answers");
    assert_eq!(allowed.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(allowed.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(body.contains("id,email,product,status"), "{body}");
    assert!(body.contains("nick@example.com"), "{body}");
    assert!(body.contains(",kontinuum,"), "{body}");
}

#[pollster::test]
async fn rate_limit_denial_is_429_with_retry_after() {
    let deny = Decision {
        ok: false,
        retry_after: Some(Duration::from_secs(17)),
    };
    let kit = TestHarness::with_ports(
        vec![Box::new(Waitlist::new().products(["kontinuum"]))],
        |ports| {
            ports.rate_limiter = Some(Arc::new(factory0_testing::FakeRateLimiter::scripted(
                vec![deny.clone()],
                deny,
            )));
        },
    );
    let response = join(&kit, "nick@example.com", "kontinuum").await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers.get("retry-after").unwrap(), "17");
}

#[pollster::test]
async fn captcha_denial_is_400() {
    let kit = TestHarness::with_ports(
        vec![Box::new(Waitlist::new().products(["kontinuum"]))],
        |ports| {
            ports.captcha = Some(Arc::new(factory0_testing::FakeCaptcha::with_tokens([
                "good",
            ])));
        },
    );
    let response = request(
        &kit.router,
        Method::POST,
        "/v1/waitlist",
        Some(r#"{"email":"nick@example.com","product":"kontinuum","captchaToken":"bad"}"#),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json()["type"],
        "https://factory0.ventures/problems/captcha-failed"
    );
}

#[pollster::test]
async fn redirect_params_are_ignored() {
    let kit = kit();
    join(&kit, "nick@example.com", "kontinuum").await;
    let confirm = request(&kit.router, Method::GET, &confirm_path(&kit, 0), None).await;
    let path = confirm_path(&kit, 0);
    for param in ["redirect", "return", "next"] {
        let baited = request(
            &kit.router,
            Method::GET,
            &format!("{path}&{param}=https://evil.example"),
            None,
        )
        .await;
        assert_eq!(
            confirm.headers.get(header::LOCATION).unwrap(),
            baited.headers.get(header::LOCATION).unwrap(),
            "no route reads a {param} query parameter"
        );
    }
}
