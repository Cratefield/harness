//! Issue #11 acceptance: dense per-product positions in join order,
//! atomic positions under five concurrent confirms, referral credit only
//! from confirmed same-product referrers, unknown product, status round
//! trip, export, and the no-enumeration byte-identity.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use cratefield_core::{Clock, Decision, Kid, MapConfig, Payload, Signer, Statement, SystemClock};
use cratefield_module_waitlist::Waitlist;
use cratefield_testing::{MailerMode, TestHarness, request};
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const BASE: &str = "https://api.test.example";
const ADMIN: &str = "test-admin-token-0123456789abcdef";
const EXPIRED_PAGE: &str = "https://test.example/confirm-expired";

fn kits() -> Vec<TestHarness> {
    TestHarness::all_dialects(|| {
        vec![Box::new(
            Waitlist::new().products(["kontinuum", "undercover"]),
        )]
    })
}

fn join_json(email: &str, product: &str) -> String {
    format!(r#"{{"email":"{email}","product":"{product}","captchaToken":"x"}}"#)
}

async fn join(kit: &TestHarness, email: &str, product: &str) -> cratefield_testing::TestResponse {
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

fn age_entry(kit: &TestHarness, email: &str, secs: i64) {
    // "Aged past the re-mail window" means every record that gates a
    // re-send: the entry row and, since issue #133, the send-claim rows.
    let sql = format!(
        "UPDATE waitlist_entries SET created_at = '{}' WHERE email_normalized = '{email}'",
        iso_ago(secs)
    );
    pollster::block_on(kit.db.execute(&Statement::new(sql))).expect("age update");
    let claim = format!(
        "UPDATE waitlist_send_cooldown SET last_sent_at = '{}' WHERE subject LIKE '{email}:%'",
        iso_ago(secs)
    );
    pollster::block_on(kit.db.execute(&Statement::new(claim))).expect("age claim");
}

fn delete_entry(kit: &TestHarness, email: &str) {
    // A purge erases the whole record — including the #133 send claim.
    // Leaving the claim behind would block the next join's confirmation
    // mail for an hour, with no entry left to confirm.
    let sql = format!("DELETE FROM waitlist_entries WHERE email_normalized = '{email}'");
    pollster::block_on(kit.db.execute(&Statement::new(sql))).expect("delete");
    let claim = format!("DELETE FROM waitlist_send_cooldown WHERE subject LIKE '{email}:%'");
    pollster::block_on(kit.db.execute(&Statement::new(claim))).expect("delete claim");
}

#[pollster::test]
async fn join_then_confirm_assigns_positions_in_order() {
    for kit in kits() {
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
            let response =
                request(&kit.router, Method::GET, &confirm_path(&kit, index), None).await;
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
}

#[pollster::test]
async fn five_concurrent_confirms_get_distinct_positions() {
    for kit in kits() {
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
}

#[pollster::test]
async fn referral_credit_only_from_confirmed_same_product_referrers() {
    for kit in kits() {
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
}

#[pollster::test]
async fn referrals_can_be_disabled() {
    for kit in TestHarness::all_dialects(|| {
        vec![Box::new(
            Waitlist::new().products(["kontinuum"]).referrals(false),
        )]
    }) {
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
}

#[pollster::test]
async fn unknown_product_is_a_400_problem() {
    for kit in kits() {
        let response = join(&kit, "nick@example.com", "no-such-product").await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/unknown-product"
        );
        assert_eq!(kit.mailer.sent().len(), 0);
    }
}

#[pollster::test]
async fn status_token_round_trip() {
    for kit in kits() {
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
}

#[pollster::test]
async fn confirmed_mail_is_sent_after_confirm() {
    for kit in kits() {
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
}

#[pollster::test]
async fn byte_identical_join_responses_across_states() {
    for kit in kits() {
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
}

#[pollster::test]
async fn send_cooldown_claims_one_mail_per_window() {
    for kit in kits() {
        join(&kit, "once@example.com", "kontinuum").await;
        // A repeat join inside the window answers position-only. The claim
        // in waitlist_send_cooldown — not the FailOpen test limiter — is
        // what keeps a header burst from becoming a mail burst (#133).
        let repeat = join(&kit, "once@example.com", "kontinuum").await;
        assert_eq!(repeat.status, StatusCode::ACCEPTED);
        assert_eq!(kit.mailer.sent().len(), 1, "the repeat must not re-send");
        // A different product is a different claim.
        join(&kit, "once@example.com", "undercover").await;
        assert_eq!(kit.mailer.sent().len(), 2, "one claim per address+product");
        // An expired claim renews.
        let sql = format!(
            "UPDATE waitlist_send_cooldown SET last_sent_at = '{}' \
         WHERE subject = 'once@example.com:kontinuum'",
            iso_ago(2 * 3600)
        );
        pollster::block_on(kit.db.execute(&Statement::new(sql))).expect("age claim");
        join(&kit, "once@example.com", "kontinuum").await;
        assert_eq!(kit.mailer.sent().len(), 3, "an aged-out claim re-sends");
    }
}

#[pollster::test]
async fn send_claim_releases_when_the_mail_fails() {
    for kit in kits() {
        // A failed send must not consume the claim: the next join mails.
        kit.mailer.set_mode(MailerMode::NotConfigured);
        let failed = join(&kit, "retry@example.com", "kontinuum").await;
        assert_eq!(failed.status, StatusCode::SERVICE_UNAVAILABLE);
        kit.mailer.set_mode(MailerMode::SendOk);
        join(&kit, "retry@example.com", "kontinuum").await;
        assert_eq!(kit.mailer.sent().len(), 1, "the 503 released the claim");
    }
}

#[pollster::test]
async fn mailer_not_configured_is_503_and_writes_nothing() {
    for kit in kits() {
        kit.mailer.set_mode(MailerMode::NotConfigured);
        let response = join(&kit, "nick@example.com", "kontinuum").await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/mail-not-configured"
        );
        assert!(column_text(&kit, "nick@example.com", "id").is_none());
    }
}

#[pollster::test]
async fn answers_schema_is_enforced() {
    for kit in TestHarness::all_dialects(|| {
        vec![Box::new(
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
        )]
    }) {
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
}

fn admin_kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || vec![Box::new(Waitlist::new().products(["kontinuum"]))],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
        },
    )
}

#[pollster::test]
async fn admin_export_requires_token_and_filters_by_product() {
    for kit in admin_kits() {
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
}

fn admin_get(uri: &str) -> axum::http::Request<axum::body::Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .body(Body::empty())
        .expect("admin request")
}

async fn export_csv(kit: &TestHarness, uri: &str) -> (axum::http::HeaderMap, String) {
    let response = kit
        .router
        .clone()
        .oneshot(admin_get(uri))
        .await
        .expect("answers");
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    (
        headers,
        String::from_utf8(body.to_vec()).expect("utf-8 csv"),
    )
}

fn emails_in(body: &str) -> Vec<String> {
    body.lines()
        .skip(1)
        .map(|line| line.split(',').nth(1).expect("email column").to_owned())
        .collect()
}

#[pollster::test]
async fn admin_export_pages_with_limit_offset_and_reports_more() {
    for kit in admin_kits() {
        for email in ["p1@example.com", "p2@example.com", "p3@example.com"] {
            join(&kit, email, "kontinuum").await;
        }

        let (headers, first) = export_csv(&kit, "/v1/waitlist/admin/export.csv?limit=2").await;
        assert_eq!(
            headers
                .get("x-cf-export-more")
                .and_then(|value| value.to_str().ok()),
            Some("true"),
            "a truncated page must advertise that more rows exist"
        );
        let mut seen = emails_in(&first);
        assert_eq!(seen.len(), 2, "{first}");

        let (headers, tail) =
            export_csv(&kit, "/v1/waitlist/admin/export.csv?limit=2&offset=2").await;
        assert!(
            !headers.contains_key("x-cf-export-more"),
            "the last page must not advertise more"
        );
        seen.extend(emails_in(&tail));
        seen.sort();
        assert_eq!(
            seen,
            ["p1@example.com", "p2@example.com", "p3@example.com"],
            "the pages must partition the export with no skips or repeats"
        );

        // The port's ceiling is a clamp, not an error.
        let (headers, clamped) =
            export_csv(&kit, "/v1/waitlist/admin/export.csv?limit=999999").await;
        assert_eq!(emails_in(&clamped).len(), 3, "{clamped}");
        assert!(!headers.contains_key("x-cf-export-more"));
    }
}

#[pollster::test]
async fn rate_limit_denial_is_429_with_retry_after() {
    let deny = Decision {
        ok: false,
        retry_after: Some(Duration::from_secs(17)),
    };
    for kit in TestHarness::all_dialects_with_ports(
        || vec![Box::new(Waitlist::new().products(["kontinuum"]))],
        move |ports| {
            ports.rate_limiter = Some(Arc::new(cratefield_testing::FakeRateLimiter::scripted(
                vec![deny.clone()],
                deny.clone(),
            )));
        },
    ) {
        let response = join(&kit, "nick@example.com", "kontinuum").await;
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers.get("retry-after").unwrap(), "17");
    }
}

#[pollster::test]
async fn captcha_denial_is_400() {
    for kit in TestHarness::all_dialects_with_ports(
        || vec![Box::new(Waitlist::new().products(["kontinuum"]))],
        |ports| {
            ports.captcha = Some(Arc::new(cratefield_testing::FakeCaptcha::with_tokens([
                "good",
            ])));
        },
    ) {
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
}

#[pollster::test]
async fn redirect_params_are_ignored() {
    for kit in kits() {
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
}

/// Two concurrent hits on ONE confirm link (a mail scanner prefetching while
/// the human clicks). The entry flips once and the referrer is credited once.
#[test]
fn double_submit_of_one_confirm_link_credits_the_referrer_once() {
    for kit in kits() {
        pollster::block_on(join(&kit, "ref@example.com", "kontinuum"));
        pollster::block_on(request(
            &kit.router,
            Method::GET,
            &confirm_path(&kit, 0),
            None,
        ));
        let code = column_text(&kit, "ref@example.com", "referral_code").expect("code");
        let referrer_id = column_text(&kit, "ref@example.com", "id").expect("id");

        // Someone joins with that referral code.
        pollster::block_on(request(
            &kit.router,
            Method::POST,
            "/v1/waitlist",
            Some(&format!(
                r#"{{"email":"friend@example.com","product":"kontinuum","ref":"{code}","captchaToken":"x"}}"#
            )),
        ));
        let path = confirm_path(&kit, 1);

        // The mail scanner prefetches the link while the human clicks it.
        let mut handles = Vec::new();
        for _ in 0..2 {
            let router = kit.router.clone();
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                let req = Request::builder()
                    .method(Method::GET)
                    .uri(path)
                    .body(Body::empty())
                    .expect("request");
                pollster::block_on(router.oneshot(req)).expect("answers");
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }

        let stmt = Statement::with_values(
            "SELECT referrals FROM waitlist_entries WHERE id = ?".to_string(),
            vec![referrer_id.clone().into()],
        );
        let rows = pollster::block_on(kit.db.query(&stmt)).expect("select");
        let referrals = rows
            .first()
            .and_then(|r| r.get::<i64>("referrals"))
            .expect("referrals");
        eprintln!("OBSERVED referrals after a double-submit = {referrals}");
        assert_eq!(
            referrals, 1,
            "referrer credited once per confirmed referral"
        );
    }
}

/// Issue #127, replay: a consumed confirm link never re-assigns anything —
/// position, `confirmed_at` and referral credit stay exactly as the single
/// flip wrote them.
#[pollster::test]
async fn replayed_confirm_keeps_position_and_does_not_reflip() {
    for kit in kits() {
        join(&kit, "nick@example.com", "kontinuum").await;
        let path = confirm_path(&kit, 0);
        request(&kit.router, Method::GET, &path, None).await;
        assert_eq!(column_int(&kit, "nick@example.com", "position"), Some(1));
        let confirmed_at = column_text(&kit, "nick@example.com", "confirmed_at").expect("stamp");

        let replay = request(&kit.router, Method::GET, &path, None).await;
        assert_eq!(replay.status, StatusCode::SEE_OTHER);
        assert_eq!(column_int(&kit, "nick@example.com", "position"), Some(1));
        assert_eq!(
            column_text(&kit, "nick@example.com", "confirmed_at").as_deref(),
            Some(confirmed_at.as_str()),
            "a replay does not rewrite confirmed_at"
        );
        assert_eq!(
            column_text(&kit, "nick@example.com", "status").as_deref(),
            Some("confirmed")
        );
    }
}

/// Issue #127, delete/recreate: tokens bind to the immutable entry id, so
/// a purged entry's link cannot confirm the fresh entry a later join
/// creates under a new id.
#[pollster::test]
async fn purged_entry_token_cannot_confirm_a_recreated_entry() {
    for kit in kits() {
        join(&kit, "nick@example.com", "kontinuum").await;
        let old_path = confirm_path(&kit, 0);
        let old_id = column_text(&kit, "nick@example.com", "id").expect("id");

        delete_entry(&kit, "nick@example.com");
        join(&kit, "nick@example.com", "kontinuum").await;
        let new_path = confirm_path(&kit, 1);
        let new_id = column_text(&kit, "nick@example.com", "id").expect("id");
        assert_ne!(old_id, new_id, "recreation is a new immutable record");

        let stale = request(&kit.router, Method::GET, &old_path, None).await;
        assert_eq!(stale.status, StatusCode::SEE_OTHER);
        assert_eq!(
            stale.headers.get(header::LOCATION).unwrap(),
            EXPIRED_PAGE,
            "the purged entry's token is dead"
        );
        assert!(
            column_int(&kit, "nick@example.com", "position").is_none(),
            "the recreated entry is still pending"
        );

        let fresh = request(&kit.router, Method::GET, &new_path, None).await;
        assert_eq!(fresh.status, StatusCode::SEE_OTHER);
        assert_eq!(column_int(&kit, "nick@example.com", "position"), Some(1));
    }
}

/// Issue #127, migration grace: a legacy bare-id token (signed before the
/// generation binding shipped) still confirms a first-generation entry.
#[pollster::test]
async fn legacy_bare_subject_token_confirms_a_first_generation_entry() {
    for kit in kits() {
        let seeded = format!(
            "INSERT INTO waitlist_entries (id, email, email_normalized, product, status, referrals, created_at) \
             VALUES ('01HW00000000000000000000001', 'legacy@example.com', 'legacy@example.com', \
             'kontinuum', 'pending', 0, '{}')",
            iso_ago(60)
        );
        pollster::block_on(kit.db.execute(&Statement::new(seeded))).expect("seed");

        let token = kit.signer.sign(&Payload {
            purpose: "waitlist.confirm".to_owned(),
            subject: "01HW00000000000000000000001".to_owned(),
            exp: None,
            kid: Kid::Cur,
        });
        let response = request(
            &kit.router,
            Method::GET,
            &format!("/v1/waitlist/confirm?token={token}"),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        assert_eq!(column_int(&kit, "legacy@example.com", "position"), Some(1));
    }
}

/// Issue #127: a token naming a generation the entry does not hold is
/// rejected by the atomic conditional update — no flip, no position, no
/// referral credit.
#[pollster::test]
async fn mismatched_generation_token_never_flips() {
    for kit in kits() {
        let seeded = format!(
            "INSERT INTO waitlist_entries (id, email, email_normalized, product, status, referrals, created_at) \
             VALUES ('01HW00000000000000000000002', 'stale@example.com', 'stale@example.com', \
             'kontinuum', 'pending', 0, '{}')",
            iso_ago(60)
        );
        pollster::block_on(kit.db.execute(&Statement::new(seeded))).expect("seed");

        let token = kit.signer.sign(&Payload {
            purpose: "waitlist.confirm".to_owned(),
            subject: "01HW00000000000000000000002.7".to_owned(),
            exp: None,
            kid: Kid::Cur,
        });
        let response = request(
            &kit.router,
            Method::GET,
            &format!("/v1/waitlist/confirm?token={token}"),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        assert_eq!(
            column_text(&kit, "stale@example.com", "status").as_deref(),
            Some("pending"),
            "the wrong generation flips nothing"
        );
        assert!(column_int(&kit, "stale@example.com", "position").is_none());
        assert!(column_text(&kit, "stale@example.com", "referral_code").is_none());
    }
}

/// Issue #127, concurrent confirmation: a re-mailed join link racing the
/// original (two mails, one pending entry) confirms exactly once and
/// credits the referrer exactly once.
#[pollster::test]
async fn two_remailed_tokens_race_to_one_confirm_and_one_credit() {
    for kit in kits() {
        join(&kit, "ref@example.com", "kontinuum").await;
        request(&kit.router, Method::GET, &confirm_path(&kit, 0), None).await;
        let code = column_text(&kit, "ref@example.com", "referral_code").expect("code");
        let referrer_id = column_text(&kit, "ref@example.com", "id").expect("id");

        let join_body = format!(
            r#"{{"email":"friend@example.com","product":"kontinuum","ref":"{code}","captchaToken":"x"}}"#
        );
        request(&kit.router, Method::POST, "/v1/waitlist", Some(&join_body)).await;
        let first_link = confirm_path(&kit, 1);

        age_entry(&kit, "friend@example.com", 2 * 3600);
        request(&kit.router, Method::POST, "/v1/waitlist", Some(&join_body)).await;
        let second_link = confirm_path(&kit, 2);

        let mut handles = Vec::new();
        for path in [first_link, second_link] {
            let router = kit.router.clone();
            handles.push(std::thread::spawn(move || {
                let req = Request::builder()
                    .method(Method::GET)
                    .uri(path)
                    .body(Body::empty())
                    .expect("request");
                let response = pollster::block_on(router.oneshot(req)).expect("answers");
                assert_eq!(response.status(), StatusCode::SEE_OTHER);
            }));
        }
        for handle in handles {
            handle.join().expect("confirm thread");
        }

        assert_eq!(
            column_text(&kit, "friend@example.com", "status").as_deref(),
            Some("confirmed")
        );
        assert!(
            column_int(&kit, "friend@example.com", "position").is_some(),
            "exactly one position assigned"
        );
        let stmt = Statement::with_values(
            "SELECT referrals FROM waitlist_entries WHERE id = ?".to_string(),
            vec![referrer_id.into()],
        );
        let rows = pollster::block_on(kit.db.query(&stmt)).expect("select");
        let referrals = rows
            .first()
            .and_then(|row| row.get::<i64>("referrals"))
            .expect("referrals");
        assert_eq!(referrals, 1, "one referral, one credit under the race");
    }
}
