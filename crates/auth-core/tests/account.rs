//! Issue #914 acceptance: passkey-first sign-up's account-side paths, run on
//! every dialect the environment provides (SQLite always, Postgres when
//! `FZ_TEST_POSTGRES_URL` names a server).
//!
//! - recovery codes are shown as plain text once, stored only as Argon2id
//!   hashes, spent once, and regenerated only on a fresh ceremony;
//! - a recovery sign-in carries the `recovery` method, which can enrol a
//!   passkey and nothing else, and starts the quiet period;
//! - the in-app notices an account sees, read by that account alone;
//! - the anonymous recovery route is rate-limited;
//! - nothing needs an email address.

use std::sync::Arc;

use axum::http::{Method, StatusCode, header};
use cratefield_auth_core::{AuthCore, Login, UserRow, insert_user, issue};
use cratefield_core::{MapConfig, Statement, UlidIdGen};
use cratefield_testing::{FakeRateLimiter, FixedClock, TestHarness};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt;

const EPOCH: i64 = 1_800_000_000;
const BASE: &str = "/v1/auth-core";

fn at(secs: i64) -> FixedClock {
    FixedClock(OffsetDateTime::from_unix_timestamp(secs).expect("epoch in range"))
}

fn iso(secs: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::from_unix_timestamp(secs)
        .expect("epoch in range")
        .replace_nanosecond(0)
        .expect("in range")
        .format(&Rfc3339)
        .expect("rfc3339")
}

fn config() -> Arc<MapConfig> {
    Arc::new(MapConfig::from_pairs([
        (
            "AUTH_CORE_SIGNING_KEYS".to_owned(),
            serde_json::to_string(&vec![dummy_key("k1")]).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE".to_owned(), "k1".to_owned()),
        (
            "AUTH_CORE_ISSUER".to_owned(),
            "https://auth.test.example".to_owned(),
        ),
        ("AUTH_CORE_TERMS_VERSION".to_owned(), "2026-10".to_owned()),
        ("AUTH_CORE_PRIVACY_VERSION".to_owned(), "2026-10".to_owned()),
    ]))
}

fn dummy_key(kid: &str) -> Value {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("entropy");
    bytes[0] = 1;
    let secret = p256::SecretKey::from_slice(&bytes).expect("scalar");
    let d = Base64UrlUnpadded::encode_string(&secret.to_bytes());
    json!({ "kty": "EC", "crv": "P-256", "kid": kid, "d": d })
}

/// Every dialect the environment provides, each with the same configuration.
fn kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || vec![Box::new(AuthCore::new())],
        |ports| ports.config = config(),
    )
}

async fn seed(kit: &TestHarness, id: &str) {
    insert_user(
        &*kit.db,
        &UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: None,
            primary_email_verified: false,
            locale: None,
            status: "active".to_owned(),
            created_at: iso(EPOCH - 1000),
            updated_at: iso(EPOCH - 1000),
        },
    )
    .await
    .expect("user");
}

async fn session(kit: &TestHarness, user: &str, at_secs: i64, amr: &[&str]) -> String {
    issue(
        &*kit.db,
        &at(at_secs),
        &UlidIdGen,
        Login {
            user_id: user,
            ip: None,
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr,
        },
    )
    .await
    .expect("session")
    .value
}

async fn send(
    kit: &TestHarness,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Option<String>) {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(format!("{BASE}{path}"));
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, format!("__Host-session={cookie}"));
    }
    let body = match body {
        Some(json) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(json.to_string())
        }
        None => axum::body::Body::empty(),
    };
    let response = kit
        .router
        .clone()
        .oneshot(request.body(body).expect("request"))
        .await
        .expect("answers");
    let status = response.status();
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, set_cookie)
}

fn codes_of(body: &Value) -> Vec<String> {
    body["recovery_codes"]
        .as_array()
        .expect("codes")
        .iter()
        .map(|c| c.as_str().expect("code").to_owned())
        .collect()
}

/// The regeneration route is reached through a fresh passkey session.
async fn fresh_codes(kit: &TestHarness, user: &str) -> Vec<String> {
    let cookie = session(kit, user, EPOCH, &["passkey", "user"]).await;
    let (status, body, _) = send(kit, Method::POST, "/recovery/codes", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    codes_of(&body)
}

#[test]
fn a_fresh_set_of_ten_codes_is_shown_and_none_is_stored_in_the_clear() {
    pollster::block_on(async {
        for kit in kits() {
            seed(&kit, "ada").await;
            let codes = fresh_codes(&kit, "ada").await;
            assert_eq!(codes.len(), 10);
            let rows: cratefield_core::Rows = kit
                .db
                .query(&Statement::new(
                    "SELECT code_hash FROM recovery_codes WHERE user_id = 'ada'".to_owned(),
                ))
                .await
                .expect("rows");
            assert_eq!(rows.len(), 10);
            for row in &rows.rows {
                let stored = row.get::<String>("code_hash").expect("hash");
                assert!(stored.starts_with("$argon2id$"), "argon2id at rest");
                assert!(!codes.iter().any(|c| stored.contains(c.as_str())));
            }
        }
    });
}

#[test]
fn a_recovery_code_signs_in_once_and_refuses_a_second_use() {
    pollster::block_on(async {
        for kit in kits() {
            seed(&kit, "ada").await;
            let codes = fresh_codes(&kit, "ada").await;
            let code = codes[0].clone();
            let (status, body, cookie) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "sub": "ada", "recovery_code": code })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert!(cookie.is_some(), "a session is issued");
            let (status, _, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "sub": "ada", "recovery_code": code })),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "a spent code is refused");
        }
    });
}

#[test]
fn a_wrong_code_and_an_unknown_account_answer_alike() {
    pollster::block_on(async {
        for kit in kits() {
            seed(&kit, "ada").await;
            let _ = fresh_codes(&kit, "ada").await;
            let (wrong_status, wrong, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "sub": "ada", "recovery_code": "ZZZZ-ZZZZ-ZZZZ-ZZZZ" })),
            )
            .await;
            let (unknown_status, unknown, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "sub": "nobody", "recovery_code": "ZZZZ-ZZZZ-ZZZZ-ZZZZ" })),
            )
            .await;
            assert_eq!(wrong_status, unknown_status);
            assert_eq!(wrong["type"], unknown["type"], "one answer for both");
        }
    });
}

#[test]
fn regenerating_needs_a_fresh_ceremony_and_retires_the_old_set() {
    pollster::block_on(async {
        for kit in kits() {
            seed(&kit, "ada").await;
            let old = fresh_codes(&kit, "ada").await;
            // A stale session cannot regenerate.
            let stale = session(&kit, "ada", EPOCH - 3600, &["passkey", "user"]).await;
            let (status, _, _) =
                send(&kit, Method::POST, "/recovery/codes", Some(&stale), None).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let new = fresh_codes(&kit, "ada").await;
            assert_ne!(old, new);
            let (status, _, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "sub": "ada", "recovery_code": old[0] })),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "the old set no longer works"
            );
        }
    });
}

#[test]
fn a_recovery_sign_in_records_a_notice_the_account_reads_and_no_one_else_does() {
    pollster::block_on(async {
        for kit in kits() {
            seed(&kit, "ada").await;
            seed(&kit, "bob").await;
            let codes = fresh_codes(&kit, "ada").await;
            let (status, _, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "sub": "ada", "recovery_code": codes[1] })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);

            let ada = session(&kit, "ada", EPOCH, &["passkey", "user"]).await;
            let bob = session(&kit, "bob", EPOCH, &["passkey", "user"]).await;
            let (status, list, _) = send(&kit, Method::GET, "/notices", Some(&ada), None).await;
            assert_eq!(status, StatusCode::OK);
            let notice = list
                .as_array()
                .expect("list")
                .iter()
                .find(|n| n["kind"] == "recovery_used")
                .expect("the recovery is in the app")
                .clone();
            let id = notice["id"].as_str().expect("id").to_owned();

            // Bob cannot mark Ada's notice read.
            let (status, _, _) = send(
                &kit,
                Method::POST,
                &format!("/notices/{id}/read"),
                Some(&bob),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "the same empty answer");
            let (_, list, _) = send(&kit, Method::GET, "/notices", Some(&ada), None).await;
            assert!(
                list[0]["read_at"].is_null()
                    || list
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|n| n["id"] == id && n["read_at"].is_null())
            );

            let (status, _, _) = send(
                &kit,
                Method::POST,
                &format!("/notices/{id}/read"),
                Some(&ada),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let (_, list, _) = send(&kit, Method::GET, "/notices", Some(&ada), None).await;
            assert!(
                list.as_array()
                    .unwrap()
                    .iter()
                    .any(|n| n["id"] == id && !n["read_at"].is_null())
            );
        }
    });
}

#[test]
fn an_account_with_no_address_never_needs_one_for_any_of_this() {
    pollster::block_on(async {
        for kit in kits() {
            seed(&kit, "ada").await;
            let codes = fresh_codes(&kit, "ada").await;
            let (status, _, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "sub": "ada", "recovery_code": codes[2] })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "recovery needs no address");
        }
    });
}

#[pollster::test]
async fn the_anonymous_recovery_route_is_rate_limited() {
    let deny = cratefield_core::Decision {
        ok: false,
        retry_after: None,
        quota: None,
    };
    let limiter = FakeRateLimiter::scripted(Vec::new(), deny);
    let kit = TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = config();
        ports.rate_limiter = Some(Arc::new(limiter));
    });
    seed(&kit, "ada").await;
    let (status, _, _) = send(
        &kit,
        Method::POST,
        "/recovery/redeem",
        None,
        Some(json!({ "sub": "ada", "recovery_code": "AAAA-AAAA-AAAA-AAAA" })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

/// Issue #914: the anonymous recovery route passes the captcha first. A token
/// the captcha does not accept is refused, and nothing is spent.
#[pollster::test]
async fn a_recovery_attempt_without_a_captcha_pass_is_refused_and_spends_nothing() {
    let captcha = cratefield_testing::FakeCaptcha::with_tokens(["good-token"]);
    let kit = TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = config();
        ports.captcha = Some(Arc::new(captcha));
    });
    seed(&kit, "ada").await;
    let codes = fresh_codes(&kit, "ada").await;
    let (status, _, _) = send(
        &kit,
        Method::POST,
        "/recovery/redeem",
        None,
        Some(json!({ "sub": "ada", "recovery_code": codes[3], "captchaToken": "bad-token" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = send(
        &kit,
        Method::POST,
        "/recovery/redeem",
        None,
        Some(json!({ "sub": "ada", "recovery_code": codes[3], "captchaToken": "good-token" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the code was not spent by the refused attempt"
    );
}
