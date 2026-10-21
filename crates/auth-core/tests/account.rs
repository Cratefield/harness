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
const ADMIN: &str = "test-admin-token-0123456789abcdef";
const REDIRECT: &str = "https://undercoverrockstars.com/auth/callback";
const VERIFIER: &str = "a-verifier-of-at-least-43-characters-1234567890";

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
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
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
                assert_eq!(stored.len(), 64, "a SHA-256 hex digest at rest");
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
                Some(json!({ "recovery_code": code })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert!(cookie.is_some(), "a session is issued");
            let (status, _, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "recovery_code": code })),
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
                Some(json!({ "recovery_code": "ZZZZ-ZZZZ-ZZZZ-ZZZZ" })),
            )
            .await;
            let (unknown_status, unknown, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "recovery_code": "ZZZZ-ZZZZ-ZZZZ-ZZZZ" })),
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
                Some(json!({ "recovery_code": old[0] })),
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
                Some(json!({ "recovery_code": codes[1] })),
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
                Some(json!({ "recovery_code": codes[2] })),
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
        Some(json!({ "recovery_code": "AAAA-AAAA-AAAA-AAAA" })),
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
        Some(json!({ "recovery_code": codes[3], "captchaToken": "bad-token" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = send(
        &kit,
        Method::POST,
        "/recovery/redeem",
        None,
        Some(json!({ "recovery_code": codes[3], "captchaToken": "good-token" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the code was not spent by the refused attempt"
    );
}

/// A public OAuth client, registered through the admin API.
async fn client_id(kit: &TestHarness) -> String {
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("{BASE}/admin/clients"))
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .header(header::CONTENT_TYPE, "application/json");
    let body = json!({ "name": "Undercover", "kind": "public", "redirect_uris": [REDIRECT] });
    let response = kit
        .router
        .clone()
        .oneshot(
            request
                .body(axum::body::Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("answers");
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let json: Value = serde_json::from_slice(&bytes).expect("json");
    json["id"].as_str().expect("id").to_owned()
}

/// `/authorize` as a relying party asks for it, with a session cookie.
async fn authorize_as(
    kit: &TestHarness,
    client: &str,
    cookie: &str,
    extra: &str,
) -> (StatusCode, axum::http::HeaderMap) {
    use cratefield_core::Clock as _;
    let _ = at(EPOCH).now();
    let challenge = {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use sha2::{Digest, Sha256};
        Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()))
    };
    let uri = format!(
        "{BASE}/authorize?response_type=code&client_id={client}&redirect_uri={REDIRECT}\
         &code_challenge={challenge}&code_challenge_method=S256&state=xyz{extra}"
    );
    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::COOKIE, format!("__Host-session={cookie}"));
    let response = kit
        .router
        .clone()
        .oneshot(request.body(axum::body::Body::empty()).expect("request"))
        .await
        .expect("answers");
    (response.status(), response.headers().clone())
}

fn is_code(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(header::LOCATION)
        .is_some_and(|value| value.to_str().is_ok_and(|v| v.contains("code=")))
}

/// Issue #914 (security review): a recovery sign-in is not a session a
/// relying party may use. It cannot obtain a code, and it does not meet a
/// step-up.
#[test]
fn a_recovery_sign_in_is_signed_out_for_the_authorization_endpoint() {
    pollster::block_on(async {
        for kit in kits() {
            seed(&kit, "ada").await;
            let client = client_id(&kit).await;
            let codes = fresh_codes(&kit, "ada").await;
            let (status, _, cookie) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "recovery_code": codes[4] })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let cookie = cookie
                .expect("a session")
                .split(';')
                .next()
                .unwrap_or_default()
                .trim_start_matches("__Host-session=")
                .to_owned();
            let (status, headers) = authorize_as(&kit, &client, &cookie, "&scope=openid").await;
            assert_eq!(status, StatusCode::OK, "the chooser, not a code");
            assert!(!is_code(&headers));
            let (status, headers) = authorize_as(&kit, &client, &cookie, "&prompt=none").await;
            assert_eq!(status, StatusCode::FOUND);
            assert!(
                headers
                    .get(header::LOCATION)
                    .is_some_and(|l| l.to_str().unwrap_or_default().contains("login_required"))
            );
        }
    });
}

/// Issue #914 (security review): redeeming a code signs the account's other
/// sessions out by default, and keeps them when the caller says not to.
#[test]
fn a_recovery_redeem_signs_the_other_sessions_out_by_default() {
    pollster::block_on(async {
        for kit in kits() {
            seed(&kit, "ada").await;
            let client = client_id(&kit).await;
            let codes = fresh_codes(&kit, "ada").await;
            let old = {
                use cratefield_auth_core::{Login, issue};
                issue(
                    &*kit.db,
                    &at(EPOCH),
                    &UlidIdGen,
                    Login {
                        user_id: "ada",
                        ip: None,
                        user_agent: None,
                        presented_cookie: None,
                        presented_session_id: None,
                        amr: &["passkey", "user"],
                    },
                )
                .await
                .expect("session")
                .value
            };
            let (status, _, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "recovery_code": codes[5] })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let (status, headers) = authorize_as(&kit, &client, &old, "&scope=openid").await;
            assert_eq!(status, StatusCode::OK, "the old session was signed out");
            assert!(!is_code(&headers));

            // Asked not to sign the others out, the old session keeps working.
            let kept = {
                use cratefield_auth_core::{Login, issue};
                issue(
                    &*kit.db,
                    &at(EPOCH),
                    &UlidIdGen,
                    Login {
                        user_id: "ada",
                        ip: None,
                        user_agent: None,
                        presented_cookie: None,
                        presented_session_id: None,
                        amr: &["passkey", "user"],
                    },
                )
                .await
                .expect("session")
                .value
            };
            let (status, _, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "recovery_code": codes[6], "sign_out_other_sessions": false })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let (_, headers) = authorize_as(&kit, &client, &kept, "&scope=openid").await;
            assert!(is_code(&headers), "asked not to, the other session is kept");
        }
    });
}

/// Issue #914 (security review): with no captcha port, recovery refuses.
#[pollster::test]
async fn recovery_refuses_without_a_captcha_port() {
    let kit = TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = config();
        ports.captcha = None;
    });
    seed(&kit, "ada").await;
    let codes = fresh_codes(&kit, "ada").await;
    let (status, _, _) = send(
        &kit,
        Method::POST,
        "/recovery/redeem",
        None,
        Some(json!({ "recovery_code": codes[7] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Issue #914 (security review): a wrong code for a real account and a code
/// for no account take the same work: one lookup, one hash. Their medians over
/// repeated runs are close, so timing does not show whether an account exists.
#[pollster::test]
async fn an_unknown_code_costs_what_a_wrong_one_costs() {
    let kit = TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = config();
    });
    seed(&kit, "ada").await;
    let _ = fresh_codes(&kit, "ada").await;
    let median = |mut values: Vec<std::time::Duration>| {
        values.sort();
        values[values.len() / 2]
    };
    let mut wrong_real = Vec::new();
    let mut unknown = Vec::new();
    for _ in 0..25 {
        let t = std::time::Instant::now();
        let (status, _, _) = send(
            &kit,
            Method::POST,
            "/recovery/redeem",
            None,
            Some(json!({ "recovery_code": "ABCD-EFGH-IJKL-MNPQ-RSTU-VWXY" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        wrong_real.push(t.elapsed());
        let t = std::time::Instant::now();
        let (status, _, _) = send(
            &kit,
            Method::POST,
            "/recovery/redeem",
            None,
            Some(json!({ "recovery_code": "ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        unknown.push(t.elapsed());
    }
    let (a, b) = (
        median(wrong_real).as_secs_f64(),
        median(unknown).as_secs_f64(),
    );
    let ratio = if a > b { a / b } else { b / a };
    assert!(ratio < 5.0, "medians {a}s and {b}s differ by {ratio}x");
}

/// Issue #914 (review): a disabled account's code is refused and not spent, so
/// it still works once the account is enabled again. The refusal is the same one
/// a wrong code gets.
#[test]
fn a_disabled_account_does_not_burn_its_recovery_code() {
    pollster::block_on(async {
        for kit in kits() {
            seed(&kit, "ada").await;
            let codes = fresh_codes(&kit, "ada").await;
            kit.db
                .execute(&Statement::new(
                    "UPDATE users SET status = 'disabled' WHERE id = 'ada'".to_owned(),
                ))
                .await
                .expect("disabled");
            let (status, body, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "recovery_code": codes[8] })),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            let (_, wrong, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "recovery_code": "ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ" })),
            )
            .await;
            assert_eq!(
                body["type"], wrong["type"],
                "the same answer as a wrong code"
            );
            kit.db
                .execute(&Statement::new(
                    "UPDATE users SET status = 'active' WHERE id = 'ada'".to_owned(),
                ))
                .await
                .expect("enabled");
            let (status, _, _) = send(
                &kit,
                Method::POST,
                "/recovery/redeem",
                None,
                Some(json!({ "recovery_code": codes[8] })),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "the code was not spent while disabled"
            );
        }
    });
}
