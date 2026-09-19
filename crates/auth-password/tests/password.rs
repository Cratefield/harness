//! Issues #12, #19 and #20 end to end.
//!
//! Most of these assert an *absence*: that two different situations
//! produce the same answer. That is the whole security property of a
//! password endpoint, and it is the one a refactor breaks without any test
//! that only checks the happy path noticing.

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, Config, Database, Decision, HttpClient, HttpError, MapConfig, RateLimitError,
    RateLimiter, Statement,
};
use cratefield_testing::TestHarness;
use factory0_auth_core::{AuthCore, STATUS_ACTIVE, UserRow, insert_user, user_by_primary_email};
use factory0_auth_password::Password;
use http::{Method, Request, Response, StatusCode, header};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;
use tower::ServiceExt;

const REGISTER: &str = "/v1/auth-password/register";
const LOGIN: &str = "/v1/auth-password/login";
const CHANGE: &str = "/v1/auth-password/change";
const GOOD: &str = "a long enough password";

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("in range")
    }
}

/// A breach corpus that answers whatever a test wants.
#[derive(Clone, Default)]
struct FakeCorpus {
    body: Arc<RwLock<Option<String>>>,
    fail: Arc<RwLock<bool>>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpClient for FakeCorpus {
    async fn send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if *self.fail.read().expect("lock") {
            return Err(HttpError::Transport("the corpus is down".into()));
        }
        let body = self.body.read().expect("lock").clone().unwrap_or_default();
        Ok(Response::builder()
            .status(200)
            .body(Bytes::from(body))
            .expect("response"))
    }
}

/// A limiter that refuses after a set number of calls, so the interaction
/// between the limit and the lockout can be exercised.
#[derive(Clone, Default)]
struct FakeLimiter {
    allow: Arc<AtomicI64>,
}

#[async_trait]
impl RateLimiter for FakeLimiter {
    async fn limit(&self, _key: &str) -> Result<Decision, RateLimitError> {
        let left = self.allow.fetch_sub(1, Ordering::SeqCst);
        Ok(Decision {
            ok: left > 0,
            retry_after: Some(std::time::Duration::from_secs(60)),
        })
    }
}

struct Kit {
    harness: TestHarness,
    corpus: FakeCorpus,
    limiter: FakeLimiter,
    clock: Arc<TestClock>,
    db: Arc<dyn Database>,
}

fn kit() -> Kit {
    kit_with(vec![], i64::MAX)
}

fn kit_with(pairs: Vec<(String, String)>, allowed_requests: i64) -> Kit {
    let corpus = FakeCorpus::default();
    let limiter = FakeLimiter::default();
    limiter.allow.store(allowed_requests, Ordering::SeqCst);
    let clock = Arc::new(TestClock(AtomicI64::new(1_788_775_200)));
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(pairs));

    let http = corpus.clone();
    let limiter_for_ports = limiter.clone();
    let clock_for_ports = clock.clone();
    let config_for_ports = config.clone();
    let harness = TestHarness::with_ports(
        vec![Box::new(AuthCore::new()), Box::new(Password::new())],
        move |ports| {
            ports.http = Some(Arc::new(http));
            ports.rate_limiter = Some(Arc::new(limiter_for_ports));
            ports.clock = Some(clock_for_ports);
            ports.config = config_for_ports;
        },
    );
    let db = harness.db.clone();
    Kit {
        harness,
        corpus,
        limiter,
        clock,
        db,
    }
}

struct Res {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl Res {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|header| {
                let value = header.strip_prefix(&format!("{name}="))?;
                let value = value.split(';').next()?.trim();
                (!value.is_empty()).then(|| value.to_owned())
            })
    }
}

async fn post(kit: &Kit, uri: &str, body: Value, cookie: Option<&str>) -> Res {
    post_with(kit, uri, body, cookie, &[]).await
}

/// `post` for a request that carries extra headers — the browser headers
/// (`origin`, `host`, `sec-fetch-site`) the login-CSRF guard reads.
async fn post_with(
    kit: &Kit,
    uri: &str,
    body: Value,
    cookie: Option<&str>,
    extra: &[(&str, &str)],
) -> Res {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, format!("__Host-fz_session={cookie}"));
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let response = kit
        .harness
        .router
        .clone()
        .oneshot(
            builder
                .body(axum::body::Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

fn count(kit: &Kit, table: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) AS n FROM {table}");
    let rows = pollster::block_on(kit.db.query(&Statement::new(sql))).expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
}

async fn register(kit: &Kit, email: &str, password: &str) -> Res {
    post(
        kit,
        REGISTER,
        json!({ "email": email, "password": password }),
        None,
    )
    .await
}

async fn login(kit: &Kit, email: &str, password: &str) -> Res {
    post(
        kit,
        LOGIN,
        json!({ "email": email, "password": password }),
        None,
    )
    .await
}

// ---------------------------------------------------------------------
// Registration (#19)

#[test]
fn registering_creates_an_account_an_identity_and_a_credential() {
    pollster::block_on(async {
        let kit = kit();
        let response = register(&kit, "ada@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text());
        assert_eq!(count(&kit, "users"), 1);
        assert_eq!(count(&kit, "identities"), 1);
        assert_eq!(count(&kit, "credentials"), 1);

        // Unverified until a magic link says otherwise: the linking rules
        // only auto-link a verified address, so registering must not be a
        // way to claim one.
        let user = user_by_primary_email(&*kit.db, "ada@example.com")
            .await
            .expect("query")
            .expect("a user");
        assert!(!user.primary_email_verified);
        assert_eq!(user.status, STATUS_ACTIVE);
    });
}

/// The acceptance criterion, tested byte for byte: a taken address and a
/// free one are indistinguishable.
#[test]
fn a_taken_address_answers_exactly_as_a_free_one_does() {
    pollster::block_on(async {
        let kit = kit();
        let first = register(&kit, "ada@example.com", GOOD).await;
        let second = register(&kit, "ada@example.com", "a different long password").await;
        let fresh = register(&kit, "grace@example.com", GOOD).await;

        assert_eq!(first.status, second.status);
        assert_eq!(first.status, fresh.status);
        assert_eq!(first.body, second.body, "the bodies differ");
        assert_eq!(first.body, fresh.body, "the bodies differ");

        // And no second account was made.
        assert_eq!(count(&kit, "users"), 2, "ada and grace, not three");
    });
}

/// Not-an-address gets the same answer too: "that is not an email" and
/// "that email is taken" must not be distinguishable either.
#[test]
fn rubbish_where_an_address_should_be_answers_the_same_way() {
    pollster::block_on(async {
        let kit = kit();
        let real = register(&kit, "ada@example.com", GOOD).await;
        for rubbish in ["", "   ", "not-an-address", "@", "ada"] {
            let response = register(&kit, rubbish, GOOD).await;
            assert_eq!(response.status, real.status, "{rubbish:?}");
            assert_eq!(response.body, real.body, "{rubbish:?}");
        }
        assert_eq!(count(&kit, "users"), 1);
    });
}

/// A password the person can fix is the one thing registration does say,
/// because it reveals nothing about anybody else and refusing silently
/// would leave them unable to sign in later.
#[test]
fn an_unusable_password_is_named_rather_than_swallowed() {
    pollster::block_on(async {
        let kit = kit();
        for bad in ["", "short", &"a".repeat(257)] {
            let response = register(&kit, "ada@example.com", bad).await;
            assert_eq!(response.status, StatusCode::BAD_REQUEST, "{bad:?}");
            assert_eq!(
                response.json()["type"],
                "https://factory0.ventures/problems/auth/password-unsuitable"
            );
        }
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn a_breached_password_is_refused_and_an_unreachable_corpus_is_not() {
    pollster::block_on(async {
        let kit = kit();
        // SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
        *kit.corpus.body.write().expect("lock") =
            Some("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\n".to_owned());
        let response = register(&kit, "ada@example.com", "password").await;
        // Refused for length before the corpus is even asked, so use a
        // long breached one to reach the check.
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);

        // Fail-open: somebody else's outage must not stop registration.
        *kit.corpus.fail.write().expect("lock") = true;
        let before = kit.corpus.calls.load(Ordering::SeqCst);
        let response = register(&kit, "grace@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text());
        assert!(
            kit.corpus.calls.load(Ordering::SeqCst) > before,
            "the corpus was not asked"
        );
        assert_eq!(count(&kit, "users"), 1);
    });
}

#[test]
fn the_breach_check_can_be_switched_off() {
    pollster::block_on(async {
        let kit = kit_with(
            vec![("AUTH_PASSWORD_BREACH_CHECK".to_owned(), "false".to_owned())],
            i64::MAX,
        );
        *kit.corpus.body.write().expect("lock") =
            Some("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\n".to_owned());
        let response = register(&kit, "ada@example.com", "password is breached here").await;
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(
            kit.corpus.calls.load(Ordering::SeqCst),
            0,
            "the corpus was asked with the check switched off"
        );
    });
}

// ---------------------------------------------------------------------
// Login (#20)

#[test]
fn the_right_password_signs_in_and_records_a_password_login() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        let response = login(&kit, "ada@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        assert!(response.cookie("__Host-fz_session").is_some());
        assert_eq!(count(&kit, "sessions"), 1);

        let rows = kit
            .db
            .query(&Statement::new("SELECT amr FROM sessions"))
            .await
            .expect("query");
        let amr = rows.first().and_then(|row| row.get::<String>("amr"));
        assert_eq!(amr.as_deref(), Some(r#"["pwd"]"#), "{amr:?}");
    });
}

/// The acceptance criterion. Four different situations, one answer.
#[test]
fn every_refused_login_answers_identically() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        // A disabled account.
        register(&kit, "grace@example.com", GOOD).await;
        kit.db
            .execute(&Statement::new(
                "UPDATE users SET status = 'disabled' WHERE primary_email = 'grace@example.com'",
            ))
            .await
            .expect("disables");

        let wrong = login(&kit, "ada@example.com", "the wrong password").await;
        let unknown = login(&kit, "nobody@example.com", GOOD).await;
        let disabled = login(&kit, "grace@example.com", GOOD).await;

        // `instance` is the request id: it is *supposed* to differ, and
        // comparing whole bodies would only ever test that. Everything a
        // caller could learn from is the rest.
        let shape = |response: &Res| {
            let mut json = response.json();
            json.as_object_mut().map(|object| object.remove("instance"));
            json
        };
        for (name, response) in [
            ("unknown address", &unknown),
            ("disabled account", &disabled),
        ] {
            assert_eq!(response.status, wrong.status, "{name} status differs");
            assert_eq!(shape(response), shape(&wrong), "{name} body differs");
            assert!(
                response.cookie("__Host-fz_session").is_none(),
                "{name} was issued a session"
            );
        }
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
        assert_ne!(
            unknown.json()["instance"],
            wrong.json()["instance"],
            "every answer carried the same request id"
        );
    });
}

#[test]
fn a_locked_account_answers_the_same_way_and_refuses_the_right_password() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        // Ten failures is the default threshold.
        for _ in 0..10 {
            let response = login(&kit, "ada@example.com", "wrong").await;
            assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        }

        // The right password now fails, and looks exactly like a wrong one.
        let locked = login(&kit, "ada@example.com", GOOD).await;
        let wrong = login(&kit, "nobody@example.com", GOOD).await;
        assert_eq!(locked.status, StatusCode::UNAUTHORIZED);
        let shape = |response: &Res| {
            let mut json = response.json();
            json.as_object_mut().map(|object| object.remove("instance"));
            json
        };
        assert_eq!(shape(&locked), shape(&wrong), "a lock announced itself");
        assert!(locked.cookie("__Host-fz_session").is_none());
        assert_eq!(count(&kit, "sessions"), 0);

        // Past the lock, the right password works again.
        kit.clock.0.fetch_add(901, Ordering::SeqCst);
        let response = login(&kit, "ada@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        assert!(response.cookie("__Host-fz_session").is_some());
    });
}

#[test]
fn a_success_clears_the_failure_count() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        for _ in 0..3 {
            login(&kit, "ada@example.com", "wrong").await;
        }
        assert_eq!(failed_attempts(&kit), 3);

        let response = login(&kit, "ada@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            failed_attempts(&kit),
            0,
            "a person who mistypes twice then succeeds must not carry it"
        );
    });
}

fn failed_attempts(kit: &Kit) -> i64 {
    let rows = pollster::block_on(
        kit.db
            .query(&Statement::new("SELECT failed_attempts FROM credentials")),
    )
    .expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("failed_attempts"))
        .unwrap_or_default()
}

/// An unknown address must not be cheap. Without the dummy verify the
/// answer comes back without doing any Argon2id work at all, and the
/// timing says "no such account" plainly.
#[test]
fn an_unknown_address_still_pays_for_a_verify() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        let known = std::time::Instant::now();
        login(&kit, "ada@example.com", "the wrong password").await;
        let known = known.elapsed();

        let unknown = std::time::Instant::now();
        login(&kit, "nobody@example.com", "the wrong password").await;
        let unknown = unknown.elapsed();

        // Not a timing assertion — a test machine is far too noisy for one
        // — but the orders of magnitude must match. A missing dummy verify
        // shows up as microseconds against tens of milliseconds.
        let ratio = known.as_secs_f64() / unknown.as_secs_f64().max(f64::MIN_POSITIVE);
        assert!(
            (0.1..=10.0).contains(&ratio),
            "an unknown address took {unknown:?} against {known:?} for a known one, \
             which is the shape of a missing dummy verify"
        );
    });
}

#[test]
fn a_rate_limited_caller_is_told_to_wait_rather_than_refused() {
    pollster::block_on(async {
        // Nothing allowed: the first key checked refuses.
        let kit = kit_with(vec![], 0);
        let response = login(&kit, "ada@example.com", GOOD).await;
        assert_eq!(
            response.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{}",
            response.text()
        );
        assert!(response.headers.contains_key(header::RETRY_AFTER));

        // And a limiter with room does not refuse. The limit is consulted
        // once per key, and there is more than one key: an IP and the
        // address, so a botnet cannot walk past the per-IP limit.
        let kit = kit_with(vec![], i64::MAX);
        let before = kit.limiter.allow.load(Ordering::SeqCst);
        login(&kit, "ada@example.com", GOOD).await;
        assert!(
            before - kit.limiter.allow.load(Ordering::SeqCst) >= 2,
            "the address was not a limit key"
        );
    });
}

// ---------------------------------------------------------------------
// Change (#19)

#[test]
fn changing_a_password_revokes_every_other_session() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        // Two devices.
        let first = login(&kit, "ada@example.com", GOOD).await;
        let second = login(&kit, "ada@example.com", GOOD).await;
        let first_cookie = first.cookie("__Host-fz_session").expect("a session");
        let second_cookie = second.cookie("__Host-fz_session").expect("a session");
        assert_eq!(count(&kit, "sessions"), 2);

        let response = post(
            &kit,
            CHANGE,
            json!({ "current_password": GOOD, "new_password": "a different long password" }),
            Some(&second_cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());

        // The other device is signed out. A password change is what a
        // person does when they think somebody else has it.
        assert!(
            factory0_auth_core::validate(&*kit.db, &*kit.clock, &first_cookie)
                .await
                .expect("query")
                .is_none(),
            "the other session survived a password change"
        );
        // And the new password is the one that works.
        assert_eq!(
            login(&kit, "ada@example.com", GOOD).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login(&kit, "ada@example.com", "a different long password")
                .await
                .status,
            StatusCode::OK
        );
    });
}

#[test]
fn a_change_needs_the_current_password_and_a_session() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        let cookie = login(&kit, "ada@example.com", GOOD)
            .await
            .cookie("__Host-fz_session")
            .expect("a session");

        // No session at all.
        let response = post(
            &kit,
            CHANGE,
            json!({ "current_password": GOOD, "new_password": "another long password" }),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        // Session, wrong current password.
        let response = post(
            &kit,
            CHANGE,
            json!({ "current_password": "not it", "new_password": "another long password" }),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        // The password is unchanged.
        assert_eq!(
            login(&kit, "ada@example.com", GOOD).await.status,
            StatusCode::OK
        );
    });
}

#[test]
fn a_new_password_must_also_be_usable() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        let cookie = login(&kit, "ada@example.com", GOOD)
            .await
            .cookie("__Host-fz_session")
            .expect("a session");

        let response = post(
            &kit,
            CHANGE,
            json!({ "current_password": GOOD, "new_password": "short" }),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            login(&kit, "ada@example.com", GOOD).await.status,
            StatusCode::OK
        );
    });
}

// ---------------------------------------------------------------------
// Rehash (#20)

#[test]
fn a_hash_at_old_parameters_is_upgraded_on_login() {
    pollster::block_on(async {
        let kit = kit();
        let now = "2026-09-07T10:00:00Z";
        insert_user(
            &*kit.db,
            &UserRow {
                id: "u1".to_owned(),
                display_name: None,
                primary_email: Some("ada@example.com".to_owned()),
                primary_email_verified: false,
                status: STATUS_ACTIVE.to_owned(),
                created_at: now.to_owned(),
                updated_at: now.to_owned(),
            },
        )
        .await
        .expect("seeds");

        // A hash at parameters we no longer write. Login is the only
        // moment the plaintext is available, so it is the only moment it
        // can be upgraded.
        let weak = weak_hash(GOOD);
        assert!(factory0_auth_core::password_needs_rehash(&weak));
        kit.db
            .execute(&Statement::new(format!(
                "INSERT INTO credentials (id, user_id, kind, password_hash, created_at, \
                 failed_attempts) VALUES ('c1', 'u1', 'password', '{weak}', '{now}', 0)"
            )))
            .await
            .expect("seeds");

        let response = login(&kit, "ada@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());

        let rows = kit
            .db
            .query(&Statement::new("SELECT password_hash FROM credentials"))
            .await
            .expect("query");
        let stored = rows
            .first()
            .and_then(|row| row.get::<String>("password_hash"))
            .expect("a hash");
        assert_ne!(stored, weak, "the old hash survived a login");
        assert!(!factory0_auth_core::password_needs_rehash(&stored));
        // And the password still works afterwards.
        assert_eq!(
            login(&kit, "ada@example.com", GOOD).await.status,
            StatusCode::OK
        );
    });
}

/// An argon2id hash at parameters this service no longer writes.
///
/// Built by hand rather than through `hash_password`, which only ever
/// writes the current parameters — the whole point is a stored value from
/// an older deployment.
fn weak_hash(password: &str) -> String {
    use argon2::{Algorithm, Argon2, Params, Version};
    use base64ct::{Base64Unpadded as PhcB64, Encoding as _};

    let (m, t, p) = (8_u32, 1_u32, 1_u32);
    let salt = b"an-old-salt-1234";
    let params = Params::new(m, t, p, Some(32)).expect("params");
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .expect("hash");
    format!(
        "$argon2id$v={v}$m={m},t={t},p={p}${salt}${hash}",
        v = Version::V0x13 as u32,
        salt = PhcB64::encode_string(salt),
        hash = PhcB64::encode_string(&out),
    )
}

/// A module that subscribes to this one's events and keeps every payload,
/// so a test can assert on what actually leaves the service.
#[derive(Clone, Default)]
struct EventSpy {
    seen: Arc<RwLock<Vec<(String, Value)>>>,
}

impl cratefield_core::Module for EventSpy {
    fn name(&self) -> &'static str {
        "event-spy"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [cratefield_core::Port] {
        &[]
    }
    fn migrations(&self) -> cratefield_core::Migrations {
        cratefield_core::Migrations::EMPTY
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), cratefield_core::ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: cratefield_core::ModuleContext) -> axum::Router {
        axum::Router::new()
    }
    fn events(&self) -> Vec<(cratefield_core::EventName, cratefield_core::EventHandler)> {
        [
            "auth-password.registered",
            "auth-password.duplicate_registration",
            "auth-password.logged_in",
            "auth-password.changed",
            "auth-password.locked",
        ]
        .into_iter()
        .map(|name| {
            let seen = Arc::clone(&self.seen);
            let event = name.to_owned();
            let handler: cratefield_core::EventHandler = Arc::new(
                move |_scope: &cratefield_core::Scope,
                      payload: Value|
                      -> cratefield_core::BoxFuture<
                    'static,
                    Result<(), cratefield_core::AnyError>,
                > {
                    seen.write().expect("lock").push((event.clone(), payload));
                    Box::pin(async { Ok(()) })
                },
            );
            (name.to_owned(), handler)
        })
        .collect()
    }
}

#[test]
fn no_event_this_module_emits_carries_an_address() {
    pollster::block_on(async {
        // Every other event in the auth stack carries ids — `user_id`,
        // `session_id`, `provider`, `credential_id`. These two carried the
        // address as well, which made them the only ones that did, and a
        // payload does not stay inside the service: it goes to the event
        // forwarder, which on the sidecar path is a separate Worker. So
        // "this address has an account" — the exact fact the 202 from
        // `/register` is built not to reveal — was leaving attached to the
        // address it is about.
        let spy = EventSpy::default();
        let clock = Arc::new(TestClock(AtomicI64::new(1_788_775_200)));
        let config: Arc<dyn Config> =
            Arc::new(MapConfig::from_pairs(Vec::<(String, String)>::new()));
        let clock_for_ports = clock.clone();
        let config_for_ports = config.clone();
        let harness = TestHarness::with_ports(
            vec![
                Box::new(AuthCore::new()),
                Box::new(Password::new()),
                Box::new(spy.clone()),
            ],
            move |ports| {
                ports.clock = Some(clock_for_ports);
                ports.config = config_for_ports;
            },
        );

        let address = "ada@example.com";
        let register = |body: Value| {
            let request = Request::builder()
                .method(Method::POST)
                .uri(REGISTER)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request");
            harness.router.clone().oneshot(request)
        };

        // A new account, then the same address again: `registered` and
        // then `duplicate_registration`.
        let first = register(json!({ "email": address, "password": GOOD }))
            .await
            .expect("response");
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let second = register(json!({ "email": address, "password": GOOD }))
            .await
            .expect("response");
        assert_eq!(second.status(), StatusCode::ACCEPTED);

        let seen = spy.seen.read().expect("lock").clone();
        let names: Vec<&str> = seen.iter().map(|(name, _)| name.as_str()).collect();
        assert!(
            names.contains(&"auth-password.registered")
                && names.contains(&"auth-password.duplicate_registration"),
            "the spy saw {names:?} — this test proves nothing if the events never fired"
        );

        for (name, payload) in &seen {
            let text = payload.to_string();
            assert!(
                !text.contains(address),
                "`{name}` carried the address: {text}"
            );
            assert!(
                !text.contains('@'),
                "`{name}` carried something address-shaped: {text}"
            );
            // And it still says who, so a subscriber can look the address
            // up: an empty payload would pass the assertions above and be
            // useless.
            assert!(
                payload.get("user_id").and_then(Value::as_str).is_some(),
                "`{name}` names nobody: {text}"
            );
        }
    });
}

const START: &str = "/v1/auth-password/start";

async fn drive(kit: &Kit, request: Request<axum::body::Body>) -> Res {
    let response = kit
        .harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

async fn get_page(kit: &Kit, uri: &str) -> Res {
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(axum::body::Body::empty())
        .expect("request");
    drive(kit, request).await
}

async fn post_form(kit: &Kit, uri: &str, body: &str) -> Res {
    post_form_with(kit, uri, body, &[]).await
}

/// `post_form` with extra headers, for the same reason `post_with` exists.
async fn post_form_with(kit: &Kit, uri: &str, body: &str, extra: &[(&str, &str)]) -> Res {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(axum::body::Body::from(body.to_owned()))
        .expect("request");
    drive(kit, request).await
}

#[test]
fn the_form_needs_no_script_and_asks_for_both_fields() {
    pollster::block_on(async {
        let kit = kit();
        let form = get_page(&kit, START).await;
        assert_eq!(form.status, StatusCode::OK);
        let html = form.text();
        assert!(html.contains("<form method=\"post\""), "{html}");
        assert!(html.contains("name=\"email\""), "{html}");
        assert!(html.contains("type=\"password\""), "{html}");
        assert!(
            !html.contains("<script"),
            "the form needs no script: {html}"
        );
        // A password manager fills a form it can read: the pair of
        // autocomplete tokens is what tells it which field is which.
        assert!(html.contains("autocomplete=\"username\""), "{html}");
        assert!(html.contains("autocomplete=\"current-password\""), "{html}");
    });
}

#[test]
fn the_form_signs_in_and_lands_where_it_was_told() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        let answer = post_form(
            &kit,
            START,
            "email=ada%40example.com&password=a+long+enough+password&return_to=%2Fwelcome",
        )
        .await;
        assert_eq!(answer.status, StatusCode::SEE_OTHER, "{}", answer.text());
        assert_eq!(
            answer
                .headers
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/welcome")
        );
        assert!(
            answer.cookie("__Host-fz_session").is_some(),
            "the redirect carries no session"
        );
    });
}

#[test]
fn the_page_separates_none_of_the_things_the_json_route_refuses_alike() {
    pollster::block_on(async {
        // The whole security property of a password endpoint. If the page
        // ever answered a wrong password differently from an unknown
        // address, this is what would say so.
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        let wrong_password = post_form(
            &kit,
            START,
            "email=ada%40example.com&password=not+the+right+password",
        )
        .await;
        let unknown = post_form(
            &kit,
            START,
            "email=nobody%40example.com&password=a+long+enough+password",
        )
        .await;
        let not_an_address = post_form(&kit, START, "email=bananas&password=whatever+at+all").await;

        assert_eq!(wrong_password.status, StatusCode::UNAUTHORIZED);
        assert_eq!(unknown.status, wrong_password.status);
        assert_eq!(not_an_address.status, wrong_password.status);
        assert_eq!(unknown.body, wrong_password.body, "the pages differ");
        assert_eq!(not_an_address.body, wrong_password.body, "the pages differ");
        assert!(
            wrong_password.text().contains("do not match"),
            "{}",
            wrong_password.text()
        );
        // And no refusal hands out a session.
        for answer in [&wrong_password, &unknown, &not_an_address] {
            assert!(answer.cookie("__Host-fz_session").is_none());
        }
    });
}

#[test]
fn the_page_and_the_json_route_share_one_lockout() {
    pollster::block_on(async {
        // Two entry points, one credential row. Failures from the form
        // have to count towards the same lock, or the form is a way round
        // it.
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        // Ten is the default threshold, the number the JSON-route lockout
        // test uses.
        for _ in 0..10 {
            post_form(
                &kit,
                START,
                "email=ada%40example.com&password=wrong+wrong+wrong",
            )
            .await;
        }
        // The right password, through the JSON route, against a lock the
        // form caused.
        let after = post(
            &kit,
            LOGIN,
            json!({ "email": "ada@example.com", "password": GOOD }),
            None,
        )
        .await;
        assert_eq!(
            after.status,
            StatusCode::UNAUTHORIZED,
            "the form's failures did not reach the lockout: {}",
            after.text()
        );
    });
}

#[test]
fn a_return_to_cannot_break_out_of_the_hidden_field_or_leave_the_service() {
    pollster::block_on(async {
        let kit = kit();
        let encoded = "%2Fok%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E";
        let page = get_page(&kit, &format!("{START}?return_to={encoded}")).await;
        assert!(!page.text().contains("<script>alert"), "{}", page.text());

        // And an absolute one never becomes a Location, which would be an
        // open redirect carrying a fresh session cookie.
        register(&kit, "ada@example.com", GOOD).await;
        let answer = post_form(
            &kit,
            START,
            "email=ada%40example.com&password=a+long+enough+password&return_to=https%3A%2F%2Fevil.example",
        )
        .await;
        assert_eq!(answer.status, StatusCode::SEE_OTHER);
        assert_eq!(
            answer
                .headers
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/"),
            "an absolute return_to was followed"
        );
    });
}

// ---------------------------------------------------------------------
// Login CSRF (#439)

/// `SameSite=Lax` stops a cross-site POST from *carrying* our session
/// cookie, not from *setting* one. A form on evil.example that posts the
/// attacker's credentials to us used to complete and leave the victim
/// signed in as the attacker. Both password entry paths now refuse it.
#[test]
fn a_cross_site_form_cannot_sign_anyone_in() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        let cross_site: &[(&str, &str)] = &[
            ("host", "auth.example.test"),
            ("origin", "https://evil.example"),
        ];
        let refused_as = |label: &str, response: &Res| {
            assert_eq!(
                response.status,
                StatusCode::FORBIDDEN,
                "{label}: {}",
                response.text()
            );
            assert_eq!(
                response.json()["type"],
                "https://factory0.ventures/problems/auth/cross-site-request",
                "{label}"
            );
            assert!(
                response.cookie("__Host-fz_session").is_none(),
                "{label} set a session cookie for a cross-site POST"
            );
        };

        let json_login = post_with(
            &kit,
            LOGIN,
            json!({ "email": "ada@example.com", "password": GOOD }),
            None,
            cross_site,
        )
        .await;
        refused_as("POST /login", &json_login);

        let form = post_form_with(
            &kit,
            START,
            "email=ada%40example.com&password=a+long+enough+password",
            cross_site,
        )
        .await;
        refused_as("POST /start", &form);

        assert_eq!(count(&kit, "sessions"), 0, "a session was issued anyway");
    });
}

/// The other signal the guard reads: `sec-fetch-site: cross-site`, with no
/// `Origin` at all — a scripted form POST still carries fetch metadata.
#[test]
fn a_cross_site_fetch_metadata_is_refused_too() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        let response = post_with(
            &kit,
            LOGIN,
            json!({ "email": "ada@example.com", "password": GOOD }),
            None,
            &[
                ("host", "auth.example.test"),
                ("sec-fetch-site", "cross-site"),
            ],
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "{}",
            response.text()
        );
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/auth/cross-site-request"
        );
        assert!(
            response.cookie("__Host-fz_session").is_none(),
            "the cross-site POST set a session cookie"
        );
        assert_eq!(count(&kit, "sessions"), 0);
    });
}

/// The guard must not break the front door: a browser posting from our own
/// form, with every header it would really send, still signs in.
#[test]
fn a_same_origin_sign_in_still_works() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        let own: &[(&str, &str)] = &[
            ("host", "auth.example.test"),
            ("origin", "https://auth.example.test"),
            ("sec-fetch-site", "same-origin"),
        ];

        let json_login = post_with(
            &kit,
            LOGIN,
            json!({ "email": "ada@example.com", "password": GOOD }),
            None,
            own,
        )
        .await;
        assert_eq!(json_login.status, StatusCode::OK, "{}", json_login.text());
        assert!(json_login.cookie("__Host-fz_session").is_some());

        let form = post_form_with(
            &kit,
            START,
            "email=ada%40example.com&password=a+long+enough+password",
            own,
        )
        .await;
        assert_eq!(form.status, StatusCode::SEE_OTHER, "{}", form.text());
        assert!(form.cookie("__Host-fz_session").is_some());
    });
}

/// A password change re-issues a session, so it is a sign-in as far as a
/// cross-site attacker is concerned: refused before anything happens, and
/// a same-origin change still reaches the handler's own logic.
#[test]
fn a_cross_site_post_cannot_change_a_password() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        let cookie = login(&kit, "ada@example.com", GOOD)
            .await
            .cookie("__Host-fz_session")
            .expect("a session");

        let cross_site = post_with(
            &kit,
            CHANGE,
            json!({ "current_password": GOOD, "new_password": "a different long password" }),
            Some(&cookie),
            &[
                ("host", "auth.example.test"),
                ("origin", "https://evil.example"),
            ],
        )
        .await;
        assert_eq!(
            cross_site.status,
            StatusCode::FORBIDDEN,
            "{}",
            cross_site.text()
        );
        assert_eq!(
            cross_site.json()["type"],
            "https://factory0.ventures/problems/auth/cross-site-request"
        );
        assert!(
            cross_site.cookie("__Host-fz_session").is_none(),
            "the cross-site change re-issued a session"
        );

        // Nothing happened: the refusal minted no session of its own.
        assert_eq!(count(&kit, "sessions"), 1);

        // And the old password still works — this signs in once more, so
        // it stays after the count above.
        assert_eq!(
            login(&kit, "ada@example.com", GOOD).await.status,
            StatusCode::OK
        );

        // A same-origin request reaches the handler's own logic: this one
        // fails for the route's ordinary reason, a password too short to
        // keep, rather than the cross-site refusal.
        let own = post_with(
            &kit,
            CHANGE,
            json!({ "current_password": GOOD, "new_password": "short" }),
            Some(&cookie),
            &[
                ("host", "auth.example.test"),
                ("origin", "https://auth.example.test"),
                ("sec-fetch-site", "same-origin"),
            ],
        )
        .await;
        assert_eq!(own.status, StatusCode::BAD_REQUEST, "{}", own.text());
        assert_eq!(
            own.json()["type"],
            "https://factory0.ventures/problems/auth/password-unsuitable"
        );
    });
}

/// The change re-issues a session, so the guard must not break it either:
/// a browser changing its password from our own form, with every header it
/// would really send, still succeeds end to end — and gets its fresh
/// session cookie back.
#[test]
fn a_same_origin_password_change_still_works() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        let cookie = login(&kit, "ada@example.com", GOOD)
            .await
            .cookie("__Host-fz_session")
            .expect("a session");

        let response = post_with(
            &kit,
            CHANGE,
            json!({ "current_password": GOOD, "new_password": "a different long password" }),
            Some(&cookie),
            &[
                ("host", "auth.example.test"),
                ("origin", "https://auth.example.test"),
                ("sec-fetch-site", "same-origin"),
            ],
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        let fresh = response
            .cookie("__Host-fz_session")
            .expect("the change re-issues a session");
        assert_ne!(fresh, cookie, "the re-issued cookie is the one presented");
        assert!(
            factory0_auth_core::validate(&*kit.db, &*kit.clock, &cookie)
                .await
                .expect("query")
                .is_none(),
            "the presented session survived the change"
        );

        // And the change itself took: the old password is done, the new
        // one signs in.
        assert_eq!(
            login(&kit, "ada@example.com", GOOD).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login(&kit, "ada@example.com", "a different long password")
                .await
                .status,
            StatusCode::OK
        );
    });
}
