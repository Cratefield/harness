//! The harness under test: auth-core (which owns the schema and the
//! migrations) plus the passkeys module, over a migrated in-memory database.

#![allow(dead_code)]

use factory0_auth_core::{AuthCore, Login, UserRow, insert_user, issue};
use factory0_auth_passkeys::Passkeys;
use factory0_core::{Clock, Config, Database, IdGen, MapConfig, UlidIdGen};
use factory0_testing::TestHarness;
use http::StatusCode;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use time::OffsetDateTime;

pub const RP_ID: &str = "auth.factory0.ventures";
pub const ORIGIN: &str = "https://auth.factory0.ventures";
pub const OTHER_ORIGIN: &str = "https://evil.example";

/// A clock a test can move: challenge expiry only means something if time
/// can pass.
pub struct TestClock(AtomicI64);

impl TestClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(1_788_775_200)))
    }

    pub fn advance_secs(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("in range")
    }
}

pub struct Kit {
    pub harness: TestHarness,
    pub db: Arc<dyn Database>,
    pub clock: Arc<TestClock>,
    pub id_gen: Arc<dyn IdGen>,
}

pub fn config_pairs() -> Vec<(String, String)> {
    vec![
        ("AUTH_PASSKEYS_RP_ID".to_owned(), RP_ID.to_owned()),
        ("AUTH_PASSKEYS_ORIGINS".to_owned(), ORIGIN.to_owned()),
        (
            "AUTH_PASSKEYS_RP_NAME".to_owned(),
            "Factory Zero".to_owned(),
        ),
    ]
}

pub fn kit() -> Kit {
    kit_with(config_pairs())
}

pub fn kit_with(pairs: Vec<(String, String)>) -> Kit {
    let clock = TestClock::new();
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(pairs));
    let clock_for_ports = clock.clone();
    let config_for_ports = config.clone();
    // auth-core is in the module list because it owns the schema: without
    // it there are no `credentials` or `single_use_tokens` tables to write.
    let harness = TestHarness::with_ports(
        vec![Box::new(AuthCore::new()), Box::new(Passkeys::new())],
        move |ports| {
            ports.clock = Some(clock_for_ports);
            ports.config = config_for_ports;
        },
    );
    let db = harness.db.clone();
    Kit {
        harness,
        db,
        clock,
        id_gen: Arc::new(UlidIdGen),
    }
}

impl Kit {
    /// An account with a verified email and nothing else.
    pub async fn user(&self, email: &str) -> String {
        let id = self.id_gen.ulid();
        let now = "2026-09-07T10:00:00Z".to_owned();
        insert_user(
            &*self.db,
            &UserRow {
                id: id.clone(),
                display_name: None,
                primary_email: Some(email.to_owned()),
                primary_email_verified: true,
                status: "active".to_owned(),
                created_at: now.clone(),
                updated_at: now,
            },
        )
        .await
        .expect("user inserts");
        id
    }

    /// A session cookie value for that account.
    pub async fn sign_in(&self, user_id: &str) -> String {
        issue(
            &*self.db,
            &*self.clock,
            &*self.id_gen,
            Login {
                user_id,
                ip: None,
                user_agent: None,
                presented_cookie: None,
                amr: &["test"],
            },
        )
        .await
        .expect("session issues")
        .value
    }
}

pub struct Res {
    pub status: StatusCode,
    pub headers: http::HeaderMap,
    pub body: Vec<u8>,
}

impl Res {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|err| {
            panic!(
                "body is not JSON ({err}): {}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn set_cookie(&self) -> Option<String> {
        self.headers
            .get(http::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }
}

/// Sends a request through the router, optionally carrying a session cookie.
pub async fn send(
    kit: &Kit,
    method: http::Method,
    path: &str,
    body: Option<&str>,
    cookie: Option<&str>,
) -> Res {
    use tower::ServiceExt;
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(http::header::COOKIE, format!("__Host-fz_session={cookie}"));
    }
    let request = match body {
        Some(body) => builder
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_owned()))
            .expect("request"),
        None => builder.body(axum::body::Body::empty()).expect("request"),
    };
    let response = kit
        .harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 4 * 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

pub async fn post(kit: &Kit, path: &str, body: &str, cookie: Option<&str>) -> Res {
    send(kit, http::Method::POST, path, Some(body), cookie).await
}

/// The challenge bytes out of an options response.
pub fn challenge_of(options: &Value) -> Vec<u8> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let encoded = options["publicKey"]["challenge"]
        .as_str()
        .unwrap_or_else(|| panic!("no challenge in {options}"));
    Base64UrlUnpadded::decode_vec(encoded).expect("challenge is base64url")
}
