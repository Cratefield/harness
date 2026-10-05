//! Helpers shared by `password.rs` and `recovery.rs`.
//!
//! Both suites drive the same router over the same harness and assert on
//! the same two things — the answer a caller gets, and the rows it left
//! behind — so the request builders, the row readers and the event spy
//! live here once rather than twice.
//!
//! `#![allow(dead_code)]`: this module is compiled into each test binary
//! separately, and no single binary uses every helper.

#![allow(dead_code)]

use cratefield_core::{MapConfig, Module, Statement};
use cratefield_testing::TestHarness;
use http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

/// A registered account's password in the happy-path tests.
pub(crate) const GOOD: &str = "a long enough password";

// ---------------------------------------------------------------------------
// Requests

pub(crate) struct Res {
    pub(crate) status: StatusCode,
    pub(crate) headers: http::HeaderMap,
    pub(crate) body: Vec<u8>,
}

impl Res {
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    pub(crate) fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|value| {
                let value = value.strip_prefix(&format!("{name}="))?;
                let value = value.split(';').next()?.trim();
                (!value.is_empty()).then(|| value.to_owned())
            })
    }
}

/// One request, whatever its shape. `content_type` is `None` for a GET.
pub(crate) async fn send(
    kit: &TestHarness,
    method: Method,
    uri: &str,
    content_type: Option<&str>,
    body: &str,
    extra: &[(&str, &str)],
) -> Res {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let response = kit
        .router
        .clone()
        .oneshot(
            builder
                .body(axum::body::Body::from(body.to_owned()))
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

pub(crate) async fn get(kit: &TestHarness, uri: &str) -> Res {
    send(kit, Method::GET, uri, None, "", &[]).await
}

pub(crate) async fn post_json(kit: &TestHarness, uri: &str, body: Value) -> Res {
    post_json_with(kit, uri, body, &[]).await
}

/// A JSON POST carrying extra headers — a session cookie, or the browser
/// headers (`origin`, `host`, `sec-fetch-site`) the CSRF guard reads.
pub(crate) async fn post_json_with(
    kit: &TestHarness,
    uri: &str,
    body: Value,
    extra: &[(&str, &str)],
) -> Res {
    send(
        kit,
        Method::POST,
        uri,
        Some("application/json"),
        &body.to_string(),
        extra,
    )
    .await
}

/// A form-encoded POST from an already-encoded body.
pub(crate) async fn post_form(kit: &TestHarness, uri: &str, body: &str) -> Res {
    post_form_with(kit, uri, body, &[]).await
}

pub(crate) async fn post_form_with(
    kit: &TestHarness,
    uri: &str,
    body: &str,
    extra: &[(&str, &str)],
) -> Res {
    send(
        kit,
        Method::POST,
        uri,
        Some("application/x-www-form-urlencoded"),
        body,
        extra,
    )
    .await
}

/// A form-encoded POST built from fields. The values are tokens,
/// passwords and addresses; nothing here needs a percent encoder except
/// the address, which is escaped for the `@`.
pub(crate) async fn post_form_fields(kit: &TestHarness, uri: &str, fields: &[(&str, &str)]) -> Res {
    let body = fields
        .iter()
        .map(|(key, value)| format!("{key}={}", percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    post_form(kit, uri, &body).await
}

fn percent_encode(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

pub(crate) async fn register(kit: &TestHarness, email: &str, password: &str) -> Res {
    post_json(
        kit,
        REGISTER,
        json!({ "email": email, "password": password }),
    )
    .await
}

pub(crate) async fn login(kit: &TestHarness, email: &str, password: &str) -> Res {
    post_json(kit, LOGIN, json!({ "email": email, "password": password })).await
}

pub(crate) const REGISTER: &str = "/v1/auth-password/register";
pub(crate) const LOGIN: &str = "/v1/auth-password/login";

// ---------------------------------------------------------------------------
// Database helpers

pub(crate) fn scalar(kit: &TestHarness, sql: &str) -> i64 {
    let rows = pollster::block_on(kit.db.query(&Statement::new(sql.to_owned()))).expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
}

pub(crate) fn exec(kit: &TestHarness, sql: &str) {
    pollster::block_on(kit.db.execute(&Statement::new(sql.to_owned()))).expect("execute");
}

pub(crate) fn user_id_of(kit: &TestHarness, email: &str) -> String {
    pollster::block_on(cratefield_auth_core::user_by_primary_email(&*kit.db, email))
        .expect("query")
        .expect("a user")
        .id
}

pub(crate) fn verified(kit: &TestHarness, email: &str) -> bool {
    pollster::block_on(cratefield_auth_core::user_by_primary_email(&*kit.db, email))
        .expect("query")
        .expect("a user")
        .primary_email_verified
}

/// Config pairs that turn this module's mail on: a public base the links
/// point at, and a `From` address.
pub(crate) fn mail_config() -> Vec<(String, String)> {
    vec![
        (
            "AUTH_PASSWORD_PUBLIC_BASE".to_owned(),
            "https://auth.example.test".to_owned(),
        ),
        (
            "AUTH_PASSWORD_MAIL_FROM".to_owned(),
            "auth@example.test".to_owned(),
        ),
    ]
}

pub(crate) fn config_with(extra: Vec<(String, String)>) -> Arc<dyn cratefield_core::Config> {
    let mut pairs = mail_config();
    pairs.extend(extra);
    Arc::new(MapConfig::from_pairs(pairs))
}

// ---------------------------------------------------------------------------
// Event spy

/// A module that subscribes to the events a test names and keeps every
/// payload, so a test can assert on what actually leaves the service.
#[derive(Clone, Default)]
pub(crate) struct EventSpy {
    pub(crate) seen: Arc<RwLock<Vec<(String, Value)>>>,
    events: &'static [&'static str],
}

impl EventSpy {
    pub(crate) fn new(events: &'static [&'static str]) -> Self {
        Self {
            seen: Arc::default(),
            events,
        }
    }
}

impl Module for EventSpy {
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
    fn validate_config(
        &self,
        _cfg: &dyn cratefield_core::Config,
    ) -> Result<(), cratefield_core::ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: cratefield_core::ModuleContext) -> axum::Router {
        axum::Router::new()
    }
    fn events(&self) -> Vec<(cratefield_core::EventName, cratefield_core::EventHandler)> {
        self.events
            .iter()
            .map(|name| {
                let seen = Arc::clone(&self.seen);
                let event = (*name).to_owned();
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
                ((*name).to_owned(), handler)
            })
            .collect()
    }
}
