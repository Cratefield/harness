//! The harness under test: auth-core (schema, sessions, linking) plus the
//! OIDC module, over a migrated in-memory database and a fake provider.

#![allow(dead_code)]

use factory0_auth_core::AuthCore;
use factory0_auth_oidc::Oidc;
use factory0_core::{Clock, Config, Database, IdGen, MapConfig, UlidIdGen};
use factory0_testing::TestHarness;
use http::StatusCode;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use time::OffsetDateTime;

use crate::support::provider::{CLIENT_ID, FakeProvider};

pub const REDIRECT_BASE: &str = "https://auth.factory0.ventures";
pub const START: &str = "/v1/auth-oidc/google/start";
pub const CALLBACK: &str = "/v1/auth-oidc/google/callback";

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
    pub provider: FakeProvider,
    pub clock: Arc<TestClock>,
    pub db: Arc<dyn Database>,
    pub id_gen: Arc<dyn IdGen>,
}

pub fn config_pairs() -> Vec<(String, String)> {
    vec![
        (
            "AUTH_OIDC_REDIRECT_BASE".to_owned(),
            REDIRECT_BASE.to_owned(),
        ),
        (
            "AUTH_OIDC_GOOGLE_CLIENT_ID".to_owned(),
            CLIENT_ID.to_owned(),
        ),
        (
            "AUTH_OIDC_GOOGLE_CLIENT_SECRET".to_owned(),
            "test-client-secret".to_owned(),
        ),
    ]
}

pub fn kit() -> Kit {
    kit_with(config_pairs())
}

pub fn kit_with(pairs: Vec<(String, String)>) -> Kit {
    let provider = FakeProvider::new();
    let clock = TestClock::new();
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(pairs));

    let http = provider.clone();
    let clock_for_ports = clock.clone();
    let config_for_ports = config.clone();
    let harness = TestHarness::with_ports(
        vec![Box::new(AuthCore::new()), Box::new(Oidc::new())],
        move |ports| {
            ports.http = Some(Arc::new(http));
            ports.clock = Some(clock_for_ports);
            ports.config = config_for_ports;
        },
    );
    let db = harness.db.clone();
    Kit {
        harness,
        provider,
        clock,
        db,
        id_gen: Arc::new(UlidIdGen),
    }
}

pub struct Res {
    pub status: StatusCode,
    pub headers: http::HeaderMap,
    pub body: Vec<u8>,
}

impl Res {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub fn location(&self) -> Option<String> {
        self.headers
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

    /// Every `Set-Cookie` on the response.
    pub fn cookies(&self) -> Vec<String> {
        self.headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_owned)
            .collect()
    }

    /// The value of one cookie, when the response sets it to something.
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.cookies().into_iter().find_map(|header| {
            let value = header.strip_prefix(&format!("{name}="))?;
            let value = value.split(';').next()?.trim();
            (!value.is_empty()).then(|| value.to_owned())
        })
    }
}

pub async fn get(kit: &Kit, path: &str, cookies: &[(&str, &str)]) -> Res {
    use tower::ServiceExt;
    let mut builder = axum::http::Request::builder()
        .method(http::Method::GET)
        .uri(path);
    if !cookies.is_empty() {
        let joined = cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        builder = builder.header(http::header::COOKIE, joined);
    }
    let response = kit
        .harness
        .router
        .clone()
        .oneshot(builder.body(axum::body::Body::empty()).expect("request"))
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

/// What `/start` produced: the flow cookie, and the state and nonce the
/// module put in the authorization URL.
pub struct Started {
    pub flow_cookie: String,
    pub state: String,
    pub nonce: String,
    pub authorization_url: String,
}

pub async fn start(kit: &Kit, query: &str) -> Started {
    let response = get(kit, &format!("{START}{query}"), &[]).await;
    assert_eq!(
        response.status,
        StatusCode::FOUND,
        "start did not redirect: {}",
        response.text()
    );
    let url = response.location().expect("a Location header");
    let parsed = url::Url::parse(&url).expect("an absolute authorization url");
    let param = |name: &str| {
        parsed
            .query_pairs()
            .find(|(key, _)| key == name)
            .map_or_else(
                || panic!("no {name} in {url}"),
                |(_, value)| value.to_string(),
            )
    };
    let started = Started {
        flow_cookie: response.cookie("__Host-fz_oidc").expect("a flow cookie"),
        state: param("state"),
        nonce: param("nonce"),
        authorization_url: url,
    };
    // A real provider echoes the nonce into the ID token; so does the fake,
    // unless a test overrides it.
    kit.provider.set_nonce(&started.nonce);
    started
}

/// Follows the callback the provider would send the browser to.
pub async fn callback(kit: &Kit, started: &Started, code: &str, state: &str) -> Res {
    get(
        kit,
        &format!("{CALLBACK}?code={code}&state={state}"),
        &[("__Host-fz_oidc", &started.flow_cookie)],
    )
    .await
}

pub fn count(kit: &Kit, table: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) AS n FROM {table}");
    let rows =
        pollster::block_on(kit.db.query(&factory0_core::Statement::new(sql))).expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
}

pub fn column(kit: &Kit, sql: &str, name: &str) -> Option<String> {
    let rows =
        pollster::block_on(kit.db.query(&factory0_core::Statement::new(sql))).expect("query");
    rows.first().and_then(|row| row.get::<String>(name))
}
