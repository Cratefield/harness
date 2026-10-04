//! The harness under test: auth-core (schema, sessions, linking) plus the
//! OIDC module, over a migrated in-memory database and a fake provider.

#![allow(dead_code)]

use cratefield_auth_core::AuthCore;
use cratefield_auth_oidc::Oidc;
use cratefield_core::{Clock, Config, Database, IdGen, MapConfig, UlidIdGen};
use cratefield_testing::TestHarness;
use http::StatusCode;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use time::OffsetDateTime;

use crate::support::provider::{APPLE_CLIENT_ID, CLIENT_ID, FakeProvider};

pub const REDIRECT_BASE: &str = "https://auth.acme.example";
pub const START: &str = "/v1/auth-oidc/google/start";
pub const CALLBACK: &str = "/v1/auth-oidc/google/callback";
pub const APPLE_START: &str = "/v1/auth-oidc/apple/start";
pub const APPLE_CALLBACK: &str = "/v1/auth-oidc/apple/callback";
/// The one SSO callback every organization registers (#627).
pub const SSO_CALLBACK: &str = "/v1/auth-oidc/sso/callback";
/// The redirect URI a test client registers, and so the one `/authorize`
/// accepts.
pub const APP_REDIRECT: &str = "https://app.example/auth/callback";
/// The admin token the client-registration API takes (issue #6).
pub const ADMIN: &str = "test-admin-token-0123456789abcdef";
/// 32 bytes of `A`, base64: the key an `sso_connections` secret is sealed
/// under. Fixed, because the only thing under test is the round trip.
pub const SEAL_KEY: &str = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=";

/// A throwaway P-256 key in the PKCS#8 PEM shape Apple issues as a `.p8`.
///
/// Derived from a fixed scalar rather than pasted, so it is certainly a
/// valid key: a hand-written PEM that does not parse makes every Apple
/// test fail as "unconfigured", which points at the wrong thing entirely.
pub fn apple_p8() -> String {
    use p256::pkcs8::EncodePrivateKey as _;
    p256::SecretKey::from_slice(&[7u8; 32])
        .expect("a valid P-256 scalar")
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("encodes")
        .to_string()
}

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

/// Google's settings plus Apple's four (#16). Apple takes no client
/// secret: it is minted from the signing key on every exchange.
pub fn config_pairs_with_apple() -> Vec<(String, String)> {
    let mut pairs = config_pairs();
    pairs.extend([
        (
            "AUTH_OIDC_APPLE_CLIENT_ID".to_owned(),
            APPLE_CLIENT_ID.to_owned(),
        ),
        (
            "AUTH_OIDC_APPLE_TEAM_ID".to_owned(),
            "TEAM123456".to_owned(),
        ),
        ("AUTH_OIDC_APPLE_KEY_ID".to_owned(), "KEY7890123".to_owned()),
        ("AUTH_OIDC_APPLE_PRIVATE_KEY".to_owned(), apple_p8()),
    ]);
    pairs
}

pub fn apple_kit() -> Kit {
    kit_with(config_pairs_with_apple())
}

/// A throwaway P-256 key in the JSON shape `AUTH_CORE_SIGNING_KEYS` takes,
/// so the auth-core half of the kit can mint a code and a token.
pub fn signing_keys_json() -> String {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let secret = p256::SecretKey::from_slice(&[7u8; 32]).expect("a valid scalar");
    let d = Base64UrlUnpadded::encode_string(&secret.to_bytes());
    serde_json::to_string(&vec![
        serde_json::json!({ "kty": "EC", "crv": "P-256", "kid": "k1", "d": d }),
    ])
    .expect("keys json")
}

/// Google's settings plus everything an enterprise SSO sign-in needs
/// (#627): a sealing key for the connection's client secret, a signing key
/// so `/authorize` and `/token` are live, and the admin token that
/// registers the client whose credentials the admin API takes.
pub fn sso_config_pairs() -> Vec<(String, String)> {
    let mut pairs = config_pairs();
    pairs.extend([
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
        ("AUTH_CORE_SSO_TOKEN_KEY".to_owned(), SEAL_KEY.to_owned()),
        ("AUTH_CORE_SIGNING_KEYS".to_owned(), signing_keys_json()),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE".to_owned(), "k1".to_owned()),
        ("AUTH_CORE_ISSUER".to_owned(), REDIRECT_BASE.to_owned()),
    ]);
    pairs
}

pub fn sso_kit() -> Kit {
    kit_with(sso_config_pairs())
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

/// Any method, with an optional `Authorization` header and JSON body. The
/// admin API (#6, #627) is not a `GET` and not form-encoded.
pub async fn send(
    kit: &Kit,
    method: http::Method,
    path: &str,
    authorization: Option<&str>,
    json: Option<&str>,
) -> Res {
    use tower::ServiceExt;
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if let Some(value) = authorization {
        builder = builder.header(http::header::AUTHORIZATION, value);
    }
    let body = match json {
        Some(payload) => {
            builder = builder.header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            axum::body::Body::from(payload.to_owned())
        }
        None => axum::body::Body::empty(),
    };
    let response = kit
        .harness
        .router
        .clone()
        .oneshot(builder.body(body).expect("request"))
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

/// `Authorization: Basic base64(id:secret)`, the credential the SSO admin
/// API takes (#627).
pub fn auth_basic(client_id: &str, secret: &str) -> String {
    use base64ct::{Base64, Encoding as _};
    format!(
        "Basic {}",
        Base64::encode_string(format!("{client_id}:{secret}").as_bytes())
    )
}

/// Registers a confidential client through the admin API and returns the
/// id and the secret that is handed over exactly once.
pub async fn create_client(kit: &Kit, name: &str) -> (String, String) {
    let body = serde_json::json!({
        "name": name,
        "kind": "confidential",
        "redirect_uris": [APP_REDIRECT],
    })
    .to_string();
    let response = send(
        kit,
        http::Method::POST,
        "/v1/auth-core/admin/clients",
        Some(&format!("Bearer {ADMIN}")),
        Some(&body),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    let json = response.json();
    (
        json["id"].as_str().expect("a client id").to_owned(),
        json["client_secret"]
            .as_str()
            .expect("the secret once")
            .to_owned(),
    )
}

/// Registers an enterprise SSO connection for that client.
pub async fn create_connection(
    kit: &Kit,
    client_id: &str,
    secret: &str,
    body: &serde_json::Value,
) -> Res {
    send(
        kit,
        http::Method::POST,
        "/v1/auth-core/sso/connections",
        Some(&auth_basic(client_id, secret)),
        Some(&body.to_string()),
    )
    .await
}

/// A form-encoded `POST`, which is how Apple delivers its authorization
/// response (#16). Cross-site in life; here it is just a POST with a body.
pub async fn post_form(kit: &Kit, path: &str, body: &str) -> Res {
    post_form_with(kit, path, body, &[]).await
}

/// The same, carrying cookies.
pub async fn post_form_with(kit: &Kit, path: &str, body: &str, cookies: &[(&str, &str)]) -> Res {
    use tower::ServiceExt;
    let mut builder = axum::http::Request::builder()
        .method(http::Method::POST)
        .uri(path)
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        );
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
        .oneshot(
            builder
                .body(axum::body::Body::from(body.to_owned()))
                .expect("request"),
        )
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
    start_at(kit, START, query).await
}

/// `/start` for whichever provider the path names.
pub async fn start_at(kit: &Kit, path: &str, query: &str) -> Started {
    let response = get(kit, &format!("{path}{query}"), &[]).await;
    started_from(kit, &response)
}

/// The `start` of one enterprise SSO connection (#627).
pub async fn sso_start(kit: &Kit, connection_id: &str, query: &str) -> Started {
    start_at(
        kit,
        &format!("/v1/auth-oidc/sso/{connection_id}/start"),
        query,
    )
    .await
}

/// Follows the SSO callback the `IdP` would send the browser to.
pub async fn sso_callback(kit: &Kit, started: &Started, code: &str, state: &str) -> Res {
    get(
        kit,
        &format!("{SSO_CALLBACK}?code={code}&state={state}"),
        &[("__Host-fz_oidc", &started.flow_cookie)],
    )
    .await
}

/// Reads a `302` to a provider as the things a test needs from it: the
/// flow cookie, and the state and nonce the module put in the URL.
fn started_from(kit: &Kit, response: &Res) -> Started {
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
        flow_cookie: response.cookie("__Host-auth_oidc").expect("a flow cookie"),
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
        &[("__Host-auth_oidc", &started.flow_cookie)],
    )
    .await
}

pub fn count(kit: &Kit, table: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) AS n FROM {table}");
    let rows =
        pollster::block_on(kit.db.query(&cratefield_core::Statement::new(sql))).expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
}

pub fn column(kit: &Kit, sql: &str, name: &str) -> Option<String> {
    let rows =
        pollster::block_on(kit.db.query(&cratefield_core::Statement::new(sql))).expect("query");
    rows.first().and_then(|row| row.get::<String>(name))
}
