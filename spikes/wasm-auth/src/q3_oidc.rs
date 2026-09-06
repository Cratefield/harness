//! Q3: `openidconnect` through the harness `HttpClient` port.
//!
//! Inside `wrangler dev` the flow runs Google discovery **live** (the real
//! `https://accounts.google.com/.well-known/openid-configuration` through
//! `worker::Fetch`), while the token endpoint and the JWKS endpoint are
//! intercepted to serve recorded fixtures, because no Google client
//! credential exists on the spike machine. The fixture ID token is a
//! Google-shaped RS256 JWT minted by `examples/mint_id_token.rs`.

use std::future::Future;
use std::pin::Pin;

use crate::port::{HttpClient, HttpError};
use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use openidconnect::core::{CoreClient, CoreIdToken, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, IssuerUrl, Nonce, OAuth2TokenResponse as _,
    RedirectUrl, TokenResponse,
};
use serde::Serialize;

pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";
pub const TOKEN_FIXTURE_URL: &str = "https://oauth2.googleapis.com/token";
pub const JWKS_FIXTURE_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

pub const FIXTURE_CLIENT_ID: &str = "spike-fixture-client.apps.googleusercontent.com";
// A labelled placeholder, not a credential: it only ever reaches the
// intercepted fixture response.
pub const FIXTURE_CLIENT_SECRET: &str = "spike-fixture-secret-not-a-real-credential";
pub const FIXTURE_REDIRECT: &str = "http://localhost:8787/q3/callback";
pub const FIXTURE_AUTH_CODE: &str = "spike-fixture-auth-code";
pub const FIXTURE_NONCE: &str = "spike-fixture-nonce";

const TOKEN_RESPONSE_FIXTURE: &str = include_str!("../fixtures/google-token-response.json");
#[cfg(target_arch = "wasm32")]
const JWKS_FIXTURE: &str = include_str!("../fixtures/google-jwks.json");

#[cfg(target_arch = "wasm32")]
fn transport(message: impl std::fmt::Display) -> HttpError {
    HttpError::Transport(message.to_string())
}

/// `HttpClient` port implementation over `worker::Fetch`, with fixture
/// interception on Google's token and JWKS endpoints.
pub struct WorkerHttpClient {
    pub intercept_fixtures: bool,
}

impl WorkerHttpClient {
    #[cfg(target_arch = "wasm32")]
    fn fixture_for(&self, url: &str, method: &str) -> Option<&'static str> {
        if !self.intercept_fixtures {
            return None;
        }
        match (method, url) {
            ("POST", TOKEN_FIXTURE_URL) => Some(TOKEN_RESPONSE_FIXTURE),
            ("GET", JWKS_FIXTURE_URL) => Some(JWKS_FIXTURE),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for WorkerHttpClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        #[cfg(target_arch = "wasm32")]
        {
            self.send_on_wasm(request).await
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (self, request);
            Err(HttpError::Transport(
                "worker::Fetch is only available on wasm32".to_string(),
            ))
        }
    }
}

// The port's async_trait requires a Send future, but every worker/wasm-bindgen
// handle is !Send (single-threaded runtime). The bridge: run the fetch inside
// spawn_local and hand the result back through a Send oneshot channel. The
// harness adapter will need exactly this pattern (recorded in the ADR).
#[cfg(target_arch = "wasm32")]
impl WorkerHttpClient {
    async fn send_on_wasm(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        let url: url::Url = parts.uri.to_string().parse().map_err(transport)?;
        if let Some(fixture) = self.fixture_for(url.as_str(), parts.method.as_str()) {
            return http::Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .header("x-fixture", "recorded")
                .body(Bytes::from(fixture.as_bytes().to_vec()))
                .map_err(transport);
        }

        let (sender, receiver) = futures_channel::oneshot::channel();
        worker::wasm_bindgen_futures::spawn_local(async move {
            let result = fetch_via_worker(parts, body, url).await;
            let _ = sender.send(result);
        });
        receiver
            .await
            .map_err(|_| HttpError::Transport("fetch task dropped".into()))?
    }
}

#[cfg(target_arch = "wasm32")]
async fn fetch_via_worker(
    parts: http::request::Parts,
    body: Bytes,
    url: url::Url,
) -> Result<http::Response<Bytes>, HttpError> {
    let mut init = worker::RequestInit::new();
    init.method = match parts.method {
        http::Method::GET => worker::Method::Get,
        http::Method::POST => worker::Method::Post,
        http::Method::PUT => worker::Method::Put,
        http::Method::PATCH => worker::Method::Patch,
        http::Method::DELETE => worker::Method::Delete,
        http::Method::HEAD => worker::Method::Head,
        http::Method::OPTIONS => worker::Method::Options,
        other => return Err(transport(format!("method {other} not mapped"))),
    };
    for (name, value) in parts.headers.iter() {
        init.headers
            .set(
                name.as_str(),
                value
                    .to_str()
                    .map_err(|e| transport(format!("header {name}: {e}")))?,
            )
            .map_err(transport)?;
    }
    if !body.is_empty() {
        init.body = Some(worker::js_sys::Uint8Array::from(body.as_ref()).into());
    }
    let worker_request = worker::Request::new_with_init(url.as_str(), &init).map_err(transport)?;
    let mut response = worker::Fetch::Request(worker_request)
        .send()
        .await
        .map_err(transport)?;

    let mut builder = http::Response::builder().status(response.status_code());
    for (name, value) in response.headers().entries() {
        builder = builder.header(name, value);
    }
    let bytes = response.bytes().await.map_err(transport)?;
    builder
        .body(Bytes::from(bytes))
        .map_err(|e| transport(e.to_string()))
}

pub enum OidcHttpError {
    Port(HttpError),
}

impl std::fmt::Display for OidcHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OidcHttpError::Port(e) => write!(f, "{e}"),
        }
    }
}
impl std::fmt::Debug for OidcHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OidcHttpError({self})")
    }
}
impl std::error::Error for OidcHttpError {}

/// `oauth2`'s bring-your-own async HTTP client, implemented over the harness
/// `HttpClient` port. This adapter is the piece that transfers unchanged to
/// the real harness crate.
pub struct OidcHttpClient<P: HttpClient> {
    pub port: P,
}

impl<'c, P: HttpClient> openidconnect::AsyncHttpClient<'c> for OidcHttpClient<P> {
    type Error = OidcHttpError;
    type Future =
        Pin<Box<dyn Future<Output = Result<openidconnect::HttpResponse, Self::Error>> + 'c>>;

    fn call(&'c self, request: openidconnect::HttpRequest) -> Self::Future {
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let port_request = http::Request::from_parts(parts, Bytes::from(body));
            let response = self
                .port
                .send(port_request)
                .await
                .map_err(OidcHttpError::Port)?;
            let (parts, body) = response.into_parts();
            Ok(http::Response::from_parts(parts, body.to_vec()))
        })
    }
}

#[derive(Serialize)]
pub struct OidcStep {
    pub step: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct OidcReport {
    pub steps: Vec<OidcStep>,
    pub subject: Option<String>,
    email: Option<String>,
}

impl OidcReport {
    fn with_identity(steps: Vec<OidcStep>, subject: String, email: Option<String>) -> Self {
        OidcReport {
            steps,
            subject: Some(subject),
            email,
        }
    }

    fn steps_only(steps: Vec<OidcStep>) -> Self {
        OidcReport {
            steps,
            subject: None,
            email: None,
        }
    }
}

fn ok(step: &'static str, detail: String) -> OidcStep {
    OidcStep {
        step,
        ok: true,
        detail,
    }
}

fn fail(step: &'static str, detail: String) -> OidcStep {
    OidcStep {
        step,
        ok: false,
        detail,
    }
}

pub fn fixture_id_token() -> Result<CoreIdToken, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(TOKEN_RESPONSE_FIXTURE).map_err(|e| format!("token fixture: {e}"))?;
    let token = parsed["id_token"]
        .as_str()
        .ok_or("token fixture missing id_token")?;
    token.parse().map_err(|e| format!("id_token parse: {e}"))
}

/// Runs discovery (live), token exchange (fixture), and ID-token
/// verification (fixture JWKS), collecting one step report per phase.
pub async fn run_oidc_flow<P, F>(port: P, now: F) -> OidcReport
where
    P: HttpClient,
    F: Fn() -> DateTime<Utc> + Send + Sync + 'static,
{
    let http = OidcHttpClient { port };
    let mut steps = Vec::new();

    let issuer = match IssuerUrl::new(GOOGLE_ISSUER.to_string()) {
        Ok(issuer) => issuer,
        Err(e) => {
            steps.push(fail("discovery", format!("issuer url: {e}")));
            return OidcReport::steps_only(steps);
        }
    };

    let metadata = match CoreProviderMetadata::discover_async(issuer, &http).await {
        Ok(metadata) => {
            steps.push(ok(
                "discovery",
                format!(
                    "live Google document: issuer {}, token endpoint {}, {} JWKS keys",
                    metadata.issuer().url(),
                    metadata
                        .token_endpoint()
                        .map(|url| url.url().as_str())
                        .unwrap_or("<none>"),
                    metadata.jwks().keys().len()
                ),
            ));
            metadata
        }
        Err(e) => {
            steps.push(fail("discovery", e.to_string()));
            return OidcReport::steps_only(steps);
        }
    };

    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(FIXTURE_CLIENT_ID.to_string()),
        Some(ClientSecret::new(FIXTURE_CLIENT_SECRET.to_string())),
    )
    .set_redirect_uri(RedirectUrl::new(FIXTURE_REDIRECT.to_string()).expect("fixture redirect"));

    let token_request = client.exchange_code(AuthorizationCode::new(FIXTURE_AUTH_CODE.to_string()));
    let token_request = match token_request {
        Ok(request) => request,
        Err(e) => {
            steps.push(fail("token-exchange", format!("request build: {e}")));
            return OidcReport::steps_only(steps);
        }
    };
    let token_response = match token_request.request_async(&http).await {
        Ok(response) => {
            steps.push(ok(
                "token-exchange",
                format!(
                    "fixture response via intercepted token endpoint: access_token {} bytes, id_token {}",
                    response.access_token().secret().len(),
                    if response.id_token().is_some() {
                        "present"
                    } else {
                        "absent"
                    }
                ),
            ));
            response
        }
        Err(e) => {
            steps.push(fail("token-exchange", e.to_string()));
            return OidcReport::steps_only(steps);
        }
    };

    let Some(id_token) = token_response.id_token() else {
        steps.push(fail(
            "id-token-verify",
            "no id_token in token response".into(),
        ));
        return OidcReport::steps_only(steps);
    };

    let verifier = client.id_token_verifier().set_time_fn(now);
    let expected_nonce = Nonce::new(FIXTURE_NONCE.to_string());
    match id_token.claims(&verifier, &expected_nonce) {
        Ok(claims) => {
            steps.push(ok(
                "id-token-verify",
                "RS256 signature verified against fixture JWKS; issuer, audience, expiry and nonce matched"
                    .into(),
            ));
            OidcReport::with_identity(
                steps,
                claims.subject().to_string(),
                claims.email().map(|email| email.to_string()),
            )
        }
        Err(e) => {
            steps.push(fail("id-token-verify", e.to_string()));
            OidcReport::steps_only(steps)
        }
    }
}

pub fn worker_now() -> DateTime<Utc> {
    DateTime::from_timestamp_millis(worker::Date::now().as_millis() as i64).unwrap_or_else(Utc::now)
}

pub fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
