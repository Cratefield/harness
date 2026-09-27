//! The token endpoint: exchange, refresh, revoke.

use base64::Engine as _;
use bytes::Bytes;
use cratefield_core::{HttpClient, HttpError};
use http::{HeaderMap, Method, Request, header};
use serde::Deserialize;
use thiserror::Error;

use crate::config::{ClientAuth, ProviderConfig, form_encode};

/// What went wrong with an OAuth call, in the shape a caller branches on.
#[derive(Debug, Error)]
pub enum OAuthError {
    /// The network, or a port failure (cap, deadline, refused destination).
    #[error("transport: {0}")]
    Transport(#[from] HttpError),
    /// The provider answered with an error; see [`ProviderError`] for what
    /// it carries.
    #[error(transparent)]
    Provider(#[from] Box<ProviderError>),
    /// A success whose body was not the JSON the contract says.
    #[error("unexpected token response: {0}")]
    Decode(String),
    /// The caller's own configuration is incomplete: a client auth method
    /// that needs a secret was configured without one.
    #[error("oauth client is misconfigured: {0}")]
    Config(String),
    /// [`OAuthClient::revoke`](crate::OAuthClient::revoke) was called on a
    /// [`ProviderConfig`] that names no revocation endpoint.
    #[error("no revocation endpoint is configured for this provider")]
    NoRevokeEndpoint,
}

impl OAuthError {
    /// RFC 6749 §5.2's `invalid_grant`: the authorization code or refresh
    /// token is invalid, expired or revoked. The one code that means
    /// "the human must authorize again" and not "try again later".
    #[must_use]
    pub fn is_invalid_grant(&self) -> bool {
        matches!(self, OAuthError::Provider(error) if error.code == "invalid_grant")
    }
}

/// The provider's answer when a token call fails. `code` and `description`
/// are the RFC 6749 §5.2 `error` / `error_description` pair when the body
/// was JSON; `body` is the raw response either way, because providers put
/// provider-specific meaning in that prose — LinkedIn names a dead refresh
/// token only in the description, never in the code.
#[derive(Error)]
#[error("provider answered {status} ({code}): {description}")]
pub struct ProviderError {
    /// HTTP status the provider answered with.
    pub status: u16,
    /// The RFC 6749 §5.2 `error` code, empty when the body was not JSON.
    pub code: String,
    /// The `error_description`, empty when the body was not JSON.
    pub description: String,
    /// The response body, verbatim.
    pub body: String,
    /// The response headers — `Retry-After` on a 429, provider trace ids.
    pub headers: HeaderMap,
}

impl std::fmt::Debug for ProviderError {
    /// Errors end up in logs, and a provider error body can echo the very
    /// token that was refused — so the body is sized, never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderError")
            .field("status", &self.status)
            .field("code", &self.code)
            .field("description", &self.description)
            .field(
                "body",
                &format_args!("<redacted {} bytes>", self.body.len()),
            )
            .field("headers", &self.headers)
            .finish()
    }
}

/// The token endpoint's answer (RFC 6749 §5.1), with the fields providers
/// actually add. Everything but the access token is optional or defaulted:
/// providers omit what does not apply, and a missing `expires_in` must not
/// become an error the caller has to defend against.
#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    /// The bearer credential every provider sends.
    pub access_token: String,
    /// Usually `Bearer`; the RFC says treat it as case-insensitive advice.
    pub token_type: Option<String>,
    /// Access-token lifetime in seconds. `0` when the provider omits it.
    #[serde(default, deserialize_with = "de_expiry")]
    pub expires_in: i64,
    /// May be absent on a refresh: some providers rotate, some do not.
    pub refresh_token: Option<String>,
    /// The refresh token's own lifetime, when a provider gives one — and
    /// when it does, it does not extend on use, so store it, never recompute.
    #[serde(default, deserialize_with = "de_expiry_opt")]
    pub refresh_token_expires_in: Option<i64>,
    /// The scopes granted, which may be fewer than those requested.
    #[serde(default)]
    pub scope: String,
}

impl std::fmt::Debug for TokenResponse {
    /// Token responses are logged by everything that touches them; both
    /// secrets are named, never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// The seconds fields, `expires_in` and `refresh_token_expires_in`: a JSON
/// number per RFC 6749 §5.1, but providers quote them, so a numeric string
/// is accepted too. `null` counts as absent, like a field left out.
fn de_expiry<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    Ok(de_expiry_opt(deserializer)?.unwrap_or(0))
}

fn de_expiry_opt<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i64>, D::Error> {
    deserializer.deserialize_any(Expiry)
}

struct Expiry;

impl serde::de::Visitor<'_> for Expiry {
    type Value = Option<i64>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an integer or a numeric string of seconds")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_i64<E: serde::de::Error>(self, seconds: i64) -> Result<Self::Value, E> {
        Ok(Some(seconds))
    }

    fn visit_u64<E: serde::de::Error>(self, seconds: u64) -> Result<Self::Value, E> {
        i64::try_from(seconds)
            .map(Some)
            .map_err(serde::de::Error::custom)
    }

    fn visit_str<E: serde::de::Error>(self, seconds: &str) -> Result<Self::Value, E> {
        seconds
            .trim()
            .parse::<i64>()
            .map(Some)
            .map_err(serde::de::Error::custom)
    }
}

impl TokenResponse {
    /// The refresh token now in force after a refresh: the one this response
    /// carries, or `previous` when the provider rotated nothing. Call it
    /// before storing, so a provider that omits the field cannot be read as
    /// "delete the refresh token".
    #[must_use]
    pub fn rotated_refresh_token<'a>(&'a self, previous: &'a str) -> &'a str {
        self.refresh_token.as_deref().unwrap_or(previous)
    }
}

/// Speaks one provider's token endpoint over an [`HttpClient`]. Cheap to
/// build, holds nothing but the two references it is given.
pub struct OAuthClient<'a> {
    http: &'a dyn HttpClient,
    config: &'a ProviderConfig,
}

impl<'a> OAuthClient<'a> {
    /// A client for `config`, sending through `http`.
    #[must_use]
    pub fn new(http: &'a dyn HttpClient, config: &'a ProviderConfig) -> Self {
        Self { http, config }
    }

    /// The second leg of the authorization-code flow (RFC 6749 §4.1.3):
    /// the code from the callback for an access token. `pkce_verifier` is
    /// the [`Pkce::verifier`](crate::Pkce::verifier) behind the challenge
    /// that went on the authorize URL, when PKCE is in play.
    ///
    /// # Errors
    ///
    /// Transport failures, the provider's own refusal (most often
    /// `invalid_grant` for a spent or forged code), an unparseable success
    /// body, or a configuration missing its secret.
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("redirect_uri", redirect_uri.to_owned()),
        ];
        if let Some(verifier) = pkce_verifier {
            form.push(("code_verifier", verifier.to_owned()));
        }
        self.token_call(form).await
    }

    /// Exchanges a refresh token for a fresh access token (RFC 6749 §6).
    /// Check [`TokenResponse::rotated_refresh_token`] afterwards: a response
    /// without a refresh token means keep the old one, not discard it.
    ///
    /// # Errors
    ///
    /// Transport failures, the provider's own refusal (most often
    /// `invalid_grant` for a dead refresh token), an unparseable success
    /// body, or a configuration missing its secret.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, OAuthError> {
        self.token_call(vec![
            ("grant_type", "refresh_token".to_owned()),
            ("refresh_token", refresh_token.to_owned()),
        ])
        .await
    }

    /// Revokes a token (RFC 7009); `token_type_hint` is `access_token` or
    /// `refresh_token` where the provider documents hints. Success is a 2xx,
    /// and per the RFC that is a 200 even for an already-revoked token:
    /// revocation is idempotent by design.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::NoRevokeEndpoint`] when the [`ProviderConfig`]
    /// names no revocation endpoint, and the usual transport / provider /
    /// decode errors otherwise.
    pub async fn revoke(&self, token: &str, token_type_hint: &str) -> Result<(), OAuthError> {
        let Some(url) = self.config.revoke_url.as_deref() else {
            return Err(OAuthError::NoRevokeEndpoint);
        };
        let form = self.form(vec![
            ("token", token.to_owned()),
            ("token_type_hint", token_type_hint.to_owned()),
        ])?;
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(basic) = self.basic_header()? {
            builder = builder.header(header::AUTHORIZATION, basic);
        }
        let request = builder
            .body(Bytes::from(form))
            .map_err(|err| OAuthError::Transport(HttpError::Transport(err.to_string())))?;
        let response = self.http.send(request).await?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(provider_error(&response))
    }

    /// The form body for a token-endpoint call, with the credentials where
    /// [`ClientAuth`] says they go — and in one place only: RFC 6749 §2.3.1
    /// names one method per call, so under Basic the client id rides in the
    /// `Authorization` header and the body goes without it. The secret is
    /// added here, not by the callers, so no grant can forget it and no
    /// caller can log the form with the secret missing.
    fn form(&self, mut params: Vec<(&str, String)>) -> Result<String, OAuthError> {
        if self.config.client_auth == ClientAuth::ClientSecretPost {
            params.push(("client_id", self.config.client_id.clone()));
            params.push(("client_secret", self.secret()?.to_owned()));
        }
        Ok(params
            .iter()
            .map(|(name, value)| format!("{name}={}", form_encode(value)))
            .collect::<Vec<_>>()
            .join("&"))
    }

    /// The `Authorization` header value for Basic client auth, or `None`
    /// when the provider takes its credentials in the form body instead.
    fn basic_header(&self) -> Result<Option<String>, OAuthError> {
        if self.config.client_auth != ClientAuth::ClientSecretBasic {
            return Ok(None);
        }
        // RFC 6749 §2.3.1: both halves are form-urlencoded before the
        // colon, and the join is standard base64.
        let credentials = format!(
            "{}:{}",
            form_encode(&self.config.client_id),
            form_encode(self.secret()?)
        );
        Ok(Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        )))
    }

    fn secret(&self) -> Result<&str, OAuthError> {
        self.config.client_secret.as_deref().ok_or_else(|| {
            OAuthError::Config("the configured client auth needs a client_secret".to_owned())
        })
    }

    async fn token_call(&self, form: Vec<(&str, String)>) -> Result<TokenResponse, OAuthError> {
        let body = self.form(form)?;
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(&self.config.token_url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json");
        if let Some(basic) = self.basic_header()? {
            request = request.header(header::AUTHORIZATION, basic);
        }
        let request = request
            .body(Bytes::from(body))
            .map_err(|err| OAuthError::Transport(HttpError::Transport(err.to_string())))?;
        let response = self.http.send(request).await?;
        if !response.status().is_success() {
            return Err(provider_error(&response));
        }
        serde_json::from_slice(response.body())
            .map_err(|err| OAuthError::Decode(format!("token response did not parse: {err}")))
    }
}

/// Reads a failure response into [`ProviderError`]: the §5.2 pair when the
/// body is JSON, the raw body and the headers either way.
fn provider_error(response: &http::Response<Bytes>) -> OAuthError {
    let status = response.status();
    let raw = String::from_utf8_lossy(response.body()).into_owned();
    let parsed = serde_json::from_slice::<ErrorBody>(response.body()).ok();
    let code = parsed
        .as_ref()
        .and_then(|body| body.error.clone())
        .unwrap_or_default();
    let description = parsed
        .and_then(|body| body.error_description)
        .unwrap_or_default();
    OAuthError::from(Box::new(ProviderError {
        status: status.as_u16(),
        code,
        description,
        body: raw,
        headers: response.headers().clone(),
    }))
}

#[derive(Deserialize)]
struct ErrorBody {
    error: Option<String>,
    error_description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::RwLock;

    const TOKENS: &str = r#"{"access_token":"at-critical-do-not-log","token_type":"Bearer",
        "expires_in":3600,"refresh_token":"rt-critical-do-not-log",
        "refresh_token_expires_in":5184000,"scope":"w_member_social"}"#;

    /// Answers every send with one canned response and keeps the requests,
    /// so the assertions can read the form and headers a call actually sent.
    struct Scripted {
        status: u16,
        body: &'static str,
        seen: RwLock<Vec<Request<Bytes>>>,
    }

    impl Scripted {
        fn ok() -> Self {
            Self {
                status: 200,
                body: TOKENS,
                seen: RwLock::new(Vec::new()),
            }
        }

        fn with(status: u16, body: &'static str) -> Self {
            Self {
                status,
                body,
                seen: RwLock::new(Vec::new()),
            }
        }

        /// The client id must appear in the body only under Post auth, so
        /// both the positive and the negative assertion read the same way.
        fn form_of(&self, index: usize) -> String {
            let seen = self.seen.read().expect("lock");
            String::from_utf8_lossy(seen[index].body()).into_owned()
        }

        fn header_of(&self, index: usize, name: &str) -> Option<String> {
            let seen = self.seen.read().expect("lock");
            seen[index]
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        }
    }

    #[async_trait]
    impl HttpClient for Scripted {
        async fn send(&self, request: Request<Bytes>) -> Result<http::Response<Bytes>, HttpError> {
            self.seen.write().expect("lock").push(request);
            Ok(http::Response::builder()
                .status(self.status)
                .body(Bytes::from(self.body))
                .expect("static body"))
        }
    }

    fn post_config() -> ProviderConfig {
        ProviderConfig {
            authorize_url: "https://provider.example/oauth/authorize".to_owned(),
            token_url: "https://provider.example/oauth/token".to_owned(),
            revoke_url: Some("https://provider.example/oauth/revoke".to_owned()),
            client_id: "client".to_owned(),
            client_secret: Some("hunter2-do-not-log".to_owned()),
            scopes: Vec::new(),
            scope_separator: " ",
            client_auth: ClientAuth::ClientSecretPost,
        }
    }

    fn basic_config() -> ProviderConfig {
        ProviderConfig {
            client_auth: ClientAuth::ClientSecretBasic,
            ..post_config()
        }
    }

    #[pollster::test]
    async fn exchange_sends_the_grant_with_the_credentials_in_the_body() {
        let http = Scripted::ok();
        let tokens = OAuthClient::new(&http, &post_config())
            .exchange_code("the-code", "https://api.test/cb", Some("the-verifier"))
            .await
            .expect("the exchange succeeds");
        assert_eq!(tokens.access_token, "at-critical-do-not-log");
        assert_eq!(tokens.expires_in, 3600);
        assert_eq!(tokens.refresh_token_expires_in, Some(5_184_000));
        assert_eq!(
            tokens.rotated_refresh_token("older"),
            "rt-critical-do-not-log"
        );
        let form = http.form_of(0);
        for piece in [
            "grant_type=authorization_code",
            "code=the-code",
            "redirect_uri=https%3A%2F%2Fapi.test%2Fcb",
            "code_verifier=the-verifier",
            "client_id=client",
            "client_secret=hunter2-do-not-log",
        ] {
            assert!(form.contains(piece), "{piece:?} missing from {form}");
        }
        assert_eq!(
            http.header_of(0, "authorization"),
            None,
            "Post auth: no header"
        );
    }

    /// RFC 6749 §2.3.1: one method per call. Under Basic the client id rides
    /// in the Authorization header, so the body must not repeat it.
    #[pollster::test]
    async fn basic_auth_keeps_the_client_id_out_of_the_body() {
        let http = Scripted::ok();
        OAuthClient::new(&http, &basic_config())
            .refresh("rt-being-rotated")
            .await
            .expect("the refresh succeeds");
        let form = http.form_of(0);
        assert!(form.contains("grant_type=refresh_token"), "{form}");
        assert!(form.contains("refresh_token=rt-being-rotated"), "{form}");
        assert!(!form.contains("client_id"), "{form}");
        assert!(!form.contains("client_secret"), "{form}");
        let authorization = http.header_of(0, "authorization").expect("Basic header");
        // RFC 6749 §2.3.1: both halves form-encoded before the colon
        // (`client:hunter2-do-not-log`, standard base64).
        assert_eq!(
            authorization, "Basic Y2xpZW50Omh1bnRlcjItZG8tbm90LWxvZw==",
            "form-encoded credentials, standard base64"
        );
    }

    /// Providers quote the seconds fields; a number and a numeric string
    /// must land as the same value, and `null` as absent.
    #[pollster::test]
    async fn quoted_expiries_parse_like_numbers() {
        let http = Scripted::with(
            200,
            r#"{"access_token":"at","expires_in":"3600",
                "refresh_token_expires_in":null,"scope":"s"}"#,
        );
        let tokens = OAuthClient::new(&http, &post_config())
            .refresh("rt")
            .await
            .expect("parses");
        assert_eq!(tokens.expires_in, 3600);
        assert_eq!(tokens.refresh_token_expires_in, None);
        assert_eq!(tokens.rotated_refresh_token("kept"), "kept");
    }

    /// The raw body can echo the refused token; the error's Display keeps
    /// the prose the caller needs, its Debug must not carry the body.
    #[pollster::test]
    async fn a_provider_error_keeps_the_prose_and_hides_the_body() {
        let http = Scripted::with(
            400,
            r#"{"error":"invalid_grant","error_description":"Refresh token rt-critical-do-not-log expired"}"#,
        );
        let error = OAuthClient::new(&http, &post_config())
            .refresh("rt-critical-do-not-log")
            .await
            .expect_err("the provider refused");
        assert!(error.is_invalid_grant(), "{error}");
        assert!(
            error
                .to_string()
                .contains("Refresh token rt-critical-do-not-log expired"),
            "{error}"
        );
        let debug = format!("{error:?}");
        assert!(debug.contains("invalid_grant"), "{debug}");
        assert!(
            !debug.contains("\"error_description\""),
            "raw body in the debug: {debug}"
        );
        assert!(debug.contains("<redacted 92 bytes>"), "{debug}");

        let http = Scripted::with(400, "not json at all");
        let error = OAuthClient::new(&http, &post_config())
            .refresh("rt")
            .await
            .expect_err("a non-JSON refusal is still a provider error");
        assert!(
            error.to_string().starts_with("provider answered 400"),
            "{error}"
        );
        assert!(matches!(error, OAuthError::Provider(_)), "{error:?}");
    }

    #[pollster::test]
    async fn a_success_that_is_not_json_is_a_decode_error() {
        let http = Scripted::with(200, "<html>ok</html>");
        let error = OAuthClient::new(&http, &post_config())
            .refresh("rt")
            .await
            .expect_err("html is not a token response");
        assert!(matches!(error, OAuthError::Decode(_)), "{error}");
    }

    #[pollster::test]
    async fn the_debug_of_a_token_response_never_shows_the_tokens() {
        let http = Scripted::ok();
        let tokens = OAuthClient::new(&http, &post_config())
            .refresh("rt")
            .await
            .expect("parses");
        let debug = format!("{tokens:?}");
        assert!(!debug.contains("at-critical-do-not-log"), "{debug}");
        assert!(!debug.contains("rt-critical-do-not-log"), "{debug}");
        assert_eq!(debug.matches("<redacted>").count(), 2, "{debug}");
    }

    #[pollster::test]
    async fn revocation_refuses_to_guess_an_endpoint() {
        let http = Scripted::ok();
        let config = ProviderConfig {
            revoke_url: None,
            ..post_config()
        };
        let error = OAuthClient::new(&http, &config)
            .revoke("rt", "refresh_token")
            .await
            .expect_err("no revoke endpoint configured");
        assert!(matches!(error, OAuthError::NoRevokeEndpoint), "{error}");
    }
}
