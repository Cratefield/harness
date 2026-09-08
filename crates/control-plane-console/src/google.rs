//! The console's own Google sign-in (issue #3, option C): the control plane
//! acts as its **own** OAuth client — config-supplied `CONSOLE_GOOGLE_CLIENT_*`
//! — rather than relaying through the `auth-*` crates, which are not deployable
//! (auth#41). A deliberate deviation from #3's "relying party, not a second
//! `IdP`", recorded there; the auth-service path stays the long-term option.
//!
//! Only the Google endpoints are hit, over the runtime's `HttpClient` port. The
//! token exchange is a direct TLS call to Google carrying the client secret, so
//! the `userinfo` it yields is trusted without separately verifying the
//! `id_token` signature (no JWKS/RS256 in the isolate). The live flow needs a
//! real Google client and is `needs-human`; [`GoogleClient::exchange`] is
//! tested against a scripted `HttpClient`.

use bytes::Bytes;
use cratefield_access::VerifiedIdentity;
use cratefield_core::{HttpClient, HttpError};
use http::Request;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;

const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const SCOPE: &str = "openid email profile";

/// The console's Google OAuth client, from `CONSOLE_GOOGLE_CLIENT_ID` /
/// `_SECRET` and the redirect URI (`<base>/v1/console/auth/callback`).
#[derive(Debug, Clone)]
pub struct GoogleClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

/// Why a Google sign-in could not be completed.
#[derive(Debug)]
pub enum GoogleError {
    /// The `HttpClient` call to Google failed.
    Transport(String),
    /// Google's response did not parse, or was an error.
    Upstream(String),
    /// Google reported the email as unverified — never admit it.
    UnverifiedEmail,
}

impl std::fmt::Display for GoogleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoogleError::Transport(e) => write!(f, "google transport: {e}"),
            GoogleError::Upstream(e) => write!(f, "google upstream: {e}"),
            GoogleError::UnverifiedEmail => write!(f, "google email not verified"),
        }
    }
}

impl From<HttpError> for GoogleError {
    fn from(err: HttpError) -> Self {
        GoogleError::Transport(err.to_string())
    }
}

impl GoogleClient {
    /// The consent URL to redirect the browser to. `state` is the CSRF token
    /// the caller also stores in a cookie and checks on the callback.
    #[must_use]
    pub fn authorize_url(&self, state: &str) -> String {
        format!(
            "{AUTH_ENDPOINT}?client_id={}&redirect_uri={}&response_type=code\
             &scope={}&state={}&access_type=online&prompt=select_account",
            enc(&self.client_id),
            enc(&self.redirect_uri),
            enc(SCOPE),
            enc(state),
        )
    }

    /// Exchanges an authorization `code` for a verified identity: `POST` the
    /// token endpoint, then `GET` userinfo with the access token.
    ///
    /// # Errors
    ///
    /// [`GoogleError`] on a transport failure, an unparseable/rejected Google
    /// response, or an unverified email.
    pub async fn exchange(
        &self,
        http: &dyn HttpClient,
        code: &str,
    ) -> Result<VerifiedIdentity, GoogleError> {
        let form = form_encode(&[
            ("code", code),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("redirect_uri", &self.redirect_uri),
            ("grant_type", "authorization_code"),
        ]);
        let token_req = Request::builder()
            .method("POST")
            .uri(TOKEN_ENDPOINT)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Bytes::from(form))
            .map_err(|e| GoogleError::Upstream(e.to_string()))?;
        let token_resp = http.send(token_req).await?;
        if !token_resp.status().is_success() {
            return Err(GoogleError::Upstream(format!(
                "token endpoint {}",
                token_resp.status().as_u16()
            )));
        }
        let token: TokenResponse = serde_json::from_slice(token_resp.body())
            .map_err(|e| GoogleError::Upstream(format!("token response: {e}")))?;

        let userinfo_req = Request::builder()
            .method("GET")
            .uri(USERINFO_ENDPOINT)
            .header(AUTHORIZATION, format!("Bearer {}", token.access_token))
            .body(Bytes::new())
            .map_err(|e| GoogleError::Upstream(e.to_string()))?;
        let userinfo_resp = http.send(userinfo_req).await?;
        if !userinfo_resp.status().is_success() {
            return Err(GoogleError::Upstream(format!(
                "userinfo endpoint {}",
                userinfo_resp.status().as_u16()
            )));
        }
        let info: UserInfo = serde_json::from_slice(userinfo_resp.body())
            .map_err(|e| GoogleError::Upstream(format!("userinfo response: {e}")))?;

        if !info.email_verified {
            return Err(GoogleError::UnverifiedEmail);
        }
        Ok(VerifiedIdentity {
            email: info.email,
            name: info.name.unwrap_or_default(),
            hosted_domain: info.hd,
        })
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct UserInfo {
    email: String,
    #[serde(default)]
    email_verified: bool,
    name: Option<String>,
    hd: Option<String>,
}

/// Percent-encodes one query/form component (unreserved bytes pass through).
fn enc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
// `ScriptedHttp` is a test fake holding a queue of canned responses, which is
// the case the workspace clippy.toml calls out: interior mutability that is
// not request state, so ADR 0007 does not apply. Annotated rather than
// swapped for an `RwLock` that would only ever be write-locked.
#[allow(clippy::disallowed_types)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct ScriptedHttp {
        responses: Mutex<std::collections::VecDeque<(u16, String)>>,
    }
    #[async_trait::async_trait]
    impl HttpClient for ScriptedHttp {
        async fn send(&self, _request: Request<Bytes>) -> Result<http::Response<Bytes>, HttpError> {
            let (status, body) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("a response");
            Ok(http::Response::builder()
                .status(status)
                .body(Bytes::from(body))
                .unwrap())
        }
    }

    fn client() -> GoogleClient {
        GoogleClient {
            client_id: "cid.apps.googleusercontent.com".to_owned(),
            client_secret: "secret".to_owned(),
            redirect_uri: "https://app.cratefield.com/v1/console/auth/callback".to_owned(),
        }
    }

    #[test]
    fn authorize_url_carries_the_encoded_params() {
        let url = client().authorize_url("state-123");
        assert!(url.starts_with(AUTH_ENDPOINT));
        assert!(url.contains("client_id=cid.apps.googleusercontent.com"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fapp.cratefield.com"));
        assert!(url.contains("scope=openid%20email%20profile"));
        assert!(url.contains("state=state-123"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn exchange_yields_a_verified_identity() {
        let http = ScriptedHttp {
            responses: Mutex::new(
                [
                    (200, r#"{"access_token":"at_1","token_type":"Bearer"}"#.to_owned()),
                    (
                        200,
                        r#"{"email":"op@cratefield.com","email_verified":true,"name":"Op","hd":"cratefield.com"}"#
                            .to_owned(),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
        };
        let identity = pollster::block_on(client().exchange(&http, "code_1")).unwrap();
        assert_eq!(identity.email, "op@cratefield.com");
        assert_eq!(identity.name, "Op");
        assert_eq!(identity.hosted_domain.as_deref(), Some("cratefield.com"));
    }

    #[test]
    fn an_unverified_email_is_refused() {
        let http = ScriptedHttp {
            responses: Mutex::new(
                [
                    (200, r#"{"access_token":"at_1"}"#.to_owned()),
                    (
                        200,
                        r#"{"email":"x@example.com","email_verified":false}"#.to_owned(),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
        };
        let err = pollster::block_on(client().exchange(&http, "code_1")).unwrap_err();
        assert!(matches!(err, GoogleError::UnverifiedEmail));
    }
}
