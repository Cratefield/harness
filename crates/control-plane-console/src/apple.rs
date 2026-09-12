//! The console's own Sign in with Apple (issue #3): the same deliberate
//! deviation from "relying party, not a second `IdP`" that [`crate::google`]
//! records, and for the same reason — the auth service is not deployable
//! (auth#41, needs Cloudflare #26). See [`crate::google`]'s header for the
//! whole decision; this flow is the second of the four ways in.
//!
//! Apple is OpenID Connect with two departures the descriptor in
//! `auth-oidc` already names, and both reach this file:
//!
//! - **`response_mode=form_post`.** Apple posts the authorization response
//!   as a cross-site form body, and a browser sends no `SameSite=Lax`
//!   cookie on one — so the state cookie this flow sets is
//!   `SameSite=None; Secure` (see [`crate::apple_state_cookie`]) and the
//!   callback route answers a `POST`, not a GET with a query string. This
//!   is the trap that has bitten this codebase before; the descriptor
//!   exists because of it.
//! - **No client secret to store.** It is minted per request as an ES256
//!   JWT over the `.p8`, by the same
//!   [`Minter`](factory0_auth_oidc::apple::Minter) the auth service uses —
//!   made public for exactly this. A second copy of ES256 secret minting
//!   is the drift this repository keeps paying for.
//!
//! The token exchange is a direct TLS call to Apple carrying the minted
//! secret, so the `id_token` it yields is trusted without verifying its
//! RS256 signature (no JWKS on the isolate) — the same argument
//! [`crate::google`] makes for trusting `userinfo`. What *is* checked:
//! `aud` must equal our Services ID, and `email_verified` must be truthy
//! (Apple sends it as the string `"true"` or a boolean; both are read).
//! The live flow needs a real Apple key and is `needs-human`;
//! [`AppleClient::exchange`] is tested against a scripted `HttpClient`.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use bytes::Bytes;
use cratefield_access::VerifiedIdentity;
use cratefield_core::{Clock, HttpClient, HttpError};
use factory0_auth_oidc::apple::{AppleConfig, Minter};
use http::Request;
use http::header::CONTENT_TYPE;
use serde::Deserialize;
use serde_json::Value;

const AUTH_ENDPOINT: &str = "https://appleid.apple.com/auth/authorize";
const TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";

/// The console's Apple client, from `CONSOLE_APPLE_CLIENT_ID` (the
/// Services ID), the three signing settings, and the shared
/// `CONSOLE_BASE_URL`.
///
/// The `.p8` contents are configuration read through the `Config` port;
/// never logged, never rendered. The manual `Debug` is what keeps that
/// promise — a derived one would put the key in any line that formats
/// this struct.
pub struct AppleClient {
    pub client_id: String,
    pub redirect_uri: String,
    pub team_id: String,
    pub key_id: String,
    pub private_key: String,
}

impl std::fmt::Debug for AppleClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleClient")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Why an Apple sign-in could not be completed.
#[derive(Debug)]
pub enum AppleError {
    /// The `HttpClient` call to Apple failed.
    Transport(String),
    /// Apple's response did not parse, or was an error.
    Upstream(String),
    /// Apple reported the email as unverified — never admit it.
    UnverifiedEmail,
    /// The `.p8` could not mint a client secret. Named separately because
    /// the operator reading the log can act on this one: the key is bad.
    Key,
}

impl std::fmt::Display for AppleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppleError::Transport(e) => write!(f, "apple transport: {e}"),
            AppleError::Upstream(e) => write!(f, "apple upstream: {e}"),
            AppleError::UnverifiedEmail => write!(f, "apple email not verified"),
            AppleError::Key => write!(f, "the Apple signing key cannot mint a client secret"),
        }
    }
}

impl From<HttpError> for AppleError {
    fn from(err: HttpError) -> Self {
        AppleError::Transport(err.to_string())
    }
}

impl AppleClient {
    fn apple_config(&self) -> AppleConfig {
        AppleConfig {
            team_id: self.team_id.clone(),
            key_id: self.key_id.clone(),
            private_key: self.private_key.clone(),
        }
    }

    /// The consent URL to redirect the browser to. `state` is the CSRF
    /// token the caller also stores in a cookie and checks on the
    /// callback.
    ///
    /// `response_mode=form_post` is asked for explicitly even though Apple
    /// switches to it by itself once `name` or `email` is scoped: saying so
    /// keeps the route that answers and the cookie that survives it an
    /// agreement rather than a coincidence.
    #[must_use]
    pub fn authorize_url(&self, state: &str) -> String {
        format!(
            "{AUTH_ENDPOINT}?response_type=code&response_mode=form_post\
             &client_id={}&redirect_uri={}&scope={}&state={}",
            crate::enc(&self.client_id),
            crate::enc(&self.redirect_uri),
            crate::enc("name email"),
            crate::enc(state),
        )
    }

    /// Exchanges an authorization `code` for a verified identity: mint the
    /// client secret, `POST` the token endpoint (Apple accepts
    /// `client_secret_post` and refuses HTTP Basic with an
    /// `invalid_client` that names nothing), then read the `id_token`
    /// claims. `user` is Apple's first-authorization form field — the only
    /// place the person's name ever arrives — parsed by the same
    /// [`factory0_auth_oidc::apple::name_from_user_field`] the auth
    /// service uses.
    ///
    /// # Errors
    ///
    /// [`AppleError`] on a transport failure, an unparseable/rejected
    /// Apple response, an unverified email, or an unusable `.p8`.
    pub async fn exchange(
        &self,
        minter: &Minter,
        http: &dyn HttpClient,
        clock: &dyn Clock,
        code: &str,
        user: Option<&str>,
    ) -> Result<VerifiedIdentity, AppleError> {
        let client_secret = minter
            .mint(&self.apple_config(), &self.client_id, clock)
            .map_err(|err| {
                // The message names the situation, never the key bytes.
                tracing::error!(error = %err, "could not mint the Apple client secret");
                AppleError::Key
            })?;
        let form = crate::form_encode(&[
            ("code", code),
            ("client_id", &self.client_id),
            ("client_secret", &client_secret),
            ("redirect_uri", &self.redirect_uri),
            ("grant_type", "authorization_code"),
        ]);
        let request = Request::builder()
            .method("POST")
            .uri(TOKEN_ENDPOINT)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Bytes::from(form))
            .map_err(|e| AppleError::Upstream(e.to_string()))?;
        let response = http.send(request).await?;
        if !response.status().is_success() {
            return Err(AppleError::Upstream(format!(
                "token endpoint {}",
                response.status().as_u16()
            )));
        }
        let token: TokenResponse = serde_json::from_slice(response.body())
            .map_err(|e| AppleError::Upstream(format!("token response: {e}")))?;
        let claims = id_token_claims(&token.id_token)?;

        if claims.get("aud").and_then(Value::as_str) != Some(self.client_id.as_str()) {
            return Err(AppleError::Upstream(
                "id token was minted for another audience".to_owned(),
            ));
        }
        let Some(email) = claims.get("email").and_then(Value::as_str) else {
            return Err(AppleError::UnverifiedEmail);
        };
        // Apple documents `email_verified` as "a String or Boolean" and
        // sends `"true"`. Anything but an affirmative value refuses.
        let verified = match claims.get("email_verified") {
            Some(Value::Bool(value)) => *value,
            Some(Value::String(value)) => value == "true",
            _ => false,
        };
        if !verified {
            return Err(AppleError::UnverifiedEmail);
        }
        // The name is in the first authorization's `user` form field and
        // nowhere else; a second sign-in arrives without it and the empty
        // name is the ordinary case.
        let name = user
            .and_then(factory0_auth_oidc::apple::name_from_user_field)
            .unwrap_or_default();
        Ok(VerifiedIdentity {
            email: email.to_owned(),
            name,
            hosted_domain: None,
        })
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// The `id_token` payload, decoded without verifying its RS256 signature.
///
/// Trusted anyway for the same reason [`crate::google::GoogleClient`]
/// trusts `userinfo`: it arrived on our own back-channel request to
/// Apple's token endpoint, authenticated with a secret only Apple and
/// this console hold, over TLS. A forged payload would have to come from
/// Apple.
fn id_token_claims(id_token: &str) -> Result<Value, AppleError> {
    // Deliberately vague about what was wrong: an error naming the bytes
    // of a malformed token would echo provider input into a log line.
    let payload = id_token
        .split('.')
        .nth(1)
        .ok_or_else(|| AppleError::Upstream("id token has no payload".to_owned()))?;
    let bytes = Base64UrlUnpadded::decode_vec(payload)
        .map_err(|_| AppleError::Upstream("id token payload is not base64url".to_owned()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| AppleError::Upstream("id token payload is not JSON".to_owned()))
}
