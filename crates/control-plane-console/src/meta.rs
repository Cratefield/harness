//! The console's own Facebook Login (issue #3): the same deliberate
//! deviation from "relying party, not a second `IdP`" that [`crate::google`]
//! records, and for the same reason — the auth service is not deployable
//! (auth#41, needs Cloudflare #26). See [`crate::google`]'s header for the
//! whole decision; this flow is the third of the four ways in.
//!
//! Meta is **not** OpenID Connect: no discovery, no ID token. The
//! authorization response is a plain redirect (so the state cookie is
//! `SameSite=Lax`, like Google's), the code exchanges for a plain OAuth 2.0
//! access token, and who the person is comes from a Graph call — made
//! through the same [`factory0_auth_meta::graph::profile`] the auth service
//! uses, made public for exactly this.
//!
//! **An identity without an email cannot be matched.** The allowlist is
//! keyed on addresses, and Meta does not have to give one: the person can
//! decline the `email` permission, and then there is nothing to match an
//! invite against. That case is refused with a page saying what to do
//! (grant the permission, or sign in another way) rather than admitted on
//! the strength of an app-scoped id the allowlist has never heard of.
//!
//! **The address Meta reports is matched, but not blindly trusted.**
//! `auth-meta` never stores a Meta address as verified, because Meta does
//! not assert verification in a form this stack can rely on (ADR 0204).
//! This console has no account linking to withhold, so the honest
//! equivalent is said here: a Meta sign-in proves the person controls the
//! Facebook account that **claims** that address, and the invite it
//! satisfies is only as strong as Facebook's own account-email
//! confirmation. That is a real, bounded trust — the same trust every
//! unverified-then-confirmed address on the web rests on — and it is why
//! the refusal below names the email case separately rather than folding
//! it into a generic failure.

use bytes::Bytes;
use cratefield_access::VerifiedIdentity;
use cratefield_core::{HttpClient, HttpError};
use factory0_auth_meta::graph;
use http::Request;
use http::header::CONTENT_TYPE;
use serde::Deserialize;

/// The console's Meta client, from `CONSOLE_META_CLIENT_ID` / `_SECRET`,
/// the shared `CONSOLE_BASE_URL`, and the Graph version.
pub struct MetaClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    /// The Graph API version every endpoint is built from. Configurable
    /// because Meta retires a version roughly two years after release;
    /// check it before deploying.
    pub graph_version: String,
}

impl std::fmt::Debug for MetaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The app secret is a secret; a derived `Debug` would put it in
        // any log line that formats this struct.
        f.debug_struct("MetaClient")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("graph_version", &self.graph_version)
            .finish_non_exhaustive()
    }
}

/// Why a Meta sign-in could not be completed.
#[derive(Debug)]
pub enum MetaError {
    /// The `HttpClient` call to Meta failed.
    Transport(String),
    /// Meta's response did not parse, or was an error.
    Upstream(String),
    /// The person declined the `email` permission (or has no verified
    /// address on file), so no allowlist entry can be matched.
    NoEmail,
}

impl std::fmt::Display for MetaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetaError::Transport(e) => write!(f, "meta transport: {e}"),
            MetaError::Upstream(e) => write!(f, "meta upstream: {e}"),
            MetaError::NoEmail => write!(f, "meta returned no email address"),
        }
    }
}

impl From<HttpError> for MetaError {
    fn from(err: HttpError) -> Self {
        MetaError::Transport(err.to_string())
    }
}

impl From<graph::GraphError> for MetaError {
    fn from(err: graph::GraphError) -> Self {
        MetaError::Upstream(err.to_string())
    }
}

impl MetaClient {
    /// The consent URL to redirect the browser to. `state` is the CSRF
    /// token the caller also stores in a cookie and checks on the
    /// callback.
    #[must_use]
    pub fn authorize_url(&self, state: &str) -> String {
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            graph::authorization_endpoint(&self.graph_version),
            crate::enc(&self.client_id),
            crate::enc(&self.redirect_uri),
            crate::enc("public_profile,email"),
            crate::enc(state),
        )
    }

    /// Exchanges an authorization `code` for a verified identity: `POST`
    /// the token endpoint (the app secret in the form body, not the query
    /// string — a URL reaches proxy logs), then fetch the profile with the
    /// access token through the shared Graph call.
    ///
    /// # Errors
    ///
    /// [`MetaError`] on a transport failure, an unparseable/rejected Meta
    /// response, or a profile that carried no email address.
    pub async fn exchange(
        &self,
        http: &dyn HttpClient,
        code: &str,
    ) -> Result<VerifiedIdentity, MetaError> {
        let form = crate::form_encode(&[
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("redirect_uri", &self.redirect_uri),
            ("code", code),
        ]);
        let request = Request::builder()
            .method("POST")
            .uri(graph::token_endpoint(&self.graph_version))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Bytes::from(form))
            .map_err(|e| MetaError::Upstream(e.to_string()))?;
        let response = http.send(request).await?;
        if !response.status().is_success() {
            return Err(MetaError::Upstream(format!(
                "token endpoint {}",
                response.status().as_u16()
            )));
        }
        let token: TokenResponse = serde_json::from_slice(response.body())
            .map_err(|e| MetaError::Upstream(format!("token response: {e}")))?;

        let profile = graph::profile(http, &self.graph_version, &token.access_token).await?;
        // No email, no match: the allowlist is keyed on addresses, and an
        // app-scoped id is not a key it has ever heard of. The caller
        // refuses with a page the operator can act on.
        let Some(email) = profile.email else {
            return Err(MetaError::NoEmail);
        };
        Ok(VerifiedIdentity {
            email,
            name: profile.name.unwrap_or_default(),
            // Meta asserts no hosted domain; a domain entry on the
            // allowlist still matches through the address's own domain.
            hosted_domain: None,
        })
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}
