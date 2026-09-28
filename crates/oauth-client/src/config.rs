//! The provider as configuration: endpoints, credentials, scopes.

/// One OAuth 2.0 provider, as far as this crate needs to know it. Built once
/// per call site (the credentials usually come from config), never global.
#[derive(Clone)]
pub struct ProviderConfig {
    /// The authorization endpoint a human's browser opens.
    pub authorize_url: String,
    /// The token endpoint, `POST`, form-encoded (RFC 6749 §3.2).
    pub token_url: String,
    /// The revocation endpoint (RFC 7009), when the provider documents one.
    /// [`OAuthClient::revoke`](crate::OAuthClient::revoke) refuses to run
    /// without it rather than guessing.
    pub revoke_url: Option<String>,
    /// The client id the provider issued.
    pub client_id: String,
    /// The client secret, for the providers that issue one.
    pub client_secret: Option<String>,
    /// Scopes requested at authorize time, joined with
    /// [`ProviderConfig::scope_separator`]. Token responses carry the scopes
    /// the provider actually granted; ask at authorize, verify after.
    pub scopes: Vec<String>,
    /// How the scope list is joined in the authorize URL. Space per
    /// RFC 6749 §3.3, which every provider this crate has met uses.
    pub scope_separator: &'static str,
    /// Where the client credentials ride on token calls.
    pub client_auth: ClientAuth,
}

impl std::fmt::Debug for ProviderConfig {
    /// Configs end up in logs when a connect fails, so the secret is named,
    /// never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("authorize_url", &self.authorize_url)
            .field("token_url", &self.token_url)
            .field("revoke_url", &self.revoke_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("scopes", &self.scopes)
            .field("scope_separator", &self.scope_separator)
            .field("client_auth", &self.client_auth)
            .finish()
    }
}

/// How client credentials are presented at the token endpoint (RFC 6749 §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// `client_id` and `client_secret` in the form body. What LinkedIn,
    /// `Stripe` and most SaaS-style providers do.
    ClientSecretPost,
    /// HTTP Basic, per RFC 6749 §2.3.1. What the RFC prefers and Google does.
    ClientSecretBasic,
}

/// The authorization URL a human's browser opens: the provider's authorize
/// endpoint with `response_type=code`, the client, the redirect, the state
/// and the scopes (RFC 6749 §4.1.1), plus the PKCE pair when the caller is
/// handed one. No PKCE where the provider does not document it — LinkedIn
/// does not, and a `code_challenge` it ignores is fine, but one it rejects
/// is a connect that never worked, so the caller decides.
#[must_use]
pub fn authorize_url(
    config: &ProviderConfig,
    redirect_uri: &str,
    state: &str,
    pkce: Option<&crate::Pkce>,
) -> String {
    let mut params: Vec<(&str, String)> = vec![
        ("response_type", "code".to_owned()),
        ("client_id", config.client_id.clone()),
        ("redirect_uri", redirect_uri.to_owned()),
        ("state", state.to_owned()),
    ];
    if !config.scopes.is_empty() {
        params.push(("scope", config.scopes.join(config.scope_separator)));
    }
    if let Some(pkce) = pkce {
        params.push(("code_challenge", pkce.challenge().to_owned()));
        params.push(("code_challenge_method", "S256".to_owned()));
    }
    let query = params
        .into_iter()
        .map(|(name, value)| format!("{name}={}", form_encode(&value)))
        .collect::<Vec<_>>()
        .join("&");
    // Some providers document their authorize endpoint with query parameters
    // already on it (a tenant, a prompt). Join on the right separator, and
    // never double one left hanging.
    let base = config.authorize_url.trim_end_matches(['?', '&']);
    let separator = if base.contains('?') { "&" } else { "?" };
    format!("{base}{separator}{query}")
}

/// `application/x-www-form-urlencoded` escaping, for query strings and form
/// bodies alike. Small and explicit rather than a dependency: unreserved
/// bytes pass through, space becomes `+`, everything else is `%XX` (with
/// uppercase hex, which is what the examples in RFC 6749 show).
pub(crate) fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            other => {
                const HEX: [u8; 16] = *b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[usize::from(other >> 4)] as char);
                out.push(HEX[usize::from(other & 0x0f)] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ProviderConfig {
        ProviderConfig {
            authorize_url: "https://provider.example/oauth/authorize".to_owned(),
            token_url: "https://provider.example/oauth/token".to_owned(),
            revoke_url: None,
            client_id: "client".to_owned(),
            client_secret: Some("hunter2-do-not-log".to_owned()),
            scopes: vec!["read".to_owned(), "write things".to_owned()],
            scope_separator: " ",
            client_auth: ClientAuth::ClientSecretPost,
        }
    }

    #[test]
    fn form_encoding_escapes_what_matters() {
        assert_eq!(form_encode("a b"), "a+b");
        assert_eq!(form_encode("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
        assert_eq!(form_encode("plain-value_1.~"), "plain-value_1.~");
    }

    #[test]
    fn the_authorize_url_carries_the_whole_ask() {
        let url = authorize_url(&config(), "https://api.test/v1/callback", "st.at.e", None);
        assert_eq!(
            url,
            "https://provider.example/oauth/authorize?response_type=code&client_id=client\
             &redirect_uri=https%3A%2F%2Fapi.test%2Fv1%2Fcallback&state=st.at.e\
             &scope=read+write+things"
        );
    }

    #[test]
    fn pkce_adds_the_s256_pair_when_asked() {
        let pkce = crate::Pkce::new().expect("randomness");
        let url = authorize_url(&config(), "https://api.test/cb", "s", Some(&pkce));
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        assert!(
            url.contains(&format!("code_challenge={}", pkce.challenge())),
            "{url}"
        );
    }

    /// Some providers document their authorize endpoint with parameters
    /// already on it; the ask must join, not overwrite or double a separator.
    #[test]
    fn an_authorize_url_with_a_query_already_on_it_is_joined_not_doubled() {
        let mut with_query = config();
        with_query.authorize_url =
            "https://provider.example/oauth/authorize?tenant=acme".to_owned();
        let url = authorize_url(&with_query, "https://api.test/cb", "s", None);
        assert_eq!(
            url.matches('?').count(),
            1,
            "one question mark, however the endpoint was written: {url}"
        );
        assert!(
            url.starts_with(
                "https://provider.example/oauth/authorize?tenant=acme&response_type=code"
            ),
            "{url}"
        );

        with_query.authorize_url = "https://provider.example/oauth/authorize?".to_owned();
        let url = authorize_url(&with_query, "https://api.test/cb", "s", None);
        assert!(
            url.starts_with("https://provider.example/oauth/authorize?response_type=code"),
            "a trailing ? must not double: {url}"
        );

        with_query.authorize_url =
            "https://provider.example/oauth/authorize?tenant=acme&".to_owned();
        let url = authorize_url(&with_query, "https://api.test/cb", "s", None);
        assert!(
            url.starts_with(
                "https://provider.example/oauth/authorize?tenant=acme&response_type=code"
            ),
            "a trailing & must not double: {url}"
        );
    }

    /// Configs reach logs on a failed connect; the secret must not.
    #[test]
    fn debug_of_the_config_never_shows_the_client_secret() {
        let debug = format!("{:?}", config());
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }
}
