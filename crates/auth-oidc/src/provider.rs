//! The provider descriptor (issue #15).
//!
//! Google is the reference implementation, and the flow is written against
//! this descriptor rather than against Google, so Apple (#16) and any other
//! compliant provider arrive as data plus whatever quirk they insist on.

use std::borrow::Cow;

use cratefield_auth_core::{PROVIDER_APPLE, PROVIDER_GOOGLE, SSO_PROVIDER};
use openidconnect::AuthType;
use openidconnect::core::{CoreClientAuthMethod, CoreJwsSigningAlgorithm, CoreProviderMetadata};

/// The `identities.provider` value an enterprise SSO sign-in writes, and
/// the route segment `/{provider}/...` must never answer for it: an SSO
/// flow is addressed by connection id, not by provider.
pub(crate) const SSO_SLUG: &str = SSO_PROVIDER;

/// How the provider delivers the authorization response.
///
/// This is not cosmetic. A `form_post` arrives as a cross-site `POST`, and
/// a `SameSite=Lax` cookie is not sent on one, so the descriptor decides
/// both the route that answers and the cookie the flow is sealed into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    /// A top-level `GET` redirect with the code in the query string.
    Query,
    /// A cross-site `POST` with a form-encoded body. Apple only.
    FormPost,
}

/// Where the client secret comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSource {
    /// A string the operator configures: `AUTH_OIDC_<CONFIG>_CLIENT_SECRET`.
    Configured,
    /// Minted per request as an ES256 JWT over the configured `.p8`
    /// (`crate::apple`). There is no secret to store and none to rotate.
    AppleMinted,
    /// Neither: the credentials belong to one `sso_connections` row
    /// (issue #627) and are read from it, so nothing in the environment
    /// names this provider's secret.
    Connection,
}

/// One OpenID Connect provider.
///
/// Not `Copy`, because [`Provider::issuer`] is an organization's rather
/// than a constant for an SSO connection (issue #627) and so is owned.
/// Everything else about a provider is still a compile-time decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// The path segment and the `identities.provider` value. These are the
    /// same string on purpose: a route that says `google` writes `google`.
    ///
    /// Still `'static`: every provider this service serves has a slug of
    /// our own choosing, and an SSO connection's is the fixed `sso`.
    pub slug: &'static str,
    /// The issuer, from which discovery finds everything else. Owned for
    /// an SSO connection, borrowed for Google and Apple.
    pub issuer: Cow<'static, str>,
    /// Requested scopes beyond `openid`, which openidconnect always sends.
    pub scopes: &'static [&'static str],
    /// Config-key infix: `AUTH_OIDC_<CONFIG>_CLIENT_ID`.
    pub config: &'static str,
    /// Human label, for the pages this module renders.
    pub label: &'static str,
    /// The signing algorithms an ID token from this provider may use.
    /// Policy, not discovery: see the comment where it is applied.
    pub signing_algorithms: &'static [CoreJwsSigningAlgorithm],
    /// How the authorization response comes back.
    pub response_mode: ResponseMode,
    /// Where the client secret comes from.
    pub secret: SecretSource,
    /// How the client authenticates at the token endpoint.
    ///
    /// Pinned here, like the signing algorithms and for the same reason:
    /// the alternative is believing the discovery document. Apple accepts
    /// only `client_secret_post`, and a client that sends HTTP Basic gets
    /// an `invalid_client` that names nothing.
    pub auth_type: TokenAuth,
}

/// How the client authenticates at the token endpoint.
///
/// A local enum rather than `oauth2::AuthType` because that one is not
/// `Copy`, and [`Provider`] is a `const` a route looks up by reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuth {
    /// HTTP Basic: `client_secret_basic`.
    Basic,
    /// Credentials in the form body: `client_secret_post`.
    RequestBody,
}

impl TokenAuth {
    pub(crate) fn as_oauth(self) -> AuthType {
        match self {
            Self::Basic => AuthType::BasicAuth,
            Self::RequestBody => AuthType::RequestBody,
        }
    }
}

impl Provider {
    /// Whether this provider answers on the cross-site `POST` callback.
    pub(crate) fn is_form_post(&self) -> bool {
        matches!(self.response_mode, ResponseMode::FormPost)
    }
}

pub const GOOGLE: Provider = Provider {
    slug: PROVIDER_GOOGLE,
    issuer: Cow::Borrowed("https://accounts.google.com"),
    scopes: &["email", "profile"],
    config: "GOOGLE",
    label: "Google",
    signing_algorithms: &[CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
    response_mode: ResponseMode::Query,
    secret: SecretSource::Configured,
    auth_type: TokenAuth::Basic,
};

/// Sign in with Apple (issues #3, #16).
///
/// The scopes are the reason the response mode is what it is: asking for
/// `name` or `email` makes Apple send the response as a `form_post`, and
/// Apple documents that as the only supported mode for those scopes.
pub const APPLE: Provider = Provider {
    slug: PROVIDER_APPLE,
    issuer: Cow::Borrowed("https://appleid.apple.com"),
    scopes: &["name", "email"],
    config: "APPLE",
    label: "Apple",
    // Apple signs ID tokens with RS256 and publishes only RSA keys.
    signing_algorithms: &[CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
    response_mode: ResponseMode::FormPost,
    secret: SecretSource::AppleMinted,
    // Apple documents `client_secret_post` and refuses HTTP Basic.
    auth_type: TokenAuth::RequestBody,
};

/// Every provider this module serves. Adding one is a line here plus its
/// config keys.
pub const PROVIDERS: &[Provider] = &[GOOGLE, APPLE];

/// The provider a request names, or `None` when the path segment is not one
/// we serve.
///
/// Never `sso`: an enterprise connection is addressed by its id, and
/// `/{provider}/...` must not answer for the flow that carries one.
pub(crate) fn by_slug(slug: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|provider| provider.slug == slug)
}

/// The descriptor for one enterprise SSO connection (issue #627).
///
/// The flow is the same flow; what differs is where the facts come from.
/// The issuer is the organization's, so it is owned rather than borrowed,
/// and the client id and secret come from the connection's own row — which
/// is what [`SecretSource::Connection`] means, and why nothing in the
/// environment names them.
///
/// `auth_type` here is provisional. The descriptor carries a value because
/// every client this module builds reads one, and Basic is the OIDC
/// default; [`with_auth_type`] replaces it with what the organization's
/// discovery document actually says before any request is made.
pub(crate) fn sso(issuer: &str) -> Provider {
    Provider {
        slug: SSO_SLUG,
        issuer: Cow::Owned(issuer.to_owned()),
        // The same two Google asks for, minus `openid`, which
        // openidconnect always sends.
        scopes: &["email", "profile"],
        // Unused: there is no `AUTH_OIDC_<CONFIG>_*` for an SSO
        // connection, and `provider_credentials` returns nothing for one.
        config: "",
        label: "SSO",
        // RS256 only, pinned for the same reason Google's is: this version
        // of openidconnect cannot verify ES256 at all, so a document that
        // listed it would be believed and then fail opaquely.
        signing_algorithms: &[CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        // The callback is a single fixed redirect, so the response must
        // arrive as a query string and the flow cookie stays `SameSite=Lax`.
        response_mode: ResponseMode::Query,
        secret: SecretSource::Connection,
        auth_type: TokenAuth::Basic,
    }
}

/// The descriptor with the client authentication the discovery document
/// asks for, wherever the descriptor does not already pin it.
///
/// Google and Apple pin theirs deliberately — Apple refuses HTTP Basic
/// with an `invalid_client` that names nothing — so this changes nothing
/// for them. An SSO connection is an arbitrary compliant `IdP`, and RFC
/// 8414 says `client_secret_basic` when the document lists neither.
pub(crate) fn with_auth_type(provider: &Provider, metadata: &CoreProviderMetadata) -> Provider {
    let mut provider = provider.clone();
    if provider.secret == SecretSource::Connection {
        provider.auth_type = auth_type_from_metadata(metadata);
    }
    provider
}

fn auth_type_from_metadata(metadata: &CoreProviderMetadata) -> TokenAuth {
    let Some(methods) = metadata.token_endpoint_auth_methods_supported() else {
        return TokenAuth::Basic;
    };
    if methods.contains(&CoreClientAuthMethod::ClientSecretBasic) {
        TokenAuth::Basic
    } else if methods.contains(&CoreClientAuthMethod::ClientSecretPost) {
        TokenAuth::RequestBody
    } else {
        // An empty or unknown list is not a licence to guess: the spec's
        // default applies, and a provider that wanted `client_secret_post`
        // says so.
        TokenAuth::Basic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slug_is_the_identity_provider_value() {
        // The route segment and the row written into `identities` are the
        // same string; if they ever drift, a second login makes a second
        // account instead of matching the first.
        assert_eq!(GOOGLE.slug, PROVIDER_GOOGLE);
        assert_eq!(by_slug("google"), Some(&GOOGLE));
        assert_eq!(by_slug("Google"), None);
        assert_eq!(APPLE.slug, PROVIDER_APPLE);
        assert_eq!(by_slug("apple"), Some(&APPLE));
    }

    #[test]
    fn only_apple_uses_the_form_post_callback() {
        // The cross-site POST route and the `SameSite=None` cookie are both
        // driven off this, so widening it widens both.
        assert!(APPLE.is_form_post());
        assert!(!GOOGLE.is_form_post());
        assert_eq!(
            PROVIDERS.iter().filter(|p| p.is_form_post()).count(),
            1,
            "a new form_post provider must be a deliberate decision"
        );
    }

    #[test]
    fn apple_asks_for_the_scopes_that_force_form_post() {
        // These two are the reason Apple posts rather than redirects. If
        // they ever go, the response mode should be revisited rather than
        // left as a POST route nobody uses.
        assert!(APPLE.scopes.contains(&"name"));
        assert!(APPLE.scopes.contains(&"email"));
        assert!(!APPLE.scopes.contains(&"openid"));
    }

    #[test]
    fn apple_authenticates_in_the_request_body() {
        // Apple refuses HTTP Basic with `invalid_client`, which names
        // nothing and reads like a bad key.
        assert_eq!(APPLE.auth_type, TokenAuth::RequestBody);
        assert_eq!(GOOGLE.auth_type, TokenAuth::Basic);
    }

    #[test]
    fn only_apple_mints_its_own_secret() {
        assert_eq!(APPLE.secret, SecretSource::AppleMinted);
        assert_eq!(GOOGLE.secret, SecretSource::Configured);
    }

    #[test]
    fn every_provider_has_its_own_slug_and_config_infix() {
        // Two providers sharing either one would read each other's keys or
        // each other's identity rows.
        for (index, provider) in PROVIDERS.iter().enumerate() {
            for other in &PROVIDERS[index + 1..] {
                assert_ne!(provider.slug, other.slug);
                assert_ne!(provider.config, other.config);
                assert_ne!(provider.issuer, other.issuer);
            }
        }
    }

    #[test]
    fn only_rs256_is_accepted_from_google() {
        // A document that listed HS256 would otherwise be believed, and
        // openidconnect verifies HS256 with the client secret we hold.
        assert_eq!(
            GOOGLE.signing_algorithms,
            [CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]
        );
    }

    /// A discovery document, minimal but complete enough for
    /// `CoreProviderMetadata` to parse. `methods` is the
    /// `token_endpoint_auth_methods_supported` array, verbatim.
    fn metadata(methods: Option<&str>) -> CoreProviderMetadata {
        let extra = methods.map_or(String::new(), |methods| {
            format!(r#","token_endpoint_auth_methods_supported":[{methods}]"#)
        });
        serde_json::from_str(&format!(
            r#"{{"issuer":"https://idp.example",
                 "authorization_endpoint":"https://idp.example/authorize",
                 "token_endpoint":"https://idp.example/token",
                 "jwks_uri":"https://idp.example/jwks",
                 "response_types_supported":["code"],
                 "subject_types_supported":["public"],
                 "id_token_signing_alg_values_supported":["RS256"]{extra}}}"#
        ))
        .expect("a well-formed discovery document")
    }

    #[test]
    fn an_sso_connection_is_addressed_by_id_and_never_by_slug() {
        // `/v1/auth-oidc/sso/start` must not exist: an SSO flow is begun
        // through `sso/{connection_id}/start`, and a slug here would make
        // the module answer for a provider it cannot configure.
        assert!(by_slug(SSO_SLUG).is_none());
        let provider = sso("https://idp.example");
        assert_eq!(provider.slug, SSO_PROVIDER);
        assert_eq!(provider.issuer, "https://idp.example");
        assert_eq!(provider.secret, SecretSource::Connection);
        assert_eq!(provider.response_mode, ResponseMode::Query);
        assert!(!provider.scopes.contains(&"openid"));
    }

    #[test]
    fn an_sso_connection_takes_its_client_authentication_from_the_document() {
        let provider = sso("https://idp.example");
        assert_eq!(
            with_auth_type(&provider, &metadata(Some(r#""client_secret_post""#))).auth_type,
            TokenAuth::RequestBody,
        );
        // Basic wins when both are offered: it is the spec's default and
        // the better-kept secret (a form body is far likelier to be logged).
        assert_eq!(
            with_auth_type(
                &provider,
                &metadata(Some(r#""client_secret_post","client_secret_basic""#))
            )
            .auth_type,
            TokenAuth::Basic,
        );
        // A document that says nothing gets the spec default, and so does
        // one that lists only methods we cannot use.
        for methods in [None, Some(r#""private_key_jwt""#)] {
            assert_eq!(
                with_auth_type(&provider, &metadata(methods)).auth_type,
                TokenAuth::Basic,
                "{methods:?}"
            );
        }
    }

    #[test]
    fn a_pinned_provider_never_re_reads_its_auth_type_from_a_document() {
        // Apple refuses HTTP Basic with an `invalid_client` that names
        // nothing, so a document claiming otherwise must not be believed.
        assert_eq!(
            with_auth_type(&APPLE, &metadata(Some(r#""client_secret_basic""#))).auth_type,
            TokenAuth::RequestBody,
        );
        assert_eq!(
            with_auth_type(&GOOGLE, &metadata(Some(r#""client_secret_post""#))).auth_type,
            TokenAuth::Basic,
        );
    }

    #[test]
    fn openid_is_not_in_the_scope_list() {
        // openidconnect always sends `openid`; listing it again would ask
        // for it twice.
        assert!(!GOOGLE.scopes.contains(&"openid"));
        assert!(GOOGLE.scopes.contains(&"email"));
    }
}
