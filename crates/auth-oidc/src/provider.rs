//! The provider descriptor (issue #15).
//!
//! Google is the reference implementation, and the flow is written against
//! this descriptor rather than against Google, so Apple (#16) and any other
//! compliant provider arrive as data plus whatever quirk they insist on.

use factory0_auth_core::PROVIDER_GOOGLE;
use openidconnect::core::CoreJwsSigningAlgorithm;

/// One OpenID Connect provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    /// The path segment and the `identities.provider` value. These are the
    /// same string on purpose: a route that says `google` writes `google`.
    pub slug: &'static str,
    /// The issuer, from which discovery finds everything else.
    pub issuer: &'static str,
    /// Requested scopes beyond `openid`, which openidconnect always sends.
    pub scopes: &'static [&'static str],
    /// Config-key infix: `AUTH_OIDC_<CONFIG>_CLIENT_ID`.
    pub config: &'static str,
    /// Human label, for the pages this module renders.
    pub label: &'static str,
    /// The signing algorithms an ID token from this provider may use.
    /// Policy, not discovery: see the comment where it is applied.
    pub signing_algorithms: &'static [CoreJwsSigningAlgorithm],
}

pub const GOOGLE: Provider = Provider {
    slug: PROVIDER_GOOGLE,
    issuer: "https://accounts.google.com",
    scopes: &["email", "profile"],
    config: "GOOGLE",
    label: "Google",
    signing_algorithms: &[CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
};

/// Every provider this module serves. Adding one is a line here plus its
/// two config keys.
pub const PROVIDERS: &[Provider] = &[GOOGLE];

/// The provider a request names, or `None` when the path segment is not one
/// we serve.
pub fn by_slug(slug: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|provider| provider.slug == slug)
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
        assert_eq!(by_slug("apple"), None, "apple arrives with #16");
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

    #[test]
    fn openid_is_not_in_the_scope_list() {
        // openidconnect always sends `openid`; listing it again would ask
        // for it twice.
        assert!(!GOOGLE.scopes.contains(&"openid"));
        assert!(GOOGLE.scopes.contains(&"email"));
    }
}
