//! Ready-made [`Provider`]s for the six services a venture most often needs
//! to connect (issue #624).
//!
//! A preset fixes only the wire facts the OAuth dance turns on — the
//! endpoints, the client-authentication method, the scope separator, the extra
//! authorize parameters, and whether the provider rotates its refresh token —
//! each cited against the vendor's own documentation. No secret lives here:
//! the client id and secret come from `CONNECTIONS_<KEY>_CLIENT_ID` /
//! `CONNECTIONS_<KEY>_CLIENT_SECRET` at call time, and the scope list is a
//! starting point a venture edits to taste.
//!
//! ```
//! use cratefield_module_connections::{Connections, presets};
//!
//! let connections = Connections::builder()
//!     .provider(presets::x())
//!     .provider(presets::gitlab().with_scopes(["read_user", "api"]))
//!     .allowed_origin("https://app.example.com")
//!     .build();
//! # let _ = connections;
//! ```

use cratefield_oauth_client::ClientAuth;

use crate::Provider;

/// X (Twitter), authorization code with PKCE.
///
/// Docs: <https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code>.
/// Basic client auth, S256 PKCE, and `offline.access` for a refresh token. X
/// documents the refresh request but not its rotation policy, so the preset
/// treats the token as rotating — the safe reading either way, since the
/// guarded write stores whatever the response returns.
#[must_use]
pub fn x() -> Provider {
    Provider {
        key: "x".to_owned(),
        authorize_url: "https://x.com/i/oauth2/authorize".to_owned(),
        token_url: "https://api.x.com/2/oauth2/token".to_owned(),
        revoke_url: Some("https://api.x.com/2/oauth2/revoke".to_owned()),
        scopes: vec![
            "tweet.read".to_owned(),
            "users.read".to_owned(),
            "offline.access".to_owned(),
        ],
        scope_separator: " ",
        client_auth: ClientAuth::ClientSecretBasic,
        authorize_params: Vec::new(),
        rotating_refresh: true,
        pkce: true,
    }
}

/// Google, the web-server flow.
///
/// Docs: <https://developers.google.com/identity/protocols/oauth2/web-server>.
/// Basic client auth (RFC 6749 §2.3.1's preference), S256 PKCE.
/// `access_type=offline` with `prompt=consent` is what makes a reconnect end
/// with a fresh refresh token; the token itself is **not** rotated.
#[must_use]
pub fn google() -> Provider {
    Provider {
        key: "google".to_owned(),
        authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
        token_url: "https://oauth2.googleapis.com/token".to_owned(),
        revoke_url: Some("https://oauth2.googleapis.com/revoke".to_owned()),
        scopes: vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ],
        scope_separator: " ",
        client_auth: ClientAuth::ClientSecretBasic,
        authorize_params: vec![
            ("access_type".to_owned(), "offline".to_owned()),
            ("prompt".to_owned(), "consent".to_owned()),
        ],
        rotating_refresh: false,
        pkce: true,
    }
}

/// LinkedIn, 3-legged OAuth.
///
/// Docs: <https://learn.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow>.
/// Credentials in the form body, no PKCE parameters in the member flow, and no
/// RFC 7009 revocation endpoint — a member withdraws access from LinkedIn
/// itself — so `revoke_url` stays unset. The refresh token is not rotated.
#[must_use]
pub fn linkedin() -> Provider {
    Provider {
        key: "linkedin".to_owned(),
        authorize_url: "https://www.linkedin.com/oauth/v2/authorization".to_owned(),
        token_url: "https://www.linkedin.com/oauth/v2/accessToken".to_owned(),
        revoke_url: None,
        scopes: vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ],
        scope_separator: " ",
        client_auth: ClientAuth::ClientSecretPost,
        authorize_params: Vec::new(),
        rotating_refresh: false,
        pkce: false,
    }
}

/// Vercel, "Sign in with Vercel".
///
/// Docs: <https://vercel.com/docs/sign-in-with-vercel/authorization-server-api>.
/// Credentials in the form body; a PKCE challenge is required and only S256 is
/// accepted. Vercel **rotates** the refresh token — each one is single-use —
/// so the stored value is replaced on every refresh.
#[must_use]
pub fn vercel() -> Provider {
    Provider {
        key: "vercel".to_owned(),
        authorize_url: "https://vercel.com/oauth/authorize".to_owned(),
        token_url: "https://api.vercel.com/login/oauth/token".to_owned(),
        revoke_url: Some("https://api.vercel.com/login/oauth/token/revoke".to_owned()),
        scopes: vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ],
        scope_separator: " ",
        client_auth: ClientAuth::ClientSecretPost,
        authorize_params: Vec::new(),
        rotating_refresh: true,
        pkce: true,
    }
}

/// GitLab on gitlab.com. Use [`gitlab_at`] for a self-managed instance.
///
/// Docs: <https://docs.gitlab.com/ee/api/oauth2.html>. Credentials in the form
/// body, S256 PKCE, and a **rotating** refresh token: the one presented is
/// revoked and a new one returned.
#[must_use]
pub fn gitlab() -> Provider {
    gitlab_at("https://gitlab.com")
}

/// GitLab on a self-managed instance: the same paths under `base`.
///
/// The OAuth 2.0 documentation applies with the instance's own host
/// substituted for `gitlab.com`; the endpoints are always `/oauth/authorize`,
/// `/oauth/token` and `/oauth/revoke` under it. A trailing slash on `base` is
/// dropped, so `https://gitlab.example.com/` names the same instance.
#[must_use]
pub fn gitlab_at(base: &str) -> Provider {
    let base = base.trim_end_matches('/');
    Provider {
        key: "gitlab".to_owned(),
        authorize_url: format!("{base}/oauth/authorize"),
        token_url: format!("{base}/oauth/token"),
        revoke_url: Some(format!("{base}/oauth/revoke")),
        scopes: vec!["read_user".to_owned()],
        scope_separator: " ",
        client_auth: ClientAuth::ClientSecretPost,
        authorize_params: Vec::new(),
        rotating_refresh: true,
        pkce: true,
    }
}

/// Linear.
///
/// Docs: <https://linear.app/developers/oauth-2-0-authentication>. Credentials
/// in the form body, S256 PKCE, and a **rotating** refresh token. Linear is
/// the one preset that joins scopes with a comma, not a space — the request is
/// comma-separated, which is why the separator is part of the spec.
#[must_use]
pub fn linear() -> Provider {
    Provider {
        key: "linear".to_owned(),
        authorize_url: "https://linear.app/oauth/authorize".to_owned(),
        token_url: "https://api.linear.app/oauth/token".to_owned(),
        revoke_url: Some("https://api.linear.app/oauth/revoke".to_owned()),
        scopes: vec!["read".to_owned(), "write".to_owned()],
        scope_separator: ",",
        client_auth: ClientAuth::ClientSecretPost,
        authorize_params: Vec::new(),
        rotating_refresh: true,
        pkce: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire facts a preset must get right, and the three a single shared
    /// constant could not carry: LinkedIn's missing revoke endpoint, Linear's
    /// comma separator, and self-managed GitLab's host substitution. The
    /// per-provider refresh *behaviour* these imply is driven end to end in
    /// `tests/refresh.rs`.
    #[test]
    fn presets_carry_the_wire_facts() {
        for provider in [x(), google(), vercel(), gitlab(), linear()] {
            assert!(!provider.key.is_empty());
            assert!(
                provider.authorize_url.starts_with("https://"),
                "{provider:?}"
            );
            assert!(provider.token_url.starts_with("https://"), "{provider:?}");
            assert!(
                provider.revoke_url.is_some(),
                "{} has no revoke URL",
                provider.key
            );
            assert!(
                !provider.scopes.is_empty(),
                "{} asks for no scopes",
                provider.key
            );
        }
        assert!(
            linkedin().revoke_url.is_none(),
            "LinkedIn documents no revocation endpoint, so the preset must not invent one"
        );
        assert_eq!(linear().scope_separator, ",");
        assert_eq!(google().scope_separator, " ");
        let self_managed = gitlab_at("https://gitlab.example.com/");
        assert_eq!(self_managed.key, "gitlab");
        assert_eq!(
            self_managed.authorize_url,
            "https://gitlab.example.com/oauth/authorize"
        );
        assert_eq!(
            self_managed.token_url,
            "https://gitlab.example.com/oauth/token"
        );
    }
}
