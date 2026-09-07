//! `factory0-auth-oidc`: OpenID Connect login (issue #15).
//!
//! ```no_run
//! use factory0_auth_oidc::Oidc;
//!
//! let module = Oidc::new();
//! ```
//!
//! Google is the reference provider and the flow is written against a
//! [`provider::Provider`] descriptor, so Apple (#16) and anything else
//! compliant arrive as data rather than as a second copy of the flow.
//!
//! The module owns no tables. `auth-core` owns the schema *and* the
//! account-linking rules (#22), which decide whether an incoming identity is
//! a known person, a link to a signed-in account, an automatic link on a
//! verified address, or a new user. This module's job is to establish who
//! the provider says is at the other end, and hand that over.
//!
//! Both routes are public, and both are guarded by the same thing: a signed,
//! origin-locked cookie that this service issued minutes earlier. It is not
//! server-side single-use — spending it is not recorded anywhere — so what
//! it gives is a browser binding and a ten-minute window, not a one-shot
//! token. That is enough because everything a holder could replay it for
//! needs the rest of the flow too: the PKCE verifier it carries only
//! matches the challenge Google already holds, and the nonce only matches
//! one ID token.

#![forbid(unsafe_code)]

mod discovery;
mod flow;
mod handlers;
mod provider;
mod session;

use factory0_core::{
    Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext, Port, Problem, ProblemDef,
};
use http::StatusCode;
use std::sync::Arc;

pub use provider::{GOOGLE, PROVIDERS, Provider};

/// A provider whose client id and secret are not both configured. Named
/// rather than hidden: the operator needs to know which key is missing, and
/// a caller needs to know the button they pressed is not wired up.
pub const PROVIDER_UNCONFIGURED: ProblemDef = ProblemDef {
    slug: "auth/oidc-provider-unconfigured",
    status: StatusCode::SERVICE_UNAVAILABLE,
    title: "That sign-in provider is not configured",
    description: "Both AUTH_OIDC_<PROVIDER>_CLIENT_ID and _CLIENT_SECRET must be set",
};

/// The provider, or our request to it, failed in a way the person cannot
/// act on. Distinct from a refused sign-in.
pub const PROVIDER_UNAVAILABLE: ProblemDef = ProblemDef {
    slug: "auth/oidc-provider-unavailable",
    status: StatusCode::BAD_GATEWAY,
    title: "The sign-in provider could not be reached",
    description: "Discovery, the token exchange or the ID token failed; the detail is in the logs",
};

/// Every way a callback can be invalid answers with this, for the same
/// reason the passkey module has one refusal: telling a caller which check
/// failed tells an attacker which half to work on.
pub const CALLBACK_REFUSED: ProblemDef = ProblemDef {
    slug: "auth/oidc-callback-refused",
    status: StatusCode::BAD_REQUEST,
    title: "That sign-in link is no longer valid",
    description: "Missing, expired, replayed or mismatched authorization state",
};

pub(crate) const DEFAULT_RETURN_TO: &str = "/";

/// The one timestamp shape this service stores.
pub(crate) fn iso(at: time::OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// The resolved configuration for one provider.
#[derive(Debug, Clone)]
pub(crate) struct ProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

/// The module's configuration, resolved once per router build.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// The public origin this service answers on; the redirect URI is built
    /// from it, and it must match what the provider has registered.
    pub redirect_base: String,
    pub default_return_to: String,
}

impl Settings {
    pub(crate) fn provider_config(
        &self,
        cfg: &dyn Config,
        provider: &Provider,
    ) -> Option<ProviderConfig> {
        let module = ModuleConfig::new("auth-oidc", cfg);
        let client_id = module.get_opt(&format!("{}_CLIENT_ID", provider.config))?;
        let client_secret = module.get_opt(&format!("{}_CLIENT_SECRET", provider.config))?;
        if client_id.trim().is_empty() || client_secret.trim().is_empty() {
            return None;
        }
        Some(ProviderConfig {
            client_id,
            client_secret,
            redirect_uri: format!(
                "{}/v1/auth-oidc/{}/callback",
                self.redirect_base.trim_end_matches('/'),
                provider.slug
            ),
        })
    }
}

fn resolve_settings(cfg: &dyn Config) -> Result<Settings, Vec<String>> {
    let module = ModuleConfig::new("auth-oidc", cfg);
    let mut problems = Vec::new();

    let redirect_base = module.get_opt("REDIRECT_BASE").unwrap_or_default();
    let trimmed = redirect_base.trim().trim_end_matches('/').to_owned();
    if trimmed.is_empty() {
        problems.push(format!(
            "{} is required (the public origin this service answers on)",
            module.key("REDIRECT_BASE")
        ));
    } else if !(trimmed.starts_with("https://")
        || trimmed.starts_with("http://localhost")
        || trimmed.starts_with("http://127.0.0.1"))
    {
        problems.push(format!(
            "{} must be https (localhost may be http), got {trimmed:?}",
            module.key("REDIRECT_BASE")
        ));
    }

    let default_return_to = module.get_str("DEFAULT_RETURN_TO", DEFAULT_RETURN_TO);
    // The same rule the `return_to` parameter gets: a configured default
    // that could leave the site would be an open redirect with extra steps.
    if handlers::safe_return_to(Some(&default_return_to)).is_none() {
        problems.push(format!(
            "{} must be a path on this service beginning with a single /, got {default_return_to:?}",
            module.key("DEFAULT_RETURN_TO")
        ));
    }

    // A provider with one half of its credentials is a deployment mistake
    // worth naming: it will answer 503 at runtime and nobody will know why.
    for provider in PROVIDERS {
        let id = module.get_opt(&format!("{}_CLIENT_ID", provider.config));
        let secret = module.get_opt(&format!("{}_CLIENT_SECRET", provider.config));
        if id.is_some() != secret.is_some() {
            problems.push(format!(
                "{} needs both {}_CLIENT_ID and {}_CLIENT_SECRET, or neither",
                provider.slug, provider.config, provider.config
            ));
        }
    }

    if problems.is_empty() {
        Ok(Settings {
            redirect_base: trimmed,
            default_return_to,
        })
    } else {
        Err(problems)
    }
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Option<Settings>,
    pub discovery: discovery::Cache,
}

impl ModuleState {
    pub(crate) fn settings(&self) -> Result<&Settings, Problem> {
        self.settings
            .as_ref()
            .ok_or_else(|| Problem::not_ready("the auth-oidc module is not configured"))
    }
}

/// OpenID Connect login.
pub struct Oidc;

impl Default for Oidc {
    fn default() -> Self {
        Self::new()
    }
}

impl Oidc {
    pub fn new() -> Self {
        Self
    }
}

impl Module for Oidc {
    fn name(&self) -> &'static str {
        "auth-oidc"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[
            Port::Db,
            Port::Clock,
            Port::IdGen,
            Port::Signer,
            Port::HttpClient,
        ]
    }

    /// Both routes are reachable by anyone, and `/start` makes the service
    /// talk to a third party, so they are rate limited where a limiter
    /// exists.
    fn optional(&self) -> &'static [Port] {
        &[Port::RateLimiter]
    }

    /// None. `auth-core` owns every table this module touches.
    fn tables(&self) -> &'static [&'static str] {
        &[]
    }

    fn emits(&self) -> &'static [&'static str] {
        &[session::EVENT_LOGGED_IN, session::EVENT_AUTO_LINKED]
    }

    fn public_writes(&self) -> bool {
        true
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        match resolve_settings(cfg) {
            Ok(_) => Ok(()),
            Err(problems) => {
                let mut errors = ConfigError::default();
                for problem in problems {
                    errors.push(format!("auth-oidc: {problem}"));
                }
                Err(errors)
            }
        }
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let settings = match resolve_settings(&*ctx.config) {
            Ok(settings) => Some(settings),
            Err(problems) => {
                tracing::error!(
                    problems = problems.join("; "),
                    "auth-oidc configuration is unusable"
                );
                None
            }
        };
        handlers::router().with_state(Arc::new(ModuleState {
            ctx: Arc::new(ctx),
            settings,
            discovery: discovery::Cache::default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_core::MapConfig;

    fn config(pairs: &[(&str, &str)]) -> MapConfig {
        MapConfig::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    #[test]
    fn the_module_owns_no_tables_and_needs_the_ports_the_flow_uses() {
        let module = Oidc::new();
        assert_eq!(module.name(), "auth-oidc");
        assert!(module.tables().is_empty());
        assert!(module.migrations().sqlite.is_empty());
        assert!(module.requires().contains(&Port::HttpClient));
        assert!(module.requires().contains(&Port::Signer));
        assert_eq!(module.optional(), [Port::RateLimiter]);
        assert!(module.public_writes());
    }

    #[test]
    fn a_redirect_base_is_required_and_must_be_https() {
        assert!(Oidc::new().validate_config(&config(&[])).is_err());
        assert!(
            Oidc::new()
                .validate_config(&config(&[(
                    "AUTH_OIDC_REDIRECT_BASE",
                    "http://auth.factory0.ventures"
                )]))
                .is_err()
        );
        assert!(
            Oidc::new()
                .validate_config(&config(&[(
                    "AUTH_OIDC_REDIRECT_BASE",
                    "https://auth.factory0.ventures"
                )]))
                .is_ok()
        );
        assert!(
            Oidc::new()
                .validate_config(&config(&[(
                    "AUTH_OIDC_REDIRECT_BASE",
                    "http://localhost:8787"
                )]))
                .is_ok(),
            "wrangler dev has to work"
        );
    }

    #[test]
    fn half_a_credential_is_a_configuration_error() {
        // It would otherwise answer 503 at runtime with nothing to say why.
        let error = Oidc::new()
            .validate_config(&config(&[
                ("AUTH_OIDC_REDIRECT_BASE", "https://auth.factory0.ventures"),
                ("AUTH_OIDC_GOOGLE_CLIENT_ID", "id"),
            ]))
            .expect_err("half a credential");
        assert!(
            error.to_string().contains("GOOGLE_CLIENT_SECRET"),
            "{error}"
        );
    }

    #[test]
    fn a_default_return_to_that_could_leave_the_site_is_refused() {
        for bad in ["https://evil.example", "//evil.example", "not-a-path"] {
            assert!(
                Oidc::new()
                    .validate_config(&config(&[
                        ("AUTH_OIDC_REDIRECT_BASE", "https://auth.factory0.ventures"),
                        ("AUTH_OIDC_DEFAULT_RETURN_TO", bad),
                    ]))
                    .is_err(),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn the_redirect_uri_is_built_from_the_base_and_the_slug() {
        let cfg = config(&[
            ("AUTH_OIDC_REDIRECT_BASE", "https://auth.factory0.ventures/"),
            ("AUTH_OIDC_GOOGLE_CLIENT_ID", "id"),
            ("AUTH_OIDC_GOOGLE_CLIENT_SECRET", "secret"),
        ]);
        let settings = resolve_settings(&cfg).expect("valid");
        let provider = settings.provider_config(&cfg, &GOOGLE).expect("configured");
        // The trailing slash on the base must not become a double slash: a
        // redirect URI is matched exactly by the provider.
        assert_eq!(
            provider.redirect_uri,
            "https://auth.factory0.ventures/v1/auth-oidc/google/callback"
        );
    }
}
