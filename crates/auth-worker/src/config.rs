//! The auth Worker's configuration surface (issue #646): one struct reads
//! every variable, validates them together at boot, and builds the [`Venture`]
//! and the [`Mailer`] the composition runs with. Every invalid value is a
//! startup error, never a silent fallback; the fallbacks live in
//! [`crate::defaults`].

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use cratefield_adapter_owlpost::Owlpost;
use cratefield_adapter_resend::Resend;
use cratefield_core::{
    Clock, Config, ConfigError, HttpClient, MailError, Mailer, Message, SendOutcome, Venture,
    VentureEnv,
};
use url::Url;

use crate::defaults;

/// Which provider the venture sends through, resolved at boot from
/// `AUTH_MAILER` and the keys present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailerKind {
    /// Sends through Resend.
    Resend,
    /// Sends through Owlpost.
    Owlpost,
    /// A capture-only no-op: no provider key is configured.
    None,
}

/// A credential: `Debug` says whether it is set, never its value.
#[derive(Clone)]
struct Secret(Option<String>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() { "<set>" } else { "<unset>" })
    }
}

#[derive(Clone, Debug)]
enum Provider {
    Resend(Secret),
    Owlpost { key: Secret, base: Option<String> },
    None,
}

/// The Worker's validated configuration: every field is usable as-is, because
/// [`AuthWorkerConfig::from_config`] refused invalid values.
#[derive(Clone, Debug)]
pub struct AuthWorkerConfig {
    /// The absolute origin the API is served on.
    pub public_url: String,
    /// The kebab-case venture name.
    pub venture_name: String,
    /// The browser origins allowed to call cross-origin.
    pub cors_origins: Vec<String>,
    /// The hostname the Turnstile verdict must name.
    pub turnstile_hostname: String,
    /// The adapter-level `From`; a module that sets its own on the [`Message`]
    /// overrides it (`auth-magic-link` sends from `AUTH_MAGIC_LINK_MAIL_FROM`).
    pub mail_from: String,
    /// The adapter-level `Reply-To`, when configured.
    pub mail_reply_to: Option<String>,
    /// Which provider [`AuthWorkerConfig::mailer`] sends through.
    pub mailer_kind: MailerKind,
    /// The deployment environment, from `ENV`.
    pub env: VentureEnv,
    provider: Provider,
}

impl AuthWorkerConfig {
    /// Reads and validates every variable, collecting **all** problems before
    /// failing.
    ///
    /// # Errors
    ///
    /// `Err` listing every invalid or missing value.
    pub fn from_config(cfg: &dyn Config) -> Result<Self, ConfigError> {
        let mut errors = ConfigError::new();

        let raw_public = get(cfg, "AUTH_PUBLIC_URL");
        let public_url = take(
            raw_public.as_deref(),
            "AUTH_PUBLIC_URL",
            defaults::PUBLIC_URL,
            // A bare trailing slash is allowed and normalized away.
            |raw| require_origin(raw.trim_end_matches('/')),
            &mut errors,
        );
        let host = host_of(&public_url).to_owned();

        let venture_name = take(
            get(cfg, "AUTH_VENTURE_NAME").as_deref(),
            "AUTH_VENTURE_NAME",
            defaults::VENTURE_NAME,
            require_kebab_case,
            &mut errors,
        );
        let cors_origins = match cfg.get("AUTH_CORS_ORIGINS") {
            Some(raw) => parse_origins(&raw, &mut errors),
            None => defaults::CORS_ORIGINS
                .iter()
                .map(ToString::to_string)
                .collect(),
        };
        let turnstile_hostname = take(
            get(cfg, "AUTH_TURNSTILE_HOSTNAME").as_deref(),
            "AUTH_TURNSTILE_HOSTNAME",
            &host,
            require_hostname,
            &mut errors,
        );

        let default_from = format!("no-reply@{host}");
        let mail_from = take(
            get(cfg, "MAIL_FROM").as_deref(),
            "MAIL_FROM",
            &default_from,
            require_address,
            &mut errors,
        );
        let mail_reply_to = get(cfg, "MAIL_REPLY_TO");
        if let Some(value) = mail_reply_to.as_deref()
            && let Err(problem) = require_address(value)
        {
            errors.push(format!("MAIL_REPLY_TO: {problem}"));
        }

        // `auth-core` mints tokens under `AUTH_CORE_ISSUER`, so a deployment
        // must not point it at another origin: the discovery document would
        // advertise an issuer the tokens do not match. Checked only when
        // `AUTH_PUBLIC_URL` is set — a staging Worker may keep the default
        // public URL and still mint under its own host.
        if let Some(issuer) = get(cfg, "AUTH_CORE_ISSUER")
            && raw_public.is_some()
            && !issuer
                .trim_end_matches('/')
                .eq_ignore_ascii_case(&public_url)
        {
            errors.push("AUTH_CORE_ISSUER must equal AUTH_PUBLIC_URL".to_owned());
        }

        let env = match get(cfg, "ENV") {
            None => VentureEnv::default(),
            Some(raw) => VentureEnv::parse(&raw).unwrap_or_else(|| {
                errors.push(format!(
                    "ENV: unknown value {raw:?} (expected development, staging or production)"
                ));
                VentureEnv::default()
            }),
        };

        let provider = resolve_provider(cfg, env, &mut errors);
        let mailer_kind = match &provider {
            Provider::Resend(_) => MailerKind::Resend,
            Provider::Owlpost { .. } => MailerKind::Owlpost,
            Provider::None => MailerKind::None,
        };

        errors.into_result()?;
        Ok(Self {
            public_url,
            venture_name,
            cors_origins,
            turnstile_hostname,
            mail_from,
            mail_reply_to,
            mailer_kind,
            env,
            provider,
        })
    }

    /// The venture descriptor: name, domain and public URL from this config.
    ///
    /// The compiled [`VentureEnv`] stays at its default, so
    /// `HarnessBuilder::build`'s production-only boot gates do not refuse the
    /// staging Worker; `ENV` is applied at request time by
    /// `cratefield_core::deployed_env`.
    #[must_use]
    pub fn venture(&self) -> Venture {
        Venture::new(
            self.venture_name.clone(),
            host_of(&self.public_url).to_owned(),
        )
        .public_url(self.public_url.clone())
        .cors_origins(self.cors_origins.clone())
    }

    /// Builds the mailer over the injected ports: a test drives the same
    /// selection the deployment does, with fakes.
    #[must_use]
    pub fn mailer(&self, http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Arc<dyn Mailer> {
        let from = self.mail_from.clone();
        let reply_to = self.mail_reply_to.clone();
        match &self.provider {
            Provider::Resend(Secret(key)) => {
                Arc::new(Resend::new(http, clock, key.clone(), from, reply_to))
            }
            Provider::Owlpost { key, base } => {
                let owlpost = Owlpost::new(http, clock, key.0.clone(), from, reply_to);
                Arc::new(match base {
                    Some(base) => owlpost.with_base_url(base.clone()),
                    None => owlpost,
                })
            }
            Provider::None => Arc::new(NoopMailer),
        }
    }
}

/// Validates the Worker's configuration without keeping it — the harness's
/// `Module::validate_config` contract names this.
///
/// # Errors
///
/// `Err` listing every invalid or missing value.
pub fn validate_config(cfg: &dyn Config) -> Result<(), ConfigError> {
    AuthWorkerConfig::from_config(cfg).map(|_| ())
}

/// Validates `raw` (or `fallback` when unset); a problem is recorded as
/// `KEY: <problem>` and `fallback` is used instead.
fn take(
    raw: Option<&str>,
    key: &str,
    fallback: &str,
    check: impl FnOnce(&str) -> Result<String, String>,
    errors: &mut ConfigError,
) -> String {
    match check(raw.unwrap_or(fallback)) {
        Ok(value) => value,
        Err(problem) => {
            errors.push(format!("{key}: {problem}"));
            fallback.to_owned()
        }
    }
}

/// `AUTH_MAILER`, the keys present and the environment, resolved into the
/// provider to build.
fn resolve_provider(cfg: &dyn Config, env: VentureEnv, errors: &mut ConfigError) -> Provider {
    let owlpost_base = get(cfg, "OWLPOST_BASE_URL");
    if let Some(base) = owlpost_base.as_deref()
        && let Err(problem) = require_base_url(base)
    {
        errors.push(format!("OWLPOST_BASE_URL: {problem}"));
    }
    let asked = get(cfg, "AUTH_MAILER").map(|value| value.to_ascii_lowercase());
    match (
        asked.as_deref(),
        get(cfg, "RESEND_API_KEY"),
        get(cfg, "OWLPOST_API_KEY"),
    ) {
        // Unset: today's behaviour — Resend when its key is present.
        (None, key, _) => key.map_or(Provider::None, |key| Provider::Resend(Secret(Some(key)))),
        (Some("resend"), Some(key), _) => Provider::Resend(Secret(Some(key))),
        (Some("resend"), None, _) => {
            errors.push("AUTH_MAILER: resend requires RESEND_API_KEY".to_owned());
            Provider::None
        }
        (Some("owlpost"), _, Some(key)) => Provider::Owlpost {
            key: Secret(Some(key)),
            base: owlpost_base,
        },
        (Some("owlpost"), _, None) => {
            errors.push("AUTH_MAILER: owlpost requires OWLPOST_API_KEY".to_owned());
            Provider::None
        }
        (Some("none"), ..) => {
            if env == VentureEnv::Production {
                errors.push("AUTH_MAILER: none is refused when ENV=production".to_owned());
            }
            Provider::None
        }
        (Some(other), ..) => {
            errors.push(format!(
                "AUTH_MAILER: unknown value {other:?} (expected resend, owlpost or none)"
            ));
            Provider::None
        }
    }
}

/// Reports a send as done without sending — until a provider key is set, so
/// magic-link requests still create their rows instead of failing.
struct NoopMailer;

#[async_trait]
impl Mailer for NoopMailer {
    async fn send(&self, _message: Message) -> Result<SendOutcome, MailError> {
        Ok(SendOutcome::Sent {
            id: "noop".to_owned(),
        })
    }
}

/// One variable, trimmed; blank reads as unset.
fn get(cfg: &dyn Config, key: &str) -> Option<String> {
    cfg.get(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Parses an absolute URL — `scheme://host[:port]`, with or without a path.
fn parse_url(value: &str) -> Result<Url, String> {
    Url::parse(value).map_err(|err| format!("{value:?} is not an absolute URL: {err}"))
}

/// The scheme rule the URL kinds share: `http(s)`, and `http` only on the
/// loopback host.
fn check_scheme(url: &Url, value: &str) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{value:?} must use http or https"));
    }
    if url.scheme() == "http" && !is_loopback(url.host_str().unwrap_or_default()) {
        return Err(format!(
            "{value:?} must use https (http is allowed only on the loopback host)"
        ));
    }
    Ok(())
}

/// A bare `scheme://host[:port]` origin: no path, query, fragment or trailing
/// slash.
fn require_origin(value: &str) -> Result<String, String> {
    let url = parse_url(value)?;
    check_scheme(&url, value)?;
    if value.ends_with('/')
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(format!(
            "{value:?} must be an origin with no path, query or fragment"
        ));
    }
    Ok(url.origin().ascii_serialization())
}

/// An absolute https URL; a path is fine, an Owlpost base may sit on one.
fn require_base_url(value: &str) -> Result<String, String> {
    let url = parse_url(value)?;
    check_scheme(&url, value)?;
    Ok(value.to_owned())
}

/// Splits a comma-separated allowlist of exact origins, trimming each. A list
/// that resolves to nothing is refused: the harness cannot express "no
/// cross-origin callers", so accepting it would only move the failure to
/// `HarnessBuilder::build`.
fn parse_origins(raw: &str, errors: &mut ConfigError) -> Vec<String> {
    let mut origins = Vec::new();
    for origin in raw
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if origin == "*" {
            errors.push("AUTH_CORS_ORIGINS: wildcard `*` is not allowed".to_owned());
            continue;
        }
        match require_origin(origin) {
            // Browsers send the canonical origin, so an entry that is not
            // already it could never match a real request.
            Ok(canonical) if canonical == origin => origins.push(canonical),
            Ok(canonical) => errors.push(format!(
                "AUTH_CORS_ORIGINS: {origin:?} must be written as its canonical origin {canonical:?}"
            )),
            Err(problem) => errors.push(format!("AUTH_CORS_ORIGINS: {problem}")),
        }
    }
    if origins.is_empty() {
        errors.push(
            "AUTH_CORS_ORIGINS: at least one origin is required (an empty allowlist is not supported)"
                .to_owned(),
        );
    }
    origins
}

/// The host of `scheme://host[:port][/…]`, brackets included for IPv6.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    if rest.starts_with('[') {
        return rest
            .split_once(']')
            .map_or(rest, |(before, _)| &rest[..=before.len()]);
    }
    rest.split(['/', '?', '#', ':']).next().unwrap_or_default()
}

/// Whether `host` names this machine; compared exactly, so `localhost.evil`
/// and `127.0.0.10` are not loopback.
fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// `AUTH_TURNSTILE_HOSTNAME`: a bare hostname — no port, no path.
fn require_hostname(value: &str) -> Result<String, String> {
    let parsed = parse_url(&format!("https://{value}"))
        .map_err(|_| format!("must be a bare hostname, got {value:?}"))?;
    if parsed.host_str() == Some(value) && parsed.port().is_none() {
        return Ok(value.to_owned());
    }
    Err(format!("must be a bare hostname, got {value:?}"))
}

/// `AUTH_VENTURE_NAME`: kebab-case, as `Venture::validate` requires.
fn require_kebab_case(value: &str) -> Result<String, String> {
    let kebab = !value.is_empty()
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        });
    if kebab {
        return Ok(value.to_owned());
    }
    Err(format!(
        "must be kebab-case ([a-z0-9]+ separated by '-'), got {value:?}"
    ))
}

/// A sending address: `addr@host`, or `Name <addr@host>`. The address needs a
/// non-empty local part and domain and a single `@`; the value must be
/// CR/LF-free (no header injection).
fn require_address(value: &str) -> Result<String, String> {
    if value.contains(['\r', '\n']) {
        return Err("must not contain CR or LF".to_owned());
    }
    // Only an address in angle brackets may follow a display name.
    let addr = match value.split_once('<') {
        Some((_, rest)) => rest.strip_suffix('>').unwrap_or_default(),
        None if value.chars().any(char::is_whitespace) => "",
        None => value,
    };
    let (local, domain) = addr.split_once('@').unwrap_or(("", ""));
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(format!("{value:?} is not an email address"));
    }
    Ok(value.to_owned())
}
