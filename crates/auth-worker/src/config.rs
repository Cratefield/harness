//! The auth Worker's configuration surface (issue #646): one struct reads
//! every variable, validates them together at boot, and builds the [`Venture`]
//! and the [`Mailer`] the composition runs with. Every invalid value is a
//! startup error, never a silent fallback.
//!
//! **One instance per app (issue #777).** Nothing here defaults to any
//! app's name or domain. The values that make an instance *somebody's*
//! (`AUTH_PUBLIC_URL`, `AUTH_VENTURE_NAME`, `AUTH_CORS_ORIGINS`,
//! `AUTH_BRAND_NAME`) are required, and a missing one is refused with a
//! message naming it. Everything else either derives from them (the
//! Turnstile hostname, the default `MAIL_FROM`, the problem-type base) or
//! is genuinely optional (the rest of the branding, `MAIL_REPLY_TO`).

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use auth_core::Brand;
use cratefield_adapter_owlpost::Owlpost;
use cratefield_adapter_resend::Resend;
use cratefield_core::{
    Clock, Config, ConfigError, HttpClient, MailError, Mailer, Message, SendOutcome, Venture,
    VentureEnv,
};
use url::Url;

/// Which provider the instance sends its mail through, resolved at boot
/// from `AUTH_MAILER` and the keys present. Owlpost is the supported
/// default; Resend stays available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailerKind {
    /// Sends through Owlpost (`cratefield-adapter-owlpost`).
    Owlpost,
    /// Sends through Resend.
    Resend,
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
    /// The instance's branding: the display name every page and mail
    /// subject uses, plus the optional logo, accent, links and footer.
    pub brand: Brand,
    /// An explicit problem-type base (`AUTH_PROBLEM_BASE`, issue #557);
    /// unset means `<AUTH_PUBLIC_URL>/problems/`.
    pub problem_base: Option<String>,
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

        let public_url = required(
            cfg,
            "AUTH_PUBLIC_URL",
            "the instance's own origin, e.g. https://auth.example.com",
            // A bare trailing slash is allowed and normalized away.
            |raw| require_origin(raw.trim_end_matches('/')),
            &mut errors,
        );
        let host = public_url
            .as_deref()
            .map(host_of)
            .unwrap_or_default()
            .to_owned();

        let venture_name = required(
            cfg,
            "AUTH_VENTURE_NAME",
            "the instance's kebab-case id, e.g. example-auth",
            require_kebab_case,
            &mut errors,
        );
        let cors_origins = read_cors_origins(cfg, &mut errors);
        check_brand(cfg, &mut errors);
        let problem_base = read_problem_base(cfg, &mut errors);
        // Defaults to the instance's own host; when the public URL is
        // missing, its own error already says so.
        let turnstile_hostname = match get(cfg, "AUTH_TURNSTILE_HOSTNAME") {
            Some(raw) => take(
                Some(&raw),
                "AUTH_TURNSTILE_HOSTNAME",
                "",
                require_hostname,
                &mut errors,
            ),
            None => host.clone(),
        };

        let default_from = if host.is_empty() {
            String::new()
        } else {
            format!("no-reply@{host}")
        };
        let mail_from = match get(cfg, "MAIL_FROM") {
            Some(raw) => take(Some(&raw), "MAIL_FROM", "", require_address, &mut errors),
            // Derived from the public URL; when that is missing its own
            // error already says so.
            None => default_from,
        };
        let mail_reply_to = get(cfg, "MAIL_REPLY_TO");
        if let Some(value) = mail_reply_to.as_deref()
            && let Err(problem) = require_address(value)
        {
            errors.push(format!("MAIL_REPLY_TO: {problem}"));
        }

        // `auth-core` mints tokens under `AUTH_CORE_ISSUER`, so an instance
        // must not point it at another origin: the discovery document would
        // advertise an issuer the tokens do not match.
        if let (Some(issuer), Some(public_url)) = (get(cfg, "AUTH_CORE_ISSUER"), &public_url)
            && !issuer
                .trim_end_matches('/')
                .eq_ignore_ascii_case(public_url)
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
        let (Some(public_url), Some(venture_name)) = (public_url, venture_name) else {
            // Both are pushed as errors when missing, so this is unreachable
            // once `into_result` passed; refuse rather than invent a value.
            let mut errors = ConfigError::new();
            errors.push("AUTH_PUBLIC_URL and AUTH_VENTURE_NAME are required".to_owned());
            return Err(errors);
        };
        let host_venture = Venture::new(venture_name.clone(), host_of(&public_url).to_owned());
        let brand = Brand::from_config(cfg, &host_venture);
        Ok(Self {
            public_url,
            venture_name,
            brand,
            problem_base,
            cors_origins,
            turnstile_hostname,
            mail_from,
            mail_reply_to,
            mailer_kind,
            env,
            provider,
        })
    }

    /// The venture descriptor: name, domain, public URL, problem-type base
    /// and mail branding from this config.
    ///
    /// The compiled [`VentureEnv`] stays at its default, so
    /// `HarnessBuilder::build`'s production-only boot gates do not refuse the
    /// staging Worker; `ENV` is applied at request time by
    /// `cratefield_core::deployed_env`.
    #[must_use]
    pub fn venture(&self) -> Venture {
        let venture = Venture::new(
            self.venture_name.clone(),
            host_of(&self.public_url).to_owned(),
        )
        .public_url(self.public_url.clone())
        .cors_origins(self.cors_origins.clone())
        .brand(cratefield_core::Brand {
            accent: self.brand.accent.clone(),
            logo_url: self.brand.logo_url.clone(),
            footer: Some(self.brand.footer.clone()),
        });
        match &self.problem_base {
            Some(base) => venture.problem_base(base.clone()),
            None => venture,
        }
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

/// `AUTH_CORS_ORIGINS`: required, and never empty.
fn read_cors_origins(cfg: &dyn Config, errors: &mut ConfigError) -> Vec<String> {
    match get(cfg, "AUTH_CORS_ORIGINS") {
        Some(raw) => parse_origins(&raw, errors),
        None if cfg.get("AUTH_CORS_ORIGINS").is_some() => parse_origins("", errors),
        None => {
            errors.push(
                "AUTH_CORS_ORIGINS is required: the app's own browser origins, \
                 comma-separated, e.g. https://example.com,https://app.example.com"
                    .to_owned(),
            );
            Vec::new()
        }
    }
}

/// The branding: `AUTH_BRAND_NAME` is required of an instance, and every
/// branding value present must be well formed.
fn check_brand(cfg: &dyn Config, errors: &mut ConfigError) {
    if get(cfg, auth_core::brand::NAME_KEY).is_none() {
        errors.push(format!(
            "{} is required: the display name the login pages and mail subjects use, \
             e.g. Example",
            auth_core::brand::NAME_KEY
        ));
    }
    for problem in Brand::problems(cfg) {
        errors.push(problem);
    }
}

/// `AUTH_PROBLEM_BASE` (issue #557): optional, an absolute URL when set.
fn read_problem_base(cfg: &dyn Config, errors: &mut ConfigError) -> Option<String> {
    let problem_base = get(cfg, "AUTH_PROBLEM_BASE");
    if let Some(base) = problem_base.as_deref()
        && let Err(problem) = require_base_url(base)
    {
        errors.push(format!("AUTH_PROBLEM_BASE: {problem}"));
    }
    problem_base
}

/// A value the instance cannot run without: a missing one is refused with
/// `what` as the hint, never replaced by somebody else's value.
fn required(
    cfg: &dyn Config,
    key: &str,
    what: &str,
    check: impl FnOnce(&str) -> Result<String, String>,
    errors: &mut ConfigError,
) -> Option<String> {
    let Some(raw) = get(cfg, key) else {
        errors.push(format!("{key} is required: {what}"));
        return None;
    };
    match check(&raw) {
        Ok(value) => Some(value),
        Err(problem) => {
            errors.push(format!("{key}: {problem}"));
            None
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
        // Unset: whichever single provider has a key, Owlpost first. Both
        // keys and no choice is ambiguous, and production must send mail.
        (None, resend, owlpost) => match (resend, owlpost) {
            (None, Some(key)) => Provider::Owlpost {
                key: Secret(Some(key)),
                base: owlpost_base,
            },
            (Some(key), None) => Provider::Resend(Secret(Some(key))),
            (Some(_), Some(_)) => {
                errors.push(
                    "AUTH_MAILER: both OWLPOST_API_KEY and RESEND_API_KEY are set; \
                     set AUTH_MAILER to owlpost or resend"
                        .to_owned(),
                );
                Provider::None
            }
            (None, None) => {
                if env == VentureEnv::Production {
                    errors.push(
                        "AUTH_MAILER: ENV=production needs a mailer; set AUTH_MAILER=owlpost \
                         and the OWLPOST_API_KEY secret (or AUTH_MAILER=resend and \
                         RESEND_API_KEY)"
                            .to_owned(),
                    );
                }
                Provider::None
            }
        },
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
