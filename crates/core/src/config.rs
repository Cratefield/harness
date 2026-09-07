//! Typed configuration: the [`Config`] trait and the error type that
//! `Harness::build` uses to report every problem at once (issue #2), plus
//! the [`ModuleConfig`] helper modules read keys through (issue #3).
//!
//! Keys are `SCREAMING_SNAKE`; module keys are prefixed with the module
//! name, e.g. `EMAIL_SIGNUP_CONFIRM_TTL_DAYS`.

use std::fmt;

use crate::signer::{HmacSigner, MIN_SECRET_BYTES};
use crate::venture::VentureEnv;

/// Read-only key/value configuration, resolved per runtime from environment
/// variables and secrets (Workers `Env`) or the process environment.
///
/// Keys are `SCREAMING_SNAKE`; module keys are prefixed with the module name,
/// e.g. `EMAIL_SIGNUP_CONFIRM_TTL_DAYS`.
pub trait Config: Send + Sync {
    fn get(&self, key: &str) -> Option<String>;
}

/// A configuration that always returns `None` (tests, offline builds).
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyConfig;

impl Config for EmptyConfig {
    fn get(&self, _key: &str) -> Option<String> {
        None
    }
}

/// Accumulates every configuration problem so `Harness::build` can report
/// them together instead of one at a time.
#[derive(Debug, Default, Clone)]
pub struct ConfigError {
    /// Human-readable problem descriptions, one per line of output.
    pub problems: Vec<String>,
}

impl ConfigError {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, problem: impl Into<String>) {
        self.problems.push(problem.into());
    }

    pub fn is_empty(&self) -> bool {
        self.problems.is_empty()
    }

    /// `Err(self)` when any problem was recorded.
    ///
    /// # Errors
    ///
    /// `Err` with every recorded problem joined in its `Display`.
    pub fn into_result(self) -> Result<(), Self> {
        if self.is_empty() { Ok(()) } else { Err(self) }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid harness configuration:")?;
        for problem in &self.problems {
            write!(f, "\n  - {problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

/// Typed view over a [`Config`] for one module: prefixes every key with the
/// module name in `SCREAMING_SNAKE` and parses values with defaults
/// (issue #3).
///
/// ```
/// use cratefield_core::{Config, ModuleConfig};
/// # struct MapConfig(std::collections::HashMap<String, String>);
/// # impl Config for MapConfig {
/// #     fn get(&self, key: &str) -> Option<String> {
/// #         self.0.get(key).cloned()
/// #     }
/// # }
/// let cfg = MapConfig(
///     [("EMAIL_SIGNUP_CONFIRM_TTL_DAYS".to_string(), "3".to_string())]
///         .into_iter()
///         .collect(),
/// );
/// let module = ModuleConfig::new("email-signup", &cfg);
/// assert_eq!(module.get_u32("CONFIRM_TTL_DAYS", 7), 3);
/// assert_eq!(module.get_bool("DOUBLE_OPT_IN", true), true);
/// assert_eq!(module.get_str("FROM_NAME", "Factory Zero"), "Factory Zero");
/// ```
pub struct ModuleConfig<'a> {
    prefix: String,
    config: &'a dyn Config,
}

fn screaming_snake(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 8);
    for ch in name.chars() {
        if ch == '-' || ch == '_' {
            out.push('_');
        } else {
            out.extend(ch.to_uppercase());
        }
    }
    out
}

impl<'a> ModuleConfig<'a> {
    pub fn new(module_name: &str, config: &'a dyn Config) -> Self {
        Self {
            prefix: screaming_snake(module_name),
            config,
        }
    }

    /// The fully-qualified key for a module-suffix key.
    pub fn key(&self, suffix: &str) -> String {
        format!("{}_{}", self.prefix, screaming_snake(suffix))
    }

    pub fn get_str(&self, key_suffix: &str, default: &str) -> String {
        self.config
            .get(&self.key(key_suffix))
            .unwrap_or_else(|| default.to_string())
    }

    pub fn get_u32(&self, key_suffix: &str, default: u32) -> u32 {
        self.config
            .get(&self.key(key_suffix))
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(default)
    }

    pub fn get_bool(&self, key_suffix: &str, default: bool) -> bool {
        match self.config.get(&self.key(key_suffix)) {
            Some(raw) => matches!(
                raw.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ),
            None => default,
        }
    }

    /// An explicitly-set string key, `None` when absent.
    pub fn get_opt(&self, key_suffix: &str) -> Option<String> {
        self.config.get(&self.key(key_suffix))
    }
}

/// The harness-level keys, parsed once from the environment `Config`
/// (issue #3): `HARNESS_SECRET` (required, ≥ 32 bytes),
/// `HARNESS_SECRET_PREVIOUS` (optional), `ADMIN_TOKEN` (optional),
/// `ENV` (`development|staging|production`, default `development`).
///
/// Dummy secrets only, in tests:
/// `HARNESS_SECRET = "test-secret-0123456789abcdef-0123"`.
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    pub harness_secret: String,
    pub harness_secret_previous: Option<String>,
    pub admin_token: Option<String>,
    pub env: VentureEnv,
}

impl HarnessConfig {
    /// # Errors
    ///
    /// One problem per invalid key, reported together: missing or short
    /// `HARNESS_SECRET`, unknown `ENV` value.
    pub fn from_config(config: &dyn Config) -> Result<Self, ConfigError> {
        let mut errors = ConfigError::default();

        let harness_secret = match config.get("HARNESS_SECRET") {
            Some(secret) if secret.len() >= MIN_SECRET_BYTES => Some(secret),
            Some(_) => {
                errors.push(format!(
                    "HARNESS_SECRET must be at least {MIN_SECRET_BYTES} bytes"
                ));
                None
            }
            None => {
                errors.push(format!(
                    "HARNESS_SECRET is required (min {MIN_SECRET_BYTES} bytes)"
                ));
                None
            }
        };
        let env = match config.get("ENV").as_deref() {
            None | Some("") => Some(VentureEnv::Development),
            Some(raw) => {
                let parsed = VentureEnv::parse(raw);
                if parsed.is_none() {
                    errors.push(format!(
                        "ENV must be one of development|staging|production, got {raw:?}"
                    ));
                }
                parsed
            }
        };

        errors.into_result()?;
        Ok(Self {
            harness_secret: harness_secret.unwrap_or_default(),
            harness_secret_previous: config.get("HARNESS_SECRET_PREVIOUS"),
            admin_token: config.get("ADMIN_TOKEN"),
            env: env.unwrap_or_default(),
        })
    }

    /// The HMAC signer for this configuration (ADR 0006).
    ///
    /// # Panics
    ///
    /// Only when `from_config` was bypassed with an invalid secret.
    pub fn signer(&self) -> HmacSigner {
        HmacSigner::new(
            self.harness_secret.clone(),
            self.harness_secret_previous.clone(),
        )
        .expect("from_config validated the secret")
    }
}

/// A `Config` backed by a map (tests, `fz doctor` with process env).
#[derive(Debug, Clone, Default)]
pub struct MapConfig(pub std::collections::HashMap<String, String>);

impl MapConfig {
    pub fn from_pairs(
        pairs: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        Self(
            pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }
}

impl Config for MapConfig {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}
