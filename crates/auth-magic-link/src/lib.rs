//! `factory0-auth-magic-link`: sign in by email (issue #21).
//!
//! ```no_run
//! use factory0_auth_magic_link::MagicLink;
//!
//! let module = MagicLink::new();
//! ```
//!
//! A magic link is a **bearer credential sent over email**, which is a
//! channel this service does not control and cannot audit. Everything here
//! follows from that: the token is 32 random bytes, stored only as its
//! SHA-256, valid for fifteen minutes, and single-use under concurrency
//! rather than by convention.
//!
//! It is also the answer to three things other modules leave undone:
//!
//! - **Verifying an address.** Password registration (#19) creates an
//!   account with `primary_email_verified = 0`, because registering must
//!   not be a way to claim somebody else's address. Consuming a link sent
//!   to that address is the proof, and the linking rules only ever
//!   auto-link a verified one.
//! - **Getting back in.** A password lockout (#12) is deliberately not a
//!   dead end; a passwordless account has no other way in at all.
//! - **Registration by mail**, for a venture that wants no passwords.
//!
//! **The link asks; only the button acts.** `GET /consume` never spends
//! the token: it always renders a confirm page, and only that page's
//! same-origin `POST` signs somebody in. Outlook, some corporate scanners
//! and several mobile clients fetch every URL in a message to check it
//! for malware, which would otherwise consume the token before the person
//! ever clicked. And a GET that signed in would be login CSRF (issue
//! #483): a site that forces a browser onto an attacker's own link sends
//! the same fetch metadata as a click out of webmail, so no header can
//! tell the two apart.

#![forbid(unsafe_code)]

mod handlers;
mod mail;

use cratefield_core::{
    Config, ConfigError, DataKind, Disposition, Migrations, Module, ModuleConfig, ModuleContext,
    PersonalDataSet, Port, ProblemDef, SqlMigration, SubjectVia,
};

/// The durable send-cooldown table behind the one-mail-per-window claim
/// (issue #133). Name must match `handlers::SEND_COOLDOWN_TABLE`.
const MIGRATION_SEND_COOLDOWN: SqlMigration = SqlMigration::new(
    "0001",
    "send_cooldown",
    include_str!("../migrations/sqlite/0001_send_cooldown.sql"),
);
use http::StatusCode;
use std::sync::Arc;

pub use mail::{MagicLinkMail, TEMPLATE_MAGIC_LINK, default_templates};

/// The one answer a request gives, whatever it found.
pub const REQUEST_REFUSED: ProblemDef = ProblemDef {
    slug: "auth/magic-link-refused",
    status: StatusCode::BAD_REQUEST,
    title: "That sign-in link is no longer valid",
    description: "Missing, expired, already used, or never issued",
};

/// The module is mounted but cannot send.
pub const NOT_READY: ProblemDef = ProblemDef {
    slug: "auth/magic-link-not-ready",
    status: StatusCode::SERVICE_UNAVAILABLE,
    title: "Email sign-in is not available",
    description: "The module is missing a port it requires",
};

/// How long a link lasts. Long enough for mail to arrive and a person to
/// read it, short enough that a message sitting in an unlocked inbox stops
/// being a way in.
pub const DEFAULT_TTL_SECS: i64 = 900;

/// The resolved configuration.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// The public origin. The link is built from it and must be reachable
    /// from a mail client.
    pub public_base: String,
    /// Where to send somebody after a successful consume, when the request
    /// carried no `return_to`.
    pub default_return_to: String,
    pub ttl_secs: i64,
    /// Whether a request for an address with no account creates one.
    ///
    /// Off by default. A venture that wants passwordless sign-up turns it
    /// on deliberately, because when it is on, anyone can create an
    /// account for any address they can type.
    pub allow_registration: bool,
    /// The `From` address. Mail from an unverified domain is refused by
    /// the adapter, which is why this is configuration and not a guess.
    pub mail_from: String,
}

fn resolve_settings(cfg: &dyn Config) -> Result<Settings, Vec<String>> {
    let module = ModuleConfig::new("auth-magic-link", cfg);
    let mut problems = Vec::new();

    let public_base = module.get_opt("PUBLIC_BASE").unwrap_or_default();
    let public_base = public_base.trim().trim_end_matches('/').to_owned();
    if public_base.is_empty() {
        problems.push(format!(
            "{} is required (the public origin a mailed link points at)",
            module.key("PUBLIC_BASE")
        ));
    } else if !(public_base.starts_with("https://")
        || public_base.starts_with("http://localhost")
        || public_base.starts_with("http://127.0.0.1"))
    {
        problems.push(format!(
            "{} must be https (localhost may be http), got {public_base:?}",
            module.key("PUBLIC_BASE")
        ));
    }

    let mail_from = module.get_opt("MAIL_FROM").unwrap_or_default();
    if mail_from.trim().is_empty() {
        problems.push(format!(
            "{} is required (the From address the link is sent from)",
            module.key("MAIL_FROM")
        ));
    }

    let default_return_to = module.get_str("DEFAULT_RETURN_TO", "/");
    if handlers::safe_return_to(Some(&default_return_to)).is_none() {
        problems.push(format!(
            "{} must be a path on this service beginning with a single /, got {default_return_to:?}",
            module.key("DEFAULT_RETURN_TO")
        ));
    }

    let ttl_secs = match module.get_opt("TTL_SECS") {
        None => DEFAULT_TTL_SECS,
        Some(raw) => match raw.trim().parse::<i64>() {
            // A link that lasts a day is a password with a long tail; one
            // that lasts a minute does not survive a slow mail queue.
            Ok(value) if (60..=86_400).contains(&value) => value,
            _ => {
                problems.push(format!(
                    "{} must be between 60 and 86400 seconds, got {raw:?}",
                    module.key("TTL_SECS")
                ));
                DEFAULT_TTL_SECS
            }
        },
    };

    let allow_registration = match module.get_opt("ALLOW_REGISTRATION") {
        None => false,
        Some(raw) => match raw.trim() {
            "true" | "1" => true,
            "false" | "0" => false,
            other => {
                problems.push(format!(
                    "{} must be true or false, got {other:?}",
                    module.key("ALLOW_REGISTRATION")
                ));
                false
            }
        },
    };

    if problems.is_empty() {
        Ok(Settings {
            public_base,
            default_return_to,
            ttl_secs,
            allow_registration,
            mail_from: mail_from.trim().to_owned(),
        })
    } else {
        Err(problems)
    }
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Option<Settings>,
}

/// Sign in by email.
pub struct MagicLink;

impl Default for MagicLink {
    fn default() -> Self {
        Self::new()
    }
}

impl MagicLink {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Module for MagicLink {
    fn name(&self) -> &'static str {
        "auth-magic-link"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Clock, Port::IdGen, Port::Mailer]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::RateLimiter, Port::Captcha]
    }

    /// One. `auth-core` owns `single_use_tokens` and everything else this
    /// module touches; the send-cooldown ledger is this module's, because
    /// the window it enforces is this module's policy.
    fn tables(&self) -> &'static [&'static str] {
        &["auth_magic_link_send_cooldown"]
    }

    /// The cooldown row is an address and a timestamp, and both are the
    /// subject's.
    ///
    /// Unlike `module-waitlist`'s cooldown — which this one copies the
    /// shape of, and which had to be declared
    /// [`unreachable`](PersonalDataSet::unreachable) — the subject here is
    /// the bare normalised address rather than `<address>:<product>`, so
    /// `WHERE subject = ?` reaches it and a subject access request is not
    /// answered with an apology. `subject_via` is the hop that makes an
    /// account id match it: rows belong to whoever holds the `users` row
    /// with that `primary_email`.
    ///
    /// [`Disposition::Erase`] and not
    /// [`Anonymise`](Disposition::Anonymise): the address *is* the primary
    /// key, so there is no column left to blank, and the row's only other
    /// value is when it was written. Keeping a throttle entry for an
    /// erased account would also mean the address stayed readable in a
    /// table after the account holding it was gone.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[PersonalDataSet {
            table: "auth_magic_link_send_cooldown",
            subject: "subject",
            kind: DataKind::Contact,
            disposition: Disposition::Erase,
            description: "When we last emailed you a sign-in link, so the same address is not \
                          mailed again within the minute.",
            redacted: &[],
            subject_via: Some(SubjectVia {
                table: "users",
                subject: "id",
                key: "primary_email",
            }),
        }];
        SETS
    }

    fn emits(&self) -> &'static [&'static str] {
        &[
            handlers::EVENT_REQUESTED,
            handlers::EVENT_LOGGED_IN,
            handlers::EVENT_EMAIL_VERIFIED,
        ]
    }

    fn public_writes(&self) -> bool {
        true
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_SEND_COOLDOWN];
        // Refuses a gap, a duplicate or an entry out of order at build
        // time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations::sqlite(&MIGRATIONS)
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        match resolve_settings(cfg) {
            Ok(_) => Ok(()),
            Err(problems) => {
                let mut errors = ConfigError::default();
                for problem in problems {
                    errors.push(format!("auth-magic-link: {problem}"));
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
                    "auth-magic-link configuration is unusable"
                );
                None
            }
        };
        handlers::router().with_state(Arc::new(ModuleState {
            ctx: Arc::new(ctx),
            settings,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;

    fn config(pairs: &[(&str, &str)]) -> MapConfig {
        MapConfig::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    fn valid() -> Vec<(&'static str, &'static str)> {
        vec![
            ("AUTH_MAGIC_LINK_PUBLIC_BASE", "https://auth.example.com"),
            ("AUTH_MAGIC_LINK_MAIL_FROM", "sign-in@example.com"),
        ]
    }

    #[test]
    fn the_module_owns_only_its_cooldown_and_needs_a_mailer() {
        let module = MagicLink::new();
        assert_eq!(module.name(), "auth-magic-link");
        // One table, and it is the send-cooldown ledger. `auth-core` owns
        // `single_use_tokens` and every other row this module touches; a
        // second name appearing here means something was declared in the
        // wrong module.
        assert_eq!(module.tables(), ["auth_magic_link_send_cooldown"]);
        // Required, not optional: a magic link with nowhere to send it is
        // not a degraded feature, it is a broken one.
        assert!(module.requires().contains(&Port::Mailer));
        assert!(module.public_writes());
    }

    #[test]
    fn every_table_the_migration_creates_is_declared_and_described() {
        // The three lists have to agree, and nothing else here checks it:
        // `fz data export` walks `tables()`, subject access and erasure
        // walk `personal_data()`, and a table in neither is outside all of
        // them (issue #272).
        let module = MagicLink::new();
        assert!(
            cratefield_core::unlisted_tables(&module).is_empty(),
            "the migration creates a table `tables()` does not name: {:?}",
            cratefield_core::unlisted_tables(&module)
        );
        assert!(
            cratefield_core::undeclared_tables(&module).is_empty(),
            "a declared table has no `personal_data()` entry: {:?}",
            cratefield_core::undeclared_tables(&module)
        );
    }

    #[test]
    fn the_defaults_are_a_quarter_hour_and_no_registration() {
        let settings = resolve_settings(&config(&valid())).expect("valid");
        assert_eq!(settings.ttl_secs, DEFAULT_TTL_SECS);
        assert_eq!(settings.ttl_secs, 900);
        assert!(
            !settings.allow_registration,
            "registration by link creates an account for any address somebody types"
        );
    }

    #[test]
    fn a_link_must_point_somewhere_a_mail_client_can_reach() {
        for bad in ["", "   ", "auth.example.com", "ftp://auth.example.com"] {
            let mut pairs = valid();
            pairs[0] = ("AUTH_MAGIC_LINK_PUBLIC_BASE", bad);
            assert!(
                resolve_settings(&config(&pairs)).is_err(),
                "{bad:?} was accepted as a public base"
            );
        }
        // Localhost over http is the one exception, for `wrangler dev`.
        let mut pairs = valid();
        pairs[0] = ("AUTH_MAGIC_LINK_PUBLIC_BASE", "http://localhost:8787");
        assert!(resolve_settings(&config(&pairs)).is_ok());
    }

    #[test]
    fn a_ttl_outside_the_sane_range_is_a_build_failure() {
        // A link that lasts a day is a password with a long tail; one that
        // lasts a minute does not survive a slow mail queue.
        for bad in ["0", "59", "86401", "a while", "-900"] {
            let mut pairs = valid();
            pairs.push(("AUTH_MAGIC_LINK_TTL_SECS", bad));
            assert!(
                resolve_settings(&config(&pairs)).is_err(),
                "{bad:?} was accepted as a ttl"
            );
        }
    }

    #[test]
    fn a_from_address_is_required_because_the_adapter_refuses_without_one() {
        let pairs = vec![("AUTH_MAGIC_LINK_PUBLIC_BASE", "https://auth.example.com")];
        let problems = resolve_settings(&config(&pairs)).expect_err("refused");
        assert!(
            problems.join("; ").contains("AUTH_MAGIC_LINK_MAIL_FROM"),
            "{problems:?}"
        );
    }
}
