//! `cratefield-module-waitlist`: per-product waitlist with confirm,
//! position, referral codes and status (issue #11, architecture section
//! 6).
//!
//! ```no_run
//! use cratefield_module_waitlist::Waitlist;
//!
//! let module = Waitlist::new()
//!     .products(["kontinuum", "undercover-rockstars"])
//!     .confirm_ttl_days(7)
//!     .referrals(true);
//! ```
//!
//! **Positions are atomic.** Confirmation runs `1 + MAX(position)` for
//! the product *inside* the position UPDATE, and that UPDATE plus the
//! referrer credit run in one [`cratefield_core::Database::batch`] —
//! atomic on D1, a transaction on the sqlite adapter — so concurrent
//! confirmations never share a position. Positions are dense at assign
//! time per product and never recomputed on delete.
//!
//! **No enumeration** (section 11): `POST /v1/waitlist` answers the same
//! `202 {"ok":true}` bytes whatever the row state; an unknown `ref` code
//! is silently ignored.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod handlers;
mod mail;
mod store;

pub use mail::{ConfirmMailData, ConfirmedMailData, default_templates};

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext,
    Port, SqlMigration,
};
use serde_json::Value;
use std::sync::Arc;

use handlers::{Products, Settings};

/// A venture's validation for the free-form `answers` field of a join.
/// `Err(detail)` becomes a `400 validation-failed` problem.
pub type AnswersSchema = Arc<dyn Fn(&Value) -> Result<(), String> + Send + Sync>;

fn accept_any_answers() -> AnswersSchema {
    Arc::new(|_answers| Ok(()))
}

/// The module's migrations: the `waitlist_entries` table in the portable
/// SQL subset (issue #11), plus the entry generation that confirm tokens
/// bind to (issue #127).
const MIGRATION_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
};

const MIGRATION_ENTRY_GENERATION: SqlMigration = SqlMigration {
    id: "0002",
    name: "entry_generation",
    sql: include_str!("../migrations/sqlite/0002_entry_generation.sql"),
};

/// The durable send-cooldown table backing the one-mail-per-window claim
/// (issue #133). Name must match `handlers::SEND_COOLDOWN_TABLE`.
const MIGRATION_MAIL_COOLDOWN: SqlMigration = SqlMigration {
    id: "0003",
    name: "mail_cooldown",
    sql: include_str!("../migrations/sqlite/0003_mail_cooldown.sql"),
};

/// A per-product waitlist.
pub struct Waitlist {
    settings: Settings,
}

impl Default for Waitlist {
    fn default() -> Self {
        Self::new()
    }
}

impl Waitlist {
    /// No products allowed until [`Waitlist::products`] or
    /// [`Waitlist::any_product`] says otherwise; 7-day confirm TTL;
    /// referrals on.
    pub fn new() -> Self {
        Self {
            settings: Settings {
                products: Products::List(Vec::new()),
                confirm_ttl_days: 7,
                retention_days_pending: 30,
                status_redirect: None,
                referrals: true,
                answers_schema: accept_any_answers(),
            },
        }
    }

    /// Exactly these product slugs may be joined.
    #[must_use]
    pub fn products(mut self, products: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.settings.products = Products::List(products.into_iter().map(Into::into).collect());
        self
    }

    /// Accept any product slug (single-product ventures that do not want
    /// an allowlist).
    #[must_use]
    pub fn any_product(mut self) -> Self {
        self.settings.products = Products::Any;
        self
    }

    /// How long a confirmation link stays valid (default 7 days).
    #[must_use]
    pub fn confirm_ttl_days(mut self, days: u32) -> Self {
        self.settings.confirm_ttl_days = days;
        self
    }

    /// Purge `pending` entries untouched for this many days from the
    /// scheduled handler (default 30; issue #13 retention rule).
    #[must_use]
    pub fn retention_days_pending(mut self, days: u32) -> Self {
        self.settings.retention_days_pending = days;
        self
    }

    /// Where confirmation redirects to, as
    /// `<url>?token=<status token>` (default
    /// `<public_url>/waitlist/status`).
    #[must_use]
    pub fn status_redirect(mut self, url: impl Into<String>) -> Self {
        self.settings.status_redirect = Some(url.into());
        self
    }

    /// Whether `ref` codes credit referrers (default `true`).
    #[must_use]
    pub fn referrals(mut self, enabled: bool) -> Self {
        self.settings.referrals = enabled;
        self
    }

    /// Validates the free-form `answers` JSON of a join (default: accept
    /// anything).
    #[must_use]
    pub fn answers_schema(
        mut self,
        validate: impl Fn(&Value) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.settings.answers_schema = Arc::new(validate);
        self
    }
}

impl Module for Waitlist {
    fn name(&self) -> &'static str {
        "waitlist"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Mailer, Port::Signer]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::Captcha, Port::RateLimiter]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["waitlist_entries", "waitlist_send_cooldown"]
    }

    fn emits(&self) -> &'static [&'static str] {
        &[handlers::EVENT_JOINED, handlers::EVENT_CONFIRMED]
    }

    fn public_writes(&self) -> bool {
        true
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 3] = [
            MIGRATION_INIT,
            MIGRATION_ENTRY_GENERATION,
            MIGRATION_MAIL_COOLDOWN,
        ];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("waitlist", cfg);
        let mut errors = ConfigError::default();

        if let Some(raw) = cfg
            .get(&module.key("CONFIRM_TTL_DAYS"))
            .map(|raw| raw.parse::<u32>())
        {
            let invalid = match raw {
                Ok(days) => days == 0,
                Err(_) => true,
            };
            if invalid {
                errors.push(format!(
                    "waitlist: {} must be a positive integer",
                    module.key("CONFIRM_TTL_DAYS")
                ));
            }
        }
        for key in ["STATUS_REDIRECT", "EXPIRED_REDIRECT", "API_BASE"] {
            if let Some(raw) = cfg.get(&module.key(key))
                && !(raw.starts_with("https://") || raw.starts_with("http://"))
            {
                errors.push(format!(
                    "waitlist: {} must be an absolute http(s) URL, got {raw:?}",
                    module.key(key)
                ));
            }
        }
        if let Some(list) = cfg.get(&module.key("PRODUCTS"))
            && list != "*"
            && list
                .split(',')
                .map(str::trim)
                .all(|slug| !is_product_slug(slug))
        {
            errors.push(format!(
                "waitlist: {} must be a comma-separated list of kebab-case slugs or `*`",
                module.key("PRODUCTS")
            ));
        }

        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(Arc::new(ctx), self.settings.clone())
    }

    fn surface(&self) -> cratefield_core::Surface {
        handlers::surface(&self.settings)
    }

    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            let Some(db) = ctx.ports.db.clone() else {
                return Ok(());
            };
            let cfg = ModuleConfig::new("waitlist", &*ctx.config);
            let days = i64::from(cfg.get_u32(
                "RETENTION_DAYS_PENDING",
                self.settings.retention_days_pending,
            ));
            let cutoff = handlers::iso_ago(days.saturating_mul(86_400));
            let deleted = store::purge_pending_older_than(&*db, &cutoff)
                .await
                .map_err(|err| Box::new(err) as AnyError)?;
            if deleted > 0 {
                tracing::info!(deleted, cron, "purged stale pending waitlist entries");
            }
            // Claims whose window has closed are dead rows (issue #133).
            let claims = cratefield_core::SendCooldown::new(handlers::SEND_COOLDOWN_TABLE)
                .prune(
                    &*db,
                    &handlers::iso_ago(handlers::REMAIL_AFTER_SECS.saturating_mul(2)),
                )
                .await
                .map_err(|err| Box::new(err) as AnyError)?;
            if claims > 0 {
                tracing::info!(claims, cron, "pruned expired waitlist send claims");
            }
            Ok(())
        })
    }
}

fn is_product_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_issue() {
        let module = Waitlist::new();
        assert_eq!(module.settings.confirm_ttl_days, 7);
        assert_eq!(module.settings.retention_days_pending, 30);
        assert!(module.settings.referrals);
        assert_eq!(module.name(), "waitlist");
        assert_eq!(
            module.tables(),
            ["waitlist_entries", "waitlist_send_cooldown"]
        );
        assert!(module.public_writes());
        assert_eq!(module.requires(), [Port::Db, Port::Mailer, Port::Signer]);
        assert_eq!(module.optional(), [Port::Captcha, Port::RateLimiter]);
        assert_eq!(module.emits(), ["waitlist.joined", "waitlist.confirmed"]);
    }

    #[test]
    fn referral_codes_are_8_char_crockford() {
        for _ in 0..64 {
            let code = handlers::referral_code();
            assert_eq!(code.len(), 8);
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()),
                "{code}"
            );
        }
    }
}
