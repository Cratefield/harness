//! `cratefield-module-email-signup`: collect an address, double opt-in via
//! a signed link, one-click unsubscribe, admin CSV export and hard delete
//! (issue #10, architecture section 6).
//!
//! ```no_run
//! use cratefield_module_email_signup::EmailSignup;
//!
//! let module = EmailSignup::new()
//!     .double_opt_in(true)
//!     .confirm_ttl_days(7)
//!     .retention_days_pending(30);
//! ```
//!
//! **No enumeration** (section 11): `POST /v1/email-signup` answers the
//! same `202 {"ok":true}` bytes for new, pending, confirmed and
//! unsubscribed addresses, and at most one confirmation mail is sent per
//! address per hour. Tokens are HMAC-signed (ADR 0006): confirm links
//! expire after `confirm_ttl_days`, unsubscribe links never do.
//!
//! Register [`default_templates`] with `Harness::builder().templates(..)`
//! so ventures can override them; the module also falls back to built-in
//! rendering when the registry has no entry.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod handlers;
mod mail;
mod store;

pub use mail::{ConfirmMailData, WelcomeMailData, default_templates};

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, DataKind, Disposition, IdGen, Migrations, Module,
    ModuleConfig, ModuleContext, PersonalDataSet, Port, SqlMigration, UlidIdGen, normalize_email,
    validation_error,
};
use std::sync::{Arc, OnceLock};

use handlers::Settings;

/// The module's migrations: the `subscribers` table in the portable SQL
/// subset (issue #10, architecture section 7), plus the subscription
/// generation that confirmation tokens bind to (issue #127).
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

const MIGRATION_SUBSCRIPTION_GENERATION: SqlMigration = SqlMigration::new(
    "0002",
    "subscription_generation",
    include_str!("../migrations/sqlite/0002_subscription_generation.sql"),
);

/// The revocable per-subscription unsubscribe token (issue #137).
const MIGRATION_UNSUBSCRIBE_TOKEN: SqlMigration = SqlMigration::new(
    "0003",
    "unsubscribe_token",
    include_str!("../migrations/sqlite/0003_unsubscribe_token.sql"),
);

/// Email signup with double opt-in.
///
/// The `waitlist.confirmed` handler needs a [`ModuleContext`], but event
/// handlers are registered at `Harness::build` and receive none — so each
/// module instance parks the context from its first `router()` build in
/// this cell (per instance, so parallel harnesses in tests stay
/// isolated). It holds wiring state, never request state (ADR 0007).
#[derive(Clone)]
pub struct EmailSignup {
    settings: Settings,
    ctx_cell: Arc<OnceLock<Arc<ModuleContext>>>,
}

impl Default for EmailSignup {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailSignup {
    /// Double opt-in on, 7-day confirm TTL, 30-day pending retention.
    pub fn new() -> Self {
        Self {
            settings: Settings {
                double_opt_in: true,
                confirm_ttl_days: 7,
                retention_days_pending: 30,
                confirmed_redirect: None,
                unsubscribed_redirect: None,
                expired_redirect: None,
                welcome_on_confirm: false,
                subscribe_on_waitlist_confirm: false,
            },
            ctx_cell: Arc::new(OnceLock::new()),
        }
    }

    /// Double opt-in (default `true`). When off, a signup is confirmed
    /// immediately and no confirmation mail is sent.
    #[must_use]
    pub fn double_opt_in(mut self, enabled: bool) -> Self {
        self.settings.double_opt_in = enabled;
        self
    }

    /// How long a confirmation link stays valid (default 7 days).
    #[must_use]
    pub fn confirm_ttl_days(mut self, days: u32) -> Self {
        self.settings.confirm_ttl_days = days;
        self
    }

    /// Redirect target after a successful confirm (default
    /// `<public_url>/confirmed`).
    #[must_use]
    pub fn confirmed_redirect(mut self, url: impl Into<String>) -> Self {
        self.settings.confirmed_redirect = Some(url.into());
        self
    }

    /// Redirect target after unsubscribing (default
    /// `<public_url>/unsubscribed`).
    #[must_use]
    pub fn unsubscribed_redirect(mut self, url: impl Into<String>) -> Self {
        self.settings.unsubscribed_redirect = Some(url.into());
        self
    }

    /// Redirect target for expired/invalid confirm links (default
    /// `<public_url>/confirm-expired`).
    #[must_use]
    pub fn expired_redirect(mut self, url: impl Into<String>) -> Self {
        self.settings.expired_redirect = Some(url.into());
        self
    }

    /// Purge `pending` rows untouched for this many days from the
    /// scheduled handler (default 30; issue #13 retention rule).
    #[must_use]
    pub fn retention_days_pending(mut self, days: u32) -> Self {
        self.settings.retention_days_pending = days;
        self
    }

    /// Send the `email-signup/welcome` mail (deferred) when a signup is
    /// confirmed. Off by default (issue #10).
    #[must_use]
    pub fn welcome_on_confirm(mut self, enabled: bool) -> Self {
        self.settings.welcome_on_confirm = enabled;
        self
    }

    /// Subscribe addresses to the signup list (as `confirmed`) when they
    /// confirm a waitlist entry — the waitlist link already proved the
    /// address. Wired through the `waitlist.confirmed` event, so there is
    /// no dependency between the module crates.
    #[must_use]
    pub fn subscribe_on_waitlist_confirm(mut self, enabled: bool) -> Self {
        self.settings.subscribe_on_waitlist_confirm = enabled;
        self
    }
}

impl Module for EmailSignup {
    fn name(&self) -> &'static str {
        "email-signup"
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
        &["subscribers"]
    }

    /// The one table, and the one column an export must not copy (issue #265).
    ///
    /// **Why `id` and not the address.** Every other handle on a subscriber in
    /// this module is the opaque row id, and deliberately: the admin delete
    /// route takes `{id}` and never the address, because a URL outlives its
    /// request in access logs, proxies and browser history (issue #135).
    /// `GET /v1/privacy/export?subject=…` puts the subject value in exactly
    /// such a URL, so declaring `email_normalized` here would have made a
    /// subject access request the one operation that writes the address into
    /// the logs the rest of the module is built to keep it out of.
    ///
    /// **Why `unsubscribe_token` is redacted.** It is a bearer capability
    /// (issue #137, ADR 0014): whoever holds the value can unsubscribe that
    /// subscription, which is why the row rotates it with each mail rather
    /// than relying on a signing key. An export is a `SELECT *` written to a
    /// file people forward, so copying it in would hand that capability to
    /// everyone the file reaches. It is named with `[redacted]` for a value
    /// rather than dropped, because "we hold nothing there" is the one thing
    /// a subject access request must not say untruthfully — and it is still
    /// erased, because the row it lives in goes.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[PersonalDataSet {
            table: "subscribers",
            subject: "id",
            kind: DataKind::Contact,
            disposition: Disposition::Erase,
            description: "The email address you gave us and the one we matched it against, \
                          where you signed up from, the language you asked to be written to \
                          in, and when you signed up, confirmed and unsubscribed.",
            redacted: &["unsubscribe_token"],
        }];
        SETS
    }

    fn emits(&self) -> &'static [&'static str] {
        &[handlers::EVENT_CONFIRMED, handlers::EVENT_UNSUBSCRIBED]
    }

    fn public_writes(&self) -> bool {
        true
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 3] = [
            MIGRATION_INIT,
            MIGRATION_SUBSCRIPTION_GENERATION,
            MIGRATION_UNSUBSCRIBE_TOKEN,
        ];
        // The array is the apply order; this refuses a gap, a duplicate
        // or an entry out of order at build time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("email-signup", cfg);
        let mut errors = ConfigError::default();

        for key in ["CONFIRM_TTL_DAYS", "RETENTION_DAYS_PENDING"] {
            match cfg.get(&module.key(key)).map(|raw| raw.parse::<u32>()) {
                Some(Ok(value)) if value > 0 => {}
                Some(_) => errors.push(format!(
                    "email-signup: {} must be a positive integer",
                    module.key(key)
                )),
                None => {}
            }
        }
        for key in [
            "CONFIRMED_REDIRECT",
            "UNSUBSCRIBED_REDIRECT",
            "EXPIRED_REDIRECT",
            "API_BASE",
        ] {
            if let Some(raw) = cfg.get(&module.key(key))
                && !(raw.starts_with("https://") || raw.starts_with("http://"))
            {
                errors.push(format!(
                    "email-signup: {} must be an absolute http(s) URL, got {raw:?}",
                    module.key(key)
                ));
            }
        }
        for key in [
            "DOUBLE_OPT_IN",
            "WELCOME_ON_CONFIRM",
            "SUBSCRIBE_ON_WAITLIST_CONFIRM",
        ] {
            if let Some(raw) = cfg.get(&module.key(key))
                && !matches!(
                    raw.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on" | "0" | "false" | "no" | "off"
                )
            {
                errors.push(format!(
                    "email-signup: {} must be a boolean, got {raw:?}",
                    module.key(key)
                ));
            }
        }
        if let Some(raw) = cfg.get(&module.key("FROM"))
            && !raw.contains('@')
        {
            errors.push(format!(
                "email-signup: {} must be an address, got {raw:?}",
                module.key("FROM")
            ));
        }

        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let shared = Arc::new(ctx);
        // First build wins; on Workers every request rebuilds the router
        // with equivalent ports, so the parked context stays valid.
        let _ = self.ctx_cell.set(Arc::clone(&shared));
        handlers::router(shared, self.settings.clone())
    }

    fn surface(&self) -> cratefield_core::Surface {
        handlers::surface(&self.settings)
    }

    fn events(&self) -> Vec<(cratefield_core::EventName, cratefield_core::EventHandler)> {
        if !self.settings.subscribe_on_waitlist_confirm {
            return Vec::new();
        }
        let cell = Arc::clone(&self.ctx_cell);
        let handler: cratefield_core::EventHandler = Arc::new(move |_scope, payload| {
            let cell = Arc::clone(&cell);
            Box::pin(async move { subscribe_waitlist_confirmed(&cell, payload).await })
        });
        vec![(handlers::WAITLIST_CONFIRMED.to_owned(), handler)]
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
            let cfg = ModuleConfig::new("email-signup", &*ctx.config);
            let days = i64::from(cfg.get_u32(
                "RETENTION_DAYS_PENDING",
                self.settings.retention_days_pending,
            ));
            let cutoff = handlers::iso_ago(days.saturating_mul(86_400));
            let deleted = store::purge_pending_older_than(&*db, &cutoff)
                .await
                .map_err(|err| Box::new(err) as AnyError)?;
            if deleted > 0 {
                tracing::info!(deleted, cron, "purged stale pending subscribers");
            }
            Ok(())
        })
    }
}

/// `waitlist.confirmed` handler: add the (now proven) address to the
/// signup list as `confirmed`, unless it is already there.
async fn subscribe_waitlist_confirmed(
    cell: &Arc<OnceLock<Arc<ModuleContext>>>,
    payload: serde_json::Value,
) -> Result<(), AnyError> {
    use serde_json::Value;

    let Some(email) = payload.get("email").and_then(Value::as_str) else {
        tracing::warn!("waitlist.confirmed without an email; ignored");
        return Ok(());
    };
    let product = payload
        .get("product")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let normalized = normalize_email(email);
    if validation_error(&normalized).is_some() {
        tracing::warn!(product, "waitlist.confirmed with an invalid email; ignored");
        return Ok(());
    }
    let Some(ctx) = cell.get() else {
        return Err("email-signup router was never built".into());
    };
    let Some(db) = ctx.ports.db.clone() else {
        return Err("email-signup has no Database port".into());
    };
    if store::find_by_normalized_email(&*db, &normalized)
        .await
        .map_err(|err| Box::new(err) as AnyError)?
        .is_some()
    {
        return Ok(());
    }
    let now = handlers::now_iso();
    store::insert_row(
        &*db,
        &store::SubscriberRow {
            id: UlidIdGen.ulid(),
            generation: 1,
            email: normalized.clone(),
            email_normalized: normalized,
            status: store::STATUS_CONFIRMED.to_owned(),
            source: Some(format!("waitlist:{product}")),
            locale: None,
            confirmed_at: Some(now.clone()),
            unsubscribed_at: None,
            unsubscribe_token: None,
            created_at: now.clone(),
            updated_at: now,
        },
    )
    .await
    .map_err(|err| Box::new(err) as AnyError)?;
    tracing::info!(product, "subscribed a confirmed waitlist address");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_issue() {
        let module = EmailSignup::new();
        assert!(module.settings.double_opt_in);
        assert_eq!(module.settings.confirm_ttl_days, 7);
        assert_eq!(module.settings.retention_days_pending, 30);
        assert!(!module.settings.welcome_on_confirm);
        assert!(!module.settings.subscribe_on_waitlist_confirm);
        assert_eq!(module.name(), "email-signup");
        assert_eq!(module.tables(), ["subscribers"]);
        assert!(module.public_writes());
        assert_eq!(module.requires(), [Port::Db, Port::Mailer, Port::Signer]);
        assert_eq!(module.optional(), [Port::Captcha, Port::RateLimiter]);
    }

    #[test]
    fn instances_do_not_share_a_context_cell() {
        let a = EmailSignup::new();
        let b = EmailSignup::new();
        assert!(!Arc::ptr_eq(&a.ctx_cell, &b.ctx_cell));
    }
}
