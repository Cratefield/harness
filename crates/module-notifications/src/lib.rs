//! `cratefield-module-notifications`: device and browser subscriptions,
//! per-account per-category preferences, a fan-out API other modules call,
//! and a drain that delivers through the `Push` port (issue #182).
//!
//! ```no_run
//! use cratefield_module_notifications::{Category, Notifications};
//!
//! let module = Notifications::new()
//!     .category(Category::new("booking"))
//!     .category(Category::new("coach_notes").default_enabled(false))
//!     .category(Category::new("room_starting").badge(true));
//! let notifier = module.notifier(); // hand this to your own modules
//! ```
//!
//! # What it owns
//!
//! - `notifications_subscriptions` — one row per device or browser,
//!   identified by `(transport, recipient_hash)` so re-registering on app
//!   launch is an upsert and a device that changes account re-homes.
//! - `notifications_preferences` — `push`, `in_app` and `email` per
//!   account per category. **All three switches are created in the first
//!   migration**, although the in-app (#187) and email (#189) children are
//!   what give the last two meaning: three siblings editing one table in
//!   the same migration stream would collide. This child reads only
//!   `push`.
//! - `notifications_outbox` — the core [`Outbox`](cratefield_core::Outbox)
//!   (#128), so a notification commits atomically with the state change
//!   that caused it.
//! - `notifications_dead_letters` — the terminal state core's outbox does
//!   not have (ADR 0016).
//!
//! # The two rules that are easy to get wrong
//!
//! **`PushError::Unregistered` is a delete instruction**, and the only
//! error that ever prunes a subscription. Not `Rejected`, not `Transient`,
//! not `NotConfigured` — a wrongly-pruned Web Push subscription cannot be
//! recreated server-side at all (ADR 0015).
//!
//! **The preference is read in the drain**, immediately before
//! `Push::send`, so an opt-out that arrives after the row was written
//! still wins.
//!
//! # No UI surface
//!
//! ADR 0010's audiences are visitor, admin and signed link. These routes
//! are none of the three: they are an app client holding an access token.
//! Declaring them `Public` would put a form no visitor can submit into
//! `/__surface`'s public subset, so the module declares nothing and the
//! sibling that needs a rendered inbox can propose an `Audience::Account`
//! in core.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod handlers;
mod notify;
mod store;

pub use handlers::{ChannelPatch, PreferencesBody, RecipientBody, RegisterBody, UNKNOWN_CATEGORY};
pub use notify::{
    DrainReport, EVENT_REQUESTED, EVENT_SUBSCRIPTION_PRUNED, Enqueued, Notifier, NotifyError,
    Skipped, TOPIC_SEND,
};
pub use store::{DeadLetterReason, Transport};

use std::sync::{Arc, OnceLock};

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext,
    NoopDefer, Notification, Port, Scope, SqlMigration, VentureEnv,
};

/// The name the module mounts under: `/v1/notifications`.
pub const MODULE_NAME: &str = "notifications";

/// Answers "did this venture wire at least one push transport?" for the
/// production readiness check.
///
/// The module cannot answer it itself. The push environment has exactly
/// **one** reader — `cratefield-push-wiring` (#191), enforced by a guard
/// over the whole workspace — because six places reading the variable names
/// is six chances to drift on one, and the drift is invisible: the doctor
/// reports a healthy deployment while every Android send answers
/// `NotConfigured`. Depending on that crate is not the way out either: it
/// pulls all three push adapters, and this module must compile the same
/// whether a venture wires zero or three.
///
/// So the venture, which already has the reader, passes the question in:
///
/// ```rust,ignore
/// Notifications::new()
///     .transport_probe(|cfg| cratefield::push_wiring::inspect_push(cfg).any_routed())
/// ```
///
/// With no probe the check is skipped and `fz doctor` is the only half that
/// runs — which is why the builder documents it and `examples/venture`
/// wires it.
pub type TransportProbe = Arc<dyn Fn(&dyn Config) -> bool + Send + Sync>;

const MIGRATION_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
};

/// One notification category the venture declares.
///
/// Categories are the vocabulary an account switches on and off, so they
/// are the venture's, not the module's: `booking`, `coach_notes`,
/// `room_starting`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    pub(crate) name: String,
    pub(crate) default_enabled: bool,
    pub(crate) badge: bool,
}

impl Category {
    /// A category that is on until the account says otherwise, and sends
    /// no badge count.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            default_enabled: true,
            badge: false,
        }
    }

    /// Whether an account that has never expressed a preference gets this
    /// category (default `true`).
    #[must_use]
    pub fn default_enabled(mut self, enabled: bool) -> Self {
        self.default_enabled = enabled;
        self
    }

    /// Whether a badge count may travel with this category's
    /// notifications (default **`false`**).
    ///
    /// Off by default because a badge number the server cannot compute
    /// correctly is worse than no badge: it is wrong on the device until
    /// the next push, and only the venture knows what it counts.
    #[must_use]
    pub fn badge(mut self, allowed: bool) -> Self {
        self.badge = allowed;
        self
    }

    /// The category's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The builder's settings, shared with the [`Notifier`] handle.
#[derive(Clone)]
pub(crate) struct Settings {
    pub categories: Arc<Vec<Category>>,
    pub max_attempts: u32,
    pub drain_batch: u64,
    pub transport_probe: Option<TransportProbe>,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("categories", &self.categories)
            .field("max_attempts", &self.max_attempts)
            .field("drain_batch", &self.drain_batch)
            .field("transport_probe", &self.transport_probe.is_some())
            .finish()
    }
}

impl Settings {
    pub(crate) fn category(&self, name: &str) -> Option<&Category> {
        self.categories
            .iter()
            .find(|category| category.name == name)
    }

    pub(crate) fn declares(&self, name: &str) -> bool {
        self.category(name).is_some()
    }
}

/// Push subscriptions, preferences, fan-out and delivery.
pub struct Notifications {
    settings: Settings,
    /// The mounted context, parked when `Harness::router` builds the
    /// module's router. The [`Notifier`] handle and the event
    /// subscription both read it.
    ctx_cell: Arc<OnceLock<Arc<ModuleContext>>>,
}

impl Default for Notifications {
    fn default() -> Self {
        Self::new()
    }
}

impl Notifications {
    /// No categories (a venture must declare its own), five attempts
    /// before a transient failure is given up on, fifty rows per drain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: Settings {
                categories: Arc::new(Vec::new()),
                max_attempts: 5,
                drain_batch: 50,
                transport_probe: None,
            },
            ctx_cell: Arc::new(OnceLock::new()),
        }
    }

    /// Declares one category.
    #[must_use]
    pub fn category(mut self, category: Category) -> Self {
        Arc::make_mut(&mut self.settings.categories).push(category);
        self
    }

    /// Declares several categories, all on by default and none carrying a
    /// badge — the common case.
    #[must_use]
    pub fn categories(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let categories = Arc::make_mut(&mut self.settings.categories);
        for name in names {
            categories.push(Category::new(name));
        }
        self
    }

    /// How many delivery attempts a transient failure gets before the row
    /// is dead-lettered (default 5; `NOTIFICATIONS_MAX_ATTEMPTS`).
    #[must_use]
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.settings.max_attempts = attempts;
        self
    }

    /// How many outbox rows one drain pass leases (default 50;
    /// `NOTIFICATIONS_DRAIN_BATCH`).
    #[must_use]
    pub fn drain_batch(mut self, rows: u64) -> Self {
        self.settings.drain_batch = rows;
        self
    }

    /// How the venture answers "is any push transport wired?", for the
    /// production readiness check (see [`TransportProbe`]).
    ///
    /// A venture that assembles the `Push` port from the environment
    /// passes `cratefield_push_wiring::inspect_push(cfg).any_routed()`.
    /// One that hands the harness its own adapter answers for itself.
    #[must_use]
    pub fn transport_probe(
        mut self,
        probe: impl Fn(&dyn Config) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.settings.transport_probe = Some(Arc::new(probe));
        self
    }

    /// The handle other modules call.
    ///
    /// Take it before composing the harness and hand it to the modules
    /// that send notifications; it starts working when
    /// `Harness::router` builds this module's router.
    #[must_use]
    pub fn notifier(&self) -> Notifier {
        Notifier {
            cell: Arc::clone(&self.ctx_cell),
            settings: self.settings.clone(),
        }
    }

    /// The declared categories.
    #[must_use]
    pub fn declared_categories(&self) -> &[Category] {
        &self.settings.categories
    }
}

/// A category name is lower-case ASCII, digits and underscores — the
/// vocabulary a client hard-codes and a preferences body keys on.
fn is_category_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl Module for Notifications {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Push, Port::Clock, Port::IdGen]
    }

    fn optional(&self) -> &'static [Port] {
        // `HttpClient` is not in the issue's list: it is what
        // `factory0-auth-client` fetches the issuer's JWKS through. A
        // venture that only fans out from its own modules never needs it,
        // and gets a module whose HTTP routes answer 401.
        &[Port::Defer, Port::HttpClient]
    }

    fn tables(&self) -> &'static [&'static str] {
        &[
            store::SUBSCRIPTIONS,
            store::PREFERENCES,
            store::OUTBOX,
            store::DEAD_LETTERS,
        ]
    }

    fn emits(&self) -> &'static [&'static str] {
        &[notify::EVENT_SUBSCRIPTION_PRUNED]
    }

    fn public_writes(&self) -> bool {
        // Every route is behind the auth extractor; there is no
        // unauthenticated write in this child. The email child adds the
        // one signed one-click unsubscribe and must flip this with its
        // justification.
        false
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new(MODULE_NAME, cfg);
        let mut errors = ConfigError::default();

        if self.settings.categories.is_empty() {
            errors.push(
                "notifications: no categories are declared, so every notify() is an unknown \
                 category — declare at least one with .category(..)"
                    .to_owned(),
            );
        }
        let mut seen: Vec<&str> = Vec::new();
        for category in self.settings.categories.iter() {
            if !is_category_name(&category.name) {
                errors.push(format!(
                    "notifications: category {:?} must be lower-case letters, digits and \
                     underscores",
                    category.name
                ));
            }
            if seen.contains(&category.name.as_str()) {
                errors.push(format!(
                    "notifications: category {:?} is declared twice",
                    category.name
                ));
            }
            seen.push(&category.name);
        }

        for (key, minimum) in [("MAX_ATTEMPTS", 1u64), ("DRAIN_BATCH", 1)] {
            if let Some(raw) = module.get_opt(key) {
                let valid = raw.parse::<u64>().is_ok_and(|value| value >= minimum);
                if !valid {
                    errors.push(format!(
                        "notifications: {} must be an integer of at least {minimum}, got {raw:?}",
                        module.key(key)
                    ));
                }
            }
        }

        let issuer = module.get_opt("AUTH_ISSUER");
        let client_id = module.get_opt("AUTH_CLIENT_ID");
        if let Some(issuer) = &issuer
            && !(issuer.starts_with("https://") || issuer.starts_with("http://"))
        {
            errors.push(format!(
                "notifications: {} must be an absolute http(s) URL, got {issuer:?}",
                module.key("AUTH_ISSUER")
            ));
        }
        if issuer.is_some() != client_id.is_some() {
            errors.push(format!(
                "notifications: set {} and {} together — one without the other cannot verify a \
                 token, so every route would answer 401",
                module.key("AUTH_ISSUER"),
                module.key("AUTH_CLIENT_ID"),
            ));
        }

        let env = cfg
            .get("ENV")
            .as_deref()
            .and_then(VentureEnv::parse)
            .unwrap_or_default();
        if env == VentureEnv::Production {
            if issuer.is_none() {
                errors.push(format!(
                    "notifications: {} and {} are required in production: without them no \
                     account can register a device",
                    module.key("AUTH_ISSUER"),
                    module.key("AUTH_CLIENT_ID"),
                ));
            }
            if self
                .settings
                .transport_probe
                .as_ref()
                .is_some_and(|probe| !probe(cfg))
            {
                errors.push(
                    "notifications: production, but this venture wired no push transport: every \
                     send would dead-letter as `not_configured`. `fz doctor` names the variables"
                        .to_owned(),
                );
            }
        }

        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let shared = Arc::new(ctx);
        // First build wins; on Workers every request rebuilds the router
        // with equivalent ports, so the parked context stays valid.
        let _ = self.ctx_cell.set(Arc::clone(&shared));
        let auth = handlers::auth_client(&shared);
        handlers::router(Arc::new(handlers::ModuleState {
            ctx: shared,
            settings: self.settings.clone(),
            auth,
        }))
    }

    fn events(&self) -> Vec<(cratefield_core::EventName, cratefield_core::EventHandler)> {
        let notifier = self.notifier();
        let handler: cratefield_core::EventHandler = Arc::new(move |scope, payload| {
            let notifier = notifier.clone();
            let scope = scope.clone();
            Box::pin(async move { on_requested(&notifier, &scope, payload).await })
        });
        vec![(notify::EVENT_REQUESTED.to_owned(), handler)]
    }

    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            // The recovery half of the outbox contract: whatever the
            // immediate `Defer` never got to — because the isolate died
            // between the commit and the drain — is delivered here.
            let scope = scheduled_scope(ctx);
            let report = self
                .notifier()
                .drain(&scope)
                .await
                .map_err(|err| Box::new(err) as AnyError)?;
            if report.claimed > 0 {
                tracing::info!(?report, cron, "drained the notifications outbox");
            }
            Ok(())
        })
    }
}

/// A scope for work no request asked for. `Scope` carries the request id,
/// the defer and the span, and nothing about a principal (ADR 0007), so a
/// scheduled one is honest rather than borrowed.
fn scheduled_scope(ctx: &ModuleContext) -> Scope {
    Scope {
        request_id: format!("scheduled-{MODULE_NAME}"),
        defer: ctx
            .ports
            .defer
            .clone()
            .unwrap_or_else(|| Arc::new(NoopDefer)),
        span: tracing::Span::none(),
    }
}

/// `notifications.requested` — the bus entry point, for a module that
/// cannot take a crate dependency on this one.
async fn on_requested(
    notifier: &Notifier,
    scope: &Scope,
    payload: serde_json::Value,
) -> Result<(), AnyError> {
    use serde_json::Value;

    let Some(account_id) = payload.get("account_id").and_then(Value::as_str) else {
        return Err("notifications.requested without an account_id".into());
    };
    let Some(category) = payload.get("category").and_then(Value::as_str) else {
        return Err("notifications.requested without a category".into());
    };
    let notification: Notification = match payload.get("notification") {
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|err| format!("notifications.requested carries no Notification: {err}"))?,
        None => return Err("notifications.requested without a notification".into()),
    };
    let ctx = notifier.context().ok_or("notifications is not mounted")?;
    let db = ctx
        .ports
        .db
        .clone()
        .ok_or("notifications has no Database port")?;
    notifier
        .notify_now(&*db, scope, account_id, category, notification)
        .await
        .map_err(|err| Box::new(err) as AnyError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module() -> Notifications {
        Notifications::new().categories(["booking", "room_starting"])
    }

    #[test]
    fn the_declaration_matches_the_issue() {
        let module = module();
        assert_eq!(module.name(), "notifications");
        assert_eq!(
            module.requires(),
            [Port::Db, Port::Push, Port::Clock, Port::IdGen]
        );
        assert_eq!(module.optional(), [Port::Defer, Port::HttpClient]);
        assert_eq!(
            module.tables(),
            [
                "notifications_subscriptions",
                "notifications_preferences",
                "notifications_outbox",
                "notifications_dead_letters",
            ]
        );
        assert_eq!(module.emits(), ["notifications.subscription_pruned"]);
        assert!(
            !module.public_writes(),
            "every route is behind the auth extractor"
        );
        assert!(
            module.surface().is_empty(),
            "ADR 0010 has no audience for a signed-in account; see the crate docs"
        );
    }

    #[test]
    fn a_category_is_on_with_no_badge_until_told_otherwise() {
        let plain = Category::new("booking");
        assert!(plain.default_enabled);
        assert!(!plain.badge, "no badge counts by default");
        assert!(!Category::new("x").default_enabled(false).default_enabled);
        assert!(Category::new("x").badge(true).badge);
    }

    #[test]
    fn config_validation_refuses_an_empty_or_duplicated_category_set() {
        let empty = Notifications::new();
        let err = empty
            .validate_config(&cratefield_core::EmptyConfig)
            .expect_err("no categories is a misconfiguration");
        assert!(err.to_string().contains("no categories"), "{err}");

        let dup = Notifications::new().categories(["booking", "booking"]);
        let err = dup
            .validate_config(&cratefield_core::EmptyConfig)
            .expect_err("a duplicate category is a misconfiguration");
        assert!(err.to_string().contains("declared twice"), "{err}");

        let bad = Notifications::new().categories(["Room Starting"]);
        let err = bad
            .validate_config(&cratefield_core::EmptyConfig)
            .expect_err("a category name is a slug");
        assert!(err.to_string().contains("lower-case"), "{err}");

        module()
            .validate_config(&cratefield_core::EmptyConfig)
            .expect("a declared, unique, well-named set is valid outside production");
    }

    #[test]
    fn production_demands_an_issuer_and_a_transport() {
        let cfg = cratefield_core::MapConfig::from_pairs([("ENV", "production")]);
        let err = module()
            .transport_probe(|_| false)
            .validate_config(&cfg)
            .expect_err("production without auth or a transport is a misconfiguration");
        let text = err.to_string();
        assert!(text.contains("NOTIFICATIONS_AUTH_ISSUER"), "{text}");
        assert!(text.contains("wired no push transport"), "{text}");

        // Without a probe the module cannot answer the question and does
        // not pretend to: `fz doctor` is the other half.
        let err = module()
            .validate_config(&cfg)
            .expect_err("the auth keys are still required");
        assert!(
            !err.to_string().contains("push transport"),
            "a module with no probe must not claim a verdict it cannot reach: {err}"
        );

        let wired = cratefield_core::MapConfig::from_pairs([
            ("ENV", "production"),
            ("NOTIFICATIONS_AUTH_ISSUER", "https://auth.example.test"),
            ("NOTIFICATIONS_AUTH_CLIENT_ID", "client-x"),
        ]);
        module()
            .transport_probe(|_| true)
            .validate_config(&wired)
            .expect("a wired production deployment is valid");
    }

    #[test]
    fn half_an_auth_configuration_is_refused() {
        let cfg = cratefield_core::MapConfig::from_pairs([(
            "NOTIFICATIONS_AUTH_ISSUER",
            "https://auth.example.test",
        )]);
        let err = module()
            .validate_config(&cfg)
            .expect_err("an issuer with no client id can verify nothing");
        assert!(err.to_string().contains("together"), "{err}");

        let cfg = cratefield_core::MapConfig::from_pairs([
            ("NOTIFICATIONS_AUTH_ISSUER", "auth.example.test"),
            ("NOTIFICATIONS_AUTH_CLIENT_ID", "client-x"),
        ]);
        let err = module()
            .validate_config(&cfg)
            .expect_err("an issuer without a scheme is not a URL");
        assert!(err.to_string().contains("absolute http(s) URL"), "{err}");
    }

    #[test]
    fn the_migration_ships_the_cores_outbox_ddl_verbatim() {
        // The outbox table is core's, written out by hand in a migration
        // file. If core's DDL changes, this is where it is noticed.
        let core = cratefield_core::Outbox::new(store::OUTBOX).create_table_sql();
        assert!(
            MIGRATION_INIT.sql.contains(&core),
            "the migration no longer ships `Outbox::create_table_sql()` verbatim:\n{core}"
        );
    }

    #[test]
    fn the_migration_is_portable() {
        assert_eq!(
            cratefield_core::lint_portable_sql(MIGRATION_INIT.sql),
            Vec::new(),
            "the migration left the portable subset (ADR 0004)"
        );
        assert_eq!(
            cratefield_core::lint_card_data(MIGRATION_INIT.sql),
            Vec::new()
        );
    }

    #[test]
    fn sqlite_has_no_enum_so_a_closed_set_is_text_plus_check() {
        assert!(
            MIGRATION_INIT.sql.contains(
                "transport TEXT NOT NULL CHECK (transport IN ('apns', 'fcm', 'webpush'))"
            ),
            "the transport column must stay TEXT + CHECK"
        );
        // The DDL only: the file's own prose says the word, and prose is
        // not executed.
        let ddl: String = MIGRATION_INIT
            .sql
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n")
            .to_ascii_uppercase();
        assert!(!ddl.contains("ENUM"), "SQLite has no ENUM:\n{ddl}");
        // And the same shape for the other closed set.
        assert!(
            MIGRATION_INIT.sql.contains("reason TEXT NOT NULL CHECK ("),
            "the dead-letter reason must stay TEXT + CHECK too"
        );
    }

    #[test]
    fn all_three_channel_switches_are_in_the_first_migration() {
        // The whole point of putting them here: #187 and #189 add
        // meaning, not columns, so the three siblings never edit one
        // table in the same migration stream.
        for column in [
            "push INTEGER NOT NULL",
            "in_app INTEGER NOT NULL",
            "email INTEGER NOT NULL",
        ] {
            assert!(
                MIGRATION_INIT.sql.contains(column),
                "the first migration must create `{column}`"
            );
        }
    }
}
