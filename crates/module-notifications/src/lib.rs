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
//! - `notifications_locales` — one account's own language (#190). A table
//!   of its own rather than a row in `notifications_preferences`: that one
//!   is keyed `(account, category)` with three NOT NULL channel switches,
//!   and a locale is not a preference about a category.
//!
//! # The rules that are easy to get wrong
//!
//! **The language is resolved per recipient at delivery**, never when the
//! caller queues the message: one account can have an English browser and
//! a Bahasa phone. The subscription's locale, then the account's, then the
//! venture's default — and a caller that passes a rendered
//! [`Notification`] gets exactly what it wrote, everywhere.
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
//! **The subscription's account and the job's account are checked against
//! each other**, in that same place. A sign-out deletes the row, but
//! signing another account in on the same device only re-homes it, and a
//! notification queued for the previous owner must be dropped rather than
//! delivered to whoever holds the device now.
//!
//! **A device token is not an authenticator.** Re-homing is the one write
//! that acts on one alone, so it is budgeted, evented and recoverable —
//! see [`Notifications::rehome_max_per_hour`].
//!
//! **Scheduled work drains through the context it is handed**, never
//! through one parked when a router was built: a cron invocation builds no
//! router at all.
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

mod clock;
mod handlers;
mod locale;
mod message;
mod notify;
mod store;
mod webhook;

pub use handlers::{
    ChannelPatch, NO_APPLICATION_SERVER_KEY, PreferencesBody, REHOME_LIMIT, RecipientBody,
    RegisterBody, UNKNOWN_CATEGORY, WEBHOOK_UNVERIFIED,
};
pub use locale::EVENT_MISSING_TRANSLATION;
pub use message::{Localizable, Message, RenderMode};
pub use notify::{
    DrainReport, EVENT_REQUESTED, EVENT_SUBSCRIPTION_PRUNED, EVENT_SUBSCRIPTION_REHOMED, Enqueued,
    Notifier, NotifyError, Skipped, TOPIC_SEND,
};
pub use store::{DeadLetterReason, Transport};

use std::sync::{Arc, OnceLock};

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, DataKind, Disposition, Migrations, Module,
    ModuleConfig, ModuleContext, NoopDefer, Notification, PersonalDataSet, Port, RoutePolicy,
    Scope, SqlMigration, VentureEnv,
};
use cratefield_i18n::{BODY, Catalog, LanguageIdentifier, TITLE};

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

/// How the venture answers "what `applicationServerKey` do browsers
/// subscribe with?" — see [`Notifications::vapid_public_key`].
pub type VapidKeyProbe = Arc<dyn Fn(&dyn Config) -> Option<String> + Send + Sync>;

const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// The #182 review's schema half: the re-home record the take-over budget
/// counts, and the index `Outbox::claim_due` reads. Its own migration
/// because `0001` is applied and an applied migration is never edited.
const MIGRATION_REHOME_AND_DUE_INDEX: SqlMigration = SqlMigration::new(
    "0002",
    "rehome_and_due_index",
    include_str!("../migrations/sqlite/0002_rehome_and_due_index.sql"),
);

/// The in-app inbox (#187): the row every `notify` writes for a category
/// that declares `in_app`, and the channel that needs no permission.
const MIGRATION_INBOX: SqlMigration = SqlMigration::new(
    "0003",
    "inbox",
    include_str!("../migrations/sqlite/0003_inbox.sql"),
);

/// Email as a third channel (#189): where a verified address lives, and
/// the window the per-category cooldown counts over.
const MIGRATION_EMAIL_TARGETS: SqlMigration = SqlMigration::new(
    "0004",
    "email_targets",
    include_str!("../migrations/sqlite/0004_email_targets.sql"),
);

/// Bounce suppression (#233): the index the provider webhook's lookup by
/// address reads. Its own migration because `0004` is applied.
const MIGRATION_EMAIL_BOUNCE_INDEX: SqlMigration = SqlMigration::new(
    "0005",
    "email_bounce_index",
    include_str!("../migrations/sqlite/0005_email_bounce_index.sql"),
);

/// Per-recipient language (#190): the device's own locale, the account's,
/// and what an inbox row was rendered in. Its own migration because
/// `0001`-`0005` are applied.
const MIGRATION_LOCALES: SqlMigration = SqlMigration::new(
    "0006",
    "locales",
    include_str!("../migrations/sqlite/0006_locales.sql"),
);

/// The account a dead letter was for (#244): already in the payload, made
/// queryable so erasure can reach a notification that gave up. Its own
/// migration because `0001`-`0006` are applied.
const MIGRATION_DEAD_LETTER_ACCOUNT: SqlMigration = SqlMigration::new(
    "0007",
    "dead_letter_account",
    include_str!("../migrations/sqlite/0007_dead_letter_account.sql"),
);

/// Coalesced summaries (#232): the trace a cooldown-suppressed email
/// leaves, so the scheduled drain can send one summary for the burst once
/// the window has rolled. Its own migration because `0001`-`0007` are
/// applied.
const MIGRATION_EMAIL_SUPPRESSED: SqlMigration = SqlMigration::new(
    "0008",
    "email_suppressed",
    include_str!("../migrations/sqlite/0008_email_suppressed.sql"),
);

/// Every migration this module ships, in order. One array, so a test that
/// asserts something about the schema reads what actually ships rather
/// than a second list that can drift from it.
const SHIPPED_MIGRATIONS: [SqlMigration; 8] = [
    MIGRATION_INIT,
    MIGRATION_REHOME_AND_DUE_INDEX,
    MIGRATION_INBOX,
    MIGRATION_EMAIL_TARGETS,
    MIGRATION_EMAIL_BOUNCE_INDEX,
    MIGRATION_LOCALES,
    MIGRATION_DEAD_LETTER_ACCOUNT,
    MIGRATION_EMAIL_SUPPRESSED,
];

/// One notification category the venture declares.
///
/// Categories are the vocabulary an account switches on and off, so they
/// are the venture's, not the module's: `booking`, `coach_notes`,
/// `room_starting`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    pub(crate) name: String,
    pub(crate) badge: bool,
    /// What an account that has never expressed a preference gets, per
    /// channel. One struct rather than three loose bools, so "the default
    /// for this category" is one thing you can pass around — and so
    /// `default_enabled` stops secretly meaning *push*.
    pub(crate) defaults: crate::store::Channels,
    pub(crate) subject_template: Option<String>,
    /// Who renders the strings this category's pushes show (#190).
    pub(crate) render: RenderMode,
}

impl Category {
    /// A category that is on until the account says otherwise, and sends
    /// no badge count.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            badge: false,
            defaults: crate::store::Channels {
                push: true,
                in_app: true,
                // Off, unlike push and in-app. An email is the most
                // intrusive of the three and the hardest to take back, so
                // a venture opts a category in deliberately.
                email: false,
            },
            subject_template: None,
            render: RenderMode::Server,
        }
    }

    /// Whether an account that has never expressed a preference gets this
    /// category (default `true`).
    #[must_use]
    pub fn default_enabled(mut self, enabled: bool) -> Self {
        self.defaults.push = enabled;
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

    /// Whether this category writes an in-app inbox row (default
    /// `true`).
    ///
    /// Turn it off for a notification that is noise once it is past —
    /// "your room starts in ten minutes" is worth a push and worth
    /// nothing in a list read tomorrow. This is the venture's decision
    /// about the *category*; the account's own `in_app` switch is
    /// separate and is checked as well.
    #[must_use]
    pub fn in_app(mut self, keeps_a_row: bool) -> Self {
        self.defaults.in_app = keeps_a_row;
        self
    }

    /// Whether this category is emailed to an account with a verified
    /// address (default **`false`**).
    ///
    /// Off by default because email is the most intrusive of the three
    /// channels and the hardest to take back — a venture opts a category
    /// in deliberately. The account's own `email` switch is separate and
    /// is checked as well, and a category that is on here still sends
    /// nothing to an account with no verified address.
    #[must_use]
    pub fn email(mut self, sends_mail: bool) -> Self {
        self.defaults.email = sends_mail;
        self
    }

    /// The subject line for this category's mail. Defaults to the
    /// notification's own title.
    #[must_use]
    pub fn subject_template(mut self, subject: impl Into<String>) -> Self {
        self.subject_template = Some(subject.into());
        self
    }

    /// Who renders this category's strings for a device (default
    /// [`RenderMode::Server`], issue #190).
    ///
    /// Only ever consulted for a [`Message::Localizable`]: a caller that
    /// passes a rendered `Notification` gets exactly what it wrote,
    /// whatever this says.
    ///
    /// [`RenderMode::Native`] and [`RenderMode::Both`] pass the caller's
    /// [`Localizable::loc`] keys through to APNs and FCM, so an app that
    /// ships its own translations renders in the device's language without
    /// the server knowing any of them. **Web Push has no such mechanism**,
    /// so a browser is always served the rendered text whatever the mode.
    #[must_use]
    pub fn render(mut self, mode: RenderMode) -> Self {
        self.render = mode;
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
    pub drain_concurrency: u32,
    pub rehome_max_per_hour: u32,
    pub inbox_retention_days: u32,
    pub email_window_secs: u32,
    pub email_max_per_window: u32,
    pub transport_probe: Option<TransportProbe>,
    pub mailer_probe: Option<TransportProbe>,
    pub vapid_key_probe: Option<VapidKeyProbe>,
    /// The venture's strings (#190). `None` is a single-language venture,
    /// which pays for none of this: a `Localizable` is then a
    /// misconfiguration rather than a silent English fallback.
    pub catalog: Option<Arc<dyn Catalog>>,
    /// The venture's default locale, when it is not the catalog's own.
    pub default_locale: Option<LanguageIdentifier>,
    /// The message ids this venture promises are translated into every
    /// locale its catalog declares — what the completeness check reads.
    pub messages: Arc<Vec<String>>,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("categories", &self.categories)
            .field("max_attempts", &self.max_attempts)
            .field("drain_batch", &self.drain_batch)
            .field("drain_concurrency", &self.drain_concurrency)
            .field("rehome_max_per_hour", &self.rehome_max_per_hour)
            .field("inbox_retention_days", &self.inbox_retention_days)
            .field("email_window_secs", &self.email_window_secs)
            .field("email_max_per_window", &self.email_max_per_window)
            .field("transport_probe", &self.transport_probe.is_some())
            .field("mailer_probe", &self.mailer_probe.is_some())
            // Whether one is wired, never what it answers: the key is
            // public, but a report that prints a probe's result is a
            // habit that reaches a probe whose result is not.
            .field("vapid_key_probe", &self.vapid_key_probe.is_some())
            // The locales a catalog has, never the strings in it: a
            // venture's copy is its own, and a `Debug` ends up in a log.
            .field(
                "locales",
                &self.catalog.as_ref().map(|catalog| {
                    catalog
                        .locales()
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                }),
            )
            .field("messages", &self.messages.len())
            // Non-exhaustive on purpose: `catalog` is the venture's own
            // copy, and a `Debug` of a catalog ends up in a log.
            .finish_non_exhaustive()
    }
}

impl Settings {
    /// The venture's default locale: the one it set, else its catalog's,
    /// else English.
    ///
    /// Always answers, which is what makes the resolution chain total: a
    /// recipient who has never expressed a language still gets one.
    pub(crate) fn venture_locale(&self) -> LanguageIdentifier {
        if let Some(locale) = &self.default_locale {
            return locale.clone();
        }
        if let Some(catalog) = &self.catalog {
            return catalog.default_locale().clone();
        }
        crate::locale::FALLBACK_LOCALE
            .parse()
            .unwrap_or_else(|_| LanguageIdentifier::default())
    }

    /// The venture's default locale as the deployment configured it:
    /// `NOTIFICATIONS_DEFAULT_LOCALE` when it names a language tag, else
    /// [`Settings::venture_locale`].
    ///
    /// A value that is not a tag is ignored rather than stored or echoed —
    /// the same door every other locale comes through.
    pub(crate) fn configured_locale(&self, ctx: &ModuleContext) -> LanguageIdentifier {
        ModuleConfig::new(MODULE_NAME, &*ctx.config)
            .get_opt("DEFAULT_LOCALE")
            .as_deref()
            .and_then(cratefield_i18n::parse_locale)
            .unwrap_or_else(|| self.venture_locale())
    }

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
    /// The settings as the composition finished them, parked at the same
    /// moment, so a [`Notifier`] taken mid-build cannot serve a set the
    /// module no longer has (see [`Notifier`]'s own `settings`).
    settings_cell: Arc<OnceLock<Settings>>,
    /// The token verifier, built once rather than per request.
    ///
    /// `router()` runs on **every** request on Workers, and an
    /// `AuthClient` built inside it starts with an empty JWKS cache: one
    /// extra outbound round-trip to the issuer per authenticated request,
    /// which anyone can drive by sending junk bearers. Parked here it is
    /// built once per isolate, cache and all. Every rebuild is handed an
    /// equivalent `HttpClient` and `Clock`, which is what makes keeping
    /// the first one sound — the same reasoning as `ctx_cell`.
    auth_cell: Arc<OnceLock<Option<Arc<factory0_auth_client::AuthClient>>>>,
    /// The venture's `applicationServerKey`, resolved once rather than
    /// per request: the probe parses a private key to derive it, and
    /// `router()` runs on every request on Workers.
    vapid_key_cell: Arc<OnceLock<Option<String>>>,
}

impl Default for Notifications {
    fn default() -> Self {
        Self::new()
    }
}

impl Notifications {
    /// No categories (a venture must declare its own), five attempts
    /// before a transient failure is given up on, fifty rows per drain,
    /// eight of them in flight at a time, and three device take-overs per
    /// account per hour.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: Settings {
                categories: Arc::new(Vec::new()),
                max_attempts: 5,
                drain_batch: 50,
                drain_concurrency: 8,
                rehome_max_per_hour: 3,
                inbox_retention_days: 90,
                email_window_secs: 3_600,
                email_max_per_window: 5,
                transport_probe: None,
                mailer_probe: None,
                vapid_key_probe: None,
                catalog: None,
                default_locale: None,
                messages: Arc::new(Vec::new()),
            },
            ctx_cell: Arc::new(OnceLock::new()),
            settings_cell: Arc::new(OnceLock::new()),
            auth_cell: Arc::new(OnceLock::new()),
            vapid_key_cell: Arc::new(OnceLock::new()),
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

    /// How many of those rows are in flight at a time (default 8;
    /// `NOTIFICATIONS_DRAIN_CONCURRENCY`).
    ///
    /// Each in-flight row is one outbound provider request, so this is the
    /// knob for a runtime that counts subrequests. `1` restores a strictly
    /// sequential drain.
    #[must_use]
    pub fn drain_concurrency(mut self, rows: u32) -> Self {
        self.settings.drain_concurrency = rows;
        self
    }

    /// How many devices one account may take over from other accounts in
    /// an hour (default 3; `NOTIFICATIONS_REHOME_MAX_PER_HOUR`).
    ///
    /// A device that signs into another account re-homes, which is the
    /// behaviour a shared tablet needs — and the reason a *token* must not
    /// be treated as proof of anything. Whoever holds a leaked
    /// FCM/APNs token can present it with their own valid bearer and take
    /// the device over: the previous owner stops receiving, and the
    /// caller's notifications start arriving on someone else's phone.
    /// Nothing in a push token distinguishes the two cases, so the module
    /// bounds them instead: over this many take-overs in an hour the
    /// registration answers [`REHOME_LIMIT`] (429), every one of them
    /// emits [`EVENT_SUBSCRIPTION_REHOMED`], and a notification queued for
    /// the previous owner is dropped rather than delivered to the new one.
    ///
    /// `0` refuses every cross-account re-home, for a venture whose
    /// devices are never shared. Sign-out (`DELETE /subscriptions/{id}`)
    /// still frees the device for the next account, because it deletes the
    /// row rather than moving it.
    #[must_use]
    pub fn rehome_max_per_hour(mut self, devices: u32) -> Self {
        self.settings.rehome_max_per_hour = devices;
        self
    }

    /// How long a read or archived inbox row is kept before the scheduled
    /// tick deletes it (default 90 days; `0` keeps them forever).
    ///
    /// Only rows the account has finished with. An unread row is still
    /// waiting to be seen however old it is, and deleting it would be the
    /// module deciding the account missed its chance.
    #[must_use]
    pub fn inbox_retention_days(mut self, days: u32) -> Self {
        self.settings.inbox_retention_days = days;
        self
    }

    /// At most this many mails per account per category per window
    /// (default 5 an hour; `0` stops the channel).
    ///
    /// A cap rather than a queue: over it the mail is dropped, not
    /// deferred. Deferring would deliver the backlog the moment the
    /// window rolled, which is the flood the cap exists to prevent.
    #[must_use]
    pub fn email_max_per_window(mut self, mails: u32) -> Self {
        self.settings.email_max_per_window = mails;
        self
    }

    /// How long that window is, in seconds (default one hour).
    #[must_use]
    pub fn email_window_secs(mut self, seconds: u32) -> Self {
        self.settings.email_window_secs = seconds;
        self
    }

    /// The venture's own strings, for [`Message::Localizable`] callers
    /// (issue #190).
    ///
    /// ```rust,ignore
    /// use cratefield_i18n::FluentCatalog;
    ///
    /// let catalog = FluentCatalog::builder()
    ///     .default_locale("en")
    ///     .locale("en", include_str!("../locales/en.ftl"))
    ///     .locale("id", include_str!("../locales/id.ftl"))
    ///     .build()?;
    /// Notifications::new().catalog(catalog).messages(["booking-confirmed"])
    /// ```
    ///
    /// Built **once**, by the venture, and shared: the bundles are parsed
    /// at cold start, not per request. A venture that never calls this
    /// pays nothing at all — no catalog is built, no locale is read, and a
    /// rendered `Notification` travels exactly as it did before this
    /// existed.
    #[must_use]
    pub fn catalog(mut self, catalog: impl Catalog + 'static) -> Self {
        self.settings.catalog = Some(Arc::new(catalog));
        self
    }

    /// A catalog the venture already holds behind an `Arc` — because it
    /// shares one with its own mail templates, say.
    #[must_use]
    pub fn shared_catalog(mut self, catalog: Arc<dyn Catalog>) -> Self {
        self.settings.catalog = Some(catalog);
        self
    }

    /// The locale a recipient who has expressed none is written to
    /// (`NOTIFICATIONS_DEFAULT_LOCALE`).
    ///
    /// Defaults to the catalog's own default locale, which is usually the
    /// right answer; set it only when they differ.
    ///
    /// # Panics
    ///
    /// If `tag` is not a BCP 47 language tag. A composition is code a
    /// developer wrote and compiled, so a typo here should stop the
    /// venture rather than quietly write everybody in English.
    #[must_use]
    pub fn default_locale(mut self, tag: &str) -> Self {
        self.settings.default_locale = Some(
            cratefield_i18n::parse_locale(tag)
                .unwrap_or_else(|| panic!("notifications: {tag:?} is not a BCP 47 language tag")),
        );
        self
    }

    /// The message ids this venture promises are translated into every
    /// locale its catalog declares.
    ///
    /// A catalog cannot know which messages a caller will name, so the
    /// venture says. Every id listed here must have a `.title` and a
    /// `.body` in **every** configured locale, or the module refuses to
    /// start and `fz doctor` lists what is missing — which is the whole
    /// point: a translation gap found at deploy time is a pull request,
    /// and the same gap found at delivery time is a person reading
    /// `booking-confirmed.title` on a lock screen.
    #[must_use]
    pub fn messages(mut self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let messages = Arc::make_mut(&mut self.settings.messages);
        for id in ids {
            messages.push(id.into());
        }
        self
    }

    /// Every `locale: key.attribute` the catalog cannot render, for the
    /// messages this venture declared with [`Notifications::messages`].
    ///
    /// Empty for a venture with no catalog and for one whose catalog is
    /// complete. Identifiers only — never a rendered string, which is
    /// built from a caller's arguments about a person.
    #[must_use]
    pub fn missing_translations(&self) -> Vec<String> {
        let Some(catalog) = self.settings.catalog.as_ref() else {
            return Vec::new();
        };
        let keys: Vec<&str> = self.settings.messages.iter().map(String::as_str).collect();
        cratefield_i18n::missing_messages(&**catalog, &keys, &[TITLE, BODY])
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// What the venture's own probes say about the ports this module
    /// cannot see for itself.
    ///
    /// Whether a `Push` transport or a `Mailer` exists is not readable
    /// from config — a venture may hand the harness its own adapter — so
    /// the venture answers, and a module with no probe says nothing
    /// rather than guessing.
    fn probe_problems(&self, cfg: &dyn Config, errors: &mut ConfigError) {
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

        // Only when a category actually asks for email. A venture with no
        // `email(true)` category never sends one, so a missing mailer is
        // not a problem it has (#189).
        let emails = self
            .settings
            .categories
            .iter()
            .filter(|category| category.defaults.email)
            .map(|category| category.name.clone())
            .collect::<Vec<_>>();
        if !emails.is_empty()
            && self
                .settings
                .mailer_probe
                .as_ref()
                .is_some_and(|probe| !probe(cfg))
        {
            errors.push(format!(
                "notifications: production, and {} opted into email, but this venture wired no \
                 Mailer port: every one of those would dead-letter as `not_configured`. \
                 Configure the mailer, or drop `.email(true)` from those categories",
                emails.join(", "),
            ));
        }
    }

    /// How the venture answers "is a mailer wired?", for the same
    /// production check as [`Notifications::transport_probe`].
    ///
    /// Needed for the same reason: whether a `Mailer` port exists is not
    /// something config can be read for — a venture may hand the harness
    /// its own adapter — so the venture answers, and a venture that
    /// assembles Resend from the environment passes a check on its key.
    ///
    /// Without a probe the check is skipped, exactly as for transports.
    #[must_use]
    pub fn mailer_probe(
        mut self,
        probe: impl Fn(&dyn Config) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.settings.mailer_probe = Some(Arc::new(probe));
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

    /// How the venture answers "what `applicationServerKey` should a
    /// browser subscribe with?", served at `GET
    /// /v1/notifications/vapid-public-key` (issue #183).
    ///
    /// The module cannot answer it, for the same reason it cannot answer
    /// [`Notifications::transport_probe`]: the push environment has
    /// exactly one reader, `cratefield-push-wiring`, and depending on it
    /// here would pull all three push adapters into a module that must
    /// compile the same whether a venture wires zero or three. So the
    /// venture, which already has the reader, passes the answer in:
    ///
    /// ```rust,ignore
    /// Notifications::new()
    ///     .vapid_public_key(cratefield::push_wiring::vapid_public_key)
    /// ```
    ///
    /// Without a probe — or with one that answers `None`, which is what
    /// an unconfigured venture gets — the route is a 404 and `cf.js`
    /// reports that this site does not offer browser push. It is the
    /// public half of the VAPID pair, handed to every browser that
    /// subscribes; the private half never leaves the adapter.
    #[must_use]
    pub fn vapid_public_key(
        mut self,
        probe: impl Fn(&dyn Config) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.settings.vapid_key_probe = Some(Arc::new(probe));
        self
    }

    /// The handle other modules call.
    ///
    /// Take it before composing the harness and hand it to the modules
    /// that send notifications; it starts working when
    /// `Harness::router` builds this module's router. Taking it early is
    /// safe in both directions: it reads the module's finished settings
    /// through a shared cell, so a category declared after this call is
    /// one the handle can send.
    #[must_use]
    pub fn notifier(&self) -> Notifier {
        Notifier {
            cell: Arc::clone(&self.ctx_cell),
            settings_cell: Arc::clone(&self.settings_cell),
            settings_at_handout: self.settings.clone(),
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
        // `Realtime` (#187) is what makes the inbox update while the app
        // is open. Without it the client polls `unread-count`; the inbox
        // row is written either way, so nothing depends on it.
        // `Mailer` (#189) is the third channel. A venture that declares no
        // category with `email(true)` never needs it.
        &[
            Port::Defer,
            Port::HttpClient,
            Port::Realtime,
            Port::Mailer,
            Port::Signer,
        ]
    }

    fn tables(&self) -> &'static [&'static str] {
        &[
            store::SUBSCRIPTIONS,
            store::PREFERENCES,
            store::OUTBOX,
            store::DEAD_LETTERS,
            store::INBOX,
            store::EMAIL_TARGETS,
            store::EMAIL_SENDS,
            store::LOCALES,
            store::EMAIL_SUPPRESSED,
        ]
    }

    /// What this module holds about a person, per table (issue #244).
    ///
    /// It held all of this before it said any of it. Erasure plans from this
    /// list and not from [`tables`](Module::tables), so until these eight
    /// declarations existed a subject access request answered without the
    /// stored address, the device tokens and the inbox, and an erasure
    /// request reported success having deleted none of them.
    ///
    /// The descriptions are published verbatim by
    /// `GET /v1/privacy/manifest` and written for the person reading that
    /// page, not for whoever maintains this file.
    ///
    /// Three of the eight are judgements rather than the obvious answer:
    ///
    /// - **`notifications_subscriptions`** is erased like the rest, and
    ///   `recipient_json` is [redacted](PersonalDataSet::redacted) from the
    ///   export. The row is the account's and must go, but the column is a
    ///   push token or a Web Push endpoint — a **bearer capability**, which
    ///   whoever holds the export could notify the device with (ADR 0015).
    ///   `recipient_hash` is exported: it identifies the device to somebody
    ///   reading their own export and cannot be sent to.
    /// - **`notifications_email_targets`** is erased, including the
    ///   unsubscribe record, which is the one case where erasing loses a
    ///   protection. It is still right here: the address is only ever mailed
    ///   because a `notify()` names this account, and the account's rows are
    ///   going in the same batch — so nothing remains that could reach the
    ///   address, and keeping it would be keeping an address somebody asked
    ///   us to forget. A venture that suppresses a **bounced** address is
    ///   keeping that in the provider, not here.
    /// - **`notifications_outbox`** is the one table declared as holding
    ///   nothing to export, and it is the honest half-answer. A queued row
    ///   does hold the message, and it is unreachable: the payload carries
    ///   the account inside JSON, and export and erasure key on a column.
    ///   The reason published for it says so, and issue #266 tracks the fix,
    ///   which is core's `Outbox` and not this module's. What bounds it is
    ///   that a row is deleted on delivery and moved to
    ///   `notifications_dead_letters` when it gives up — and dead letters,
    ///   which used to be permanent, carry an `account_id` since migration
    ///   `0007` precisely so an erasure reaches them.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            PersonalDataSet {
                table: store::SUBSCRIPTIONS,
                subject: "account_id",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "Each phone or browser you turned notifications on for, with the \
                              address the notification is delivered to, the language that device \
                              is set to, and when it last checked in.",
                redacted: &["recipient_json"],
                subject_via: None,
            },
            PersonalDataSet {
                table: store::PREFERENCES,
                subject: "account_id",
                kind: DataKind::Usage,
                disposition: Disposition::Erase,
                description: "Which kinds of notification you have switched on or off, for each \
                              of the three ways we can reach you.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: store::LOCALES,
                subject: "account_id",
                kind: DataKind::Usage,
                disposition: Disposition::Erase,
                description: "The language you asked to be written to in.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: store::INBOX,
                subject: "account_id",
                kind: DataKind::Content,
                disposition: Disposition::Erase,
                description: "The notifications you can read back in the app: what each one said, \
                              when it arrived, and when you opened or archived it.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: store::EMAIL_TARGETS,
                subject: "account_id",
                kind: DataKind::Contact,
                disposition: Disposition::Erase,
                description: "The email address notifications are sent to, whether it has been \
                              confirmed, and whether you have unsubscribed from them.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: store::EMAIL_SENDS,
                subject: "account_id",
                kind: DataKind::Usage,
                disposition: Disposition::Erase,
                description: "When we last emailed you about each kind of notification, which is \
                              what stops us emailing you about it again too soon.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: store::DEAD_LETTERS,
                subject: "account_id",
                kind: DataKind::Content,
                disposition: Disposition::Erase,
                description: "A notification we gave up trying to deliver, kept with what it said \
                              so somebody can find out why it failed.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: store::EMAIL_SUPPRESSED,
                subject: "account_id",
                kind: DataKind::Usage,
                disposition: Disposition::Erase,
                description: "Which notifications we held back from your inbox because too many \
                              arrived at once, kept only until they are gathered into one \
                              summary email.",
                redacted: &[],
            },
            PersonalDataSet::none(
                store::OUTBOX,
                "Notifications waiting to be sent. A row holds the message until it is delivered \
                 or given up on, minutes later, and is then deleted; it is filed under the send \
                 rather than under you, so an erasure request does not reach one that happens to \
                 be in flight.",
            ),
        ];
        SETS
    }

    fn emits(&self) -> &'static [&'static str] {
        &[
            notify::EVENT_SUBSCRIPTION_PRUNED,
            notify::EVENT_SUBSCRIPTION_REHOMED,
            locale::EVENT_MISSING_TRANSLATION,
        ]
    }

    /// The translation completeness check (#190).
    ///
    /// It reads only what the venture compiled in — its catalog and the
    /// message ids it declared — so `fz doctor` can run it with no
    /// environment at all, and it says the same thing on a laptop as in
    /// CI. The same gaps also fail [`Module::validate_config`], so a
    /// deployment that skipped the doctor still refuses to start.
    fn self_check(&self) -> Vec<String> {
        self.missing_translations()
            .into_iter()
            .map(|missing| {
                format!(
                    "notifications: no translation for {missing} — every message listed in \
                     `.messages(..)` needs a `.title` and a `.body` in every configured locale"
                )
            })
            .collect()
    }

    fn public_writes(&self) -> bool {
        // Two routes, and only two, are not behind the auth extractor,
        // because neither caller can hold a session:
        //
        // - `POST /email/unsubscribe` (#189) is RFC 8058 one-click. A
        //   mailbox provider posts it on the recipient's behalf and has
        //   never signed in to anything here; the signed token is the
        //   authority.
        // - `POST /email/webhook` (#233) is the provider's bounce
        //   delivery. Resend has no account either; its Svix signature
        //   is the authority.
        //
        // Everything else stays authenticated. This has to be `true`
        // even though both are proved, because the flag is what makes
        // `WriteGuards::collect` read `public_write_policy` at all —
        // left `false`, a module with unauthenticated writes is simply
        // invisible to the production check.
        true
    }

    fn public_write_policy(&self) -> RoutePolicy {
        // Not `HumanForm`: neither caller is a person and neither can
        // solve a CAPTCHA. Not `Signature` either — that one means a
        // payments webhook, and `WriteGuards::needs_payments` would
        // demand a `Payments` port this module has no use for.
        //
        // `SignedLink` says what is actually true: the proof is an
        // artifact this service issued, so production must have a usable
        // `Signer`. Without one `unsubscribe_url` cannot mint a token at
        // all, so `compose` ships no `List-Unsubscribe` header rather
        // than one naming a URI that cannot accept the POST (issue #234)
        // — which keeps the mail compliant, and costs the venture the
        // one-click standing Gmail and Yahoo want from a bulk sender.
        // This check is how a deployment finds out before its mail does.
        RoutePolicy::SignedLink
    }

    fn migrations(&self) -> Migrations {
        const _: () = cratefield_core::assert_migration_set(&SHIPPED_MIGRATIONS);
        Migrations {
            sqlite: &SHIPPED_MIGRATIONS,
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

        // Parsed as the `u32` the runtime reads, not as a `u64`: a value
        // above `u32::MAX` used to validate clean and then fall back to
        // the default at run time, which is the one outcome configuration
        // validation exists to prevent — a deployment that was told its
        // setting was fine and is not running it.
        for (key, minimum) in [
            ("MAX_ATTEMPTS", 1u32),
            ("DRAIN_BATCH", 1),
            ("DRAIN_CONCURRENCY", 1),
            ("REHOME_MAX_PER_HOUR", 0),
        ] {
            if let Some(raw) = module.get_opt(key) {
                let valid = raw.parse::<u32>().is_ok_and(|value| value >= minimum);
                if !valid {
                    errors.push(format!(
                        "notifications: {} must be an integer between {minimum} and {}, got \
                         {raw:?}",
                        module.key(key),
                        u32::MAX
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

        if let Some(raw) = module.get_opt("DEFAULT_LOCALE")
            && cratefield_i18n::parse_locale(&raw).is_none()
        {
            // Names the variable, never the value: a deployment that put
            // something else in this field must not have it echoed into a
            // boot log. What it was is on the machine that set it.
            errors.push(format!(
                "notifications: {} is not a BCP 47 language tag, so every recipient with no \
                 language of their own would silently get the compiled-in default instead",
                module.key("DEFAULT_LOCALE")
            ));
        }

        // The catalog's own completeness. Not production-only: a venture
        // that declared a message and did not translate it is broken
        // everywhere, and the failure is a person reading a message id.
        for problem in self.self_check() {
            errors.push(problem);
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
            self.probe_problems(cfg, &mut errors);
        }

        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let shared = Arc::new(ctx);
        // First build wins; on Workers every request rebuilds the router
        // with equivalent ports, so the parked context stays valid.
        let _ = self.ctx_cell.set(Arc::clone(&shared));
        let _ = self.settings_cell.set(self.settings.clone());
        // Built once per isolate, not once per request: see `auth_cell`.
        let auth = self
            .auth_cell
            .get_or_init(|| handlers::auth_client(&shared))
            .clone();
        let vapid_public_key = self
            .vapid_key_cell
            .get_or_init(|| {
                self.settings
                    .vapid_key_probe
                    .as_ref()
                    .and_then(|probe| probe(&*shared.config))
            })
            .clone();
        handlers::router(Arc::new(handlers::ModuleState {
            ctx: shared,
            settings: self.settings.clone(),
            auth,
            vapid_public_key,
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
            //
            // Through the ports of the context the runtime hands in, not
            // the one parked at router-build time. Cloudflare's scheduled
            // path builds no router, so on a cold isolate there is no
            // parked context and this whole half never ran; on a warm one
            // it ran against some earlier request's bindings.
            let scope = scheduled_scope(ctx);
            let report = self
                .notifier()
                .drain_with(ctx, &scope)
                .await
                .map_err(|err| Box::new(err) as AnyError)?;
            if report.claimed > 0 {
                tracing::info!(?report, cron, "drained the notifications outbox");
            }

            // Retention, on the same tick. A failure here is logged rather
            // than returned: the drain above already succeeded, and losing
            // a scheduled run over housekeeping would stop the recovery
            // half too.
            let days = ModuleConfig::new(MODULE_NAME, &*ctx.config)
                .get_u32("INBOX_RETENTION_DAYS", self.settings.inbox_retention_days);
            if days > 0
                && let Some(db) = ctx.ports.db.as_ref()
            {
                let cutoff = clock::plus_secs(
                    &clock::now_iso(ctx.ports.clock.as_ref()),
                    -(i64::from(days) * 86_400),
                );
                // The send window only ever looks back one window, so
                // anything older than the inbox cutoff is long dead.
                if let Err(err) = store::prune_email_sends(&**db, &cutoff).await {
                    tracing::error!(error = %err, "pruning the email send window failed");
                }
                // A suppression row is normally cleared when its summary is
                // sent; this catches the ones a burst that never rolled
                // (cap later set to 0) or a mailer that kept failing left
                // behind. They are only ever worth one summary, so keeping
                // them past retention would summarise stale news.
                if let Err(err) = store::prune_email_suppressed(&**db, &cutoff).await {
                    tracing::error!(error = %err, "pruning suppressed email rows failed");
                }
                match store::prune_inbox(&**db, &cutoff).await {
                    Ok(pruned) if pruned > 0 => {
                        tracing::info!(pruned, cron, "pruned read notifications past retention");
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::error!(error = %err, "pruning the notifications inbox failed");
                    }
                }
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
        assert_eq!(
            module.optional(),
            [
                Port::Defer,
                Port::HttpClient,
                Port::Realtime,
                Port::Mailer,
                Port::Signer,
            ]
        );
        assert_eq!(
            module.tables(),
            [
                "notifications_subscriptions",
                "notifications_preferences",
                "notifications_outbox",
                "notifications_dead_letters",
                "notifications_inbox",
                "notifications_email_targets",
                "notifications_email_sends",
                "notifications_locales",
                "notifications_email_suppressed",
            ]
        );
        assert_eq!(
            module.emits(),
            [
                "notifications.subscription_pruned",
                "notifications.subscription_rehomed",
                "notifications.missing_translation",
            ]
        );
        assert!(
            module.public_writes(),
            "the one-click unsubscribe (#189) and the provider webhook (#233) are \
             unauthenticated; left false, the production check never sees them"
        );
        assert_eq!(
            module.public_write_policy(),
            RoutePolicy::SignedLink,
            "both are proved by an artifact this service issued, not by a CAPTCHA \
             nobody is there to solve — and not by `Signature`, which asks for a \
             Payments port this module has no use for"
        );
        assert!(
            module.surface().is_empty(),
            "ADR 0010 has no audience for a signed-in account; see the crate docs"
        );
    }

    #[test]
    fn a_category_is_on_with_no_badge_until_told_otherwise() {
        let plain = Category::new("booking");
        assert!(plain.defaults.push);
        assert!(!plain.badge, "no badge counts by default");
        assert!(!Category::new("x").default_enabled(false).defaults.push);
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
    fn a_number_the_runtime_cannot_read_is_refused_by_validation() {
        // The runtime reads these through `ModuleConfig::get_u32`, so a
        // value above `u32::MAX` silently falls back to the default.
        // Validating it as a `u64` accepted exactly that and told the
        // deployment its setting was fine.
        for key in [
            "NOTIFICATIONS_MAX_ATTEMPTS",
            "NOTIFICATIONS_DRAIN_BATCH",
            "NOTIFICATIONS_DRAIN_CONCURRENCY",
        ] {
            let cfg = cratefield_core::MapConfig::from_pairs([(key, "4294967296")]);
            let err = module()
                .validate_config(&cfg)
                .expect_err("a value above u32::MAX is not the value the runtime would read");
            assert!(err.to_string().contains(key), "{err}");

            let zero = cratefield_core::MapConfig::from_pairs([(key, "0")]);
            module()
                .validate_config(&zero)
                .expect_err("zero is not a usable batch, attempt count or concurrency");
        }

        // And the one whose floor really is zero: a venture that refuses
        // every cross-account device take-over.
        module()
            .validate_config(&cratefield_core::MapConfig::from_pairs([(
                "NOTIFICATIONS_REHOME_MAX_PER_HOUR",
                "0",
            )]))
            .expect("0 re-homes an hour is a policy, not a mistake");
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
    fn every_hot_read_has_an_index() {
        // `claim_due` filters and orders on `next_attempt_at` and runs on
        // every send and every scheduled tick — the hottest read the
        // module has, and the one that scanned the whole table while a
        // far colder one was indexed. This is core's first `Outbox`
        // consumer, so this DDL is the template the next module copies.
        for (index, table, column) in [
            (
                "notifications_outbox_due",
                "notifications_outbox",
                "next_attempt_at",
            ),
            (
                "notifications_subscriptions_by_account",
                "notifications_subscriptions",
                "account_id",
            ),
        ] {
            let expected = format!("CREATE INDEX IF NOT EXISTS {index}\n    ON {table} ({column})");
            // Across the whole set, not one file: `notifications_outbox_due`
            // arrives in `0002` because `0001` is applied and an applied
            // migration is never edited. Which migration declares an index
            // is not the property — shipping it is.
            assert!(
                SHIPPED_MIGRATIONS
                    .iter()
                    .any(|migration| migration.sql.contains(&expected)),
                "some migration must index {table}.{column}:\n{expected}"
            );
        }
    }

    #[test]
    fn the_migration_is_portable() {
        for migration in SHIPPED_MIGRATIONS {
            assert_eq!(
                cratefield_core::lint_portable_sql(migration.sql),
                Vec::new(),
                "migration {} left the portable subset (ADR 0004)",
                migration.id
            );
            assert_eq!(
                cratefield_core::lint_card_data(migration.sql),
                Vec::new(),
                "migration {}",
                migration.id
            );
        }
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
