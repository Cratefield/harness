//! The fan-out API other modules call, and the drain that delivers it
//! (issue #182).
//!
//! # The shape of a send
//!
//! [`Notifier::notify`] does **not** write. It returns [`Enqueued`], whose
//! statements the caller appends to its own `db.batch(..)`, so a booking's
//! confirmation row and the notification that announces it commit together
//! or not at all — the core [`Outbox`] contract (#128). Then
//! [`Notifier::deliver_now`] uses `Defer` to *attempt* immediate delivery,
//! and the venture's scheduled entry point drains whatever that missed.
//!
//! The order matters and is not interchangeable: deferring the drain from
//! inside `notify` would race the caller's own commit, and a drain that
//! ran first would find no row.
//!
//! # Where the preference is checked
//!
//! In the **drain**, immediately before `Push::send`. That is what makes a
//! late opt-out win: a preference checked only when the row was written
//! would still deliver everything already queued. `notify` also skips
//! enqueueing for a category that is already off, but that is an
//! optimisation over rows the drain would drop anyway — never the
//! authority.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use cratefield_core::{
    Database, DbError, ModuleConfig, ModuleContext, Notification, Outbox, OutboxRecord, Push,
    PushError, PushOutcome, Scope, Statement,
};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::clock::{now_iso, plus_secs};
use crate::store::{self, Channels, DeadLetterReason, Subscription};
use crate::{Category, Settings};

/// The outbox topic every row this module writes carries.
pub const TOPIC_SEND: &str = "notifications.send";

/// The event a venture can subscribe to instead of taking a crate
/// dependency on this module.
pub const EVENT_REQUESTED: &str = "notifications.requested";

/// Emitted when the provider told us a recipient is gone and the
/// subscription was deleted. Carries no recipient: a serialised
/// [`cratefield_core::Recipient`] is credential material (ADR 0015).
pub const EVENT_SUBSCRIPTION_PRUNED: &str = "notifications.subscription_pruned";

/// Emitted when a device that was one account's became another's.
///
/// A device token is not an authenticator (see
/// [`crate::Notifications::rehome_max_per_hour`]), so the venture is told
/// every time a subscription changes hands and can act on it — mail the
/// previous owner, raise it to whoever watches for abuse. Carries no
/// recipient: like the prune event, a serialised
/// [`cratefield_core::Recipient`] is credential material (ADR 0015).
pub const EVENT_SUBSCRIPTION_REHOMED: &str = "notifications.subscription_rehomed";

/// The first retry delay; each further attempt doubles it.
const BACKOFF_BASE_SECS: u64 = 30;
/// The ceiling on the doubling.
const BACKOFF_MAX_SECS: u64 = 3_600;
/// How long a claimed row stays leased to one drainer.
pub(crate) const LEASE_SECS: i64 = 300;

/// One unit of work in `notifications_outbox`.
///
/// The recipient is **not** in it. It is credential material, and an
/// outbox payload is ordinary data that ends up in exports and in
/// diagnostics; the drain reads the subscription row instead. That also
/// gives the right behaviour for free: a device that signed out between
/// the commit and the drain has no subscription, so its queued
/// notification is dropped rather than sent to a stranger's phone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SendJob {
    pub notification_id: String,
    pub account_id: String,
    pub category: String,
    pub subscription_id: String,
    pub notification: Notification,
}

/// Why [`Notifier::notify`] produced no statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    /// The account has this category switched off.
    PreferenceOff,
    /// The account has no registered device.
    NoSubscriptions,
}

/// The outbox inserts one [`Notifier::notify`] produced.
///
/// Append [`Enqueued::statements`] to the caller's own `db.batch(..)`.
/// Nothing is written until that batch runs.
#[derive(Debug, Clone)]
pub struct Enqueued {
    notification_id: String,
    statements: Vec<Statement>,
    /// How many of `statements` are push rows. Counted rather than derived
    /// from the length: since #187 the batch may also carry the in-app
    /// inbox insert, and `len()` means devices.
    devices: usize,
    inbox: bool,
    /// The room and payload for the live announcement, present exactly
    /// when an inbox row is in `statements`. Built here so
    /// [`Notifier::announce`] is a broadcast and nothing else.
    announcement: Option<(String, Vec<u8>)>,
    skipped: Option<Skipped>,
}

impl Enqueued {
    /// The `INSERT`s to append to the caller's batch, in subscription
    /// order.
    #[must_use]
    pub fn statements(&self) -> &[Statement] {
        &self.statements
    }

    /// The statements, consumed.
    #[must_use]
    pub fn into_statements(self) -> Vec<Statement> {
        self.statements
    }

    /// The id shared by every row of this fan-out, and carried to the
    /// device in `data.notification_id` so a client that is reached on
    /// two devices can dedupe.
    #[must_use]
    pub fn notification_id(&self) -> &str {
        &self.notification_id
    }

    /// How many devices this notification will be attempted on.
    ///
    /// Devices, not statements: the batch may also carry the in-app inbox
    /// insert, which is not a send.
    #[must_use]
    pub fn len(&self) -> usize {
        self.devices
    }

    /// Whether nothing will be *sent*. An inbox row may still be written —
    /// see [`Enqueued::wrote_inbox`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices == 0
    }

    /// Whether the batch carries an in-app inbox row (#187).
    ///
    /// Independent of [`Enqueued::is_empty`]: the inbox is written for an
    /// account with no device and for one whose *push* preference is off,
    /// because those switch off push, not the record.
    #[must_use]
    pub fn wrote_inbox(&self) -> bool {
        self.inbox
    }

    /// Why nothing will be **pushed**, when nothing will be.
    #[must_use]
    pub fn skipped(&self) -> Option<Skipped> {
        self.skipped
    }
}

/// Why a fan-out could not be prepared.
#[derive(Debug)]
pub enum NotifyError {
    /// The category is not one the venture declared. A typo in a caller
    /// is a bug, not a silent no-op.
    UnknownCategory(String),
    /// `Notification::data` is neither absent nor a JSON object, so the
    /// module cannot add `category` and `notification_id` to it.
    InvalidData,
    /// The module's router has not been built yet, so it has no ports.
    NotMounted,
    /// A port the module requires is absent from this deployment.
    MissingPort(&'static str),
    Database(DbError),
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotifyError::UnknownCategory(category) => write!(
                f,
                "notifications: category {category:?} is not declared by this venture"
            ),
            NotifyError::InvalidData => f.write_str(
                "notifications: Notification::data must be a JSON object or absent, because the \
                 module adds `category` and `notification_id` to it",
            ),
            NotifyError::NotMounted => f.write_str(
                "notifications: the module's router has not been built, so it has no ports yet",
            ),
            NotifyError::MissingPort(port) => {
                write!(f, "notifications: this deployment provides no {port} port")
            }
            NotifyError::Database(err) => write!(f, "notifications: {err}"),
        }
    }
}

impl std::error::Error for NotifyError {}

impl From<DbError> for NotifyError {
    fn from(err: DbError) -> Self {
        NotifyError::Database(err)
    }
}

/// What one drain pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Rows this drainer leased.
    pub claimed: usize,
    /// Accepted by the provider.
    pub delivered: usize,
    /// Rescheduled after a transient failure.
    pub retried: usize,
    /// Subscriptions deleted because the provider said they were gone.
    pub pruned: usize,
    /// Rows moved to `notifications_dead_letters`.
    pub dead_lettered: usize,
    /// Rows dropped without sending: the category was switched off after
    /// the row was written, the device signed out, or the device now
    /// belongs to another account.
    pub dropped: usize,
    /// Rows whose own database call failed. The pass carries on: those
    /// rows keep their lease and become due again when it expires, and
    /// the rows behind them are not held hostage to one transient error.
    pub failed: usize,
}

/// What happened to one leased row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Delivered,
    Retried,
    Pruned,
    DeadLettered,
    Dropped,
}

impl DrainReport {
    fn record(&mut self, outcome: Outcome) {
        let counter = match outcome {
            Outcome::Delivered => &mut self.delivered,
            Outcome::Retried => &mut self.retried,
            Outcome::Pruned => &mut self.pruned,
            Outcome::DeadLettered => &mut self.dead_lettered,
            Outcome::Dropped => &mut self.dropped,
        };
        *counter += 1;
    }
}

/// The handle other modules call.
///
/// A venture gets one from [`crate::Notifications::notifier`] and hands it
/// to its own modules; it is a cheap clone and shares the mounted module's
/// ports, so it is usable only after `Harness::router` has built the
/// module's router.
#[derive(Clone)]
pub struct Notifier {
    pub(crate) cell: Arc<OnceLock<Arc<ModuleContext>>>,
    /// The module's settings as they were **finished**, parked when its
    /// router is built. Shared with the module, so a handle taken before
    /// the last `.category(..)` cannot serve a smaller set than the one
    /// the module validated, mounted and lists over `GET /preferences`.
    pub(crate) settings_cell: Arc<OnceLock<Settings>>,
    /// What the builder had when this handle was taken: all a handle has
    /// to go on before the module is mounted.
    pub(crate) settings_at_handout: Settings,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier")
            .field("mounted", &self.cell.get().is_some())
            .field("categories", &self.settings().categories.len())
            .finish_non_exhaustive()
    }
}

impl Notifier {
    fn ctx(&self) -> Result<&Arc<ModuleContext>, NotifyError> {
        self.cell.get().ok_or(NotifyError::NotMounted)
    }

    /// The module's settings: the finished set once it is mounted, and the
    /// set this handle was taken from before that.
    ///
    /// The indirection is the fix for a whole class of silent
    /// divergence. `Settings::categories` is an `Arc<Vec<..>>` that
    /// `.category(..)` mutates through `Arc::make_mut`, so taking the
    /// handle before the last one used to fork the vector: the module
    /// kept both categories, the handle kept one, and `notify` failed
    /// `UnknownCategory` at runtime for a category `validate_config`
    /// accepted and `GET /preferences` listed. Reading through the shared
    /// cell makes the two agree by construction.
    pub(crate) fn settings(&self) -> &Settings {
        self.settings_cell
            .get()
            .unwrap_or(&self.settings_at_handout)
    }

    /// The declared category, or an error naming the unknown one.
    fn category(&self, name: &str) -> Result<&Category, NotifyError> {
        self.settings()
            .categories
            .iter()
            .find(|category| category.name == name)
            .ok_or_else(|| NotifyError::UnknownCategory(name.to_owned()))
    }

    fn now(&self) -> String {
        now_iso(self.cell.get().and_then(|ctx| ctx.ports.clock.as_ref()))
    }

    fn new_id(&self) -> String {
        crate::clock::new_id(self.cell.get().and_then(|ctx| ctx.ports.id_gen.as_ref()))
    }

    /// The mounted context, once `Harness::router` has built the module's
    /// router. `None` before that.
    #[must_use]
    pub fn context(&self) -> Option<&Arc<ModuleContext>> {
        self.cell.get()
    }

    /// How many attempts a transient failure gets. The builder's value
    /// unless the deployment overrides it.
    fn max_attempts(&self, ctx: &ModuleContext) -> i64 {
        let configured = ModuleConfig::new(crate::MODULE_NAME, &*ctx.config)
            .get_u32("MAX_ATTEMPTS", self.settings().max_attempts);
        i64::from(configured.max(1))
    }

    /// How many rows one drain pass leases.
    fn drain_batch(&self, ctx: &ModuleContext) -> u64 {
        let settings = self.settings();
        let configured = ModuleConfig::new(crate::MODULE_NAME, &*ctx.config).get_u32(
            "DRAIN_BATCH",
            u32::try_from(settings.drain_batch).unwrap_or(u32::MAX),
        );
        u64::from(configured).max(1)
    }

    /// How many rows one drain pass has in flight at a time.
    ///
    /// The drain is one `wait_until` against a 300 s lease, and every row
    /// is a provider round-trip: fifty of them end to end is fifty
    /// latencies added up, for work that shares nothing between rows.
    /// Bounded rather than unbounded because each in-flight row is a
    /// subrequest, and a runtime counts those.
    fn drain_concurrency(&self, ctx: &ModuleContext) -> usize {
        let configured = ModuleConfig::new(crate::MODULE_NAME, &*ctx.config)
            .get_u32("DRAIN_CONCURRENCY", self.settings().drain_concurrency);
        usize::try_from(configured.max(1)).unwrap_or(1)
    }

    /// Whether `account_id` wants an inbox row for `category`.
    ///
    /// Two switches, both of which must be on: the venture's, which says
    /// whether the category is worth keeping at all, and the account's.
    async fn in_app_allowed(
        &self,
        db: &dyn Database,
        account_id: &str,
        category: &Category,
    ) -> Result<bool, DbError> {
        if !category.in_app {
            return Ok(false);
        }
        // Falls back to `true`, not to `default_enabled`: that is the
        // *push* default, and a category whose push is off by default —
        // `coach_notes` — is exactly the one whose record the account
        // still wants. A push opt-out switches off the interruption, not
        // the history (#187).
        Ok(store::preference(db, account_id, &category.name)
            .await?
            .is_none_or(|channels: Channels| channels.in_app))
    }

    /// Whether `account_id` wants push for `category` **right now**.
    async fn push_allowed(
        &self,
        db: &dyn Database,
        account_id: &str,
        category: &Category,
    ) -> Result<bool, DbError> {
        Ok(store::preference(db, account_id, &category.name)
            .await?
            .map_or(category.default_enabled, |channels: Channels| channels.push))
    }

    /// Prepares one notification for every device `account_id` has.
    ///
    /// Writes nothing: append [`Enqueued::statements`] to your own
    /// `db.batch(..)` so the notification is durable exactly when your
    /// state change is, then call [`Notifier::deliver_now`].
    ///
    /// # Errors
    ///
    /// [`NotifyError::UnknownCategory`] for a category the venture did
    /// not declare, [`NotifyError::InvalidData`] for a non-object
    /// `data`, and [`NotifyError::Database`] when a read fails.
    pub async fn notify(
        &self,
        db: &dyn Database,
        account_id: &str,
        category: &str,
        notification: Notification,
    ) -> Result<Enqueued, NotifyError> {
        let category = self.category(category)?.clone();
        let notification_id = self.new_id();

        // Prepared before either channel decides anything, so the row the
        // inbox keeps and the payload a device receives are the same
        // notification, and an invalid `data` is one error either way.
        let notification = prepare(notification, &category, &notification_id)?;
        let now = self.now();
        let mut statements = Vec::new();

        // In-app first, and unconditionally with respect to push: an
        // account with no device, or with push switched off, still gets
        // the record. Those switch off push, not the inbox.
        let inbox = self.in_app_allowed(db, account_id, &category).await?;
        let mut announcement = None;
        if inbox {
            let inbox_id = self.new_id();
            announcement = Some((
                format!("{INBOX_ROOM_PREFIX}{account_id}"),
                serde_json::to_vec(&json!({
                    "type": "notification",
                    "id": inbox_id,
                    "notification_id": notification_id,
                    "category": category.name,
                    "title": notification.title,
                    "body": notification.body,
                    "url": notification.url,
                    "created_at": now,
                }))
                .map_err(|err| {
                    NotifyError::Database(DbError::Execute(format!(
                        "notification does not serialise: {err}"
                    )))
                })?,
            ));
            statements.push(store::insert_inbox_statement(
                &inbox_id,
                account_id,
                &notification_id,
                &category.name,
                &notification.title,
                &notification.body,
                notification.url.as_deref(),
                notification.icon.as_deref(),
                &serde_json::to_string(&notification.data).map_err(|err| {
                    NotifyError::Database(DbError::Execute(format!(
                        "notification data does not serialise: {err}"
                    )))
                })?,
                &now,
            ));
        }

        // Cheap skip, not the check that counts: the drain re-reads the
        // preference immediately before sending, so an opt-out that
        // arrives after this line still wins.
        if !self.push_allowed(db, account_id, &category).await? {
            return Ok(Enqueued {
                notification_id,
                statements,
                devices: 0,
                inbox,
                announcement,
                skipped: Some(Skipped::PreferenceOff),
            });
        }

        let subscriptions = store::subscriptions_for_account(db, account_id).await?;
        if subscriptions.is_empty() {
            return Ok(Enqueued {
                notification_id,
                statements,
                devices: 0,
                inbox,
                announcement,
                skipped: Some(Skipped::NoSubscriptions),
            });
        }

        let outbox = Outbox::new(store::OUTBOX);
        statements.reserve(subscriptions.len());
        for subscription in &subscriptions {
            let job = SendJob {
                notification_id: notification_id.clone(),
                account_id: account_id.to_owned(),
                category: category.name.clone(),
                subscription_id: subscription.id.clone(),
                notification: notification.clone(),
            };
            let payload = serde_json::to_string(&job).map_err(|err| {
                NotifyError::Database(DbError::Execute(format!(
                    "notification does not serialise: {err}"
                )))
            })?;
            statements.push(outbox.enqueue_statement(&self.new_id(), TOPIC_SEND, &payload, &now));
        }
        Ok(Enqueued {
            devices: subscriptions.len(),
            notification_id,
            statements,
            inbox,
            announcement,
            skipped: None,
        })
    }

    /// [`Notifier::notify`] for a caller with no state change of its own:
    /// commits the outbox rows in their own batch and attempts immediate
    /// delivery. The event-bus entry point is this.
    ///
    /// # Errors
    ///
    /// As [`Notifier::notify`], plus [`NotifyError::Database`] when the
    /// batch fails.
    pub async fn notify_now(
        &self,
        db: &dyn Database,
        scope: &Scope,
        account_id: &str,
        category: &str,
        notification: Notification,
    ) -> Result<Enqueued, NotifyError> {
        let enqueued = self.notify(db, account_id, category, notification).await?;
        // `is_empty()` is about devices, and an account with none can
        // still have an inbox row waiting in this batch. Commit on the
        // statements, not on the device count.
        if !enqueued.statements().is_empty() {
            db.batch(enqueued.statements()).await?;
            self.announce(scope, &enqueued).await;
        }
        if !enqueued.is_empty() {
            self.deliver_now(scope);
        }
        Ok(enqueued)
    }

    /// Announces a just-committed inbox row to the account's room, when
    /// the venture wired `Realtime`.
    ///
    /// Call it **after** your batch commits, for the same reason
    /// [`Notifier::deliver_now`] says so: a client that received the event
    /// will read the inbox, and the row has to be there.
    /// [`Notifier::notify_now`] does it for you.
    ///
    /// Deliberately not part of the drain. The drain runs only when there
    /// are push rows, and the account this matters most to — no device, or
    /// push refused — has none. A failure is logged and swallowed: a live
    /// update is an optimisation over the client's own polling, and losing
    /// one must never fail the caller's write.
    pub async fn announce(&self, scope: &Scope, enqueued: &Enqueued) {
        let Some((room, payload)) = enqueued.announcement.as_ref() else {
            return;
        };
        let Some(realtime) = self.cell.get().and_then(|ctx| ctx.ports.realtime.clone()) else {
            return;
        };
        if let Err(err) = realtime.broadcast(room, payload).await {
            tracing::warn!(
                error = %err,
                request = %scope.request_id,
                "the inbox row is written; announcing it live failed"
            );
        }
    }

    /// Attempts immediate delivery on the request's `Defer`.
    ///
    /// Call it **after** your batch commits. Nothing is lost if the
    /// isolate dies first: the venture's scheduled drain picks the rows
    /// up on the next tick.
    pub fn deliver_now(&self, scope: &Scope) {
        let notifier = self.clone();
        let scope_for_drain = scope.clone();
        scope.defer.wait_until(Box::pin(async move {
            match notifier.drain(&scope_for_drain).await {
                Ok(report) if report.claimed > 0 => {
                    tracing::debug!(?report, "notifications drained");
                }
                Ok(_) => {}
                Err(err) => tracing::error!(error = %err, "notifications drain failed"),
            }
        }));
    }

    /// Delivers every due outbox row this drainer can lease, through the
    /// **mounted** module's ports.
    ///
    /// The whole delivery policy lives here: `Delivered` completes the
    /// row, `Unregistered` deletes the row **and** the subscription,
    /// `Rejected` and `NotConfigured` dead-letter it, and `Transient`
    /// retries with backoff — never before the `retry_after` the provider
    /// asked for — to a bound, then dead-letters.
    ///
    /// # Errors
    ///
    /// [`NotifyError`] when the module is not mounted, a port is missing,
    /// or the claim itself fails. A per-row failure never aborts the
    /// pass: it is counted in [`DrainReport::failed`] and the row keeps
    /// its lease until it expires.
    pub async fn drain(&self, scope: &Scope) -> Result<DrainReport, NotifyError> {
        self.drain_with(self.ctx()?, scope).await
    }

    /// [`Notifier::drain`] through the ports of the context handed in.
    ///
    /// This is what scheduled work must use. A cron invocation builds no
    /// router, so on a cold isolate there is no mounted context to drain
    /// through at all, and on a warm one draining through the parked
    /// context means using some earlier request's database handle.
    ///
    /// # Errors
    ///
    /// As [`Notifier::drain`], minus [`NotifyError::NotMounted`]: this
    /// entry point needs no mounted module.
    pub async fn drain_with(
        &self,
        ctx: &ModuleContext,
        scope: &Scope,
    ) -> Result<DrainReport, NotifyError> {
        let db = ctx
            .ports
            .db
            .clone()
            .ok_or(NotifyError::MissingPort("Database"))?;
        let push = ctx
            .ports
            .push
            .clone()
            .ok_or(NotifyError::MissingPort("Push"))?;

        let now = now_iso(ctx.ports.clock.as_ref());
        let lease_until = plus_secs(&now, LEASE_SECS);
        let records = Outbox::new(store::OUTBOX)
            .claim_due(&*db, &now, &lease_until, self.drain_batch(ctx))
            .await?;

        let mut report = DrainReport {
            claimed: records.len(),
            ..DrainReport::default()
        };
        let (db, push, now) = (&*db, &*push, now.as_str());
        let pending: Vec<_> = records
            .iter()
            .map(|record| async move {
                (
                    record.id.as_str(),
                    self.deliver_one(ctx, db, push, scope, record, now).await,
                )
            })
            .collect();
        let mut deliveries =
            futures_util::stream::iter(pending).buffer_unordered(self.drain_concurrency(ctx));
        while let Some((row, result)) = deliveries.next().await {
            match result {
                Ok(outcome) => report.record(outcome),
                // The row keeps its lease and becomes due again when that
                // expires. Abandoning the rest of the pass over one
                // transient error would leave every row behind it leased
                // and untouched for the whole lease.
                Err(error) => {
                    report.failed += 1;
                    tracing::error!(row = %row, %error, "delivering a notification failed");
                }
            }
        }
        Ok(report)
    }

    async fn deliver_one(
        &self,
        ctx: &ModuleContext,
        db: &dyn Database,
        push: &dyn Push,
        scope: &Scope,
        record: &OutboxRecord,
        now: &str,
    ) -> Result<Outcome, NotifyError> {
        let Ok(job) = serde_json::from_str::<SendJob>(&record.payload) else {
            tracing::error!(row = %record.id, "outbox row is not a notifications job");
            self.dead_letter(
                db,
                record,
                DeadLetterReason::Malformed,
                "outbox payload is not a notifications job",
                now,
            )
            .await?;
            return Ok(Outcome::DeadLettered);
        };

        let Some(subscription) = store::subscription_by_id(db, &job.subscription_id).await? else {
            // Signed out between the commit and the drain. Not a failure:
            // there is nothing left to deliver to.
            db.execute(&store::delete_outbox_statement(&record.id))
                .await?;
            return Ok(Outcome::Dropped);
        };

        // The device changed hands between the commit and the drain: a
        // sign-out deletes the row, but signing *another* account in on
        // the same device only re-homes it. Sending anyway would deliver
        // this account's notification to whoever holds the device now,
        // judged against this account's preferences — the row's account
        // and the job's account have to be the same account or there is
        // nothing here to deliver.
        if subscription.account_id != job.account_id {
            tracing::info!(
                row = %record.id,
                subscription = %subscription.id,
                "dropped a notification whose device now belongs to another account"
            );
            db.execute(&store::delete_outbox_statement(&record.id))
                .await?;
            return Ok(Outcome::Dropped);
        }

        // The check that counts. A preference read now, not when the row
        // was written, is what makes a late opt-out win.
        let Ok(category) = self.category(&job.category).cloned() else {
            // The venture stopped declaring the category between the commit
            // and the drain. Silence is the safe answer.
            db.execute(&store::delete_outbox_statement(&record.id))
                .await?;
            return Ok(Outcome::Dropped);
        };
        if !self.push_allowed(db, &job.account_id, &category).await? {
            db.execute(&store::delete_outbox_statement(&record.id))
                .await?;
            return Ok(Outcome::Dropped);
        }

        match push.send(&subscription.recipient, &job.notification).await {
            Ok(PushOutcome::Delivered { .. }) => {
                db.execute(&store::delete_outbox_statement(&record.id))
                    .await?;
                Ok(Outcome::Delivered)
            }
            Ok(PushOutcome::NotConfigured) => {
                self.dead_letter(
                    db,
                    record,
                    DeadLetterReason::NotConfigured,
                    &format!(
                        "no adapter is configured for {}: the module is mounted without the \
                         transport it needs",
                        subscription.transport
                    ),
                    now,
                )
                .await?;
                Ok(Outcome::DeadLettered)
            }
            // A delete instruction, not a failed send, and the only error
            // that is ever allowed to prune (ADR 0015).
            Err(PushError::Unregistered) => {
                self.prune(ctx, db, scope, record, &subscription).await?;
                Ok(Outcome::Pruned)
            }
            Err(PushError::Rejected(message)) => {
                self.dead_letter(db, record, DeadLetterReason::Rejected, &message, now)
                    .await?;
                Ok(Outcome::DeadLettered)
            }
            Err(PushError::Transient {
                message,
                retry_after,
            }) => {
                let attempts = record.attempts.saturating_add(1);
                if attempts >= self.max_attempts(ctx) {
                    self.dead_letter(
                        db,
                        record,
                        DeadLetterReason::AttemptsExhausted,
                        &format!("gave up after {attempts} attempts: {message}"),
                        now,
                    )
                    .await?;
                    Ok(Outcome::DeadLettered)
                } else {
                    let delay = backoff(attempts).max(retry_after.unwrap_or(Duration::ZERO));
                    let seconds = i64::try_from(delay.as_secs())
                        .unwrap_or_else(|_| i64::try_from(BACKOFF_MAX_SECS).unwrap_or(i64::MAX));
                    Outbox::new(store::OUTBOX)
                        .retry_later(db, &record.id, &plus_secs(now, seconds))
                        .await?;
                    Ok(Outcome::Retried)
                }
            }
        }
    }

    /// The provider says this recipient is gone: delete the subscription
    /// and the row in one batch, then say so on the bus.
    async fn prune(
        &self,
        ctx: &ModuleContext,
        db: &dyn Database,
        scope: &Scope,
        record: &OutboxRecord,
        subscription: &Subscription,
    ) -> Result<(), NotifyError> {
        db.batch(&[
            store::delete_subscription_statement(&subscription.id),
            store::delete_outbox_statement(&record.id),
        ])
        .await?;
        tracing::info!(
            subscription = %subscription.id,
            transport = %subscription.transport,
            "pruned a subscription the provider reported as gone"
        );
        ctx.events.emit_in(
            scope,
            EVENT_SUBSCRIPTION_PRUNED,
            json!({
                "subscription_id": subscription.id,
                "account_id": subscription.account_id,
                "transport": subscription.transport.as_str(),
            }),
        );
        Ok(())
    }

    /// Moves a row that will never succeed out of the work queue, in one
    /// batch so it can never be both queued and dead.
    async fn dead_letter(
        &self,
        db: &dyn Database,
        record: &OutboxRecord,
        reason: DeadLetterReason,
        last_error: &str,
        now: &str,
    ) -> Result<(), NotifyError> {
        tracing::error!(
            row = %record.id,
            reason = reason.as_str(),
            error = last_error,
            "notification dead-lettered"
        );
        // The attempt that just failed counts: `OutboxRecord::attempts` is
        // what had already failed before it.
        let attempts = record.attempts.saturating_add(1);
        // And the row's own enqueue time, so `created_at` and `failed_at`
        // are two facts rather than one written twice.
        let created_at = store::outbox_created_at(db, &record.id)
            .await?
            .unwrap_or_else(|| now.to_owned());
        db.batch(&[
            store::dead_letter_statement(
                record,
                &store::DeadLetter {
                    reason,
                    last_error,
                    attempts,
                    created_at: &created_at,
                    failed_at: now,
                },
            ),
            store::delete_outbox_statement(&record.id),
        ])
        .await?;
        Ok(())
    }
}

/// The notification as it will be stored and sent: `data` always carries
/// `category` and `notification_id`, and a badge count survives only for a
/// category that asked for one.
fn prepare(
    mut notification: Notification,
    category: &Category,
    notification_id: &str,
) -> Result<Notification, NotifyError> {
    let mut data = match notification.data {
        Value::Null => serde_json::Map::new(),
        Value::Object(map) => map,
        _ => return Err(NotifyError::InvalidData),
    };
    data.insert("category".to_owned(), json!(category.name));
    data.insert("notification_id".to_owned(), json!(notification_id));
    notification.data = Value::Object(data);

    // No badge counts by default: a number that is wrong is worse than no
    // number, and only the venture knows whether it can count.
    if !category.badge {
        notification.badge = None;
    }
    Ok(notification)
}

/// The room one account's live inbox events go to. A client joins
/// `notifications:<account_id>` when the app opens.
///
/// Nothing is published here that the inbox row does not also hold, so a
/// client that missed the event loses nothing by reading the list.
pub const INBOX_ROOM_PREFIX: &str = "notifications:";

/// Exponential backoff on the number of failed attempts, capped.
fn backoff(attempts: i64) -> Duration {
    let exponent = u32::try_from(attempts.saturating_sub(1).max(0)).unwrap_or(u32::MAX);
    let secs = BACKOFF_BASE_SECS
        .checked_shl(exponent.min(16))
        .unwrap_or(BACKOFF_MAX_SECS)
        .min(BACKOFF_MAX_SECS);
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_stops_at_an_hour() {
        assert_eq!(backoff(1), Duration::from_secs(30));
        assert_eq!(backoff(2), Duration::from_secs(60));
        assert_eq!(backoff(3), Duration::from_secs(120));
        assert_eq!(backoff(9), Duration::from_secs(3_600));
        assert_eq!(backoff(64), Duration::from_secs(3_600));
    }

    #[test]
    fn data_always_carries_the_category_and_the_notification_id() {
        let category = Category::new("booking");
        let mut notification = Notification::new("Booked", "See you Tuesday");
        notification.data = json!({ "booking_id": "b-1" });
        let prepared = prepare(notification, &category, "01JNOTIF").expect("prepared");
        assert_eq!(prepared.data["booking_id"], "b-1");
        assert_eq!(prepared.data["category"], "booking");
        assert_eq!(prepared.data["notification_id"], "01JNOTIF");
    }

    #[test]
    fn a_badge_survives_only_for_a_category_that_asked_for_one() {
        let mut notification = Notification::new("a", "b");
        notification.badge = Some(7);
        let plain = prepare(notification.clone(), &Category::new("booking"), "id").expect("plain");
        assert_eq!(plain.badge, None, "no badge counts by default");
        let opted =
            prepare(notification, &Category::new("booking").badge(true), "id").expect("opted");
        assert_eq!(opted.badge, Some(7));
    }

    #[test]
    fn a_non_object_data_is_refused_rather_than_silently_replaced() {
        let mut notification = Notification::new("a", "b");
        notification.data = json!(["not", "an", "object"]);
        assert!(matches!(
            prepare(notification, &Category::new("booking"), "id"),
            Err(NotifyError::InvalidData)
        ));
    }

    #[test]
    fn a_job_payload_carries_no_recipient() {
        // The regression this pins: a payload with the token in it would
        // put credential material into every export and diagnostic.
        let job = SendJob {
            notification_id: "n".to_owned(),
            account_id: "a".to_owned(),
            category: "booking".to_owned(),
            subscription_id: "s".to_owned(),
            notification: Notification::new("a", "b"),
        };
        let json = serde_json::to_string(&job).expect("serialises");
        assert!(!json.contains("device_token"), "{json}");
        assert!(!json.contains("endpoint"), "{json}");
        assert!(!json.contains("recipient"), "{json}");
    }
}
