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
    Clock, Database, DbError, IdGen, ModuleConfig, ModuleContext, Notification, Outbox,
    OutboxRecord, Push, PushError, PushOutcome, Scope, Statement, SystemClock, UlidIdGen,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

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

/// The first retry delay; each further attempt doubles it.
const BACKOFF_BASE_SECS: u64 = 30;
/// The ceiling on the doubling.
const BACKOFF_MAX_SECS: u64 = 3_600;
/// How long a claimed row stays leased to one drainer.
const LEASE_SECS: i64 = 300;

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
    #[must_use]
    pub fn len(&self) -> usize {
        self.statements.len()
    }

    /// Whether nothing will be sent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    /// Why nothing will be sent, when nothing will be.
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
    /// the row was written, or the device signed out.
    pub dropped: usize,
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
    pub(crate) settings: Settings,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier")
            .field("mounted", &self.cell.get().is_some())
            .field("categories", &self.settings.categories.len())
            .finish()
    }
}

impl Notifier {
    fn ctx(&self) -> Result<&Arc<ModuleContext>, NotifyError> {
        self.cell.get().ok_or(NotifyError::NotMounted)
    }

    /// The declared category, or an error naming the unknown one.
    fn category(&self, name: &str) -> Result<&Category, NotifyError> {
        self.settings
            .categories
            .iter()
            .find(|category| category.name == name)
            .ok_or_else(|| NotifyError::UnknownCategory(name.to_owned()))
    }

    fn now(&self) -> String {
        let now = match self.cell.get().and_then(|ctx| ctx.ports.clock.clone()) {
            Some(clock) => clock.now(),
            None => SystemClock.now(),
        };
        iso(now)
    }

    fn new_id(&self) -> String {
        match self.cell.get().and_then(|ctx| ctx.ports.id_gen.clone()) {
            Some(id_gen) => id_gen.ulid(),
            None => UlidIdGen.ulid(),
        }
    }

    /// The mounted context, once `Harness::router` has built the module's
    /// router. `None` before that.
    #[must_use]
    pub fn context(&self) -> Option<&Arc<ModuleContext>> {
        self.cell.get()
    }

    /// How many attempts a transient failure gets. The builder's value
    /// unless the deployment overrides it.
    fn max_attempts(&self) -> i64 {
        let configured = self.cell.get().map_or(self.settings.max_attempts, |ctx| {
            ModuleConfig::new(crate::MODULE_NAME, &*ctx.config)
                .get_u32("MAX_ATTEMPTS", self.settings.max_attempts)
        });
        i64::from(configured.max(1))
    }

    /// How many rows one drain pass leases.
    fn drain_batch(&self) -> u64 {
        let configured = self.cell.get().map_or(self.settings.drain_batch, |ctx| {
            u64::from(ModuleConfig::new(crate::MODULE_NAME, &*ctx.config).get_u32(
                "DRAIN_BATCH",
                u32::try_from(self.settings.drain_batch).unwrap_or(u32::MAX),
            ))
        });
        configured.max(1)
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

        // Cheap skip, not the check that counts: the drain re-reads the
        // preference immediately before sending, so an opt-out that
        // arrives after this line still wins.
        if !self.push_allowed(db, account_id, &category).await? {
            return Ok(Enqueued {
                notification_id,
                statements: Vec::new(),
                skipped: Some(Skipped::PreferenceOff),
            });
        }

        let subscriptions = store::subscriptions_for_account(db, account_id).await?;
        if subscriptions.is_empty() {
            return Ok(Enqueued {
                notification_id,
                statements: Vec::new(),
                skipped: Some(Skipped::NoSubscriptions),
            });
        }

        let notification = prepare(notification, &category, &notification_id)?;
        let now = self.now();
        let outbox = Outbox::new(store::OUTBOX);
        let mut statements = Vec::with_capacity(subscriptions.len());
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
            notification_id,
            statements,
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
        if !enqueued.is_empty() {
            db.batch(enqueued.statements()).await?;
            self.deliver_now(scope);
        }
        Ok(enqueued)
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

    /// Delivers every due outbox row this drainer can lease.
    ///
    /// The whole delivery policy lives here: `Delivered` completes the
    /// row, `Unregistered` deletes the row **and** the subscription,
    /// `Rejected` and `NotConfigured` dead-letter it, and `Transient`
    /// retries with backoff — never before the `retry_after` the provider
    /// asked for — to a bound, then dead-letters.
    ///
    /// # Errors
    ///
    /// [`NotifyError`] when a port is missing or a database call fails.
    /// A per-row failure never aborts the pass.
    pub async fn drain(&self, scope: &Scope) -> Result<DrainReport, NotifyError> {
        let ctx = self.ctx()?;
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

        let now = self.now();
        let lease_until = iso(parse(&now).saturating_add(time::Duration::seconds(LEASE_SECS)));
        let outbox = Outbox::new(store::OUTBOX);
        let records = outbox
            .claim_due(&*db, &now, &lease_until, self.drain_batch())
            .await?;

        let mut report = DrainReport {
            claimed: records.len(),
            ..DrainReport::default()
        };
        for record in &records {
            self.deliver_one(&*db, &*push, scope, record, &now, &mut report)
                .await?;
        }
        Ok(report)
    }

    async fn deliver_one(
        &self,
        db: &dyn Database,
        push: &dyn Push,
        scope: &Scope,
        record: &OutboxRecord,
        now: &str,
        report: &mut DrainReport,
    ) -> Result<(), NotifyError> {
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
            report.dead_lettered += 1;
            return Ok(());
        };

        let Some(subscription) = store::subscription_by_id(db, &job.subscription_id).await? else {
            // Signed out between the commit and the drain. Not a failure:
            // there is nothing left to deliver to.
            db.execute(&store::delete_outbox_statement(&record.id))
                .await?;
            report.dropped += 1;
            return Ok(());
        };

        // The check that counts. A preference read now, not when the row
        // was written, is what makes a late opt-out win.
        let Ok(category) = self.category(&job.category).cloned() else {
            // The venture stopped declaring the category between the commit
            // and the drain. Silence is the safe answer.
            db.execute(&store::delete_outbox_statement(&record.id))
                .await?;
            report.dropped += 1;
            return Ok(());
        };
        if !self.push_allowed(db, &job.account_id, &category).await? {
            db.execute(&store::delete_outbox_statement(&record.id))
                .await?;
            report.dropped += 1;
            return Ok(());
        }

        match push.send(&subscription.recipient, &job.notification).await {
            Ok(PushOutcome::Delivered { .. }) => {
                db.execute(&store::delete_outbox_statement(&record.id))
                    .await?;
                report.delivered += 1;
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
                report.dead_lettered += 1;
            }
            // A delete instruction, not a failed send, and the only error
            // that is ever allowed to prune (ADR 0015).
            Err(PushError::Unregistered) => {
                self.prune(db, scope, record, &subscription).await?;
                report.pruned += 1;
            }
            Err(PushError::Rejected(message)) => {
                self.dead_letter(db, record, DeadLetterReason::Rejected, &message, now)
                    .await?;
                report.dead_lettered += 1;
            }
            Err(PushError::Transient {
                message,
                retry_after,
            }) => {
                let attempts = record.attempts.saturating_add(1);
                if attempts >= self.max_attempts() {
                    self.dead_letter(
                        db,
                        record,
                        DeadLetterReason::AttemptsExhausted,
                        &format!("gave up after {attempts} attempts: {message}"),
                        now,
                    )
                    .await?;
                    report.dead_lettered += 1;
                } else {
                    let delay = backoff(attempts).max(retry_after.unwrap_or(Duration::ZERO));
                    let next = iso(parse(now).saturating_add(
                        time::Duration::try_from(delay).unwrap_or(time::Duration::seconds(
                            i64::try_from(BACKOFF_MAX_SECS).unwrap_or(i64::MAX),
                        )),
                    ));
                    Outbox::new(store::OUTBOX)
                        .retry_later(db, &record.id, &next)
                        .await?;
                    report.retried += 1;
                }
            }
        }
        Ok(())
    }

    /// The provider says this recipient is gone: delete the subscription
    /// and the row in one batch, then say so on the bus.
    async fn prune(
        &self,
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
        if let Some(ctx) = self.cell.get() {
            ctx.events.emit_in(
                scope,
                EVENT_SUBSCRIPTION_PRUNED,
                json!({
                    "subscription_id": subscription.id,
                    "account_id": subscription.account_id,
                    "transport": subscription.transport.as_str(),
                }),
            );
        }
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
        db.batch(&[
            store::dead_letter_statement(record, reason, last_error, now),
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

/// Exponential backoff on the number of failed attempts, capped.
fn backoff(attempts: i64) -> Duration {
    let exponent = u32::try_from(attempts.saturating_sub(1).max(0)).unwrap_or(u32::MAX);
    let secs = BACKOFF_BASE_SECS
        .checked_shl(exponent.min(16))
        .unwrap_or(BACKOFF_MAX_SECS)
        .min(BACKOFF_MAX_SECS);
    Duration::from_secs(secs)
}

fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn parse(iso: &str) -> OffsetDateTime {
    OffsetDateTime::parse(iso, &Rfc3339).unwrap_or(OffsetDateTime::UNIX_EPOCH)
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
