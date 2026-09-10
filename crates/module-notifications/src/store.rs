//! Every statement this module runs, in one place (issue #182).
//!
//! Rows are read back through the `Database` port's small owned row model,
//! so nothing engine-specific leaks past this file. Booleans are read as
//! `i64` and compared against zero rather than through `bool`: the column
//! is `INTEGER`, and which sea-query integer variant an adapter hands back
//! is the adapter's business.

use cratefield_core::{Database, DbError, Recipient, Row, Statement};
use sea_query::{Alias, Expr, Order, Query};
use serde::{Deserialize, Serialize};

/// The subscriptions table. Must match `0001_init.sql` and
/// [`crate::Notifications::tables`].
pub(crate) const SUBSCRIPTIONS: &str = "notifications_subscriptions";
/// The per-account per-category preferences table.
pub(crate) const PREFERENCES: &str = "notifications_preferences";
/// The core [`cratefield_core::Outbox`] table this module owns.
pub(crate) const OUTBOX: &str = "notifications_outbox";
/// The terminal state core's outbox does not have (ADR 0016).
pub(crate) const DEAD_LETTERS: &str = "notifications_dead_letters";

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// A row that cannot be decoded is a bug or a hand-edited database, not a
/// caller's problem: it becomes a query error and the caller answers 500.
fn corrupt(table: &str, id: &str, what: &str) -> DbError {
    DbError::Query(format!("{table} row {id} has no usable {what}"))
}

/// The transport a subscription is reached over.
///
/// Stored as the `TEXT` + `CHECK` column the migration declares — SQLite
/// has no `ENUM` — and accepted on the wire in the same three spellings.
/// Note that the JSON tag of the port's own [`Recipient::WebPush`] is
/// `web_push`: this is the *column's* vocabulary, and the column and the
/// recipient are checked against each other on every write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Apns,
    Fcm,
    Webpush,
}

impl Transport {
    /// The value stored in `notifications_subscriptions.transport`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Apns => "apns",
            Transport::Fcm => "fcm",
            Transport::Webpush => "webpush",
        }
    }

    /// The transport a recipient is reached over. Exhaustive by
    /// construction: a new [`Recipient`] variant fails to compile here.
    #[must_use]
    pub fn of(recipient: &Recipient) -> Self {
        match recipient {
            Recipient::Apns { .. } => Transport::Apns,
            Recipient::Fcm { .. } => Transport::Fcm,
            Recipient::WebPush { .. } => Transport::Webpush,
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "apns" => Some(Transport::Apns),
            "fcm" => Some(Transport::Fcm),
            "webpush" => Some(Transport::Webpush),
            _ => None,
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The canonical string a [`Recipient`] is hashed from: the token for the
/// two token transports, and `endpoint` plus `p256dh` for Web Push, which
/// is what identifies one browser subscription (the `auth` secret is not
/// an identifier and never enters the digest).
fn canonical(recipient: &Recipient) -> String {
    match recipient {
        Recipient::Apns { device_token } => format!("apns:{device_token}"),
        Recipient::Fcm { registration_token } => format!("fcm:{registration_token}"),
        Recipient::WebPush {
            endpoint, p256dh, ..
        } => format!("webpush:{endpoint}\u{0}{p256dh}"),
    }
}

/// SHA-256 of the canonical recipient, lowercase hex. Re-registration on
/// app launch is an upsert on this, so a device never accumulates rows,
/// and the same device signing into another account re-homes cleanly.
#[must_use]
pub(crate) fn recipient_hash(recipient: &Recipient) -> String {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;

    let digest = Sha256::digest(canonical(recipient).as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// One row of `notifications_subscriptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Subscription {
    pub id: String,
    pub account_id: String,
    pub transport: Transport,
    pub recipient: Recipient,
    pub app_id: Option<String>,
    pub app_version: Option<String>,
    pub created_at: String,
    pub last_seen_at: String,
}

const SUBSCRIPTION_COLUMNS: [&str; 8] = [
    "id",
    "account_id",
    "transport",
    "recipient_json",
    "app_id",
    "app_version",
    "created_at",
    "last_seen_at",
];

fn read_subscription(row: &Row) -> Result<Subscription, DbError> {
    let id = row
        .get::<String>("id")
        .ok_or_else(|| corrupt(SUBSCRIPTIONS, "?", "id"))?;
    let raw = row
        .get::<String>("recipient_json")
        .ok_or_else(|| corrupt(SUBSCRIPTIONS, &id, "recipient"))?;
    let recipient: Recipient = serde_json::from_str(&raw)
        .map_err(|_| corrupt(SUBSCRIPTIONS, &id, "recipient (not the port's JSON form)"))?;
    let transport = row
        .get::<String>("transport")
        .as_deref()
        .and_then(Transport::parse)
        .ok_or_else(|| corrupt(SUBSCRIPTIONS, &id, "transport"))?;
    Ok(Subscription {
        account_id: row
            .get::<String>("account_id")
            .ok_or_else(|| corrupt(SUBSCRIPTIONS, &id, "account"))?,
        transport,
        recipient,
        app_id: row.get::<Option<String>>("app_id").flatten(),
        app_version: row.get::<Option<String>>("app_version").flatten(),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
        last_seen_at: row.get::<String>("last_seen_at").unwrap_or_default(),
        id,
    })
}

fn select_subscriptions() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns(SUBSCRIPTION_COLUMNS.map(iden))
        .from(iden(SUBSCRIPTIONS));
    select
}

/// What a registration writes.
pub(crate) struct NewSubscription<'a> {
    pub id: &'a str,
    pub account_id: &'a str,
    pub recipient: &'a Recipient,
    pub app_id: Option<&'a str>,
    pub app_version: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub now: &'a str,
    /// The start of the window `rehome_limit` counts over.
    pub rehome_cutoff: &'a str,
    /// How many devices this account may take over from another account
    /// inside that window. A device token is not an authenticator, so an
    /// unbounded re-home is a mass-silencing primitive for anyone holding
    /// a log full of them (see [`Upserted::RehomeRefused`]).
    pub rehome_limit: usize,
}

/// What a registration did to the row it identified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Upserted {
    /// A device this venture had never seen.
    Created(String),
    /// The caller's own device, re-registering — an app launch.
    Refreshed(String),
    /// The row changed hands: this device was another account's and is
    /// now this caller's. The previous owner stops receiving on it, and
    /// its queued notifications are dropped rather than delivered to the
    /// new owner (`deliver_one` re-checks the pairing).
    Rehomed {
        id: String,
        previous_account_id: String,
    },
    /// The row is another account's and this caller has spent its re-home
    /// budget for the window. Refused rather than served: a caller taking
    /// over device after device is not a person signing in on a shared
    /// tablet.
    RehomeRefused,
}

/// The `(id, account_id)` of the row a recipient identifies, if any.
async fn owner_of(
    db: &dyn Database,
    transport: Transport,
    hash: &str,
) -> Result<Option<(String, String)>, DbError> {
    let mut select = Query::select();
    select
        .columns([iden("id"), iden("account_id")])
        .from(iden(SUBSCRIPTIONS))
        .and_where(Expr::col(iden("transport")).eq(transport.as_str()))
        .and_where(Expr::col(iden("recipient_hash")).eq(hash));
    let Some(row) = db
        .query(&Statement::render(&select))
        .await?
        .first()
        .cloned()
    else {
        return Ok(None);
    };
    let id = row
        .get::<String>("id")
        .ok_or_else(|| corrupt(SUBSCRIPTIONS, "?", "id"))?;
    let account_id = row
        .get::<String>("account_id")
        .ok_or_else(|| corrupt(SUBSCRIPTIONS, &id, "account"))?;
    Ok(Some((id, account_id)))
}

/// How many devices `account_id` has taken over from another account since
/// `cutoff`, counted up to `limit` and no further.
async fn rehomes_since(
    db: &dyn Database,
    account_id: &str,
    cutoff: &str,
    limit: usize,
) -> Result<usize, DbError> {
    // Deliberately not `COUNT(*)`: the answer is only ever compared
    // against a small limit, and a bounded row count needs no aggregate
    // and no result-column alias to stay portable (ADR 0004).
    let mut select = Query::select();
    select
        .column(iden("id"))
        .from(iden(SUBSCRIPTIONS))
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .and_where(Expr::col(iden("rehomed_at")).gt(cutoff))
        .limit(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1));
    Ok(db.query(&Statement::render(&select)).await?.rows.len())
}

/// The `UPDATE` a registration applies to the row it found. `rehomed_from`
/// is the account the row is being taken from, which both guards the write
/// and stamps `rehomed_at`; `None` is the caller refreshing its own row.
fn refresh_statement(
    id: &str,
    new: &NewSubscription<'_>,
    recipient_json: &str,
    rehomed_from: Option<&str>,
) -> Statement {
    let mut update = Query::update();
    update
        .table(iden(SUBSCRIPTIONS))
        .value(iden("account_id"), new.account_id)
        .value(iden("recipient_json"), recipient_json)
        .value(iden("app_id"), new.app_id)
        .value(iden("app_version"), new.app_version)
        .value(iden("user_agent"), new.user_agent)
        .value(iden("last_seen_at"), new.now)
        .and_where(Expr::col(iden("id")).eq(id));
    if let Some(previous) = rehomed_from {
        update
            .value(iden("rehomed_at"), new.now)
            // Guarded on the owner the budget was checked against, so a
            // re-home that raced another one cannot land unchecked.
            .and_where(Expr::col(iden("account_id")).eq(previous));
    }
    Statement::render(&update)
}

/// Registers a device, or re-registers one already known.
///
/// The identity is `(transport, recipient_hash)`, so re-registering on app
/// launch updates the row it already has, and a shared device that signs
/// into a second account moves rather than delivering that account's
/// notifications to both.
///
/// Both writes are safe under a client that registers twice at once (a
/// double-tap, a retry): the `INSERT` is only reached when no row was
/// found, and a lost race is answered by taking the row the winner wrote
/// rather than by returning the unique-key violation as a 500. The
/// engine's own constraint, not the read, is what decides.
///
/// # Errors
///
/// [`DbError`] when a read or write fails for any reason other than losing
/// that race.
pub(crate) async fn upsert_subscription(
    db: &dyn Database,
    new: &NewSubscription<'_>,
) -> Result<Upserted, DbError> {
    let transport = Transport::of(new.recipient);
    let hash = recipient_hash(new.recipient);
    let recipient_json = serde_json::to_string(new.recipient)
        .map_err(|err| DbError::Execute(format!("recipient does not serialise: {err}")))?;

    if let Some(existing) = owner_of(db, transport, &hash).await? {
        return take_over(db, new, &recipient_json, existing).await;
    }

    let mut insert = Query::insert();
    insert
        .into_table(iden(SUBSCRIPTIONS))
        .columns([
            "id",
            "account_id",
            "transport",
            "recipient_json",
            "recipient_hash",
            "app_id",
            "app_version",
            "user_agent",
            "created_at",
            "last_seen_at",
        ])
        .values_panic([
            new.id.into(),
            new.account_id.into(),
            transport.as_str().into(),
            recipient_json.as_str().into(),
            hash.as_str().into(),
            new.app_id.into(),
            new.app_version.into(),
            new.user_agent.into(),
            new.now.into(),
            new.now.into(),
        ]);
    match db.execute(&Statement::render(&insert)).await {
        Ok(_) => Ok(Upserted::Created(new.id.to_owned())),
        Err(err) => match owner_of(db, transport, &hash).await? {
            // A concurrent registration of the same device won the unique
            // key between the read and this insert. Update its row.
            Some(existing) => take_over(db, new, &recipient_json, existing).await,
            None => Err(err),
        },
    }
}

/// The write for a row that already exists: a refresh when it is the
/// caller's own, a budgeted re-home when it is not.
async fn take_over(
    db: &dyn Database,
    new: &NewSubscription<'_>,
    recipient_json: &str,
    existing: (String, String),
) -> Result<Upserted, DbError> {
    let (id, owner) = existing;
    if owner == new.account_id {
        db.execute(&refresh_statement(&id, new, recipient_json, None))
            .await?;
        return Ok(Upserted::Refreshed(id));
    }

    // The budget bounds an attack; it is not a lock. Two simultaneous
    // re-homes of the same row can both read a count below the limit, and
    // one extra take-over does not change what the limit is for.
    if rehomes_since(db, new.account_id, new.rehome_cutoff, new.rehome_limit).await?
        >= new.rehome_limit
    {
        return Ok(Upserted::RehomeRefused);
    }

    let affected = db
        .execute(&refresh_statement(&id, new, recipient_json, Some(&owner)))
        .await?;
    if affected == 0 {
        // The row moved between the read and the guarded write. If it
        // moved to this caller, this registration is a refresh after all;
        // if it moved to a third account, this caller does not get to
        // take it without a fresh budget check.
        return match owner_of(
            db,
            Transport::of(new.recipient),
            &recipient_hash(new.recipient),
        )
        .await?
        {
            Some((id, now_owner)) if now_owner == new.account_id => Ok(Upserted::Refreshed(id)),
            _ => Ok(Upserted::RehomeRefused),
        };
    }
    Ok(Upserted::Rehomed {
        id,
        previous_account_id: owner,
    })
}

/// One account's subscriptions, oldest first.
///
/// # Errors
///
/// [`DbError`] when the read fails or a row cannot be decoded.
pub(crate) async fn subscriptions_for_account(
    db: &dyn Database,
    account_id: &str,
) -> Result<Vec<Subscription>, DbError> {
    let mut select = select_subscriptions();
    select
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .order_by(iden("created_at"), Order::Asc)
        .order_by(iden("id"), Order::Asc);
    db.query(&Statement::render(&select))
        .await?
        .rows
        .iter()
        .map(read_subscription)
        .collect()
}

/// One subscription by id, whoever owns it.
///
/// # Errors
///
/// [`DbError`] when the read fails or the row cannot be decoded.
pub(crate) async fn subscription_by_id(
    db: &dyn Database,
    id: &str,
) -> Result<Option<Subscription>, DbError> {
    let mut select = select_subscriptions();
    select.and_where(Expr::col(iden("id")).eq(id));
    match db.query(&Statement::render(&select)).await?.first() {
        Some(row) => read_subscription(row).map(Some),
        None => Ok(None),
    }
}

/// Deletes a subscription, but only the named account's.
///
/// Scoping the `DELETE` itself is what makes another account's id a `404`
/// rather than a `403`: the route never learns whether the row exists.
///
/// # Errors
///
/// [`DbError`] when the delete fails.
pub(crate) async fn delete_subscription_for_account(
    db: &dyn Database,
    id: &str,
    account_id: &str,
) -> Result<bool, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(SUBSCRIPTIONS))
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("account_id")).eq(account_id));
    Ok(db.execute(&Statement::render(&delete)).await? == 1)
}

/// The unconditional delete the drain batches with the outbox row when the
/// provider says a recipient is gone.
#[must_use]
pub(crate) fn delete_subscription_statement(id: &str) -> Statement {
    let mut delete = Query::delete();
    delete
        .from_table(iden(SUBSCRIPTIONS))
        .and_where(Expr::col(iden("id")).eq(id));
    Statement::render(&delete)
}

// ---------------------------------------------------------------------------
// Preferences

/// The three channel switches, as stored. This child reads only `push`;
/// `in_app` and `email` are written and read back untouched so the inbox
/// (#187) and email (#189) children need no migration of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Channels {
    pub push: bool,
    pub in_app: bool,
    pub email: bool,
}

impl Channels {
    pub(crate) fn all(enabled: bool) -> Self {
        Self {
            push: enabled,
            in_app: enabled,
            email: enabled,
        }
    }
}

fn flag(row: &Row, column: &str) -> bool {
    row.get::<i64>(column).unwrap_or(0) != 0
}

/// Every stored preference row for one account, by category. A category
/// with no row is absent: the caller falls back to its declared default.
///
/// # Errors
///
/// [`DbError`] when the read fails, or when a row's category will not
/// decode — the same refusal [`read_subscription`] makes, and for a
/// stronger reason. Skipping the row would hand the caller the category's
/// *default* for a row that exists precisely because the account chose
/// something else: an explicit opt-out silently becomes an opt-in, and
/// `GET /preferences` reports it as on. Sending to someone who switched a
/// category off is the worse failure, so this answers 500 instead.
pub(crate) async fn preferences_for_account(
    db: &dyn Database,
    account_id: &str,
) -> Result<Vec<(String, Channels)>, DbError> {
    let mut select = Query::select();
    select
        .columns([
            iden("category"),
            iden("push"),
            iden("in_app"),
            iden("email"),
        ])
        .from(iden(PREFERENCES))
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .order_by(iden("category"), Order::Asc);
    db.query(&Statement::render(&select))
        .await?
        .rows
        .iter()
        .map(|row| {
            let category = row
                .get::<String>("category")
                .ok_or_else(|| corrupt(PREFERENCES, account_id, "category"))?;
            Ok((
                category,
                Channels {
                    push: flag(row, "push"),
                    in_app: flag(row, "in_app"),
                    email: flag(row, "email"),
                },
            ))
        })
        .collect()
}

/// One account's stored preference for one category, or `None` when it has
/// never expressed one.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub(crate) async fn preference(
    db: &dyn Database,
    account_id: &str,
    category: &str,
) -> Result<Option<Channels>, DbError> {
    let mut select = Query::select();
    select
        .columns([iden("push"), iden("in_app"), iden("email")])
        .from(iden(PREFERENCES))
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .and_where(Expr::col(iden("category")).eq(category));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(|row| Channels {
            push: flag(row, "push"),
            in_app: flag(row, "in_app"),
            email: flag(row, "email"),
        }))
}

/// The write for one category: an `UPDATE` when the account already has a
/// row, an `INSERT` when it does not. Deliberately not `ON CONFLICT`,
/// which is one more dialect difference than the portable subset wants
/// (ADR 0004); the caller batches these, so a whole `PUT` is one unit of
/// work either way.
#[must_use]
pub(crate) fn write_preference_statement(
    account_id: &str,
    category: &str,
    channels: Channels,
    exists: bool,
    now: &str,
) -> Statement {
    let bit = |on: bool| i64::from(on);
    if exists {
        let mut update = Query::update();
        update
            .table(iden(PREFERENCES))
            .value(iden("push"), bit(channels.push))
            .value(iden("in_app"), bit(channels.in_app))
            .value(iden("email"), bit(channels.email))
            .value(iden("updated_at"), now)
            .and_where(Expr::col(iden("account_id")).eq(account_id))
            .and_where(Expr::col(iden("category")).eq(category));
        return Statement::render(&update);
    }
    let mut insert = Query::insert();
    insert
        .into_table(iden(PREFERENCES))
        .columns([
            "account_id",
            "category",
            "push",
            "in_app",
            "email",
            "updated_at",
        ])
        .values_panic([
            account_id.into(),
            category.into(),
            bit(channels.push).into(),
            bit(channels.in_app).into(),
            bit(channels.email).into(),
            now.into(),
        ]);
    Statement::render(&insert)
}

// ---------------------------------------------------------------------------
// Outbox and dead letters

/// The batch-friendly form of [`cratefield_core::Outbox::complete`], which
/// executes on its own. The drain needs the delete to commit in the *same*
/// unit of work as a dead-letter insert or a subscription prune, or a
/// failure between the two leaves work that can never finish.
#[must_use]
pub(crate) fn delete_outbox_statement(id: &str) -> Statement {
    let mut delete = Query::delete();
    delete
        .from_table(iden(OUTBOX))
        .and_where(Expr::col(iden("id")).eq(id));
    Statement::render(&delete)
}

/// Why a notification will never be delivered. The set matches the
/// `CHECK` constraint in `0001_init.sql`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadLetterReason {
    /// The provider refused the request and will refuse it again.
    Rejected,
    /// No adapter serves this recipient's transport: the module is
    /// mounted without the transport it needs. A distinct reason so ops
    /// can tell "the payload is wrong" from "you forgot the keys".
    NotConfigured,
    /// Retried to the bound and still failing.
    AttemptsExhausted,
    /// The outbox payload is not a job this module wrote.
    Malformed,
}

impl DeadLetterReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DeadLetterReason::Rejected => "rejected",
            DeadLetterReason::NotConfigured => "not_configured",
            DeadLetterReason::AttemptsExhausted => "attempts_exhausted",
            DeadLetterReason::Malformed => "malformed",
        }
    }
}

/// When the outbox row was enqueued, so a dead letter can carry the
/// moment the notification was created rather than the moment it was
/// abandoned. `None` when the row is already gone.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub(crate) async fn outbox_created_at(
    db: &dyn Database,
    id: &str,
) -> Result<Option<String>, DbError> {
    let mut select = Query::select();
    select
        .column(iden("created_at"))
        .from(iden(OUTBOX))
        .and_where(Expr::col(iden("id")).eq(id));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .and_then(|row| row.get::<String>("created_at")))
}

/// What a dead letter records about the delivery that gave up.
pub(crate) struct DeadLetter<'a> {
    pub reason: DeadLetterReason,
    pub last_error: &'a str,
    /// Attempts **made**, including the one that just failed — the same
    /// number the `last_error` prose quotes. `OutboxRecord::attempts` is
    /// the count *before* this attempt, and storing that while the message
    /// said "gave up after N attempts" left every dead letter disagreeing
    /// with itself by one.
    pub attempts: i64,
    /// When the notification was enqueued (the outbox row's own
    /// `created_at`), not when it was abandoned.
    pub created_at: &'a str,
    /// When it was abandoned.
    pub failed_at: &'a str,
}

/// Moves one outbox record into the dead-letter table.
#[must_use]
pub(crate) fn dead_letter_statement(
    record: &cratefield_core::OutboxRecord,
    dead: &DeadLetter<'_>,
) -> Statement {
    let mut insert = Query::insert();
    insert
        .into_table(iden(DEAD_LETTERS))
        .columns([
            "id",
            "topic",
            "payload",
            "attempts",
            "reason",
            "last_error",
            "created_at",
            "failed_at",
        ])
        .values_panic([
            record.id.as_str().into(),
            record.topic.as_str().into(),
            record.payload.as_str().into(),
            dead.attempts.into(),
            dead.reason.as_str().into(),
            dead.last_error.into(),
            dead.created_at.into(),
            dead.failed_at.into(),
        ]);
    Statement::render(&insert)
}
