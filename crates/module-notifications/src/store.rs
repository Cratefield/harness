//! Every statement this module runs, in one place (issue #182).
//!
//! Rows are read back through the `Database` port's small owned row model,
//! so nothing engine-specific leaks past this file. Booleans are read as
//! `i64` and compared against zero rather than through `bool`: the column
//! is `INTEGER`, and which sea-query integer variant an adapter hands back
//! is the adapter's business.

use cratefield_core::{Database, DbError, Recipient, Row, Statement};
use cratefield_i18n::LanguageIdentifier;
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
/// The per-account in-app inbox (#187).
pub(crate) const INBOX: &str = "notifications_inbox";
/// Where an account's verified email address lives (#189).
pub(crate) const EMAIL_TARGETS: &str = "notifications_email_targets";
/// One row per mail actually sent, for the per-category cooldown (#189).
pub(crate) const EMAIL_SENDS: &str = "notifications_email_sends";
/// One account's own language, for the inbox and the mailbox (#190).
pub(crate) const LOCALES: &str = "notifications_locales";

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
    /// The device's own language, if it said (#190). Parsed on the way
    /// out as well as on the way in: the column can only have been
    /// written through [`cratefield_i18n::parse_locale`], and reading it
    /// back through the same door means a hand-edited database cannot put
    /// arbitrary text into a rendered page either.
    pub locale: Option<LanguageIdentifier>,
    pub created_at: String,
    pub last_seen_at: String,
}

const SUBSCRIPTION_COLUMNS: [&str; 9] = [
    "id",
    "account_id",
    "transport",
    "recipient_json",
    "app_id",
    "app_version",
    "locale",
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
        locale: row
            .get::<String>("locale")
            .as_deref()
            .and_then(cratefield_i18n::parse_locale),
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
    /// The device's language, already parsed and canonicalised — `None`
    /// when the client said nothing usable. On a re-registration `None`
    /// **keeps** whatever the row had: an app launch that omits the field
    /// is not the device saying it has no language.
    pub locale: Option<&'a str>,
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
    // Only when the client actually said. Writing `NULL` here would make
    // every app launch that omits the field forget the device's language.
    if let Some(locale) = new.locale {
        update.value(iden("locale"), locale);
    }
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
            "locale",
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
            new.locale.into(),
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
// The account's own language (#190)

/// The language this account reads, if it has said. `None` means the
/// venture's default answers instead.
///
/// Read back through [`cratefield_i18n::parse_locale`], the same door the
/// write goes through, so the only thing that can come out of this column
/// is a canonical BCP 47 tag — including out of a database somebody edited
/// by hand.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub(crate) async fn account_locale(
    db: &dyn Database,
    account_id: &str,
) -> Result<Option<LanguageIdentifier>, DbError> {
    let mut select = Query::select();
    select
        .column(iden("locale"))
        .from(iden(LOCALES))
        .and_where(Expr::col(iden("account_id")).eq(account_id));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .and_then(|row| row.get::<String>("locale"))
        .as_deref()
        .and_then(cratefield_i18n::parse_locale))
}

/// Sets the language this account reads.
///
/// `locale` is already parsed and canonicalised — the route's job, so that
/// arbitrary text from a body or a header never reaches the column.
///
/// Not `ON CONFLICT`, for the reason [`write_preference_statement`] gives:
/// one more dialect difference than the portable subset wants (ADR 0004).
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub(crate) async fn set_account_locale(
    db: &dyn Database,
    account_id: &str,
    locale: &str,
    now: &str,
) -> Result<(), DbError> {
    let existing = account_locale(db, account_id).await?.is_some();
    let statement = if existing {
        let mut update = Query::update();
        update
            .table(iden(LOCALES))
            .value(iden("locale"), locale)
            .value(iden("updated_at"), now)
            .and_where(Expr::col(iden("account_id")).eq(account_id));
        Statement::render(&update)
    } else {
        let mut insert = Query::insert();
        insert
            .into_table(iden(LOCALES))
            .columns(["account_id", "locale", "updated_at"])
            .values_panic([account_id.into(), locale.into(), now.into()]);
        Statement::render(&insert)
    };
    db.execute(&statement).await?;
    Ok(())
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
    /// Why it gave up, as the provider put it. Sanitized where it is
    /// **bound**, not here — see [`dead_letter_statement`].
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
///
/// `last_error` is scrubbed **here**, at the one place the column is
/// bound, rather than at each caller (issue #235). The log leg of
/// `dead_letter` was already sanitized — `tracing` runs every value it
/// prints through [`scrub_text`](cratefield_core::scrub_text) — and the
/// database leg was not, so a provider's `422` quoting the recipient
/// address sat in plain text in a venture's own table, outliving the
/// erasure of `notifications_email_targets`, while the log a developer
/// checks showed it correctly redacted. That asymmetry is what made it
/// easy to miss, so the fix is to give the column exactly the guarantee
/// the log has, for every writer whatever it passes: `MailError` and
/// `PushError` now scrub in their own `Display`, and a caller that hands
/// over a bare provider string (`PushError::Rejected`'s inner text, a
/// `format!` around it) is covered here regardless.
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
            cratefield_core::scrub_text(dead.last_error).into(),
            dead.created_at.into(),
            dead.failed_at.into(),
        ]);
    Statement::render(&insert)
}

// ---------------------------------------------------------------------------
// The in-app inbox (#187)

/// One inbox row, as the routes render it.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct InboxItem {
    pub id: String,
    pub notification_id: String,
    pub category: String,
    pub title: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub data: serde_json::Value,
    /// What this row was rendered in (#190), so a client can set `lang`
    /// on the item. Absent for a row a venture rendered itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Which way that locale's text runs, `"ltr"` or `"rtl"`.
    ///
    /// Computed here rather than left to the client, because there is no
    /// browser API that answers it: `Intl` has no directionality, and a
    /// client that worked it out would be a second copy of the list in
    /// `cratefield-i18n` — one that knows `ar` and not `az-Arab`, and
    /// drifts the first time the other is extended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<&'static str>,
    /// The catalog message this row came from, kept beside the rendered
    /// text so a client that wants another language can re-render. The
    /// module never re-renders a stored row itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loc_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loc_args: Option<serde_json::Value>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_at: Option<String>,
}

/// One row of the in-app inbox, as `notify` writes it.
pub(crate) struct NewInboxRow<'a> {
    pub id: &'a str,
    pub account_id: &'a str,
    pub notification_id: &'a str,
    pub category: &'a str,
    pub title: &'a str,
    pub body: &'a str,
    pub url: Option<&'a str>,
    pub icon: Option<&'a str>,
    pub data_json: &'a str,
    /// The locale the title and body above were rendered in — already a
    /// canonical tag, never what a client sent.
    pub locale: Option<&'a str>,
    pub loc_key: Option<&'a str>,
    pub loc_args_json: Option<&'a str>,
    pub now: &'a str,
}

/// The insert `notify` appends to the caller's batch.
///
/// A statement rather than a write, because the inbox row has to commit in
/// the same unit of work as the caller's own state change: a booking that
/// rolls back must not leave "your booking is confirmed" in the list.
#[must_use]
pub(crate) fn insert_inbox_statement(row: &NewInboxRow<'_>) -> Statement {
    let mut insert = Query::insert();
    insert
        .into_table(iden(INBOX))
        .columns([
            "id",
            "account_id",
            "notification_id",
            "category",
            "title",
            "body",
            "url",
            "icon",
            "data_json",
            "locale",
            "loc_key",
            "loc_args_json",
            "created_at",
        ])
        .values_panic([
            row.id.into(),
            row.account_id.into(),
            row.notification_id.into(),
            row.category.into(),
            row.title.into(),
            row.body.into(),
            row.url.into(),
            row.icon.into(),
            row.data_json.into(),
            row.locale.into(),
            row.loc_key.into(),
            row.loc_args_json.into(),
            row.now.into(),
        ]);
    Statement::render(&insert)
}

/// One page of an account's inbox, newest first.
///
/// Ordered by `(created_at, id)` and paged by the same pair. `created_at`
/// alone is not unique — two notifications in one second tie — and paging
/// on a non-unique key either skips rows or repeats them. `id` alone is
/// not ordered: it comes from the `IdGen` port, whose ULIDs read the real
/// clock and randomise the tail, so two minted in the same millisecond
/// have no defined order and neither matches the `Clock` the API reports.
/// The pair is both ordered and unique, which is what a cursor needs.
///
/// Archived rows are excluded: archiving is the account saying "not in my
/// list".
///
/// # Errors
///
/// [`DbError`] when the read fails or a row will not decode.
pub(crate) async fn inbox_page(
    db: &dyn Database,
    account_id: &str,
    before: Option<(&str, &str)>,
    unread_only: bool,
    limit: u64,
) -> Result<Vec<InboxItem>, DbError> {
    let mut select = Query::select();
    select
        .columns([
            iden("id"),
            iden("notification_id"),
            iden("category"),
            iden("title"),
            iden("body"),
            iden("url"),
            iden("icon"),
            iden("data_json"),
            iden("locale"),
            iden("loc_key"),
            iden("loc_args_json"),
            iden("created_at"),
            iden("read_at"),
        ])
        .from(iden(INBOX))
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .and_where(Expr::col(iden("archived_at")).is_null())
        .order_by(iden("created_at"), Order::Desc)
        .order_by(iden("id"), Order::Desc)
        .limit(limit);
    if let Some((at, id)) = before {
        // Strictly older than the cursor row: an earlier instant, or the
        // same instant and a lower id. Plain comparisons and OR, so it
        // stays in the portable subset (ADR 0004).
        select.and_where(
            Expr::col(iden("created_at"))
                .lt(at)
                .or(Expr::col(iden("created_at"))
                    .eq(at)
                    .and(Expr::col(iden("id")).lt(id))),
        );
    }
    if unread_only {
        select.and_where(Expr::col(iden("read_at")).is_null());
    }
    db.query(&Statement::render(&select))
        .await?
        .rows
        .iter()
        .map(read_inbox_item)
        .collect()
}

/// One row, or the query error a row that will not decode deserves.
fn read_inbox_item(row: &Row) -> Result<InboxItem, DbError> {
    let locale = row
        .get::<String>("locale")
        .as_deref()
        .and_then(cratefield_i18n::parse_locale);
    let id = row
        .get::<String>("id")
        .ok_or_else(|| DbError::Query(format!("{INBOX} row has no id")))?;
    let data = row
        .get::<String>("data_json")
        .as_deref()
        .map_or_else(|| Ok(serde_json::Value::Null), serde_json::from_str)
        .map_err(|err| DbError::Query(format!("{INBOX} row {id} has unreadable data: {err}")))?;
    Ok(InboxItem {
        notification_id: row
            .get::<String>("notification_id")
            .ok_or_else(|| corrupt(INBOX, &id, "notification_id"))?,
        category: row
            .get::<String>("category")
            .ok_or_else(|| corrupt(INBOX, &id, "category"))?,
        title: row
            .get::<String>("title")
            .ok_or_else(|| corrupt(INBOX, &id, "title"))?,
        body: row
            .get::<String>("body")
            .ok_or_else(|| corrupt(INBOX, &id, "body"))?,
        url: row.get::<String>("url"),
        icon: row.get::<String>("icon"),
        data,
        // Through the parser on the way out as well: this value reaches a
        // `lang` attribute in somebody's browser, and a column is not a
        // place to trust.
        dir: locale
            .as_ref()
            .map(|locale| cratefield_i18n::direction(locale).as_str()),
        locale: locale.map(|locale| locale.to_string()),
        loc_key: row.get::<String>("loc_key"),
        loc_args: row
            .get::<String>("loc_args_json")
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok()),
        created_at: row
            .get::<String>("created_at")
            .ok_or_else(|| corrupt(INBOX, &id, "created_at"))?,
        read_at: row.get::<String>("read_at"),
        id,
    })
}

/// How many unread, unarchived rows the account has.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub(crate) async fn unread_count(db: &dyn Database, account_id: &str) -> Result<i64, DbError> {
    let mut select = Query::select();
    select
        .expr_as(Expr::col(iden("id")).count(), iden("unread"))
        .from(iden(INBOX))
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .and_where(Expr::col(iden("archived_at")).is_null())
        .and_where(Expr::col(iden("read_at")).is_null());
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .and_then(|row| row.get::<i64>("unread"))
        .unwrap_or(0))
}

/// Marks one row read, scoped to its owner. `false` when the account does
/// not own a row with that id — which the route answers as a 404, never a
/// 403, so it cannot be used to discover that somebody else's id exists.
///
/// Idempotent: `read_at` is only set where it is still NULL, so reading
/// twice keeps the first timestamp.
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub(crate) async fn mark_read(
    db: &dyn Database,
    id: &str,
    account_id: &str,
    now: &str,
) -> Result<bool, DbError> {
    let mut exists = Query::select();
    exists
        .column(iden("id"))
        .from(iden(INBOX))
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("account_id")).eq(account_id));
    if db
        .query(&Statement::render(&exists))
        .await?
        .first()
        .is_none()
    {
        return Ok(false);
    }
    let mut update = Query::update();
    update
        .table(iden(INBOX))
        .value(iden("read_at"), now)
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .and_where(Expr::col(iden("read_at")).is_null());
    db.execute(&Statement::render(&update)).await?;
    Ok(true)
}

/// Marks every unread row read. Returns how many moved, so a second call
/// answering `0` is the visible proof it is idempotent.
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub(crate) async fn mark_all_read(
    db: &dyn Database,
    account_id: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(INBOX))
        .value(iden("read_at"), now)
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .and_where(Expr::col(iden("read_at")).is_null());
    db.execute(&Statement::render(&update)).await
}

/// Archives one row, scoped to its owner. A soft delete: the row stays for
/// `fz data export` and for retention to collect.
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub(crate) async fn archive(
    db: &dyn Database,
    id: &str,
    account_id: &str,
    now: &str,
) -> Result<bool, DbError> {
    let mut update = Query::update();
    update
        .table(iden(INBOX))
        .value(iden("archived_at"), now)
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .and_where(Expr::col(iden("archived_at")).is_null());
    Ok(db.execute(&Statement::render(&update)).await? == 1)
}

/// Deletes inbox rows the account is finished with and that fell out of
/// the retention window.
///
/// Only rows it has read or archived: an unread row is still waiting to be
/// seen, however old, and deleting it would be the module deciding the
/// account missed its chance.
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub(crate) async fn prune_inbox(db: &dyn Database, older_than: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(INBOX))
        .and_where(Expr::col(iden("created_at")).lt(older_than))
        .and_where(
            Expr::col(iden("read_at"))
                .is_not_null()
                .or(Expr::col(iden("archived_at")).is_not_null()),
        );
    db.execute(&Statement::render(&delete)).await
}

// ---------------------------------------------------------------------------
// Email targets and the send window (#189)

/// An account's email address, as the drain reads it.
#[derive(Debug, Clone)]
pub(crate) struct EmailTarget {
    pub email: String,
    pub verified_at: Option<String>,
    pub unsubscribed_at: Option<String>,
}

impl EmailTarget {
    /// Whether the drain may mail this address.
    ///
    /// Verified and not unsubscribed. Both halves matter and neither is
    /// the other: an unverified address is somebody else's mailbox until
    /// proven otherwise, and an unsubscribed one is this account's own
    /// answer.
    pub fn mailable(&self) -> bool {
        self.verified_at.is_some() && self.unsubscribed_at.is_none()
    }
}

/// The address for one account, if it has set one.
///
/// # Errors
///
/// [`DbError`] when the read fails or the row will not decode.
pub(crate) async fn email_target(
    db: &dyn Database,
    account_id: &str,
) -> Result<Option<EmailTarget>, DbError> {
    let mut select = Query::select();
    select
        .columns([iden("email"), iden("verified_at"), iden("unsubscribed_at")])
        .from(iden(EMAIL_TARGETS))
        .and_where(Expr::col(iden("account_id")).eq(account_id));
    let rows = db.query(&Statement::render(&select)).await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    Ok(Some(EmailTarget {
        email: row
            .get::<String>("email")
            .ok_or_else(|| corrupt(EMAIL_TARGETS, account_id, "email"))?,
        verified_at: row.get::<String>("verified_at"),
        unsubscribed_at: row.get::<String>("unsubscribed_at"),
    }))
}

/// Writes an account's address. An address that changed is unverified
/// again: verification is of the address, not of the account.
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub(crate) async fn set_email_target(
    db: &dyn Database,
    account_id: &str,
    email: &str,
    verified: bool,
    now: &str,
) -> Result<(), DbError> {
    let existing = email_target(db, account_id).await?;
    let verified_at = verified.then(|| now.to_owned());
    let statement = if let Some(current) = existing {
        let mut update = Query::update();
        update
            .table(iden(EMAIL_TARGETS))
            .value(iden("email"), email)
            .value(iden("updated_at"), now)
            .and_where(Expr::col(iden("account_id")).eq(account_id));
        if current.email == email {
            // The same address: keep whatever standing it already had,
            // including an unsubscribe. Re-submitting your own address is
            // not a way to undo opting out.
            if let Some(at) = verified_at {
                update.value(iden("verified_at"), at);
            }
        } else {
            // A new address starts unverified and unsubscribed-clear: the
            // previous address's answers were about a different mailbox.
            update
                .value(iden("verified_at"), verified_at)
                .value(iden("unsubscribed_at"), None::<String>)
                .value(iden("unsubscribed_reason"), None::<String>);
        }
        Statement::render(&update)
    } else {
        let mut insert = Query::insert();
        insert
            .into_table(iden(EMAIL_TARGETS))
            .columns(["account_id", "email", "verified_at", "updated_at"])
            .values_panic([
                account_id.into(),
                email.into(),
                verified_at.into(),
                now.into(),
            ]);
        Statement::render(&insert)
    };
    db.execute(&statement).await?;
    Ok(())
}

/// Turns the whole channel off for this account's address.
///
/// # Errors
///
/// [`DbError`] when the write fails.
/// Suppresses every account holding `email`, for a reason the account did
/// not choose — a hard bounce or a spam complaint (#233).
///
/// By address, not by account, because that is all the provider knows: it
/// reports the mailbox it could not deliver to. Two accounts sharing one
/// mailbox is ordinary, and a bounce is about the mailbox, so both are
/// suppressed.
///
/// `unsubscribed_at IS NULL` makes a redelivery — which a provider will
/// send, since it retries until it gets a 2xx — change nothing, and keeps
/// the *first* reason: somebody who had already unsubscribed by hand did
/// not un-choose that by later bouncing.
///
/// Returns how many accounts were suppressed, which is a count and safe
/// to log. The address is not.
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub(crate) async fn suppress_address(
    db: &dyn Database,
    email: &str,
    reason: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(EMAIL_TARGETS))
        .value(iden("unsubscribed_at"), now)
        .value(iden("unsubscribed_reason"), reason)
        .value(iden("updated_at"), now)
        .and_where(Expr::col(iden("email")).eq(email))
        .and_where(Expr::col(iden("unsubscribed_at")).is_null());
    db.execute(&Statement::render(&update)).await
}

pub(crate) async fn unsubscribe_all(
    db: &dyn Database,
    account_id: &str,
    reason: &str,
    now: &str,
) -> Result<bool, DbError> {
    let mut update = Query::update();
    update
        .table(iden(EMAIL_TARGETS))
        .value(iden("unsubscribed_at"), now)
        .value(iden("unsubscribed_reason"), reason)
        .value(iden("updated_at"), now)
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .and_where(Expr::col(iden("unsubscribed_at")).is_null());
    Ok(db.execute(&Statement::render(&update)).await? == 1)
}

/// How many mails this account has had for this category since `since`.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub(crate) async fn emails_since(
    db: &dyn Database,
    account_id: &str,
    category: &str,
    since: &str,
) -> Result<i64, DbError> {
    let mut select = Query::select();
    select
        .expr_as(Expr::col(iden("id")).count(), iden("sent"))
        .from(iden(EMAIL_SENDS))
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .and_where(Expr::col(iden("category")).eq(category))
        .and_where(Expr::col(iden("sent_at")).gte(since));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .and_then(|row| row.get::<i64>("sent"))
        .unwrap_or(0))
}

/// Records one mail against the cooldown window.
#[must_use]
pub(crate) fn record_email_statement(
    id: &str,
    account_id: &str,
    category: &str,
    now: &str,
) -> Statement {
    let mut insert = Query::insert();
    insert
        .into_table(iden(EMAIL_SENDS))
        .columns(["id", "account_id", "category", "sent_at"])
        .values_panic([id.into(), account_id.into(), category.into(), now.into()]);
    Statement::render(&insert)
}

/// Drops send-window rows that fell out of every cooldown window.
///
/// # Errors
///
/// [`DbError`] when the write fails.
pub(crate) async fn prune_email_sends(db: &dyn Database, older_than: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(EMAIL_SENDS))
        .and_where(Expr::col(iden("sent_at")).lt(older_than));
    db.execute(&Statement::render(&delete)).await
}
