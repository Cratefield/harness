//! Every statement this module runs, in one place (on the pattern of
//! `module-notifications`' `store.rs`). Rows are read back through the
//! `Database` port's small owned row model, so nothing engine-specific
//! leaks past this file. A nullable `INTEGER` reads as `Option<i64>`
//! directly: a SQL `NULL` and a missing column both convert to `None`.

use cratefield_core::{Database, DbError, IdGen, Outbox, Row, Statement, UlidIdGen};
use sea_query::{Alias, Expr, Order, Query};
use serde::{Deserialize, Serialize};

/// The delivery targets. Must match `0001_init.sql` and
/// [`crate::Webhooks::tables`].
pub(crate) const ENDPOINTS: &str = "webhooks_endpoints";
/// The core [`Outbox`] table this module owns: one row per
/// (event, endpoint), so each endpoint retries independently.
pub(crate) const OUTBOX: &str = "webhooks_outbox";
/// One row per attempt actually made.
pub(crate) const DELIVERIES: &str = "webhooks_deliveries";
/// The terminal state core's outbox does not have (ADR 0016).
pub(crate) const DEAD_LETTERS: &str = "webhooks_dead_letters";

/// The outbox topic a delivery row carries.
pub const TOPIC_DELIVER: &str = "webhooks.deliver";

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// One row of `webhooks_endpoints`, without the secret: a list never hands
/// signing material back. The secret is returned exactly once, by
/// [`crate::Webhooks::create_endpoint`].
// `pub` rather than `pub(crate)`: these are the module's read-back types,
// re-exported at the crate root; the module itself stays private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub id: String,
    pub subject: String,
    pub url: String,
    pub event_types: String,
    pub created_at: String,
}

/// One row of `webhooks_deliveries`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub id: String,
    pub endpoint_id: String,
    pub subject: String,
    pub event_id: String,
    pub event_type: String,
    pub attempt: i64,
    pub status_code: Option<i64>,
    pub error: Option<String>,
    pub at: String,
}

/// What a delivery gave up on. `attempts_exhausted` is the ordinary way a
/// dead letter happens; `rejected` is a failure no retry fixes (an HTTP
/// 410 Gone, or the `HttpClient` port refusing the destination outright);
/// `malformed` is an outbox row this module cannot read back — a bug or a
/// hand-edited database, not weather.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeadLetterReason {
    AttemptsExhausted,
    Rejected,
    Malformed,
}

impl DeadLetterReason {
    /// The value stored in `webhooks_dead_letters.reason`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DeadLetterReason::AttemptsExhausted => "attempts_exhausted",
            DeadLetterReason::Rejected => "rejected",
            DeadLetterReason::Malformed => "malformed",
        }
    }
}

/// One row of `webhooks_dead_letters`, as [`crate::Webhooks::dead_letters`]
/// reads it back and [`crate::Webhooks::replay`] acts on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetter {
    pub id: String,
    pub endpoint_id: String,
    pub subject: String,
    pub event_id: String,
    pub event_type: String,
    pub data: String,
    pub attempts: i64,
    pub reason: String,
    pub last_error: String,
    pub status_code: Option<i64>,
    /// When the event was published — what a replay preserves, because
    /// the envelope names the event's own time, not a drain's.
    pub created_at: String,
    pub failed_at: String,
}

/// The job one outbox row carries: the event and the endpoint it must
/// reach. The endpoint's URL and secret are **not** in it — like a push
/// recipient (ADR 0015), a signing secret is credential material, and an
/// outbox payload is ordinary data that ends up in exports and
/// diagnostics; the drain reads the endpoint row instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DeliveryJob {
    pub endpoint_id: String,
    pub event_id: String,
    pub event_type: String,
    pub subject: String,
    /// When the event was published — the outbox table does not carry a
    /// `created_at` column, and the envelope and the dead letter both
    /// name the event's own time, not a drain's.
    pub created_at: String,
    /// The caller's event payload, exactly as published.
    pub data: serde_json::Value,
}

/// The columns every endpoint read shares.
const ENDPOINT_COLUMNS: [&str; 5] = ["id", "subject", "url", "event_types", "created_at"];

/// The columns every delivery-log write and read shares (the insert and
/// the list select must agree).
const DELIVERY_COLUMNS: [&str; 9] = [
    "id",
    "endpoint_id",
    "subject",
    "event_id",
    "event_type",
    "attempt",
    "status_code",
    "error",
    "at",
];

/// The columns every dead-letter write and read shares (the insert and
/// both selects must agree).
const DEAD_LETTER_COLUMNS: [&str; 12] = [
    "id",
    "endpoint_id",
    "subject",
    "event_id",
    "event_type",
    "data",
    "attempts",
    "reason",
    "last_error",
    "status_code",
    "created_at",
    "failed_at",
];

/// What the drain needs to reach one endpoint: its URL and the secret it
/// signs with. The one read that may carry the secret — the listable
/// [`Endpoint`] never does — so credential material cannot end up in a
/// list response by construction.
pub(crate) struct DeliveryTarget {
    pub url: String,
    pub secret: String,
}

/// The one endpoint of `subject` with `endpoint_id`, resolved to
/// [`DeliveryTarget`] in a single read, or `None`.
pub(crate) async fn delivery_target(
    db: &dyn Database,
    subject: &str,
    endpoint_id: &str,
) -> Result<Option<DeliveryTarget>, DbError> {
    let mut select = Query::select();
    select
        .columns(["url", "secret"])
        .from(iden(ENDPOINTS))
        .and_where(Expr::col(iden("subject")).eq(subject))
        .and_where(Expr::col(iden("id")).eq(endpoint_id));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(|row| DeliveryTarget {
            url: row.get::<String>("url").unwrap_or_default(),
            secret: row.get::<String>("secret").unwrap_or_default(),
        }))
}

/// Whether the endpoint row still exists — the guard
/// [`crate::Webhooks::replay`] needs: a dead letter whose endpoint is
/// gone has nowhere to be re-delivered to, so it must stay put.
pub(crate) async fn endpoint_exists(
    db: &dyn Database,
    subject: &str,
    endpoint_id: &str,
) -> Result<bool, DbError> {
    let mut select = Query::select();
    select
        .column(iden("id"))
        .from(iden(ENDPOINTS))
        .and_where(Expr::col(iden("subject")).eq(subject))
        .and_where(Expr::col(iden("id")).eq(endpoint_id));
    Ok(!db.query(&Statement::render(&select)).await?.rows.is_empty())
}

/// Every endpoint of one subject, creation order. Disabled and deleted
/// endpoints are simply not here.
pub(crate) async fn endpoints_for_subject(
    db: &dyn Database,
    subject: &str,
) -> Result<Vec<Endpoint>, DbError> {
    let mut select = Query::select();
    select
        .columns(ENDPOINT_COLUMNS)
        .from(iden(ENDPOINTS))
        .and_where(Expr::col(iden("subject")).eq(subject))
        // `id` breaks ties: `created_at` has second resolution, and two
        // endpoints created in the same second must list deterministically.
        .order_by(iden("created_at"), Order::Asc)
        .order_by(iden("id"), Order::Asc);
    let rows = db.query(&Statement::render(&select)).await?;
    Ok(rows.rows.iter().map(endpoint_from).collect())
}

fn endpoint_from(row: &Row) -> Endpoint {
    Endpoint {
        id: row.get::<String>("id").unwrap_or_default(),
        subject: row.get::<String>("subject").unwrap_or_default(),
        url: row.get::<String>("url").unwrap_or_default(),
        event_types: row.get::<String>("event_types").unwrap_or_default(),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
    }
}

/// Inserts one endpoint. `secret` is bound here and nowhere else; the
/// caller has already generated it.
pub(crate) fn insert_endpoint_statement(
    id: &str,
    subject: &str,
    url: &str,
    secret: &str,
    event_types: &str,
    now: &str,
) -> Statement {
    let mut insert = Query::insert();
    insert
        .into_table(iden(ENDPOINTS))
        .columns([
            "id",
            "subject",
            "url",
            "secret",
            "event_types",
            "created_at",
        ])
        .values_panic([
            id.to_owned().into(),
            subject.to_owned().into(),
            url.to_owned().into(),
            secret.to_owned().into(),
            event_types.to_owned().into(),
            now.to_owned().into(),
        ]);
    Statement::render(&insert)
}

/// Deletes one endpoint of one subject; `true` when a row went. Queued
/// deliveries for it are left to the drain, which drops them when the
/// endpoint no longer resolves.
pub(crate) async fn delete_endpoint(
    db: &dyn Database,
    subject: &str,
    endpoint_id: &str,
) -> Result<bool, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(ENDPOINTS))
        .and_where(Expr::col(iden("subject")).eq(subject))
        .and_where(Expr::col(iden("id")).eq(endpoint_id));
    Ok(db.execute(&Statement::render(&delete)).await? == 1)
}

/// The enqueue for one fan-out target, returned into the caller's own
/// `db.batch_atomic(..)` — the core [`Outbox`] contract, so the event is
/// durable exactly when the caller's state change is. Nothing is written
/// until that batch runs.
pub(crate) fn enqueue_statement(job: &DeliveryJob, subject: &str, at: &str) -> Statement {
    let payload = serde_json::to_string(job).unwrap_or_else(|_| "{}".to_owned());
    Outbox::new(OUTBOX).enqueue_statement(
        &UlidIdGen.ulid(),
        TOPIC_DELIVER,
        &payload,
        Some(subject),
        at,
    )
}

/// Records one attempt in the delivery log.
///
/// Written as its own statement after the attempt, not in the batch that
/// completes or retries the outbox row: the log is diagnostic, and a crash
/// between the two costs one double-logged attempt — what at-least-once
/// delivery looks like in a log.
pub(crate) async fn record_delivery(
    db: &dyn Database,
    delivery_id: &str,
    job: &DeliveryJob,
    attempt: i64,
    status_code: Option<i64>,
    error: Option<&str>,
    at: &str,
) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(DELIVERIES))
        .columns(DELIVERY_COLUMNS)
        .values_panic([
            delivery_id.to_owned().into(),
            job.endpoint_id.clone().into(),
            job.subject.clone().into(),
            job.event_id.clone().into(),
            job.event_type.clone().into(),
            attempt.into(),
            status_code.into(),
            error.map(str::to_owned).into(),
            at.to_owned().into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// A subject's delivery log, newest attempt first.
pub(crate) async fn deliveries(
    db: &dyn Database,
    subject: &str,
    limit: u64,
) -> Result<Vec<Delivery>, DbError> {
    let mut select = Query::select();
    select
        .columns(DELIVERY_COLUMNS)
        .from(iden(DELIVERIES))
        .and_where(Expr::col(iden("subject")).eq(subject))
        // `id` breaks ties: attempts in the same second keep a stable,
        // ULID-ordered story instead of an engine-dependent shuffle.
        .order_by(iden("at"), Order::Desc)
        .order_by(iden("id"), Order::Desc)
        .limit(limit);
    let rows = db.query(&Statement::render(&select)).await?;
    Ok(rows.rows.iter().map(delivery_from).collect())
}

fn delivery_from(row: &Row) -> Delivery {
    Delivery {
        id: row.get::<String>("id").unwrap_or_default(),
        endpoint_id: row.get::<String>("endpoint_id").unwrap_or_default(),
        subject: row.get::<String>("subject").unwrap_or_default(),
        event_id: row.get::<String>("event_id").unwrap_or_default(),
        event_type: row.get::<String>("event_type").unwrap_or_default(),
        attempt: row.get::<i64>("attempt").unwrap_or(0),
        status_code: row.get::<i64>("status_code"),
        error: row.get::<Option<String>>("error").flatten(),
        at: row.get::<String>("at").unwrap_or_default(),
    }
}

/// What a delivery gave up on, bound in one place. `last_error` is prose
/// from a receiver or a transport — never the endpoint's secret, which is
/// in no error path at all.
pub(crate) struct GiveUp<'a> {
    pub outbox_row_id: &'a str,
    /// Attempts **made**, including the one that just failed.
    pub attempts: i64,
    pub reason: DeadLetterReason,
    pub last_error: &'a str,
    pub status_code: Option<i64>,
    /// When the event was enqueued, not when it was abandoned.
    pub created_at: &'a str,
    pub failed_at: &'a str,
}

/// Moves one failed delivery into the dead-letter table and drops its
/// outbox row, in one batch: a delivery that will never succeed leaves the
/// work queue and stays replayable.
pub(crate) async fn dead_letter(
    db: &dyn Database,
    dead_letter_id: &str,
    job: &DeliveryJob,
    gave_up: &GiveUp<'_>,
) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(DEAD_LETTERS))
        .columns(DEAD_LETTER_COLUMNS)
        .values_panic([
            dead_letter_id.to_owned().into(),
            job.endpoint_id.clone().into(),
            job.subject.clone().into(),
            job.event_id.clone().into(),
            job.event_type.clone().into(),
            job.data.to_string().into(),
            gave_up.attempts.into(),
            gave_up.reason.as_str().into(),
            gave_up.last_error.to_owned().into(),
            gave_up.status_code.into(),
            gave_up.created_at.to_owned().into(),
            gave_up.failed_at.to_owned().into(),
        ]);
    db.batch_atomic(&[
        Statement::render(&insert),
        delete_outbox_statement(gave_up.outbox_row_id),
    ])
    .await?;
    Ok(())
}

pub(crate) fn delete_outbox_statement(id: &str) -> Statement {
    let mut delete = Query::delete();
    delete
        .from_table(iden(OUTBOX))
        .and_where(Expr::col(iden("id")).eq(id));
    Statement::render(&delete)
}

/// A subject's dead letters, oldest first — the list
/// [`crate::Webhooks::replay`] takes an id from.
pub(crate) async fn dead_letters(
    db: &dyn Database,
    subject: &str,
    limit: u64,
) -> Result<Vec<DeadLetter>, DbError> {
    let mut select = Query::select();
    select
        .columns(DEAD_LETTER_COLUMNS)
        .from(iden(DEAD_LETTERS))
        .and_where(Expr::col(iden("subject")).eq(subject))
        .order_by(iden("failed_at"), Order::Asc)
        .limit(limit);
    let rows = db.query(&Statement::render(&select)).await?;
    Ok(rows.rows.iter().map(dead_letter_from).collect())
}

fn dead_letter_from(row: &Row) -> DeadLetter {
    DeadLetter {
        id: row.get::<String>("id").unwrap_or_default(),
        endpoint_id: row.get::<String>("endpoint_id").unwrap_or_default(),
        subject: row.get::<String>("subject").unwrap_or_default(),
        event_id: row.get::<String>("event_id").unwrap_or_default(),
        event_type: row.get::<String>("event_type").unwrap_or_default(),
        data: row.get::<String>("data").unwrap_or_default(),
        attempts: row.get::<i64>("attempts").unwrap_or(0),
        reason: row.get::<String>("reason").unwrap_or_default(),
        last_error: row.get::<String>("last_error").unwrap_or_default(),
        status_code: row.get::<i64>("status_code"),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
        failed_at: row.get::<String>("failed_at").unwrap_or_default(),
    }
}

/// The one dead letter of `subject` with `dead_letter_id`, or `None`.
async fn find_dead_letter(
    db: &dyn Database,
    subject: &str,
    dead_letter_id: &str,
) -> Result<Option<DeadLetter>, DbError> {
    let mut select = Query::select();
    select
        .columns(DEAD_LETTER_COLUMNS)
        .from(iden(DEAD_LETTERS))
        .and_where(Expr::col(iden("subject")).eq(subject))
        .and_where(Expr::col(iden("id")).eq(dead_letter_id));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(dead_letter_from))
}

/// Re-enqueues one dead letter and removes it, in one batch. The new
/// outbox row starts from zero attempts; the delivery log keeps the
/// history. `Ok(false)` — the letter left in place — when the id names no
/// dead letter of this subject, or when the letter's endpoint is gone:
/// consuming the letter for a delivery the drain would only drop would
/// destroy the event for good.
pub(crate) async fn replay(
    db: &dyn Database,
    subject: &str,
    dead_letter_id: &str,
    at: &str,
) -> Result<bool, DbError> {
    let Some(letter) = find_dead_letter(db, subject, dead_letter_id).await? else {
        return Ok(false);
    };
    if !endpoint_exists(db, subject, &letter.endpoint_id).await? {
        return Ok(false);
    }
    let data: serde_json::Value =
        serde_json::from_str(&letter.data).unwrap_or(serde_json::Value::Null);
    let job = DeliveryJob {
        endpoint_id: letter.endpoint_id,
        event_id: letter.event_id,
        event_type: letter.event_type,
        subject: letter.subject,
        created_at: letter.created_at,
        data,
    };
    db.batch_atomic(&[
        enqueue_statement(&job, &job.subject, at),
        delete_dead_letter_statement(&letter.id),
    ])
    .await?;
    Ok(true)
}

pub(crate) fn delete_dead_letter_statement(id: &str) -> Statement {
    let mut delete = Query::delete();
    delete
        .from_table(iden(DEAD_LETTERS))
        .and_where(Expr::col(iden("id")).eq(id));
    Statement::render(&delete)
}

/// The job every unit test shares, at store scope so sibling test modules
/// (`deliver`'s) reach it too.
#[cfg(test)]
pub(crate) fn test_job() -> DeliveryJob {
    DeliveryJob {
        endpoint_id: "ep".to_owned(),
        event_id: "ev".to_owned(),
        event_type: "order.paid".to_owned(),
        subject: "acct".to_owned(),
        created_at: "2026-09-27T00:00:00Z".to_owned(),
        data: serde_json::json!({ "amount": 1 }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The migration carries the outbox DDL verbatim; a core change to
    /// `create_table_sql` must be copied here on purpose, never silently.
    #[test]
    fn the_migration_carries_the_outbox_ddl_verbatim() {
        let sql = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/sqlite/0001_init.sql"
        ))
        .expect("the migration is in the crate");
        assert!(
            sql.contains(&Outbox::new(OUTBOX).create_table_sql()),
            "webhooks_outbox must match Outbox::create_table_sql"
        );
    }

    #[test]
    fn a_job_enqueues_one_row_with_its_subject() {
        let job = test_job();
        let statement = enqueue_statement(&job, "acct", "2026-09-27T00:00:00Z");
        assert!(statement.sql.contains("INSERT INTO"));
        assert!(statement.sql.contains("webhooks_outbox"));
        assert!(statement.sql.contains("subject"));
    }
}
