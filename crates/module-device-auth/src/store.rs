//! Sea-query data access for the one device-auth table (issue #587).
//!
//! Every value is bound, never interpolated. Both codes reach this module
//! as passwords: the caller hashes them, and this layer only ever sees the
//! hash, so a query log or a prepared-statement trace holds nothing that
//! can be replayed.
//!
//! Two statements are the whole concurrency story, and both lean on the
//! `UPDATE` row count rather than a read-then-write:
//!
//! - [`touch_poll`] widens `last_polled_at` only when the row has waited
//!   out its interval, so the caller that sees one row won the poll and
//!   the caller that sees zero must widen the interval instead;
//! - [`consume`] flips `approved` to `consumed` in one conditional
//!   statement, so a credential is minted at most once even when two
//!   polls race.
//!
//! `Database::execute` returns the affected-row count on every adapter and
//! is atomic for a single statement, which is what both depend on.

use cratefield_core::{Database, DbError, Row, Statement};
use sea_query::{Alias, Condition, Expr, Query};

const TABLE: &str = "device_auth_codes";

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// One stored request, as the handlers need it: the client it was issued
/// to, what it asked for, and where it is in the flow.
pub(crate) struct CodeRow {
    pub(crate) client_id: String,
    pub(crate) scopes: String,
    pub(crate) name: Option<String>,
    pub(crate) status: String,
    pub(crate) approver_subject: Option<String>,
    pub(crate) expires_at: String,
    pub(crate) interval_secs: i64,
}

fn row_from(row: &Row) -> CodeRow {
    CodeRow {
        client_id: row.get("client_id").unwrap_or_default(),
        scopes: row.get("scopes").unwrap_or_default(),
        name: row.get("name"),
        status: row.get("status").unwrap_or_default(),
        approver_subject: row.get("approver_subject"),
        expires_at: row.get("expires_at").unwrap_or_default(),
        interval_secs: row.get("interval_secs").unwrap_or(0),
    }
}

/// One request to insert, as the handler has it.
pub(crate) struct NewCode<'a> {
    pub(crate) device_code_hash: &'a str,
    pub(crate) user_code_hash: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) scopes: &'a str,
    pub(crate) name: Option<&'a str>,
    pub(crate) now: &'a str,
    pub(crate) expires_at: &'a str,
    pub(crate) interval_secs: i64,
}

/// Inserts a fresh pending request. `device_code_hash` is the primary key,
/// so a collision is impossible in practice; `user_code_hash` is unique,
/// and the caller checks it first because the space it is drawn from is
/// small enough to make a birthday collision a real, if rare, event.
///
/// # Errors
/// Any database error.
pub(crate) async fn insert(db: &dyn Database, code: &NewCode<'_>) -> Result<u64, DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(TABLE))
        .columns([
            "device_code_hash",
            "user_code_hash",
            "client_id",
            "scopes",
            "name",
            "status",
            "created_at",
            "expires_at",
            "interval_secs",
        ])
        .values_panic([
            code.device_code_hash.into(),
            code.user_code_hash.into(),
            code.client_id.into(),
            code.scopes.into(),
            code.name.into(),
            "pending".into(),
            code.now.into(),
            code.expires_at.into(),
            code.interval_secs.into(),
        ]);
    db.execute(&Statement::render(&insert)).await
}

/// Whether a user code is already taken: the collision check before an
/// insert, so a repeat mints a new code rather than failing the request.
///
/// # Errors
/// Any database error.
pub(crate) async fn user_code_exists(
    db: &dyn Database,
    user_code_hash: &str,
) -> Result<bool, DbError> {
    let mut select = Query::select();
    select
        .column(iden("user_code_hash"))
        .from(iden(TABLE))
        .and_where(Expr::col(iden("user_code_hash")).eq(user_code_hash));
    Ok(!db.query(&Statement::render(&select)).await?.is_empty())
}

/// The row a polling client is asking about, looked up by **both** the
/// device code and the client id: a code presented by another client is
/// no code at all, so the lookup pairs them and lets a miss answer
/// `invalid_grant`.
///
/// # Errors
/// Any database error.
pub(crate) async fn find_by_device(
    db: &dyn Database,
    device_code_hash: &str,
    client_id: &str,
) -> Result<Option<CodeRow>, DbError> {
    let mut select = Query::select();
    select
        .columns([
            "client_id",
            "scopes",
            "name",
            "status",
            "approver_subject",
            "expires_at",
            "interval_secs",
        ])
        .from(iden(TABLE))
        .and_where(Expr::col(iden("device_code_hash")).eq(device_code_hash))
        .and_where(Expr::col(iden("client_id")).eq(client_id));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(row_from))
}

/// The still-pending request a browser is being asked to approve, found by
/// the user code the person typed. Expired and already-answered rows are
/// excluded, so the page never shows a code that can no longer be used.
///
/// # Errors
/// Any database error.
pub(crate) async fn find_pending_by_user(
    db: &dyn Database,
    user_code_hash: &str,
    now: &str,
) -> Result<Option<CodeRow>, DbError> {
    let mut select = Query::select();
    select
        .columns([
            "client_id",
            "scopes",
            "name",
            "status",
            "approver_subject",
            "expires_at",
            "interval_secs",
        ])
        .from(iden(TABLE))
        .and_where(Expr::col(iden("user_code_hash")).eq(user_code_hash))
        .and_where(Expr::col(iden("status")).eq("pending"))
        .and_where(Expr::col(iden("expires_at")).gt(now));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(row_from))
}

/// The RFC 8628 §3.5 interval gate. The `UPDATE` widens `last_polled_at`
/// only when the row has gone `interval_secs` or longer without a poll, so
/// exactly one poller per interval sees a row count of one. A caller that
/// sees zero was too early — or lost the race — and must [`widen`] the
/// interval and answer `slow_down`.
///
/// # Errors
/// Any database error.
pub(crate) async fn touch_poll(
    db: &dyn Database,
    device_code_hash: &str,
    client_id: &str,
    now: &str,
    not_after: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(TABLE))
        .value(iden("last_polled_at"), now)
        .and_where(Expr::col(iden("device_code_hash")).eq(device_code_hash))
        .and_where(Expr::col(iden("client_id")).eq(client_id))
        .and_where(Expr::col(iden("status")).eq("pending"))
        .and_where(Expr::col(iden("expires_at")).gt(now))
        .and_where(
            Condition::any()
                .add(Expr::col(iden("last_polled_at")).is_null())
                .add(Expr::col(iden("last_polled_at")).lte(not_after))
                .into(),
        );
    db.execute(&Statement::render(&update)).await
}

/// The penalty for polling too fast: RFC 8628 §3.5 says `slow_down` and
/// five more seconds. Widening the interval rather than storing a
/// separate deadline keeps the rule and its state in one row.
///
/// # Errors
/// Any database error.
pub(crate) async fn widen_interval(
    db: &dyn Database,
    device_code_hash: &str,
    client_id: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(TABLE))
        .value(
            iden("interval_secs"),
            Expr::col(iden("interval_secs")).add(5),
        )
        .and_where(Expr::col(iden("device_code_hash")).eq(device_code_hash))
        .and_where(Expr::col(iden("client_id")).eq(client_id));
    db.execute(&Statement::render(&update)).await
}

/// The at-most-once consume: `approved` becomes `consumed` exactly once,
/// and the caller that sees one row is the one that mints the credential.
/// A row count of zero means somebody else won the race, or the code
/// expired, or it was consumed on an earlier poll — all of which answer
/// `expired_token`.
///
/// # Errors
/// Any database error.
pub(crate) async fn consume(
    db: &dyn Database,
    device_code_hash: &str,
    client_id: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(TABLE))
        .value(iden("status"), "consumed")
        .and_where(Expr::col(iden("device_code_hash")).eq(device_code_hash))
        .and_where(Expr::col(iden("client_id")).eq(client_id))
        .and_where(Expr::col(iden("status")).eq("approved"))
        .and_where(Expr::col(iden("expires_at")).gt(now));
    db.execute(&Statement::render(&update)).await
}

/// Records the approver's answer: `pending` becomes `approved` or
/// `denied`, with the subject that answered. The `status = 'pending'` and
/// expiry guards make the write single-use and idempotent-safe, and a row
/// count of zero is the honest "this code was not pending" — a mistyped
/// code, one already answered, or one past its expiry.
///
/// # Errors
/// Any database error.
pub(crate) async fn decide(
    db: &dyn Database,
    user_code_hash: &str,
    status: &str,
    approver_subject: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(TABLE))
        .values([
            (iden("status"), status.into()),
            (iden("approver_subject"), approver_subject.into()),
        ])
        .and_where(Expr::col(iden("user_code_hash")).eq(user_code_hash))
        .and_where(Expr::col(iden("status")).eq("pending"))
        .and_where(Expr::col(iden("expires_at")).gt(now));
    db.execute(&Statement::render(&update)).await
}

/// Deletes every row whose `expires_at` has passed. Expired rows are
/// useless to both sides — the client gets `expired_token` and the
/// approver is told the code is gone — so they are simply removed.
/// Idempotent, and safe to run as often as the venture's cron fires.
///
/// # Errors
/// Any database error.
pub(crate) async fn purge_expired(db: &dyn Database, now: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(TABLE))
        .and_where(Expr::col(iden("expires_at")).lte(now));
    db.execute(&Statement::render(&delete)).await
}
