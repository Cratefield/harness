//! Sea-query data access for the module's tables (issue #764).
//!
//! Every value is bound, never interpolated. The three statements where a
//! race would matter are all conditional `UPDATE`s judged by the affected
//! row count, the pattern [`store`](cratefield_core::Database)::`execute`
//! makes atomic on every adapter:
//!
//! - [`consume_code`] spends a link code only while it is unconsumed and
//!   unexpired, so a code presented twice links once;
//! - [`decide_action`] moves an action out of `pending` exactly once, so
//!   a replayed tap — or the other button, afterwards — is refused;
//! - [`confirm_action`] is the same single-use move for the web app's
//!   passkey confirmation.
//!
//! Three more conditional `UPDATE`s undo a step whose consequences did
//! not land — the hook after the decision failed, so a redelivery or a
//! retried confirm can run again: [`unconsume_code`],
//! [`revert_tap`](revert_tap) and [`revert_confirm`]. Each is conditional
//! on the row still carrying the state the failed step set, so a rollback
//! never fights a winner and the single-use gate above stays the only
//! gate.

use cratefield_core::{Database, DbError, Row, Statement};
use sea_query::{Alias, Expr, OnConflict, Query};

const CODES: &str = "telegram_link_codes";
const LINKS: &str = "telegram_links";
const ACTIONS: &str = "telegram_actions";

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// An RFC 3339 UTC timestamp with whole seconds — the format every
/// `expires_at` in this module is written and compared in.
pub(crate) fn stamp(at: time::OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// telegram_link_codes

/// Stores a one-time code, by its SHA-256 hash. The code itself never
/// lands in the database: it rides the deep link and the Telegram chat.
///
/// # Errors
/// Any database error.
pub(crate) async fn insert_code(
    db: &dyn Database,
    code_hash: &str,
    subject: &str,
    expires_at: &str,
) -> Result<u64, DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(CODES))
        .columns(["code_hash", "subject", "expires_at", "consumed_at"])
        .values_panic([
            code_hash.into(),
            subject.into(),
            expires_at.into(),
            Option::<String>::None.into(),
        ]);
    db.execute(&Statement::render(&insert)).await
}

/// The single-use spend: consumes the code only while it is unconsumed
/// and unexpired, so the caller that sees one row linked the account and
/// every later presentation of the same code is refused. A row count of
/// zero is the honest "this code is not good" — mistyped, expired, used.
///
/// # Errors
/// Any database error.
pub(crate) async fn consume_code(
    db: &dyn Database,
    code_hash: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(CODES))
        .value(iden("consumed_at"), now)
        .and_where(Expr::col(iden("code_hash")).eq(code_hash))
        .and_where(Expr::col(iden("consumed_at")).is_null())
        .and_where(Expr::col(iden("expires_at")).gt(now));
    db.execute(&Statement::render(&update)).await
}

/// Puts a consumed code back, so the delivery that consumed it — and then
/// failed before it finished — can be retried by a redelivery. Only a
/// consumed row is touched, and only that row: a code that was never
/// spent cannot be conjured into being spent, and one already put back
/// stays put back. The expiry does not move; a rolled-back code still
/// dies at its original ten minutes.
///
/// # Errors
/// Any database error.
pub(crate) async fn unconsume_code(db: &dyn Database, code_hash: &str) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(CODES))
        .value(iden("consumed_at"), Option::<String>::None)
        .and_where(Expr::col(iden("code_hash")).eq(code_hash))
        .and_where(Expr::col(iden("consumed_at")).is_not_null());
    db.execute(&Statement::render(&update)).await
}

/// The subject a code was issued to — read after a successful
/// [`consume_code`], which is the only time it matters.
///
/// # Errors
/// Any database error.
pub(crate) async fn code_subject(
    db: &dyn Database,
    code_hash: &str,
) -> Result<Option<String>, DbError> {
    let mut select = Query::select();
    select
        .column(iden("subject"))
        .from(iden(CODES))
        .and_where(Expr::col(iden("code_hash")).eq(code_hash));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .and_then(|row| row.get("subject")))
}

// ---------------------------------------------------------------------------
// telegram_links

/// The subject a Telegram user already stands behind, if any — the
/// "already linked to a different account" check.
///
/// # Errors
/// Any database error.
pub(crate) async fn subject_of_telegram_user(
    db: &dyn Database,
    telegram_user_id: i64,
) -> Result<Option<String>, DbError> {
    let mut select = Query::select();
    select
        .column(iden("subject"))
        .from(iden(LINKS))
        .and_where(Expr::col(iden("telegram_user_id")).eq(telegram_user_id));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .and_then(|row| row.get("subject")))
}

/// The chat a subject's account is wired to: the Telegram user and the
/// chat the `/start` came from. Everything that sends — the link reply,
/// an action prompt, the notifications channel — resolves the recipient
/// here, the way mail's job carries an account and not an address.
///
/// # Errors
/// Any database error.
pub(crate) async fn link_of_subject(
    db: &dyn Database,
    subject: &str,
) -> Result<Option<(i64, i64)>, DbError> {
    let mut select = Query::select();
    select
        .columns(["telegram_user_id", "chat_id"])
        .from(iden(LINKS))
        .and_where(Expr::col(iden("subject")).eq(subject));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(|row: &Row| {
            (
                row.get::<i64>("telegram_user_id").unwrap_or_default(),
                row.get::<i64>("chat_id").unwrap_or_default(),
            )
        }))
}

/// Upserts the link: re-linking moves the subject's row to the new
/// Telegram user and chat. (The other direction — one Telegram user
/// behind two subjects — is refused by the caller, which checks
/// [`subject_of_telegram_user`] first; the UNIQUE constraint here is what
/// stops a race, by failing the write.)
///
/// # Errors
/// Any database error.
pub(crate) async fn upsert_link(
    db: &dyn Database,
    subject: &str,
    telegram_user_id: i64,
    chat_id: i64,
    linked_at: &str,
) -> Result<u64, DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(LINKS))
        .columns(["subject", "telegram_user_id", "chat_id", "linked_at"])
        .values_panic([
            subject.into(),
            telegram_user_id.into(),
            chat_id.into(),
            linked_at.into(),
        ]);
    insert.on_conflict(
        OnConflict::column(iden("subject"))
            .update_columns(["telegram_user_id", "chat_id", "linked_at"])
            .to_owned(),
    );
    db.execute(&Statement::render(&insert)).await
}

/// Removes a subject's link. Idempotent: the row count is returned for
/// the log, not for a decision.
///
/// # Errors
/// Any database error.
pub(crate) async fn delete_link(db: &dyn Database, subject: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(LINKS))
        .and_where(Expr::col(iden("subject")).eq(subject));
    db.execute(&Statement::render(&delete)).await
}

// ---------------------------------------------------------------------------
// telegram_actions

/// One consent request, as the handlers see it. The `action_id` is not
/// carried: the tap opens it from the token, and the confirm route reads
/// it off the path.
pub(crate) struct ActionRow {
    pub(crate) subject: String,
    pub(crate) action: String,
    pub(crate) value_moving: bool,
    pub(crate) status: String,
    pub(crate) expires_at: String,
}

fn row_from(row: &Row) -> ActionRow {
    ActionRow {
        subject: row.get("subject").unwrap_or_default(),
        action: row.get("action").unwrap_or_default(),
        value_moving: row.get::<i64>("value_moving").unwrap_or_default() != 0,
        status: row.get("status").unwrap_or_default(),
        expires_at: row.get("expires_at").unwrap_or_default(),
    }
}

/// Records a fresh `pending` action.
///
/// # Errors
/// Any database error.
pub(crate) async fn insert_action(
    db: &dyn Database,
    action_id: &str,
    subject: &str,
    action: &str,
    value_moving: bool,
    expires_at: &str,
    created_at: &str,
) -> Result<u64, DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(ACTIONS))
        .columns([
            "action_id",
            "subject",
            "action",
            "value_moving",
            "status",
            "expires_at",
            "created_at",
        ])
        .values_panic([
            action_id.into(),
            subject.into(),
            action.into(),
            i64::from(value_moving).into(),
            "pending".into(),
            expires_at.into(),
            created_at.into(),
        ]);
    db.execute(&Statement::render(&insert)).await
}

/// Looks one action up. Expired rows still read — the caller decides what
/// an expired row is allowed to do, which is nothing.
///
/// # Errors
/// Any database error.
pub(crate) async fn action_by_id(
    db: &dyn Database,
    action_id: &str,
) -> Result<Option<ActionRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(["subject", "action", "value_moving", "status", "expires_at"])
        .from(iden(ACTIONS))
        .and_where(Expr::col(iden("action_id")).eq(action_id));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(row_from))
}

/// The one decision a pending action gets: `status` becomes `to_status`
/// only while the row is still `pending` and unexpired, so the tap that
/// sees one row owns the decision and every later tap — a replay, or the
/// other button — is refused. `decided_at` rides along.
///
/// # Errors
/// Any database error.
pub(crate) async fn decide_action(
    db: &dyn Database,
    action_id: &str,
    to_status: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(ACTIONS))
        .values([
            (iden("status"), to_status.into()),
            (iden("decided_at"), now.into()),
        ])
        .and_where(Expr::col(iden("action_id")).eq(action_id))
        .and_where(Expr::col(iden("status")).eq("pending"))
        .and_where(Expr::col(iden("expires_at")).gt(now));
    db.execute(&Statement::render(&update)).await
}

/// The passkey half: `awaiting_passkey` becomes `approved` exactly once,
/// and only from the web app route that proved a fresh ceremony. A
/// Telegram tap can put a row **into** `awaiting_passkey`; nothing but
/// this statement — and therefore nothing but the `StepUp` check in front
/// of it — moves value past it.
///
/// # Errors
/// Any database error.
pub(crate) async fn confirm_action(
    db: &dyn Database,
    action_id: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(ACTIONS))
        .values([
            (iden("status"), "approved".into()),
            (iden("decided_at"), now.into()),
        ])
        .and_where(Expr::col(iden("action_id")).eq(action_id))
        .and_where(Expr::col(iden("status")).eq("awaiting_passkey"))
        .and_where(Expr::col(iden("expires_at")).gt(now));
    db.execute(&Statement::render(&update)).await
}

/// Puts a confirmed action back into `awaiting_passkey`, so the confirm
/// request whose hook failed can be retried by the caller. Conditional on
/// the row still carrying the status this route set: if anything has
/// moved it since, the statement touches nothing and the state that
/// replaced the confirmation stands. `decided_at` is cleared with the
/// status — a row back in `awaiting_passkey` has not been decided.
///
/// # Errors
/// Any database error.
pub(crate) async fn revert_confirm(db: &dyn Database, action_id: &str) -> Result<u64, DbError> {
    revert_action_to(db, action_id, "approved", "awaiting_passkey").await
}

/// Puts a tapped action back into `pending`, so the delivery whose hook
/// failed can be retried by Telegram's redelivery. `decided_status` is
/// what the tap set — `denied`, or `approved` for a harmless action; a
/// value-moving arm (`awaiting_passkey`) fires no hook and is never
/// rolled back. Conditional on the row still carrying that status, the
/// same shape as [`revert_confirm`].
///
/// # Errors
/// Any database error.
pub(crate) async fn revert_tap(
    db: &dyn Database,
    action_id: &str,
    decided_status: &str,
) -> Result<u64, DbError> {
    revert_action_to(db, action_id, decided_status, "pending").await
}

/// The shared shape of the two rollbacks: `from_status` becomes
/// `to_status`, `decided_at` clears, and only while the row is still in
/// `from_status`. The single-use gate is untouched — this runs *after* a
/// decision was made and is itself conditional, so two racing deliveries
/// still move the row out of `pending` exactly once.
///
/// # Errors
/// Any database error.
async fn revert_action_to(
    db: &dyn Database,
    action_id: &str,
    from_status: &str,
    to_status: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(ACTIONS))
        .values([
            (iden("status"), to_status.into()),
            (iden("decided_at"), Option::<String>::None.into()),
        ])
        .and_where(Expr::col(iden("action_id")).eq(action_id))
        .and_where(Expr::col(iden("status")).eq(from_status));
    db.execute(&Statement::render(&update)).await
}
