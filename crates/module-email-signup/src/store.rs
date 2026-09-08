//! Sea-query data access for the `subscribers` table (ADR 0004: queries
//! are built, migrations are SQL). All timestamps are fixed-width
//! `YYYY-MM-DDTHH:MM:SSZ` strings, so lexicographic order is
//! chronological order.
//!
//! Subscription state machine (issue #127). `generation` identifies one
//! subscription lifecycle; confirmation tokens bind to `(id, generation)`
//! and every transition is an atomic conditional update:
//!
//! ```text
//! (absent) ──signup──▶ pending(1)
//! pending(N) ──signup (re-mail)──▶ pending(N)          generation kept:
//!                                                        in-flight links stay valid
//! pending(N) ──confirm(gen N)──▶ confirmed(N)          token consumed
//! pending | confirmed ──unsubscribe──▶ unsubscribed(N)
//! unsubscribed(N) ──signup──▶ pending(N+1)             new generation: every
//!                                                        token with gen ≤ N dies
//! confirmed ──signup──▶ confirmed                      never reset, never re-mailed
//! deleted ──signup──▶ pending(1) under a NEW id
//! ```
//!
//! The generation bump lives inside the refresh UPDATE's `CASE`, so it is
//! evaluated against the row's state at write time: no interleaving of a
//! concurrent unsubscribe can refresh an unsubscribed row back to pending
//! without bumping.

use cratefield_core::{Database, DbError, Row, Statement};
use sea_query::{Alias, Expr, Query, SimpleExpr};

pub(crate) const STATUS_PENDING: &str = "pending";
pub(crate) const STATUS_CONFIRMED: &str = "confirmed";
pub(crate) const STATUS_UNSUBSCRIBED: &str = "unsubscribed";

pub(crate) const ALL_STATUSES: [&str; 3] = [STATUS_PENDING, STATUS_CONFIRMED, STATUS_UNSUBSCRIBED];

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

fn select_all() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "email",
            "email_normalized",
            "status",
            "generation",
            "source",
            "locale",
            "confirmed_at",
            "unsubscribed_at",
            "unsubscribe_token",
            "created_at",
            "updated_at",
        ])
        .from(iden("subscribers"));
    select
}

#[derive(Debug, Clone)]
pub(crate) struct SubscriberRow {
    pub id: String,
    pub email: String,
    pub email_normalized: String,
    pub status: String,
    pub generation: i64,
    pub source: Option<String>,
    pub locale: Option<String>,
    pub confirmed_at: Option<String>,
    pub unsubscribed_at: Option<String>,
    /// The current revocable per-subscription unsubscribe token
    /// (issue #137). `None` until the first mail minted after the
    /// migration; rotating it retires every older opaque link.
    pub unsubscribe_token: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn row_from(row: &Row) -> SubscriberRow {
    SubscriberRow {
        id: row.get::<String>("id").unwrap_or_default(),
        email: row.get::<String>("email").unwrap_or_default(),
        email_normalized: row.get::<String>("email_normalized").unwrap_or_default(),
        status: row.get::<String>("status").unwrap_or_default(),
        generation: row.get::<i64>("generation").unwrap_or(1),
        source: row.get::<Option<String>>("source").flatten(),
        locale: row.get::<Option<String>>("locale").flatten(),
        confirmed_at: row.get::<Option<String>>("confirmed_at").flatten(),
        unsubscribed_at: row.get::<Option<String>>("unsubscribed_at").flatten(),
        unsubscribe_token: row.get::<Option<String>>("unsubscribe_token").flatten(),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
        updated_at: row.get::<String>("updated_at").unwrap_or_default(),
    }
}

pub(crate) async fn find_by_normalized_email(
    db: &dyn Database,
    email_normalized: &str,
) -> Result<Option<SubscriberRow>, DbError> {
    let query = select_all()
        .and_where(Expr::col(iden("email_normalized")).eq(email_normalized))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(row_from))
}

pub(crate) async fn find_by_id(
    db: &dyn Database,
    id: &str,
) -> Result<Option<SubscriberRow>, DbError> {
    let query = select_all()
        .and_where(Expr::col(iden("id")).eq(id))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(row_from))
}

/// Inserts a new row; a concurrent insert of the same address is not an
/// error (`ON CONFLICT DO NOTHING`), the first mail already went out.
pub(crate) async fn insert_row(db: &dyn Database, row: &SubscriberRow) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden("subscribers"))
        .columns([
            "id",
            "email",
            "email_normalized",
            "status",
            "generation",
            "source",
            "locale",
            "confirmed_at",
            "unsubscribed_at",
            "unsubscribe_token",
            "created_at",
            "updated_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.email.clone().into(),
            row.email_normalized.clone().into(),
            row.status.as_str().into(),
            row.generation.into(),
            row.source.clone().into(),
            row.locale.clone().into(),
            row.confirmed_at.clone().into(),
            row.unsubscribed_at.clone().into(),
            row.unsubscribe_token.clone().into(),
            row.created_at.clone().into(),
            row.updated_at.clone().into(),
        ])
        .on_conflict(
            sea_query::OnConflict::columns([iden("email_normalized")])
                .do_nothing()
                .to_owned(),
        );
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// Refreshes a pending/unsubscribed row back to `pending`. Rows that were
/// confirmed in the meantime are left alone (`0` returned).
///
/// Issue #127: re-entering pending from any other state is a new
/// subscription generation — the `CASE` bumps `generation` atomically
/// against the row's state at write time, invalidating every confirm
/// token signed for an earlier generation. A pending row keeps its
/// generation (a re-mail is the same lifecycle), so links already in
/// flight stay valid.
/// Also rotates the revocable unsubscribe token (issue #137): the mail
/// this refresh accompanies carries the new opaque link, and the next
/// mail will carry the next one.
pub(crate) async fn refresh_to_pending(
    db: &dyn Database,
    id: &str,
    source: Option<&str>,
    locale: Option<&str>,
    unsubscribe_token: &str,
    now: &str,
) -> Result<u64, DbError> {
    let generation = SimpleExpr::Case(Box::new(
        Expr::case(
            Expr::col(iden("status")).ne(STATUS_PENDING),
            Expr::col(iden("generation")).add(1),
        )
        .finally(Expr::col(iden("generation"))),
    ));
    let mut update = Query::update();
    update
        .table(iden("subscribers"))
        .values([
            (iden("status"), STATUS_PENDING.into()),
            (iden("generation"), generation),
            (iden("source"), source.into()),
            (iden("locale"), locale.into()),
            (iden("confirmed_at"), Option::<String>::None.into()),
            (iden("unsubscribed_at"), Option::<String>::None.into()),
            (iden("unsubscribe_token"), unsubscribe_token.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("status")).ne(STATUS_CONFIRMED));
    db.execute(&Statement::render(&update)).await
}

/// The row the current opaque unsubscribe token belongs to (issue #137).
pub(crate) async fn find_by_unsubscribe_token(
    db: &dyn Database,
    token: &str,
) -> Result<Option<SubscriberRow>, DbError> {
    let query = select_all()
        .and_where(Expr::col(iden("unsubscribe_token")).eq(token))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(row_from))
}

/// Backfills the opaque token onto a row that predates the #137 mail
/// path, so a welcome mail can always carry a revocable link.
pub(crate) async fn rotate_unsubscribe_token(
    db: &dyn Database,
    id: &str,
    token: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("subscribers"))
        .values([
            (iden("unsubscribe_token"), token.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

/// Flips a pending row to confirmed; `0` when already confirmed, gone, or
/// when `generation` does not match the row's current one (a token from
/// an earlier subscription lifecycle, issue #127). The conditional update
/// is the atomic consume: exactly one caller per `(id, generation)` sees
/// `1`.
pub(crate) async fn confirm(
    db: &dyn Database,
    id: &str,
    generation: i64,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("subscribers"))
        .values([
            (iden("status"), STATUS_CONFIRMED.into()),
            (iden("confirmed_at"), now.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("status")).eq(STATUS_PENDING))
        .and_where(Expr::col(iden("generation")).eq(generation));
    db.execute(&Statement::render(&update)).await
}

/// Flips to unsubscribed; `0` when already unsubscribed or gone.
pub(crate) async fn unsubscribe(db: &dyn Database, id: &str, now: &str) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("subscribers"))
        .values([
            (iden("status"), STATUS_UNSUBSCRIBED.into()),
            (iden("unsubscribed_at"), now.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("status")).ne(STATUS_UNSUBSCRIBED));
    db.execute(&Statement::render(&update)).await
}

pub(crate) async fn delete_by_id(db: &dyn Database, id: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden("subscribers"))
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&delete)).await
}

pub(crate) async fn purge_pending_older_than(
    db: &dyn Database,
    cutoff_iso: &str,
) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden("subscribers"))
        .and_where(Expr::col(iden("status")).eq(STATUS_PENDING))
        .and_where(Expr::col(iden("updated_at")).lt(cutoff_iso));
    db.execute(&Statement::render(&delete)).await
}

pub(crate) async fn list_for_export(
    db: &dyn Database,
    status: Option<&str>,
) -> Result<Vec<SubscriberRow>, DbError> {
    let mut query = select_all();
    query.order_by(iden("created_at"), sea_query::Order::Asc);
    if let Some(status) = status {
        query.and_where(Expr::col(iden("status")).eq(status));
    }
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(row_from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::Module;

    fn migrated_db() -> cratefield_adapter_sqlite::SqliteDatabase {
        let module = crate::EmailSignup::new();
        let db = cratefield_adapter_sqlite::SqliteDatabase::in_memory().expect("db");
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .expect("migrate");
        db
    }

    fn seed(
        db: &cratefield_adapter_sqlite::SqliteDatabase,
        id: &str,
        status: &str,
        generation: i64,
    ) {
        let stmt = Statement::with_values(
            "INSERT INTO subscribers \
             (id, email, email_normalized, status, generation, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
                .to_owned(),
            vec![
                id.into(),
                format!("{id}@example.com").into(),
                format!("{id}@example.com").into(),
                status.into(),
                generation.into(),
            ],
        );
        pollster::block_on(db.execute(&stmt)).expect("seed");
    }

    fn state(db: &cratefield_adapter_sqlite::SqliteDatabase, id: &str) -> (String, i64) {
        let row = pollster::block_on(find_by_id(db, id))
            .expect("query")
            .expect("row");
        (row.status, row.generation)
    }

    #[test]
    fn refresh_bumps_generation_only_when_re_entering_pending() {
        let db = migrated_db();
        seed(&db, "pending-row", STATUS_PENDING, 5);
        seed(&db, "unsubscribed-row", STATUS_UNSUBSCRIBED, 5);
        seed(&db, "confirmed-row", STATUS_CONFIRMED, 5);

        let now = "2026-01-02T00:00:00Z";
        pollster::block_on(refresh_to_pending(
            &db,
            "pending-row",
            None,
            None,
            "tok-1",
            now,
        ))
        .expect("ok");
        pollster::block_on(refresh_to_pending(
            &db,
            "unsubscribed-row",
            None,
            None,
            "tok-2",
            now,
        ))
        .expect("ok");
        pollster::block_on(refresh_to_pending(
            &db,
            "confirmed-row",
            None,
            None,
            "tok-3",
            now,
        ))
        .expect("ok");

        assert_eq!(
            state(&db, "pending-row"),
            (STATUS_PENDING.to_owned(), 5),
            "a pending re-mail is the same lifecycle: in-flight tokens stay valid"
        );
        assert_eq!(
            state(&db, "unsubscribed-row"),
            (STATUS_PENDING.to_owned(), 6),
            "resubscription is a new generation: old tokens die"
        );
        assert_eq!(
            state(&db, "confirmed-row"),
            (STATUS_CONFIRMED.to_owned(), 5),
            "signup never resets a confirmed row"
        );
    }

    #[test]
    fn confirm_consumes_exactly_one_generation() {
        let db = migrated_db();
        seed(&db, "row", STATUS_PENDING, 2);

        let now = "2026-01-02T00:00:00Z";
        let stale = pollster::block_on(confirm(&db, "row", 1, now)).expect("ok");
        assert_eq!(stale, 0, "a token from generation 1 matches no row");
        assert_eq!(state(&db, "row"), (STATUS_PENDING.to_owned(), 2));

        let current = pollster::block_on(confirm(&db, "row", 2, now)).expect("ok");
        assert_eq!(current, 1, "the current generation confirms");
        assert_eq!(state(&db, "row"), (STATUS_CONFIRMED.to_owned(), 2));

        let replay = pollster::block_on(confirm(&db, "row", 2, now)).expect("ok");
        assert_eq!(replay, 0, "confirm is single-use");
    }
}
