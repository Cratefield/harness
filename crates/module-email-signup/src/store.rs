//! Sea-query data access for the `subscribers` table (ADR 0004: queries
//! are built, migrations are SQL). All timestamps are fixed-width
//! `YYYY-MM-DDTHH:MM:SSZ` strings, so lexicographic order is
//! chronological order.

use factory0_core::{Database, DbError, Row, Statement};
use sea_query::{Alias, Expr, Query};

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
            "source",
            "locale",
            "confirmed_at",
            "unsubscribed_at",
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
    pub source: Option<String>,
    pub locale: Option<String>,
    pub confirmed_at: Option<String>,
    pub unsubscribed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn row_from(row: &Row) -> SubscriberRow {
    SubscriberRow {
        id: row.get::<String>("id").unwrap_or_default(),
        email: row.get::<String>("email").unwrap_or_default(),
        email_normalized: row.get::<String>("email_normalized").unwrap_or_default(),
        status: row.get::<String>("status").unwrap_or_default(),
        source: row.get::<Option<String>>("source").flatten(),
        locale: row.get::<Option<String>>("locale").flatten(),
        confirmed_at: row.get::<Option<String>>("confirmed_at").flatten(),
        unsubscribed_at: row.get::<Option<String>>("unsubscribed_at").flatten(),
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
            "source",
            "locale",
            "confirmed_at",
            "unsubscribed_at",
            "created_at",
            "updated_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.email.clone().into(),
            row.email_normalized.clone().into(),
            row.status.as_str().into(),
            row.source.clone().into(),
            row.locale.clone().into(),
            row.confirmed_at.clone().into(),
            row.unsubscribed_at.clone().into(),
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
pub(crate) async fn refresh_to_pending(
    db: &dyn Database,
    id: &str,
    source: Option<&str>,
    locale: Option<&str>,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("subscribers"))
        .values([
            (iden("status"), STATUS_PENDING.into()),
            (iden("source"), source.into()),
            (iden("locale"), locale.into()),
            (iden("confirmed_at"), Option::<String>::None.into()),
            (iden("unsubscribed_at"), Option::<String>::None.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("status")).ne(STATUS_CONFIRMED));
    db.execute(&Statement::render(&update)).await
}

/// Flips a pending row to confirmed; `0` when already confirmed or gone.
pub(crate) async fn confirm(db: &dyn Database, id: &str, now: &str) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("subscribers"))
        .values([
            (iden("status"), STATUS_CONFIRMED.into()),
            (iden("confirmed_at"), now.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("status")).eq(STATUS_PENDING));
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

pub(crate) async fn delete_by_normalized_email(
    db: &dyn Database,
    email_normalized: &str,
) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden("subscribers"))
        .and_where(Expr::col(iden("email_normalized")).eq(email_normalized));
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
