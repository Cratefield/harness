//! Sea-query data access for `waitlist_entries` (ADR 0004). Positions
//! are assigned **inside** [`confirm_entry`]'s single
//! [`factory0_core::Database::batch`] call — the `1 + MAX(position)`
//! subquery runs inside the UPDATE, so concurrent confirms can never
//! share a position (atomic on D1, a transaction on the sqlite adapter).

use factory0_core::{Database, DbError, Row, Statement};
use sea_query::{Alias, Expr, Func, Query, SimpleExpr};

pub(crate) const STATUS_PENDING: &str = "pending";
pub(crate) const STATUS_CONFIRMED: &str = "confirmed";

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
            "product",
            "status",
            "position",
            "referral_code",
            "referred_by",
            "referrals",
            "answers",
            "created_at",
            "confirmed_at",
        ])
        .from(iden("waitlist_entries"));
    select
}

#[derive(Debug, Clone)]
pub(crate) struct WaitlistRow {
    pub id: String,
    pub email: String,
    pub email_normalized: String,
    pub product: String,
    pub status: String,
    pub position: Option<i64>,
    pub referral_code: Option<String>,
    pub referred_by: Option<String>,
    pub referrals: i64,
    pub answers: Option<String>,
    pub created_at: String,
    pub confirmed_at: Option<String>,
}

fn row_from(row: &Row) -> WaitlistRow {
    WaitlistRow {
        id: row.get::<String>("id").unwrap_or_default(),
        email: row.get::<String>("email").unwrap_or_default(),
        email_normalized: row.get::<String>("email_normalized").unwrap_or_default(),
        product: row.get::<String>("product").unwrap_or_default(),
        status: row.get::<String>("status").unwrap_or_default(),
        position: row.get::<i64>("position"),
        referral_code: row.get::<Option<String>>("referral_code").flatten(),
        referred_by: row.get::<Option<String>>("referred_by").flatten(),
        referrals: row.get::<i64>("referrals").unwrap_or(0),
        answers: row.get::<Option<String>>("answers").flatten(),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
        confirmed_at: row.get::<Option<String>>("confirmed_at").flatten(),
    }
}

pub(crate) async fn find_by_id(
    db: &dyn Database,
    id: &str,
) -> Result<Option<WaitlistRow>, DbError> {
    let query = select_all()
        .and_where(Expr::col(iden("id")).eq(id))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(row_from))
}

pub(crate) async fn find_by_email_and_product(
    db: &dyn Database,
    email_normalized: &str,
    product: &str,
) -> Result<Option<WaitlistRow>, DbError> {
    let query = select_all()
        .and_where(Expr::col(iden("email_normalized")).eq(email_normalized))
        .and_where(Expr::col(iden("product")).eq(product))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(row_from))
}

/// A confirmed entry's id for a referral code, same product — `None`
/// makes the ref silently ignored (issue #11).
pub(crate) async fn find_confirmed_by_referral_code(
    db: &dyn Database,
    product: &str,
    referral_code: &str,
) -> Result<Option<WaitlistRow>, DbError> {
    let query = select_all()
        .and_where(Expr::col(iden("product")).eq(product))
        .and_where(Expr::col(iden("referral_code")).eq(referral_code))
        .and_where(Expr::col(iden("status")).eq(STATUS_CONFIRMED))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(row_from))
}

/// Inserts a new row; a concurrent join of the same address+product is
/// not an error (`ON CONFLICT DO NOTHING`), the first mail already went
/// out.
pub(crate) async fn insert_row(db: &dyn Database, row: &WaitlistRow) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden("waitlist_entries"))
        .columns([
            "id",
            "email",
            "email_normalized",
            "product",
            "status",
            "position",
            "referral_code",
            "referred_by",
            "referrals",
            "answers",
            "created_at",
            "confirmed_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.email.clone().into(),
            row.email_normalized.clone().into(),
            row.product.clone().into(),
            row.status.as_str().into(),
            row.position.into(),
            row.referral_code.clone().into(),
            row.referred_by.clone().into(),
            row.referrals.into(),
            row.answers.clone().into(),
            row.created_at.clone().into(),
            row.confirmed_at.clone().into(),
        ])
        .on_conflict(
            sea_query::OnConflict::columns([iden("email_normalized"), iden("product")])
                .do_nothing()
                .to_owned(),
        );
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// Refreshes a pending row for a re-mailed join request: answers and
/// `created_at` (which doubles as the last-join-request timestamp; the
/// table has no `updated_at` column) move to now.
pub(crate) async fn refresh_pending(
    db: &dyn Database,
    id: &str,
    answers: Option<&str>,
    referred_by: Option<&str>,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("waitlist_entries"))
        .values([
            (iden("status"), STATUS_PENDING.into()),
            (iden("answers"), answers.into()),
            (iden("referred_by"), referred_by.into()),
            (iden("created_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("status")).ne(STATUS_CONFIRMED));
    db.execute(&Statement::render(&update)).await
}

/// The next position for `product`: `1 + MAX(position)`, computed inside
/// the UPDATE statement so it is evaluated under the batch's atomicity.
fn next_position_expr(product: &str) -> SimpleExpr {
    let mut subquery = Query::select();
    subquery
        .expr(Func::max(Expr::col((
            iden("waitlist_entries"),
            iden("position"),
        ))))
        .from(iden("waitlist_entries"))
        .and_where(Expr::col((iden("waitlist_entries"), iden("product"))).eq(product));
    let coalesced = Func::coalesce([
        SimpleExpr::SubQuery(None, Box::new(subquery.into_sub_query_statement())),
        0i64.into(),
    ]);
    Expr::expr(coalesced).add(1)
}

/// Flips a pending entry to confirmed, assigns its dense per-product
/// position and referral code, and credits the referrer — all inside one
/// atomic [`Database::batch`]. Returns `Ok(false)` when the entry was
/// already confirmed (a replayed link).
///
/// Positions are never recomputed: the `MAX` only looks forward, and
/// deleting rows leaves gaps on purpose (issue #11).
pub(crate) async fn confirm_entry(
    db: &dyn Database,
    row: &WaitlistRow,
    now: &str,
    referral_code: &str,
) -> Result<bool, DbError> {
    let mut flip = Query::update();
    flip.table(iden("waitlist_entries"))
        .values([
            (iden("status"), STATUS_CONFIRMED.into()),
            (iden("confirmed_at"), now.into()),
            (iden("position"), next_position_expr(&row.product)),
            (iden("referral_code"), referral_code.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(row.id.as_str()))
        .and_where(Expr::col(iden("status")).eq(STATUS_PENDING));

    let mut stmts = vec![Statement::render(&flip)];
    if let Some(referrer) = row.referred_by.as_deref() {
        let mut credit = Query::update();
        credit
            .table(iden("waitlist_entries"))
            .value(iden("referrals"), Expr::col(iden("referrals")).add(1))
            .and_where(Expr::col(iden("id")).eq(referrer));
        stmts.push(Statement::render(&credit));
    }
    db.batch(&stmts).await?;
    // The batch reports no per-statement counts; the row's state is the
    // truth for whether this call flipped anything.
    Ok(find_by_id(db, &row.id)
        .await?
        .is_some_and(|fresh| fresh.position.is_some()))
}

pub(crate) async fn list_for_export(
    db: &dyn Database,
    product: Option<&str>,
) -> Result<Vec<WaitlistRow>, DbError> {
    let mut query = select_all();
    query.order_by(iden("created_at"), sea_query::Order::Asc);
    if let Some(product) = product {
        query.and_where(Expr::col(iden("product")).eq(product));
    }
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(row_from).collect())
}
