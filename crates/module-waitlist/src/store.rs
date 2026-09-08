//! Sea-query data access for `waitlist_entries` (ADR 0004). Positions
//! are assigned **inside** [`confirm_entry`]'s single
//! [`cratefield_core::Database::batch`] call — the `1 + MAX(position)`
//! subquery runs inside the UPDATE, under a per-product lock statement
//! that serializes concurrent confirms of one product on every engine
//! (atomic on D1, a locked transaction on the sqlite and Postgres
//! adapters; issue #20).

use cratefield_core::{Database, DbError, Row, Statement};
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
            "generation",
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
    pub generation: i64,
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
        generation: row.get::<i64>("generation").unwrap_or(1),
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
            "generation",
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
            row.generation.into(),
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
///
/// Issue #127: same generation rule as module-email-signup — re-entering
/// pending from another state would bump `generation` atomically (the
/// `CASE` sees the row's state at write time), invalidating confirm
/// tokens from an earlier lifecycle. Today's state machine never leaves
/// pending through this path (the `status <> 'confirmed'` guard plus the
/// handler's early return on confirmed rows), so a re-mail keeps its
/// generation and links already in flight stay valid.
pub(crate) async fn refresh_pending(
    db: &dyn Database,
    id: &str,
    answers: Option<&str>,
    referred_by: Option<&str>,
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
        .table(iden("waitlist_entries"))
        .values([
            (iden("status"), STATUS_PENDING.into()),
            (iden("generation"), generation),
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
/// already confirmed (a replayed link) or when `generation` is not the
/// entry's current one (a token from an earlier lifecycle, issue #127).
///
/// Positions are never recomputed: the `MAX` only looks forward, and
/// deleting rows leaves gaps on purpose (issue #11).
///
/// The batch opens with a per-product lock statement — `UPDATE … SET
/// referrals = referrals WHERE product = ?` — that changes no value but,
/// on Postgres, takes the row locks of every entry in the product before
/// the position `MAX` runs, so concurrent confirms of the same product
/// serialize instead of each reading a pre-commit `MAX` and sharing a
/// position (the parity suite, issue #20). SQLite and D1 serialize a
/// whole batch on the single connection already; there the statement is
/// a value-neutral no-op.
pub(crate) async fn confirm_entry(
    db: &dyn Database,
    row: &WaitlistRow,
    generation: i64,
    now: &str,
    referral_code: &str,
) -> Result<bool, DbError> {
    let mut lock = Query::update();
    lock.table(iden("waitlist_entries"))
        .value(iden("referrals"), Expr::col(iden("referrals")))
        .and_where(Expr::col(iden("product")).eq(row.product.as_str()));

    let mut flip = Query::update();
    flip.table(iden("waitlist_entries"))
        .values([
            (iden("status"), STATUS_CONFIRMED.into()),
            (iden("confirmed_at"), now.into()),
            (iden("position"), next_position_expr(&row.product)),
            (iden("referral_code"), referral_code.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(row.id.as_str()))
        .and_where(Expr::col(iden("status")).eq(STATUS_PENDING))
        .and_where(Expr::col(iden("generation")).eq(generation));

    // The credit runs BEFORE the flip and carries the same guard: it applies
    // only while this entry is still pending at this generation, i.e. only
    // when this batch is the one that confirms it. Ordered the other way the
    // credit cannot tell whether the flip was its own, and a replayed or
    // interleaved confirm credits the referrer again for one referral.
    let mut stmts = vec![Statement::render(&lock)];
    if let Some(referrer) = row.referred_by.as_deref() {
        let mut still_pending = Query::select();
        still_pending
            .expr(Expr::val(1))
            .from(iden("waitlist_entries"))
            .and_where(Expr::col(iden("id")).eq(row.id.as_str()))
            .and_where(Expr::col(iden("status")).eq(STATUS_PENDING))
            .and_where(Expr::col(iden("generation")).eq(generation));

        let mut credit = Query::update();
        credit
            .table(iden("waitlist_entries"))
            .value(iden("referrals"), Expr::col(iden("referrals")).add(1))
            .and_where(Expr::col(iden("id")).eq(referrer))
            .and_where(Expr::exists(still_pending));
        stmts.push(Statement::render(&credit));
    }
    stmts.push(Statement::render(&flip));
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

/// Hard-deletes pending entries whose last join request (`created_at`)
/// is older than the cutoff; confirmed entries keep their positions.
pub(crate) async fn purge_pending_older_than(
    db: &dyn Database,
    cutoff_iso: &str,
) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden("waitlist_entries"))
        .and_where(Expr::col(iden("status")).eq(STATUS_PENDING))
        .and_where(Expr::col(iden("created_at")).lt(cutoff_iso));
    db.execute(&Statement::render(&delete)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::{Module, Statement};

    /// A true interleave hands both callers a snapshot that still says
    /// "pending": each read the row before either wrote. The flip is
    /// guarded, so only one applies; the credit must carry the same guard,
    /// or the referrer is paid twice for one referral. A token from the
    /// wrong generation never flips at all (issue #127).
    #[test]
    fn replayed_confirm_credits_the_referrer_once() {
        let module = crate::Waitlist::new().products(["kontinuum"]);
        let db = cratefield_adapter_sqlite::SqliteDatabase::in_memory().expect("db");
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .expect("migrate");

        let insert = |id: &str, email: &str, status: &str, referred_by: Option<&str>| {
            let stmt = Statement::with_values(
                "INSERT INTO waitlist_entries \
                 (id, email, email_normalized, product, status, referrals, created_at, referred_by) \
                 VALUES (?, ?, ?, 'kontinuum', ?, 0, '2026-01-01T00:00:00Z', ?)",
                vec![
                    id.into(),
                    email.into(),
                    email.into(),
                    status.into(),
                    referred_by.into(),
                ],
            );
            pollster::block_on(db.execute(&stmt)).expect("insert");
        };
        insert("referrer", "ref@example.com", "confirmed", None);
        insert("friend", "friend@example.com", "pending", Some("referrer"));

        let snapshot = pollster::block_on(find_by_id(&db, "friend"))
            .expect("query")
            .expect("row");
        assert_eq!(snapshot.generation, 1);

        let stale = pollster::block_on(confirm_entry(
            &db,
            &snapshot,
            snapshot.generation + 1,
            "2026-01-01T00:00:01Z",
            "CODE1234",
        ))
        .expect("confirm");
        assert!(!stale, "a token from another generation flips nothing");

        for _ in 0..2 {
            pollster::block_on(confirm_entry(
                &db,
                &snapshot,
                snapshot.generation,
                "2026-01-01T00:00:01Z",
                "CODE1234",
            ))
            .expect("confirm");
        }

        let rows = pollster::block_on(db.query(&Statement::with_values(
            "SELECT referrals FROM waitlist_entries WHERE id = ?",
            vec!["referrer".into()],
        )))
        .expect("select");
        let referrals = rows
            .first()
            .and_then(|row| row.get::<i64>("referrals"))
            .expect("referrals");
        assert_eq!(referrals, 1, "one referral, one credit");
    }
}
