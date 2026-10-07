//! Sea-query data access for `waitlist_entries` (ADR 0004). Positions
//! are assigned **inside** [`confirm_entry`]'s single
//! [`cratefield_core::Database::batch_atomic`] call — the position comes
//! from a per-product counter on `waitlist_position_lock`, incremented by
//! the same single-row UPDATE that takes the lock, so concurrent confirms
//! of one product serialize and never share a position on every engine
//! (atomic on D1, a locked transaction on the sqlite and Postgres
//! adapters; issues #20, #173, #126). A UNIQUE(product, position) index
//! backstops the allocation: a duplicate cannot survive even if the
//! counter ever raced.

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

/// The next position for `product`: read from the per-product counter on
/// `waitlist_position_lock` that [`confirm_entry`]'s take-lock statement
/// has already incremented *inside this batch's transaction* (issue
/// #126). The old `1 + MAX(position)` was computed from the entries
/// table, so its safety rested entirely on the mutex statement before it
/// — and that read could not survive any future code path that read it
/// outside the locked transaction. The counter makes allocation a plain
/// read of a row this transaction holds a write lock on; a duplicate
/// that slips through anyway is killed by the UNIQUE(product, position)
/// index (migration 0006) rather than silently surviving the race.
fn allocated_position_expr(product: &str) -> SimpleExpr {
    let mut counter = Query::select();
    counter
        .expr(Expr::col(iden("next_position")))
        .from(iden("waitlist_position_lock"))
        .and_where(Expr::col(iden("product")).eq(product))
        .limit(1);
    let coalesced = Func::coalesce([
        SimpleExpr::SubQuery(None, Box::new(counter.into_sub_query_statement())),
        0i64.into(),
    ]);
    Expr::expr(coalesced).into()
}

/// Flips a pending entry to confirmed, assigns its dense per-product
/// position and referral code, and credits the referrer — all inside one
/// atomic [`Database::batch_atomic`]. Returns `Ok(false)` when the entry was
/// already confirmed (a replayed link) or when `generation` is not the
/// entry's current one (a token from an earlier lifecycle, issue #127).
///
/// Positions are never recomputed: the counter only ever moves forward,
/// and deleting rows leaves gaps on purpose (issue #11).
///
/// The batch opens with a single-row per-product mutex on
/// `waitlist_position_lock`: an `INSERT … ON CONFLICT DO NOTHING` that
/// materialises the product's counter row, then an `UPDATE … WHERE
/// product = ?` of that one row that both takes the lock and increments
/// the per-product position counter. Concurrent confirms of the product
/// queue on that row (the conflict wait covers the cold-start race
/// where the row does not exist yet), so each one allocates its position
/// only after the previous confirm committed — positions stay distinct
/// and dense, and the flip reads the counter the same transaction just
/// advanced rather than a `MAX` over rows another writer could still
/// touch (issues #20, #173, #126). A UNIQUE(product, position) index
/// (migration 0006) backstops the allocation. Locking exactly one row
/// removes the deadlock the old bulk `UPDATE … WHERE product = ?` over
/// all of `waitlist_entries` caused on Postgres: a multi-row UPDATE
/// takes row locks in executor order, so two confirms could grab the
/// same row set opposite ways and one was killed as the deadlock
/// victim. SQLite and D1 serialize a whole batch on the single
/// connection already; there the mutex statements are ordinary
/// same-transaction writes.
pub(crate) async fn confirm_entry(
    db: &dyn Database,
    row: &WaitlistRow,
    generation: i64,
    now: &str,
    referral_code: &str,
) -> Result<bool, DbError> {
    let mut ensure_lock_row = Query::insert();
    ensure_lock_row
        .into_table(iden("waitlist_position_lock"))
        .columns(["product", "updated_at"])
        .values_panic([row.product.clone().into(), now.to_owned().into()])
        .on_conflict(
            sea_query::OnConflict::column(iden("product"))
                .do_nothing()
                .to_owned(),
        );

    let mut take_lock = Query::update();
    take_lock
        .table(iden("waitlist_position_lock"))
        .value(iden("updated_at"), now)
        // The lock claim and the position allocation are the same
        // statement (issue #126): whoever wins the row lock has also
        // taken the next counter value, so no confirm can observe a
        // counter it did not itself advance.
        .value(
            iden("next_position"),
            Expr::col(iden("next_position")).add(1),
        )
        .and_where(Expr::col(iden("product")).eq(row.product.as_str()));

    let mut flip = Query::update();
    flip.table(iden("waitlist_entries"))
        .values([
            (iden("status"), STATUS_CONFIRMED.into()),
            (iden("confirmed_at"), now.into()),
            (iden("position"), allocated_position_expr(&row.product)),
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
    let mut stmts = vec![
        Statement::render(&ensure_lock_row),
        Statement::render(&take_lock),
    ];
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
    db.batch_atomic(&stmts).await?;
    // The batch reports no per-statement counts, so the answer has to be
    // read back — but the row's *state* is not an answer, because the
    // state a racer observes may be the winner's. Two confirms of one
    // link both find a positioned row, so "does it hold a position"
    // answers `true` twice and the loser sends a second "you are on the
    // list" mail for the one place the person holds.
    //
    // The discriminator is the `referral_code` this call tried to write:
    // the flip stamps it and only the flip does, so it is present exactly
    // when this batch is the one that confirmed the entry. It is safe as
    // the marker because `handlers::referral_code` mints a fresh
    // ULID-derived code per attempt, and `now` is not — it is truncated
    // to the second, so two racers routinely share it.
    Ok(find_by_id(db, &row.id)
        .await?
        .is_some_and(|fresh| fresh.referral_code.as_deref() == Some(referral_code)))
}

pub(crate) async fn list_for_export(
    db: &dyn Database,
    product: Option<&str>,
    fetch: u64,
    offset: u64,
) -> Result<Vec<WaitlistRow>, DbError> {
    let mut query = select_all();
    query.order_by(iden("created_at"), sea_query::Order::Asc);
    // `id` breaks ties among rows sharing a `created_at`, so a page
    // boundary can never skip or repeat an entry (issue #136).
    query.order_by(iden("id"), sea_query::Order::Asc);
    if let Some(product) = product {
        query.and_where(Expr::col(iden("product")).eq(product));
    }
    query.limit(fetch);
    query.offset(offset);
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

    /// Two confirms of ONE entry — a link scanner racing the reader, or a
    /// browser prefetching the `see_other` target while the click lands —
    /// must report `true` exactly once. The guard that keeps them from
    /// both flipping is the flip's own `status = pending AND generation`
    /// predicate, which is what makes the batch atomic; but the batch
    /// reports no counts, so the answer comes from a read taken after it
    /// commits. Reading the row's *state* answers `true` twice — the
    /// loser reads the winner's position — and the caller mails a second
    /// "you are on the list" for the one place the person holds. The
    /// read must discriminate on something only the winning batch wrote.
    #[test]
    fn a_replayed_or_concurrent_confirm_reports_flipped_once() {
        use cratefield_core::Module;
        use std::sync::{Arc, Barrier};

        let module = crate::Waitlist::new().products(["kontinuum"]);
        let db = cratefield_adapter_sqlite::SqliteDatabase::in_memory().expect("db");
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .expect("migrate");
        pollster::block_on(db.execute(&Statement::with_values(
            "INSERT INTO waitlist_entries \
             (id, email, email_normalized, product, status, referrals, created_at) \
             VALUES ('e1', 'a@b.test', 'a@b.test', 'kontinuum', 'pending', 0, \
                     '2026-01-01T00:00:00Z')",
            vec![],
        )))
        .expect("insert");

        let row = pollster::block_on(find_by_id(&db, "e1"))
            .expect("query")
            .expect("row");

        // Concurrent: both batches carry the same generation guard, and
        // each mints its own referral code, so the codes tell the winner
        // apart from the loser after the fact.
        let db = Arc::new(db);
        let gate = Arc::new(Barrier::new(2));
        let racers: Vec<_> = ["CODEAAAA", "CODEBBBB"]
            .into_iter()
            .map(|code| {
                let db = Arc::clone(&db);
                let gate = Arc::clone(&gate);
                let row = row.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    pollster::block_on(confirm_entry(
                        &*db,
                        &row,
                        row.generation,
                        "2026-01-01T00:00:01Z",
                        code,
                    ))
                    .expect("confirm")
                })
            })
            .collect();
        let flipped: Vec<bool> = racers
            .into_iter()
            .map(|racer| racer.join().expect("confirm thread"))
            .collect();
        assert_eq!(
            flipped.iter().filter(|won| **won).count(),
            1,
            "exactly one confirm of one link reports a flip, not both: {flipped:?}"
        );

        // Replayed: the same call again, on its own, is the same shape
        // with no concurrency at all — and the entry already holds a
        // position, so a state-based read would answer `true` here too.
        let replay = pollster::block_on(confirm_entry(
            &*db,
            &row,
            row.generation,
            "2026-01-01T00:00:02Z",
            "CODECCCC",
        ))
        .expect("replay");
        assert!(!replay, "a replayed confirm flips nothing");
    }

    /// Issue #707: a database that confirmed entries before migration
    /// 0004 shipped has no `waitlist_position_lock` row for its product,
    /// so 0006's backfill never seeded the counter and the first confirm
    /// after the upgrade assigned position 1 to a third entry — colliding
    /// with the UNIQUE(product, position) index 0006 added and failing the
    /// commit. 0007 gives those products the counter they should have
    /// had.
    #[test]
    fn confirm_after_upgrade_continues_the_pre_0004_sequence() {
        use crate::{
            MIGRATION_ANONYMISABLE_ENTRY, MIGRATION_ENTRY_GENERATION, MIGRATION_INIT,
            MIGRATION_LOCK_BACKFILL, MIGRATION_MAIL_COOLDOWN, MIGRATION_POSITION_COUNTER,
            MIGRATION_POSITION_LOCK,
        };

        let module = crate::Waitlist::new().products(["kontinuum"]);
        let db = cratefield_adapter_sqlite::SqliteDatabase::in_memory().expect("db");

        // 0001 to 0004: the schema a database that predates the lock table
        // actually has. Entries are inserted by raw SQL because there is no
        // code path that can create them here without also creating the
        // lock row the bug is about.
        db.apply_migrations(
            module.name(),
            &[
                MIGRATION_INIT,
                MIGRATION_ENTRY_GENERATION,
                MIGRATION_MAIL_COOLDOWN,
                MIGRATION_POSITION_LOCK,
            ],
        )
        .expect("migrate to 0004");

        let seed = |id: &str, email: &str, status: &str, position: Option<i64>| {
            let confirmed_at = (position.is_some()).then_some("2026-01-01T00:00:00Z");
            let stmt = Statement::with_values(
                "INSERT INTO waitlist_entries \
                 (id, email, email_normalized, product, status, position, \
                  referrals, created_at, confirmed_at, generation) \
                 VALUES (?, ?, ?, 'kontinuum', ?, ?, 0, '2026-01-01T00:00:00Z', ?, 1)",
                vec![
                    id.into(),
                    email.into(),
                    email.into(),
                    status.into(),
                    position.into(),
                    confirmed_at.into(),
                ],
            );
            pollster::block_on(db.execute(&stmt)).expect("insert");
        };
        seed("old-1", "one@example.com", "confirmed", Some(1));
        seed("old-2", "two@example.com", "confirmed", Some(2));

        let locks = pollster::block_on(db.query(&Statement::new(
            "SELECT product FROM waitlist_position_lock",
        )))
        .expect("select");
        assert!(
            locks.is_empty(),
            "a pre-0004 database has confirmed positions and no lock row"
        );

        db.apply_migrations(
            module.name(),
            &[
                MIGRATION_ANONYMISABLE_ENTRY,
                MIGRATION_POSITION_COUNTER,
                MIGRATION_LOCK_BACKFILL,
            ],
        )
        .expect("migrate to 0007");

        seed("newcomer", "three@example.com", "pending", None);

        let snapshot = pollster::block_on(find_by_id(&db, "newcomer"))
            .expect("query")
            .expect("row");
        assert_eq!(snapshot.position, None, "pending entries hold no position");

        let flipped = pollster::block_on(confirm_entry(
            &db,
            &snapshot,
            snapshot.generation,
            "2026-01-01T00:00:01Z",
            "CODE1234",
        ))
        .expect("confirm after upgrade");
        assert!(flipped, "a pending entry at its generation confirms");

        let confirmed = pollster::block_on(find_by_id(&db, "newcomer"))
            .expect("query")
            .expect("row");
        assert_eq!(
            confirmed.position,
            Some(3),
            "the counter continues the pre-0004 sequence, not position 1"
        );

        let counters = pollster::block_on(db.query(&Statement::new(
            "SELECT next_position FROM waitlist_position_lock WHERE product = 'kontinuum'",
        )))
        .expect("select");
        assert_eq!(
            counters
                .first()
                .and_then(|row| row.get::<i64>("next_position")),
            Some(3),
            "0007 seeded the counter at 2 and the confirm advanced it to 3"
        );
    }
}
