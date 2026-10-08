//! Sea-query data access for the two wallet tables (issue #835).
//!
//! Every value is bound, never interpolated. The nonce consume is the one
//! replay check: a single guarded `UPDATE … WHERE consumed_at IS NULL`, and
//! the row count decides which caller won. The `wallet_links` unique index on
//! `(chain, address)` is the one-wallet one-account rule; `insert_link`
//! returns whether the insert won or an existing link belongs to the same
//! account (idempotent) or a different one (conflict).

use cratefield_core::{Database, DbError, Row, Statement};
use sea_query::{Alias, Expr, Query};

const NONCES: &str = "wallet_nonces";
const LINKS: &str = "wallet_links";

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

// ---------------------------------------------------------------------------
// Nonces

/// A nonce row, as the verify handler needs it: who it was minted for, on
/// which chain family, and for which chain id. The expiry is not carried —
/// the guarded consume below re-asserts it in the `WHERE` clause, so a row is
/// never accepted because a stale copy of its expiry said so.
pub(crate) struct NonceRow {
    pub(crate) account_id: String,
    pub(crate) chain: String,
    pub(crate) chain_id: String,
}

fn nonce_from(row: &Row) -> NonceRow {
    NonceRow {
        account_id: row.get("account_id").unwrap_or_default(),
        chain: row.get("chain").unwrap_or_default(),
        chain_id: row.get("chain_id").unwrap_or_default(),
    }
}

/// Inserts a fresh single-use nonce, bound to the chain id it was minted for.
pub(crate) async fn insert_nonce(
    db: &dyn Database,
    nonce: &str,
    account_id: &str,
    chain: &str,
    chain_id: &str,
    now: &str,
    expires_at: &str,
) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(NONCES))
        .columns([
            "nonce",
            "account_id",
            "chain",
            "chain_id",
            "created_at",
            "expires_at",
        ])
        .values_panic([
            nonce.into(),
            account_id.into(),
            chain.into(),
            chain_id.into(),
            now.into(),
            expires_at.into(),
        ]);
    db.execute(&Statement::render(&insert)).await.map(|_| ())
}

/// Finds a nonce row by its value. Returns `None` when no such nonce exists.
pub(crate) async fn find_nonce(
    db: &dyn Database,
    nonce: &str,
) -> Result<Option<NonceRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(["account_id", "chain", "chain_id"])
        .from(iden(NONCES))
        .and_where(Expr::col(iden("nonce")).eq(nonce));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(nonce_from))
}

/// The single-use consume: sets `consumed_at` only when the nonce is still
/// unconsumed and unexpired. A row count of one means the caller won; zero
/// means the nonce was already consumed, expired, or unknown — all of which
/// the handler refuses.
pub(crate) async fn consume_nonce(
    db: &dyn Database,
    nonce: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(NONCES))
        .value(iden("consumed_at"), now)
        .and_where(Expr::col(iden("nonce")).eq(nonce))
        .and_where(Expr::col(iden("consumed_at")).is_null())
        .and_where(Expr::col(iden("expires_at")).gt(now));
    db.execute(&Statement::render(&update)).await
}

/// Deletes every nonce past its expiry. Idempotent, safe to run on every
/// cron tick.
pub(crate) async fn purge_expired_nonces(db: &dyn Database, now: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(NONCES))
        .and_where(Expr::col(iden("expires_at")).lte(now));
    db.execute(&Statement::render(&delete)).await
}

// ---------------------------------------------------------------------------
// Links

/// A linked wallet, as the handlers need it.
pub(crate) struct LinkRow {
    pub(crate) id: String,
    pub(crate) account_id: String,
    pub(crate) chain: String,
    pub(crate) address: String,
    pub(crate) linked_at: String,
}

fn link_from(row: &Row) -> LinkRow {
    LinkRow {
        id: row.get("id").unwrap_or_default(),
        account_id: row.get("account_id").unwrap_or_default(),
        chain: row.get("chain").unwrap_or_default(),
        address: row.get("address").unwrap_or_default(),
        linked_at: row.get("linked_at").unwrap_or_default(),
    }
}

/// The outcome of trying to insert a link.
pub(crate) enum InsertOutcome {
    /// The link was inserted.
    Created(LinkRow),
    /// A link already existed for the same account — idempotent ok.
    SameAccount(LinkRow),
    /// A link already existed for a different account — 409.
    DifferentAccount,
}

/// Inserts a link, or reports an existing one. The `UNIQUE (chain, address)`
/// index is the one-wallet one-account rule: a conflict is resolved by
/// looking up the existing row and checking its `account_id`.
pub(crate) async fn insert_link(
    db: &dyn Database,
    id: &str,
    account_id: &str,
    chain: &str,
    address: &str,
    now: &str,
) -> Result<InsertOutcome, DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(LINKS))
        .columns(["id", "account_id", "chain", "address", "linked_at"])
        .values_panic([
            id.into(),
            account_id.into(),
            chain.into(),
            address.into(),
            now.into(),
        ])
        .on_conflict(
            sea_query::OnConflict::columns([iden("chain"), iden("address")])
                .do_nothing()
                .to_owned(),
        );
    let inserted = db.execute(&Statement::render(&insert)).await?;
    if inserted == 1 {
        return Ok(InsertOutcome::Created(LinkRow {
            id: id.to_owned(),
            account_id: account_id.to_owned(),
            chain: chain.to_owned(),
            address: address.to_owned(),
            linked_at: now.to_owned(),
        }));
    }
    // Conflict: look up the existing link.
    let existing = find_link_by_chain_address(db, chain, address).await?;
    match existing {
        Some(row) if row.account_id == account_id => Ok(InsertOutcome::SameAccount(row)),
        Some(_) => Ok(InsertOutcome::DifferentAccount),
        None => {
            // The insert reported 0 rows but no existing link was found — a
            // race. Treat it as a conflict to be safe.
            Ok(InsertOutcome::DifferentAccount)
        }
    }
}

/// Looks up a link by `(chain, address)`.
pub(crate) async fn find_link_by_chain_address(
    db: &dyn Database,
    chain: &str,
    address: &str,
) -> Result<Option<LinkRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(["id", "account_id", "chain", "address", "linked_at"])
        .from(iden(LINKS))
        .and_where(Expr::col(iden("chain")).eq(chain))
        .and_where(Expr::col(iden("address")).eq(address));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(link_from))
}

/// All links belonging to `account_id`.
pub(crate) async fn links_for_account(
    db: &dyn Database,
    account_id: &str,
) -> Result<Vec<LinkRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(["id", "account_id", "chain", "address", "linked_at"])
        .from(iden(LINKS))
        .and_where(Expr::col(iden("account_id")).eq(account_id));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .rows
        .iter()
        .map(link_from)
        .collect())
}

/// Deletes a link by `id`, but only if it belongs to `account_id`. Returns
/// the affected row count: one on success, zero when the link does not exist
/// or belongs to another account.
pub(crate) async fn delete_link(
    db: &dyn Database,
    id: &str,
    account_id: &str,
) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(LINKS))
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("account_id")).eq(account_id));
    db.execute(&Statement::render(&delete)).await
}
