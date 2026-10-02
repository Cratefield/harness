//! Sea-query access for the two connections tables (issue #624).
//!
//! Every value is bound, never interpolated. The concurrency story is two
//! guarded `UPDATE`s whose affected-row count is the answer: [`spend_state`]
//! sets `spent_at` only where the state is unspent and unexpired, and
//! [`store_refreshed`] rewrites the token columns only where the refresh
//! ciphertext is still the one the caller read. `Database::execute` returns
//! that count on every adapter and is atomic for one statement, which is what
//! both depend on.

use cratefield_core::{Database, DbError, Row, Statement};
use sea_query::{Alias, Condition, Expr, Query, SimpleExpr};

pub(crate) const CONNECTIONS: &str = "connection";
pub(crate) const STATES: &str = "connection_state";

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

// ---------------------------------------------------------------------------
// Connection state (one connect attempt in flight)

/// One state row, as `complete` needs it. `state_hash` comes back with it
/// because it is the row id the sealed PKCE verifier's AAD is bound to.
pub(crate) struct StateRow {
    pub(crate) state_hash: String,
    pub(crate) subject: String,
    pub(crate) provider: String,
    pub(crate) return_to: String,
    pub(crate) verifier_sealed: Option<String>,
}

fn state_from(row: &Row) -> StateRow {
    StateRow {
        state_hash: row.get("state_hash").unwrap_or_default(),
        subject: row.get("subject").unwrap_or_default(),
        provider: row.get("provider").unwrap_or_default(),
        return_to: row.get("return_to").unwrap_or_default(),
        verifier_sealed: row.get("verifier_sealed"),
    }
}

/// One state row to insert.
pub(crate) struct NewState<'a> {
    pub(crate) state_hash: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) provider: &'a str,
    pub(crate) return_to: &'a str,
    pub(crate) verifier_sealed: Option<&'a str>,
    pub(crate) now: &'a str,
    pub(crate) expires_at: &'a str,
}

/// Records a fresh connect attempt. `state_hash` is the primary key, so a
/// collision overwrites nothing a caller could still be waiting on.
pub(crate) async fn insert_state(db: &dyn Database, state: &NewState<'_>) -> Result<u64, DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(STATES))
        .columns([
            "state_hash",
            "subject",
            "provider",
            "return_to",
            "verifier_sealed",
            "expires_at",
            "created_at",
        ])
        .values_panic([
            state.state_hash.into(),
            state.subject.into(),
            state.provider.into(),
            state.return_to.into(),
            state.verifier_sealed.into(),
            state.expires_at.into(),
            state.now.into(),
        ]);
    db.execute(&Statement::render(&insert)).await
}

/// The single-use consume: an unspent, unexpired state becomes spent exactly
/// once, and the caller that sees one row is the one that exchanges the code.
/// Zero means a replay, a state never issued, or one past its deadline.
pub(crate) async fn spend_state(
    db: &dyn Database,
    state_hash: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(STATES))
        .value(iden("spent_at"), now)
        .and_where(Expr::col(iden("state_hash")).eq(state_hash))
        .and_where(Expr::col(iden("spent_at")).is_null())
        .and_where(Expr::col(iden("expires_at")).gt(now));
    db.execute(&Statement::render(&update)).await
}

/// The row a spent state names.
pub(crate) async fn find_state(
    db: &dyn Database,
    state_hash: &str,
) -> Result<Option<StateRow>, DbError> {
    let mut select = Query::select();
    select
        .columns([
            "state_hash",
            "subject",
            "provider",
            "return_to",
            "verifier_sealed",
        ])
        .from(iden(STATES))
        .and_where(Expr::col(iden("state_hash")).eq(state_hash));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(state_from))
}

/// Deletes every state that is spent or past its expiry. Idempotent, and safe
/// to run as often as the venture's cron fires.
pub(crate) async fn purge_states(db: &dyn Database, now: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete.from_table(iden(STATES)).and_where(
        Condition::any()
            .add(Expr::col(iden("spent_at")).is_not_null())
            .add(Expr::col(iden("expires_at")).lte(now))
            .into(),
    );
    db.execute(&Statement::render(&delete)).await
}

// ---------------------------------------------------------------------------
// Connection (the live row)

/// One connection row, as the lifecycle needs it.
pub(crate) struct ConnectionRow {
    pub(crate) id: String,
    pub(crate) subject: String,
    pub(crate) provider: String,
    pub(crate) external_account_id: Option<String>,
    pub(crate) display_name: Option<String>,
    pub(crate) scopes: String,
    pub(crate) status: String,
    pub(crate) access_token_sealed: Option<String>,
    pub(crate) refresh_token_sealed: Option<String>,
    pub(crate) access_expires_at: Option<String>,
    pub(crate) refresh_expires_at: Option<String>,
    pub(crate) last_error: Option<String>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

const CONNECTION_COLUMNS: [&str; 14] = [
    "id",
    "subject",
    "provider",
    "external_account_id",
    "display_name",
    "scopes",
    "status",
    "access_token_sealed",
    "refresh_token_sealed",
    "access_expires_at",
    "refresh_expires_at",
    "last_error",
    "created_at",
    "updated_at",
];

fn connection_from(row: &Row) -> ConnectionRow {
    ConnectionRow {
        id: row.get("id").unwrap_or_default(),
        subject: row.get("subject").unwrap_or_default(),
        provider: row.get("provider").unwrap_or_default(),
        external_account_id: row.get("external_account_id"),
        display_name: row.get("display_name"),
        scopes: row.get("scopes").unwrap_or_default(),
        status: row.get("status").unwrap_or_default(),
        access_token_sealed: row.get("access_token_sealed"),
        refresh_token_sealed: row.get("refresh_token_sealed"),
        access_expires_at: row.get("access_expires_at"),
        refresh_expires_at: row.get("refresh_expires_at"),
        last_error: row.get("last_error"),
        created_at: row.get("created_at").unwrap_or_default(),
        updated_at: row.get("updated_at").unwrap_or_default(),
    }
}

/// One connection to insert.
pub(crate) struct NewConnection<'a> {
    pub(crate) id: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) provider: &'a str,
    pub(crate) scopes: &'a str,
    pub(crate) access_token_sealed: Option<&'a str>,
    pub(crate) refresh_token_sealed: Option<&'a str>,
    pub(crate) access_expires_at: Option<&'a str>,
    pub(crate) refresh_expires_at: Option<&'a str>,
    pub(crate) now: &'a str,
}

/// Inserts a freshly connected row in `active`.
pub(crate) async fn insert_connection(
    db: &dyn Database,
    connection: &NewConnection<'_>,
) -> Result<u64, DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(CONNECTIONS))
        .columns([
            "id",
            "subject",
            "provider",
            "scopes",
            "status",
            "access_token_sealed",
            "refresh_token_sealed",
            "access_expires_at",
            "refresh_expires_at",
            "created_at",
            "updated_at",
        ])
        .values_panic([
            connection.id.into(),
            connection.subject.into(),
            connection.provider.into(),
            connection.scopes.into(),
            "active".into(),
            connection.access_token_sealed.into(),
            connection.refresh_token_sealed.into(),
            connection.access_expires_at.into(),
            connection.refresh_expires_at.into(),
            connection.now.into(),
            connection.now.into(),
        ]);
    db.execute(&Statement::render(&insert)).await
}

/// One connection by id.
pub(crate) async fn load_connection(
    db: &dyn Database,
    id: &str,
) -> Result<Option<ConnectionRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(CONNECTION_COLUMNS)
        .from(iden(CONNECTIONS))
        .and_where(Expr::col(iden("id")).eq(id));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(connection_from))
}

/// A subject's connections, oldest first.
pub(crate) async fn list_connections(
    db: &dyn Database,
    subject: &str,
) -> Result<Vec<ConnectionRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(CONNECTION_COLUMNS)
        .from(iden(CONNECTIONS))
        .and_where(Expr::col(iden("subject")).eq(subject))
        .order_by(iden("created_at"), sea_query::Order::Asc);
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .rows
        .iter()
        .map(connection_from)
        .collect())
}

/// The live connections whose access token is due for a refresh: `active`, and
/// with a recorded expiry at or before `not_after`. A row whose provider
/// stated no lifetime has nothing to be due against, so it is left alone.
pub(crate) async fn due_connections(
    db: &dyn Database,
    not_after: &str,
) -> Result<Vec<ConnectionRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(CONNECTION_COLUMNS)
        .from(iden(CONNECTIONS))
        .and_where(Expr::col(iden("status")).eq("active"))
        .and_where(Expr::col(iden("access_expires_at")).lte(not_after))
        .order_by(iden("access_expires_at"), sea_query::Order::Asc);
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .rows
        .iter()
        .map(connection_from)
        .collect())
}

/// The one write path for a connection row: `UPDATE connection SET <values>
/// WHERE id = :id`, plus one more equality guard when given. The affected-row
/// count is the answer the callers branch on.
async fn update_by_id(
    db: &dyn Database,
    id: &str,
    values: Vec<(Alias, SimpleExpr)>,
    guard: Option<(&str, &str)>,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(CONNECTIONS))
        .values(values)
        .and_where(Expr::col(iden("id")).eq(id));
    if let Some((column, value)) = guard {
        update.and_where(Expr::col(iden(column)).eq(value));
    }
    db.execute(&Statement::render(&update)).await
}

/// The guarded refresh write: both sealed tokens and both expiries move in one
/// statement, but only where `refresh_token_sealed` still holds `previous` —
/// the ciphertext the caller read. One means this caller won; zero means
/// another worker refreshed first, so this caller must re-read rather than
/// write.
///// The values are the statement's own columns; bundling them in a struct would
// only move the same arguments to its construction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn store_refreshed(
    db: &dyn Database,
    id: &str,
    previous: &str,
    access_token_sealed: &str,
    refresh_token_sealed: &str,
    access_expires_at: Option<&str>,
    refresh_expires_at: Option<&str>,
    now: &str,
) -> Result<u64, DbError> {
    update_by_id(
        db,
        id,
        vec![
            (iden("access_token_sealed"), access_token_sealed.into()),
            (iden("refresh_token_sealed"), refresh_token_sealed.into()),
            (iden("access_expires_at"), access_expires_at.into()),
            (iden("refresh_expires_at"), refresh_expires_at.into()),
            (iden("updated_at"), now.into()),
        ],
        Some(("refresh_token_sealed", previous)),
    )
    .await
}

/// Moves a row's status and records why, without touching its tokens.
pub(crate) async fn set_status(
    db: &dyn Database,
    id: &str,
    status: &str,
    last_error: Option<&str>,
    now: &str,
) -> Result<u64, DbError> {
    update_by_id(
        db,
        id,
        vec![
            (iden("status"), status.into()),
            (iden("last_error"), last_error.into()),
            (iden("updated_at"), now.into()),
        ],
        None,
    )
    .await
}

/// Revokes a row: `revoked`, and both sealed tokens cleared so nothing usable
/// is left at rest.
pub(crate) async fn set_revoked(db: &dyn Database, id: &str, now: &str) -> Result<u64, DbError> {
    update_by_id(
        db,
        id,
        vec![
            (iden("status"), "revoked".into()),
            (iden("access_token_sealed"), Option::<String>::None.into()),
            (iden("refresh_token_sealed"), Option::<String>::None.into()),
            (iden("updated_at"), now.into()),
        ],
        None,
    )
    .await
}

/// Records the provider identity a venture learned with the access token.
pub(crate) async fn set_account(
    db: &dyn Database,
    id: &str,
    external_account_id: Option<&str>,
    display_name: Option<&str>,
    now: &str,
) -> Result<u64, DbError> {
    update_by_id(
        db,
        id,
        vec![
            (iden("external_account_id"), external_account_id.into()),
            (iden("display_name"), display_name.into()),
            (iden("updated_at"), now.into()),
        ],
        None,
    )
    .await
}

/// The scopes a row was granted, split back into tokens.
pub(crate) fn scopes_of(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_owned).collect()
}
