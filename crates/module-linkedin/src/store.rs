//! Sea-query data access for the module's six tables (ADR 0004: queries are
//! built, migrations are SQL).
//!
//! Timestamps are fixed-width `YYYY-MM-DDTHH:MM:SSZ` strings, so lexicographic
//! comparison is chronological comparison and a due-work query is a plain
//! string `<=`.
//!
//! Two functions here carry the module's correctness weight and both work by
//! counting affected rows rather than by reading and then writing: `spend_state`
//! (an OAuth state may be used exactly once) and `claim_post` (a post may be
//! published exactly once). `Database::batch_atomic` returns `()` and cannot report
//! how many rows it touched, so neither may use it.

use cratefield_core::{Clock, Database, DbError, Row, Rows, Statement};
use sea_query::{Alias, Expr, Query};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub(crate) const ACCOUNTS: &str = "linkedin_accounts";
pub(crate) const PAGES: &str = "linkedin_pages";
pub(crate) const POSTS: &str = "linkedin_posts";
pub(crate) const ASSETS: &str = "linkedin_assets";
pub(crate) const OAUTH_STATES: &str = "linkedin_oauth_states";
pub(crate) const BUDGET: &str = "linkedin_request_budget";

pub(crate) const ACCOUNT_CONNECTED: &str = "connected";
pub(crate) const ACCOUNT_NEEDS_RECONNECT: &str = "needs_reconnect";

pub(crate) const PAGE_ACTIVE: &str = "active";
pub(crate) const PAGE_REVOKED: &str = "revoked";

pub(crate) const POST_SCHEDULED: &str = "scheduled";
pub(crate) const POST_PUBLISHING: &str = "publishing";
pub(crate) const POST_PUBLISH_REQUESTED: &str = "publish_requested";
pub(crate) const POST_PUBLISHED: &str = "published";
pub(crate) const POST_FAILED: &str = "failed";
pub(crate) const POST_DELETED: &str = "deleted";

pub(crate) const ASSET_WAITING: &str = "waiting_upload";
pub(crate) const ASSET_PROCESSING: &str = "processing";
pub(crate) const ASSET_AVAILABLE: &str = "available";
pub(crate) const ASSET_FAILED: &str = "failed";

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// The clock, as the module always writes it: seconds precision, `Z` suffix.
pub(crate) fn now_iso(clock: &dyn Clock) -> String {
    iso(clock.now())
}

pub(crate) fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

pub(crate) fn parse_iso(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

/// `now + seconds`, as a stored timestamp.
pub(crate) fn iso_in(clock: &dyn Clock, seconds: i64) -> String {
    iso(clock.now().saturating_add(time::Duration::seconds(seconds)))
}

/// The UTC day a budget row is keyed by.
pub(crate) fn day_of(clock: &dyn Clock) -> String {
    let now = clock.now();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    )
}

fn text(row: &Row, column: &str) -> String {
    row.get::<String>(column).unwrap_or_default()
}

fn maybe(row: &Row, column: &str) -> Option<String> {
    row.get::<Option<String>>(column).flatten()
}

// ---------------------------------------------------------------------------
// Accounts

#[derive(Debug, Clone)]
pub(crate) struct AccountRow {
    pub id: String,
    pub person_urn: Option<String>,
    pub access_token: String,
    pub access_expires_at: String,
    pub refresh_token: Option<String>,
    pub refresh_expires_at: Option<String>,
    pub scopes: String,
    pub status: String,
    pub expiring_notified_at: Option<String>,
}

fn account_from(row: &Row) -> AccountRow {
    AccountRow {
        id: text(row, "id"),
        person_urn: maybe(row, "person_urn"),
        access_token: text(row, "access_token"),
        access_expires_at: text(row, "access_expires_at"),
        refresh_token: maybe(row, "refresh_token"),
        refresh_expires_at: maybe(row, "refresh_expires_at"),
        scopes: text(row, "scopes"),
        status: text(row, "status"),
        expiring_notified_at: maybe(row, "expiring_notified_at"),
    }
}

fn account_columns() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "person_urn",
            "access_token",
            "access_expires_at",
            "refresh_token",
            "refresh_expires_at",
            "scopes",
            "status",
            "expiring_notified_at",
        ])
        .from(iden(ACCOUNTS));
    select
}

/// The connected account, or `None` when nobody has connected yet. One row
/// per deployment, so there is no ambiguity about which token to use.
pub(crate) async fn load_account(db: &dyn Database) -> Result<Option<AccountRow>, DbError> {
    let query = account_columns().limit(1).to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(account_from))
}

/// Replaces the connected account. Connect is an explicit act by an
/// administrator, so a second connect legitimately supersedes the first
/// rather than failing on the singleton constraint.
pub(crate) async fn put_account(
    db: &dyn Database,
    row: &AccountRow,
    now: &str,
) -> Result<(), DbError> {
    let mut delete = Query::delete();
    delete.from_table(iden(ACCOUNTS));
    db.execute(&Statement::render(&delete)).await?;

    let mut insert = Query::insert();
    insert
        .into_table(iden(ACCOUNTS))
        .columns([
            "id",
            "singleton",
            "person_urn",
            "access_token",
            "access_expires_at",
            "refresh_token",
            "refresh_expires_at",
            "scopes",
            "status",
            "expiring_notified_at",
            "created_at",
            "updated_at",
        ])
        .values_panic([
            row.id.clone().into(),
            1.into(),
            row.person_urn.clone().into(),
            row.access_token.clone().into(),
            row.access_expires_at.clone().into(),
            row.refresh_token.clone().into(),
            row.refresh_expires_at.clone().into(),
            row.scopes.clone().into(),
            row.status.clone().into(),
            row.expiring_notified_at.clone().into(),
            now.into(),
            now.into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// Stores a refreshed token pair. The refresh expiry comes from LinkedIn's
/// `refresh_token_expires_in` and is never recomputed as "a year from now":
/// the TTL does not extend on use.
pub(crate) async fn store_refreshed(
    db: &dyn Database,
    id: &str,
    access_token: &str,
    access_expires_at: &str,
    refresh_token: Option<&str>,
    refresh_expires_at: Option<&str>,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(ACCOUNTS))
        .values([
            (iden("access_token"), access_token.into()),
            (iden("access_expires_at"), access_expires_at.into()),
            (iden("status"), ACCOUNT_CONNECTED.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    if let Some(token) = refresh_token {
        update.value(iden("refresh_token"), token);
    }
    if let Some(expiry) = refresh_expires_at {
        update.value(iden("refresh_expires_at"), expiry);
    }
    db.execute(&Statement::render(&update)).await
}

pub(crate) async fn set_account_status(
    db: &dyn Database,
    id: &str,
    status: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(ACCOUNTS))
        .values([
            (iden("status"), status.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

pub(crate) async fn set_person_urn(
    db: &dyn Database,
    id: &str,
    person_urn: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(ACCOUNTS))
        .values([
            (iden("person_urn"), person_urn.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

pub(crate) async fn mark_expiring_notified(
    db: &dyn Database,
    id: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(ACCOUNTS))
        .values([
            (iden("expiring_notified_at"), now.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

/// Forgets the tokens. Post history is deliberately kept: it records what we
/// published, which outlives one connection.
pub(crate) async fn delete_account(db: &dyn Database) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete.from_table(iden(ACCOUNTS));
    db.execute(&Statement::render(&delete)).await
}

// ---------------------------------------------------------------------------
// OAuth states

pub(crate) async fn insert_state(
    db: &dyn Database,
    id: &str,
    expires_at: &str,
    now: &str,
) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(OAUTH_STATES))
        .columns(["id", "expires_at", "created_at"])
        .values_panic([id.into(), expires_at.into(), now.into()]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// Spends a state exactly once. The delete is conditional on the row still
/// existing and not having expired, and the affected-row count is the proof:
/// a replayed callback deletes nothing and gets `false`.
pub(crate) async fn spend_state(db: &dyn Database, id: &str, now: &str) -> Result<bool, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(OAUTH_STATES))
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("expires_at")).gt(now));
    Ok(db.execute(&Statement::render(&delete)).await? == 1)
}

pub(crate) async fn purge_expired_states(db: &dyn Database, now: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(OAUTH_STATES))
        .and_where(Expr::col(iden("expires_at")).lte(now));
    db.execute(&Statement::render(&delete)).await
}

// ---------------------------------------------------------------------------
// Pages

#[derive(Debug, Clone)]
pub(crate) struct PageRow {
    pub id: String,
    pub account_id: String,
    pub org_id: String,
    pub urn: String,
    pub name: String,
    pub vanity_name: Option<String>,
    pub kind: String,
    pub parent_org_id: Option<String>,
    pub role: String,
    pub can_post_organic: bool,
    pub state: String,
    pub logo_urn: Option<String>,
    pub synced_at: String,
}

fn page_from(row: &Row) -> PageRow {
    PageRow {
        id: text(row, "id"),
        account_id: text(row, "account_id"),
        org_id: text(row, "org_id"),
        urn: text(row, "urn"),
        name: text(row, "name"),
        vanity_name: maybe(row, "vanity_name"),
        kind: text(row, "kind"),
        parent_org_id: maybe(row, "parent_org_id"),
        role: text(row, "role"),
        // Read as an integer, not a bool: core's `TryFromValue for bool`
        // handles `Bool` and `Int` but not the `BigInt` SQLite returns for an
        // INTEGER column, so `get::<bool>` would silently answer false.
        can_post_organic: row.get::<i64>("can_post_organic").unwrap_or_default() != 0,
        state: text(row, "state"),
        logo_urn: maybe(row, "logo_urn"),
        synced_at: text(row, "synced_at"),
    }
}

fn page_columns() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "account_id",
            "org_id",
            "urn",
            "name",
            "vanity_name",
            "kind",
            "parent_org_id",
            "role",
            "can_post_organic",
            "state",
            "logo_urn",
            "synced_at",
        ])
        .from(iden(PAGES));
    select
}

/// Update-then-insert rather than `ON CONFLICT DO UPDATE`: the same two
/// statements work on every dialect the harness targets, and the update path
/// is the common one after the first sync.
pub(crate) async fn upsert_page(db: &dyn Database, row: &PageRow) -> Result<(), DbError> {
    let mut update = Query::update();
    update
        .table(iden(PAGES))
        .values([
            (iden("urn"), row.urn.clone().into()),
            (iden("name"), row.name.clone().into()),
            (iden("vanity_name"), row.vanity_name.clone().into()),
            (iden("kind"), row.kind.clone().into()),
            (iden("parent_org_id"), row.parent_org_id.clone().into()),
            (iden("role"), row.role.clone().into()),
            (
                iden("can_post_organic"),
                i64::from(row.can_post_organic).into(),
            ),
            (iden("state"), row.state.clone().into()),
            (iden("logo_urn"), row.logo_urn.clone().into()),
            (iden("synced_at"), row.synced_at.clone().into()),
        ])
        .and_where(Expr::col(iden("account_id")).eq(row.account_id.as_str()))
        .and_where(Expr::col(iden("org_id")).eq(row.org_id.as_str()));
    if db.execute(&Statement::render(&update)).await? > 0 {
        return Ok(());
    }

    let mut insert = Query::insert();
    insert
        .into_table(iden(PAGES))
        .columns([
            "id",
            "account_id",
            "org_id",
            "urn",
            "name",
            "vanity_name",
            "kind",
            "parent_org_id",
            "role",
            "can_post_organic",
            "state",
            "logo_urn",
            "synced_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.account_id.clone().into(),
            row.org_id.clone().into(),
            row.urn.clone().into(),
            row.name.clone().into(),
            row.vanity_name.clone().into(),
            row.kind.clone().into(),
            row.parent_org_id.clone().into(),
            row.role.clone().into(),
            i64::from(row.can_post_organic).into(),
            row.state.clone().into(),
            row.logo_urn.clone().into(),
            row.synced_at.clone().into(),
        ])
        .on_conflict(
            sea_query::OnConflict::columns([iden("account_id"), iden("org_id")])
                .do_nothing()
                .to_owned(),
        );
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// Anything the current sync did not touch has lost its role: mark it
/// revoked rather than deleting it, so a post that references the page still
/// resolves to something.
pub(crate) async fn revoke_pages_not_synced(
    db: &dyn Database,
    account_id: &str,
    synced_at: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(PAGES))
        .values([
            (iden("state"), PAGE_REVOKED.into()),
            (iden("can_post_organic"), 0_i64.into()),
        ])
        .and_where(Expr::col(iden("account_id")).eq(account_id))
        .and_where(Expr::col(iden("synced_at")).lt(synced_at))
        .and_where(Expr::col(iden("state")).eq(PAGE_ACTIVE));
    db.execute(&Statement::render(&update)).await
}

pub(crate) async fn list_pages(
    db: &dyn Database,
    kind: Option<&str>,
) -> Result<Vec<PageRow>, DbError> {
    let mut query = page_columns();
    if let Some(kind) = kind {
        query.and_where(Expr::col(iden("kind")).eq(kind));
    }
    let query = query
        .order_by(iden("name"), sea_query::Order::Asc)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(page_from).collect())
}

pub(crate) async fn find_page(db: &dyn Database, org_id: &str) -> Result<Option<PageRow>, DbError> {
    let query = page_columns()
        .and_where(Expr::col(iden("org_id")).eq(org_id))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(page_from))
}

// ---------------------------------------------------------------------------
// Assets

#[derive(Debug, Clone)]
pub(crate) struct AssetRow {
    pub id: String,
    pub account_id: String,
    pub org_id: String,
    pub image_urn: String,
    pub status: String,
    pub sha256: String,
    pub byte_len: i64,
    pub alt_text: Option<String>,
    pub checked_at: Option<String>,
}

fn asset_from(row: &Row) -> AssetRow {
    AssetRow {
        id: text(row, "id"),
        account_id: text(row, "account_id"),
        org_id: text(row, "org_id"),
        image_urn: text(row, "image_urn"),
        status: text(row, "status"),
        sha256: text(row, "sha256"),
        byte_len: row.get::<i64>("byte_len").unwrap_or_default(),
        alt_text: maybe(row, "alt_text"),
        checked_at: maybe(row, "checked_at"),
    }
}

fn asset_columns() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "account_id",
            "org_id",
            "image_urn",
            "status",
            "sha256",
            "byte_len",
            "alt_text",
            "checked_at",
        ])
        .from(iden(ASSETS));
    select
}

pub(crate) async fn insert_asset(
    db: &dyn Database,
    row: &AssetRow,
    now: &str,
) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(ASSETS))
        .columns([
            "id",
            "account_id",
            "org_id",
            "image_urn",
            "status",
            "sha256",
            "byte_len",
            "alt_text",
            "checked_at",
            "created_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.account_id.clone().into(),
            row.org_id.clone().into(),
            row.image_urn.clone().into(),
            row.status.clone().into(),
            row.sha256.clone().into(),
            row.byte_len.into(),
            row.alt_text.clone().into(),
            row.checked_at.clone().into(),
            now.into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// An asset for these exact bytes that is still usable. A failed upload is
/// deliberately not reused: dedupe must never make a bad upload permanent.
pub(crate) async fn find_reusable_asset(
    db: &dyn Database,
    org_id: &str,
    sha256: &str,
) -> Result<Option<AssetRow>, DbError> {
    let query = asset_columns()
        .and_where(Expr::col(iden("org_id")).eq(org_id))
        .and_where(Expr::col(iden("sha256")).eq(sha256))
        .and_where(Expr::col(iden("status")).is_in([
            ASSET_AVAILABLE,
            ASSET_PROCESSING,
            ASSET_WAITING,
        ]))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(asset_from))
}

pub(crate) async fn find_asset(db: &dyn Database, id: &str) -> Result<Option<AssetRow>, DbError> {
    let query = asset_columns()
        .and_where(Expr::col(iden("id")).eq(id))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(asset_from))
}

pub(crate) async fn assets_in_flight(db: &dyn Database) -> Result<Vec<AssetRow>, DbError> {
    let query = asset_columns()
        .and_where(Expr::col(iden("status")).is_in([ASSET_WAITING, ASSET_PROCESSING]))
        .limit(50)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(asset_from).collect())
}

pub(crate) async fn set_asset_status(
    db: &dyn Database,
    id: &str,
    status: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(ASSETS))
        .values([
            (iden("status"), status.into()),
            (iden("checked_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

// ---------------------------------------------------------------------------
// Posts

#[derive(Debug, Clone)]
pub(crate) struct PostRow {
    pub id: String,
    pub account_id: String,
    pub org_id: String,
    pub idempotency_key: String,
    pub commentary: String,
    pub visibility: String,
    pub asset_id: Option<String>,
    pub article_source: Option<String>,
    pub article_title: Option<String>,
    pub article_description: Option<String>,
    pub state: String,
    pub post_urn: Option<String>,
    pub scheduled_at: Option<String>,
    pub not_before: Option<String>,
    pub publishing_since: Option<String>,
    pub attempts: i64,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
    pub edited_at: Option<String>,
    pub previous_commentary: Option<String>,
    pub created_at: String,
    pub published_at: Option<String>,
    pub deleted_at: Option<String>,
}

fn post_from(row: &Row) -> PostRow {
    PostRow {
        id: text(row, "id"),
        account_id: text(row, "account_id"),
        org_id: text(row, "org_id"),
        idempotency_key: text(row, "idempotency_key"),
        commentary: text(row, "commentary"),
        visibility: text(row, "visibility"),
        asset_id: maybe(row, "asset_id"),
        article_source: maybe(row, "article_source"),
        article_title: maybe(row, "article_title"),
        article_description: maybe(row, "article_description"),
        state: text(row, "state"),
        post_urn: maybe(row, "post_urn"),
        scheduled_at: maybe(row, "scheduled_at"),
        not_before: maybe(row, "not_before"),
        publishing_since: maybe(row, "publishing_since"),
        attempts: row.get::<i64>("attempts").unwrap_or_default(),
        error_code: maybe(row, "error_code"),
        error_detail: maybe(row, "error_detail"),
        edited_at: maybe(row, "edited_at"),
        previous_commentary: maybe(row, "previous_commentary"),
        created_at: text(row, "created_at"),
        published_at: maybe(row, "published_at"),
        deleted_at: maybe(row, "deleted_at"),
    }
}

fn post_columns() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "account_id",
            "org_id",
            "idempotency_key",
            "commentary",
            "visibility",
            "asset_id",
            "article_source",
            "article_title",
            "article_description",
            "state",
            "post_urn",
            "scheduled_at",
            "not_before",
            "publishing_since",
            "attempts",
            "error_code",
            "error_detail",
            "edited_at",
            "previous_commentary",
            "created_at",
            "published_at",
            "deleted_at",
        ])
        .from(iden(POSTS));
    select
}

pub(crate) async fn insert_post(
    db: &dyn Database,
    row: &PostRow,
    now: &str,
) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(POSTS))
        .columns([
            "id",
            "account_id",
            "org_id",
            "idempotency_key",
            "commentary",
            "visibility",
            "asset_id",
            "article_source",
            "article_title",
            "article_description",
            "state",
            "scheduled_at",
            "not_before",
            "attempts",
            "created_at",
            "updated_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.account_id.clone().into(),
            row.org_id.clone().into(),
            row.idempotency_key.clone().into(),
            row.commentary.clone().into(),
            row.visibility.clone().into(),
            row.asset_id.clone().into(),
            row.article_source.clone().into(),
            row.article_title.clone().into(),
            row.article_description.clone().into(),
            row.state.clone().into(),
            row.scheduled_at.clone().into(),
            row.not_before.clone().into(),
            0.into(),
            now.into(),
            now.into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

pub(crate) async fn find_post(db: &dyn Database, id: &str) -> Result<Option<PostRow>, DbError> {
    let query = post_columns()
        .and_where(Expr::col(iden("id")).eq(id))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(post_from))
}

pub(crate) async fn find_post_by_idempotency(
    db: &dyn Database,
    org_id: &str,
    key: &str,
) -> Result<Option<PostRow>, DbError> {
    let query = post_columns()
        .and_where(Expr::col(iden("org_id")).eq(org_id))
        .and_where(Expr::col(iden("idempotency_key")).eq(key))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(post_from))
}

pub(crate) async fn list_posts(
    db: &dyn Database,
    org_id: Option<&str>,
    state: Option<&str>,
    limit: u64,
) -> Result<Vec<PostRow>, DbError> {
    let mut query = post_columns();
    if let Some(org_id) = org_id {
        query.and_where(Expr::col(iden("org_id")).eq(org_id));
    }
    if let Some(state) = state {
        query.and_where(Expr::col(iden("state")).eq(state));
    }
    let query = query
        .order_by(iden("created_at"), sea_query::Order::Desc)
        .limit(limit)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(post_from).collect())
}

/// Ids of posts that are due to be published: scheduled and past their
/// `not_before`, or holding a publish lease that has expired.
pub(crate) async fn due_post_ids(
    db: &dyn Database,
    now: &str,
    lease_cutoff: &str,
    limit: u64,
) -> Result<Vec<String>, DbError> {
    let mut select = Query::select();
    select
        .column(iden("id"))
        .from(iden(POSTS))
        .cond_where(
            sea_query::Cond::any()
                .add(
                    sea_query::Cond::all()
                        .add(Expr::col(iden("state")).eq(POST_SCHEDULED))
                        .add(
                            sea_query::Cond::any()
                                .add(Expr::col(iden("not_before")).is_null())
                                .add(Expr::col(iden("not_before")).lte(now)),
                        )
                        .add(
                            sea_query::Cond::any()
                                .add(Expr::col(iden("scheduled_at")).is_null())
                                .add(Expr::col(iden("scheduled_at")).lte(now)),
                        ),
                )
                .add(
                    sea_query::Cond::all()
                        .add(Expr::col(iden("state")).eq(POST_PUBLISHING))
                        .add(Expr::col(iden("publishing_since")).lt(lease_cutoff)),
                ),
        )
        .order_by(iden("created_at"), sea_query::Order::Asc)
        .limit(limit);
    let rows: Rows = db.query(&Statement::render(&select)).await?;
    Ok(rows
        .rows
        .iter()
        .map(|row| text(row, "id"))
        .filter(|id| !id.is_empty())
        .collect())
}

/// Claims a post for publishing. The update is conditional on the row still
/// being claimable, so of two concurrent passes exactly one gets `true` and
/// the other leaves the row alone. This is the guard that keeps a post from
/// being created twice on LinkedIn.
pub(crate) async fn claim_post(
    db: &dyn Database,
    id: &str,
    now: &str,
    lease_cutoff: &str,
) -> Result<bool, DbError> {
    let mut update = Query::update();
    update
        .table(iden(POSTS))
        .values([
            (iden("state"), POST_PUBLISHING.into()),
            (iden("publishing_since"), now.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id))
        .cond_where(
            sea_query::Cond::any()
                .add(Expr::col(iden("state")).eq(POST_SCHEDULED))
                .add(
                    sea_query::Cond::all()
                        .add(Expr::col(iden("state")).eq(POST_PUBLISHING))
                        .add(Expr::col(iden("publishing_since")).lt(lease_cutoff)),
                ),
        );
    Ok(db.execute(&Statement::render(&update)).await? == 1)
}

/// Records the URN LinkedIn returned, before we know whether the post
/// finished publishing. Written as its own step so a crash after the create
/// still leaves the URN behind for reconciliation.
pub(crate) async fn set_post_urn(
    db: &dyn Database,
    id: &str,
    urn: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(POSTS))
        .values([
            (iden("post_urn"), urn.into()),
            (iden("state"), POST_PUBLISH_REQUESTED.into()),
            (iden("publishing_since"), now.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

pub(crate) async fn mark_published(db: &dyn Database, id: &str, now: &str) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(POSTS))
        .values([
            (iden("state"), POST_PUBLISHED.into()),
            (iden("published_at"), now.into()),
            (iden("publishing_since"), Option::<String>::None.into()),
            (iden("not_before"), Option::<String>::None.into()),
            (iden("error_code"), Option::<String>::None.into()),
            (iden("error_detail"), Option::<String>::None.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

pub(crate) async fn mark_failed(
    db: &dyn Database,
    id: &str,
    code: &str,
    detail: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(POSTS))
        .values([
            (iden("state"), POST_FAILED.into()),
            (iden("error_code"), code.into()),
            (iden("error_detail"), detail.into()),
            (iden("publishing_since"), Option::<String>::None.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

/// Puts a post back in the queue with a retry clock. Used for 429s, 5xx and
/// media that is still processing: the Clock port cannot sleep, so waiting is
/// a column and the next cron pass is the timer.
pub(crate) async fn defer_post(
    db: &dyn Database,
    id: &str,
    not_before: &str,
    reason: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(POSTS))
        .values([
            (iden("state"), POST_SCHEDULED.into()),
            (iden("not_before"), not_before.into()),
            (iden("publishing_since"), Option::<String>::None.into()),
            (iden("error_code"), reason.into()),
            (iden("attempts"), Expr::col(iden("attempts")).add(1)),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

pub(crate) async fn update_commentary(
    db: &dyn Database,
    id: &str,
    commentary: &str,
    previous: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(POSTS))
        .values([
            (iden("commentary"), commentary.into()),
            (iden("previous_commentary"), previous.into()),
            (iden("edited_at"), now.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

pub(crate) async fn mark_deleted(db: &dyn Database, id: &str, now: &str) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden(POSTS))
        .values([
            (iden("state"), POST_DELETED.into()),
            (iden("deleted_at"), now.into()),
            (iden("publishing_since"), Option::<String>::None.into()),
            (iden("updated_at"), now.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

/// Posts holding a URN but not yet confirmed published.
pub(crate) async fn awaiting_confirmation(
    db: &dyn Database,
    limit: u64,
) -> Result<Vec<PostRow>, DbError> {
    let query = post_columns()
        .and_where(Expr::col(iden("state")).eq(POST_PUBLISH_REQUESTED))
        .order_by(iden("created_at"), sea_query::Order::Asc)
        .limit(limit)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(post_from).collect())
}

// ---------------------------------------------------------------------------
// Request budget

/// Adds to today's spend. In the database, not in the isolate: the cap is per
/// app per day and a Worker isolate is neither.
pub(crate) async fn spend_budget(db: &dyn Database, day: &str, n: u32) -> Result<(), DbError> {
    if n == 0 {
        return Ok(());
    }
    let mut update = Query::update();
    update
        .table(iden(BUDGET))
        .values([(iden("spent"), Expr::col(iden("spent")).add(i64::from(n)))])
        .and_where(Expr::col(iden("day")).eq(day));
    if db.execute(&Statement::render(&update)).await? > 0 {
        return Ok(());
    }
    let mut insert = Query::insert();
    insert
        .into_table(iden(BUDGET))
        .columns(["day", "spent"])
        .values_panic([day.into(), i64::from(n).into()])
        .on_conflict(
            sea_query::OnConflict::column(iden("day"))
                .do_nothing()
                .to_owned(),
        );
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

pub(crate) async fn budget_spent(db: &dyn Database, day: &str) -> Result<i64, DbError> {
    let mut select = Query::select();
    select
        .column(iden("spent"))
        .from(iden(BUDGET))
        .and_where(Expr::col(iden("day")).eq(day))
        .limit(1);
    let rows = db.query(&Statement::render(&select)).await?;
    Ok(rows
        .first()
        .and_then(|row| row.get::<i64>("spent"))
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `claim_post` and `due_post_ids` mix `and_where` with `cond_where`.
    /// If sea-query treated `cond_where` as a replacement rather than
    /// another AND, `claim_post` would update every claimable row instead of
    /// one, and with a single row in the table the two behaviours look
    /// identical. So the rendered SQL is asserted directly.
    #[test]
    fn timestamps_are_fixed_width_so_string_order_is_time_order() {
        let early =
            iso(time::OffsetDateTime::from_unix_timestamp(1_788_775_200).expect("in range"));
        let late = iso(time::OffsetDateTime::from_unix_timestamp(1_788_775_260).expect("in range"));
        assert_eq!(early.len(), late.len(), "{early} vs {late}");
        assert!(early < late, "{early} is not before {late}");
        assert_eq!(parse_iso(&early).map(iso).as_deref(), Some(early.as_str()));
        // Whatever the offset suffix is, the module writes and parses one
        // shape, and that is what the due-work queries compare.
        assert!(early.starts_with("2026-09-07T"), "{early}");
    }

    #[test]
    fn claiming_a_post_is_scoped_to_that_post() {
        let mut update = Query::update();
        update
            .table(iden(POSTS))
            .values([(iden("state"), POST_PUBLISHING.into())])
            .and_where(Expr::col(iden("id")).eq("post_1"))
            .cond_where(
                sea_query::Cond::any()
                    .add(Expr::col(iden("state")).eq(POST_SCHEDULED))
                    .add(
                        sea_query::Cond::all()
                            .add(Expr::col(iden("state")).eq(POST_PUBLISHING))
                            .add(Expr::col(iden("publishing_since")).lt("cutoff")),
                    ),
            );
        let statement = Statement::render(&update);
        // Values are placeholders, so the shape is what to assert on: the id
        // filter, then AND, then the parenthesised state condition.
        assert_eq!(
            statement.sql,
            r#"UPDATE "linkedin_posts" SET "state" = ? WHERE "id" = ? AND ("state" = ? OR ("state" = ? AND "publishing_since" < ?))"#,
            "the claim is no longer scoped to one row"
        );
        assert_eq!(statement.values.0.len(), 5);
    }
}
