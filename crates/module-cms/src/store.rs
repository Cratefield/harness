//! Data access for the CMS tables, in the portable SQL subset. Reads and
//! writes go through [`Statement::with_values`] with `?` placeholders, so the
//! same statements run on the sqlite adapter, D1 and Postgres.

use factory0_core::{Database, DbError, Row, Statement};
use sea_query::Value as SeaValue;

pub(crate) const STATUS_DRAFT: &str = "draft";
pub(crate) const STATUS_PUBLISHED: &str = "published";
pub(crate) const STATUS_UNPUBLISHED: &str = "unpublished";

/// The editable working copy of one content item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Item {
    pub collection: String,
    pub slug: String,
    pub title: String,
    pub body: String,
    pub data: String,
    pub status: String,
    pub version: i64,
    pub updated_at: String,
}

/// A published snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Revision {
    pub collection: String,
    pub slug: String,
    pub version: i64,
    pub title: String,
    pub body: String,
    pub data: String,
    pub created_at: String,
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

fn int(value: i64) -> SeaValue {
    SeaValue::BigInt(Some(value))
}

fn item_from(row: &Row) -> Item {
    Item {
        collection: row.get::<String>("collection").unwrap_or_default(),
        slug: row.get::<String>("slug").unwrap_or_default(),
        title: row.get::<String>("title").unwrap_or_default(),
        body: row.get::<String>("body").unwrap_or_default(),
        data: row.get::<String>("data").unwrap_or_else(|| "{}".to_owned()),
        status: row.get::<String>("status").unwrap_or_default(),
        version: row.get::<i64>("version").unwrap_or_default(),
        updated_at: row.get::<String>("updated_at").unwrap_or_default(),
    }
}

fn revision_from(row: &Row) -> Revision {
    Revision {
        collection: row.get::<String>("collection").unwrap_or_default(),
        slug: row.get::<String>("slug").unwrap_or_default(),
        version: row.get::<i64>("version").unwrap_or_default(),
        title: row.get::<String>("title").unwrap_or_default(),
        body: row.get::<String>("body").unwrap_or_default(),
        data: row.get::<String>("data").unwrap_or_else(|| "{}".to_owned()),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
    }
}

const ITEM_COLUMNS: &str = "collection, slug, title, body, data, status, version, updated_at";

/// The item for one (collection, slug), or `None`.
pub(crate) async fn find_item(
    db: &dyn Database,
    collection: &str,
    slug: &str,
) -> Result<Option<Item>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            format!("SELECT {ITEM_COLUMNS} FROM cms_item WHERE collection = ? AND slug = ?"),
            vec![text(collection), text(slug)],
        ))
        .await?;
    Ok(rows.first().map(item_from))
}

/// Every item in a collection, newest edit first. For the admin list.
pub(crate) async fn list_items(db: &dyn Database, collection: &str) -> Result<Vec<Item>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            format!(
                "SELECT {ITEM_COLUMNS} FROM cms_item WHERE collection = ? \
                 ORDER BY updated_at DESC"
            ),
            vec![text(collection)],
        ))
        .await?;
    Ok(rows.rows.iter().map(item_from).collect())
}

/// Creates or updates the draft fields of an item, leaving its published
/// state untouched. A brand-new item starts in `draft` at version 0.
pub(crate) async fn save_item(
    db: &dyn Database,
    collection: &str,
    slug: &str,
    title: &str,
    body: &str,
    data: &str,
    now: &str,
) -> Result<(), DbError> {
    db.execute(&Statement::with_values(
        "INSERT INTO cms_item (collection, slug, title, body, data, status, version, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, 0, ?) \
         ON CONFLICT(collection, slug) DO UPDATE SET \
         title = excluded.title, body = excluded.body, data = excluded.data, \
         updated_at = excluded.updated_at",
        vec![
            text(collection),
            text(slug),
            text(title),
            text(body),
            text(data),
            text(STATUS_DRAFT),
            text(now),
        ],
    ))
    .await?;
    Ok(())
}

/// Publishes the item's current draft: appends an immutable revision at the
/// next version and points the item at it, in one atomic batch. Returns the
/// new version.
pub(crate) async fn publish_item(
    db: &dyn Database,
    item: &Item,
    revision_id: &str,
    now: &str,
) -> Result<i64, DbError> {
    let next = item.version + 1;
    db.batch(&[
        Statement::with_values(
            "INSERT INTO cms_revision \
             (id, collection, slug, version, title, body, data, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(revision_id),
                text(&item.collection),
                text(&item.slug),
                int(next),
                text(&item.title),
                text(&item.body),
                text(&item.data),
                text(now),
            ],
        ),
        Statement::with_values(
            "UPDATE cms_item SET status = ?, version = ?, updated_at = ? \
             WHERE collection = ? AND slug = ?",
            vec![
                text(STATUS_PUBLISHED),
                int(next),
                text(now),
                text(&item.collection),
                text(&item.slug),
            ],
        ),
    ])
    .await?;
    Ok(next)
}

/// Marks an item unpublished: its public read stops resolving, but its
/// revisions are kept.
pub(crate) async fn unpublish_item(
    db: &dyn Database,
    collection: &str,
    slug: &str,
    now: &str,
) -> Result<(), DbError> {
    db.execute(&Statement::with_values(
        "UPDATE cms_item SET status = ?, updated_at = ? WHERE collection = ? AND slug = ?",
        vec![
            text(STATUS_UNPUBLISHED),
            text(now),
            text(collection),
            text(slug),
        ],
    ))
    .await?;
    Ok(())
}

/// Deletes an item and every revision of it.
pub(crate) async fn delete_item(
    db: &dyn Database,
    collection: &str,
    slug: &str,
) -> Result<(), DbError> {
    db.batch(&[
        Statement::with_values(
            "DELETE FROM cms_revision WHERE collection = ? AND slug = ?",
            vec![text(collection), text(slug)],
        ),
        Statement::with_values(
            "DELETE FROM cms_item WHERE collection = ? AND slug = ?",
            vec![text(collection), text(slug)],
        ),
    ])
    .await?;
    Ok(())
}

/// The published revision an item points at, or `None` when the item is not
/// currently published.
pub(crate) async fn published_revision(
    db: &dyn Database,
    collection: &str,
    slug: &str,
) -> Result<Option<Revision>, DbError> {
    let Some(item) = find_item(db, collection, slug).await? else {
        return Ok(None);
    };
    if item.status != STATUS_PUBLISHED {
        return Ok(None);
    }
    let rows = db
        .query(&Statement::with_values(
            "SELECT collection, slug, version, title, body, data, created_at \
             FROM cms_revision WHERE collection = ? AND slug = ? AND version = ?",
            vec![text(collection), text(slug), int(item.version)],
        ))
        .await?;
    Ok(rows.first().map(revision_from))
}

/// The published revisions of a whole collection, newest publish first.
pub(crate) async fn published_in_collection(
    db: &dyn Database,
    collection: &str,
) -> Result<Vec<Revision>, DbError> {
    // Join each published item to the revision it points at.
    let rows = db
        .query(&Statement::with_values(
            "SELECT r.collection AS collection, r.slug AS slug, r.version AS version, \
             r.title AS title, r.body AS body, r.data AS data, r.created_at AS created_at \
             FROM cms_item i \
             JOIN cms_revision r \
             ON r.collection = i.collection AND r.slug = i.slug AND r.version = i.version \
             WHERE i.collection = ? AND i.status = ? \
             ORDER BY r.created_at DESC",
            vec![text(collection), text(STATUS_PUBLISHED)],
        ))
        .await?;
    Ok(rows.rows.iter().map(revision_from).collect())
}
