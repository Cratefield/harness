//! The audit log (issue #878): who did what to which resource of an
//! organization, and with which credential.
//!
//! Append-only by API: there is [`record`] and there is [`list`], and no
//! function here updates or deletes an entry. An entry names its **actor** (a
//! member or a service account, by kind and id), the member a service account
//! acted **on behalf of** when there is one, and the **credential** — a key or
//! token *prefix*, or `session` — never a secret. `resource` and `detail` are
//! the venture's own vocabulary; keep secrets and page text out of both.

use cratefield_core::{Database, DbError, Row, Statement};
use time::OffsetDateTime;

use crate::clock::iso;

/// The audit table.
pub const TABLE: &str = "org_audit";

/// The most entries one [`list`] call answers.
pub const MAX_PAGE: usize = 200;

/// The longest a stored field may be, in characters; longer values are cut.
const MAX_FIELD: usize = 2000;

/// One audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// The entry's id. Time-ordered ids (a ULID) make [`list`]'s order the
    /// order things happened in.
    pub id: String,
    /// The organization.
    pub org_id: String,
    /// `member`, `service_account`, or the venture's own word.
    pub actor_kind: String,
    /// The actor's id.
    pub actor_id: String,
    /// The member a service account acted for, when there is one.
    pub on_behalf_of: Option<String>,
    /// The credential's public prefix, or `session`.
    pub credential: String,
    /// What was done, as a dotted verb: `member.invite`, `grant.create`, …
    pub action: String,
    /// What it was done to.
    pub resource: String,
    /// Anything else worth keeping, short.
    pub detail: String,
    /// When (RFC 3339), set by [`record`].
    pub at: String,
}

fn cut(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control() || *ch == '\n')
        .take(MAX_FIELD)
        .collect()
}

/// Appends one entry, stamped `now`. Fields longer than 2000 characters are
/// cut and control characters dropped, so an entry cannot be used to smuggle
/// a terminal escape into whoever reads the log.
///
/// # Errors
///
/// [`DbError`] when the insert fails.
pub async fn record(
    db: &dyn Database,
    entry: &AuditEntry,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    let statement = Statement::with_values(
        "INSERT INTO org_audit \
           (id, org_id, actor_kind, actor_id, on_behalf_of, credential, action, resource, \
            detail, at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            entry.id.as_str().into(),
            entry.org_id.as_str().into(),
            cut(&entry.actor_kind).into(),
            cut(&entry.actor_id).into(),
            entry.on_behalf_of.as_deref().map(cut).into(),
            cut(&entry.credential).into(),
            cut(&entry.action).into(),
            cut(&entry.resource).into(),
            cut(&entry.detail).into(),
            iso(now).into(),
        ],
    );
    db.execute(&statement).await.map(|_| ())
}

fn entry_from(row: &Row) -> AuditEntry {
    let text = |name: &str| row.get::<String>(name).unwrap_or_default();
    AuditEntry {
        id: text("id"),
        org_id: text("org_id"),
        actor_kind: text("actor_kind"),
        actor_id: text("actor_id"),
        on_behalf_of: row
            .get::<String>("on_behalf_of")
            .filter(|value| !value.is_empty()),
        credential: text("credential"),
        action: text("action"),
        resource: text("resource"),
        detail: text("detail"),
        at: text("at"),
    }
}

/// Entries of `org_id`, newest first: at most `limit` (capped at
/// [`MAX_PAGE`]), and only those with an id below `before` when one is given
/// — pass the last id of a page to read the next.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub async fn list(
    db: &dyn Database,
    org_id: &str,
    before: Option<&str>,
    limit: usize,
) -> Result<Vec<AuditEntry>, DbError> {
    let limit = limit.clamp(1, MAX_PAGE);
    let columns = "id, org_id, actor_kind, actor_id, on_behalf_of, credential, action, \
                   resource, detail, at";
    let statement = match before {
        None => Statement::with_values(
            format!(
                "SELECT {columns} FROM org_audit WHERE org_id = ? ORDER BY id DESC LIMIT {limit}"
            ),
            vec![org_id.into()],
        ),
        Some(before) => Statement::with_values(
            format!(
                "SELECT {columns} FROM org_audit WHERE org_id = ? AND id < ? \
                 ORDER BY id DESC LIMIT {limit}"
            ),
            vec![org_id.into(), before.into()],
        ),
    };
    Ok(db
        .query(&statement)
        .await?
        .rows
        .iter()
        .map(entry_from)
        .collect())
}
