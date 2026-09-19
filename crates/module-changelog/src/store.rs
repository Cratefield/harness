//! Data access for the changelog tables, in the portable SQL subset. Reads
//! and writes go through [`Statement::with_values`] with `?` placeholders,
//! so the same statements run on the sqlite adapter, D1 and Postgres. The
//! only interpolated numbers are page bounds the handler has already parsed
//! and clamped.

use std::collections::{HashMap, HashSet};

use cratefield_core::{Clock, Database, DbError, Row, Statement};
use sea_query::Value as SeaValue;

/// A stored release: what upstream published, verbatim, plus the
/// bookkeeping the store adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Release {
    pub source: String,
    pub version: String,
    pub title: String,
    pub body: String,
    pub url: String,
    pub published_at: String,
    pub prerelease: bool,
    pub draft: bool,
    pub first_seen_at: String,
    pub updated_at: String,
}

/// One release as upstream reports it right now — the fields a refresh
/// compares, without the bookkeeping the store adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpstreamRelease {
    pub version: String,
    pub title: String,
    pub body: String,
    pub url: String,
    pub published_at: String,
    pub prerelease: bool,
    pub draft: bool,
}

/// The `changelog_source` row: how the last fetch went and which cache
/// generation is current.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SourceState {
    pub source: String,
    pub etag: String,
    pub generation: String,
    pub last_refreshed_at: String,
    pub last_status: String,
}

/// What one refresh changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RefreshCounts {
    pub inserted: u64,
    pub updated: u64,
    pub unchanged: u64,
    pub removed: u64,
}

impl RefreshCounts {
    /// Whether the database now holds anything it did not before the
    /// refresh — the condition on which the cache generation moves.
    pub(crate) fn changed(&self) -> bool {
        self.inserted + self.updated + self.removed > 0
    }
}

const RELEASE_COLUMNS: &str = "source, version, title, body, url, published_at, prerelease, \
     draft, first_seen_at, updated_at";

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

fn flag(value: bool) -> SeaValue {
    SeaValue::BigInt(Some(i64::from(value)))
}

/// The RFC 3339 wall-clock timestamp a refresh stamps its rows with, from
/// the `Clock` port, truncated to whole seconds — the same shape every other
/// module stores.
pub(crate) fn now_iso(clock: &dyn Clock) -> String {
    use time::format_description::well_known::Rfc3339;
    clock
        .now()
        .replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn release_from(row: &Row) -> Release {
    Release {
        source: row.get::<String>("source").unwrap_or_default(),
        version: row.get::<String>("version").unwrap_or_default(),
        title: row.get::<String>("title").unwrap_or_default(),
        body: row.get::<String>("body").unwrap_or_default(),
        url: row.get::<String>("url").unwrap_or_default(),
        published_at: row.get::<String>("published_at").unwrap_or_default(),
        prerelease: row.get::<i64>("prerelease").unwrap_or_default() != 0,
        draft: row.get::<i64>("draft").unwrap_or_default() != 0,
        first_seen_at: row.get::<String>("first_seen_at").unwrap_or_default(),
        updated_at: row.get::<String>("updated_at").unwrap_or_default(),
    }
}

fn source_state_from(row: &Row) -> SourceState {
    SourceState {
        source: row.get::<String>("source").unwrap_or_default(),
        etag: row.get::<String>("etag").unwrap_or_default(),
        generation: row.get::<String>("generation").unwrap_or_default(),
        last_refreshed_at: row.get::<String>("last_refreshed_at").unwrap_or_default(),
        last_status: row.get::<String>("last_status").unwrap_or_default(),
    }
}

/// One page of releases for `source`, newest first. The ordering is the
/// `changelog_release_by_published` index; `limit`/`offset` are parsed,
/// clamped numbers, interpolated rather than bound because both engines take
/// them as integers in every position the portable subset allows.
pub(crate) async fn list_releases(
    db: &dyn Database,
    source: &str,
    limit: u64,
    offset: u64,
) -> Result<Vec<Release>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            format!(
                "SELECT {RELEASE_COLUMNS} FROM changelog_release WHERE source = ? \
                 ORDER BY published_at DESC, version DESC LIMIT {limit} OFFSET {offset}"
            ),
            vec![text(source)],
        ))
        .await?;
    Ok(rows.rows.iter().map(release_from).collect())
}

/// How many releases `source` has, for the list's `total`.
pub(crate) async fn count_releases(db: &dyn Database, source: &str) -> Result<u64, DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT COUNT(*) AS total FROM changelog_release WHERE source = ?",
            vec![text(source)],
        ))
        .await?;
    let total = rows
        .first()
        .and_then(|row| row.get::<i64>("total"))
        .unwrap_or_default();
    Ok(u64::try_from(total.max(0)).unwrap_or_default())
}

/// The one release for `source` at `version`, or `None`.
pub(crate) async fn find_release(
    db: &dyn Database,
    source: &str,
    version: &str,
) -> Result<Option<Release>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            format!(
                "SELECT {RELEASE_COLUMNS} FROM changelog_release \
                 WHERE source = ? AND version = ?"
            ),
            vec![text(source), text(version)],
        ))
        .await?;
    Ok(rows.first().map(release_from))
}

/// The source's bookkeeping row, or `None` before the first refresh.
pub(crate) async fn source_state(
    db: &dyn Database,
    source: &str,
) -> Result<Option<SourceState>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT source, etag, generation, last_refreshed_at, last_status \
             FROM changelog_source WHERE source = ?",
            vec![text(source)],
        ))
        .await?;
    Ok(rows.first().map(source_state_from))
}

/// The stored upstream-derived fields of one row, keyed by version — what a
/// refresh compares against. `(title, body, url, published_at, prerelease,
/// draft)`.
type StoredFields = (String, String, String, String, bool, bool);

fn stored_fields_of(db_rows: &[Row]) -> HashMap<String, StoredFields> {
    let mut existing = HashMap::with_capacity(db_rows.len());
    for row in db_rows {
        let Some(version) = row.get::<String>("version") else {
            continue;
        };
        existing.insert(
            version,
            (
                row.get::<String>("title").unwrap_or_default(),
                row.get::<String>("body").unwrap_or_default(),
                row.get::<String>("url").unwrap_or_default(),
                row.get::<String>("published_at").unwrap_or_default(),
                row.get::<i64>("prerelease").unwrap_or_default() != 0,
                row.get::<i64>("draft").unwrap_or_default() != 0,
            ),
        );
    }
    existing
}

/// The INSERT for a release the read said is not stored yet — an **upsert**
/// on the primary key. Two overlapping refreshes (the schedule and an admin
/// `POST`) can both read the row as missing and both attempt this insert;
/// the primary key would turn the loser into a `DbError` and a 500 for data
/// that is in fact consistent. On conflict the upstream-derived fields move
/// and `first_seen_at` — and the row itself — stay.
fn insert_release(source: &str, release: &UpstreamRelease, now: &str) -> Statement {
    Statement::with_values(
        format!(
            "INSERT INTO changelog_release ({RELEASE_COLUMNS}) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(source, version) DO UPDATE SET \
                 title = excluded.title, body = excluded.body, url = excluded.url, \
                 published_at = excluded.published_at, prerelease = excluded.prerelease, \
                 draft = excluded.draft, updated_at = excluded.updated_at"
        ),
        vec![
            text(source),
            text(&release.version),
            text(&release.title),
            text(&release.body),
            text(&release.url),
            text(&release.published_at),
            flag(release.prerelease),
            flag(release.draft),
            text(now),
            text(now),
        ],
    )
}

/// Mirrors one successful fetch into the database, **without churn**: the
/// stored rows are read once, and a release whose upstream-derived fields
/// (title, body, url, `published_at`, prerelease, draft) all match writes
/// nothing at all — its `updated_at` does not move. `prune` decides the fate
/// of versions upstream no longer reports: the caller passes `true` only for
/// a fetch that saw the whole source, because a fetch that stopped at the
/// page cap cannot tell "upstream deleted it" from "it is on a page we did
/// not reach", and pruning against a prefix would take every release past
/// the cap with it. `first_seen_at` survives every update. All the writes
/// commit as one batch.
pub(crate) async fn apply_refresh(
    db: &dyn Database,
    source: &str,
    incoming: &[UpstreamRelease],
    now: &str,
    prune: bool,
) -> Result<RefreshCounts, DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT version, title, body, url, published_at, prerelease, draft \
             FROM changelog_release WHERE source = ?",
            vec![text(source)],
        ))
        .await?;
    let existing = stored_fields_of(&rows.rows);

    let mut counts = RefreshCounts::default();
    let mut statements: Vec<Statement> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::with_capacity(incoming.len());

    for release in incoming {
        // The same version twice in one payload would fight the row the
        // first copy just wrote; the first one wins.
        if !seen.insert(release.version.as_str()) {
            continue;
        }
        match existing.get(&release.version) {
            Some((title, body, url, published_at, prerelease, draft))
                if title == &release.title
                    && body == &release.body
                    && url == &release.url
                    && published_at == &release.published_at
                    && prerelease == &release.prerelease
                    && draft == &release.draft =>
            {
                counts.unchanged += 1;
            }
            Some(_) => {
                counts.updated += 1;
                statements.push(Statement::with_values(
                    "UPDATE changelog_release \
                     SET title = ?, body = ?, url = ?, published_at = ?, prerelease = ?, \
                         draft = ?, updated_at = ? \
                     WHERE source = ? AND version = ?",
                    vec![
                        text(&release.title),
                        text(&release.body),
                        text(&release.url),
                        text(&release.published_at),
                        flag(release.prerelease),
                        flag(release.draft),
                        text(now),
                        text(source),
                        text(&release.version),
                    ],
                ));
            }
            None => {
                counts.inserted += 1;
                statements.push(insert_release(source, release, now));
            }
        }
    }

    if prune {
        for version in existing.keys() {
            if !seen.contains(version.as_str()) {
                counts.removed += 1;
                statements.push(Statement::with_values(
                    "DELETE FROM changelog_release WHERE source = ? AND version = ?",
                    vec![text(source), text(version)],
                ));
            }
        }
    }

    if !statements.is_empty() {
        db.batch_atomic(&statements).await?;
    }
    Ok(counts)
}

/// Records a **successful** refresh: the new etag, the generation that is
/// current as of it, when it ran and how it went.
pub(crate) async fn record_source(
    db: &dyn Database,
    source: &str,
    etag: &str,
    generation: &str,
    last_refreshed_at: &str,
    last_status: &str,
) -> Result<(), DbError> {
    db.execute(&Statement::with_values(
        "INSERT INTO changelog_source \
             (source, etag, generation, last_refreshed_at, last_status) \
         VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT(source) DO UPDATE SET \
             etag = excluded.etag, generation = excluded.generation, \
             last_refreshed_at = excluded.last_refreshed_at, \
             last_status = excluded.last_status",
        vec![
            text(source),
            text(etag),
            text(generation),
            text(last_refreshed_at),
            text(last_status),
        ],
    ))
    .await?;
    Ok(())
}

/// Records a **failed** attempt: when it ran and how it went. The etag and
/// the generation stay, and no release row is touched — a failed refresh
/// must not corrupt or clear what is stored.
pub(crate) async fn record_status(
    db: &dyn Database,
    source: &str,
    last_status: &str,
    last_refreshed_at: &str,
) -> Result<(), DbError> {
    db.execute(&Statement::with_values(
        "INSERT INTO changelog_source \
             (source, etag, generation, last_refreshed_at, last_status) \
         VALUES (?, '', '', ?, ?) \
         ON CONFLICT(source) DO UPDATE SET \
             last_refreshed_at = excluded.last_refreshed_at, \
             last_status = excluded.last_status",
        vec![text(source), text(last_refreshed_at), text(last_status)],
    ))
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Changelog;
    use cratefield_testing::TestHarness;

    fn release(version: &str, title: &str, body: &str) -> UpstreamRelease {
        UpstreamRelease {
            version: version.to_owned(),
            title: title.to_owned(),
            body: body.to_owned(),
            url: String::new(),
            published_at: String::new(),
            prerelease: false,
            draft: false,
        }
    }

    /// The insert is an upsert: two overlapping refreshes — the schedule and
    /// an admin `POST` — can both read a release as missing and both attempt
    /// the insert, and the primary key must turn the loser into an in-place
    /// update, not a `DbError` and a 500 for data that is in fact
    /// consistent. On conflict the upstream-derived fields move and
    /// `first_seen_at` stays exactly where the first insert put it.
    ///
    /// The race itself cannot be reproduced through the routes (the store
    /// reads before it writes), so the test runs the very statement a losing
    /// refresh runs — [`insert_release`] against an occupied key — on every
    /// dialect the environment provides.
    #[test]
    fn a_conflicting_insert_updates_in_place_and_keeps_first_seen() {
        for harness in
            TestHarness::all_dialects(|| vec![Box::new(Changelog::new().repo("owner/name"))])
        {
            let source = "github-releases:owner/name";

            // The first refresh inserts.
            let first = pollster::block_on(apply_refresh(
                harness.db.as_ref(),
                source,
                &[release("v1.0.0", "1.0.0", "- where it started")],
                "2026-01-01T00:00:00Z",
                true,
            ))
            .expect("the first insert lands");
            assert_eq!(first.inserted, 1, "{}", harness.dialect);

            // The racing refresh has read the same "not there" and now runs
            // its own insert for the same key — the upsert, not a bare
            // INSERT the primary key would refuse.
            pollster::block_on(harness.db.execute(&insert_release(
                source,
                &release("v1.0.0", "1.0.0 rewritten", "- rewritten upstream"),
                "2026-02-01T00:00:00Z",
            )))
            .expect("a conflicting insert is an update, not a primary-key error");

            let rows = pollster::block_on(harness.db.query(&Statement::with_values(
                "SELECT title, body, first_seen_at, updated_at FROM changelog_release \
                 WHERE source = ? AND version = ?",
                vec![text(source), text("v1.0.0")],
            )))
            .expect("the row reads");
            let row = rows.first().expect("still exactly one row");
            assert_eq!(
                row.get::<String>("title").as_deref(),
                Some("1.0.0 rewritten"),
                "{}",
                harness.dialect,
            );
            assert_eq!(
                row.get::<String>("body").as_deref(),
                Some("- rewritten upstream"),
                "{}",
                harness.dialect,
            );
            assert_eq!(
                row.get::<String>("first_seen_at").as_deref(),
                Some("2026-01-01T00:00:00Z"),
                "the conflict moved first_seen_at ({})",
                harness.dialect,
            );
            assert_eq!(
                row.get::<String>("updated_at").as_deref(),
                Some("2026-02-01T00:00:00Z"),
                "{}",
                harness.dialect,
            );

            // And the store's own comparison still recognises the row: the
            // next refresh is a no-op, not another insert.
            let second = pollster::block_on(apply_refresh(
                harness.db.as_ref(),
                source,
                &[release("v1.0.0", "1.0.0 rewritten", "- rewritten upstream")],
                "2026-03-01T00:00:00Z",
                true,
            ))
            .expect("the follow-up refresh runs");
            assert_eq!(second.inserted, 0, "{}", harness.dialect);
            assert_eq!(second.unchanged, 1, "{}", harness.dialect);
        }
    }
}
