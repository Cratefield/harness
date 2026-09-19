//! Sea-query data access for the two telemetry tables (issue #413). Both
//! are aggregate: a batch never becomes a row per event, it accumulates
//! into one bucket per dimension tuple, so a client that runs a command
//! ten thousand times leaves one row behind, not ten thousand. Values are
//! always bound, never interpolated — though it would cost a client
//! nothing, since every value has already passed a closed grammar.

use crate::payload::Batch;
use cratefield_core::{Database, DbError, Row, Statement};
use sea_query::{Alias, Expr, OnConflict, Query};

const EVENTS_TABLE: &str = "telemetry_events";
const MODULES_TABLE: &str = "telemetry_modules";

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// One accumulated dimension bucket: the four event dimensions, with the
/// counts of every identical record in the batch summed into it.
struct Bucket {
    event: String,
    outcome: String,
    error_kind: String,
    duration: String,
    count: i64,
}

impl Bucket {
    fn matches(&self, record: &crate::payload::EventRecord) -> bool {
        self.event == record.name
            && self.outcome == record.outcome.as_str()
            && self.error_kind == record.error.as_str()
            && self.duration == record.duration.as_str()
    }
}

/// Writes one accepted batch in a single all-or-nothing call: one upsert
/// per distinct dimension bucket plus one insert per reported module.
/// Nothing about the caller is written — no IP, no user agent, nothing but
/// the batch's own closed-grammar values (issue #413).
///
/// # Errors
/// Any database error; the batch is then written whole or not at all.
pub(crate) async fn record_batch(
    db: &dyn Database,
    batch: &Batch,
    day: &str,
    now: &str,
) -> Result<(), DbError> {
    // Accumulate first: two records in one batch that land in the same
    // bucket must arrive as one row, or the upserts below would try to
    // affect the same row twice in one statement — which Postgres refuses.
    let mut buckets: Vec<Bucket> = Vec::new();
    for record in &batch.events {
        match buckets.iter_mut().find(|bucket| bucket.matches(record)) {
            Some(bucket) => bucket.count += i64::from(record.count),
            None => buckets.push(Bucket {
                event: record.name.clone(),
                outcome: record.outcome.as_str().to_owned(),
                error_kind: record.error.as_str().to_owned(),
                duration: record.duration.as_str().to_owned(),
                count: i64::from(record.count),
            }),
        }
    }

    let client = &batch.client;
    let version = client.version.to_string();
    let mut stmts = Vec::with_capacity(buckets.len() + batch.modules.len());
    for bucket in &buckets {
        // The key is the dimension tuple joined with `|`, day first: two
        // writes on different days are different buckets, and a bucket is
        // where an install's counts accumulate for one day. The join stays
        // unambiguous without claiming the impossible: the event name is
        // venture-chosen, and could in principle carry a `|`. What makes
        // the key safe is position — the six components before the event
        // and the three after it (the day, the install id, the client
        // fields, the outcome, the error class, the duration bucket) are
        // all closed values that cannot carry a `|`, so the tuple splits
        // uniquely from both ends no matter what the name contains, and
        // `validate_config` refuses a declared name carrying one at all.
        // The stored columns, not the key, are what queries read.
        let bucket_key = [
            day,
            batch.install.as_str(),
            client.kind.as_str(),
            version.as_str(),
            client.platform.as_str(),
            client.arch.as_str(),
            bucket.event.as_str(),
            bucket.outcome.as_str(),
            bucket.error_kind.as_str(),
            bucket.duration.as_str(),
        ]
        .join("|");

        let mut insert = Query::insert();
        insert
            .into_table(iden(EVENTS_TABLE))
            .columns([
                "bucket_key",
                "day",
                "install_id",
                "client_kind",
                "client_version",
                "platform",
                "arch",
                "event",
                "outcome",
                "error_kind",
                "duration_bucket",
                "events",
                "first_seen_at",
                "last_seen_at",
            ])
            .values_panic([
                bucket_key.into(),
                day.into(),
                batch.install.as_str().into(),
                client.kind.as_str().into(),
                version.as_str().into(),
                client.platform.as_str().into(),
                client.arch.as_str().into(),
                bucket.event.as_str().into(),
                bucket.outcome.as_str().into(),
                bucket.error_kind.as_str().into(),
                bucket.duration.as_str().into(),
                bucket.count.into(),
                now.into(),
                now.into(),
            ])
            // Accumulate, never replace: a repeat batch adds its counts to
            // the bucket. sea-query's `OnConflict::value` renders the
            // accumulation with qualified columns —
            // `"events" = "telemetry_events"."events" +
            // "excluded"."events"` — which SQLite and Postgres both accept;
            // an `INSERT OR IGNORE` here would lose counts instead.
            .on_conflict(
                OnConflict::column(iden("bucket_key"))
                    .value(
                        iden("events"),
                        Expr::col((iden(EVENTS_TABLE), iden("events")))
                            .add(Expr::col((Alias::new("excluded"), iden("events")))),
                    )
                    .value(iden("last_seen_at"), now)
                    .to_owned(),
            );
        stmts.push(Statement::render(&insert));
    }

    for module in &batch.modules {
        let mut insert = Query::insert();
        insert
            .into_table(iden(MODULES_TABLE))
            .columns(["install_id", "day", "module"])
            .values_panic([
                batch.install.as_str().into(),
                day.into(),
                module.as_str().into(),
            ])
            // A module reported twice in one day is one row (the
            // parse-time duplicate rule bounds how many inserts there can
            // be); `ON CONFLICT DO NOTHING` is the portable form —
            // `INSERT OR IGNORE` would not survive Postgres.
            .on_conflict(
                OnConflict::columns([iden("install_id"), iden("day"), iden("module")])
                    .do_nothing()
                    .to_owned(),
            );
        stmts.push(Statement::render(&insert));
    }

    db.batch_atomic(&stmts).await
}

/// One aggregate row of the admin usage report: the dimensions and the two
/// totals over them. There is no install id on this type — the GROUP BY is
/// the privacy control, so a per-install row never exists to leak.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct UsageRow {
    /// The counted event name.
    #[serde(rename = "event")]
    pub event: String,
    /// How the runs ended.
    #[serde(rename = "outcome")]
    pub outcome: String,
    /// The error class.
    #[serde(rename = "error")]
    pub error_kind: String,
    /// The duration bucket.
    #[serde(rename = "duration")]
    pub duration_bucket: String,
    /// The client version triple.
    #[serde(rename = "version")]
    pub client_version: String,
    /// The client platform.
    #[serde(rename = "platform")]
    pub platform: String,
    /// The day bucket, `YYYY-MM-DD`.
    #[serde(rename = "day")]
    pub day: String,
    /// The accumulated count over all installs.
    #[serde(rename = "total")]
    pub total: i64,
    /// How many distinct installs are behind the total.
    #[serde(rename = "installs")]
    pub installs: i64,
}

/// The admin aggregate: one row per (event, outcome, error class, duration
/// bucket, client version, platform, day) with the total count and the
/// number of distinct installs behind it, grouped in SQL (issue #413).
///
/// # Errors
/// Any database error.
pub(crate) async fn usage(db: &dyn Database) -> Result<Vec<UsageRow>, DbError> {
    let dimensions = [
        "event",
        "outcome",
        "error_kind",
        "duration_bucket",
        "client_version",
        "platform",
        "day",
    ];
    let mut select = Query::select();
    select
        .columns(dimensions)
        .expr_as(Expr::col(iden("events")).sum(), iden("total"))
        .expr_as(
            Expr::col(iden("install_id")).count_distinct(),
            iden("installs"),
        )
        .from(iden(EVENTS_TABLE))
        .group_by_columns(dimensions)
        .order_by(iden("day"), sea_query::Order::Asc)
        .order_by(iden("event"), sea_query::Order::Asc)
        .limit(u64::try_from(cratefield_core::MAX_EXPORT_ROWS).unwrap_or(u64::MAX));
    let rows = db.query(&Statement::render(&select)).await?;
    Ok(rows.rows.iter().map(row_from).collect())
}

fn row_from(row: &Row) -> UsageRow {
    UsageRow {
        event: row.get("event").unwrap_or_default(),
        outcome: row.get("outcome").unwrap_or_default(),
        error_kind: row.get("error_kind").unwrap_or_default(),
        duration_bucket: row.get("duration_bucket").unwrap_or_default(),
        client_version: row.get("client_version").unwrap_or_default(),
        platform: row.get("platform").unwrap_or_default(),
        day: row.get("day").unwrap_or_default(),
        total: row.get("total").unwrap_or_default(),
        installs: row.get("installs").unwrap_or_default(),
    }
}

/// Deletes the buckets of both tables whose `day` is strictly older than
/// `day` (ISO dates compare lexicographically, so a string comparison is
/// the whole purge). Called by the module's scheduled handler; safe to run
/// as often as the venture likes, because it deletes at most everything.
///
/// # Errors
/// Any database error.
pub(crate) async fn purge_older_than(db: &dyn Database, day: &str) -> Result<u64, DbError> {
    let mut events = Query::delete();
    events
        .from_table(iden(EVENTS_TABLE))
        .and_where(Expr::col(iden("day")).lt(day));
    let mut modules = Query::delete();
    modules
        .from_table(iden(MODULES_TABLE))
        .and_where(Expr::col(iden("day")).lt(day));
    let deleted_events = db.execute(&Statement::render(&events)).await?;
    let deleted_modules = db.execute(&Statement::render(&modules)).await?;
    Ok(deleted_events + deleted_modules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Telemetry;
    use crate::payload::{
        Arch, Client, ClientKind, DurationBucket, ErrorKind, EventRecord, Outcome, Platform,
        Version,
    };
    use cratefield_core::Module;

    fn db() -> cratefield_adapter_sqlite::SqliteDatabase {
        let module = Telemetry::new().events(["run"]).modules(["telemetry"]);
        let db =
            cratefield_adapter_sqlite::SqliteDatabase::in_memory().expect("in-memory database");
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .expect("migrations");
        db
    }

    fn batch(install: &str, count: u32) -> Batch {
        Batch {
            schema: crate::payload::SCHEMA,
            install: install.to_owned(),
            client: Client {
                kind: ClientKind::Cli,
                version: Version {
                    major: 0,
                    minor: 4,
                    patch: 1,
                },
                platform: Platform::Linux,
                arch: Arch::Aarch64,
            },
            modules: vec!["telemetry".to_owned()],
            events: vec![
                EventRecord {
                    name: "run".to_owned(),
                    outcome: Outcome::Ok,
                    error: ErrorKind::None,
                    duration: DurationBucket::Unknown,
                    count,
                },
                // Two records, same bucket: they must arrive as one row.
                EventRecord {
                    name: "run".to_owned(),
                    outcome: Outcome::Ok,
                    error: ErrorKind::None,
                    duration: DurationBucket::Unknown,
                    count: 2,
                },
            ],
        }
    }

    fn count(db: &cratefield_adapter_sqlite::SqliteDatabase, sql: &str, install: &str) -> i64 {
        pollster::block_on(db.query(&Statement::with_values(
            sql.to_owned(),
            vec![install.into()],
        )))
        .expect("query")
        .rows
        .first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
    }

    /// The accumulation path end to end, against real SQL: same batch
    /// twice is one bucket with summed counts, a second install is a
    /// second bucket, and the modules table stays deduplicated.
    #[test]
    fn a_repeat_batch_accumulates_counts_not_rows() {
        let db = db();
        let alice = "7b0a1f2c3d4e5f60718293a4b5c6d7e8";
        let bob = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
        pollster::block_on(async {
            record_batch(&db, &batch(alice, 3), "2027-01-15", "2027-01-15T00:00:00Z")
                .await
                .expect("first write");
            record_batch(&db, &batch(alice, 3), "2027-01-15", "2027-01-15T01:00:00Z")
                .await
                .expect("second write");
            record_batch(&db, &batch(bob, 1), "2027-01-15", "2027-01-15T02:00:00Z")
                .await
                .expect("third write");
        });

        let rows = pollster::block_on(
            db.query(&Statement::with_values(
                "SELECT install_id, day, event, outcome, error_kind, duration_bucket, \
             client_kind, client_version, platform, arch, events, first_seen_at, \
             last_seen_at FROM telemetry_events WHERE install_id = ? ORDER BY day"
                    .to_owned(),
                vec![alice.into()],
            )),
        )
        .expect("query");
        assert_eq!(
            rows.rows.len(),
            1,
            "one bucket per day, not per record or per batch"
        );
        let alice_row = &rows.rows[0];
        assert_eq!(
            alice_row.get::<i64>("events"),
            Some(10),
            "the batch's two same-bucket records arrived as 5, twice"
        );
        assert_eq!(
            alice_row.get::<String>("first_seen_at").as_deref(),
            Some("2027-01-15T00:00:00Z"),
            "the bucket's first write is kept"
        );
        assert_eq!(
            alice_row.get::<String>("last_seen_at").as_deref(),
            Some("2027-01-15T01:00:00Z"),
            "the bucket's last write wins"
        );

        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) AS n FROM telemetry_modules WHERE install_id = ?",
                alice
            ),
            1,
            "a module reported repeatedly is one row"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) AS n FROM telemetry_modules WHERE install_id = ?",
                bob
            ),
            1
        );

        let report = pollster::block_on(usage(&db)).expect("usage");
        assert_eq!(
            report.len(),
            1,
            "the two installs share dimensions, so the GROUP BY merges them"
        );
        assert_eq!(
            report[0].total, 13,
            "3 + 2, twice for alice, 1 + 2 once for bob"
        );
        assert_eq!(report[0].installs, 2, "both installs are behind the total");
        assert!(
            !format!("{report:?}").contains(alice),
            "the aggregate carries no install id to leak"
        );
    }

    /// The retention purge removes strictly older days, from both tables,
    /// and leaves the rest alone.
    #[test]
    fn the_purge_removes_only_days_past_retention() {
        let db = db();
        let alice = "7b0a1f2c3d4e5f60718293a4b5c6d7e8";
        pollster::block_on(async {
            record_batch(&db, &batch(alice, 1), "2026-06-01", "2026-06-01T00:00:00Z")
                .await
                .expect("old write");
            record_batch(&db, &batch(alice, 1), "2027-01-15", "2027-01-15T00:00:00Z")
                .await
                .expect("fresh write");
        });
        let deleted = pollster::block_on(purge_older_than(&db, "2027-01-01")).expect("purge");
        assert_eq!(deleted, 2, "one old bucket in each table");
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) AS n FROM telemetry_events WHERE install_id = ?",
                alice
            ),
            1,
            "the fresh bucket stays"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) AS n FROM telemetry_modules WHERE install_id = ?",
                alice
            ),
            1,
            "the fresh module row stays"
        );
    }
}
