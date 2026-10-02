//! `cratefield_core::Usage` (issue #588) against real SQLite **and** Postgres:
//! the guarded upsert admits exactly the allowance under concurrency, the
//! batch form rolls back with the work it pays for, refunds never go below
//! zero, and read/history/purge report the windows.

use cratefield_core::{Consumption, Database, Period, Statement, Usage};
use cratefield_testing::{Dialect, TestHarness, assert_batch_is_atomic};
use std::sync::{Arc, Barrier};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The effect table a batch commits beside its consumption, so a rolled-back
/// batch is observable.
const EFFECTS: &str = "CREATE TABLE IF NOT EXISTS usage_effects (\n    \
                       id TEXT PRIMARY KEY,\n    \
                       note TEXT NOT NULL\n);";

fn at(text: &str) -> OffsetDateTime {
    OffsetDateTime::parse(text, &Rfc3339).expect("test instant parses")
}

/// SQLite always; Postgres when the kit is built with the `postgres` feature
/// and `FZ_TEST_POSTGRES_URL` names a server (a non-postgres build never
/// constructs a Postgres harness, so the skip is real).
fn dialects() -> Vec<Dialect> {
    #[cfg(feature = "postgres")]
    {
        Dialect::available()
    }
    #[cfg(not(feature = "postgres"))]
    {
        vec![Dialect::Sqlite]
    }
}

/// A migrated empty harness per dialect, its effect table and the meter.
fn kits() -> Vec<(TestHarness, Usage)> {
    dialects()
        .into_iter()
        .map(|dialect| {
            let kit = TestHarness::with_database(Vec::new(), dialect);
            let usage = Usage::new("meter_usage");
            pollster::block_on(kit.db.execute(&Statement::new(usage.create_table_sql())))
                .expect("create usage table");
            pollster::block_on(kit.db.execute(&Statement::new(EFFECTS)))
                .expect("create effects table");
            (kit, usage)
        })
        .collect()
}

async fn effect_count(db: &dyn Database) -> i64 {
    let rows = db
        .query(&Statement::new("SELECT COUNT(*) AS n FROM usage_effects"))
        .await
        .expect("count effects");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .expect("one count row")
}

fn effect(id: &str) -> Statement {
    Statement::with_values(
        "INSERT INTO usage_effects (id, note) VALUES (?, ?)",
        vec![id.into(), "work".into()],
    )
}

/// A statement that always fails: the `note` column is `NOT NULL`.
fn doomed_effect(id: &str) -> Statement {
    Statement::with_values(
        "INSERT INTO usage_effects (id, note) VALUES (?, ?)",
        vec![id.into(), Option::<String>::None.into()],
    )
}

#[test]
fn concurrent_consumes_never_overspend() {
    for (kit, usage) in kits() {
        let period = Period::CalendarMonthUtc;
        let now = at("2026-06-15T12:00:00Z");
        let racers = 200;
        let gate = Arc::new(Barrier::new(racers));
        let mut handles = Vec::new();
        for _ in 0..racers {
            let db = Arc::clone(&kit.db);
            let usage = usage.clone();
            let gate = Arc::clone(&gate);
            handles.push(std::thread::spawn(move || {
                gate.wait();
                pollster::block_on(usage.consume(&*db, "acct", "mail", period, now, 1, Some(100)))
                    .expect("consume")
            }));
        }
        let admitted = handles
            .into_iter()
            .map(|handle| handle.join().expect("race thread"))
            .filter(|outcome| matches!(outcome, Consumption::Consumed(_)))
            .count();
        assert_eq!(
            admitted, 100,
            "{}: exactly the allowance was admitted",
            kit.dialect
        );
        let used =
            pollster::block_on(usage.read(&*kit.db, "acct", "mail", period, now)).expect("read");
        assert_eq!(used, 100, "{}: used equals the allowance", kit.dialect);
    }
}

#[test]
fn a_batch_commits_or_rolls_back_with_its_consumption() {
    for (kit, usage) in kits() {
        let period = Period::CalendarMonthUtc;
        let now = at("2026-06-15T12:00:00Z");
        let db = &*kit.db;
        pollster::block_on(async {
            assert_batch_is_atomic(db).await;

            // A batch that pays for its work: both commit.
            db.batch_atomic(&[
                usage.consume_statement("acct", "mail", period, now, 5, Some(10)),
                effect("ok"),
            ])
            .await
            .expect("a within-allowance batch commits");
            assert_eq!(
                usage.read(db, "acct", "mail", period, now).await.unwrap(),
                5
            );
            assert_eq!(effect_count(db).await, 1);

            // The consumption succeeds but the work fails: both roll back.
            db.batch_atomic(&[
                usage.consume_statement("acct", "mail", period, now, 5, Some(10)),
                doomed_effect("rolled-back"),
            ])
            .await
            .expect_err("a failing statement fails the batch");
            assert_eq!(
                usage.read(db, "acct", "mail", period, now).await.unwrap(),
                5
            );
            assert_eq!(effect_count(db).await, 1);

            // The allowance is spent: the consumption statement fails the
            // batch, and the paid-for work must not commit for free.
            db.batch_atomic(&[
                usage.consume_statement("acct", "mail", period, now, 6, Some(10)),
                effect("free-work"),
            ])
            .await
            .expect_err("an exhausted allowance fails the batch");
            assert_eq!(
                usage.read(db, "acct", "mail", period, now).await.unwrap(),
                5
            );
            assert_eq!(effect_count(db).await, 1);
        });
    }
}

#[test]
fn refund_never_goes_below_zero() {
    for (kit, usage) in kits() {
        let period = Period::CalendarMonthUtc;
        let now = at("2026-06-15T12:00:00Z");
        let db = &*kit.db;
        pollster::block_on(async {
            usage
                .consume(db, "acct", "mail", period, now, 3, None)
                .await
                .unwrap();
            usage
                .refund(db, "acct", "mail", period, now, 10)
                .await
                .unwrap();
            assert_eq!(
                usage.read(db, "acct", "mail", period, now).await.unwrap(),
                0
            );

            usage
                .consume(db, "acct", "mail", period, now, 4, None)
                .await
                .unwrap();
            usage
                .refund(db, "acct", "mail", period, now, 2)
                .await
                .unwrap();
            assert_eq!(
                usage.read(db, "acct", "mail", period, now).await.unwrap(),
                2
            );

            // A refund with no row at all is a no-op, not a negative row.
            usage
                .refund(db, "nobody", "mail", period, now, 5)
                .await
                .unwrap();
            assert_eq!(
                usage.read(db, "nobody", "mail", period, now).await.unwrap(),
                0
            );
        });
    }
}

#[test]
fn an_unbounded_meter_counts_without_a_ceiling() {
    for (kit, usage) in kits() {
        let period = Period::CalendarMonthUtc;
        let now = at("2026-06-15T12:00:00Z");
        let db = &*kit.db;
        pollster::block_on(async {
            for _ in 0..5 {
                let outcome = usage
                    .consume(db, "acct", "mail", period, now, 10, None)
                    .await
                    .unwrap();
                assert!(matches!(outcome, Consumption::Consumed(_)));
            }
            assert_eq!(
                usage.read(db, "acct", "mail", period, now).await.unwrap(),
                50
            );

            // No ceiling, and a u64 above i64::MAX saturates to the counter's
            // top rather than failing the Postgres bind. A fresh subject, so
            // the guard never adds to an existing total and overflows BIGINT.
            let outcome = usage
                .consume(db, "huge", "mail", period, now, u64::MAX, None)
                .await
                .unwrap();
            assert!(matches!(outcome, Consumption::Consumed(_)));
            assert_eq!(
                usage.read(db, "huge", "mail", period, now).await.unwrap(),
                u64::try_from(i64::MAX).expect("i64::MAX fits u64")
            );
        });
    }
}

#[test]
fn read_history_and_purge_agree_with_what_was_spent() {
    for (kit, usage) in kits() {
        let period = Period::CalendarMonthUtc;
        let db = &*kit.db;
        let (april, may, june) = (
            at("2026-04-10T12:00:00Z"),
            at("2026-05-10T12:00:00Z"),
            at("2026-06-15T12:00:00Z"),
        );
        pollster::block_on(async {
            // Nothing spent yet: zero, not an error.
            assert_eq!(
                usage.read(db, "acct", "mail", period, june).await.unwrap(),
                0
            );
            usage
                .consume(db, "acct", "mail", period, april, 1, None)
                .await
                .unwrap();
            usage
                .consume(db, "acct", "mail", period, may, 3, None)
                .await
                .unwrap();
            usage
                .consume(db, "acct", "mail", period, june, 7, None)
                .await
                .unwrap();

            // Most recent first, an empty older period reported as zero.
            let history = usage
                .history(db, "acct", "mail", period, june, 3)
                .await
                .unwrap();
            assert_eq!(history.len(), 3);
            assert_eq!(
                (history[0].0.start, history[0].1),
                (at("2026-06-01T00:00:00Z"), 7)
            );
            assert_eq!(
                (history[1].0.start, history[1].1),
                (at("2026-05-01T00:00:00Z"), 3)
            );
            assert_eq!(
                (history[2].0.start, history[2].1),
                (at("2026-04-01T00:00:00Z"), 1)
            );

            // Retention keeps the two most recent windows and drops April.
            let now = at("2026-06-20T00:00:00Z");
            assert_eq!(usage.purge(db, period, now, 2).await.unwrap(), 1);
            let history = usage
                .history(db, "acct", "mail", period, now, 3)
                .await
                .unwrap();
            assert_eq!(history[2].1, 0, "a purged window reads as zero");
            // Keeping nothing clears the meter.
            assert_eq!(usage.purge(db, period, now, 0).await.unwrap(), 2);
        });
    }
}
