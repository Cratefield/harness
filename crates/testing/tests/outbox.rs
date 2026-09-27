//! Integration test for `cratefield_core::Outbox` (issue #128) against real
//! SQLite: enqueue, lease-once (a second drainer sees nothing while leased),
//! complete removes, retry reschedules with an incremented attempt count.
//! Plus the budget-aware drain (issue #537): `reschedule` as the per-item
//! cursor, and `drain_within` stopping when the invocation budget is spent.

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{
    Database, DrainOptions, Outbox, OutboxRecord, Processed, ScheduledBudget, Statement,
};
use cratefield_testing::FixedClock;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

fn db_with_outbox(outbox: &Outbox) -> SqliteDatabase {
    let db = SqliteDatabase::in_memory().expect("in-memory sqlite");
    pollster::block_on(db.execute(&Statement::new(outbox.create_table_sql())))
        .expect("create outbox table");
    db
}

/// The RFC 3339 spelling the outbox stores, to the second.
fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .expect("in range")
}

fn epoch() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("in range")
}

async fn enqueue(outbox: &Outbox, db: &SqliteDatabase, ids: &[&str], at: &str) {
    let batch: Vec<Statement> = ids
        .iter()
        .map(|id| outbox.enqueue_statement(id, "poll", "{}", None, at))
        .collect();
    db.batch_atomic(&batch).await.expect("enqueued");
}

#[test]
fn enqueue_lease_and_complete() {
    let outbox = Outbox::new("mail_outbox");
    let db = db_with_outbox(&outbox);
    pollster::block_on(async {
        // Enqueue two units of work (as a module would, inside its own batch):
        // one naming its subject, one written like a pre-migration row.
        db.batch_atomic(&[
            outbox.enqueue_statement(
                "a",
                "confirmation",
                "{\"to\":\"a\"}",
                Some("acct-a"),
                "2026-09-07T00:00:00Z",
            ),
            outbox.enqueue_statement(
                "b",
                "confirmation",
                "{\"to\":\"b\"}",
                None,
                "2026-09-07T00:00:01Z",
            ),
        ])
        .await
        .unwrap();

        // Drain: both are due, both get leased, in next_attempt_at order.
        let due = outbox
            .claim_due(&db, "2026-09-07T01:00:00Z", "2026-09-07T01:05:00Z", 10)
            .await
            .unwrap();
        assert_eq!(
            due.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );

        // A concurrent drainer in the lease window sees nothing.
        let again = outbox
            .claim_due(&db, "2026-09-07T01:00:01Z", "2026-09-07T01:05:00Z", 10)
            .await
            .unwrap();
        assert!(
            again.is_empty(),
            "leased rows are hidden from other drainers"
        );

        // Deliver `a`; retry `b`.
        outbox.complete(&db, "a").await.unwrap();
        outbox
            .retry_later(&db, "b", "2026-09-07T02:00:00Z")
            .await
            .unwrap();

        // After the lease expires (and b's next attempt is due), b comes back
        // with attempts incremented; a is gone for good.
        let later = outbox
            .claim_due(&db, "2026-09-07T03:00:00Z", "2026-09-07T03:05:00Z", 10)
            .await
            .unwrap();
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].id, "b");
        assert_eq!(
            later[0].attempts, 1,
            "a failed delivery bumped the attempt count"
        );
    });
}

#[test]
fn a_not_yet_due_record_is_not_leased() {
    let outbox = Outbox::new("mail_outbox");
    let db = db_with_outbox(&outbox);
    pollster::block_on(async {
        db.execute(&outbox.enqueue_statement("future", "x", "{}", None, "2026-09-07T10:00:00Z"))
            .await
            .unwrap();
        let due = outbox
            .claim_due(&db, "2026-09-07T00:00:00Z", "2026-09-07T00:05:00Z", 10)
            .await
            .unwrap();
        assert!(
            due.is_empty(),
            "next_attempt_at in the future is not due yet"
        );
    });
}

#[test]
fn reschedule_moves_the_due_date_without_counting_an_attempt() {
    let outbox = Outbox::new("mail_outbox");
    let db = db_with_outbox(&outbox);
    pollster::block_on(async {
        db.execute(&outbox.enqueue_statement(
            "merchant",
            "poll",
            "{}",
            None,
            "2026-09-07T00:00:00Z",
        ))
        .await
        .unwrap();

        // Claim it (leased for five minutes), then reschedule to noon: the
        // recurring-work move — a new due time, the lease gone, no attempt.
        let claimed = outbox
            .claim_due(&db, "2026-09-07T00:00:00Z", "2026-09-07T00:05:00Z", 10)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        outbox
            .reschedule(&db, "merchant", "2026-09-07T12:00:00Z")
            .await
            .unwrap();

        let between = outbox
            .claim_due(&db, "2026-09-07T03:00:00Z", "2026-09-07T03:05:00Z", 10)
            .await
            .unwrap();
        assert!(
            between.is_empty(),
            "rescheduled out from under the old lease, to the new time"
        );

        let due = outbox
            .claim_due(&db, "2026-09-07T12:00:00Z", "2026-09-07T12:05:00Z", 10)
            .await
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(
            due[0].attempts, 0,
            "a reschedule is a cursor move, not a failure"
        );
    });
}

#[test]
fn drain_applies_done_retry_and_next_at_outcomes() {
    let outbox = Outbox::new("mail_outbox");
    let db = db_with_outbox(&outbox);
    pollster::block_on(async {
        let now = epoch();
        enqueue(&outbox, &db, &["done", "flaky", "recurring"], &iso(now)).await;
        let report = outbox
            .drain_within(
                &db,
                &FixedClock(now),
                &ScheduledBudget::unbounded(),
                DrainOptions {
                    limit: 10,
                    lease: time::Duration::minutes(5),
                    subrequests_per_item: 0,
                },
                |record| async move {
                    match record.id.as_str() {
                        "done" => Processed::Done,
                        "flaky" => Processed::RetryAt(now + time::Duration::hours(1)),
                        _ => Processed::NextAt(now + time::Duration::days(1)),
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(report.processed, 3);
        assert_eq!(report.released, 0);
        assert!(!report.stopped_by_budget);

        // Nothing is immediately due: done is gone, the other two moved.
        let due_now = outbox
            .claim_due(&db, &iso(now), &iso(now + time::Duration::minutes(5)), 10)
            .await
            .unwrap();
        assert!(due_now.is_empty());

        // The retry path counted its attempt; the NextAt cursor did not.
        let flaky = outbox
            .claim_due(
                &db,
                &iso(now + time::Duration::hours(1)),
                &iso(now + time::Duration::hours(2)),
                10,
            )
            .await
            .unwrap();
        assert_eq!(flaky[0].id, "flaky");
        assert_eq!(flaky[0].attempts, 1, "a failed delivery is an attempt");
        outbox.complete(&db, "flaky").await.unwrap();
        let recurring = outbox
            .claim_due(
                &db,
                &iso(now + time::Duration::days(1)),
                &iso(now + time::Duration::days(1) + time::Duration::minutes(5)),
                10,
            )
            .await
            .unwrap();
        assert_eq!(recurring[0].id, "recurring");
        assert_eq!(
            recurring[0].attempts, 0,
            "NextAt is a cursor move, not a failure"
        );
    });
}

#[test]
fn a_subrequest_budget_caps_how_much_is_claimed() {
    let outbox = Outbox::new("mail_outbox");
    let db = db_with_outbox(&outbox);
    pollster::block_on(async {
        let now = epoch();
        enqueue(&outbox, &db, &["a", "b", "c", "d", "e"], &iso(now)).await;
        let report = outbox
            .drain_within(
                &db,
                &FixedClock(now),
                &ScheduledBudget::new(None, Some(3)),
                DrainOptions {
                    limit: 10,
                    lease: time::Duration::minutes(5),
                    subrequests_per_item: 1,
                },
                |_: OutboxRecord| async { Processed::Done },
            )
            .await
            .unwrap();
        assert_eq!(report.processed, 3);
        assert_eq!(report.released, 0);
        assert!(
            report.stopped_by_budget,
            "three of the ten asked-for items is a budget stop, not a quiet short drain"
        );

        // The two rows the budget never reached were never leased: a fresh
        // budget claims them at the very same instant.
        let rest = outbox
            .claim_due(&db, &iso(now), &iso(now + time::Duration::minutes(5)), 10)
            .await
            .unwrap();
        assert_eq!(rest.len(), 2);
        assert_eq!(rest[0].attempts, 0, "never touched, never counted");
    });
}

#[test]
fn an_already_expired_budget_claims_nothing() {
    let outbox = Outbox::new("mail_outbox");
    let db = db_with_outbox(&outbox);
    pollster::block_on(async {
        let now = epoch();
        enqueue(&outbox, &db, &["a", "b"], &iso(now)).await;
        let budget = ScheduledBudget::new(Some(now - time::Duration::seconds(1)), None);
        let report = outbox
            .drain_within(
                &db,
                &FixedClock(now),
                &budget,
                DrainOptions {
                    limit: 10,
                    lease: time::Duration::minutes(5),
                    subrequests_per_item: 1,
                },
                |_: OutboxRecord| async { Processed::Done },
            )
            .await
            .unwrap();
        assert_eq!(report.processed, 0);
        assert_eq!(report.released, 0);
        assert!(report.stopped_by_budget, "stopped before claiming anything");

        let still_due = outbox
            .claim_due(&db, &iso(now), &iso(now + time::Duration::minutes(5)), 10)
            .await
            .unwrap();
        assert_eq!(
            still_due.len(),
            2,
            "nothing was leased out from under the next drain"
        );
    });
}

#[test]
fn a_budget_spent_mid_batch_releases_the_rest_immediately() {
    let outbox = Outbox::new("mail_outbox");
    let db = db_with_outbox(&outbox);
    pollster::block_on(async {
        let now = epoch();
        enqueue(&outbox, &db, &["a", "b", "c"], &iso(now)).await;
        // Two subrequests in the budget; the handler for `a` spends one
        // more than its own, the way a genuinely chatty handler would.
        let budget = ScheduledBudget::new(None, Some(2));
        let budget_ref = &budget;
        let report = outbox
            .drain_within(
                &db,
                &FixedClock(now),
                &budget,
                DrainOptions {
                    limit: 10,
                    lease: time::Duration::minutes(5),
                    subrequests_per_item: 1,
                },
                |record| {
                    let chatty = record.id == "a";
                    async move {
                        if chatty {
                            budget_ref.try_spend(1);
                        }
                        Processed::Done
                    }
                },
            )
            .await
            .unwrap();
        // The claim was capped at two (a, b): a fits, its handler spends
        // the last subrequest, b no longer fits — b goes back released,
        // c was never claimed.
        assert_eq!(report.processed, 1);
        assert_eq!(report.released, 1);
        assert!(report.stopped_by_budget);
        assert_eq!(budget.spent(), 2);

        // Released and unclaimed rows are due again this very instant.
        let rest = outbox
            .claim_due(&db, &iso(now), &iso(now + time::Duration::minutes(5)), 10)
            .await
            .unwrap();
        assert_eq!(
            rest.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["b", "c"],
            "the released row and the never-claimed one, both due now"
        );
        assert_eq!(rest[0].attempts, 0, "a release is not a failure");
    });
}

#[test]
fn the_claim_cap_divides_the_budget_first_and_only_binds_when_filled() {
    let outbox = Outbox::new("mail_outbox");
    let db = db_with_outbox(&outbox);
    pollster::block_on(async {
        let now = epoch();
        // Five expensive items, a limit of 3, a budget of 40 subrequests:
        // 40 / 5 = 8 items fit in the budget, so the limit of 3 binds, not
        // the budget — three are claimed and handled, and the tick is not
        // "cut short" by anything but the caller's own limit.
        enqueue(&outbox, &db, &["a", "b", "c", "d", "e"], &iso(now)).await;
        let report = outbox
            .drain_within(
                &db,
                &FixedClock(now),
                &ScheduledBudget::new(None, Some(40)),
                DrainOptions {
                    limit: 3,
                    lease: time::Duration::minutes(5),
                    subrequests_per_item: 5,
                },
                |_: OutboxRecord| async { Processed::Done },
            )
            .await
            .unwrap();
        assert_eq!(report.processed, 3);
        assert!(
            !report.stopped_by_budget,
            "the limit, not the budget, bound"
        );

        // Two cheap rows, a cap of 3 below the limit of 10: the claim comes
        // back short because those were all the rows there were, which is
        // not a budget stop. (Fresh table: d and e from above must not
        // refill the claim here.)
        let cheap = Outbox::new("other_outbox");
        let cheap_db = db_with_outbox(&cheap);
        enqueue(&cheap, &cheap_db, &["f", "g"], &iso(now)).await;
        let report = cheap
            .drain_within(
                &cheap_db,
                &FixedClock(now),
                &ScheduledBudget::new(None, Some(3)),
                DrainOptions {
                    limit: 10,
                    lease: time::Duration::minutes(5),
                    subrequests_per_item: 1,
                },
                |_: OutboxRecord| async { Processed::Done },
            )
            .await
            .unwrap();
        assert_eq!(report.processed, 2);
        assert!(
            !report.stopped_by_budget,
            "two due rows is not a budget stop"
        );
    });
}

#[test]
fn a_nextat_in_another_offset_is_stored_as_utc() {
    let outbox = Outbox::new("mail_outbox");
    let db = db_with_outbox(&outbox);
    pollster::block_on(async {
        let now = epoch();
        enqueue(&outbox, &db, &["merchant"], &iso(now)).await;
        // The handler answers in +05:30 — what a poller that carries the
        // merchant's timezone would do. The stored cursor must still be the
        // UTC spelling the due compare relies on.
        let offset = time::UtcOffset::from_hms(5, 30, 0).expect("valid offset");
        let report = outbox
            .drain_within(
                &db,
                &FixedClock(now),
                &ScheduledBudget::unbounded(),
                DrainOptions {
                    limit: 10,
                    lease: time::Duration::minutes(5),
                    subrequests_per_item: 0,
                },
                |_: OutboxRecord| async move {
                    Processed::NextAt((now + time::Duration::hours(2)).to_offset(offset))
                },
            )
            .await
            .unwrap();
        assert_eq!(report.processed, 1);

        // Not due an hour in (UTC), due at the two-hour mark — a stored
        // +05:30 string would sort after the Z spelling and never match.
        let lease = iso(now + time::Duration::hours(1));
        let early = outbox
            .claim_due(&db, &iso(now + time::Duration::hours(1)), &lease, 10)
            .await
            .unwrap();
        assert!(
            early.is_empty(),
            "the offset was normalized, not stored raw"
        );
        let due = outbox
            .claim_due(
                &db,
                &iso(now + time::Duration::hours(2)),
                &iso(now + time::Duration::hours(3)),
                10,
            )
            .await
            .unwrap();
        assert_eq!(due[0].id, "merchant");
    });
}
