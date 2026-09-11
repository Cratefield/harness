//! Integration test for `cratefield_core::Outbox` (issue #128) against real
//! SQLite: enqueue, lease-once (a second drainer sees nothing while leased),
//! complete removes, retry reschedules with an incremented attempt count.

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{Database, Outbox, Statement};

fn db_with_outbox(outbox: &Outbox) -> SqliteDatabase {
    let db = SqliteDatabase::in_memory().expect("in-memory sqlite");
    pollster::block_on(db.execute(&Statement::new(outbox.create_table_sql())))
        .expect("create outbox table");
    db
}

#[test]
fn enqueue_lease_and_complete() {
    let outbox = Outbox::new("mail_outbox");
    let db = db_with_outbox(&outbox);
    pollster::block_on(async {
        // Enqueue two units of work (as a module would, inside its own batch).
        db.batch_atomic(&[
            outbox.enqueue_statement(
                "a",
                "confirmation",
                "{\"to\":\"a\"}",
                "2026-09-07T00:00:00Z",
            ),
            outbox.enqueue_statement(
                "b",
                "confirmation",
                "{\"to\":\"b\"}",
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
        db.execute(&outbox.enqueue_statement("future", "x", "{}", "2026-09-07T10:00:00Z"))
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
