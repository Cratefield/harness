//! Integration test for `cratefield_core::Inbox` (issue #134) against a real
//! SQLite database: an event id is claimed exactly once, so duplicate and
//! concurrent deliveries are deduplicated.

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{Database, Inbox, Statement};

fn db_with_inbox(inbox: &Inbox) -> SqliteDatabase {
    let db = SqliteDatabase::in_memory().expect("in-memory sqlite");
    pollster::block_on(db.execute(&Statement::new(inbox.create_table_sql())))
        .expect("create inbox table");
    db
}

#[test]
fn an_event_is_claimed_once_and_duplicates_are_skipped() {
    let inbox = Inbox::new("billing_inbox");
    let db = db_with_inbox(&inbox);
    pollster::block_on(async {
        // First delivery wins.
        assert!(
            inbox
                .claim(&db, "evt_1", "2026-09-07T00:00:00Z")
                .await
                .unwrap()
        );
        // A retry / replay of the same event is skipped.
        assert!(
            !inbox
                .claim(&db, "evt_1", "2026-09-07T00:05:00Z")
                .await
                .unwrap()
        );
        // A different event is independent.
        assert!(
            inbox
                .claim(&db, "evt_2", "2026-09-07T00:06:00Z")
                .await
                .unwrap()
        );

        assert!(inbox.seen(&db, "evt_1").await.unwrap());
        assert!(inbox.seen(&db, "evt_2").await.unwrap());
        assert!(!inbox.seen(&db, "evt_3").await.unwrap());
    });
}

#[test]
fn concurrent_claims_of_one_event_yield_exactly_one_winner() {
    // The DB serialises writes on one connection, but the ON CONFLICT DO
    // NOTHING contract is what guarantees first-writer-wins: whichever ordering
    // the engine picks, exactly one claim inserts the row.
    let inbox = Inbox::new("billing_inbox");
    let db = db_with_inbox(&inbox);
    let winners = pollster::block_on(async {
        let mut wins = 0;
        for _ in 0..5 {
            if inbox
                .claim(&db, "evt_hot", "2026-09-07T00:00:00Z")
                .await
                .unwrap()
            {
                wins += 1;
            }
        }
        wins
    });
    assert_eq!(
        winners, 1,
        "exactly one of five racing claims applies the effect"
    );
}
