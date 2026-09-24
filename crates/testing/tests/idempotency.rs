//! Integration tests for `cratefield_core::Inbox` (issues #134, #534) against
//! a real SQLite database: an event id is claimed exactly once, so duplicate
//! and concurrent deliveries are deduplicated — and with `claim_with` the
//! claim and the effect commit together, so a failure between them loses
//! nothing.

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{Database, DbError, Inbox, Rows, Statement};
use std::sync::atomic::{AtomicBool, Ordering};

/// The effect's target: the statements a handler batches with the claim
/// insert into this. `payload` is `NOT NULL` so a test can build a statement
/// that deterministically fails mid-batch.
const CREATE_EFFECTS: &str = "CREATE TABLE effects (\n    \
                              id TEXT PRIMARY KEY,\n    \
                              payload TEXT NOT NULL\n\
                              );";

fn db_with_inbox(inbox: &Inbox) -> SqliteDatabase {
    let db = SqliteDatabase::in_memory().expect("in-memory sqlite");
    pollster::block_on(db.execute(&Statement::new(inbox.create_table_sql())))
        .expect("create inbox table");
    db
}

fn db_with_inbox_and_effects(inbox: &Inbox) -> SqliteDatabase {
    let db = db_with_inbox(inbox);
    pollster::block_on(db.execute(&Statement::new(CREATE_EFFECTS))).expect("create effects table");
    db
}

/// How many effect rows committed.
async fn effect_count(db: &dyn Database) -> i64 {
    let rows = db
        .query(&Statement::new("SELECT COUNT(*) AS n FROM effects"))
        .await
        .expect("count effects");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .expect("one count row")
}

/// A `Database` decorator that stages the lost race from `claim_with`'s error
/// path: on its **first** `query` — the `seen` pre-check — it delegates the
/// read (which comes back empty) and commits the rival's claim *before
/// returning it*. The delivery therefore passes the pre-check, races into its
/// batch against an already-claimed key, fails the primary key, and
/// `claim_with` must re-check `seen`, find the rival, and answer `Ok(false)`
/// rather than surfacing the engine error. Everything else delegates
/// untouched; the rival fires once.
struct RivalClaimsAfterFirstSeen {
    inner: SqliteDatabase,
    rival_claim: Statement,
    fired: AtomicBool,
}

#[async_trait::async_trait]
impl Database for RivalClaimsAfterFirstSeen {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        self.inner.execute(stmt).await
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        let rows = self.inner.query(stmt).await;
        if !self.fired.swap(true, Ordering::SeqCst) {
            // The rival wins between the pre-check's read and the batch.
            self.inner
                .batch_atomic(std::slice::from_ref(&self.rival_claim))
                .await?;
        }
        rows
    }

    async fn batch_atomic(&self, stmts: &[Statement]) -> Result<(), DbError> {
        self.inner.batch_atomic(stmts).await
    }
}

fn grant(id: &str) -> Statement {
    Statement::new(format!(
        "INSERT INTO effects (id, payload) VALUES ('{id}', 'granted')"
    ))
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

#[test]
fn claim_with_commits_the_claim_and_the_effect_together() {
    let inbox = Inbox::new("billing_inbox");
    let db = db_with_inbox_and_effects(&inbox);
    pollster::block_on(async {
        let won = inbox
            .claim_with(&db, "evt_1", "2026-09-07T00:00:00Z", &[grant("e1")])
            .await
            .expect("claim_with succeeds");
        assert!(won, "the first delivery commits claim and effect");
        assert!(inbox.seen(&db, "evt_1").await.unwrap());
        assert_eq!(effect_count(&db).await, 1);
    });
}

#[test]
fn a_redelivery_after_claim_with_is_skipped_and_the_effect_stays_applied_once() {
    let inbox = Inbox::new("billing_inbox");
    let db = db_with_inbox_and_effects(&inbox);
    pollster::block_on(async {
        assert!(
            inbox
                .claim_with(&db, "evt_1", "2026-09-07T00:00:00Z", &[grant("e1")])
                .await
                .unwrap()
        );
        // The provider retries the same event: the claim is already recorded,
        // so the effect must not run a second time.
        let redelivered = inbox
            .claim_with(&db, "evt_1", "2026-09-07T00:05:00Z", &[grant("e1-dup")])
            .await
            .expect("claim_with succeeds on a duplicate");
        assert!(!redelivered, "a duplicate delivery gets false");
        assert_eq!(effect_count(&db).await, 1, "the effect applied once");
    });
}

#[test]
fn a_failure_between_claim_and_effect_loses_nothing_and_the_retry_wins() {
    // The hazard from issue #534: the worker dies between the claim and the
    // effect. Here a NOT NULL violation stands in for the death — the effect
    // statement fails mid-batch — and the two are the same thing to the
    // database: a D1 batch is one transaction, so a worker dying mid-batch
    // commits nothing either. The claim must roll back *with* the effect, so
    // the redelivery is not treated as a duplicate and re-runs both.
    let inbox = Inbox::new("billing_inbox");
    let db = db_with_inbox_and_effects(&inbox);
    pollster::block_on(async {
        let broken = vec![Statement::new(
            "INSERT INTO effects (id, payload) VALUES ('e1', NULL)",
        )];
        let err = inbox
            .claim_with(&db, "evt_1", "2026-09-07T00:00:00Z", &broken)
            .await
            .expect_err("the failing effect aborts the batch");
        assert!(
            matches!(err, DbError::Batch(_)),
            "the aborted batch surfaces as a batch error: {err}"
        );

        assert!(
            !inbox.seen(&db, "evt_1").await.unwrap(),
            "the claim rolled back with the effect: the key is still unclaimed"
        );
        assert_eq!(effect_count(&db).await, 0);

        // The retried delivery, with a working effect, wins — the event is
        // not lost.
        assert!(
            inbox
                .claim_with(&db, "evt_1", "2026-09-07T00:05:00Z", &[grant("e1")])
                .await
                .unwrap(),
            "the retry re-runs claim and effect"
        );
        assert_eq!(effect_count(&db).await, 1);
    });
}

#[test]
fn a_duplicate_claim_inside_the_batch_aborts_its_own_effect() {
    // Two deliveries that would both pass the seen-check race straight into
    // the batch (what claim_with's error path re-checks for). Because
    // claim_statement carries no ON CONFLICT DO NOTHING, the loser's
    // primary-key violation rolls its whole batch back — the effect it was
    // smuggling never commits.
    let inbox = Inbox::new("billing_inbox");
    let db = db_with_inbox_and_effects(&inbox);
    pollster::block_on(async {
        let ts = "2026-09-07T00:00:00Z";
        let first = db
            .batch_atomic(&[inbox.claim_statement("evt_hot", ts), grant("a")])
            .await;
        let second = db
            .batch_atomic(&[inbox.claim_statement("evt_hot", ts), grant("b")])
            .await;
        assert!(first.is_ok(), "the first batch commits");
        assert!(
            second.is_err(),
            "the duplicate claim fails the primary key and aborts its batch"
        );
        assert_eq!(
            effect_count(&db).await,
            1,
            "the losing delivery applied no effect"
        );
    });
}

#[test]
fn a_rival_claim_committed_mid_delivery_is_a_lost_race_not_an_error() {
    // The exact case claim_with's error-path re-check disambiguates: the seen
    // pre-check passes, then a concurrent delivery commits its claim before
    // ours batches. Our batch fails the primary key, the re-check finds the
    // rival — claim_with must report the lost race (Ok(false)), not surface
    // the engine error, and our effect must not have committed.
    let inbox = Inbox::new("billing_inbox");
    let inner = db_with_inbox_and_effects(&inbox);
    let db = RivalClaimsAfterFirstSeen {
        inner,
        rival_claim: inbox.claim_statement("evt_race", "2026-09-07T00:00:00Z"),
        fired: AtomicBool::new(false),
    };
    pollster::block_on(async {
        let won = inbox
            .claim_with(&db, "evt_race", "2026-09-07T00:00:05Z", &[grant("race")])
            .await
            .expect("a lost race is Ok(false), not an error");
        assert!(!won, "the rival committed the claim first");

        // The row recorded is the rival's, not ours — our batch's claim never
        // committed.
        let rows = db
            .query(&Statement::new(
                "SELECT seen_at FROM billing_inbox WHERE event_key = 'evt_race'",
            ))
            .await
            .expect("read the claim back");
        assert_eq!(
            rows.first()
                .and_then(|row| row.get::<String>("seen_at"))
                .as_deref(),
            Some("2026-09-07T00:00:00Z"),
            "the rival's claim is what's recorded"
        );
        assert_eq!(
            effect_count(&db).await,
            0,
            "the losing delivery applied no effect, and the rival carried none"
        );
    });
}
