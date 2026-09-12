//! Durable outbox (issue #128): the pair of the [`Inbox`](crate::Inbox). Where
//! the inbox makes *inbound* effects exactly-once, the outbox makes *outbound*
//! work at-least-once even across a crash.
//!
//! `Defer` (Workers `wait_until`, native `tokio::spawn`) is an execution
//! *opportunity*, not durable delivery: a process exit, an execution deadline
//! or a downstream failure loses the confirmation mail or the cross-module
//! action after the database mutation already committed. The outbox closes that
//! gap:
//!
//! 1. A module writes an outbox row **inside the same batch** as its state
//!    change — [`enqueue_statement`](Outbox::enqueue_statement) returns a
//!    [`Statement`] the module appends to its own `db.batch_atomic(..)`, so the row
//!    commits atomically with the change or not at all.
//! 2. It then uses `Defer` only to *attempt* immediate delivery: lease due rows
//!    with [`claim_due`](Outbox::claim_due), deliver, and
//!    [`complete`](Outbox::complete) (delete) or [`retry_later`](Outbox::retry_later).
//! 3. The venture's scheduled entry point drains whatever immediate delivery
//!    missed, on the same lease + bounded-retry path.
//!
//! Leasing is race-free without a portable `RETURNING`: `claim_due` selects due
//! rows, then wins each one with a guarded `UPDATE … WHERE locked_until IS NULL
//! OR locked_until < now` (the same first-writer-wins the inbox uses), so two
//! drainers never deliver the same row. Consumers must still be idempotent
//! (pair the topic with an [`Inbox`](crate::Inbox) key) — the outbox guarantees
//! at-least-once, not exactly-once.

use crate::ports::{Database, DbError, Statement};
use sea_query::{Alias, Expr, Order, Query};

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// A leased outbox record handed to a drainer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRecord {
    pub id: String,
    /// What kind of work this is (the module routes on it).
    pub topic: String,
    /// The opaque payload the module wrote (typically JSON).
    pub payload: String,
    /// How many delivery attempts have already failed.
    pub attempts: i64,
}

/// A durable work queue over the `Database` port. Construct it with the table
/// the owning module declares (e.g. `"<module>_outbox"`).
#[derive(Debug, Clone)]
pub struct Outbox {
    table: String,
}

impl Outbox {
    #[must_use]
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
        }
    }

    /// The portable DDL for the outbox table. The owning module ships this as a
    /// forward-only migration.
    #[must_use]
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n    \
             id TEXT PRIMARY KEY,\n    \
             topic TEXT NOT NULL,\n    \
             payload TEXT NOT NULL,\n    \
             subject TEXT,\n    \
             attempts INTEGER NOT NULL DEFAULT 0,\n    \
             next_attempt_at TEXT NOT NULL,\n    \
             locked_until TEXT,\n    \
             created_at TEXT NOT NULL\n);",
            table = self.table
        )
    }

    /// The `INSERT` that enqueues one unit of work. Return it into the module's
    /// **own** `db.batch_atomic(..)` alongside the state change, so the row is durable
    /// exactly when the change is. `id` is a caller-supplied ULID; `at` is an
    /// RFC 3339 timestamp used for both `created_at` and the initial
    /// `next_attempt_at` (deliver as soon as possible).
    ///
    /// `subject` is the person the work is for — an account id, a waitlist
    /// entry id — or `None` for work that names nobody. Writing it is what
    /// makes the queued row reachable for export and erasure (issue #266):
    /// the payload JSON is the module's own dialect and no predicate can
    /// match into it. Pass it for every per-person job even when it feels
    /// redundant with the payload; `None` rows drain identically but are
    /// returned for nobody's subject, so a forgotten `Some` is a silent
    /// hole in the erasure catalogue rather than an error.
    #[must_use]
    pub fn enqueue_statement(
        &self,
        id: &str,
        topic: &str,
        payload: &str,
        subject: Option<&str>,
        at: &str,
    ) -> Statement {
        let mut insert = Query::insert();
        insert
            .into_table(iden(&self.table))
            .columns([
                "id",
                "topic",
                "payload",
                "subject",
                "attempts",
                "next_attempt_at",
                "created_at",
            ])
            .values_panic([
                id.to_owned().into(),
                topic.to_owned().into(),
                payload.to_owned().into(),
                subject.map(str::to_owned).into(),
                0i64.into(),
                at.to_owned().into(),
                at.to_owned().into(),
            ]);
        Statement::render(&insert)
    }

    /// Leases up to `limit` records that are due (`next_attempt_at <= now`) and
    /// not already leased, marking each `locked_until = lease_until` so a
    /// concurrent drainer skips it. Returns only the rows this caller won.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if a read or lease write fails.
    pub async fn claim_due(
        &self,
        db: &dyn Database,
        now: &str,
        lease_until: &str,
        limit: u64,
    ) -> Result<Vec<OutboxRecord>, DbError> {
        let mut select = Query::select();
        select
            .columns([iden("id"), iden("topic"), iden("payload"), iden("attempts")])
            .from(iden(&self.table))
            .and_where(Expr::col(iden("next_attempt_at")).lte(now))
            .and_where(
                Expr::col(iden("locked_until"))
                    .is_null()
                    .or(Expr::col(iden("locked_until")).lt(now)),
            )
            .order_by(iden("next_attempt_at"), Order::Asc)
            .limit(limit);
        let rows = db.query(&Statement::render(&select)).await?;

        let mut leased = Vec::new();
        for row in &rows.rows {
            let id = row.get::<String>("id").unwrap_or_default();
            // Win the lease with a guarded update: exactly one drainer's write
            // takes, and only it processes the row.
            let mut lease = Query::update();
            lease
                .table(iden(&self.table))
                .value(iden("locked_until"), lease_until)
                .and_where(Expr::col(iden("id")).eq(id.as_str()))
                .and_where(
                    Expr::col(iden("locked_until"))
                        .is_null()
                        .or(Expr::col(iden("locked_until")).lt(now)),
                );
            if db.execute(&Statement::render(&lease)).await? == 1 {
                leased.push(OutboxRecord {
                    id,
                    topic: row.get::<String>("topic").unwrap_or_default(),
                    payload: row.get::<String>("payload").unwrap_or_default(),
                    attempts: row.get::<i64>("attempts").unwrap_or(0),
                });
            }
        }
        Ok(leased)
    }

    /// Removes a record after successful delivery.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the delete fails.
    pub async fn complete(&self, db: &dyn Database, id: &str) -> Result<(), DbError> {
        let mut delete = Query::delete();
        delete
            .from_table(iden(&self.table))
            .and_where(Expr::col(iden("id")).eq(id));
        db.execute(&Statement::render(&delete)).await?;
        Ok(())
    }

    /// Reschedules a record after a failed delivery: increments `attempts`,
    /// sets the next attempt time (the caller applies its own backoff), and
    /// clears the lease so a drainer can pick it up again.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the update fails.
    pub async fn retry_later(
        &self,
        db: &dyn Database,
        id: &str,
        next_attempt_at: &str,
    ) -> Result<(), DbError> {
        let mut update = Query::update();
        update
            .table(iden(&self.table))
            .value(iden("attempts"), Expr::col(iden("attempts")).add(1))
            .value(iden("next_attempt_at"), next_attempt_at)
            .value(iden("locked_until"), Option::<String>::None)
            .and_where(Expr::col(iden("id")).eq(id));
        db.execute(&Statement::render(&update)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_sql_is_portable_ddl() {
        let sql = Outbox::new("mail_outbox").create_table_sql();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS mail_outbox"));
        assert!(sql.contains("next_attempt_at TEXT NOT NULL"));
        assert!(sql.contains("locked_until TEXT"));
        // Nullable, not NOT NULL: the migration story is ADD COLUMN on a
        // live table, and NOT NULL would force a backfill that cannot be
        // honest about rows whose payload never parsed.
        assert!(sql.contains("subject TEXT"));
    }

    #[test]
    fn enqueue_statement_inserts_the_row() {
        let stmt = Outbox::new("mail_outbox").enqueue_statement(
            "01J",
            "confirmation",
            "{\"to\":\"a@b\"}",
            Some("acct-1"),
            "2026-09-07T00:00:00Z",
        );
        assert!(stmt.sql.contains("INSERT INTO"));
        assert!(stmt.sql.contains("mail_outbox"));
        assert!(stmt.sql.contains("subject"));
        // id, topic, payload, subject, attempts, next_attempt_at, created_at
        assert_eq!(stmt.values.0.len(), 7);
        assert_eq!(stmt.values.0[3], "acct-1".into());
    }

    #[test]
    fn enqueue_statement_without_a_subject_binds_null() {
        // The shape a row written before the migration has: the column
        // exists, the value does not. The drain treats both the same.
        let stmt = Outbox::new("mail_outbox").enqueue_statement(
            "01J",
            "confirmation",
            "{\"to\":\"a@b\"}",
            None,
            "2026-09-07T00:00:00Z",
        );
        assert!(stmt.sql.contains("subject"));
        assert_eq!(
            stmt.values.0[3],
            sea_query::Value::from(Option::<String>::None)
        );
    }
}
