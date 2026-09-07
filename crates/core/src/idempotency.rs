//! Idempotent event handling (issue #134): an **inbox** that records each
//! external event's id once, so a duplicate, replayed, concurrent or
//! out-of-order delivery applies its effects exactly once.
//!
//! Verifying a Stripe webhook's signature and timestamp authenticates a
//! *delivery* — it does not stop Stripe from delivering the same event twice
//! (it retries), or two workers from processing the same event at once. A
//! module wraps its handler in a [`claim`](Inbox::claim): the primary key plus
//! `ON CONFLICT DO NOTHING` lets exactly one caller insert the row, so exactly
//! one caller sees `true` and does the work.
//!
//! ```ignore
//! let inbox = Inbox::new("billing_inbox");
//! let event = payments.verify_webhook(sig, body).await?; // verified first
//! if inbox.claim(db, &event.id, &now).await? {
//!     // first time: apply the effect (grant the entitlement, ...)
//! } // else: a duplicate delivery — already handled, do nothing
//! ```
//!
//! The owning module includes [`Inbox::create_table_sql`] as a migration (it
//! owns the table, per the module contract). Prune old rows on whatever horizon
//! the provider retries within; the inbox is a dedup ledger, not a record.

use crate::ports::{Database, DbError, Statement};
use sea_query::{Alias, Expr, OnConflict, Query};

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// A dedup ledger over the `Database` port. Construct it with the table the
/// owning module declares (e.g. `"<module>_inbox"`).
#[derive(Debug, Clone)]
pub struct Inbox {
    table: String,
}

impl Inbox {
    #[must_use]
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
        }
    }

    /// The portable DDL for the inbox table. The owning module ships this as a
    /// forward-only migration (it renders identically on SQLite/D1 and
    /// Postgres, ADR 0004).
    #[must_use]
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n    \
             event_key TEXT PRIMARY KEY,\n    \
             seen_at TEXT NOT NULL\n);",
            table = self.table
        )
    }

    /// Records `event_key`, returning `true` the **first** time it is seen
    /// (proceed and apply the effect) and `false` for any later delivery of the
    /// same id (a duplicate/replay/concurrent race — skip).
    ///
    /// The insert is a single `ON CONFLICT DO NOTHING` statement, so it is
    /// atomic on both D1 and Postgres: under concurrent claims of the same key
    /// exactly one insert takes, and only that caller gets `true`. `seen_at` is
    /// an RFC 3339 timestamp the caller reads from the `Clock` port.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the write fails.
    pub async fn claim(
        &self,
        db: &dyn Database,
        event_key: &str,
        seen_at: &str,
    ) -> Result<bool, DbError> {
        let mut insert = Query::insert();
        insert
            .into_table(iden(&self.table))
            .columns(["event_key", "seen_at"])
            .values_panic([event_key.to_owned().into(), seen_at.to_owned().into()])
            .on_conflict(
                OnConflict::column(iden("event_key"))
                    .do_nothing()
                    .to_owned(),
            );
        let affected = db.execute(&Statement::render(&insert)).await?;
        Ok(affected == 1)
    }

    /// Whether `event_key` has already been recorded (a read-only check; a
    /// handler still uses [`claim`](Self::claim) to act, since only `claim` is
    /// race-free).
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the read fails.
    pub async fn seen(&self, db: &dyn Database, event_key: &str) -> Result<bool, DbError> {
        let mut select = Query::select();
        select
            .expr(Expr::val(1))
            .from(iden(&self.table))
            .and_where(Expr::col(iden("event_key")).eq(event_key))
            .limit(1);
        let rows = db.query(&Statement::render(&select)).await?;
        Ok(!rows.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_sql_is_portable_ddl() {
        let sql = Inbox::new("billing_inbox").create_table_sql();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS billing_inbox"));
        assert!(sql.contains("event_key TEXT PRIMARY KEY"));
        assert!(sql.contains("seen_at TEXT NOT NULL"));
    }

    #[test]
    fn claim_renders_insert_on_conflict_do_nothing() {
        // Render the statement the claim issues, without a database, and assert
        // its shape: an insert into the table with the two columns and an
        // ON CONFLICT DO NOTHING clause (the atomic first-writer-wins).
        let inbox = Inbox::new("billing_inbox");
        let mut insert = Query::insert();
        insert
            .into_table(iden(&inbox.table))
            .columns(["event_key", "seen_at"])
            .values_panic([
                "evt_1".to_owned().into(),
                "2026-09-07T00:00:00Z".to_owned().into(),
            ])
            .on_conflict(
                OnConflict::column(iden("event_key"))
                    .do_nothing()
                    .to_owned(),
            );
        let stmt = Statement::render(&insert);
        assert!(stmt.sql.contains("INSERT INTO"));
        assert!(stmt.sql.contains("billing_inbox"));
        assert!(stmt.sql.to_uppercase().contains("ON CONFLICT"));
        assert!(stmt.sql.to_uppercase().contains("DO NOTHING"));
        assert_eq!(stmt.values.0.len(), 2);
    }
}
