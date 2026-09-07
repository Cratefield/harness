//! The Postgres migration runner (issue #18): applies module migration
//! sets in lock order, tracked in `harness_migrations(id, applied_at)`.
//!
//! The runner's own bookkeeping statements are built with sea-query and
//! rendered with [`sea_query::PostgresQueryBuilder`] (ADR 0004); module
//! migration files are plain SQL applied verbatim via the simple query
//! protocol (they may hold several statements).

use crate::convert::{bind_values, rebind_placeholders};
use factory0_core::{Database, DbError, Harness, Migrations, SqlMigration, Statement};
use sea_query::{Alias, ColumnDef, PostgresQueryBuilder, Query, Table};
use sqlx::postgres::{PgArguments, PgConnection};
use std::collections::HashMap;

/// Selects the migration set a module contributes to a Postgres
/// deployment: its `postgres` set when it ships one, else its `sqlite`
/// set — but only when every file passes the portable-SQL lint
/// ([`factory0_core::lint_portable_sql`], the same predicate `fz doctor`
/// enforces, so the two can never drift).
///
/// # Errors
///
/// A human-readable message naming the offending migration file and token
/// when the fallback `sqlite` set fails the lint.
pub fn select_set(migrations: &Migrations) -> Result<&'static [SqlMigration], String> {
    if !migrations.postgres.is_empty() {
        return Ok(migrations.postgres);
    }
    for migration in migrations.sqlite {
        let hits = factory0_core::lint_portable_sql(migration.sql);
        if let Some((token, explanation)) = hits.first() {
            return Err(format!(
                "sqlite migration {}/{} fails the portable-SQL lint (found {token:?}: \
                 {explanation}); ship a migrations/postgres override instead",
                migration.id, migration.name
            ));
        }
    }
    Ok(migrations.sqlite)
}

fn tracking_table_ddl() -> Statement {
    let sql = Table::create()
        .table(Alias::new("harness_migrations"))
        .if_not_exists()
        .col(ColumnDef::new(Alias::new("id")).text().primary_key())
        .col(ColumnDef::new(Alias::new("applied_at")).text().not_null())
        .col(ColumnDef::new(Alias::new("checksum")).text())
        .build(PostgresQueryBuilder);
    Statement::new(sql)
}

/// Databases migrated before checksums were recorded have the
/// two-column table. Their existing rows stay NULL, which reads as
/// "applied, cannot verify" rather than as a mismatch.
fn tracking_table_backfill_ddl() -> Statement {
    Statement::new(
        "ALTER TABLE harness_migrations ADD COLUMN IF NOT EXISTS checksum text".to_owned(),
    )
}

fn applied_query() -> Statement {
    let (sql, values) = Query::select()
        .column(Alias::new("id"))
        .column(Alias::new("checksum"))
        .from(Alias::new("harness_migrations"))
        .build(PostgresQueryBuilder);
    debug_assert!(values.0.is_empty(), "the applied query binds nothing");
    Statement::new(sql)
}

/// Renders `INSERT INTO harness_migrations (id, applied_at)`
/// `VALUES ($1, $2)` with the values as binds (`PostgresQueryBuilder`).
fn record_insert(id: &str, applied_at: &str, checksum: &str) -> Result<Statement, DbError> {
    let (sql, values) = Query::insert()
        .into_table(Alias::new("harness_migrations"))
        .columns([
            Alias::new("id"),
            Alias::new("applied_at"),
            Alias::new("checksum"),
        ])
        .values([id.into(), applied_at.into(), checksum.into()])
        .map_err(|err| DbError::Batch(err.to_string()))?
        .build(PostgresQueryBuilder);
    Ok(Statement::with_values(sql, values.0))
}

/// Executes one port statement on an open connection (pool connection or
/// migration transaction). Statements rendered by
/// `PostgresQueryBuilder` already carry `$n` placeholders, so
/// [`rebind_placeholders`] is a no-op for them and only translates
/// portable `?` statements.
async fn exec_on(conn: &mut PgConnection, stmt: &Statement) -> Result<(), DbError> {
    let sql = rebind_placeholders(&stmt.sql);
    let mut args = PgArguments::default();
    bind_values(&mut args, &stmt.values.0)?;
    sqlx::query_with(sql.as_str(), args)
        .execute(conn)
        .await
        .map_err(|err| DbError::Batch(first_line(&err.to_string()).to_owned()))?;
    Ok(())
}

/// sqlx error strings can embed the whole offending statement; keep the
/// first non-empty line for the error message.
fn first_line(message: &str) -> &str {
    message
        .lines()
        .find(|line| !line.is_empty())
        .unwrap_or("unknown error")
}

fn iso_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl crate::Postgres {
    /// Applies a module's unapplied migrations in `id` order, tracked
    /// under `<module>/<id>` in a `harness_migrations` table; each
    /// migration runs in its own transaction so a failure rolls back
    /// atomically and re-running is idempotent. Mirrors
    /// `SqliteDatabase::apply_migrations` exactly.
    ///
    /// # Errors
    ///
    /// [`DbError::Batch`] when the tracking DDL or a migration's SQL
    /// fails, or when the bookkeeping insert cannot be rendered.
    pub async fn apply_migrations(
        &self,
        module: &str,
        migrations: &[SqlMigration],
    ) -> Result<(), DbError> {
        self.execute(&tracking_table_ddl()).await?;
        self.execute(&tracking_table_backfill_ddl()).await?;

        let applied: HashMap<String, Option<String>> = self
            .query(&applied_query())
            .await?
            .rows
            .iter()
            .filter_map(|row| Some((row.get::<String>("id")?, row.get::<String>("checksum"))))
            .collect();

        // Lock order: ids are zero-padded, so lexical order is apply order
        // (the same discipline `fz migrations collect` numbers files by).
        let mut ordered: Vec<&SqlMigration> = migrations.iter().collect();
        ordered.sort_by_key(|migration| migration.id);

        for migration in ordered {
            let key = format!("{module}/{}", migration.id);
            let checksum = factory0_core::migration_checksum(migration.sql);
            if let Some(recorded) = applied.get(&key) {
                if let Some(recorded) = recorded.as_ref().filter(|hash| *hash != &checksum) {
                    return Err(DbError::Batch(factory0_core::migration_edited(
                        &key, recorded, &checksum,
                    )));
                }
                continue;
            }
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|err| DbError::Batch(err.to_string()))?;
            // Migration files may hold several statements; the simple
            // query protocol (raw_sql) is the only multi-statement path.
            sqlx::raw_sql(migration.sql)
                .execute(&mut *tx)
                .await
                .map_err(|err| {
                    DbError::Batch(format!(
                        "migration {key} failed: {}",
                        first_line(&err.to_string())
                    ))
                })?;
            let record = record_insert(&key, &iso_now(), &checksum)?;
            exec_on(&mut tx, &record).await?;
            tx.commit()
                .await
                .map_err(|err| DbError::Batch(err.to_string()))?;
        }
        Ok(())
    }

    /// Applies every module's migrations for a whole harness, in lock
    /// order: modules in harness (config) order, each set by zero-padded
    /// migration id — the order `fz migrations collect` pins in
    /// `.harness-lock.json`. For each module the `postgres` set applies
    /// when shipped, else the `sqlite` set when it passes the portable
    /// lint ([`select_set`]).
    ///
    /// # Errors
    ///
    /// [`DbError::Batch`] when a module's sqlite set fails the lint or any
    /// migration fails to apply.
    pub async fn apply_harness_migrations(&self, harness: &Harness) -> Result<(), DbError> {
        for module in harness.modules() {
            let set = select_set(&module.migrations())
                .map_err(|reason| DbError::Batch(format!("module {}: {reason}", module.name())))?;
            self.apply_migrations(module.name(), set).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::select_set;
    use factory0_core::{Migrations, SqlMigration};

    const PORTABLE: SqlMigration = SqlMigration {
        id: "0001",
        name: "init",
        sql: "CREATE TABLE t (id TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0);",
    };

    #[test]
    fn prefers_the_postgres_set_when_shipped() {
        const PG: SqlMigration = SqlMigration {
            id: "0001",
            name: "init",
            sql: "CREATE TABLE t (id TEXT PRIMARY KEY);",
        };
        let migrations = Migrations {
            sqlite: &[PORTABLE],
            postgres: &[PG],
        };
        let selected = select_set(&migrations).expect("postgres set wins");
        assert_eq!(selected.len(), 1);
        assert!(selected[0].sql.contains("TEXT"));
    }

    #[test]
    fn falls_back_to_sqlite_that_passes_the_lint() {
        let migrations = Migrations::sqlite(&[PORTABLE]);
        let selected = select_set(&migrations).expect("portable sqlite applies");
        assert_eq!(selected.len(), 1);
        assert!(selected[0].sql.contains("TEXT"));
    }

    #[test]
    fn rejects_sqlite_that_fails_the_lint() {
        const NOT_PORTABLE: SqlMigration = SqlMigration {
            id: "0002",
            name: "oops",
            sql: "CREATE TABLE t (id SERIAL PRIMARY KEY);",
        };
        let migrations = Migrations::sqlite(&[PORTABLE, NOT_PORTABLE]);
        let err = select_set(&migrations).expect_err("SERIAL is not portable");
        assert!(err.contains("0002/oops"), "names the file: {err}");
        assert!(err.contains("SERIAL"), "names the token: {err}");
    }
}
