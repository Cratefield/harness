//! The read-only session every inspection read goes through.
//!
//! Read-only is enforced twice, as ADR 0026 (Decision 3) requires, and then
//! checked:
//!
//! 1. the session's `default_transaction_read_only` is set on at startup and
//!    again with `SET` once connected, so a statement outside the
//!    transaction cannot write either;
//! 2. every read runs inside one `REPEATABLE READ READ ONLY` transaction,
//!    so all of it sees one snapshot, and the transaction is rolled back,
//!    never committed;
//! 3. before the rollback, `txid_current_if_assigned()` must still be null:
//!    a write — even one refused — would have assigned a transaction id.
//!
//! The third guard is ours; the role is the user's. `docs/import/supabase.md`
//! shows how to create a role that cannot write at all, and the report says
//! whether the role used could ([`crate::report::ReadOnlyEvidence`]).

use sqlx::Connection as _;
use sqlx::postgres::{PgConnectOptions, PgConnection};
use std::str::FromStr as _;

use crate::secret::Secret;

/// Why an inspection stopped. The exit code is non-zero for every one of
/// them; a blocker is never one of them (it is part of the report).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InspectError {
    /// An input was refused before anything was contacted.
    #[error("{0}")]
    InvalidInput(String),
    /// The database could not be reached or refused the login.
    #[error("could not connect to the database: {0}")]
    Connect(String),
    /// The role lacks a privilege a read needs.
    #[error("permission denied: {0}")]
    Permission(String),
    /// A read failed for another reason.
    #[error("a catalog read failed: {0}")]
    Query(String),
    /// A transaction id was assigned during the inspection, which only a
    /// write does. Should never happen; the inspection is abandoned.
    #[error("a write was attempted during the inspection; nothing was committed")]
    WriteDetected,
    /// The Management API refused the token.
    #[error("{0}")]
    ManagementUnauthorized(String),
}

impl InspectError {
    /// The error is about reaching or being allowed into a source — the
    /// class the CLI's exit code reports.
    #[must_use]
    pub fn is_access(&self) -> bool {
        matches!(
            self,
            Self::Connect(_) | Self::Permission(_) | Self::ManagementUnauthorized(_)
        )
    }
}

/// Strips everything a database error might echo back that the caller
/// gave in secret: the URL and its password, then `scrub_text` for the
/// rest.
pub(crate) fn redact(message: &str, url: &Secret) -> String {
    let mut message = message.replace(url.expose(), "[redacted]");
    if let Ok(parsed) = url::Url::parse(url.expose())
        && let Some(password) = parsed.password()
        && !password.is_empty()
    {
        message = message.replace(password, "[redacted]");
        let decoded = percent_decode(password);
        if !decoded.is_empty() {
            message = message.replace(&decoded, "[redacted]");
        }
    }
    cratefield_core::scrub_text(&message)
}

/// `%XX` decoding, enough to recognise a URL-encoded password in plain
/// text.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && text.is_char_boundary(index + 3)
            && let Ok(byte) = u8::from_str_radix(&text[index + 1..index + 3], 16)
        {
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Maps a sqlx error to the class the exit code and the message need.
pub(crate) fn classify(error: &sqlx::Error, url: &Secret) -> InspectError {
    let text = redact(&error.to_string(), url);
    match error {
        sqlx::Error::Database(db) => match db.code().as_deref() {
            Some("42501") => InspectError::Permission(text),
            Some(code) if code.starts_with("28") || code.starts_with("08") || code == "3D000" => {
                InspectError::Connect(text)
            }
            _ => InspectError::Query(text),
        },
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::Configuration(_)
        | sqlx::Error::Protocol(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed => InspectError::Connect(text),
        _ => InspectError::Query(text),
    }
}

/// One connection, in one read-only transaction.
pub struct ReadOnlySession {
    pub(crate) conn: PgConnection,
    pub(crate) url: Secret,
}

impl ReadOnlySession {
    /// Connects to `url` read-only and opens the `REPEATABLE READ READ
    /// ONLY` transaction.
    ///
    /// # Errors
    ///
    /// [`InspectError::Connect`] when the database cannot be reached or
    /// refuses the login; [`InspectError::InvalidInput`] when the URL does
    /// not parse. Neither message quotes the URL.
    pub async fn open(url: &Secret) -> Result<Self, InspectError> {
        let options = PgConnectOptions::from_str(url.expose())
            .map_err(|_| {
                InspectError::InvalidInput(
                    "the database URL is not a valid Postgres connection string".to_owned(),
                )
            })?
            .application_name("cratefield-import-supabase")
            .options([
                ("default_transaction_read_only", "on"),
                ("statement_timeout", "120000"),
            ]);
        let mut conn = PgConnection::connect_with(&options)
            .await
            .map_err(|error| classify(&error, url))?;
        for statement in [
            // Again, in case a pooler dropped the startup options.
            "SET default_transaction_read_only = on",
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
        ] {
            sqlx::raw_sql(statement)
                .execute(&mut conn)
                .await
                .map_err(|error| classify(&error, url))?;
        }
        Ok(Self {
            conn,
            url: url.clone(),
        })
    }

    pub(crate) fn error(&self, error: &sqlx::Error) -> InspectError {
        classify(error, &self.url)
    }

    /// Runs `sql` inside the session's transaction. For tests: the guards
    /// have to refuse a write, and this is how one is attempted.
    ///
    /// # Errors
    ///
    /// The database's refusal, classified.
    #[doc(hidden)]
    pub async fn execute_for_test(&mut self, sql: &str) -> Result<(), InspectError> {
        sqlx::raw_sql(sql)
            .execute(&mut self.conn)
            .await
            .map(|_| ())
            .map_err(|error| self.error(&error))
    }

    /// Asserts no transaction id was assigned, then rolls back.
    ///
    /// # Errors
    ///
    /// [`InspectError::WriteDetected`] when one was.
    pub(crate) async fn finish(mut self) -> Result<bool, InspectError> {
        let assigned: Option<String> =
            sqlx::query_scalar("SELECT txid_current_if_assigned()::text")
                .fetch_one(&mut self.conn)
                .await
                .map_err(|error| self.error(&error))?;
        // Rolled back either way; a failed rollback still ends the session
        // when the connection drops, and nothing was ever committed.
        let _ = sqlx::raw_sql("ROLLBACK").execute(&mut self.conn).await;
        let _ = self.conn.close().await;
        if assigned.is_some() {
            return Err(InspectError::WriteDetected);
        }
        Ok(true)
    }
}
