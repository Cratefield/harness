//! The inputs that are secrets, and the one view of them a report may hold.
//!
//! ADR 0026, Decision 2: the database URL and the Management API token live
//! in process memory only, are cleared on drop, never reach a log line, and
//! the report names the database by host, port and database alone.

use std::fmt;
use zeroize::Zeroizing;

/// A secret string: cleared on drop, and `Debug` prints `[redacted]`, so a
/// stray `{:?}` cannot disclose it.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps `value`.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The value. Named `expose` so a reader has to notice.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The part of a connection string a report may show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceName {
    /// The host.
    pub host: String,
    /// The port (5432 when the URL names none).
    pub port: u16,
    /// The database (`postgres` when the URL names none).
    pub database: String,
}

/// Parses `url` as a `postgres://` or `postgresql://` connection string and
/// returns its host, port and database, and nothing else.
///
/// # Errors
///
/// A message that never quotes the URL: it may hold a password.
pub fn source_name(url: &Secret) -> Result<SourceName, String> {
    let parsed = url::Url::parse(url.expose()).map_err(|_| {
        "the database URL is not a valid URL (postgres://user:password@host:5432/postgres)"
            .to_owned()
    })?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") {
        return Err(format!(
            "the database URL must start with postgres:// or postgresql://, not {}://",
            parsed.scheme()
        ));
    }
    let host = parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "the database URL names no host".to_owned())?
        .to_owned();
    let database = parsed.path().trim_start_matches('/');
    Ok(SourceName {
        host,
        port: parsed.port().unwrap_or(5432),
        database: if database.is_empty() {
            "postgres".to_owned()
        } else {
            database.to_owned()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_value() {
        let secret = Secret::new("postgres://u:hunter2@db.example.test/postgres");
        assert_eq!(format!("{secret:?}"), "[redacted]");
    }

    #[test]
    fn the_source_name_keeps_host_port_and_database_only() {
        let name = source_name(&Secret::new(
            "postgresql://inspect.ref:hunter2@db.abc.supabase.co:6543/postgres?sslmode=require",
        ))
        .expect("parses");
        assert_eq!(
            name,
            SourceName {
                host: "db.abc.supabase.co".to_owned(),
                port: 6543,
                database: "postgres".to_owned(),
            }
        );
    }

    #[test]
    fn a_bad_url_is_refused_without_quoting_it() {
        let error = source_name(&Secret::new("hunter2 is not a url")).unwrap_err();
        assert!(!error.contains("hunter2"), "{error}");
        let error = source_name(&Secret::new("mysql://u:hunter2@h/db")).unwrap_err();
        assert!(!error.contains("hunter2"), "{error}");
    }
}
