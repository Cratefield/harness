//! The `Database` port: engine-agnostic statements and rows over
//! sea-query-rendered SQL (ADR 0004).

use async_trait::async_trait;
use sea_query::Value as SeaValue;
use thiserror::Error;

/// A rendered SQL statement: `(sql, values)` with `?` placeholders, produced
/// by rendering a sea-query query for a dialect. Modules build queries with
/// sea-query and render through the helpers on this type (or let adapters do
/// it); adapters bind `values` positionally.
#[derive(Debug, Clone)]
pub struct Statement {
    pub sql: String,
    pub values: sea_query::Values,
}

impl Statement {
    /// A parameterless statement (`SELECT 1`, DDL).
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            values: sea_query::Values(Vec::new()),
        }
    }

    /// A statement with positional `?` values.
    pub fn with_values(sql: impl Into<String>, values: Vec<SeaValue>) -> Self {
        Self {
            sql: sql.into(),
            values: sea_query::Values(values),
        }
    }

    /// Renders a sea-query statement (select/insert/update/delete) with the
    /// SQLite dialect. The portable subset renders identically for D1,
    /// rusqlite and (later) Postgres (ADR 0004).
    pub fn render(query: &impl sea_query::QueryStatementBuilder) -> Self {
        let (sql, values) = query.build_any(&sea_query::SqliteQueryBuilder);
        Self { sql, values }
    }
}

/// A small owned row model. No engine types leak past this point.
#[derive(Debug, Clone)]
pub struct Rows {
    pub rows: Vec<Row>,
}

impl Rows {
    pub fn new(rows: Vec<Row>) -> Self {
        Self { rows }
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn first(&self) -> Option<&Row> {
        self.rows.first()
    }
}

/// One result row: ordered `(column name, value)` pairs.
#[derive(Debug, Clone)]
pub struct Row {
    columns: Vec<(String, SeaValue)>,
}

impl Row {
    pub fn new(columns: Vec<(String, SeaValue)>) -> Self {
        Self { columns }
    }

    /// Column names in result order.
    pub fn column_names(&self) -> impl Iterator<Item = &str> {
        self.columns.iter().map(|(name, _)| name.as_str())
    }

    /// Typed column access. `None` when the column is missing, `NULL`, or
    /// not representable as `T`.
    pub fn get<T: TryFromValue>(&self, column: &str) -> Option<T> {
        let value = self
            .columns
            .iter()
            .find(|(name, _)| name == column)
            .map(|(_, value)| value)?;
        T::try_from_value(value)
    }
}

/// Conversion from a sea-query [`SeaValue`] for typed row access.
pub trait TryFromValue: Sized {
    fn try_from_value(value: &SeaValue) -> Option<Self>;
}

fn text(value: &SeaValue) -> Option<String> {
    match value {
        SeaValue::String(Some(s)) => Some((**s).clone()),
        SeaValue::Char(Some(c)) => Some(c.to_string()),
        _ => None,
    }
}

macro_rules! impl_int {
    ($($t:ty),* $(,)?) => {
        $(
            impl TryFromValue for $t {
                fn try_from_value(value: &SeaValue) -> Option<Self> {
                    let i: i64 = match value {
                        SeaValue::TinyInt(Some(v)) => i64::from(*v),
                        SeaValue::SmallInt(Some(v)) => i64::from(*v),
                        SeaValue::Int(Some(v)) => i64::from(*v),
                        SeaValue::BigInt(Some(v)) => *v,
                        _ => return None,
                    };
                    <$t>::try_from(i).ok()
                }
            }
        )*
    };
}

impl_int!(i8, i16, i32, i64, u8, u16, u32, u64, usize);

impl TryFromValue for String {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        text(value)
    }
}

impl TryFromValue for bool {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        match value {
            SeaValue::Bool(Some(v)) => Some(*v),
            SeaValue::Int(Some(v)) => Some(*v != 0),
            _ => None,
        }
    }
}

impl TryFromValue for f64 {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        match value {
            SeaValue::Float(Some(v)) => Some(f64::from(*v)),
            SeaValue::Double(Some(v)) => Some(*v),
            _ => None,
        }
    }
}

impl TryFromValue for Option<String> {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        // In sea-query 0.32 a SQL NULL is the variant with `None` inside
        // (e.g. `Value::String(None)`); a type mismatch is our `None`.
        match value {
            SeaValue::String(inner) => Some(inner.as_deref().map(String::from)),
            _ => None,
        }
    }
}

impl TryFromValue for SeaValue {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        Some(value.clone())
    }
}

/// Database failures, sanitized for logs and problem details.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DbError {
    #[error("execute failed: {0}")]
    Execute(String),
    #[error("query failed: {0}")]
    Query(String),
    #[error("batch failed: {0}")]
    Batch(String),
}

/// Execute statements against the venture database. Implementations: D1
/// (Workers), rusqlite (tests, self-hosted), Postgres (phase 3).
///
/// `batch` runs all statements in one unit of work where the engine supports
/// it (a transaction on SQLite and D1's atomic batch); documented per
/// adapter.
#[async_trait]
pub trait Database: Send + Sync {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError>;
    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError>;
    async fn batch(&self, stmts: &[Statement]) -> Result<(), DbError>;
}
