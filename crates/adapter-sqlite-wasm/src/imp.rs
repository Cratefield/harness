//! The wasm32 implementation (see crate docs). Split out so the crate is
//! cleanly empty on native targets.

use async_trait::async_trait;
use cratefield_core::{Database, DbError, Row, Rows, SqlMigration, Statement};
use js_sys::Promise;
use sea_query::Value as SeaValue;
use send_wrapper::SendWrapper;
use serde_json::Value as Json;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

// The JS bridge. `inline_js` ships with the crate; each function forwards to
// `globalThis.__cratefieldSqlite`, which the host installs over sqlite-wasm.
#[wasm_bindgen(inline_js = r#"
function bridge() {
    const b = globalThis.__cratefieldSqlite;
    if (!b) { throw new Error("cratefield: sqlite bridge not installed (globalThis.__cratefieldSqlite)"); }
    return b;
}
export async function __cf_db_run(sql, params) {
    const changed = await bridge().run(sql, JSON.parse(params));
    return Number(changed) || 0;
}
export async function __cf_db_query(sql, params) {
    const rows = await bridge().query(sql, JSON.parse(params));
    return JSON.stringify(rows);
}
export async function __cf_db_batch(items) {
    await bridge().batch(JSON.parse(items));
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = __cf_db_run)]
    fn js_run(sql: &str, params: &str) -> Promise;
    #[wasm_bindgen(js_name = __cf_db_query)]
    fn js_query(sql: &str, params: &str) -> Promise;
    #[wasm_bindgen(js_name = __cf_db_batch)]
    fn js_batch(items: &str) -> Promise;
}

/// The browser [`Database`]: sqlite-wasm on OPFS via the host bridge.
///
/// A zero-sized handle; every call goes through the JS bridge. Construct with
/// [`SqliteWasmDatabase::new`] and share as `Arc<dyn Database>`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SqliteWasmDatabase;

impl SqliteWasmDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Applies a module's unapplied migrations in order, tracked under
    /// `<module>/<id>` in `harness_migrations` — the same scheme and
    /// idempotency as the rusqlite and D1 adapters (ADR 0004).
    ///
    /// # Errors
    ///
    /// [`DbError::Batch`] when a migration's SQL fails, or when a previously
    /// applied migration's checksum no longer matches its source.
    pub async fn apply_migrations(
        &self,
        module: &str,
        migrations: &[SqlMigration],
    ) -> Result<(), DbError> {
        self.execute(&Statement::new(
            "CREATE TABLE IF NOT EXISTS harness_migrations (\
                 id TEXT PRIMARY KEY, applied_at TEXT NOT NULL, checksum TEXT);",
        ))
        .await
        .map_err(|err| DbError::Batch(err.to_string()))?;

        for migration in migrations {
            let key = format!("{module}/{}", migration.id);
            let checksum = cratefield_core::migration_checksum(migration.sql);
            let existing = self
                .query(&Statement::with_values(
                    "SELECT checksum FROM harness_migrations WHERE id = ?",
                    vec![SeaValue::String(Some(Box::new(key.clone())))],
                ))
                .await
                .map_err(|err| DbError::Batch(err.to_string()))?;
            if let Some(row) = existing.first() {
                if let Some(recorded) = row.get::<String>("checksum")
                    && recorded != checksum
                {
                    return Err(DbError::Batch(cratefield_core::migration_edited(
                        &key, &recorded, &checksum,
                    )));
                }
                continue;
            }
            // Each migration + its bookkeeping row in one atomic batch.
            self.batch(&[
                Statement::new(migration.sql),
                Statement::with_values(
                    "INSERT INTO harness_migrations (id, applied_at, checksum) VALUES (?, ?, ?)",
                    vec![
                        SeaValue::String(Some(Box::new(key.clone()))),
                        SeaValue::String(Some(Box::new(iso_now()))),
                        SeaValue::String(Some(Box::new(checksum))),
                    ],
                ),
            ])
            .await?;
        }
        Ok(())
    }
}

fn iso_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn changes_to_u64(changes: f64) -> u64 {
    // sqlite's `changes()` is a non-negative row count.
    changes.max(0.0) as u64
}

fn params_json(stmt: &Statement) -> String {
    let values: Vec<Json> = stmt.values.0.iter().map(sea_to_json).collect();
    Json::Array(values).to_string()
}

fn js_error(value: &JsValue) -> String {
    value
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(value, &JsValue::from_str("message"))
                .ok()
                .and_then(|m| m.as_string())
        })
        .unwrap_or_else(|| format!("{value:?}"))
}

#[async_trait]
impl Database for SqliteWasmDatabase {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        let promise = js_run(&stmt.sql, &params_json(stmt));
        let out = SendWrapper::new(JsFuture::from(promise))
            .await
            .map_err(|err| DbError::Execute(js_error(&err)))?;
        Ok(changes_to_u64(out.as_f64().unwrap_or(0.0)))
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        let promise = js_query(&stmt.sql, &params_json(stmt));
        let out = SendWrapper::new(JsFuture::from(promise))
            .await
            .map_err(|err| DbError::Query(js_error(&err)))?;
        let json = out
            .as_string()
            .ok_or_else(|| DbError::Query("bridge query returned a non-string".to_owned()))?;
        let value: Json =
            serde_json::from_str(&json).map_err(|err| DbError::Query(err.to_string()))?;
        let Json::Array(rows) = value else {
            return Err(DbError::Query(
                "bridge query result was not an array".to_owned(),
            ));
        };
        let rows = rows
            .into_iter()
            .map(|row| {
                let Json::Object(map) = row else {
                    return Row::new(Vec::new());
                };
                Row::new(
                    map.into_iter()
                        .map(|(column, value)| (column, json_to_sea(&value)))
                        .collect(),
                )
            })
            .collect();
        Ok(Rows::new(rows))
    }

    async fn batch(&self, stmts: &[Statement]) -> Result<(), DbError> {
        let items: Vec<Json> = stmts
            .iter()
            .map(|stmt| {
                let params: Vec<Json> = stmt.values.0.iter().map(sea_to_json).collect();
                serde_json::json!({ "sql": stmt.sql, "params": params })
            })
            .collect();
        let promise = js_batch(&Json::Array(items).to_string());
        SendWrapper::new(JsFuture::from(promise))
            .await
            .map_err(|err| DbError::Batch(js_error(&err)))?;
        Ok(())
    }
}

// The sea-query <-> JSON marshalling matches `cratefield-runtime-cloudflare`'s
// D1 adapter so the portable subset round-trips identically (ADR 0004).

fn sea_to_json(value: &SeaValue) -> Json {
    match value {
        SeaValue::Bool(Some(v)) => Json::Bool(*v),
        SeaValue::TinyInt(Some(v)) => (*v).into(),
        SeaValue::SmallInt(Some(v)) => (*v).into(),
        SeaValue::Int(Some(v)) => (*v).into(),
        SeaValue::BigInt(Some(v)) => (*v).into(),
        SeaValue::TinyUnsigned(Some(v)) => (*v).into(),
        SeaValue::SmallUnsigned(Some(v)) => (*v).into(),
        SeaValue::Unsigned(Some(v)) => (*v).into(),
        SeaValue::BigUnsigned(Some(v)) => (*v).into(),
        SeaValue::Float(Some(v)) => f64::from(*v).into(),
        SeaValue::Double(Some(v)) => (*v).into(),
        SeaValue::String(Some(v)) => v.as_str().into(),
        SeaValue::Char(Some(v)) => v.to_string().into(),
        _ => Json::Null,
    }
}

fn json_to_sea(value: &Json) -> SeaValue {
    match value {
        Json::Null => SeaValue::String(None),
        Json::Bool(v) => SeaValue::Bool(Some(*v)),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                SeaValue::BigInt(Some(i))
            } else {
                SeaValue::Double(Some(n.as_f64().unwrap_or_default()))
            }
        }
        Json::String(s) => SeaValue::String(Some(Box::new(s.clone()))),
        Json::Array(_) | Json::Object(_) => SeaValue::String(Some(Box::from(value.to_string()))),
    }
}
