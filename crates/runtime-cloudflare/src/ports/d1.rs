//! `Database` over `worker::D1Database` (ADR 0004): sea-query renders the
//! statement, values bind positionally, `batch` uses D1's atomic batch.

use async_trait::async_trait;
use factory0_core::{Database, DbError, Row, Rows, Statement};
use sea_query::Value as SeaValue;
use serde_json::Value as Json;
use worker::D1Database as WorkerD1;
use worker::send::IntoSendFuture;

pub struct D1Database(pub WorkerD1);

fn bind_statement(
    db: &WorkerD1,
    stmt: &Statement,
) -> worker::Result<worker::d1::D1PreparedStatement> {
    let prepared = db.prepare(&stmt.sql);
    if stmt.values.0.is_empty() {
        return Ok(prepared);
    }
    // Bind through serde_json + serde_wasm_bindgen rather than `bind_refs`
    // with `D1Type`: the `D1Type` conversion path fails (integer binds
    // error, text binds hang) under workerd/miniflare, while the
    // JSON->JsValue path is the one workers-rs itself uses for D1 results.
    //
    // A JSON `null` must bind as JS `null`, not the `undefined` that
    // `serde_wasm_bindgen` produces for it: D1 rejects `undefined` with
    // `D1_TYPE_ERROR: Type 'undefined' not supported`, so any write with a
    // NULL column (a nullable field left unset) would fail. Map null first.
    let js_values: Vec<worker::wasm_bindgen::JsValue> = stmt
        .values
        .0
        .iter()
        .map(sea_to_json)
        .map(|json| {
            if json.is_null() {
                Ok(worker::wasm_bindgen::JsValue::NULL)
            } else {
                worker::d1::serde_wasm_bindgen::to_value(&json)
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(worker::Error::SerdeWasmBindgenError)?;
    prepared.bind(&js_values)
}

fn sea_to_json(value: &SeaValue) -> serde_json::Value {
    match value {
        SeaValue::Bool(Some(v)) => serde_json::Value::Bool(*v),
        SeaValue::TinyInt(Some(v)) => (*v).into(),
        SeaValue::SmallInt(Some(v)) => (*v).into(),
        SeaValue::Int(Some(v)) => (*v).into(),
        SeaValue::BigInt(Some(v)) => (*v).into(),
        SeaValue::TinyUnsigned(Some(v)) => (*v).into(),
        SeaValue::SmallUnsigned(Some(v)) => (*v).into(),
        SeaValue::Unsigned(Some(v)) => (*v).into(),
        // u64 > JSON safe range is not representable; the portable subset
        // stores ids as TEXT, so this never triggers in practice.
        SeaValue::BigUnsigned(Some(v)) => (*v).into(),
        SeaValue::Float(Some(v)) => f64::from(*v).into(),
        SeaValue::Double(Some(v)) => (*v).into(),
        SeaValue::String(Some(v)) => v.as_str().into(),
        _ => serde_json::Value::Null,
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

fn d1_rows_to_rows(result: &worker::d1::D1Result) -> Result<Rows, DbError> {
    let values: Vec<Json> = result
        .results()
        .map_err(|err| DbError::Query(err.to_string()))?;
    let rows = values
        .into_iter()
        .map(|value| {
            let Json::Object(map) = value else {
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

#[async_trait]
impl Database for D1Database {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        let prepared =
            bind_statement(&self.0, stmt).map_err(|err| DbError::Execute(err.to_string()))?;
        // Writes go through `batch` (single-statement): plain `.run()` /
        // `.all()` promises never resolve for writes under local
        // workerd/miniflare (verified empirically); batch resolves.
        let results = self
            .0
            .batch(vec![prepared])
            .into_send()
            .await
            .map_err(|err| DbError::Execute(err.to_string()))?;
        let changed = results
            .first()
            .and_then(|result| result.meta().ok().flatten())
            .and_then(|meta| meta.changes)
            .unwrap_or_default();
        Ok(u64::try_from(changed).unwrap_or(u64::MAX))
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        let prepared =
            bind_statement(&self.0, stmt).map_err(|err| DbError::Query(err.to_string()))?;
        let result = prepared
            .all()
            .into_send()
            .await
            .map_err(|err| DbError::Query(err.to_string()))?;
        d1_rows_to_rows(&result)
    }

    /// D1 batches are atomic (single implicit transaction).
    async fn batch(&self, stmts: &[Statement]) -> Result<(), DbError> {
        let mut prepared = Vec::with_capacity(stmts.len());
        for stmt in stmts {
            prepared.push(
                bind_statement(&self.0, stmt).map_err(|err| DbError::Batch(err.to_string()))?,
            );
        }
        self.0
            .batch(prepared)
            .into_send()
            .await
            .map_err(|err| DbError::Batch(err.to_string()))?;
        Ok(())
    }
}
