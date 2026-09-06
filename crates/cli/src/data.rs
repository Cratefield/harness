//! `fz data export` / `fz data import` (issue #21): moving a venture's
//! D1 data to Postgres — the migration-path step between "stand up
//! Postgres, run the migrations" and "switch the runtime" (architecture
//! section 10).
//!
//! **Export** reads a venture SQLite database — D1 is SQLite, and the
//! Cloudflare-side step is `wrangler d1 export` loaded into a local
//! SQLite file; `docs/DATA-MOVE.md` is the runbook. It writes one JSON
//! Lines file: a manifest line first (per-table row counts and sha256,
//! tables in lock order), then one `{"table","row"}` record per table
//! row, tables in the same lock order.
//!
//! **Import** (requires the crate's `postgres` feature, like `fz
//! migrations apply`) loads that file into a Postgres database in lock
//! order: it verifies every table's sha256 against the manifest,
//! refuses a non-empty table without `--append`, inserts batched
//! multi-row statements inside one transaction per table, and verifies
//! row counts afterwards. `--plan` prints what either command would do
//! and writes nothing.

use factory0_adapter_sqlite::SqliteDatabase;
use factory0_core::{Database, Harness, Row, Statement};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use std::path::Path;

/// Rows per multi-row INSERT during import: 200 rows × ≤ ~16 columns
/// stays far below Postgres' 65 535 bind-parameter ceiling.
#[cfg(feature = "postgres")]
const IMPORT_BATCH_ROWS: usize = 200;

// ---------------------------------------------------------------------------
// Manifest and record model

#[derive(Debug, Serialize, Deserialize)]
struct TableManifest {
    table: String,
    columns: Vec<String>,
    rows: u64,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    tables: Vec<TableManifest>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    table: String,
    row: Map<String, Json>,
}

/// The parsed export file. Record lines are kept as raw bytes: the
/// sha256 must cover exactly what export wrote, not a re-serialization.
struct ExportFile {
    manifest: Manifest,
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    records: Vec<(String, Vec<u8>)>,
}

fn parse_export_file(bytes: &[u8], path: &Path) -> Result<ExportFile, String> {
    let mut lines = bytes.split(|b| *b == b'\n');
    let first = lines.next().unwrap_or_default();
    let manifest: Manifest = serde_json::from_slice(first).map_err(|err| {
        format!(
            "{}: the first line must be the manifest: {err}",
            path.display()
        )
    })?;
    if manifest.tables.is_empty() {
        return Err(format!("{}: the manifest lists no tables", path.display()));
    }
    let mut records = Vec::new();
    for raw in lines {
        if raw.is_empty() {
            continue;
        }
        let record: Record = serde_json::from_slice(raw).map_err(|err| {
            format!(
                "{}: line {} is not a data record: {err}",
                path.display(),
                records.len() + 2
            )
        })?;
        records.push((record.table, raw.to_vec()));
    }
    Ok(ExportFile { manifest, records })
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// A manifest comes from a file anyone can edit, and its table and
/// column names end up inside generated SQL: accept only the portable
/// identifier shape, then quote them.
fn validate_identifier(kind: &str, name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = matches!(chars.next(), Some('a'..='z' | 'A'..='Z' | '_'))
        && chars.all(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "invalid {kind} {name:?}: only [A-Za-z_][A-Za-z0-9_]* is allowed"
        ))
    }
}

/// The venture's tables in lock order: modules in harness (config)
/// order, each module's tables in declared order — the order `fz
/// migrations collect` pins and the manifest carries. The migrations
/// bookkeeping table is infrastructure, never venture data.
fn harness_tables(harness: &Harness) -> Vec<String> {
    harness
        .modules()
        .iter()
        .flat_map(|module| module.tables().iter().map(|t| (*t).to_owned()))
        .collect()
}

// ---------------------------------------------------------------------------
// Export

/// Exports the venture's tables from the SQLite database at `db_path`
/// to `out_path` as manifest + JSONL records (see the module docs).
/// `plan` prints the per-table summary without writing.
///
/// # Errors
///
/// A human-readable message when the database cannot be opened, a table
/// is missing, a value is outside the portable subset, or the file
/// cannot be written.
pub fn export(
    harness: &Harness,
    db_path: &Path,
    out_path: &Path,
    plan: bool,
) -> Result<(), String> {
    let tables = harness_tables(harness);
    if tables.is_empty() {
        return Err("the harness's modules declare no tables; nothing to export".to_owned());
    }
    for table in &tables {
        validate_identifier("table", table)?;
    }
    let db = SqliteDatabase::open(&db_path.to_string_lossy())
        .map_err(|err| format!("cannot open {}: {err}", db_path.display()))?;

    let mut manifest = Manifest { tables: Vec::new() };
    let mut body = String::new();
    for table in &tables {
        let rows =
            pollster::block_on(db.query(&Statement::new(format!("SELECT * FROM \"{table}\""))))
                .map_err(|err| format!("cannot read {table}: {err} (is the database migrated?)"))?;
        let columns: Vec<String> = rows
            .first()
            .map(|first| first.column_names().map(str::to_owned).collect())
            .unwrap_or_default();
        for column in &columns {
            validate_identifier("column", column)?;
        }
        if plan {
            println!("  {table}: {} rows, {} columns", rows.len(), columns.len());
            manifest.tables.push(TableManifest {
                table: table.clone(),
                columns,
                rows: rows.len() as u64,
                sha256: String::new(),
            });
            continue;
        }
        let mut table_bytes = Vec::new();
        for row in &rows.rows {
            let record = record_line(table, row)?;
            table_bytes.extend_from_slice(record.as_bytes());
            table_bytes.push(b'\n');
            body.push_str(&record);
            body.push('\n');
        }
        manifest.tables.push(TableManifest {
            table: table.clone(),
            columns,
            rows: rows.len() as u64,
            sha256: sha256_hex(&table_bytes),
        });
    }

    if plan {
        println!(
            "plan: export {} ({} tables) -> {}",
            db_path.display(),
            manifest.tables.len(),
            out_path.display()
        );
        return Ok(());
    }
    let manifest_line = serde_json::to_string(&manifest)
        .map_err(|err| format!("cannot serialize the manifest: {err}"))?;
    std::fs::write(out_path, format!("{manifest_line}\n{body}"))
        .map_err(|err| format!("cannot write {}: {err}", out_path.display()))?;
    let total: u64 = manifest.tables.iter().map(|t| t.rows).sum();
    println!(
        "exported {total} rows across {} tables to {}",
        manifest.tables.len(),
        out_path.display()
    );
    Ok(())
}

fn record_line(table: &str, row: &Row) -> Result<String, String> {
    let mut object = Map::new();
    for name in row.column_names() {
        let value = row
            .get::<sea_query::Value>(name)
            .unwrap_or(sea_query::Value::String(None));
        let json = sea_value_to_json(&value)
            .map_err(|problem| format!("table {table}, column {name}: {problem}"))?;
        object.insert(name.to_owned(), json);
    }
    let record = Record {
        table: table.to_owned(),
        row: object,
    };
    serde_json::to_string(&record).map_err(|err| format!("cannot serialize a row: {err}"))
}

fn sea_value_to_json(value: &sea_query::Value) -> Result<Json, String> {
    use sea_query::Value as Sea;
    Ok(match value {
        Sea::Bool(None)
        | Sea::TinyInt(None)
        | Sea::SmallInt(None)
        | Sea::Int(None)
        | Sea::BigInt(None)
        | Sea::TinyUnsigned(None)
        | Sea::SmallUnsigned(None)
        | Sea::Unsigned(None)
        | Sea::BigUnsigned(None)
        | Sea::Float(None)
        | Sea::Double(None)
        | Sea::String(None)
        | Sea::Char(None)
        | Sea::Bytes(None) => Json::Null,
        Sea::Bool(Some(v)) => Json::Bool(*v),
        Sea::TinyInt(Some(v)) => i64::from(*v).into(),
        Sea::SmallInt(Some(v)) => i64::from(*v).into(),
        Sea::Int(Some(v)) => i64::from(*v).into(),
        Sea::BigInt(Some(v)) => (*v).into(),
        Sea::TinyUnsigned(Some(v)) => u64::from(*v).into(),
        Sea::SmallUnsigned(Some(v)) => u64::from(*v).into(),
        Sea::Unsigned(Some(v)) => (*v).into(),
        Sea::BigUnsigned(Some(v)) => (*v).into(),
        Sea::Float(Some(v)) => Json::from(f64::from(*v)),
        Sea::Double(Some(v)) => Json::from(*v),
        Sea::String(Some(v)) => Json::String((**v).clone()),
        Sea::Char(Some(v)) => Json::String(v.to_string()),
        // BLOBs are outside the portable subset (ADR 0004); refuse them
        // rather than invent an encoding import could not round-trip.
        Sea::Bytes(Some(_)) => {
            return Err(
                "BLOB data is outside the portable subset and cannot be exported".to_owned(),
            );
        }
    })
}

// ---------------------------------------------------------------------------
// Import (Postgres; requires the `postgres` feature)

/// Imports an export file into the Postgres database at `url` (see the
/// module docs). `plan` prints the per-table target state without
/// writing.
///
/// # Errors
///
/// A human-readable message when the file is malformed, a sha256 or row
/// count disagrees with the manifest, a target table is missing or
/// non-empty without `--append`, or any insert fails. The connection
/// string is never echoed.
pub fn import(
    harness: &Harness,
    file_path: &Path,
    url: &str,
    append: bool,
    plan: bool,
) -> Result<(), String> {
    let bytes = std::fs::read(file_path)
        .map_err(|err| format!("cannot read {}: {err}", file_path.display()))?;
    let file = parse_export_file(&bytes, file_path)?;
    validate_manifest(harness, &file.manifest)?;

    #[cfg(not(feature = "postgres"))]
    {
        let _ = (url, append, plan);
        Err(
            "this fz binary was built without factory0-cli's `postgres` feature — \
             rebuild the fz bin with `--features factory0-cli/postgres` to import \
             into Postgres"
                .to_owned(),
        )
    }
    #[cfg(feature = "postgres")]
    import_postgres(file_path, &file, url, append, plan)
}

/// The manifest must be exactly this venture's tables, in lock order,
/// each a valid identifier — the wrong venture's export file fails
/// before anything touches the network.
fn validate_manifest(harness: &Harness, manifest: &Manifest) -> Result<(), String> {
    let expected = harness_tables(harness);
    let mut seen = std::collections::BTreeSet::new();
    for table in &manifest.tables {
        validate_identifier("table", &table.table)?;
        if !seen.insert(table.table.clone()) {
            return Err(format!(
                "table {} appears twice in the manifest",
                table.table
            ));
        }
        for column in &table.columns {
            validate_identifier("column", column)?;
        }
    }
    for table in &manifest.tables {
        if !expected.contains(&table.table) {
            return Err(format!(
                "manifest table {} is not a table of this venture's modules (expected: {})",
                table.table,
                expected.join(", ")
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn import_postgres(
    file_path: &Path,
    file: &ExportFile,
    url: &str,
    append: bool,
    plan: bool,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("cannot start the async runtime: {err}"))?;
    runtime.block_on(async {
        let db = factory0_adapter_postgres::Postgres::connect(url)
            .await
            .map_err(|err| format!("cannot connect (check --url): {err}"))?;

        let schemas = load_target_schemas(&db, &file.manifest).await?;
        check_column_drift(&file.manifest, &schemas)?;
        let existing = preflight_counts(&db, &file.manifest, append, plan).await?;

        if plan {
            println!(
                "plan: import {} ({} tables, {} rows) -> postgres{}",
                file_path.display(),
                file.manifest.tables.len(),
                file.manifest.tables.iter().map(|t| t.rows).sum::<u64>(),
                if append { " with --append" } else { "" }
            );
            for (entry, had) in file.manifest.tables.iter().zip(&existing) {
                println!(
                    "  {}: incoming {} rows, target has {had} rows{}",
                    entry.table,
                    entry.rows,
                    if *had > 0 && !append {
                        " — REFUSES without --append"
                    } else {
                        ""
                    }
                );
            }
            return Ok(());
        }

        let slices = table_slices(&file.manifest, file)?;
        verify_hashes(&file.manifest, &slices)?;
        import_tables(&db, &file.manifest, &schemas, &slices).await?;
        verify_counts(&db, &file.manifest, &existing).await?;
        println!("import verified against the manifest");
        Ok(())
    })
}

/// Per table, the target's `(column, data type)` list in ordinal order —
/// the type drives every bind, including typed NULLs (a text-typed NULL
/// will not insert into an integer column).
#[cfg(feature = "postgres")]
async fn load_target_schemas(
    db: &factory0_adapter_postgres::Postgres,
    manifest: &Manifest,
) -> Result<Vec<Vec<(String, String)>>, String> {
    let mut schemas = Vec::with_capacity(manifest.tables.len());
    for entry in &manifest.tables {
        let rows = db
            .query(&Statement::with_values(
                "SELECT column_name, data_type FROM information_schema.columns \
                 WHERE table_name = ? ORDER BY ordinal_position",
                vec![entry.table.clone().into()],
            ))
            .await
            .map_err(|err| format!("cannot read the schema of {}: {err}", entry.table))?;
        let columns: Vec<(String, String)> = rows
            .rows
            .iter()
            .map(|row| {
                (
                    row.get::<String>("column_name").unwrap_or_default(),
                    row.get::<String>("data_type").unwrap_or_default(),
                )
            })
            .collect();
        if columns.is_empty() {
            return Err(format!(
                "table {} does not exist in the target — run `fz migrations apply \
                 --dialect postgres` first",
                entry.table
            ));
        }
        schemas.push(columns);
    }
    Ok(schemas)
}

/// The manifest's columns must be exactly the target's columns before
/// anything is written — an export from a drifted schema fails loudly.
#[cfg(feature = "postgres")]
fn check_column_drift(
    manifest: &Manifest,
    schemas: &[Vec<(String, String)>],
) -> Result<(), String> {
    for (entry, columns) in manifest.tables.iter().zip(schemas) {
        if entry.columns.is_empty() {
            continue;
        }
        let target: Vec<&str> = columns.iter().map(|(name, _)| name.as_str()).collect();
        let mut exported = entry.columns.clone();
        exported.sort_unstable();
        let mut target_sorted = target.clone();
        target_sorted.sort_unstable();
        if exported != target_sorted {
            return Err(format!(
                "table {}: the export has columns [{}] but the target has [{}]",
                entry.table,
                entry.columns.join(", "),
                target.join(", ")
            ));
        }
    }
    Ok(())
}

/// Row counts before any write: a non-empty table without `--append` is
/// refused up front, so a partial import never starts.
#[cfg(feature = "postgres")]
async fn preflight_counts(
    db: &factory0_adapter_postgres::Postgres,
    manifest: &Manifest,
    append: bool,
    plan: bool,
) -> Result<Vec<u64>, String> {
    let mut existing = Vec::with_capacity(manifest.tables.len());
    for entry in &manifest.tables {
        let count = row_count(db, &entry.table).await?;
        if count > 0 && !append && !plan {
            return Err(format!(
                "table {} already has {count} rows — pass --append to add to it",
                entry.table
            ));
        }
        existing.push(count);
    }
    Ok(existing)
}

/// One table's `(table, raw line)` record group.
#[cfg(feature = "postgres")]
type RecordGroup = [(String, Vec<u8>)];

/// Slices the file into per-table record groups in manifest (lock)
/// order. Records must arrive grouped per table — anything else is a
/// hand-edited file.
#[cfg(feature = "postgres")]
fn table_slices<'a>(
    manifest: &Manifest,
    file: &'a ExportFile,
) -> Result<Vec<&'a RecordGroup>, String> {
    let mut slices = Vec::with_capacity(manifest.tables.len());
    let mut cursor = 0usize;
    for entry in &manifest.tables {
        let expected_rows = usize::try_from(entry.rows).unwrap_or(usize::MAX);
        let end = (cursor + expected_rows).min(file.records.len());
        let slice = &file.records[cursor..end];
        for (table, _) in slice {
            if table != &entry.table {
                return Err(format!(
                    "records for {} are out of lock order (found {}) — the file was \
                     edited after export",
                    entry.table, table
                ));
            }
        }
        if slice.len() != expected_rows {
            return Err(format!(
                "table {}: the manifest says {} rows but the file holds {}",
                entry.table,
                entry.rows,
                slice.len()
            ));
        }
        slices.push(slice);
        cursor += expected_rows;
    }
    Ok(slices)
}

/// Verifies EVERY table's sha256 against the manifest before anything
/// is written — a tampered file leaves the target untouched (earlier
/// tables in lock order are not imported around a later failure).
#[cfg(feature = "postgres")]
fn verify_hashes(manifest: &Manifest, slices: &[&RecordGroup]) -> Result<(), String> {
    for (entry, slice) in manifest.tables.iter().zip(slices) {
        let mut hashed = Vec::new();
        for (_, line) in *slice {
            hashed.extend_from_slice(line);
            hashed.push(b'\n');
        }
        let digest = sha256_hex(&hashed);
        if digest != entry.sha256 {
            return Err(format!(
                "table {}: sha256 mismatch (manifest {}, file {}) — the file was \
                 edited or truncated after export",
                entry.table, entry.sha256, digest
            ));
        }
    }
    Ok(())
}

/// Inserts each table's records in batched multi-row statements inside
/// one transaction per table (atomic per table; `--append` re-runs
/// resume at the tables that are still empty).
#[cfg(feature = "postgres")]
async fn import_tables(
    db: &factory0_adapter_postgres::Postgres,
    manifest: &Manifest,
    schemas: &[Vec<(String, String)>],
    slices: &[&RecordGroup],
) -> Result<(), String> {
    for ((entry, columns), slice) in manifest.tables.iter().zip(schemas).zip(slices) {
        if entry.rows > 0 {
            insert_table(db, entry, columns, slice).await?;
        }
    }
    Ok(())
}

/// After the writes: every table must hold exactly what the manifest
/// promised on top of what it had.
#[cfg(feature = "postgres")]
async fn verify_counts(
    db: &factory0_adapter_postgres::Postgres,
    manifest: &Manifest,
    existing: &[u64],
) -> Result<(), String> {
    for (entry, had) in manifest.tables.iter().zip(existing) {
        let now = row_count(db, &entry.table).await?;
        let expected = had + entry.rows;
        if now != expected {
            return Err(format!(
                "table {}: expected {expected} rows after import, found {now}",
                entry.table
            ));
        }
        println!(
            "  {}: {} rows imported, {now} total",
            entry.table, entry.rows
        );
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn row_count(db: &factory0_adapter_postgres::Postgres, table: &str) -> Result<u64, String> {
    let rows = db
        .query(&Statement::new(format!(
            "SELECT COUNT(*) AS n FROM \"{table}\""
        )))
        .await
        .map_err(|err| format!("cannot count {table}: {err}"))?;
    let count = rows
        .first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default();
    Ok(u64::try_from(count).unwrap_or_default())
}

#[cfg(feature = "postgres")]
async fn insert_table(
    db: &factory0_adapter_postgres::Postgres,
    entry: &TableManifest,
    columns: &[(String, String)],
    records: &RecordGroup,
) -> Result<(), String> {
    let column_list = entry
        .columns
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders = format!("({})", vec!["?"; entry.columns.len()].join(", "));

    let mut statements = Vec::new();
    for chunk in records.chunks(IMPORT_BATCH_ROWS) {
        let mut sql = format!("INSERT INTO \"{}\" ({column_list}) VALUES ", entry.table);
        let mut values = Vec::with_capacity(chunk.len() * entry.columns.len());
        for (index, (_, line)) in chunk.iter().enumerate() {
            let record: Record = serde_json::from_slice(line)
                .map_err(|err| format!("table {}: row {}: {err}", entry.table, index))?;
            if index > 0 {
                sql.push_str(", ");
            }
            sql.push_str(&placeholders);
            for column in &entry.columns {
                let value = record.row.get(column).unwrap_or(&Json::Null);
                let Some(pg_type) = columns
                    .iter()
                    .find(|(name, _)| name == column)
                    .map(|(_, kind)| kind.as_str())
                else {
                    return Err(format!(
                        "table {}: column {column} vanished from the target schema",
                        entry.table
                    ));
                };
                values.push(bind_json_for_type(
                    &entry.table,
                    column,
                    pg_type,
                    value,
                    index,
                )?);
            }
        }
        statements.push(Statement::with_values(sql, values));
    }
    db.batch(&statements)
        .await
        .map_err(|err| format!("table {}: {err}", entry.table))
}

/// Maps one JSON value onto the sea-query bind matching the target
/// column's Postgres type, so SQL NULL binds as a NULL of the right
/// type and integers do not arrive as text.
#[cfg(feature = "postgres")]
fn bind_json_for_type(
    table: &str,
    column: &str,
    pg_type: &str,
    value: &Json,
    row_index: usize,
) -> Result<sea_query::Value, String> {
    use sea_query::Value as Sea;
    let where_ = |problem: String| format!("{table}.{column}, row {row_index}: {problem}");
    let kind = match value {
        Json::Null => "null",
        Json::Bool(_) => "a boolean",
        Json::Number(_) => "a number",
        Json::String(_) => "a string",
        Json::Array(_) => "an array",
        Json::Object(_) => "an object",
    };
    let int_of = || {
        value
            .as_i64()
            .ok_or_else(|| where_(format!("expected an integer, found {kind}")))
    };
    Ok(match pg_type {
        "smallint" => match value {
            Json::Null => Sea::SmallInt(None),
            _ => Sea::SmallInt(Some(i16::try_from(int_of()?).map_err(|_| {
                where_("the value does not fit the SMALLINT column".to_owned())
            })?)),
        },
        "integer" => match value {
            Json::Null => Sea::Int(None),
            _ => Sea::Int(Some(i32::try_from(int_of()?).map_err(|_| {
                where_("the value does not fit the INTEGER column".to_owned())
            })?)),
        },
        "bigint" => match value {
            Json::Null => Sea::BigInt(None),
            _ => Sea::BigInt(Some(int_of()?)),
        },
        "real" | "double precision" => match value {
            Json::Null => Sea::Double(None),
            _ => {
                Sea::Double(Some(value.as_f64().ok_or_else(|| {
                    where_(format!("expected a number, found {kind}"))
                })?))
            }
        },
        "boolean" => match value {
            Json::Null => Sea::Bool(None),
            Json::Bool(v) => Sea::Bool(Some(*v)),
            Json::Number(_) => Sea::Bool(Some(int_of()? != 0)),
            _ => return Err(where_(format!("expected a boolean, found {kind}"))),
        },
        "text" | "character varying" | "character" | "varchar" | "bpchar" | "name" => match value {
            Json::Null => Sea::String(None),
            Json::String(v) => Sea::String(Some(Box::new(v.clone()))),
            _ => return Err(where_(format!("expected a string, found {kind}"))),
        },
        other => {
            return Err(where_(format!(
                "target type {other:?} is outside the portable subset (TEXT, INTEGER, \
                 REAL, BOOLEAN)"
            )));
        }
    })
}
