//! The Backups screen (issue #29): what has been backed up, where it
//! went, and whether anyone has ever proved a backup comes back.
//!
//! The screen holds three truths at once, and the tension between them
//! is the design:
//!
//! 1. **A backup history that only records successes is how people find
//!    out at restore time.** Every attempt is a row in `backup_attempt`,
//!    failed ones included, and the failure's reason is recorded
//!    verbatim.
//! 2. **Keeping a backup needs storage the control plane does not
//!    have.** The store that would hold backups is R2, the control plane
//!    holds no credential for it (#26), and so the [`BackupStore`]
//!    port's only implementation is [`Unwired`], which refuses. "Back up
//!    now" runs the attempt for real and records the refusal — the same
//!    contract the provisioning engine has with its own
//!    [`cratefield_provisioning::Unwired`].
//! 3. **A backup that has never been restored is not a backup.** The
//!    restore path is therefore part of this screen: the D1 Time Travel
//!    facts below are stated as facts, the export this screen serves is
//!    real, the rehearsal procedure is written out, and whether a
//!    rehearsal has ever happened is recorded and shown — "never
//!    rehearsed" when it has not, because a page that lists backups and
//!    says nothing about restoring them reproduces exactly the false
//!    confidence that sentence warns about.
//!
//! What is real today: the export. The control plane's own database is
//! the one database it can reach, and reading it through the `Database`
//! port to produce a download — the same shape `fz data export` writes
//! (a manifest line, then one JSON record per row) — needs no
//! credential at all. That export does **not** go through
//! [`BackupStore::take`], and the reason is the port's own contract:
//! `take` promises the store *kept* the result somewhere `fetch` can
//! answer for. A download keeps nothing — the operator's copy is the
//! copy — so routing it through `take` would record successes that
//! `fetch` then contradicts. It is served by its own route, recorded
//! with the destination it truly has ("operator download"), and the
//! page says what it carries and what it deliberately omits.
//!
//! [`Unwired`]: crate::backups::Unwired
//! [`BackupStore`]: crate::backups::BackupStore
//! [`BackupStore::take`]: crate::backups::BackupStore::take
//!
//! Out of scope, named: **scheduled backups.** The rotation work in
//! another worktree adds a `Module::scheduled` implementation to this
//! module; scheduling belongs with it, and this screen records who or
//! what asked (`requested_by`) so a scheduled job's rows will read as
//! its own from the first one. **Restoring into a live database** —
//! writing a restore needs a credential and a destination the control
//! plane does not have (#26), so the rehearsal here proves the file,
//! not a standing replacement, and says exactly that.

use std::sync::Arc;

use axum::extract::{Form, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use cratefield_chrome::{Page, escape, render};
use cratefield_console::current_session;
use cratefield_core::{Database, DbError, MAX_EXPORT_ROWS, Statement};
use cratefield_introspect as introspect;
use http::{StatusCode, header};
use sea_query::Value as SeaValue;
use serde_json::{Value as Json, json};

use crate::{DashboardState, account_nav, account_of, frame, guard, internal, now_rfc3339, ulid};

/// The path this screen sits at.
const PATH: &str = "/v1/dashboard/backups";

/// Rows per read while building the export — the same page size the
/// data screen's CSV export reads.
const EXPORT_PAGE: u64 = 500;

/// The schema migration: `backup_attempt` and `restore_rehearsal`. The
/// set id it lands under in the dashboard's migration list is wired in
/// `lib.rs`; the file numbering is this crate's own directory's.
pub(crate) const MIGRATION: cratefield_core::SqlMigration = cratefield_core::SqlMigration::new(
    "0009",
    "backups",
    include_str!("../migrations/sqlite/0004_backups.sql"),
);

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

/// A failure from the thing that would keep backups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupError {
    /// Safe to record and show; never a credential.
    pub message: String,
}

impl BackupError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// A backup the store kept: where it put it, how big it is, and the
/// sha256 of the bytes (empty when the store cannot know it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub destination: String,
    pub size: u64,
    pub sha256: String,
}

/// Where kept backups live. `take` produces one and the store keeps it;
/// `list` names every backup the store still holds; `fetch` returns one
/// held backup's bytes. Together they are the contract a restore needs:
/// something was taken, it is still there, it can be read back.
///
/// `list` and `fetch` have no caller in this screen today and that is
/// the point of recording it here: no store is wired, so nothing is
/// held and there is nothing truthful to list or fetch. They are
/// exercised by the fake in the tests, and the day an R2 adapter
/// exists (#26), the restore path grows into them instead of around
/// them.
#[allow(async_fn_in_trait)]
pub trait BackupStore {
    /// Take a backup of `scope` now; the store decides where it goes.
    async fn take(&self, scope: &str) -> Result<Stored, BackupError>;
    /// Every backup the store still holds, by id.
    async fn list(&self) -> Result<Vec<String>, BackupError>;
    /// One held backup's bytes.
    async fn fetch(&self, id: &str) -> Result<Vec<u8>, BackupError>;
}

/// The backup store the control plane has today: none.
///
/// Keeping a backup needs an adapter that talks to R2, and the control
/// plane holds no credential for one (#26). "Back up now" runs through
/// this implementation for real: the take is refused, the refusal is
/// recorded as a failed attempt with its reason, and the row is there
/// to see. Nothing pretends to be queued, loading, or in flight — a
/// refusal is a stop, and it reads as one. The day a real
/// [`BackupStore`] is passed instead, the same press stores a backup
/// and the row records where.
pub struct Unwired;

impl Unwired {
    /// The one message, so every recorded refusal reads the same.
    fn refuse<T>(what: &str) -> Result<T, BackupError> {
        Err(BackupError::new(format!(
            "no backup store is wired: {what} needs an adapter that talks to R2, and the \
             control plane holds no credential for one (#26). Nothing was changed."
        )))
    }
}

// Every method answers without awaiting anything, which is the whole
// point: there is nothing to talk to. The port is async because a real
// store is.
#[allow(clippy::unused_async_trait_impl)]
impl BackupStore for Unwired {
    async fn take(&self, _scope: &str) -> Result<Stored, BackupError> {
        Self::refuse("keeping a backup")
    }
    async fn list(&self) -> Result<Vec<String>, BackupError> {
        Self::refuse("listing kept backups")
    }
    async fn fetch(&self, _id: &str) -> Result<Vec<u8>, BackupError> {
        Self::refuse("fetching a kept backup")
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}

/// One backup attempt, as the screen renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttemptRow {
    pub id: String,
    pub scope: String,
    pub requested_by: String,
    pub destination: String,
    pub size: Option<i64>,
    pub sha256: String,
    pub succeeded: bool,
    pub error: String,
    pub started_at: String,
}

async fn attempts_for(db: &dyn Database, account_id: &str) -> Result<Vec<AttemptRow>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT id, scope, requested_by, destination, size_bytes, sha256, succeeded, \
             error, started_at FROM backup_attempt WHERE account_id = ? \
             ORDER BY started_at DESC, id DESC",
            vec![text(account_id)],
        ))
        .await?;
    Ok(rows
        .rows
        .iter()
        .map(|row| AttemptRow {
            id: row.get("id").unwrap_or_default(),
            scope: row.get("scope").unwrap_or_default(),
            requested_by: row.get("requested_by").unwrap_or_default(),
            destination: row.get("destination").unwrap_or_default(),
            size: row.get("size_bytes"),
            sha256: row.get("sha256").unwrap_or_default(),
            succeeded: row.get::<i64>("succeeded").unwrap_or_default() != 0,
            error: row.get("error").unwrap_or_default(),
            started_at: row.get("started_at").unwrap_or_default(),
        })
        .collect())
}

async fn record_attempt(
    db: &dyn Database,
    id: &str,
    account_id: &str,
    requested_by: &str,
    outcome: &Stored,
    now: &str,
) -> Result<(), DbError> {
    db.execute(&Statement::with_values(
        "INSERT INTO backup_attempt (id, account_id, scope, requested_by, destination, \
         size_bytes, sha256, succeeded, error, started_at, finished_at) \
         VALUES (?, ?, 'control-plane', ?, ?, ?, ?, 1, '', ?, ?)",
        vec![
            text(id),
            text(account_id),
            text(requested_by),
            text(&outcome.destination),
            sea_query::Value::BigInt(Some(i64::try_from(outcome.size).unwrap_or(0))),
            text(&outcome.sha256),
            text(now),
            text(now),
        ],
    ))
    .await?;
    Ok(())
}

async fn record_failed_attempt(
    db: &dyn Database,
    id: &str,
    account_id: &str,
    requested_by: &str,
    error: &str,
    now: &str,
) -> Result<(), DbError> {
    db.execute(&Statement::with_values(
        "INSERT INTO backup_attempt (id, account_id, scope, requested_by, destination, \
         size_bytes, sha256, succeeded, error, started_at, finished_at) \
         VALUES (?, ?, 'control-plane', ?, '', NULL, '', 0, ?, ?, ?)",
        vec![
            text(id),
            text(account_id),
            text(requested_by),
            text(error),
            text(now),
            text(now),
        ],
    ))
    .await?;
    Ok(())
}

/// Runs one backup attempt for real through the port and records it
/// either way. The recording is not optional plumbing: with [`Unwired`]
/// this function's whole observable effect *is* the row — the attempt
/// happened, it failed, and the history says so.
pub(crate) async fn attempt_backup<S: BackupStore>(
    db: &dyn Database,
    account_id: &str,
    requested_by: &str,
    store: &S,
    id: &str,
    now: &str,
) -> Result<AttemptRow, DbError> {
    match store.take("control-plane").await {
        Ok(stored) => {
            record_attempt(db, id, account_id, requested_by, &stored, now).await?;
        }
        Err(err) => {
            record_failed_attempt(db, id, account_id, requested_by, &err.message, now).await?;
        }
    }
    let row = attempts_for(db, account_id)
        .await?
        .into_iter()
        .find(|row| row.id == id);
    Ok(row.expect("the row was just written"))
}

// ---------------------------------------------------------------------------
// The export: the one backup that is real today
// ---------------------------------------------------------------------------

/// Tables the export never carries, with the reason rendered on the
/// page. `fz data export` makes the first call (migration bookkeeping
/// is infrastructure, not data); the data screen's CSV made the rest
/// (key material does not belong in a file somebody keeps, ciphertext
/// without its master key is noise either way, and the audit chain is
/// both BLOB-digested — outside the portable subset this format
/// carries — and an attestation of rows this export deliberately
/// omits, so half of it here would vouch for nothing).
const SKIPPED: &[(&str, &str)] = &[
    (
        "harness_migrations",
        "migration bookkeeping, not data — `fz data export` makes the same call",
    ),
    (
        "harness_secrets",
        "sealed ciphertext, and a file somebody keeps is exactly where key material must \
         not go. Re-seal secrets into a restored control plane; the data screen's CSV \
         export makes the same call.",
    ),
    (
        "harness_secret_keys",
        "the wrapped data keys — the same reasoning as the ciphertext they protect.",
    ),
    (
        "harness_secret_audit",
        "the tamper-evident access chain: its hash columns are binary digests outside \
         the portable subset, and it attests the secret rows this export omits — a \
         chain carried without the rows it attests vouches for nothing.",
    ),
];

/// The export's shape is `fz data export`'s: one manifest line naming
/// every table with its columns, row count and sha256, then one
/// `{"table","row"}` record per row, table by table. Same field names,
/// same record spelling, so the file is verifiable with the same
/// procedure the CLI's files are — the rehearsal below is that
/// procedure.
///
/// Two deliberate differences from the CLI, both stated on the page
/// rather than hidden in the format: tables are ordered by name (a
/// module cannot read the composition's lock order, which belongs to
/// the harness — `fz data export` reads it from a compiled-in harness),
/// and three tables are omitted by name ([`SKIPPED`]).
pub(crate) struct Export {
    pub body: String,
}

pub(crate) async fn export_control_plane(db: &dyn Database) -> Result<Export, String> {
    let schema = introspect::schema(db)
        .await
        .map_err(|err| err.to_string())?;
    let skipped: Vec<&str> = SKIPPED.iter().map(|(table, _)| *table).collect();
    let mut tables: Vec<&cratefield_tables::TableDef> = schema
        .tables
        .iter()
        .filter(|table| !skipped.contains(&table.name.as_str()))
        .collect();
    tables.sort_unstable_by(|left, right| left.name.cmp(&right.name));

    // Refuse before building anything if any table is over the
    // harness-wide export cap. The manifest's row counts and hashes are
    // the file's whole claim to be a backup; a silently truncated table
    // wearing a complete manifest would be the most dangerous thing
    // this screen could produce, so an over-cap table is a refusal with
    // a direction (use `fz data export` against a database file), not a
    // short file.
    for table in &tables {
        let count = introspect::row_count(db, &table.name)
            .await
            .map_err(|err| err.to_string())?;
        if count > MAX_EXPORT_ROWS as u64 {
            return Err(format!(
                "table {} holds {} rows, over the harness export cap of {} — this export \
                 path is for the control plane's own operator-scale tables. Refusing \
                 rather than writing a manifest that lies; use `fz data export` against \
                 a database file instead.",
                table.name, count, MAX_EXPORT_ROWS
            ));
        }
    }

    let mut manifest_tables = Vec::new();
    let mut body = String::new();
    for table in &tables {
        let order_by: Vec<&str> = if table.primary_key.is_empty() {
            table
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .collect()
        } else {
            table.primary_key.iter().map(String::as_str).collect()
        };
        let mut table_bytes: Vec<u8> = Vec::new();
        let mut columns: Vec<String> = Vec::new();
        let mut written = 0_u64;
        loop {
            let page = introspect::rows(db, &table.name, &order_by, EXPORT_PAGE, written)
                .await
                .map_err(|err| format!("could not read {}: {err}", table.name))?;
            if page.is_empty() {
                break;
            }
            if columns.is_empty() {
                columns = page
                    .first()
                    .map(|row| row.column_names().map(str::to_owned).collect())
                    .unwrap_or_default();
            }
            for row in &page.rows {
                let record = record_line(&table.name, row)?;
                table_bytes.extend_from_slice(record.as_bytes());
                table_bytes.push(b'\n');
                body.push_str(&record);
                body.push('\n');
                written += 1;
            }
            if (page.len() as u64) < EXPORT_PAGE {
                break;
            }
        }
        manifest_tables.push(json!({
            "table": table.name,
            "columns": columns,
            "rows": written,
            "sha256": sha256_hex(&table_bytes),
        }));
    }
    let manifest = json!({ "tables": manifest_tables });
    let first_line = serde_json::to_string(&manifest).map_err(|err| err.to_string())?;
    Ok(Export {
        body: format!("{first_line}\n{body}"),
    })
}

/// One row as one JSONL record, keys sorted — byte-identical across
/// exports for the same data, exactly as `fz data export`'s
/// `record_line` promises (and for the same reason: the sha256 in the
/// manifest must not depend on which features `serde_json` was built
/// with).
fn record_line(table: &str, row: &cratefield_core::Row) -> Result<String, String> {
    let mut names: Vec<&str> = row.column_names().collect();
    names.sort_unstable();
    let mut object = serde_json::Map::new();
    for name in names {
        let value = row.get::<SeaValue>(name).unwrap_or(SeaValue::String(None));
        let json = sea_value_to_json(&value)
            .map_err(|problem| format!("table {table}, column {name}: {problem}"))?;
        object.insert(name.to_owned(), json);
    }
    serde_json::to_string(&json!({ "table": table, "row": object }))
        .map_err(|err| format!("cannot serialize a row: {err}"))
}

/// The portable value subset — the same one `fz data export` carries.
/// BLOBs are refused by name rather than encoded: an invented encoding
/// is a format `fz data import` cannot round-trip, and the control
/// plane's only BLOB columns are in the tables this export skips, so a
/// BLOB here means something changed under us and should stop the
/// export rather than ride along in it.
fn sea_value_to_json(value: &SeaValue) -> Result<Json, String> {
    Ok(match value {
        SeaValue::Bool(None)
        | SeaValue::TinyInt(None)
        | SeaValue::SmallInt(None)
        | SeaValue::Int(None)
        | SeaValue::BigInt(None)
        | SeaValue::Float(None)
        | SeaValue::Double(None)
        | SeaValue::String(None)
        | SeaValue::Char(None)
        | SeaValue::Bytes(None) => Json::Null,
        SeaValue::Bool(Some(v)) => Json::Bool(*v),
        SeaValue::TinyInt(Some(v)) => i64::from(*v).into(),
        SeaValue::SmallInt(Some(v)) => i64::from(*v).into(),
        SeaValue::Int(Some(v)) => i64::from(*v).into(),
        SeaValue::BigInt(Some(v)) => (*v).into(),
        SeaValue::Float(Some(v)) => Json::from(f64::from(*v)),
        SeaValue::Double(Some(v)) => Json::from(*v),
        SeaValue::String(Some(v)) => Json::String((**v).clone()),
        SeaValue::Char(Some(v)) => Json::String(v.to_string()),
        SeaValue::Bytes(Some(_)) => {
            return Err(
                "BLOB data is outside the portable subset and cannot be exported".to_owned(),
            );
        }
        // The unsigned variants never come back through the sqlite and
        // postgres adapters; a catch-all keeps this honest if one ever
        // does, instead of panicking inside a page render.
        other => Json::String(other.to_string()),
    })
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

// ---------------------------------------------------------------------------
// The rehearsal
// ---------------------------------------------------------------------------

/// One recorded rehearsal, as the screen renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RehearsalRow {
    pub id: String,
    pub attempt_id: String,
    pub rehearsed_by: String,
    pub outcome: String,
    pub rehearsed_at: String,
}

async fn rehearsals_for(db: &dyn Database, account_id: &str) -> Result<Vec<RehearsalRow>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT id, attempt_id, rehearsed_by, outcome, rehearsed_at FROM \
             restore_rehearsal WHERE account_id = ? ORDER BY rehearsed_at DESC, id DESC",
            vec![text(account_id)],
        ))
        .await?;
    Ok(rows
        .rows
        .iter()
        .map(|row| RehearsalRow {
            id: row.get("id").unwrap_or_default(),
            attempt_id: row.get("attempt_id").unwrap_or_default(),
            rehearsed_by: row.get("rehearsed_by").unwrap_or_default(),
            outcome: row.get("outcome").unwrap_or_default(),
            rehearsed_at: row.get("rehearsed_at").unwrap_or_default(),
        })
        .collect())
}

/// Records a rehearsal against an attempt of this account. The attempt
/// must be the operator's own: a rehearsal is a claim about work done,
/// and it anchors to a row nobody else can name.
pub(crate) async fn record_rehearsal(
    db: &dyn Database,
    account_id: &str,
    rehearsed_by: &str,
    attempt_id: &str,
    outcome: &str,
    id: &str,
    now: &str,
) -> Result<bool, DbError> {
    let owned = db
        .query(&Statement::with_values(
            "SELECT 1 FROM backup_attempt WHERE id = ? AND account_id = ?",
            vec![text(attempt_id), text(account_id)],
        ))
        .await?;
    if owned.first().is_none() {
        return Ok(false);
    }
    db.execute(&Statement::with_values(
        "INSERT INTO restore_rehearsal (id, account_id, attempt_id, rehearsed_by, outcome, \
         rehearsed_at) VALUES (?, ?, ?, ?, ?, ?)",
        vec![
            text(id),
            text(account_id),
            text(attempt_id),
            text(rehearsed_by),
            text(outcome),
            text(now),
        ],
    ))
    .await?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The rehearsal procedure, written out. Each step is a real command
/// that works today; the verifier is inline because a procedure that
/// depends on a script nobody shipped is a procedure nobody runs.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn procedure() -> String {
    let verifier = "python3 - file.jsonl <<'PY'\n\
import hashlib, json, sys\n\
lines = open(sys.argv[1], 'rb').read().split(b'\\n')\n\
manifest = json.loads(lines[0])\n\
body = [l for l in lines[1:] if l]\n\
pos, ok = 0, True\n\
for t in manifest['tables']:\n\
    rows = body[pos:pos + t['rows']]; pos += t['rows']\n\
    digest = hashlib.sha256(b''.join(r + b'\\n' for r in rows)).hexdigest()\n\
    good = len(rows) == t['rows'] and digest == t['sha256']\n\
    ok = ok and good\n\
    print(('ok  ' if good else 'FAIL'), t['table'], f\"{len(rows)}/{t['rows']}\")\n\
sys.exit(0 if ok and pos == len(body) else 1)\n\
PY";
    format!(
        "<ol class=\"dash__steps\">\
         <li><strong>Take an export.</strong> The button above downloads the control \
         plane's own database: a manifest line first, then one JSON record per row — \
         the same shape <code>fz data export</code> writes for a venture's database. \
         For a venture's own database, <code>fz data export</code> against the \
         database file is the equivalent step.</li>\
         <li><strong>Verify the file against its own manifest.</strong> This is the \
         restore's proof — the counts and the sha256 every table's lines must \
         reproduce — and it needs nothing but the file itself:\n\
         <pre><code>{verifier}</code></pre></li>\
         <li><strong>Read what it omitted.</strong> The manifest lists what moved; \
         the notes above list what did not and why. A restore that expects sealed \
         secrets from this file will not find them — by design.</li>\
         <li><strong>Record it below.</strong> What you ran, and what you saw. The \
         point of the record is the date: \"verified on…\" is a claim with a \
         timestamp, and its absence is visible.</li></ol>\
         <p class=\"dash__note\">This rehearsal proves the file — that what was \
         downloaded is complete, unchanged, and account-shaped. Standing a \
         replacement control plane up from it (import into a fresh database, boot \
         against it, sign in) needs import tooling for this shape and a destination \
         database, and is future work; this screen says so rather than calling a \
         verified file a tested restore.</p>",
        verifier = escape(verifier),
    )
}

/// The Time Travel card: D1's own capabilities, stated as fact. Every
/// claim here is a property of D1 that this product neither provides,
/// extends, nor manages — and the one number in it belongs to
/// Cloudflare's docs, not to this codebase.
fn time_travel_card() -> String {
    crate::card(
        "What D1's Time Travel actually gives you",
        None,
        "<p class=\"dash__note\">Every venture's database is D1, and D1 keeps its own \
         continuous backups — <strong>Time Travel</strong> — covering the last \
         <strong>30 days</strong>. That window is D1's: automatic, on by default, and \
         not something this product turns on, extends, or monitors. The figure is \
         Cloudflare's to change; their documentation is the number of record.</p>\
         <p class=\"dash__note\">What it can recover: a whole database, restored to any \
         point inside the window (<code>wrangler d1 time-travel restore</code>, or a \
         bookmark taken before a change went wrong).</p>\
         <p class=\"dash__note\">What it cannot: single rows or tables — a restore is \
         the entire database or nothing; anything older than the window; and — the \
         part that matters on this screen — anything at all <em>from here</em>: \
         reaching a venture's database needs a Deployer that does not exist yet \
         (#26), so this product cannot trigger, script, or verify a venture's Time \
         Travel restore. An operator with access to the account runs it at \
         Cloudflare directly.</p>",
        true,
    )
}

/// One attempt row. A failed attempt renders its error in full — the
/// failure you could have acted on, written down.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn render_attempts(rows: &[AttemptRow]) -> String {
    let mut out = String::from(
        "<div class=\"dash__lrow dash__lrow--backups dash__lrow--head\">\
         <span>When</span><span>What</span><span>Asked by</span><span>Where it went</span>\
         <span>Size</span><span>Verdict</span></div>",
    );
    if rows.is_empty() {
        out.push_str(
            "<p class=\"dash__empty\">No backup has been attempted yet. Pressing \
             <em>Back up now</em> runs one for real — which today means it fails \
             honestly and appears here, because no store is wired.</p>",
        );
    }
    for row in rows {
        let size = match row.size {
            Some(bytes) => format!("{bytes} bytes"),
            None => "—".to_owned(),
        };
        let verdict = if row.succeeded {
            "<span class=\"dash__dot dash__dot--live\"></span> succeeded".to_owned()
        } else {
            format!(
                "<span class=\"dash__dot dash__dot--bad\"></span> <strong>failed</strong>\
                 <br><span class=\"dash__err\">{error}</span>",
                error = escape(&row.error)
            )
        };
        out.push_str(&format!(
            "<div class=\"dash__lrow dash__lrow--backups\">\
             <span>{when}</span><span>{scope}</span><span>{who}</span>\
             <span>{went}</span><span>{size}</span><span>{verdict}</span></div>",
            when = escape(&row.started_at),
            scope = escape(&row.scope),
            who = escape(&row.requested_by),
            went = if row.destination.is_empty() {
                "<em>nowhere — it failed</em>".to_owned()
            } else {
                escape(&row.destination)
            },
            size = size,
            verdict = verdict,
        ));
    }
    out
}

/// The rehearsal form's attempt options, built with the loop the other
/// row lists use (a `map(format!()).collect()` trips two lints that
/// disagree with each other about the right shape).
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn options_html(attempts: &[AttemptRow]) -> String {
    let mut options = String::new();
    for row in attempts {
        let verdict = if row.succeeded { "succeeded" } else { "failed" };
        options.push_str(&format!(
            "<option value=\"{id}\">{when} — {verdict}</option>",
            id = escape(&row.id),
            when = escape(&row.started_at),
        ));
    }
    options
}

#[allow(clippy::format_push_string)] // the house idiom for HTML building
#[allow(clippy::too_many_lines)]
fn page(
    identity: &str,
    attempts: &[AttemptRow],
    rehearsals: &[RehearsalRow],
    observed_store: &str,
) -> Response {
    let rehearsal_status = match rehearsals.first() {
        Some(latest) => format!(
            "<p class=\"dash__row\"><span class=\"dash__dot dash__dot--live\"></span>\
             <strong>Last rehearsed {when}</strong> by {who}: {outcome}</p>",
            when = escape(&latest.rehearsed_at),
            who = escape(&latest.rehearsed_by),
            outcome = escape(&latest.outcome),
        ),
        None => "<p class=\"dash__row\"><span class=\"dash__dot dash__dot--bad\"></span>\
                 <strong>Never rehearsed.</strong> A backup that has never been restored \
                 is not a backup — it is a file with hopes. The procedure below is the \
                 one to run, and the record below it is how this screen knows you \
                 did.</p>"
            .to_owned(),
    };

    let body = format!(
        "<p class=\"dash__banner\"><span class=\"chip chip--degraded\">No backup \
         store</span><strong>No backup is kept anywhere today.</strong> Keeping one \
         needs an adapter that talks to R2, and the control plane holds no credential \
         for one (#26). <em>Back up now</em> runs the attempt for real and records the \
         refusal below — it does not pretend, and it does not read as pending.</p>\
         <p class=\"dash__note\">The store was asked, not assumed, while this page \
         rendered: {observed}</p>\
         <p class=\"dash__note\">Today you do this instead: export the control plane's \
         own database from this page — a real download, recorded below with its size \
         and sha256 — and run <code>fz data export</code> for a venture's own \
         database. D1's own Time Travel (below) is the point-in-time story in the \
         meantime.</p>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Backup attempts <span class=\"dash__tag\">{n}</span></p>\
         <div class=\"dash__list\">{attempts}</div>\
         <form method=\"post\" action=\"{PATH}/take\">\
         <div class=\"dash__act\">\
         <button class=\"btn btn--primary\" type=\"submit\">Back up now</button>\
         <a class=\"btn\" href=\"{PATH}/export\">Export the control plane's database</a>\
         </div></form>\
         <p class=\"dash__note\">Every attempt is recorded, failed ones included — a \
         backup history that only records successes is how people find out at restore \
         time. The export and a kept backup are different things and are recorded as \
         different things: the export's destination is <em>operator download</em>, \
         because the copy that leaves in your browser is the only copy there is.</p></div>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">What the export carries</p>\
         <p class=\"dash__note\">Every table of the control plane's own database, read \
         live through its database port when the export runs, in the \
         <code>fz data export</code> shape: a manifest line with per-table row counts \
         and sha256, then one JSON record per row. Tables are ordered by name; the \
         CLI's lock order belongs to the harness it is compiled into, and a module \
         reads the live catalog instead.</p>\
         <p class=\"dash__note\">Deliberately omitted: {omitted}</p></div>\
         {time_travel}\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Restore</p>{status}\
         <p class=\"dash__card-h\" style=\"margin-top:18px\">The rehearsal procedure</p>\
         {procedure}\
         <p class=\"dash__card-h\" style=\"margin-top:18px\">Record a rehearsal</p>\
         <form method=\"post\" action=\"{PATH}/rehearse\">\
         <p class=\"field\"><label for=\"rehearse-attempt\">Backup attempt</label>\
         <select id=\"rehearse-attempt\" name=\"attempt\">{options}</select></p>\
         <p class=\"field\"><label for=\"rehearse-outcome\">What you saw</label>\
         <input id=\"rehearse-outcome\" name=\"outcome\" required maxlength=\"500\" \
         autocomplete=\"off\" placeholder=\"manifest verified, 11/11 tables ok\"></p>\
         <div class=\"dash__act\">\
         <button class=\"btn\" type=\"submit\">Record the rehearsal</button></div></form>\
         <p class=\"dash__note\">Self-reported, on purpose: the rehearsal happens at a \
         terminal and against a file, not through this screen, and an honest record of \
         work done beats a button that only ever says yes. Rehearsals appear above, \
         newest first.</p></div>",
        n = attempts.len(),
        attempts = render_attempts(attempts),
        observed = observed_store,
        omitted = SKIPPED
            .iter()
            .map(|(table, why)| format!("<code>{}</code> — {}", escape(table), escape(why)))
            .collect::<Vec<_>>()
            .join("; "),
        time_travel = time_travel_card(),
        status = rehearsal_status,
        procedure = procedure(),
        options = options_html(attempts),
    );

    Html(render(&Page {
        title: "Backups",
        signed_in_as: Some(identity),
        body: &format!(
            "<div class=\"page-h\"><h1>Backups</h1></div>\
             <p class=\"lede\">What was backed up, where it went, whether it worked, \
             and whether anyone has ever proved one comes back.</p>{frame}",
            frame = frame(&account_nav("backups"), "Backups", &body),
        ),
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `/v1/dashboard/backups` — the attempt history, the export, the Time
/// Travel facts, and the rehearsal.
pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, _repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let attempts = match attempts_for(db.as_ref(), &account.id).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(error = %err, "backup attempt read failed");
            return internal("could not load the backup history");
        }
    };
    let rehearsals = match rehearsals_for(db.as_ref(), &account.id).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(error = %err, "rehearsal read failed");
            return internal("could not load the restore rehearsals");
        }
    };
    // The banner's claim about what is kept is observed, not asserted:
    // the store is asked while the page renders, the same way a venture
    // is health-checked rather than assumed live. With `Unwired` the
    // answer is the refusal itself; with a real store it will be the
    // held backups, and this line grows into that without a redesign.
    let observed_store = match Unwired.list().await {
        Ok(held) => format!(
            "the store holds {} backup(s): {}",
            held.len(),
            escape(&held.join(", "))
        ),
        // Pre-escaped HTML: the page renders this line verbatim.
        Err(err) => format!("<em>{}</em>", escape(&err.to_string())),
    };
    page(&session.account_id, &attempts, &rehearsals, &observed_store)
}

/// `/v1/dashboard/backups/take` — one backup attempt, run for real
/// through the port. The scope is the control plane's own database
/// because that is the one database it can reach; a venture's database
/// needs a Deployer (#26), and this handler does not pretend to scope
/// what it cannot touch.
pub(super) async fn take(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, _repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    if let Err(err) = attempt_backup(
        db.as_ref(),
        &account.id,
        &session.account_id,
        &Unwired,
        &ulid(ctx),
        &now_rfc3339(ctx),
    )
    .await
    {
        tracing::error!(error = %err, "backup attempt could not be recorded");
        return internal("could not record the backup attempt");
    }
    Redirect::to(PATH).into_response()
}

/// `/v1/dashboard/backups/export` — the real export: the control plane's
/// own database, read live through its database port, served as a
/// download in the `fz data export` shape and recorded as the attempt
/// it is (destination: operator download — the copy that leaves in the
/// browser is the only copy).
pub(super) async fn export(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    // Admin-gated, unlike every other screen here, because this one is
    // not account-scoped and cannot be: a backup of the control database
    // is every account's ventures, every operator's identity and the
    // whole request log, and scoping it to the asking account would
    // produce a file that is not a backup. Every other read in this
    // dashboard is narrowed to the operator's own account, so a
    // signed-in session is the wrong key for the one operation that
    // reaches past it — the same call the console's operator invite
    // makes, for the same reason.
    if let Err(problem) = cratefield_core::require_admin(&*ctx.config, &headers) {
        return problem.into_response();
    }
    // Admin-gated, unlike every other screen here, because this one is
    // not account-scoped and cannot be: a backup of the control database
    // is every account's ventures, every operator's identity and the
    // whole request log, and scoping it to the asking account would
    // produce a file that is not a backup. Every other read in this
    // dashboard is narrowed to the operator's own account, so a
    // signed-in session is the wrong key for the one operation that
    // reaches past it — the same call the console's operator invite
    // makes, for the same reason.
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, _repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let export = match export_control_plane(db.as_ref()).await {
        Ok(export) => export,
        Err(err) => {
            tracing::error!(error = %err, "control-plane export refused");
            return (StatusCode::CONFLICT, err).into_response();
        }
    };
    let now = now_rfc3339(ctx);
    let stored = Stored {
        destination: "operator download".to_owned(),
        size: export.body.len() as u64,
        sha256: sha256_hex(export.body.as_bytes()),
    };
    if let Err(err) = record_attempt(
        db.as_ref(),
        &ulid(ctx),
        &account.id,
        &session.account_id,
        &stored,
        &now,
    )
    .await
    {
        tracing::error!(error = %err, "export could not be recorded");
        return internal("the export was built but could not be recorded");
    }

    let mut response = Response::new(axum::body::Body::from(export.body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/x-ndjson; charset=utf-8"),
    );
    let disposition = format!(
        "attachment; filename=\"control-plane-export-{}.jsonl\"",
        ulid(ctx)
    );
    if let Ok(value) = header::HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

/// `/v1/dashboard/backups/rehearse` — records that a restore was
/// rehearsed, against one of this account's own attempts, in the
/// operator's own words.
pub(super) async fn rehearse(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, _repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let attempt = form
        .iter()
        .find(|(key, _)| key == "attempt")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    let outcome = form
        .iter()
        .find(|(key, _)| key == "outcome")
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_default();
    if attempt.is_empty() || outcome.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "the rehearsal needs an attempt and what you saw",
        )
            .into_response();
    }
    match record_rehearsal(
        db.as_ref(),
        &account.id,
        &session.account_id,
        &attempt,
        &outcome,
        &ulid(ctx),
        &now_rfc3339(ctx),
    )
    .await
    {
        // An attempt that is not this account's is indistinguishable
        // from one that does not exist, on purpose.
        Ok(false) => (StatusCode::NOT_FOUND, "no such backup attempt").into_response(),
        Ok(true) => Redirect::to(PATH).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "rehearsal write failed");
            internal("could not record the rehearsal")
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unused_async_trait_impl)] // the sync test fakes implement an async port
    use super::*;
    use crate::Dashboard;
    use cratefield_access::{DEFAULT_TTL_SECS, issue_session};
    use cratefield_accounts::Repository;
    use cratefield_adapter_sqlite::SqliteDatabase;
    use cratefield_testing::TestHarness;
    use http::{Method, Request as HttpRequest};
    use tower::util::ServiceExt;

    const EMAIL: &str = "op@cratefield.com";
    const NOW: u64 = 1_800_000_000;

    /// The admin token this crate's tests present for the export, which
    /// is the one operation here that reaches past the asking account.
    const ADMIN: &str = "test-admin-token";

    fn kit() -> TestHarness {
        TestHarness::with_ports(
            vec![
                Box::new(cratefield_console::Console),
                Box::new(Dashboard::new(None)),
            ],
            |ports| {
                ports.config = std::sync::Arc::new(cratefield_core::MapConfig::from_pairs(vec![
                    ("HARNESS_SECRET", cratefield_testing::TEST_HARNESS_SECRET),
                    ("ADMIN_TOKEN", ADMIN),
                ]));
            },
        )
    }

    /// The export, presented with the admin bearer `require_admin`
    /// wants — the one route here a session alone does not open.
    async fn export_as_admin(kit: &TestHarness, cookie: &str) -> Reply {
        let request = HttpRequest::builder()
            .method(Method::GET)
            .uri(format!("{PATH}/export"))
            .header(http::header::COOKIE, cookie)
            .header(http::header::AUTHORIZATION, format!("Bearer {ADMIN}"))
            .body(axum::body::Body::empty())
            .expect("request");
        reply_of(kit, request).await
    }

    fn cookie(kit: &TestHarness) -> String {
        let token = issue_session(kit.signer.as_ref(), EMAIL, NOW, DEFAULT_TTL_SECS);
        format!("cf_session={token}")
    }

    async fn seeded() -> TestHarness {
        let kit = kit();
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .expect("account");
        repo.create_venture(
            "v1",
            "acc_1",
            "my-app",
            "my-app.cratefield.app",
            "cms",
            "ten_1",
            "t0",
        )
        .await
        .expect("venture");
        kit
    }

    struct Reply {
        status: StatusCode,
        location: String,
        content_type: Option<String>,
        body: String,
    }

    async fn send(
        kit: &TestHarness,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        form: Option<&str>,
    ) -> Reply {
        let mut builder = HttpRequest::builder().method(method).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(http::header::COOKIE, cookie);
        }
        let body = match form {
            Some(form) => {
                builder = builder.header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                );
                axum::body::Body::from(form.to_owned())
            }
            None => axum::body::Body::empty(),
        };
        reply_of(kit, builder.body(body).expect("request")).await
    }

    /// Runs one request through the router and reads the whole reply.
    async fn reply_of(kit: &TestHarness, request: HttpRequest<axum::body::Body>) -> Reply {
        let response = kit
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router answers");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 8 * 1024 * 1024)
            .await
            .expect("body");
        Reply {
            status: parts.status,
            location: parts
                .headers
                .get(http::header::LOCATION)
                .map(|value| value.to_str().unwrap().to_owned())
                .unwrap_or_default(),
            content_type: parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
        }
    }

    /// A store that succeeds, for the flow tests: the same shape the
    /// provisioning crate's `FakeDeployer` has.
    struct FakeStore {
        destination: &'static str,
    }

    impl BackupStore for FakeStore {
        async fn take(&self, _scope: &str) -> Result<Stored, BackupError> {
            Ok(Stored {
                destination: self.destination.to_owned(),
                size: 1234,
                sha256: "ab".repeat(32),
            })
        }
        async fn list(&self) -> Result<Vec<String>, BackupError> {
            Ok(vec!["b1".to_owned()])
        }
        async fn fetch(&self, id: &str) -> Result<Vec<u8>, BackupError> {
            Ok(id.as_bytes().to_vec())
        }
    }

    #[pollster::test]
    async fn a_succeeding_store_records_where_the_backup_went() {
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("accounts", &[cratefield_accounts::MIGRATION])
            .expect("accounts schema");
        db.apply_migrations("dashboard", &[MIGRATION])
            .expect("backups schema");
        let db: Arc<dyn Database> = Arc::new(db);

        let row = attempt_backup(
            db.as_ref(),
            "acc_1",
            EMAIL,
            &FakeStore {
                destination: "r2://backups/2026/b1",
            },
            "b1",
            "t1",
        )
        .await
        .expect("recorded");
        assert!(row.succeeded);
        assert_eq!(row.destination, "r2://backups/2026/b1");
        assert_eq!(row.size, Some(1234));
        assert_eq!(row.error, "");

        // The port's other two calls are part of the contract a restore
        // needs; nothing calls them from a handler today (nothing is
        // kept), so they are proven here against the fake.
        let store = FakeStore {
            destination: "r2://backups/2026/b1",
        };
        assert_eq!(store.list().await.expect("held"), vec!["b1".to_owned()]);
        assert_eq!(store.fetch("b1").await.expect("bytes"), b"b1".to_vec());
    }

    #[pollster::test]
    async fn the_unwired_store_refuses_and_the_attempt_is_a_failed_row() {
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("dashboard", &[MIGRATION])
            .expect("backups schema");
        let db: Arc<dyn Database> = Arc::new(db);

        let row = attempt_backup(db.as_ref(), "acc_1", EMAIL, &Unwired, "b1", "t1")
            .await
            .expect("the attempt is recorded");
        assert!(!row.succeeded, "a refusal is not a success");
        assert_eq!(row.destination, "", "nothing was kept anywhere");
        assert_eq!(row.size, None, "and nothing was produced");
        assert!(
            row.error.contains("no backup store is wired"),
            "the refusal is recorded verbatim: {}",
            row.error
        );
        assert!(row.error.contains("#26"), "{}", row.error);
    }

    #[pollster::test]
    async fn a_signed_in_operator_alone_cannot_export_the_control_database() {
        // Every other read in this dashboard is narrowed to the asking
        // account. This one cannot be — a backup of the control database
        // is every account's ventures, every operator's identity and the
        // whole request log — so a session is the wrong key for it, and
        // it takes the same admin token the console's operator invite
        // takes.
        let kit = seeded().await;
        let cookie = cookie(&kit);

        let refused = send(
            &kit,
            Method::GET,
            &format!("{PATH}/export"),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::UNAUTHORIZED,
            "a session alone must not export the control database: {}",
            refused.body
        );
        assert!(
            !refused.body.contains("\"table\""),
            "the refusal carries no export: {}",
            refused.body
        );

        // The positive half, so the refusal above cannot be passing
        // because the route is broken: the same request with the admin
        // token returns the real file.
        let allowed = export_as_admin(&kit, &cookie).await;
        assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.body);
        assert!(
            allowed.body.contains("\"table\":\"account\""),
            "{}",
            allowed.body
        );
    }

    #[pollster::test]
    async fn the_export_is_real_and_records_itself() {
        let kit = seeded().await;
        let cookie = cookie(&kit);
        let reply = export_as_admin(&kit, &cookie).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(
            reply.content_type.as_deref(),
            Some("application/x-ndjson; charset=utf-8")
        );

        // The file: a manifest line that names real tables with real
        // counts and hashes, then the rows themselves.
        let first_line = reply.body.lines().next().expect("manifest line");
        let manifest: Json = serde_json::from_str(first_line).expect("manifest is JSON");
        let tables = manifest["tables"].as_array().expect("tables");
        let names: Vec<&str> = tables
            .iter()
            .map(|entry| entry["table"].as_str().expect("name"))
            .collect();
        for expected in ["account", "venture", "backup_attempt"] {
            assert!(
                names.contains(&expected),
                "the export carries {expected}: {names:?}"
            );
        }
        for omitted in [
            "harness_migrations",
            "harness_secrets",
            "harness_secret_keys",
            "harness_secret_audit",
        ] {
            assert!(
                !names.contains(&omitted),
                "the export must omit {omitted}: {names:?}"
            );
        }
        // Name order, stated on the page.
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "tables are ordered by name");

        // The rows really are in the file: the seeded account and
        // venture, spelled out as records.
        assert!(
            reply.body.contains("\"op@cratefield.com\""),
            "the seeded operator's row is in the export: {}",
            &reply.body[..reply.body.len().min(600)]
        );
        assert!(reply.body.contains("my-app.cratefield.app"), "venture row");

        // Every table's sha256 is the hash of exactly its own lines —
        // the manifest is the verification, so it must verify. This is
        // the rehearsal procedure, run by the test.
        let mut lines: Vec<&str> = reply.body.split('\n').collect();
        if lines.last() == Some(&"") {
            lines.pop();
        }
        let records: Vec<&str> = lines[1..].to_vec();
        let mut cursor = 0_usize;
        for entry in tables {
            let count = usize::try_from(entry["rows"].as_u64().expect("count")).expect("rows");
            let slice = &records[cursor..cursor + count];
            cursor += count;
            let mut hashed = Vec::new();
            for line in slice {
                hashed.extend_from_slice(line.as_bytes());
                hashed.push(b'\n');
            }
            assert_eq!(
                entry["sha256"].as_str().expect("sha"),
                sha256_hex(&hashed),
                "table {} verifies",
                entry["table"]
            );
            for line in slice {
                let record: Json = serde_json::from_str(line).expect("record");
                assert_eq!(
                    record["table"].as_str().expect("table"),
                    entry["table"].as_str().expect("name")
                );
            }
        }
        assert_eq!(
            cursor,
            records.len(),
            "no stray records after the last table"
        );

        // The attempt it recorded: succeeded, honestly destinationed,
        // with the size and sha of the very bytes served.
        let rows = attempts_for(kit.db.as_ref(), "acc_1").await.expect("rows");
        assert_eq!(rows.len(), 1, "one export, one row");
        let row = &rows[0];
        assert!(row.succeeded);
        assert_eq!(row.destination, "operator download");
        assert_eq!(
            row.size,
            Some(i64::try_from(reply.body.len()).expect("size fits")),
            "the recorded size is the served size"
        );
        assert_eq!(row.sha256, sha256_hex(reply.body.as_bytes()));
    }

    #[pollster::test]
    async fn a_table_over_the_export_cap_is_a_refusal_not_a_short_file() {
        let kit = seeded().await;
        // One table pushed past the harness-wide cap. Batched inserts:
        // sqlite's bind limit is real and so is the test's patience.
        let mut written = 0;
        while written < MAX_EXPORT_ROWS + 1 {
            let chunk: Vec<String> = (0..250)
                .map(|n| {
                    format!(
                        "('over-cap-{}', 'email', 'cap test', 'op', 't0')",
                        written + n
                    )
                })
                .collect();
            kit.db
                .execute(&Statement::new(format!(
                    "INSERT INTO allowlist (value, kind, note, added_by, added_at) \
                     VALUES {}",
                    chunk.join(", ")
                )))
                .await
                .expect("seed");
            written += 250;
        }
        let reply = export_as_admin(&kit, &cookie(&kit)).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
        assert!(
            reply.body.contains("over the harness export cap"),
            "{}",
            reply.body
        );
        assert!(
            reply.body.contains("fz data export"),
            "the refusal points somewhere real: {}",
            reply.body
        );
        // And nothing was recorded: a refused export is not an attempt.
        let rows = attempts_for(kit.db.as_ref(), "acc_1").await.expect("rows");
        assert!(rows.is_empty());
    }

    #[pollster::test]
    async fn the_screen_says_what_is_real_what_is_not_and_never_rehearsed() {
        let kit = seeded().await;
        let cookie = cookie(&kit);
        let reply = send(&kit, Method::GET, PATH, Some(&cookie), None).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

        // The honest no-store state, in so many words.
        assert!(
            reply.body.contains("No backup is kept anywhere today"),
            "{}",
            reply.body
        );
        assert!(reply.body.contains("#26"), "{}", reply.body);
        assert!(
            reply.body.contains("Today you do this instead:"),
            "{}",
            reply.body
        );
        // The Time Travel facts, as facts.
        assert!(reply.body.contains("Time Travel"), "{}", reply.body);
        assert!(reply.body.contains("30"), "{}", reply.body);
        assert!(
            reply
                .body
                .contains("not something this product turns on, extends, or monitors"),
            "{}",
            reply.body
        );
        assert!(
            reply
                .body
                .contains("a restore is the entire database or nothing"),
            "{}",
            reply.body
        );
        // The restore path.
        assert!(
            reply.body.contains("Never rehearsed."),
            "the empty rehearsal state must say so plainly: {}",
            reply.body
        );
        assert!(
            reply
                .body
                .contains("A backup that has never been restored is not a backup"),
            "{}",
            reply.body
        );
        // The planned page is gone.
        assert!(!reply.body.contains("Not built."), "{}", reply.body);
    }

    #[pollster::test]
    async fn taking_a_backup_through_the_screen_records_the_failed_attempt() {
        let kit = seeded().await;
        let cookie = cookie(&kit);
        let reply = send(
            &kit,
            Method::POST,
            &format!("{PATH}/take"),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_eq!(reply.location, PATH);

        let page = send(&kit, Method::GET, PATH, Some(&cookie), None).await;
        assert!(
            page.body.contains("no backup store is wired"),
            "the recorded refusal is on the page: {}",
            page.body
        );
        assert!(page.body.contains("failed"), "{}", page.body);

        let rows = attempts_for(kit.db.as_ref(), "acc_1").await.expect("rows");
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].succeeded);
        // The attempt is scoped: another account sees none of it.
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login("b@x.co", "B", "acc_2", "t0")
            .await
            .expect("account");
        let theirs = attempts_for(kit.db.as_ref(), "acc_2").await.expect("rows");
        assert!(
            theirs.is_empty(),
            "one account's attempts are not another's"
        );
    }

    #[pollster::test]
    async fn a_rehearsal_can_be_recorded_and_changes_what_the_page_says() {
        let kit = seeded().await;
        let cookie = cookie(&kit);
        // Something to rehearse against: take the real export first.
        export_as_admin(&kit, &cookie).await;
        let attempts = attempts_for(kit.db.as_ref(), "acc_1").await.expect("rows");
        let attempt = attempts[0].id.clone();

        let reply = send(
            &kit,
            Method::POST,
            &format!("{PATH}/rehearse"),
            Some(&cookie),
            Some(&format!(
                "attempt={attempt}&outcome=manifest verified, all tables ok"
            )),
        )
        .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);

        let page = send(&kit, Method::GET, PATH, Some(&cookie), None).await;
        assert!(
            !page.body.contains("Never rehearsed."),
            "a recorded rehearsal replaces the empty state: {}",
            page.body
        );
        assert!(page.body.contains("Last rehearsed"), "{}", page.body);
        assert!(
            page.body.contains("manifest verified, all tables ok"),
            "the operator's own words, verbatim: {}",
            page.body
        );

        // An attempt that is not this account's is a 404, not a
        // rehearsal against a stranger's backup.
        let token = issue_session(kit.signer.as_ref(), "b@x.co", NOW, DEFAULT_TTL_SECS);
        let stranger = format!("cf_session={token}");
        let reply = send(
            &kit,
            Method::POST,
            &format!("{PATH}/rehearse"),
            Some(&stranger),
            Some(&format!("attempt={attempt}&outcome=no")),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);

        // And an empty outcome never records.
        let reply = send(
            &kit,
            Method::POST,
            &format!("{PATH}/rehearse"),
            Some(&cookie),
            Some(&format!("attempt={attempt}&outcome=")),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    }

    #[pollster::test]
    async fn an_unauthenticated_request_is_redirected_to_the_login_gate() {
        let kit = seeded().await;
        for uri in [PATH.to_owned(), format!("{PATH}/export")] {
            let reply = send(&kit, Method::GET, &uri, None, None).await;
            assert_eq!(reply.status, StatusCode::SEE_OTHER);
            assert_eq!(reply.location, "/v1/console/login");
        }
        // A parseable body, so the form extractor lets the request
        // reach the guard, which is what is under test.
        let reply = send(
            &kit,
            Method::POST,
            &format!("{PATH}/take"),
            None,
            Some("x=1"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert_eq!(reply.location, "/v1/console/login");
    }
}
