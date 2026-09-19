//! The issue #438 canary: drives the real compiled
//! `cratefield_runtime_cloudflare::D1Database` adapter against a live D1
//! binding under workerd (miniflare), and answers with HTTP 500 when a BLOB
//! round trip loses a byte. One route per byte-bearing production path:
//!
//! - `POST /blob` — an explicit bind/read of the hostile payload (so the
//!   node harness gets a byte-level verdict: expected vs got hex), plus the
//!   NULL-blob read assertion from the conformance kit's blob contract.
//! - `POST /session` — auth-core's `insert_session` /
//!   `session_by_token_hash`: the cookie path binds `token_hash` as
//!   `Vec<u8>` (`crates/auth-core/src/store.rs`).
//! - `POST /secrets` — `Secrets::put` then `Secrets::get`: nonce,
//!   ciphertext and the wrapped DEK all bind as bytes.
//!
//! The migrations applied here are the real ones (`crates/auth-core/
//! migrations/sqlite/0001_init.sql` plus `0003_token_issuing.sql`;
//! `crates/secrets/migrations/sqlite/0001_init.sql` plus the audit chain
//! from `0002_audit.sql`, its store attribution from
//! `0003_audit_store.sql`, and the store-attribution rebuild from
//! `0004_store_attribution.sql`) — not a reimplementation of the schema.
//!
//! The node harness `run.mjs` boots miniflare and asserts every route
//! returns 200; a non-200 there is the canary's failure signal.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cratefield_core::{Database, Statement};
use cratefield_kms::{Dek, Kms, KmsError};
use cratefield_runtime_cloudflare::D1Database;
use cratefield_secrets::{Actor, SecretBytes, Secrets};
use factory0_auth_core::{
    insert_session, insert_user, session_by_token_hash, Redacted, SessionRow, UserRow,
    STATUS_ACTIVE,
};
use serde_json::{json, Value as Json};
use worker::{Context, Env, Method, Request, Response};

/// Bytes that die in any text-encoding hop: a NUL (truncation bait), 0xFF
/// and 0xFE (invalid UTF-8 anywhere), a stray continuation byte 0x80, the
/// broken pair 0xC3 0x28, and a newline (trim bait). Eleven bytes — not a
/// multiple of three, so a base64 hop would leave padding artefacts. The
/// same payload the conformance kit's blob contract binds.
const HOSTILE: &[u8] = &[
    0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x80, 0xFE, 0xC3, 0x28, 0x0A,
];

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Strips `--` line comments, then splits on `;`. Plain DDL survives both
/// steps; the semicolons inside 0001's column comments do not, which is
/// why comments go first. A `BEGIN ... END` trigger body (the secrets
/// audit chain's append-only enforcement in 0002) is kept whole: while a
/// `BEGIN` is open the split is suppressed, so the trigger's interior
/// semicolon does not cut the `CREATE TRIGGER` in half.
fn statements(sql: &str) -> Vec<Statement> {
    fn count_word(text: &str, word: &str) -> usize {
        text.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|piece| piece.eq_ignore_ascii_case(word))
            .count()
    }
    let stripped = sql
        .lines()
        .map(|line| match line.find("--") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut out = Vec::new();
    let mut pending = String::new();
    for fragment in stripped.split(';') {
        pending.push_str(fragment);
        if count_word(&pending, "BEGIN") > count_word(&pending, "END") {
            pending.push_str("; "); // the semicolon separated trigger-body statements
            continue;
        }
        let stmt = pending.trim();
        if !stmt.is_empty() {
            out.push(Statement::new(stmt));
        }
        pending.clear();
    }
    let stmt = pending.trim();
    if !stmt.is_empty() {
        out.push(Statement::new(stmt));
    }
    out
}

/// The auth-core schema (0001 plus 0003's `amr` column and token-table
/// rebuild) and the secrets schema (0001, the audit chain from 0002 plus
/// its store attribution from 0003, and the store-attribution rebuild
/// from 0004) — applied once per isolate through the adapter's own atomic
/// batch. `Secrets::put`/`get` refuse without the audit chain
/// (`NotAudited`), so 0002/0003 are as load-bearing here as 0001.
async fn migrate(db: &dyn Database) -> Result<(), Json> {
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.load(Ordering::Relaxed) {
        return Ok(());
    }
    let mut stmts = Vec::new();
    stmts.extend(statements(include_str!(
        "../../../crates/auth-core/migrations/sqlite/0001_init.sql"
    )));
    stmts.extend(statements(include_str!(
        "../../../crates/auth-core/migrations/sqlite/0003_token_issuing.sql"
    )));
    stmts.extend(statements(include_str!(
        "../../../crates/secrets/migrations/sqlite/0001_init.sql"
    )));
    stmts.extend(statements(include_str!(
        "../../../crates/secrets/migrations/sqlite/0002_audit.sql"
    )));
    stmts.extend(statements(include_str!(
        "../../../crates/secrets/migrations/sqlite/0003_audit_store.sql"
    )));
    stmts.extend(statements(include_str!(
        "../../../crates/secrets/migrations/sqlite/0004_store_attribution.sql"
    )));
    db.batch_atomic(&stmts)
        .await
        .map_err(|err| json!({ "ok": false, "stage": "migrate", "error": err.to_string() }))?;
    DONE.store(true, Ordering::Relaxed);
    Ok(())
}

async fn d1(env: Env) -> Result<D1Database, Json> {
    let binding = env
        .d1("DB")
        .map_err(|err| json!({ "ok": false, "stage": "binding", "error": err.to_string() }))?;
    Ok(D1Database(binding))
}

/// P1: the shared conformance contract plus an explicit hostile bind whose
/// verdict the harness can print byte for byte.
async fn blob(env: Env) -> Result<Json, Json> {
    let db = d1(env).await?;
    migrate(&db).await?;

    db.execute(&Statement::new(
        "CREATE TABLE IF NOT EXISTS blob_canary \
         (id INTEGER PRIMARY KEY, payload BLOB)",
    ))
    .await
    .map_err(
        |err| json!({ "ok": false, "stage": "create blob_canary", "error": err.to_string() }),
    )?;
    db.execute(&Statement::new("DELETE FROM blob_canary"))
        .await
        .map_err(
            |err| json!({ "ok": false, "stage": "clear blob_canary", "error": err.to_string() }),
        )?;

    db.execute(&Statement::with_values(
        "INSERT INTO blob_canary (id, payload) VALUES (?, ?)",
        vec![1_i32.into(), HOSTILE.to_vec().into()],
    ))
    .await
    .map_err(|err| json!({ "ok": false, "stage": "bind bytes", "error": err.to_string() }))?;

    let rows = db
        .query(&Statement::with_values(
            "SELECT payload FROM blob_canary WHERE id = ?",
            vec![1_i32.into()],
        ))
        .await
        .map_err(|err| json!({ "ok": false, "stage": "read bytes", "error": err.to_string() }))?;
    let row = rows.first().ok_or_else(
        || json!({ "ok": false, "stage": "read bytes", "error": "no row came back" }),
    )?;
    let got: Option<Vec<u8>> = row.get("payload");
    if got.as_deref() != Some(HOSTILE) {
        return Err(json!({
            "ok": false,
            "stage": "blob byte compare",
            "expected_hex": hex(HOSTILE),
            "got": got.map(|bytes| hex(&bytes)).unwrap_or_else(|| "null".to_owned()),
        }));
    }

    // The NULL-blob half of `cratefield_testing::assert_blob_round_trips`
    // (the crate is not depended on here: its workspace dependency entry
    // defaults `default-features = true`, which workspace inheritance ORs
    // past a member's `false`, dragging the bundled-SQLite wasm adapter —
    // a C build — into this graph). The assertion is byte for byte the
    // kit's: a NULL blob reads back as no bytes, not as empty or garbage.
    db.execute(&Statement::with_values(
        "INSERT INTO blob_canary (id, payload) VALUES (?, ?)",
        vec![2_i32.into(), None::<Vec<u8>>.into()],
    ))
    .await
    .map_err(|err| json!({ "ok": false, "stage": "bind NULL blob", "error": err.to_string() }))?;
    let nulled = db
        .query(&Statement::with_values(
            "SELECT payload FROM blob_canary WHERE id = ?",
            vec![2_i32.into()],
        ))
        .await
        .map_err(
            |err| json!({ "ok": false, "stage": "read NULL blob", "error": err.to_string() }),
        )?;
    let nulled_row = nulled.first().ok_or_else(
        || json!({ "ok": false, "stage": "read NULL blob", "error": "no row came back" }),
    )?;
    let nulled_got: Option<Vec<u8>> = nulled_row.get("payload");
    if nulled_got.is_some() {
        return Err(json!({
            "ok": false,
            "stage": "NULL blob compare",
            "error": "a NULL blob read back as bytes",
            "got": nulled_got.map(|bytes| hex(&bytes)),
        }));
    }

    Ok(json!({
        "ok": true,
        "path": "D1Database bind/read + assert_blob_round_trips",
        "payload_hex": hex(HOSTILE),
    }))
}

/// P2: the auth-core cookie path. `token_hash` binds as `Vec<u8>`; a text
/// hop anywhere between the adapter and workerd's D1 loses bytes the way
/// the blob route above catches.
async fn session(env: Env) -> Result<Json, Json> {
    let db = d1(env).await?;
    migrate(&db).await?;

    // Fixed ids so the route is rerunnable against a warm database.
    let _ = db
        .execute(&Statement::new(
            "DELETE FROM sessions WHERE id = 'canary-session'",
        ))
        .await;
    let _ = db
        .execute(&Statement::new(
            "DELETE FROM users WHERE id = 'canary-user'",
        ))
        .await;

    let user = UserRow {
        id: "canary-user".to_owned(),
        display_name: None,
        primary_email: Some("canary@d1-blob-canary.invalid".to_owned()),
        primary_email_verified: true,
        status: STATUS_ACTIVE.to_owned(),
        created_at: "2026-09-19T00:00:00Z".to_owned(),
        updated_at: "2026-09-19T00:00:00Z".to_owned(),
    };
    insert_user(&db, &user)
        .await
        .map_err(|err| json!({ "ok": false, "stage": "insert_user", "error": err.to_string() }))?;

    let row = SessionRow {
        id: "canary-session".to_owned(),
        user_id: user.id.clone(),
        token_hash: Redacted(HOSTILE.to_vec()),
        created_at: "2026-09-19T00:00:00Z".to_owned(),
        last_seen_at: "2026-09-19T00:00:00Z".to_owned(),
        expires_at: "2026-10-19T00:00:00Z".to_owned(),
        revoked_at: None,
        ip_hash: None,
        ua_family: Some("canary".to_owned()),
        amr: Some(r#"["password"]"#.to_owned()),
    };
    insert_session(&db, &row).await.map_err(
        |err| json!({ "ok": false, "stage": "insert_session", "error": err.to_string() }),
    )?;

    let found = session_by_token_hash(&db, HOSTILE)
        .await
        .map_err(|err| {
            json!({ "ok": false, "stage": "session_by_token_hash", "error": err.to_string() })
        })?
        .ok_or_else(|| {
            json!({
                "ok": false,
                "stage": "session_by_token_hash",
                "error": "the lookup by the bound bytes found no row",
            })
        })?;
    if found.token_hash.0 != HOSTILE {
        return Err(json!({
            "ok": false,
            "stage": "session token_hash compare",
            "expected_hex": hex(HOSTILE),
            "got_hex": hex(&found.token_hash.0),
        }));
    }
    if found.amr.as_deref() != Some(r#"["password"]"#) {
        return Err(json!({
            "ok": false,
            "stage": "session amr compare",
            "expected": r#"["password"]"#,
            "got": found.amr,
        }));
    }

    Ok(json!({
        "ok": true,
        "path": "auth-core insert_session / session_by_token_hash",
        "token_hash_hex": hex(HOSTILE),
        "amr": found.amr,
    }))
}

/// A canary stand-in for the KMS, not a KMS: wrap is the identity so the
/// run stays reproducible. Every byte the secrets store writes (wrapped
/// DEK, nonce, ciphertext) still crosses the D1 BLOB bind path for real.
struct CanaryKms;

#[async_trait::async_trait]
impl Kms for CanaryKms {
    fn provider(&self) -> &'static str {
        "canary-static"
    }

    fn key_ref(&self) -> &str {
        "canary/master"
    }

    async fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, KmsError> {
        Ok(dek.expose().to_vec())
    }

    async fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, KmsError> {
        Dek::from_bytes(wrapped.to_vec())
    }
}

/// P3: `Secrets::put` then `get`. Nonce and ciphertext bind as bytes; if
/// the round trip loses one, XChaCha20Poly1305 refuses to authenticate and
/// the read returns `NotAuthentic` rather than the plaintext.
async fn secrets(env: Env) -> Result<Json, Json> {
    let db = d1(env).await?;
    migrate(&db).await?;

    let store = Secrets::new(Arc::new(CanaryKms)).tenant("canary-tenant", Arc::new(db));
    let actor = Actor::new("d1-blob-canary")
        .map_err(|err| json!({ "ok": false, "stage": "Actor::new", "error": err.to_string() }))?;

    let payload = SecretBytes::new(HOSTILE.to_vec());
    let version = store
        .put("canary/blob", &payload, &actor)
        .await
        .map_err(|err| json!({ "ok": false, "stage": "Secrets::put", "error": err.to_string() }))?;
    let got = store
        .get("canary/blob", &actor)
        .await
        .map_err(|err| json!({ "ok": false, "stage": "Secrets::get", "error": err.to_string() }))?
        .ok_or_else(|| {
            json!({ "ok": false, "stage": "Secrets::get", "error": "get returned None after put" })
        })?;
    if got.expose() != HOSTILE {
        return Err(json!({
            "ok": false,
            "stage": "secrets plaintext compare",
            "expected_hex": hex(HOSTILE),
            "got_hex": hex(got.expose()),
        }));
    }

    Ok(json!({
        "ok": true,
        "path": "Secrets::put / Secrets::get",
        "version": version,
        "plaintext_hex": hex(HOSTILE),
    }))
}

#[worker::event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    let get = req.method() == Method::Get;
    let body = match req.path().as_str() {
        "/health" if get => Ok(json!({ "ok": true, "worker": "d1-blob-canary" })),
        "/blob" if !get => blob(env).await,
        "/session" if !get => session(env).await,
        "/secrets" if !get => secrets(env).await,
        _ => Err(json!({ "ok": false, "error": "not found" })),
    };
    match body {
        Ok(value) => Response::from_json(&value),
        // Every canary failure is a 500 whose body names the stage and
        // carries the expected/got hex — what `run.mjs` prints verbatim.
        Err(value) => Ok(Response::from_json(&value)?.with_status(500)),
    }
}
