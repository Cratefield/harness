//! Behaviour tests for `cratefield_core::ApiKeys` (issue #532) against a
//! real SQLite database: the round trip from issue to verify, what is
//! stored (a hash, never the secret), revocation, rotation, the scope
//! gate and the throttled last-used touch.

use axum::http::{HeaderMap, header};
use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{
    ApiKeyError, ApiKeyMode, ApiKeys, Clock, Database, IssuedKey, RandomBytes, RandomError, Row,
    Statement, SystemClock, require_api_key,
};
use sea_query::{Alias, Expr, Query};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// A deterministic entropy source: an advancing, obviously-fake byte
/// pattern, so issued keys are stable and assertions can be exact — and
/// successive draws differ, the way a real CSPRNG's do.
struct Cycle(std::sync::atomic::AtomicUsize);

impl RandomBytes for Cycle {
    fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        use std::sync::atomic::Ordering;
        let start = self.0.fetch_add(dest.len(), Ordering::Relaxed);
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = u8::try_from((start + index) % 251).expect("mod 251 fits a u8");
        }
        Ok(())
    }
}

fn rng() -> Arc<dyn RandomBytes> {
    Arc::new(Cycle(std::sync::atomic::AtomicUsize::new(0)))
}

/// A clock the test drives, so the last-used touch window can be
/// observed without waiting.
struct FixedClock {
    // Test-fixture time travel, not request state; the scoped allow
    // follows the policy in clippy.toml (interior mutability for fakes).
    #[allow(clippy::disallowed_types)]
    now: std::sync::Mutex<OffsetDateTime>,
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        *self.now.lock().expect("clock lock uncontended")
    }
}

const NOW: &str = "2026-09-27T12:00:00Z";

/// A fresh store over its own in-memory database, table included.
fn db() -> (Arc<SqliteDatabase>, ApiKeys) {
    db_with_clock(Arc::new(SystemClock))
}

fn db_with_clock(clock: Arc<dyn Clock>) -> (Arc<SqliteDatabase>, ApiKeys) {
    let db = Arc::new(SqliteDatabase::in_memory().expect("in-memory sqlite"));
    let store = ApiKeys::new(db.clone(), clock, rng(), "api_keys");
    pollster::block_on(db.execute(&Statement::new(store.create_table_sql())))
        .expect("create api_keys table");
    (db, store)
}

/// The canonical test key: `pos` speaks for `acct_123`.
async fn key_for(store: &ApiKeys, scopes: &[&str], mode: ApiKeyMode) -> IssuedKey {
    store
        .issue("pos", "acct_123", scopes, mode)
        .await
        .expect("issue")
}

fn bearer(token: &str) -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert(
        header::AUTHORIZATION,
        header::HeaderValue::from_str(&format!("Bearer {token}")).expect("header builds"),
    );
    map
}

/// The full stored row for a prefix, read through sea-query so nothing
/// is interpolated into SQL.
async fn stored_row(db: &SqliteDatabase, prefix: &str) -> Row {
    let columns = [
        "prefix",
        "secret_hash",
        "namespace",
        "subject",
        "scopes",
        "mode",
        "created_at",
        "last_used_at",
        "revoked_at",
    ];
    let mut select = Query::select();
    select
        .columns(columns)
        .from(Alias::new("api_keys"))
        .and_where(Expr::col(Alias::new("prefix")).eq(prefix));
    let rows = db
        .query(&Statement::render(&select))
        .await
        .expect("row reads");
    assert_eq!(rows.len(), 1, "exactly one row for {prefix}");
    rows.rows.into_iter().next().expect("one row")
}

async fn last_used(db: &SqliteDatabase, prefix: &str) -> Option<String> {
    stored_row(db, prefix).await.get("last_used_at").flatten()
}

/// Every prefix in the table — the cheap "rotating minted nothing" probe.
async fn prefixes(db: &SqliteDatabase) -> Vec<String> {
    let mut select = Query::select();
    select
        .column(Alias::new("prefix"))
        .from(Alias::new("api_keys"));
    db.query(&Statement::render(&select))
        .await
        .expect("prefix reads")
        .rows
        .into_iter()
        .map(|row| row.get::<String>("prefix").unwrap_or_default())
        .collect()
}

#[pollster::test]
async fn issued_keys_verify_and_carry_subject_scopes_and_mode() {
    let (_db, store) = db();
    // Caller mistakes are refused before anything is written.
    assert!(matches!(
        store.issue("Pos", "acct", &[], ApiKeyMode::Test).await,
        Err(ApiKeyError::Namespace(_))
    ));
    assert!(matches!(
        store
            .issue("pos", "acct", &["read write"], ApiKeyMode::Test)
            .await,
        Err(ApiKeyError::Scope(_))
    ));
    let issued = key_for(&store, &["read", "write"], ApiKeyMode::Live).await;

    let principal = store
        .verify(&issued.token)
        .await
        .expect("verify runs")
        .expect("the key verifies");
    assert_eq!(principal.prefix, issued.prefix);
    assert_eq!(principal.namespace, "pos");
    assert_eq!(principal.subject, "acct_123");
    assert_eq!(principal.scopes, ["read", "write"]);
    assert_eq!(principal.mode, ApiKeyMode::Live);
    assert!(principal.has_scope("read"));
    // The per-key rate-limit hook (issue #538's limiter takes any key).
    assert_eq!(
        principal.rate_limit_key(),
        format!("apikey:{}", issued.prefix)
    );
    // The subject/session shape shared with the session auth port.
    let subject = principal.to_subject();
    assert_eq!(subject.id, "acct_123");
    assert_eq!(subject.session, issued.prefix);
    // A test-mode key round-trips with its own mode.
    let test = key_for(&store, &["read"], ApiKeyMode::Test).await;
    assert_eq!(
        store
            .verify(&test.token)
            .await
            .expect("verify")
            .expect("test verifies")
            .mode,
        ApiKeyMode::Test
    );
}

#[pollster::test]
async fn the_stored_row_holds_a_hash_and_never_the_secret() {
    let (db, store) = db();
    let issued = key_for(&store, &["read"], ApiKeyMode::Live).await;
    let secret = issued.token.rsplit('_').next().expect("secret part");
    let row = stored_row(&db, &issued.prefix).await;
    // The row's text columns never carry the plaintext secret (or the
    // token); the hash is the only trace.
    for (name, value) in row.columns() {
        if let sea_query::Value::String(Some(text)) = value {
            assert!(
                !text.contains(secret),
                "column {name} holds the plaintext secret"
            );
            assert!(
                !text.contains(&issued.token),
                "column {name} holds the full token"
            );
        }
    }
    // And the stored hash really is SHA-256 over the whole token.
    assert_eq!(
        row.get::<String>("secret_hash").as_deref(),
        Some(hex::encode(Sha256::digest(issued.token.as_bytes())).as_str())
    );
}

#[pollster::test]
async fn a_wrong_secret_with_the_right_prefix_is_refused() {
    let (_db, store) = db();
    let issued = key_for(&store, &["read"], ApiKeyMode::Live).await;
    let forged = format!("{}_{}", issued.prefix, "f".repeat(64));
    assert!(store.verify(&forged).await.expect("verify runs").is_none());
    // The gate answers the uniform 401, never a hint about which part
    // failed.
    let problem = require_api_key(&store, &bearer(&forged), "read")
        .await
        .expect_err("forged");
    assert_eq!(problem.slug, "api-key-unauthorized");
    assert_eq!(problem.status, axum::http::StatusCode::UNAUTHORIZED);
}

#[pollster::test]
async fn a_malformed_token_never_reaches_the_database() {
    // `FailingDb` errors on every statement, so an Ok answer here proves
    // the parse ran first (shared fixture from tests/common/mod.rs).
    let store = ApiKeys::new(
        Arc::new(common::FailingDb),
        Arc::new(SystemClock),
        rng(),
        "api_keys",
    );
    assert_eq!(store.verify("not-a-key").await.expect("no db hit"), None);
    let problem = require_api_key(&store, &bearer("not-a-key"), "read")
        .await
        .expect_err("malformed");
    assert_eq!(problem.slug, "api-key-unauthorized");
}

#[pollster::test]
async fn a_missing_header_is_unauthorized_and_a_db_failure_is_not() {
    let (_db, store) = db();
    let problem = require_api_key(&store, &HeaderMap::new(), "read")
        .await
        .expect_err("no header");
    assert_eq!(problem.slug, "api-key-unauthorized");

    // A store that cannot answer is a 503, not an unauthorized: nothing
    // about the caller's credential has been established.
    let broken = ApiKeys::new(
        Arc::new(common::FailingDb),
        Arc::new(SystemClock),
        rng(),
        "api_keys",
    );
    let token = "pos_live_3f9a0c1d2e4b5a6c_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let problem = require_api_key(&broken, &bearer(token), "read")
        .await
        .expect_err("db down");
    assert_eq!(problem.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
}

#[pollster::test]
async fn a_valid_key_without_the_scope_is_forbidden() {
    let (_db, store) = db();
    let issued = key_for(&store, &["read"], ApiKeyMode::Live).await;
    let problem = require_api_key(&store, &bearer(&issued.token), "write")
        .await
        .expect_err("no write scope");
    assert_eq!(problem.slug, "api-key-forbidden");
    assert_eq!(problem.status, axum::http::StatusCode::FORBIDDEN);
    // The same key passes for a scope it holds.
    require_api_key(&store, &bearer(&issued.token), "read")
        .await
        .expect("read scope held");
}

#[pollster::test]
async fn revoked_keys_stop_verifying() {
    let (_db, store) = db();
    let issued = key_for(&store, &["read"], ApiKeyMode::Live).await;
    store.revoke(&issued.prefix).await.expect("revoke");
    assert_eq!(store.verify(&issued.token).await.expect("verify"), None);
    let problem = require_api_key(&store, &bearer(&issued.token), "read")
        .await
        .expect_err("revoked");
    assert_eq!(problem.slug, "api-key-unauthorized");
    // An unknown prefix is an error, and revoking twice is fine.
    assert!(matches!(
        store.revoke("pos_live_0000000000000000").await,
        Err(ApiKeyError::UnknownKey(_))
    ));
    store
        .revoke(&issued.prefix)
        .await
        .expect("idempotent revoke");
}

#[pollster::test]
async fn rotate_replaces_a_key_keeping_subject_scopes_and_mode() {
    let (db, store) = db();
    let issued = key_for(&store, &["read", "write"], ApiKeyMode::Live).await;
    let rotated = store.rotate(&issued.prefix).await.expect("rotate");
    assert_ne!(rotated.prefix, issued.prefix);
    // The old token is dead the moment the rotation commits; the new one
    // verifies with everything but the secret carried over.
    assert_eq!(store.verify(&issued.token).await.expect("verify"), None);
    let principal = store
        .verify(&rotated.token)
        .await
        .expect("verify")
        .expect("the rotated key verifies");
    assert_eq!(principal.subject, "acct_123");
    assert_eq!(principal.scopes, ["read", "write"]);
    assert_eq!(principal.mode, ApiKeyMode::Live);
    // Rotating the now-revoked prefix — twice, to be sure — is refused
    // and mints nothing: exactly the two rows remain, and the live
    // replacement still verifies.
    assert!(matches!(
        store.rotate(&issued.prefix).await,
        Err(ApiKeyError::UnknownKey(_))
    ));
    assert_eq!(prefixes(&db).await.len(), 2);
    store.revoke(&rotated.prefix).await.expect("revoke again");
    assert!(matches!(
        store.rotate(&rotated.prefix).await,
        Err(ApiKeyError::UnknownKey(_))
    ));
    assert_eq!(prefixes(&db).await.len(), 2);
}

#[pollster::test]
async fn last_used_at_is_written_at_most_once_per_minute() {
    let start = OffsetDateTime::parse(NOW, &Rfc3339).expect("fixed now");
    let clock = Arc::new(FixedClock {
        // Test-fixture time travel, not request state; the scoped allow
        // follows the policy in clippy.toml (interior mutability for fakes).
        #[allow(clippy::disallowed_types)]
        now: std::sync::Mutex::new(start),
    });
    let (db, store) = db_with_clock(clock.clone());
    let issued = key_for(&store, &["read"], ApiKeyMode::Live).await;
    assert_eq!(
        last_used(&db, &issued.prefix).await,
        None,
        "issuing touches nothing"
    );

    // The first successful verify stamps it.
    store
        .verify(&issued.token)
        .await
        .expect("verify")
        .expect("verifies");
    let first = last_used(&db, &issued.prefix).await.expect("touched");
    assert_eq!(first, NOW);

    // Seconds later: nothing written.
    *clock.now.lock().expect("clock lock uncontended") = start + time::Duration::seconds(30);
    store
        .verify(&issued.token)
        .await
        .expect("verify")
        .expect("verifies");
    assert_eq!(last_used(&db, &issued.prefix).await, Some(first.clone()));

    // A minute later: written again.
    *clock.now.lock().expect("clock lock uncontended") = start + time::Duration::seconds(61);
    store
        .verify(&issued.token)
        .await
        .expect("verify")
        .expect("verifies");
    let second = last_used(&db, &issued.prefix).await.expect("touched again");
    assert_ne!(second, first);
}

// `mod common` pulls the shared fixtures in; `FailingDb` is all this file
// needs, the rest is `#[allow(dead_code)]`'d at the source.
mod common;
