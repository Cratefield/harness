//! The store end to end (issue #39): round trip, versioning, soft
//! delete, and the binding matrix from `docs/SECRETS-DESIGN.md` §5 — a
//! row that is moved, renamed, rolled back or repointed must fail to
//! decrypt rather than quietly succeed.

use std::sync::Arc;

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{Database, Statement};
use cratefield_kms::{Dek, Kms, LocalFileKms};
use cratefield_secrets::{Access, Actor, Audit, AuditEvent, SecretStore, Secrets, SecretsError};

fn kms() -> Arc<dyn Kms> {
    let kek = Dek::generate().expect("rng");
    Arc::new(LocalFileKms::from_key(kek, "test-kek", "test").expect("not production"))
}

/// A store on a fresh in-memory database, migrated.
fn store_on(secrets: &Secrets, id: &str) -> (SecretStore, Arc<dyn Database>) {
    let db = SqliteDatabase::in_memory().expect("in-memory db");
    db.apply_migrations("secrets", cratefield_secrets::migrations().sqlite)
        .expect("schema applies");
    let db: Arc<dyn Database> = Arc::new(db);
    (secrets.tenant(id, Arc::clone(&db)), db)
}

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}

fn actor() -> Actor {
    Actor::new("test-suite").expect("named")
}

/// Records what the audit sink saw, so "every method audits" is checked
/// rather than assumed.
#[derive(Default)]
struct Recorder {
    // Test-fixture recording, not request state: the scoped allow follows
    // the policy in clippy.toml.
    #[allow(clippy::disallowed_types)]
    seen: std::sync::Mutex<Vec<(String, Access, bool)>>,
}

#[async_trait::async_trait]
impl Audit for Recorder {
    async fn record(&self, event: &AuditEvent<'_>) -> Result<(), SecretsError> {
        self.seen.lock().expect("uncontended").push((
            event.name.unwrap_or("-").to_owned(),
            event.access,
            event.allowed,
        ));
        Ok(())
    }
}

#[pollster::test]
async fn a_secret_round_trips_and_versions_monotonically() {
    let secrets = Secrets::new(kms());
    let (store, _db) = store_on(&secrets, "tenant-a");

    assert_eq!(
        store
            .put("resend/api_key", &"first".into(), &actor())
            .await
            .expect("put"),
        1,
        "versions start at 1"
    );
    let got = store
        .get("resend/api_key", &actor())
        .await
        .expect("get")
        .expect("present");
    assert_eq!(got.expose_str().expect("utf-8"), "first");

    assert_eq!(
        store
            .put("resend/api_key", &"second".into(), &actor())
            .await
            .expect("put"),
        2,
        "a put never overwrites; it adds a version"
    );
    let got = store
        .get("resend/api_key", &actor())
        .await
        .expect("get")
        .expect("present");
    assert_eq!(
        got.expose_str().expect("utf-8"),
        "second",
        "get returns the latest"
    );

    assert!(
        store
            .get("never/written", &actor())
            .await
            .expect("get")
            .is_none(),
        "an absent secret is None, not an error"
    );
}

#[pollster::test]
async fn list_returns_names_and_versions_and_delete_is_soft() {
    let secrets = Secrets::new(kms());
    let (store, db) = store_on(&secrets, "tenant-a");

    store
        .put("a/key", &"one".into(), &actor())
        .await
        .expect("put");
    store
        .put("a/key", &"two".into(), &actor())
        .await
        .expect("put");
    store
        .put("b/key", &"three".into(), &actor())
        .await
        .expect("put");

    let listed = store.list(&actor()).await.expect("list");
    assert_eq!(listed.len(), 2, "one entry per name, at its latest version");
    assert_eq!(listed[0].name, "a/key");
    assert_eq!(listed[0].version, 2);
    assert!(!listed[0].deleted);
    assert_eq!(listed[1].name, "b/key");

    store.delete("a/key", &actor()).await.expect("delete");
    assert!(
        store.get("a/key", &actor()).await.expect("get").is_none(),
        "a deleted secret is not readable"
    );
    assert!(
        store.get("b/key", &actor()).await.expect("get").is_some(),
        "and its neighbour is untouched"
    );

    // Soft: the rows are still there for the audit trail.
    let rows = db
        .query(&Statement::new(
            "SELECT COUNT(*) AS n FROM harness_secrets WHERE name = 'a/key'",
        ))
        .await
        .expect("count");
    assert_eq!(rows.first().and_then(|r| r.get::<i64>("n")), Some(2));
    assert!(store.list(&actor()).await.expect("list")[0].deleted);
}

#[pollster::test]
async fn every_method_is_audited_including_the_failures() {
    let recorder = Arc::new(Recorder::default());
    let secrets = Secrets::new(kms()).with_audit(recorder.clone());
    let (store, _db) = store_on(&secrets, "tenant-a");

    store
        .put("a/key", &"one".into(), &actor())
        .await
        .expect("put");
    store.get("a/key", &actor()).await.expect("get");
    store.list(&actor()).await.expect("list");
    store.delete("a/key", &actor()).await.expect("delete");
    let _ = store.put("", &"x".into(), &actor()).await;

    let seen = recorder.seen.lock().expect("uncontended").clone();
    assert_eq!(seen.len(), 5, "one event per call: {seen:?}");
    assert_eq!(seen[0], ("a/key".to_owned(), Access::Put, true));
    assert_eq!(seen[1], ("a/key".to_owned(), Access::Get, true));
    assert_eq!(seen[2], ("-".to_owned(), Access::List, true));
    assert_eq!(seen[3], ("a/key".to_owned(), Access::Delete, true));
    assert_eq!(
        seen[4],
        (String::new(), Access::Put, false),
        "a refused write is recorded as loudly as a successful one"
    );
}

/// The design's §5 table, as code. Each mutation is what an attacker or
/// a careless restore would do to a row; every one must fail to decrypt.
#[pollster::test]
async fn the_binding_matrix_holds() {
    let kms = kms();
    let secrets = Secrets::new(Arc::clone(&kms));
    let (store, db) = store_on(&secrets, "tenant-a");
    store
        .put("resend/api_key", &"sk_live_x".into(), &actor())
        .await
        .expect("put");

    // Baseline: it reads back.
    assert!(
        store
            .get("resend/api_key", &actor())
            .await
            .expect("get")
            .is_some()
    );

    // 1. Renamed by editing the row.
    db.execute(&Statement::new(
        "UPDATE harness_secrets SET name = 'resend/api_keys' WHERE name = 'resend/api_key'",
    ))
    .await
    .expect("rename");
    let err = store
        .get("resend/api_keys", &actor())
        .await
        .expect_err("a renamed row must fail");
    assert!(matches!(err, SecretsError::NotAuthentic { .. }), "{err}");
    db.execute(&Statement::new(
        "UPDATE harness_secrets SET name = 'resend/api_key' WHERE name = 'resend/api_keys'",
    ))
    .await
    .expect("undo");

    // 2. Version rolled back.
    db.execute(&Statement::new(
        "UPDATE harness_secrets SET version = 7 WHERE name = 'resend/api_key'",
    ))
    .await
    .expect("reversion");
    let err = store
        .get("resend/api_key", &actor())
        .await
        .expect_err("a moved version must fail");
    assert!(matches!(err, SecretsError::NotAuthentic { .. }), "{err}");
    db.execute(&Statement::new(
        "UPDATE harness_secrets SET version = 1 WHERE name = 'resend/api_key'",
    ))
    .await
    .expect("undo");

    // 3. key_id repointed at another real key in the same store. The
    // foreign key means it must be a key that exists, so this is the
    // realistic version of the attack: two DEKs, the row moved between
    // them.
    let second = Dek::generate().expect("rng");
    let wrapped = kms.wrap(&second).await.expect("wrap");
    db.execute(&Statement::with_values(
        "INSERT INTO harness_secret_keys \
         (key_id, kms_provider, kms_key_ref, wrapped_dek, cipher, state, created_at) \
         VALUES ('dek_second', 'local-file', 'test-kek', ?, 'xchacha20poly1305', 'retiring', '2026-01-01T00:00:00Z')",
        vec![sea_query::Value::Bytes(Some(Box::new(wrapped)))],
    ))
    .await
    .expect("a second key row");
    db.execute(&Statement::new(
        "UPDATE harness_secrets SET key_id = 'dek_second' WHERE name = 'resend/api_key'",
    ))
    .await
    .expect("repoint");
    let err = store
        .get("resend/api_key", &actor())
        .await
        .expect_err("a repointed row must fail");
    assert!(matches!(err, SecretsError::NotAuthentic { .. }), "{err}");

    // 4. A flipped bit in the ciphertext.
    db.execute(&Statement::new(
        "UPDATE harness_secrets SET key_id = \
         (SELECT key_id FROM harness_secret_keys WHERE state = 'active') \
         WHERE name = 'resend/api_key'",
    ))
    .await
    .expect("restore key id");
    let ciphertext: Vec<u8> = db
        .query(&Statement::new(
            "SELECT ciphertext FROM harness_secrets WHERE name = 'resend/api_key'",
        ))
        .await
        .expect("read")
        .first()
        .and_then(|row| row.get("ciphertext"))
        .expect("bytes");
    let mut altered = ciphertext.clone();
    altered[0] ^= 0b0000_0001;
    db.execute(&Statement::with_values(
        "UPDATE harness_secrets SET ciphertext = ? WHERE name = 'resend/api_key'",
        vec![sea_query::Value::Bytes(Some(Box::new(altered)))],
    ))
    .await
    .expect("tamper");
    let err = store
        .get("resend/api_key", &actor())
        .await
        .expect_err("a flipped bit must fail");
    assert!(matches!(err, SecretsError::NotAuthentic { .. }), "{err}");
}

/// The property the two tiers rest on: a row copied from one tenant's
/// database into another's does not decrypt there, even when the second
/// store is handed the first one's key.
#[pollster::test]
async fn a_row_copied_between_tenants_does_not_decrypt() {
    let secrets = Secrets::new(kms());
    let (alpha, alpha_db) = store_on(&secrets, "tenant-alpha");
    let (beta, beta_db) = store_on(&secrets, "tenant-beta");

    alpha
        .put("stripe/key", &"sk_alpha".into(), &actor())
        .await
        .expect("put");

    // Copy alpha's key row and its secret row into beta's database: the
    // worst case, where the attacker also carries the wrapped DEK across.
    let key = alpha_db
        .query(&Statement::new(
            "SELECT key_id, kms_provider, kms_key_ref, wrapped_dek, cipher, state, created_at \
             FROM harness_secret_keys",
        ))
        .await
        .expect("read keys");
    let key = key.first().expect("alpha has a key");
    beta_db
        .execute(&Statement::with_values(
            "INSERT OR REPLACE INTO harness_secret_keys \
             (key_id, kms_provider, kms_key_ref, wrapped_dek, cipher, state, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(&key.get::<String>("key_id").expect("key_id")),
                text(&key.get::<String>("kms_provider").expect("provider")),
                text(&key.get::<String>("kms_key_ref").expect("key_ref")),
                sea_query::Value::Bytes(Some(Box::new(
                    key.get::<Vec<u8>>("wrapped_dek").expect("wrapped"),
                ))),
                text(&key.get::<String>("cipher").expect("cipher")),
                text(&key.get::<String>("state").expect("state")),
                text(&key.get::<String>("created_at").expect("created_at")),
            ],
        ))
        .await
        .expect("copy the key row");

    let secret = alpha_db
        .query(&Statement::new(
            "SELECT name, version, key_id, nonce, ciphertext, created_at, created_by \
             FROM harness_secrets",
        ))
        .await
        .expect("read secrets");
    let secret = secret.first().expect("alpha has a secret");
    beta_db
        .execute(&Statement::with_values(
            "INSERT OR REPLACE INTO harness_secrets \
             (name, version, key_id, nonce, ciphertext, created_at, created_by) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(&secret.get::<String>("name").expect("name")),
                sea_query::Value::BigInt(Some(secret.get::<i64>("version").expect("version"))),
                text(&secret.get::<String>("key_id").expect("key_id")),
                sea_query::Value::Bytes(Some(Box::new(
                    secret.get::<Vec<u8>>("nonce").expect("nonce"),
                ))),
                sea_query::Value::Bytes(Some(Box::new(
                    secret.get::<Vec<u8>>("ciphertext").expect("ciphertext"),
                ))),
                text(&secret.get::<String>("created_at").expect("created_at")),
                text(&secret.get::<String>("created_by").expect("created_by")),
            ],
        ))
        .await
        .expect("copy the secret row");

    let err = beta
        .get("stripe/key", &actor())
        .await
        .expect_err("alpha's row must not decrypt in beta's store");
    assert!(matches!(err, SecretsError::NotAuthentic { .. }), "{err}");

    // And it still decrypts where it belongs.
    assert_eq!(
        alpha
            .get("stripe/key", &actor())
            .await
            .expect("get")
            .expect("present")
            .expose_str()
            .expect("utf-8"),
        "sk_alpha"
    );
}

/// A ciphertext cannot be orphaned: the schema's foreign key refuses to
/// remove a key row that secrets still reference. So a crypto-shred is
/// dropping the tenant's database (which is what offboarding is under
/// ADR 0008's one-database-per-tenant), not deleting one row and hoping.
#[pollster::test]
async fn a_key_row_cannot_be_removed_while_secrets_reference_it() {
    let secrets = Secrets::new(kms());
    let (store, db) = store_on(&secrets, "tenant-a");
    store
        .put("a/key", &"one".into(), &actor())
        .await
        .expect("put");

    let err = db
        .execute(&Statement::new("DELETE FROM harness_secret_keys"))
        .await
        .expect_err("the key a ciphertext needs cannot simply vanish");
    assert!(
        err.to_string().to_lowercase().contains("foreign key"),
        "{err}"
    );
    assert!(
        store.get("a/key", &actor()).await.expect("get").is_some(),
        "and the secret still reads"
    );
}

#[pollster::test]
async fn names_and_actors_are_validated() {
    let secrets = Secrets::new(kms());
    let (store, _db) = store_on(&secrets, "tenant-a");
    assert!(store.put("", &"x".into(), &actor()).await.is_err());
    assert!(store.put("   ", &"x".into(), &actor()).await.is_err());
    assert!(
        store
            .put(&"n".repeat(201), &"x".into(), &actor())
            .await
            .is_err()
    );
    assert!(Actor::new("").is_err(), "there is no anonymous access");
}

#[pollster::test]
async fn a_card_data_shaped_name_is_refused() {
    let secrets = Secrets::new(kms());
    let (store, _db) = store_on(&secrets, "tenant-a");
    // Card details belong in Stripe, so a secret name that looks like card
    // data is refused (#44). Stripe's own secrets go under plain names.
    for name in ["cvv", "card_number", "customer/card_cvv", "exp_month"] {
        let err = store
            .put(name, &"x".into(), &actor())
            .await
            .expect_err("card-data name refused");
        assert!(
            matches!(err, SecretsError::Invalid(_)),
            "name `{name}` should be Invalid, got {err:?}"
        );
    }
    // A legitimate Stripe secret name is fine.
    store
        .put("stripe/webhook_signing_secret", &"whsec_x".into(), &actor())
        .await
        .expect("a plain Stripe secret name is allowed");
}
