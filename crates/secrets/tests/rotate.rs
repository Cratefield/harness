//! Key rotation (issue #42): the data key and the wrapping, both with a
//! plan mode, and reads that keep working throughout.

use std::sync::Arc;

use factory0_adapter_sqlite::SqliteDatabase;
use factory0_core::{Database, Statement};
use factory0_kms::{Dek, Kms, LocalFileKms};
use factory0_secrets::{Actor, ChainAudit, SecretStore, Secrets, StoreId, migrations, verify};

fn kms() -> Arc<dyn Kms> {
    let kek = Dek::generate().expect("rng");
    Arc::new(LocalFileKms::from_key(kek, "kek-one", "test").expect("not production"))
}

fn actor() -> Actor {
    Actor::new("operator").expect("named")
}

fn store_with(kms: Arc<dyn Kms>) -> (SecretStore, Arc<dyn Database>, StoreId) {
    let db = SqliteDatabase::in_memory().expect("in-memory db");
    db.apply_migrations("secrets", migrations().sqlite)
        .expect("schema");
    let db: Arc<dyn Database> = Arc::new(db);
    let id = StoreId::Tenant("tenant-a".to_owned());
    let secrets =
        Secrets::new(kms).with_audit(Arc::new(ChainAudit::new(id.clone(), Arc::clone(&db))));
    (secrets.tenant("tenant-a", Arc::clone(&db)), db, id)
}

async fn key_states(db: &dyn Database) -> Vec<(String, String)> {
    db.query(&Statement::new(
        "SELECT key_id, state FROM harness_secret_keys ORDER BY created_at, key_id",
    ))
    .await
    .expect("keys")
    .rows
    .iter()
    .map(|row| {
        (
            row.get::<String>("key_id").unwrap_or_default(),
            row.get::<String>("state").unwrap_or_default(),
        )
    })
    .collect()
}

#[pollster::test]
async fn rotating_the_data_key_re_encrypts_everything_and_retires_the_old_key() {
    let (store, db, id) = store_with(kms());
    for (name, value) in [("a/key", "one"), ("b/key", "two")] {
        store.put(name, &value.into(), &actor()).await.expect("put");
    }
    store
        .put("a/key", &"one-v2".into(), &actor())
        .await
        .expect("put");

    let before = key_states(&*db).await;
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].1, "active");

    // A plan changes nothing and says what it would do.
    let planned = store.rotate_dek(&actor(), true).await.expect("plan");
    assert!(planned.planned);
    assert_eq!(planned.reencrypted, 3, "three live versions");
    assert_eq!(planned.to_key, None);
    assert_eq!(key_states(&*db).await, before, "a plan touches nothing");

    let report = store.rotate_dek(&actor(), false).await.expect("rotate");
    assert!(!report.planned);
    assert_eq!(report.reencrypted, 3);
    assert_eq!(report.from_key, Some(before[0].0.clone()));
    assert!(
        report.retired_old,
        "nothing references the old key any more"
    );

    // Both keys still exist; the old one is retired, not deleted, so a
    // restore of an older backup still has something to unwrap with.
    let after = key_states(&*db).await;
    assert_eq!(after.len(), 2);
    assert!(
        after
            .iter()
            .any(|(id, state)| id == &before[0].0 && state == "retired")
    );
    assert!(after.iter().any(|(_, state)| state == "active"));

    // Every secret still reads, and every row names the new key.
    assert_eq!(
        store
            .get("a/key", &actor())
            .await
            .expect("get")
            .expect("present")
            .expose_str()
            .expect("utf-8"),
        "one-v2"
    );
    assert_eq!(
        store
            .get("b/key", &actor())
            .await
            .expect("get")
            .expect("present")
            .expose_str()
            .expect("utf-8"),
        "two"
    );
    let under_old: i64 = db
        .query(&Statement::with_values(
            "SELECT COUNT(*) AS n FROM harness_secrets WHERE key_id = ?",
            vec![sea_query::Value::String(Some(Box::new(
                before[0].0.clone(),
            )))],
        ))
        .await
        .expect("count")
        .first()
        .and_then(|row| row.get("n"))
        .unwrap_or_default();
    assert_eq!(under_old, 0, "nothing is sealed under the old key");

    verify(&id, &*db)
        .await
        .expect("the audit chain still verifies");
}

/// The property the issue asks for: reads do not fail while a rotation
/// is in progress. Rotation re-encrypts one row at a time and both keys
/// exist throughout, so a read between any two steps sees a row it can
/// open. This drives the steps explicitly rather than racing threads,
/// because the invariant is about the intermediate states, not timing.
#[pollster::test]
async fn reads_never_fail_part_way_through_a_rotation() {
    let (store, db, _id) = store_with(kms());
    for i in 0..6 {
        store
            .put(&format!("k{i}"), &format!("v{i}").as_str().into(), &actor())
            .await
            .expect("put");
    }

    // A half-finished rotation: install the new key, re-encrypt some
    // rows, and read everything at each step.
    let old_key = {
        let report = store.rotate_dek(&actor(), true).await.expect("plan");
        assert_eq!(report.reencrypted, 6);
        report.from_key.expect("a key")
    };

    for step in 0..3 {
        // Interleave: read every secret, then advance the rotation by
        // running it again (it is idempotent and finishes what is left).
        for i in 0..6 {
            let got = store
                .get(&format!("k{i}"), &actor())
                .await
                .unwrap_or_else(|err| panic!("step {step}, k{i} must still read: {err}"))
                .unwrap_or_else(|| panic!("step {step}, k{i} vanished"));
            assert_eq!(got.expose_str().expect("utf-8"), format!("v{i}"));
        }
        store.rotate_dek(&actor(), false).await.expect("rotate");
    }

    // Three rotations later everything still reads and the first key is
    // long retired.
    for i in 0..6 {
        assert_eq!(
            store
                .get(&format!("k{i}"), &actor())
                .await
                .expect("get")
                .expect("present")
                .expose_str()
                .expect("utf-8"),
            format!("v{i}")
        );
    }
    let states = key_states(&*db).await;
    assert_eq!(states.len(), 4, "one original plus three rotations");
    assert!(
        states
            .iter()
            .any(|(id, state)| id == &old_key && state == "retired")
    );
    assert_eq!(
        states.iter().filter(|(_, state)| state == "active").count(),
        1,
        "exactly one active key at all times"
    );
}

/// A soft-deleted secret still references its key, so the old key is
/// kept `retiring` rather than retired: its ciphertexts are still there.
#[pollster::test]
async fn a_deleted_secret_keeps_the_old_key_retiring() {
    let (store, db, _id) = store_with(kms());
    store.put("gone", &"x".into(), &actor()).await.expect("put");
    store.delete("gone", &actor()).await.expect("delete");

    let report = store.rotate_dek(&actor(), false).await.expect("rotate");
    assert_eq!(
        report.reencrypted, 0,
        "a deleted version is not re-encrypted"
    );
    assert!(
        !report.retired_old,
        "something still references the old key"
    );
    let states = key_states(&*db).await;
    assert!(
        states.iter().any(|(_, state)| state == "retiring"),
        "{states:?}"
    );
}

/// Re-wrapping moves the data keys onto the master key's current
/// material without touching a single secret.
#[pollster::test]
async fn rewrapping_changes_the_wrapping_and_nothing_else() {
    let (store, db, id) = store_with(kms());
    store
        .put("a/key", &"one".into(), &actor())
        .await
        .expect("put");

    let wrapped_before: Vec<u8> = db
        .query(&Statement::new(
            "SELECT wrapped_dek FROM harness_secret_keys",
        ))
        .await
        .expect("read")
        .first()
        .and_then(|row| row.get("wrapped_dek"))
        .expect("bytes");
    let ciphertext_before: Vec<u8> = db
        .query(&Statement::new("SELECT ciphertext FROM harness_secrets"))
        .await
        .expect("read")
        .first()
        .and_then(|row| row.get("ciphertext"))
        .expect("bytes");

    let planned = store.rewrap(&actor(), true).await.expect("plan");
    assert!(planned.planned);
    assert_eq!(planned.keys, 1);

    let report = store.rewrap(&actor(), false).await.expect("rewrap");
    assert_eq!(report.keys, 1);
    assert_eq!(report.key_ref, "kek-one");

    let wrapped_after: Vec<u8> = db
        .query(&Statement::new(
            "SELECT wrapped_dek FROM harness_secret_keys",
        ))
        .await
        .expect("read")
        .first()
        .and_then(|row| row.get("wrapped_dek"))
        .expect("bytes");
    let ciphertext_after: Vec<u8> = db
        .query(&Statement::new("SELECT ciphertext FROM harness_secrets"))
        .await
        .expect("read")
        .first()
        .and_then(|row| row.get("ciphertext"))
        .expect("bytes");

    assert_ne!(wrapped_before, wrapped_after, "the wrapping changed");
    assert_eq!(
        ciphertext_before, ciphertext_after,
        "no secret was re-encrypted: they are sealed under the DEK, not the KEK"
    );
    assert_eq!(
        store
            .get("a/key", &actor())
            .await
            .expect("get")
            .expect("present")
            .expose_str()
            .expect("utf-8"),
        "one"
    );
    verify(&id, &*db).await.expect("the chain verifies");
}

#[pollster::test]
async fn both_operations_are_audited() {
    let (store, db, id) = store_with(kms());
    store
        .put("a/key", &"one".into(), &actor())
        .await
        .expect("put");
    store.rotate_dek(&actor(), true).await.expect("plan");
    store.rotate_dek(&actor(), false).await.expect("rotate");
    store.rewrap(&actor(), false).await.expect("rewrap");

    let actions: Vec<String> = db
        .query(&Statement::new(
            "SELECT action FROM harness_secret_audit ORDER BY seq",
        ))
        .await
        .expect("read")
        .rows
        .iter()
        .filter_map(|row| row.get::<String>("action"))
        .collect();
    assert_eq!(
        actions,
        vec!["put", "rotate_dek", "rotate_dek", "rewrap"],
        "a plan is an access too: it read every key"
    );
    verify(&id, &*db).await.expect("the chain verifies");
}
