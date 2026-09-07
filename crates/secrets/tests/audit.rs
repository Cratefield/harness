//! The audit chain (issue #41): one row per access, append-only enforced
//! by the database, and a chain that names the first broken link when
//! something bypasses that enforcement.

use std::sync::Arc;

use factory0_adapter_sqlite::SqliteDatabase;
use factory0_core::{Database, Statement};
use factory0_kms::{Dek, Kms, LocalFileKms};
use factory0_secrets::{
    Actor, ChainAudit, SecretStore, Secrets, SecretsError, StoreId, migrations, verify,
};

fn kms() -> Arc<dyn Kms> {
    let kek = Dek::generate().expect("rng");
    Arc::new(LocalFileKms::from_key(kek, "test-kek", "test").expect("not production"))
}

fn actor() -> Actor {
    Actor::new("auditor").expect("named")
}

/// A store whose audit sink is the chain in its own database.
fn store() -> (SecretStore, Arc<dyn Database>, StoreId) {
    let db = SqliteDatabase::in_memory().expect("in-memory db");
    db.apply_migrations("secrets", migrations().sqlite)
        .expect("schema applies");
    let db: Arc<dyn Database> = Arc::new(db);
    let id = StoreId::Tenant("tenant-a".to_owned());
    let secrets =
        Secrets::new(kms()).with_audit(Arc::new(ChainAudit::new(id.clone(), Arc::clone(&db))));
    (secrets.tenant("tenant-a", Arc::clone(&db)), db, id)
}

async fn count(db: &dyn Database) -> i64 {
    db.query(&Statement::new(
        "SELECT COUNT(*) AS n FROM harness_secret_audit",
    ))
    .await
    .expect("count")
    .first()
    .and_then(|row| row.get::<i64>("n"))
    .unwrap_or_default()
}

#[pollster::test]
async fn every_method_writes_exactly_one_row_and_the_chain_verifies() {
    let (store, db, id) = store();

    store
        .put("a/key", &"one".into(), &actor())
        .await
        .expect("put");
    store.get("a/key", &actor()).await.expect("get");
    store.list(&actor()).await.expect("list");
    store.delete("a/key", &actor()).await.expect("delete");
    let _ = store.put("", &"x".into(), &actor()).await; // refused, still audited

    assert_eq!(count(&*db).await, 5, "one row per call, failures included");

    let anchor = verify(&id, &*db).await.expect("the chain verifies");
    assert_eq!(anchor.seq, 5);
    assert_eq!(anchor.store, "tenant-a");
    assert_eq!(anchor.hash.len(), 64, "a sha256 in hex");

    // The actions are the ones that happened, in order.
    let rows = db
        .query(&Statement::new(
            "SELECT action, allowed FROM harness_secret_audit ORDER BY seq",
        ))
        .await
        .expect("read");
    let actions: Vec<(String, i64)> = rows
        .rows
        .iter()
        .map(|row| {
            (
                row.get::<String>("action").unwrap_or_default(),
                row.get::<i64>("allowed").unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        actions,
        vec![
            ("put".to_owned(), 1),
            ("get".to_owned(), 1),
            ("list".to_owned(), 1),
            ("delete".to_owned(), 1),
            ("put".to_owned(), 0),
        ]
    );
}

/// No secret value may reach the log, whatever else it records.
#[pollster::test]
async fn the_log_never_contains_a_secret_value() {
    let (store, db, _id) = store();
    store
        .put("stripe/key", &"sk_live_super_secret_value".into(), &actor())
        .await
        .expect("put");
    store.get("stripe/key", &actor()).await.expect("get");

    let rows = db
        .query(&Statement::new(
            "SELECT actor, name, action, request_id FROM harness_secret_audit",
        ))
        .await
        .expect("read");
    for row in &rows.rows {
        for column in ["actor", "name", "action", "request_id"] {
            let value: String = row.get(column).unwrap_or_default();
            assert!(
                !value.contains("sk_live"),
                "{column} carried the secret: {value}"
            );
        }
    }
}

/// Append-only is the database's job, not the application's.
#[pollster::test]
async fn update_and_delete_are_refused_by_the_database() {
    let (store, db, id) = store();
    store
        .put("a/key", &"one".into(), &actor())
        .await
        .expect("put");

    let err = db
        .execute(&Statement::new(
            "UPDATE harness_secret_audit SET actor = 'someone else' WHERE seq = 1",
        ))
        .await
        .expect_err("UPDATE must be refused");
    assert!(err.to_string().contains("append-only"), "{err}");

    let err = db
        .execute(&Statement::new(
            "DELETE FROM harness_secret_audit WHERE seq = 1",
        ))
        .await
        .expect_err("DELETE must be refused");
    assert!(err.to_string().contains("append-only"), "{err}");

    verify(&id, &*db).await.expect("and the chain is untouched");
}

/// What the chain is for: something that bypasses the trigger — a
/// superuser, an edit to the file — still cannot alter a row unnoticed.
#[pollster::test]
async fn a_row_altered_behind_the_trigger_breaks_the_chain_at_that_row() {
    let (store, db, id) = store();
    for name in ["a/key", "b/key", "c/key"] {
        store.put(name, &"x".into(), &actor()).await.expect("put");
    }
    verify(&id, &*db).await.expect("verifies before");

    // Bypass the trigger the way a superuser would: drop it, edit, and
    // put it back. The chain does not care that the trigger was gone.
    db.execute(&Statement::new(
        "DROP TRIGGER harness_secret_audit_no_update",
    ))
    .await
    .expect("drop");
    db.execute(&Statement::new(
        "UPDATE harness_secret_audit SET actor = 'not-the-auditor' WHERE seq = 2",
    ))
    .await
    .expect("edit");

    let err = verify(&id, &*db)
        .await
        .expect_err("the edit must be caught");
    match err {
        SecretsError::ChainBroken { seq, detail, .. } => {
            assert_eq!(seq, 2, "it names the first broken link, not the last");
            assert!(detail.contains("altered"), "{detail}");
        }
        other => panic!("expected a broken chain, got {other}"),
    }
}

#[pollster::test]
async fn a_removed_row_breaks_the_chain_where_it_was() {
    let (store, db, id) = store();
    for name in ["a/key", "b/key", "c/key"] {
        store.put(name, &"x".into(), &actor()).await.expect("put");
    }
    db.execute(&Statement::new(
        "DROP TRIGGER harness_secret_audit_no_delete",
    ))
    .await
    .expect("drop");
    db.execute(&Statement::new(
        "DELETE FROM harness_secret_audit WHERE seq = 2",
    ))
    .await
    .expect("remove");

    let err = verify(&id, &*db).await.expect_err("a gap must be caught");
    match err {
        SecretsError::ChainBroken { seq, detail, .. } => {
            assert_eq!(seq, 3);
            assert!(detail.contains("missing or out of order"), "{detail}");
        }
        other => panic!("expected a broken chain, got {other}"),
    }
}

/// The one thing a chain cannot catch by itself: its own tail being
/// removed, because a shorter valid chain is still valid. That is what
/// the anchor is for, and this test is the reason it exists.
#[pollster::test]
async fn a_truncated_chain_still_verifies_which_is_why_the_anchor_exists() {
    let (store, db, id) = store();
    for name in ["a/key", "b/key", "c/key"] {
        store.put(name, &"x".into(), &actor()).await.expect("put");
    }
    let before = verify(&id, &*db).await.expect("verifies");
    assert_eq!(before.seq, 3);

    db.execute(&Statement::new(
        "DROP TRIGGER harness_secret_audit_no_delete",
    ))
    .await
    .expect("drop");
    db.execute(&Statement::new(
        "DELETE FROM harness_secret_audit WHERE seq = 3",
    ))
    .await
    .expect("truncate the tail");

    let after = verify(&id, &*db)
        .await
        .expect("a truncated chain is internally consistent");
    assert_ne!(
        before, after,
        "which is exactly why the anchor is published outside the database"
    );
    assert_eq!(after.seq, 2, "the anchor's seq is what catches it");
}

#[pollster::test]
async fn an_empty_chain_verifies_to_the_genesis_anchor() {
    let (_store, db, id) = store();
    let anchor = verify(&id, &*db).await.expect("an empty chain verifies");
    assert_eq!(anchor.seq, 0);
    assert_eq!(anchor.hash, "0".repeat(64));
}

/// A sink that cannot record turns the access into a refusal: the store
/// does not serve a secret nobody can account for.
#[pollster::test]
async fn a_secret_is_refused_when_it_cannot_be_audited() {
    struct Broken;

    #[async_trait::async_trait]
    impl factory0_secrets::Audit for Broken {
        async fn record(
            &self,
            _event: &factory0_secrets::AuditEvent<'_>,
        ) -> Result<(), SecretsError> {
            Err(SecretsError::NotAudited(
                "the log is unreachable".to_owned(),
            ))
        }
    }

    let db = SqliteDatabase::in_memory().expect("in-memory db");
    db.apply_migrations("secrets", migrations().sqlite)
        .expect("schema");
    let db: Arc<dyn Database> = Arc::new(db);
    let secrets = Secrets::new(kms()).with_audit(Arc::new(Broken));
    let store = secrets.tenant("tenant-a", db);

    let err = store
        .put("a/key", &"one".into(), &actor())
        .await
        .expect_err("an unauditable write is refused");
    assert!(matches!(err, SecretsError::NotAudited(_)), "{err}");

    let err = store
        .get("a/key", &actor())
        .await
        .expect_err("an unauditable read is refused");
    assert!(matches!(err, SecretsError::NotAudited(_)), "{err}");
}
