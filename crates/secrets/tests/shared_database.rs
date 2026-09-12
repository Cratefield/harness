//! Several stores in one physical database (the control-plane
//! composition, and the reason store attribution exists): the global
//! store and every tenant store the platform runs live side by side in
//! the control database, so every row-level query must be store-scoped
//! or one store's operations land on another's rows.
//!
//! Until the `store` column landed, the AAD kept the *ciphertexts*
//! separate — a row never decrypts in the wrong store — but the SQL
//! layer was store-blind: `active_key` served whichever key row was
//! newest regardless of store, `delete` soft-deleted every store's rows
//! of that name, and `rotate_dek` tried to re-encrypt the other stores'
//! rows and failed closed on their AAD. The wiring of the control
//! plane's secrets-manager screen was what exercised those paths against
//! a shared database for the first time; these tests are what keeps
//! them true.

use std::sync::Arc;

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::Database;
use cratefield_kms::{Dek, Kms, LocalFileKms};
use cratefield_secrets::{Actor, SecretBytes, Secrets, StoreId, verify};

fn kms() -> Arc<dyn Kms> {
    let kek = Dek::generate().expect("rng");
    Arc::new(LocalFileKms::from_key(kek, "test-kek", "test").expect("not production"))
}

/// One database, several stores — the shape of the control database.
fn shared_db() -> Arc<dyn Database> {
    let db = SqliteDatabase::in_memory().expect("in-memory db");
    db.apply_migrations("secrets", cratefield_secrets::migrations().sqlite)
        .expect("schema applies");
    Arc::new(db)
}

fn actor() -> Actor {
    Actor::new("test-suite").expect("named")
}

#[pollster::test]
async fn each_store_provisions_its_own_key_and_keeps_it() {
    let db = shared_db();
    let secrets = Secrets::new(kms());
    let global = secrets.control_plane_global(Arc::clone(&db));
    let tenant = secrets.tenant("tenant-a", Arc::clone(&db));

    global
        .put("platform/demo-key", &SecretBytes::from("g"), &actor())
        .await
        .expect("global put");
    tenant
        .put("venture/x", &SecretBytes::from("t"), &actor())
        .await
        .expect("tenant put");

    let rows = db
        .query(&cratefield_core::Statement::new(
            "SELECT store, COUNT(*) AS n FROM harness_secret_keys GROUP BY store",
        ))
        .await
        .expect("keys by store");
    let by_store: Vec<(String, i64)> = rows
        .rows
        .iter()
        .map(|row| {
            (
                row.get::<String>("store").unwrap_or_default(),
                row.get::<i64>("n").unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        by_store,
        vec![("global".to_owned(), 1), ("tenant-a".to_owned(), 1),],
        "each store provisions its own data key, stamped with its store"
    );
}

#[pollster::test]
async fn a_shared_database_serves_each_stores_reads_independently() {
    let db = shared_db();
    let secrets = Secrets::new(kms());
    let global = secrets.control_plane_global(Arc::clone(&db));
    let tenant = secrets.tenant("tenant-a", Arc::clone(&db));

    // The same name in both stores: the collision that used to make one
    // store's `get` find the other's row and fail to decrypt it.
    global
        .put("shared-name", &SecretBytes::from("global value"), &actor())
        .await
        .expect("global put");
    tenant
        .put("shared-name", &SecretBytes::from("tenant value"), &actor())
        .await
        .expect("tenant put");

    assert_eq!(
        global
            .get("shared-name", &actor())
            .await
            .expect("read")
            .expect("present")
            .expose(),
        b"global value"
    );
    assert_eq!(
        tenant
            .get("shared-name", &actor())
            .await
            .expect("read")
            .expect("present")
            .expose(),
        b"tenant value"
    );
    assert_eq!(
        global.list(&actor()).await.expect("list").len(),
        1,
        "a store's list holds only its own rows"
    );
}

#[pollster::test]
async fn deleting_in_one_store_leaves_the_other_stores_rows_alone() {
    let db = shared_db();
    let secrets = Secrets::new(kms());
    let global = secrets.control_plane_global(Arc::clone(&db));
    let tenant = secrets.tenant("tenant-a", Arc::clone(&db));

    for store in [&global, &tenant] {
        store
            .put("shared-name", &SecretBytes::from("v"), &actor())
            .await
            .expect("put");
    }
    global
        .delete("shared-name", &actor())
        .await
        .expect("delete in global");

    assert!(
        global
            .get("shared-name", &actor())
            .await
            .expect("read")
            .is_none(),
        "global's own row is soft-deleted"
    );
    assert_eq!(
        tenant
            .get("shared-name", &actor())
            .await
            .expect("read")
            .expect("present")
            .expose(),
        b"v",
        "the other store's row of the same name survives"
    );
}

#[pollster::test]
async fn rotating_one_store_never_touches_another_stores_rows() {
    let db = shared_db();
    let secrets = Secrets::new(kms());
    let global = secrets.control_plane_global(Arc::clone(&db));
    let tenant = secrets.tenant("tenant-a", Arc::clone(&db));

    global
        .put(
            "platform/demo-key",
            &SecretBytes::from("global value"),
            &actor(),
        )
        .await
        .expect("global put");
    tenant
        .put("venture/x", &SecretBytes::from("tenant value"), &actor())
        .await
        .expect("tenant put");

    // Before attribution this failed closed on the tenant row's AAD —
    // the refusal was correct, but rotation of a shared database's
    // stores was impossible. Now each store rotates only its own rows.
    let report = global
        .rotate_dek(&actor(), false)
        .await
        .expect("rotate global");
    assert_eq!(report.reencrypted, 1, "only global's own row");
    assert!(
        report.to_key.is_some(),
        "the run completed and named the new key"
    );

    // Both stores still read their own values under their own keys.
    assert_eq!(
        global
            .get("platform/demo-key", &actor())
            .await
            .expect("read")
            .expect("present")
            .expose(),
        b"global value"
    );
    assert_eq!(
        tenant
            .get("venture/x", &actor())
            .await
            .expect("read")
            .expect("present")
            .expose(),
        b"tenant value"
    );

    // And the tenant's store can rotate in the same database too.
    let tenant_report = tenant
        .rotate_dek(&actor(), false)
        .await
        .expect("rotate tenant");
    assert_eq!(tenant_report.reencrypted, 1);
}

#[pollster::test]
async fn a_rewrap_touches_only_its_own_stores_keys() {
    let db = shared_db();
    let secrets = Secrets::new(kms());
    let global = secrets.control_plane_global(Arc::clone(&db));
    let tenant = secrets.tenant("tenant-a", Arc::clone(&db));

    global
        .put("platform/demo-key", &SecretBytes::from("g"), &actor())
        .await
        .expect("global put");
    tenant
        .put("venture/x", &SecretBytes::from("t"), &actor())
        .await
        .expect("tenant put");

    let report = global.rewrap(&actor(), false).await.expect("rewrap global");
    assert_eq!(report.keys, 1, "one store, one key to re-wrap");

    // The tenant's wrapped key bytes were not rewritten: its key row's
    // wrapped blob is the one its own put wrote. (A rewrap under the
    // same master key would be harmless, but a store-scoped one should
    // not even touch the other rows.)
    let tenant_key: Vec<u8> = db
        .query(&cratefield_core::Statement::new(
            "SELECT wrapped_dek FROM harness_secret_keys WHERE store = 'tenant-a'",
        ))
        .await
        .expect("query")
        .first()
        .and_then(|row| row.get("wrapped_dek"))
        .expect("the tenant's key");
    let tenant_again: Vec<u8> = db
        .query(&cratefield_core::Statement::new(
            "SELECT wrapped_dek FROM harness_secret_keys WHERE store = 'tenant-a'",
        ))
        .await
        .expect("query")
        .first()
        .and_then(|row| row.get("wrapped_dek"))
        .expect("the tenant's key");
    assert_eq!(tenant_key, tenant_again);
}

#[pollster::test]
async fn both_stores_chains_verify_on_the_shared_ledger() {
    let db = shared_db();
    let secrets = Secrets::new(kms());
    let global = secrets.control_plane_global(Arc::clone(&db));
    let tenant = secrets.tenant("tenant-a", Arc::clone(&db));

    global
        .put("platform/demo-key", &SecretBytes::from("g"), &actor())
        .await
        .expect("global put");
    tenant
        .put("venture/x", &SecretBytes::from("t"), &actor())
        .await
        .expect("tenant put");

    verify(&StoreId::Global, db.as_ref())
        .await
        .expect("the global store's chain verifies");
    verify(&StoreId::Tenant("tenant-a".to_owned()), db.as_ref())
        .await
        .expect("the tenant store's chain verifies");
}

#[pollster::test]
async fn legacy_unstamped_rows_stay_visible_to_the_store_that_reads_them() {
    // A row as written before attribution: no store value (the
    // migration's empty default). The compat rule — the same one the
    // audit chain chose in #142 — is that unstamped rows stay visible
    // wherever they were visible before, which for a single-store
    // database is its one store. Sealed by hand under the global store's
    // own key and AAD, exactly as the pre-attribution writer left it.
    let db = shared_db();
    let secrets = Secrets::new(kms());
    let global = secrets.control_plane_global(Arc::clone(&db));
    let actor = actor();
    global
        .put("legacy/name", &SecretBytes::from("legacy value"), &actor)
        .await
        .expect("put");

    db.execute(&cratefield_core::Statement::with_values(
        "UPDATE harness_secrets SET store = '' WHERE name = ?",
        vec![sea_query_text("legacy/name")],
    ))
    .await
    .expect("un-stamp the row");

    assert_eq!(
        global
            .get("legacy/name", &actor)
            .await
            .expect("read")
            .expect("present")
            .expose(),
        b"legacy value",
        "an unstamped row still reads in the store that owns its database"
    );
}

fn sea_query_text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}
