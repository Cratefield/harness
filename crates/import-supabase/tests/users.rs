//! `read_users` and `record_mapping` against the fixture project (issue
//! #659), on the Postgres named by `FZ_TEST_POSTGRES_URL` — CI's
//! `postgres:16` service container. Every test skips, saying why, when the
//! variable is unset.

use std::collections::BTreeSet;

use cratefield_adapter_postgres::testing::{TempDb, base_url, skip_reason};
use cratefield_import_supabase::{
    EXTERNAL_PROVIDER, ImportPlan, InspectError, InspectOptions, MappedUser, MappingError, Secret,
    SkipReason, UsersOptions, inspect, read_users, record_mapping,
};
use sqlx::{Connection as _, PgConnection, PgPool};

const FIXTURE: &str = include_str!("fixtures/supabase-project.sql");
const PROJECT_REF: &str = "fixtureprojectref000";

const ADA: &str = "00000000-0000-4000-8000-000000000001";
const GRACE: &str = "00000000-0000-4000-8000-000000000002";
const LINUS: &str = "00000000-0000-4000-8000-000000000003";
const PHONE: &str = "00000000-0000-4000-8000-000000000004";
const GUEST: &str = "00000000-0000-4000-8000-000000000005";
const ADA_HASH: &str = "$2a$10$abcdefghijklmnopqrstuuOJ4f0Zf1rSYx2Zl8pQ1fSl8sQf2aZ1u";

/// A throwaway database, with the fixture loaded when `fixture`, or `None`
/// (and the skip reason printed) without a server.
async fn db(tag: &str, fixture: bool) -> Option<TempDb> {
    let Some(base) = base_url() else {
        eprintln!("skipping: {}", skip_reason());
        return None;
    };
    let db = TempDb::create(&base, tag).await?;
    if fixture {
        db.assert_postgres_16().await;
        let pool = PgPool::connect(&db.url).await.expect("connect");
        sqlx::raw_sql(FIXTURE)
            .execute(&pool)
            .await
            .expect("the fixture loads");
        pool.close().await;
    }
    Some(db)
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // the planning, unmapped, redaction and batching checks
async fn the_users_are_planned_for_import() {
    let Some(db) = db("supabase_users_plan", true).await else {
        return;
    };
    let mut options = UsersOptions::new(Secret::new(db.url.clone()));
    options.oidc_providers = BTreeSet::from(["google".to_owned()]);
    let plan = read_users(&options).await.expect("read_users succeeds");

    assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
    assert_eq!(plan.metadata.len(), 3);
    let ids: Vec<&str> = plan
        .records
        .iter()
        .map(|record| record.external_id.as_str())
        .collect();
    assert_eq!(ids, [ADA, GRACE, LINUS]);

    // Each record rides with the metadata read alongside it, same id order.
    let paired: Vec<(&str, &str)> = plan
        .users()
        .map(|(record, metadata)| (record.external_id.as_str(), metadata.supabase_id.as_str()))
        .collect();
    assert_eq!(paired, [(ADA, ADA), (GRACE, GRACE), (LINUS, LINUS)]);

    let (ada, grace, linus) = (&plan.records[0], &plan.records[1], &plan.records[2]);
    assert_eq!(ada.external_provider, EXTERNAL_PROVIDER);
    assert_eq!(ada.email, "ada@example.test");
    assert!(ada.email_verified);
    assert_eq!(ada.created_at.as_deref(), Some("2026-01-01T00:00:00Z"));
    assert_eq!(
        ada.password_hash.as_ref().map(Secret::expose),
        Some(ADA_HASH),
        "ada's bcrypt hash passes through"
    );
    assert!(ada.identities.is_empty(), "email is not OIDC");
    assert!(grace.email_verified);
    assert!(grace.password_hash.is_none(), "grace has no password");
    assert_eq!(grace.identities[0].provider, "google");
    assert_eq!(grace.identities[0].subject, "1094857261");
    assert!(!linus.email_verified, "linus is unconfirmed");
    assert!(linus.identities.is_empty());

    // Unmapped: github, which the harness has no slug for. Metadata rides
    // alongside, one per imported user.
    assert_eq!(plan.unmapped[0].provider, "github");
    assert_eq!(plan.unmapped[0].supabase_ids, [LINUS]);
    assert_eq!(plan.metadata[0].supabase_id, ADA);
    let name = &plan.metadata[0].user_metadata.as_ref().unwrap()["name"];
    assert_eq!(name, "Ada");

    // `Debug` prints no address and redacts the hash; the JSON carries both
    // — the import has to store the hash — with the contract's keys exactly.
    let debug = format!("{ada:?}");
    assert!(
        !debug.contains("$2") && debug.contains("[redacted]"),
        "{debug}"
    );
    assert!(
        !debug.contains("ada@example.test"),
        "the record's Debug carries no address: {debug}"
    );
    let json = serde_json::to_value(ada).expect("serializes");
    assert!(json["password_hash"].as_str().unwrap().starts_with("$2"));
    let object = json.as_object().unwrap();
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys.join(","),
        "created_at,email,email_verified,external_id,external_provider,identities,password_hash"
    );
    // A passwordless record omits the key.
    assert!(
        serde_json::to_value(grace)
            .unwrap()
            .get("password_hash")
            .is_none()
    );

    // Without `google` listed, grace's identity is unmapped too.
    let unlisted = read_users(&UsersOptions::new(Secret::new(db.url.clone())))
        .await
        .expect("read_users succeeds");
    assert!(
        unlisted
            .records
            .iter()
            .find(|r| r.external_id == GRACE)
            .unwrap()
            .identities
            .is_empty()
    );
    let providers: Vec<&str> = unlisted
        .unmapped
        .iter()
        .map(|unmapped| unmapped.provider.as_str())
        .collect();
    assert_eq!(providers, ["github", "google"]);

    // A batch size of one is the same plan as one page.
    let mut small = UsersOptions::new(Secret::new(db.url.clone()));
    small.batch_size = 1;
    small.oidc_providers = BTreeSet::from(["google".to_owned()]);
    let small = read_users(&small).await.expect("batched");
    assert_eq!(
        serde_json::to_value(&small.records).expect("serializes"),
        serde_json::to_value(&plan.records).expect("serializes")
    );
    let meta_ids = |plan: &ImportPlan| {
        plan.metadata
            .iter()
            .map(|metadata| metadata.supabase_id.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(meta_ids(&small), meta_ids(&plan));
    db.finish().await;
}

#[tokio::test]
async fn phone_only_and_anonymous_users_are_skipped() {
    let Some(db) = db("supabase_users_skip", true).await else {
        return;
    };
    let pool = PgPool::connect(&db.url).await.expect("connect");
    // The fixture has no `phone_confirmed_at` (no phone user to confirm), so
    // add it to model a phone-only account, plus a guest.
    sqlx::raw_sql(&format!(
        "ALTER TABLE auth.users ADD COLUMN phone_confirmed_at timestamptz; \
         INSERT INTO auth.users (id, aud, role, phone, phone_confirmed_at, created_at) VALUES \
         ('{PHONE}', 'authenticated', 'authenticated', '+15551234567', now(), now()); \
         INSERT INTO auth.users (id, aud, role, email, is_anonymous, created_at) VALUES \
         ('{GUEST}', 'authenticated', 'authenticated', 'guest@example.test', true, now());"
    ))
    .execute(&pool)
    .await
    .expect("add the phone-only and anonymous users");
    pool.close().await;

    let plan = read_users(&UsersOptions::new(Secret::new(db.url.clone())))
        .await
        .expect("read_users succeeds");
    assert_eq!(plan.records.len(), 3, "only the email users are imported");
    let skipped: Vec<(&str, SkipReason)> = plan
        .skipped
        .iter()
        .map(|skipped| (skipped.supabase_id.as_str(), skipped.reason))
        .collect();
    assert_eq!(
        skipped,
        [(PHONE, SkipReason::NoEmail), (GUEST, SkipReason::Anonymous)]
    );
    assert_eq!(plan.skipped[0].reason.as_str(), "no-email");
    assert_eq!(plan.skipped[1].reason.as_str(), "anonymous");

    // inspect counts the phone-only user as confirmed: the phone number is
    // an address. Only linus and the guest are unconfirmed.
    let report = inspect(&InspectOptions::new(
        PROJECT_REF,
        Secret::new(db.url.clone()),
    ))
    .await
    .expect("inspect succeeds");
    assert_eq!(report.auth.users, 5);
    assert_eq!(report.auth.users_unconfirmed, 2);
    db.finish().await;
}

#[tokio::test]
async fn rls_without_bypass_is_refused_before_a_row_is_read() {
    let Some(db) = db("supabase_users_rls", true).await else {
        return;
    };
    let role = format!("fz_users_rls_{}", std::process::id());
    let password = format!("rls-fixture-password-{}", std::process::id());
    let database = db.url.rsplit('/').next().expect("a database").to_owned();
    let pool = PgPool::connect(&db.url).await.expect("connect");
    sqlx::raw_sql(&format!(
        "ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY; \
         ALTER TABLE auth.identities ENABLE ROW LEVEL SECURITY; \
         DROP ROLE IF EXISTS {role}; \
         CREATE ROLE {role} LOGIN PASSWORD '{password}'; \
         ALTER ROLE {role} SET default_transaction_read_only = on; \
         GRANT CONNECT ON DATABASE \"{database}\" TO {role}; \
         GRANT USAGE ON SCHEMA auth TO {role}; \
         GRANT SELECT ON ALL TABLES IN SCHEMA auth TO {role};"
    ))
    .execute(&pool)
    .await
    .expect("enable RLS and create the role");
    pool.close().await;

    // postgres://postgres:postgres@host:port/db -> postgres://role:pw@host:port/db
    let (scheme, rest) = db.url.split_once("://").expect("a scheme");
    let (_, host_and_path) = rest.split_once('@').expect("userinfo");
    let url = format!("{scheme}://{role}:{password}@{host_and_path}");
    let error = read_users(&UsersOptions::new(Secret::new(url)))
        .await
        .expect_err("a role that cannot bypass RLS is refused");
    assert!(matches!(error, InspectError::Permission(_)), "{error:?}");
    let message = error.to_string();
    assert!(message.contains("auth.users"), "{message}");
    assert!(message.contains("BYPASSRLS"), "{message}");
    // The refusal names the table, never a row.
    assert!(!message.contains("example.test"), "{message}");

    let cleanup = PgPool::connect(&base_url().expect("set"))
        .await
        .expect("connect");
    let _ = sqlx::raw_sql(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(&cleanup)
        .await;
    cleanup.close().await;
    db.finish().await;
}

#[tokio::test]
async fn rls_forced_on_the_owner_is_refused_before_a_row_is_read() {
    let Some(db) = db("supabase_users_rls_force", true).await else {
        return;
    };
    let role = format!("fz_users_force_{}", std::process::id());
    let password = format!("force-fixture-password-{}", std::process::id());
    let database = db.url.rsplit('/').next().expect("a database").to_owned();
    let pool = PgPool::connect(&db.url).await.expect("connect");
    // FORCE ROW LEVEL SECURITY subjects the owner to RLS too, so owning the
    // table no longer exempts this role.
    sqlx::raw_sql(&format!(
        "DROP ROLE IF EXISTS {role}; \
         CREATE ROLE {role} LOGIN PASSWORD '{password}'; \
         ALTER ROLE {role} SET default_transaction_read_only = on; \
         GRANT CONNECT ON DATABASE \"{database}\" TO {role}; \
         GRANT USAGE ON SCHEMA auth TO {role}; \
         ALTER TABLE auth.users OWNER TO {role}; \
         ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY; \
         ALTER TABLE auth.users FORCE ROW LEVEL SECURITY;"
    ))
    .execute(&pool)
    .await
    .expect("make the role the owner and force RLS");
    pool.close().await;

    let (scheme, rest) = db.url.split_once("://").expect("a scheme");
    let (_, host_and_path) = rest.split_once('@').expect("userinfo");
    let url = format!("{scheme}://{role}:{password}@{host_and_path}");
    let error = read_users(&UsersOptions::new(Secret::new(url)))
        .await
        .expect_err("FORCE RLS hides rows from the owner too");
    assert!(matches!(error, InspectError::Permission(_)), "{error:?}");
    let message = error.to_string();
    assert!(message.contains("auth.users"), "{message}");
    assert!(message.contains("BYPASSRLS"), "{message}");
    assert!(!message.contains("example.test"), "{message}");

    // Drop the database first: the role owns a table in it, so it cannot go
    // while that dependency stands.
    db.finish().await;
    let cleanup = PgPool::connect(&base_url().expect("set"))
        .await
        .expect("connect");
    let _ = sqlx::raw_sql(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(&cleanup)
        .await;
    cleanup.close().await;
}

#[tokio::test]
async fn mapping_is_idempotent_and_drift_stops_it() {
    let Some(db) = db("supabase_users_mapping", false).await else {
        return;
    };
    let mut conn = PgConnection::connect(&db.url).await.expect("connect");
    let target = Secret::new(db.url.clone());
    let row = MappedUser {
        supabase_id: ADA.to_owned(),
        account_id: "sub_ada".to_owned(),
        user_metadata: Some(serde_json::json!({"name": "Ada"})),
        app_metadata: None,
    };
    let inserted = record_mapping(&mut conn, &target, std::slice::from_ref(&row))
        .await
        .expect("insert");
    assert_eq!((inserted.inserted, inserted.unchanged), (1, 0));

    // The same account again: unchanged, metadata refreshed, one row.
    let mut refreshed = row.clone();
    refreshed.user_metadata = Some(serde_json::json!({"name": "Ada Lovelace"}));
    let unchanged = record_mapping(&mut conn, &target, std::slice::from_ref(&refreshed))
        .await
        .expect("unchanged");
    assert_eq!((unchanged.inserted, unchanged.unchanged), (0, 1));
    let metadata: String =
        sqlx::query_scalar("SELECT user_metadata::text FROM import_supabase_users")
            .fetch_one(&mut conn)
            .await
            .expect("metadata");
    let metadata: serde_json::Value = serde_json::from_str(&metadata).expect("json");
    assert_eq!(metadata["name"], "Ada Lovelace");

    // A second Supabase user merged into the same account is fine: the
    // source id is the only key, so `--merge-by-email` may map two ids to
    // one account.
    let merged = MappedUser {
        supabase_id: GRACE.to_owned(),
        ..row.clone()
    };
    let both = record_mapping(&mut conn, &target, std::slice::from_ref(&merged))
        .await
        .expect("two ids may share one account");
    assert_eq!((both.inserted, both.unchanged), (1, 0));

    // The only drift is an existing id pointing at another account, and a
    // failed batch writes nothing.
    let drift = MappedUser {
        account_id: "sub_other".to_owned(),
        ..row.clone()
    };
    let error = record_mapping(&mut conn, &target, std::slice::from_ref(&drift))
        .await
        .expect_err("drift");
    assert!(matches!(error, MappingError::Drift(_)), "{error:?}");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM import_supabase_users")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(rows, 2);

    conn.close().await.expect("close");
    db.finish().await;
}
