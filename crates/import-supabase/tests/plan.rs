//! `fz import supabase`'s plan against the fixture project (issue #728), on
//! the Postgres named by `FZ_TEST_POSTGRES_URL` — CI's `postgres:16` service
//! container. Every test skips, saying why, when the variable is unset.

use cratefield_adapter_postgres::testing::{TempDb, base_url, skip_reason};
use cratefield_import_supabase::{
    InspectOptions, PLAN_VERSION, Plan, Secret, build_plan, check_drift, inspect, inspection_hash,
    read_target,
};

const FIXTURE: &str = include_str!("fixtures/supabase-project.sql");
const PROJECT_REF: &str = "fixtureprojectref000";

/// A throwaway database with the fixture loaded, or `None` (and the skip
/// reason printed) without a server.
async fn fixture_db(tag: &str) -> Option<TempDb> {
    let Some(base) = base_url() else {
        eprintln!("skipping: {}", skip_reason());
        return None;
    };
    let db = TempDb::create(&base, tag).await?;
    db.assert_postgres_16().await;
    let pool = sqlx::PgPool::connect(&db.url).await.expect("connect");
    sqlx::raw_sql(FIXTURE)
        .execute(&pool)
        .await
        .expect("the fixture loads");
    pool.close().await;
    Some(db)
}

/// A fingerprint of the target: every relation outside the system schemas,
/// and the one row of `public.only`. Enough to notice a write.
async fn fingerprint(url: &str) -> Vec<String> {
    let pool = sqlx::PgPool::connect(url).await.expect("connect");
    let relations: Vec<(String, String)> = sqlx::query_as(
        "SELECT n.nspname::text, c.relname::text FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') \
         ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await
    .expect("relations");
    let rows: Vec<(i32,)> = sqlx::query_as("SELECT id FROM public.only ORDER BY id")
        .fetch_all(&pool)
        .await
        .expect("rows");
    pool.close().await;
    relations
        .into_iter()
        .map(|(schema, name)| format!("{schema}.{name}"))
        .chain(rows.into_iter().map(|(id,)| format!("only:{id}")))
        .collect()
}

#[tokio::test]
async fn a_dry_run_plans_and_leaves_the_target_untouched() {
    let Some(db) = fixture_db("supabase_plan").await else {
        return;
    };
    let base = base_url().expect("set");
    let Some(target_db) = TempDb::create(&base, "supabase_plan_target").await else {
        return;
    };
    target_db.assert_postgres_16().await;
    let pool = sqlx::PgPool::connect(&target_db.url)
        .await
        .expect("connect");
    sqlx::raw_sql("CREATE TABLE public.only (id int); INSERT INTO public.only VALUES (1)")
        .execute(&pool)
        .await
        .expect("the target table");
    pool.close().await;

    let report = inspect(&InspectOptions::new(
        PROJECT_REF,
        Secret::new(db.url.clone()),
    ))
    .await
    .expect("inspect the source");
    let before = fingerprint(&target_db.url).await;
    let facts = read_target(&Secret::new(target_db.url.clone()))
        .await
        .expect("read the target");
    let plan = build_plan(&report, Some(&facts));
    let after = fingerprint(&target_db.url).await;
    assert_eq!(before, after, "reading the target must not change it");

    // The plan serialises and parses back.
    let json = plan.to_json();
    assert!(json.ends_with('\n'));
    let parsed: Plan = serde_json::from_str(&json).expect("plan.json parses back");
    assert_eq!(parsed, plan);
    assert_eq!(plan.plan_version, PLAN_VERSION);
    assert_eq!(plan.inspection_hash, inspection_hash(&report));
    assert_eq!(plan.project.project_ref, PROJECT_REF);
    assert!(plan.target.is_some());
    assert!(
        plan.schema_mapping
            .iter()
            .any(|mapping| mapping.from == "public" && mapping.to == "app"),
        "{:?}",
        plan.schema_mapping
    );
    assert_eq!(
        plan.phases
            .iter()
            .map(|phase| phase.phase.as_str())
            .collect::<Vec<_>>(),
        ["auth_users", "schema", "data", "storage", "verify"]
    );

    // Same server: the fixture's extensions are all available and none is in
    // public, so no extension blocker.
    let codes: Vec<&str> = plan.blockers.iter().map(|b| b.code.as_str()).collect();
    for code in [
        "target_not_checked",
        "extension_missing",
        "extension_older",
        "extension_in_public",
    ] {
        assert!(!codes.contains(&code), "{code} in {codes:?}");
    }

    db.finish().await;
    target_db.finish().await;
}

#[tokio::test]
async fn drift_is_detected_after_a_column_change() {
    let Some(db) = fixture_db("supabase_drift").await else {
        return;
    };
    let report = inspect(&InspectOptions::new(
        PROJECT_REF,
        Secret::new(db.url.clone()),
    ))
    .await
    .expect("inspect");
    let plan = build_plan(&report, None);

    // An unchanged source inspected again does not drift.
    let fresh = inspect(&InspectOptions::new(
        PROJECT_REF,
        Secret::new(db.url.clone()),
    ))
    .await
    .expect("re-inspect");
    check_drift(&plan, &fresh).expect("an unchanged source does not drift");

    // A new column does.
    let pool = sqlx::PgPool::connect(&db.url).await.expect("connect");
    sqlx::raw_sql("ALTER TABLE public.projects ADD COLUMN budget numeric")
        .execute(&pool)
        .await
        .expect("add a column");
    pool.close().await;
    let changed = inspect(&InspectOptions::new(
        PROJECT_REF,
        Secret::new(db.url.clone()),
    ))
    .await
    .expect("re-inspect");
    let error = check_drift(&plan, &changed).expect_err("a new column drifts");
    assert!(
        error.to_string().contains("changed since the plan"),
        "{error}"
    );
    assert!(error.to_string().contains(&plan.inspection_hash), "{error}");

    db.finish().await;
}
