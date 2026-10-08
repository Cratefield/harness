//! `inspect` against the fixture project (issue #658), on the Postgres
//! named by `FZ_TEST_POSTGRES_URL` — CI's `postgres:16` service container.
//! Every test skips, saying why, when the variable is unset.
//!
//! Regenerate the snapshots with `INSTA_UPDATE=always cargo test -p
//! cratefield-import-supabase` (or `cargo insta review`), and write the
//! Markdown sample the docs and the PR quote with
//! `FZ_WRITE_SAMPLE_REPORT=1`.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_postgres::testing::{TempDb, base_url, skip_reason};
use cratefield_core::{
    Answer, Calibration, Classifier, ClassifierError, ClassifierProfile, HttpClient, HttpError,
    Question,
};
use cratefield_import_supabase::{
    Classification, Disposition, InspectError, InspectOptions, ManagementApi, PolicyPattern,
    PolicySource, ReadOnlySession, Report, Secret, SectionCoverage, SourceStatus, inspect,
};

const FIXTURE: &str = include_str!("fixtures/supabase-project.sql");
const PROJECT_REF: &str = "fixtureprojectref000";
const MANAGEMENT_TOKEN: &str = "sbp_fixture0token0do0not0print0000000000";
const AUTH_CONFIG_SECRET: &str = "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reported";
const SMTP_PASSWORD: &str = "smtp-fixture-password-never-reported";

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

/// The role the docs tell a user to create — `BYPASSRLS` plus
/// `pg_read_all_data`, which on Supabase the project's `postgres` role can
/// grant even though it is not a superuser and owns no `auth`/`storage`/
/// `cron` object — and the URL that logs in as it. `BYPASSRLS` is what lets
/// it read `storage.objects` despite its RLS.
async fn read_only_role(db: &TempDb, tag: &str) -> (String, String, String) {
    let role = format!("fz_inspect_{tag}_{}", std::process::id());
    let password = format!("ro-fixture-password-{tag}-{}", std::process::id());
    let pool = sqlx::PgPool::connect(&db.url).await.expect("connect");
    let database = db.url.rsplit('/').next().expect("a database").to_owned();
    sqlx::raw_sql(&format!(
        "DROP ROLE IF EXISTS {role}; \
         CREATE ROLE {role} LOGIN PASSWORD '{password}' BYPASSRLS; \
         ALTER ROLE {role} SET default_transaction_read_only = on; \
         GRANT CONNECT ON DATABASE \"{database}\" TO {role}; \
         GRANT pg_read_all_data TO {role};"
    ))
    .execute(&pool)
    .await
    .expect("create the read-only role");
    pool.close().await;
    // postgres://postgres:postgres@host:port/db -> postgres://role:password@host:port/db
    let (scheme, rest) = db.url.split_once("://").expect("a scheme");
    let (_, host_and_path) = rest.split_once('@').expect("userinfo");
    let url = format!("{scheme}://{role}:{password}@{host_and_path}");
    (role, password, url)
}

async fn drop_role(role: &str) {
    let pool = sqlx::PgPool::connect(&base_url().expect("set"))
        .await
        .expect("connect");
    let _ = sqlx::raw_sql(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(&pool)
        .await;
    pool.close().await;
}

/// One section's coverage entry, if present.
fn coverage_of<'a>(report: &'a Report, section: &str) -> Option<&'a SectionCoverage> {
    report
        .coverage
        .sections
        .iter()
        .find(|entry| entry.section == section)
}

/// The section was reported `not_visible`.
fn not_visible(report: &Report, section: &str) -> bool {
    coverage_of(report, section).is_some_and(|entry| entry.coverage == SourceStatus::NotVisible)
}

/// Drops the role that owns `auth`/`storage` and the inspecting role,
/// removing their grants first so the drop succeeds on a shared server.
async fn drop_roles(url: &str, owner: &str, role: &str) {
    let pool = sqlx::PgPool::connect(url).await.expect("connect");
    let _ = sqlx::raw_sql(&format!(
        "REASSIGN OWNED BY {owner} TO postgres; DROP OWNED BY {owner}; DROP OWNED BY {role}; \
         DROP ROLE IF EXISTS {owner}; DROP ROLE IF EXISTS {role};"
    ))
    .execute(&pool)
    .await;
    pool.close().await;
}

/// What varies between machines and runs: the throwaway database's name,
/// the server's minor version, and on-disk sizes. Everything else is
/// compared byte for byte.
// Plain assignments read better in a test's normalization than `clone_into`.
#[allow(clippy::assigning_clones)]
fn normalized(report: &Report) -> Report {
    let mut report = report.clone();
    let role = format!("`{}`", report.read_only.role);
    // The crate version changes on every release; it is checked below, not
    // frozen into the snapshot.
    report.tool.version = "<version>".to_owned();
    report.project.host = "<host>".to_owned();
    report.project.port = 5432;
    report.project.database = "<database>".to_owned();
    report.project.server_version = report
        .project
        .server_version
        .split('.')
        .next()
        .unwrap_or_default()
        .to_owned();
    report.read_only.role = "<role>".to_owned();
    for table in &mut report.tables {
        table.data_bytes = 0;
        table.index_bytes = 0;
    }
    report.summary.data_bytes = 0;
    report.summary.index_bytes = 0;
    report.summary.estimated_transfer_seconds = 0;
    report.warnings = report
        .warnings
        .iter()
        .map(|warning| warning.replace(&role, "`<role>`"))
        .collect();
    report
}

#[tokio::test]
async fn the_fixture_report_matches_its_snapshot() {
    let Some(db) = fixture_db("supabase_snapshot").await else {
        return;
    };
    let report = inspect(&InspectOptions::new(
        PROJECT_REF,
        Secret::new(db.url.clone()),
    ))
    .await
    .expect("inspect succeeds");

    // Sizes are normalized out of the snapshot, so they are checked here.
    assert!(report.summary.data_bytes > 0);
    assert!(report.summary.estimated_transfer_seconds >= 1);
    assert_eq!(
        report.summary.storage_bytes,
        Some(20_480 + 31_744 + 12_582_912)
    );

    // The blockers the fixture plants, and only those.
    let blockers: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.classification == Classification::Blocker)
        .map(|finding| finding.id.as_str())
        .collect();
    assert_eq!(
        blockers,
        [
            "extension:dblink",
            "foreign_key:public.attachments.attachments_object_id_fkey"
        ]
    );
    assert!(!report.summary.ready);
    // Nothing is guessed: without a token Edge Functions are unknown.
    assert_eq!(report.edge_functions.status, SourceStatus::NotInspected);
    assert_eq!(report.auth.enabled_providers, None);
    // Without a classifier, what no rule placed is left for review. The three
    // are the bespoke interval and the two policies its expression cannot
    // classify without a judge; the storage policies belong to the storage
    // phase, not here.
    let review: Vec<&str> = report
        .policies
        .iter()
        .filter(|policy| policy.pattern == PolicyPattern::NeedsReview)
        .map(|policy| policy.name.as_str())
        .collect();
    assert_eq!(
        review,
        [
            "Archived projects stay visible for a grace period",
            "Members can read their team's rows",
            "Members can leave unless they own the team",
        ]
    );

    // The version is normalized out of the snapshot, so it is checked here.
    assert_eq!(report.tool.version, env!("CARGO_PKG_VERSION"));

    let normalized = normalized(&report);
    insta::assert_snapshot!("fixture-report.json", normalized.to_json());
    insta::assert_snapshot!("fixture-report.md", normalized.to_markdown());

    if std::env::var_os("FZ_WRITE_SAMPLE_REPORT").is_some() {
        let mut sample = report.clone();
        sample.project.host = "db.fixtureprojectref000.supabase.co".to_owned();
        sample.project.port = 5432;
        sample.project.database = "postgres".to_owned();
        // `16.4 (Debian 16.4-1.pgdg120+1)` -> `16.4`.
        sample.project.server_version = sample
            .project
            .server_version
            .split(' ')
            .next()
            .unwrap_or_default()
            .to_owned();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/import/supabase-report.sample.md"
        );
        std::fs::write(path, sample.to_markdown()).expect("write the sample");
    }
    db.finish().await;
}

#[tokio::test]
async fn a_read_only_role_is_enough_and_is_recorded() {
    let Some(db) = fixture_db("supabase_role").await else {
        return;
    };
    let (role, password, url) = read_only_role(&db, "role").await;
    let report = inspect(&InspectOptions::new(PROJECT_REF, Secret::new(url)))
        .await
        .expect("a role with SELECT alone can inspect");
    assert!(report.read_only.transaction_read_only);
    assert!(report.read_only.session_read_only);
    assert!(report.read_only.no_transaction_id_assigned);
    assert!(!report.read_only.role_is_superuser);
    assert!(!report.read_only.role_can_write, "the role can write");
    assert_eq!(report.read_only.role, role);
    // The docs role reads every section in full: `pg_read_all_data` for
    // USAGE/SELECT, `BYPASSRLS` past storage.objects' RLS. Nothing is
    // `not_visible`, and the real object counts are there.
    let not_visible: Vec<&str> = report
        .coverage
        .sections
        .iter()
        .filter(|section| section.coverage == SourceStatus::NotVisible)
        .map(|section| section.section.as_str())
        .collect();
    assert!(not_visible.is_empty(), "{not_visible:?}");
    assert_eq!(report.summary.storage_objects, Some(3));
    assert_eq!(
        report.summary.storage_bytes,
        Some(20_480 + 31_744 + 12_582_912)
    );
    let out = format!("{}{}", report.to_json(), report.to_markdown());
    assert!(!out.contains(&password));
    db.finish().await;
    drop_role(&role).await;
}

/// The `postgres`-role URL of a Supabase stack (`supabase start`), for
/// issue #723's acceptance criterion: the role SQL the docs tell a user to
/// run, executed as `postgres`, yields a report identical to the `postgres`
/// run apart from `read_only` and warnings. Skips when unset.
fn supabase_db_url() -> Option<String> {
    std::env::var("FZ_TEST_SUPABASE_DB_URL")
        .ok()
        .map(|url| url.trim().to_owned())
        .filter(|url| !url.is_empty())
}

/// The role SQL from `docs/import/supabase.md`, embedded at compile time so
/// the document and this test cannot drift: the first fenced `sql` block
/// under the "Read-only, twice" heading.
fn documented_role_sql() -> &'static str {
    const DOC: &str = include_str!("../../../docs/import/supabase.md");
    DOC.split_once("## Read-only, twice")
        .expect("the read-only section of docs/import/supabase.md")
        .1
        .split_once("```sql")
        .expect("the role SQL block in the read-only section")
        .1
        .split_once("```")
        .expect("the role SQL block's closing fence")
        .0
}

/// The rows the stack needs for RLS and the counts to mean something: a
/// couple of `auth.users` and their identities, two buckets with objects
/// and a `pg_cron` job. `supabase start` ships `pg_cron` preloaded but not
/// created, so the seed creates it first. Idempotent, so a reused stack
/// stays stable.
const SEED: &str = "\
CREATE EXTENSION IF NOT EXISTS pg_cron WITH SCHEMA pg_catalog; \
INSERT INTO auth.users (id, email) VALUES \
  ('11111111-1111-1111-1111-111111111111', 'acceptance-one@example.test'), \
  ('22222222-2222-2222-2222-222222222222', 'acceptance-two@example.test') \
ON CONFLICT (id) DO NOTHING; \
INSERT INTO auth.identities (provider_id, user_id, identity_data, provider) VALUES \
  ('acceptance-one', '11111111-1111-1111-1111-111111111111', '{}'::jsonb, 'email'), \
  ('acceptance-two', '22222222-2222-2222-2222-222222222222', '{}'::jsonb, 'google') \
ON CONFLICT (provider_id, provider) DO NOTHING; \
INSERT INTO storage.buckets (id, name) VALUES \
  ('acceptance-bucket-one', 'acceptance-bucket-one'), \
  ('acceptance-bucket-two', 'acceptance-bucket-two') \
ON CONFLICT (id) DO NOTHING; \
INSERT INTO storage.objects (id, bucket_id, name, metadata) VALUES \
  ('33333333-3333-3333-3333-333333333333', 'acceptance-bucket-one', 'one.txt', \
   '{\"size\": 1024}'::jsonb), \
  ('44444444-4444-4444-4444-444444444444', 'acceptance-bucket-two', 'two.txt', \
   '{\"size\": 2048}'::jsonb) \
ON CONFLICT (id) DO NOTHING; \
SELECT cron.unschedule(jobid) FROM cron.job WHERE jobname = 'cratefield_acceptance'; \
SELECT cron.schedule('cratefield_acceptance', '0 3 * * *', 'SELECT 1');";

/// Loads [`SEED`] through `url`.
async fn seed(url: &str) {
    let pool = sqlx::PgPool::connect(url).await.expect("seed connect");
    sqlx::raw_sql(SEED)
        .execute(&pool)
        .await
        .expect("seed loads");
    pool.close().await;
}

/// The stack's owner (`supabase_admin`, password `postgres`) at the same
/// host and port as `base`, which owns `auth`, `storage` and `cron`; falls
/// back to `base` when that role cannot connect.
async fn seed_url(base: &str) -> String {
    let (scheme, rest) = base.split_once("://").expect("a URL scheme");
    let (_, host_and_path) = rest.split_once('@').expect("userinfo in the URL");
    let admin = format!("{scheme}://supabase_admin:postgres@{host_and_path}");
    match sqlx::PgPool::connect(&admin).await {
        Ok(pool) => {
            pool.close().await;
            admin
        }
        Err(_) => base.to_owned(),
    }
}

/// Drops the documented role however the test ends, panics included: a
/// `Drop` cannot await, so this runs on its own thread and runtime. The
/// role's name is unique, so a leaked one can never collide with a run's.
struct DropRoleGuard {
    url: String,
    role: String,
}

impl Drop for DropRoleGuard {
    fn drop(&mut self) {
        let (url, role) = (self.url.clone(), self.role.clone());
        let _ = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                return;
            };
            runtime.block_on(async {
                let Ok(pool) = sqlx::PgPool::connect(&url).await else {
                    return;
                };
                let _ = sqlx::raw_sql(&format!("REVOKE pg_read_all_data FROM {role}"))
                    .execute(&pool)
                    .await;
                let _ = sqlx::raw_sql(&format!("DROP ROLE IF EXISTS {role}"))
                    .execute(&pool)
                    .await;
                pool.close().await;
            });
        })
        .join();
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // the whole scenario, in order
async fn the_documented_role_sql_yields_the_postgres_report_on_supabase() {
    let Some(base) = supabase_db_url() else {
        eprintln!(
            "skipping: FZ_TEST_SUPABASE_DB_URL is not set — start a Supabase stack \
             (supabase start) and set it to \
             postgresql://postgres:postgres@127.0.0.1:54322/postgres"
        );
        return;
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past 1970")
        .as_nanos();
    let role = format!("fz_inspect_acceptance_{}_{nanos}", std::process::id());
    let password = format!("acceptance-password-{nanos}");
    // Cleanup runs even when an assertion below panics.
    let _guard = DropRoleGuard {
        url: base.clone(),
        role: role.clone(),
    };

    seed(&seed_url(&base).await).await;

    // The documented SQL, run as `postgres` — what the Supabase SQL editor
    // does — with a unique role name and a random password.
    let sql = documented_role_sql()
        .replace("cratefield_inspect", &role)
        .replace("<a long random password>", &password);
    let pool = sqlx::PgPool::connect(&base)
        .await
        .expect("connect as postgres");
    sqlx::raw_sql(&sql)
        .execute(&pool)
        .await
        .expect("the documented role SQL runs as postgres");
    pool.close().await;

    // postgres://user:pass@host:port/db -> the same, logging in as the role.
    let (scheme, rest) = base.split_once("://").expect("a URL scheme");
    let (_, host_and_path) = rest.split_once('@').expect("userinfo in the URL");
    let role_url = format!("{scheme}://{role}:{password}@{host_and_path}");

    let as_postgres = inspect(&InspectOptions::new(PROJECT_REF, Secret::new(base)))
        .await
        .expect("inspect as postgres");
    let as_role = inspect(&InspectOptions::new(PROJECT_REF, Secret::new(role_url)))
        .await
        .expect("inspect as the documented role");

    // The documented role (`pg_read_all_data` plus `BYPASSRLS`) reads every
    // section: nothing is unknown, and it cannot write.
    let not_visible: Vec<&str> = as_role
        .coverage
        .sections
        .iter()
        .filter(|section| section.coverage == SourceStatus::NotVisible)
        .map(|section| section.section.as_str())
        .collect();
    assert!(not_visible.is_empty(), "{not_visible:?}");
    assert_eq!(as_role.read_only.role, role);
    assert!(as_role.read_only.transaction_read_only);
    assert!(!as_role.read_only.role_can_write);

    // Identical apart from what is genuinely about the connection:
    // `read_only` and `warnings`. The report carries no timestamp.
    let comparable = |report: &Report| {
        let mut value: serde_json::Value =
            serde_json::from_str(&report.to_json()).expect("the report round-trips");
        let object = value.as_object_mut().expect("the report is an object");
        object.remove("read_only");
        object.remove("warnings");
        value
    };
    assert_eq!(comparable(&as_postgres), comparable(&as_role));
    // A marker only a run prints, never a skip: the E2E job greps for it,
    // so a stack that is not reached fails the job rather than passing it.
    println!("supabase acceptance: the documented role matched the postgres run");
}

/// The fixture's table `public.name`, if the report lists it.
fn has_table(report: &Report, name: &str) -> bool {
    report
        .tables
        .iter()
        .any(|table| table.schema == "public" && table.name == name)
}

/// The fixture's enum `public.name`, if the report lists it.
fn has_enum(report: &Report, name: &str) -> bool {
    report
        .enums
        .iter()
        .any(|entry| entry.schema == "public" && entry.name == name)
}

/// The fixture's function `public.name`, if the report lists it.
fn has_function(report: &Report, name: &str) -> bool {
    report
        .functions
        .iter()
        .any(|function| function.schema == "public" && function.name == name)
}

/// The fixture's trigger on `public.table`, if the report lists it.
fn has_trigger(report: &Report, table: &str, name: &str) -> bool {
    report
        .triggers
        .iter()
        .any(|trigger| trigger.schema == "public" && trigger.table == table && trigger.name == name)
}

/// The fixture's policy on `public.table`, by name. The fixture names its
/// policies after the shape they express rather than after the column, so
/// this looks them up by the name `schema.sql` gives them and asserts the
/// shape below — which is what the importer has to place.
fn fixture_policy<'a>(
    report: &'a Report,
    table: &str,
    name: &str,
) -> &'a cratefield_import_supabase::Policy {
    report
        .policies
        .iter()
        .find(|policy| policy.schema == "public" && policy.table == table && policy.name == name)
        .unwrap_or_else(|| {
            panic!(
                "{table} has no policy {name:?}; the fixture's policies are {:?}",
                report
                    .policies
                    .iter()
                    .filter(|policy| policy.schema == "public" && policy.table == table)
                    .map(|policy| policy.name.as_str())
                    .collect::<Vec<_>>()
            )
        })
}

/// Issue #733: the EarthOS-shaped fixture
/// (`tests/supabase-fixture/schema.sql` plus `seed.sh`) is visible to the
/// role `docs/import/supabase.md` tells a user to create, and through it to
/// `postgres` — the same equality the sibling test asserts, but on a
/// fixture that looks like a real project: tenancy through a parent, four
/// RLS shapes, enums, a SECURITY DEFINER function, a trigger, a cron job,
/// and users created through `GoTrue` rather than inserted.
///
/// The point is that the two runs are equal by construction only when the
/// grants really carry: a fixture with nothing in it would compare equal
/// whatever the role could see, so every fixture object is asserted present
/// in the `postgres` report before the comparison, and the report must
/// contain the fixture's counts rather than nulls. Skips without
/// `FZ_TEST_SUPABASE_DB_URL`; fails, loudly, when the fixture is missing —
/// a silently skipped seed would read as green.
#[tokio::test]
#[allow(clippy::too_many_lines)] // the whole scenario, in order
async fn the_earthos_shaped_fixture_is_visible_to_the_documented_role() {
    let Some(base) = supabase_db_url() else {
        eprintln!(
            "skipping: FZ_TEST_SUPABASE_DB_URL is not set — start a Supabase stack \
             (supabase start) and set it to \
             postgresql://postgres:postgres@127.0.0.1:54322/postgres"
        );
        return;
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past 1970")
        .as_nanos();
    let role = format!("fz_inspect_earthos_{}_{nanos}", std::process::id());
    let password = format!("earthos-acceptance-password-{nanos}");
    // Cleanup runs even when an assertion below panics.
    let _guard = DropRoleGuard {
        url: base.clone(),
        role: role.clone(),
    };

    // The documented SQL, run as `postgres` — what the Supabase SQL editor
    // does — with a unique role name and a random password.
    let sql = documented_role_sql()
        .replace("cratefield_inspect", &role)
        .replace("<a long random password>", &password);
    let pool = sqlx::PgPool::connect(&base)
        .await
        .expect("connect as postgres");
    sqlx::raw_sql(&sql)
        .execute(&pool)
        .await
        .expect("the documented role SQL runs as postgres");
    pool.close().await;

    // postgres://user:pass@host:port/db -> the same, logging in as the role.
    let (scheme, rest) = base.split_once("://").expect("a URL scheme");
    let (_, host_and_path) = rest.split_once('@').expect("userinfo in the URL");
    let role_url = format!("{scheme}://{role}:{password}@{host_and_path}");

    let as_postgres = inspect(&InspectOptions::new(PROJECT_REF, Secret::new(base)))
        .await
        .expect("inspect as postgres");
    let as_role = inspect(&InspectOptions::new(PROJECT_REF, Secret::new(role_url)))
        .await
        .expect("inspect as the documented role");

    // The fixture is loaded, or this test is not testing anything: an empty
    // stack would pass every assertion below for the wrong reason.
    assert!(
        has_table(&as_postgres, "projects"),
        "the EarthOS fixture is missing (no public.projects) — run \
         crates/import-supabase/tests/supabase-fixture/schema.sql and then \
         crates/import-supabase/tests/supabase-fixture/seed.sh against the stack \
         named by FZ_TEST_SUPABASE_DB_URL"
    );

    // The tenant shape: tenancy through a parent row, the shadow users table
    // GoTrue's trigger fills, the spatial table and the audit log.
    for table in [
        "projects",
        "organizations",
        "organizations_members",
        "users",
        "places",
        "audit_events",
        "projects_internal",
    ] {
        assert!(
            has_table(&as_postgres, table),
            "no public.{table} in the report"
        );
    }
    // RLS is on every one of them, and the inspector read that from the
    // catalog rather than from a policy it invented.
    for table in ["projects", "organizations", "users", "projects_internal"] {
        let entry = as_postgres
            .tables
            .iter()
            .find(|entry| entry.schema == "public" && entry.name == table)
            .unwrap_or_else(|| panic!("no public.{table}"));
        assert!(entry.rls_enabled, "public.{table} reports RLS off");
    }
    // `audit_events` is the locked table: RLS with no policy at all, which
    // is an informational fact and never a policy.
    assert!(
        !as_postgres
            .policies
            .iter()
            .any(|policy| policy.table == "audit_events"),
        "audit_events has RLS and no policy; it must report none"
    );

    // The four RLS shapes on `projects`, each placed by a rule — no
    // classifier runs in this job, so an unplaced one would mean the rule
    // missed a shape the fixture is here to prove.
    for (name, expected) in [
        ("projects_owner", PolicyPattern::TenantScoped),
        ("projects_owner_via_parent", PolicyPattern::TenantScoped),
        ("projects_tenant_via_parent", PolicyPattern::TenantScoped),
        ("projects_public_read", PolicyPattern::PublicReadFiltered),
    ] {
        let policy = fixture_policy(&as_postgres, "projects", name);
        assert_eq!(policy.pattern, expected, "{name} was placed wrongly");
        assert_eq!(policy.source, PolicySource::Rule, "{name}");
        assert!(
            policy.using.is_some(),
            "{name} carries no USING expression: {}",
            policy.test_stub
        );
    }
    // The one that must cover every command is the ALL policy, and the
    // three SELECT ones are reads only: getting that backwards would send
    // someone to write a delete route.
    assert_eq!(
        fixture_policy(&as_postgres, "projects", "projects_owner_via_parent").command,
        "ALL"
    );
    for name in [
        "projects_owner",
        "projects_tenant_via_parent",
        "projects_public_read",
    ] {
        assert_eq!(
            fixture_policy(&as_postgres, "projects", name).command,
            "SELECT",
            "{name}"
        );
    }
    // The filtered public read is bounded by the fixture's own columns, so
    // the advice names them: that is what the person writing the route needs.
    let public_read = fixture_policy(&as_postgres, "projects", "projects_public_read");
    assert!(
        public_read.suggested_equivalent.contains("visibility"),
        "the filtered public read does not name its filter column: {}",
        public_read.suggested_equivalent
    );
    // And the tenancy shapes really do reach `auth.uid()`, which is what
    // makes them tenancy rather than an owner check on a bare column.
    for name in [
        "projects_owner",
        "projects_owner_via_parent",
        "projects_tenant_via_parent",
    ] {
        assert!(
            fixture_policy(&as_postgres, "projects", name)
                .using
                .as_deref()
                .is_some_and(|expr| expr.contains("auth.uid()")),
            "{name} does not name auth.uid(): {:?}",
            fixture_policy(&as_postgres, "projects", name).using
        );
    }
    // The deny-all shape, on the table that is locked by it.
    let deny_all = fixture_policy(
        &as_postgres,
        "projects_internal",
        "projects_internal_deny_all",
    );
    assert_eq!(deny_all.pattern, PolicyPattern::DenyAll);
    assert_eq!(deny_all.command, "SELECT");
    // The membership policy on the join table the tenant shape reads.
    let self_policy = fixture_policy(
        &as_postgres,
        "organizations_members",
        "organizations_members_self",
    );
    assert_eq!(self_policy.pattern, PolicyPattern::OwnerOnly);
    // A policy on the fixture's own table is a policy; the platform's own on
    // `cron` is a managed one, and never a finding. Each policy's finding
    // is named `schema.table.policy` — the id a dispositions file keys on.
    assert!(
        as_postgres.findings.iter().any(|finding| {
            finding.kind == "policy" && finding.object == "public.projects.projects_public_read"
        }),
        "no needs-work finding for the public.projects public-read policy"
    );
    assert!(
        !as_postgres
            .managed_policies
            .iter()
            .any(|policy| policy.schema == "public"),
        "a public policy was reported as a managed one"
    );

    // Enums, the SECURITY DEFINER function and the trigger the sign-up path
    // depends on.
    for name in ["project_status", "member_role"] {
        assert!(has_enum(&as_postgres, name), "no public.{name} enum");
    }
    // `handle_new_user` runs as its owner, so the importer's needs-work
    // classification has to see it — it is the trigger that fills
    // public.users, and a harness route cannot.
    assert!(has_function(&as_postgres, "handle_new_user"));
    let handler = as_postgres
        .functions
        .iter()
        .find(|function| function.schema == "public" && function.name == "handle_new_user")
        .expect("the sign-up handler");
    assert!(
        handler.security_definer,
        "handle_new_user is not SECURITY DEFINER"
    );
    // And the tenancy function reaches `auth.uid()`: a harness has no
    // session, so that is a needs-work item, not an automatic one.
    let tenant = as_postgres
        .functions
        .iter()
        .find(|function| function.schema == "public" && function.name == "current_tenant_id")
        .expect("the tenancy function");
    assert!(
        tenant.references_auth,
        "current_tenant_id does not name auth."
    );
    assert!(
        tenant.security_definer,
        "current_tenant_id is not SECURITY DEFINER"
    );
    // And the plain trigger is a plain trigger.
    assert!(has_function(&as_postgres, "touch_updated_at"));
    assert!(has_trigger(&as_postgres, "projects", "touch_projects"));

    // The cron job, the auth users GoTrue created and the buckets the
    // Storage API made: the three sections that are `not_visible` rather
    // than zero when a grant is missing, so a real count here is the
    // evidence that BYPASSRLS reached past their RLS.
    let jobs = as_postgres
        .cron_jobs
        .as_ref()
        .expect("pg_cron jobs are visible to postgres");
    assert!(
        jobs.iter().any(|job| job.name == "earthos-heartbeat"),
        "no earthos-heartbeat cron job: {:?}",
        jobs.iter().map(|job| job.name.as_str()).collect::<Vec<_>>()
    );
    let users = as_postgres
        .auth
        .users
        .expect("auth.users is visible to postgres");
    assert!(users >= 1, "the fixture seeded no auth users");
    let buckets = as_postgres
        .storage
        .buckets
        .as_ref()
        .expect("storage.buckets is visible to postgres");
    assert!(!buckets.is_empty(), "the fixture seeded no storage buckets");

    // The documented role sees all of it: nothing is `not_visible`, and the
    // counts it reports are the real ones, not nulls.
    let not_visible: Vec<&str> = as_role
        .coverage
        .sections
        .iter()
        .filter(|section| section.coverage == SourceStatus::NotVisible)
        .map(|section| section.section.as_str())
        .collect();
    assert!(not_visible.is_empty(), "{not_visible:?}");
    assert_eq!(as_role.read_only.role, role);
    assert!(as_role.read_only.transaction_read_only);
    assert!(!as_role.read_only.role_can_write);
    assert_eq!(as_role.auth.users, as_postgres.auth.users);
    assert_eq!(
        as_role.storage.buckets.as_ref().map(Vec::len),
        as_postgres.storage.buckets.as_ref().map(Vec::len)
    );
    assert!(has_table(&as_role, "projects"));

    // Identical apart from what is genuinely about the connection:
    // `read_only` and `warnings`. The report carries no timestamp.
    let comparable = |report: &Report| {
        let mut value: serde_json::Value =
            serde_json::from_str(&report.to_json()).expect("the report round-trips");
        let object = value.as_object_mut().expect("the report is an object");
        object.remove("read_only");
        object.remove("warnings");
        value
    };
    assert_eq!(comparable(&as_postgres), comparable(&as_role));
    // A marker only a run prints, never a skip: the E2E job greps for it,
    // so a stack that is not reached fails the job rather than passing it.
    println!("earthos acceptance: the documented role saw the fixture");
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // the whole scenario, in order
async fn a_role_that_cannot_see_a_section_gets_not_visible_not_zero() {
    let Some(db) = fixture_db("supabase_visibility").await else {
        return;
    };
    let pool = sqlx::PgPool::connect(&db.url).await.expect("connect");
    let pid = std::process::id();
    let owner = format!("fixture_supabase_admin_{pid}");
    let role = format!("fz_visibility_{pid}");
    let password = format!("visibility-password-{pid}");
    let database = db.url.rsplit('/').next().expect("a database").to_owned();

    // As on Supabase: auth/storage owned by a non-superuser other role,
    // RLS on their tables and on cron.job, a user schema, and an inspect
    // role that lacks BYPASSRLS, cron USAGE and newsletter USAGE.
    let setup = format!(
        "DROP ROLE IF EXISTS {owner}; CREATE ROLE {owner} NOLOGIN; \
         ALTER SCHEMA auth OWNER TO {owner}; ALTER SCHEMA storage OWNER TO {owner}; \
         ALTER TABLE auth.users OWNER TO {owner}; \
         ALTER TABLE auth.identities OWNER TO {owner}; \
         ALTER TABLE auth.mfa_factors OWNER TO {owner}; \
         ALTER TABLE storage.buckets OWNER TO {owner}; \
         ALTER TABLE storage.objects OWNER TO {owner}; \
         CREATE SCHEMA cron; \
         CREATE TABLE cron.job (jobid bigint, jobname text, schedule text, command text, \
         active bool); \
         INSERT INTO cron.job VALUES (1, 'nightly', '0 3 * * *', 'select 1', true); \
         ALTER TABLE cron.job ENABLE ROW LEVEL SECURITY; \
         CREATE SCHEMA newsletter; \
         CREATE TABLE newsletter.subscribers (id bigint PRIMARY KEY, email text); \
         ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY; \
         ALTER TABLE auth.identities ENABLE ROW LEVEL SECURITY; \
         ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY; \
         ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY; \
         CREATE ROLE {role} LOGIN PASSWORD '{password}' NOBYPASSRLS; \
         ALTER ROLE {role} SET default_transaction_read_only = on; \
         GRANT CONNECT ON DATABASE \"{database}\" TO {role}; \
         GRANT USAGE ON SCHEMA public, auth, storage, extensions TO {role}; \
         GRANT SELECT ON ALL TABLES IN SCHEMA public, auth, storage TO {role};"
    );
    sqlx::raw_sql(&setup).execute(&pool).await.expect("setup");
    pool.close().await;

    let (scheme, rest) = db.url.split_once("://").expect("a scheme");
    let (_, host_and_path) = rest.split_once('@').expect("userinfo");
    let url = format!("{scheme}://{role}:{password}@{host_and_path}");
    let options = InspectOptions::new(PROJECT_REF, Secret::new(url));

    // One run, no abort: every section it cannot see is named.
    let report = inspect(&options).await.expect("inspect does not abort");
    for name in [
        "auth",
        "storage.buckets",
        "storage.objects",
        "cron",
        "schema:newsletter",
    ] {
        assert!(
            not_visible(&report, name),
            "{name}: {:?}",
            report.coverage.sections
        );
    }
    assert!(!not_visible(&report, "schema:public"));
    assert_eq!(
        coverage_of(&report, "schema:public").map(|entry| entry.coverage),
        Some(SourceStatus::Inspected)
    );
    // The reasons name RLS where RLS is what hides, USAGE where it is not.
    assert!(
        coverage_of(&report, "auth")
            .unwrap()
            .reason
            .contains("row-level security"),
        "{}",
        coverage_of(&report, "auth").unwrap().reason
    );
    assert!(
        coverage_of(&report, "cron")
            .unwrap()
            .reason
            .contains("USAGE"),
        "{}",
        coverage_of(&report, "cron").unwrap().reason
    );

    assert!(!report.summary.ready);
    for name in [
        "auth",
        "storage.buckets",
        "storage.objects",
        "cron",
        "schema:newsletter",
    ] {
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.id == format!("visibility:{name}"))
            .unwrap_or_else(|| panic!("a blocker for {name}"));
        assert_eq!(finding.classification, Classification::Blocker);
    }
    let fixes = report
        .findings
        .iter()
        .filter(|finding| finding.kind == "visibility")
        .map(|finding| finding.cratefield_equivalent.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    // The fix leads with what the source's postgres can run, and keeps the
    // specific grants as the alternative.
    assert!(
        fixes.contains("ALTER ROLE") && fixes.contains("BYPASSRLS"),
        "{fixes}"
    );
    assert!(fixes.contains("GRANT pg_read_all_data"), "{fixes}");
    assert!(fixes.contains("GRANT USAGE ON SCHEMA \"cron\""), "{fixes}");
    assert!(
        fixes.contains("GRANT USAGE ON SCHEMA \"newsletter\""),
        "{fixes}"
    );
    assert!(fixes.contains("CREATE POLICY"), "{fixes}");
    // A user schema keeps its tables listed; only their rows are unknown,
    // so the reason counts the tables the role cannot SELECT.
    assert!(
        coverage_of(&report, "schema:newsletter")
            .unwrap()
            .reason
            .contains("lacks SELECT on 1 table"),
        "{}",
        coverage_of(&report, "schema:newsletter").unwrap().reason
    );

    // A section it cannot see is absent, never zero.
    assert_eq!(report.auth.users, None);
    assert_eq!(report.auth.identities_by_provider, None);
    assert_eq!(report.storage.buckets, None);
    assert_eq!(report.cron_jobs, None);
    assert_eq!(report.summary.storage_objects, None);
    let json = report.to_json();
    for forbidden in [
        "\"users\": 0",
        "\"users\":0",
        "\"buckets\": []",
        "\"cron_jobs\": []",
        "\"identities_by_provider\": []",
    ] {
        assert!(!json.contains(forbidden), "the JSON contains {forbidden}");
    }
    // Read-only throughout, as before.
    assert!(report.read_only.transaction_read_only);
    assert!(report.read_only.session_read_only);
    assert!(report.read_only.no_transaction_id_assigned);
    assert_eq!(report.read_only.role, role);

    // Now fix it exactly as the blocked sections asked, and every section
    // becomes inspected with the real counts.
    let grant = format!(
        "GRANT USAGE ON SCHEMA cron, newsletter TO {role}; \
         GRANT SELECT ON ALL TABLES IN SCHEMA cron, newsletter TO {role}; \
         CREATE POLICY cratefield_inspect_read ON auth.users FOR SELECT TO {role} USING (true); \
         CREATE POLICY cratefield_inspect_read ON auth.identities FOR SELECT TO {role} USING \
         (true); \
         CREATE POLICY cratefield_inspect_read ON storage.buckets FOR SELECT TO {role} USING \
         (true); \
         CREATE POLICY cratefield_inspect_read ON storage.objects FOR SELECT TO {role} USING \
         (true); \
         CREATE POLICY cratefield_inspect_read ON cron.job FOR SELECT TO {role} USING (true);"
    );
    let pool = sqlx::PgPool::connect(&db.url).await.expect("connect");
    sqlx::raw_sql(&grant).execute(&pool).await.expect("grants");
    pool.close().await;

    let report = inspect(&options).await.expect("inspect after grants");
    for name in [
        "auth",
        "storage.buckets",
        "storage.objects",
        "cron",
        "schema:newsletter",
    ] {
        assert_eq!(
            coverage_of(&report, name).map(|entry| entry.coverage),
            Some(SourceStatus::Inspected),
            "{name}: {:?}",
            report.coverage.sections
        );
    }
    assert_eq!(report.auth.users, Some(3));
    assert_eq!(
        report.auth.identities_by_provider.as_ref().map(Vec::len),
        Some(3)
    );
    assert_eq!(report.storage.buckets.as_ref().map(Vec::len), Some(2));
    assert_eq!(report.summary.storage_objects, Some(3));
    assert_eq!(report.cron_jobs.as_ref().map(Vec::len), Some(1));
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.kind == "visibility"),
        "no visibility blocker once every section is visible"
    );

    // A restrictive policy on top of the permissive `USING (true)`
    // policies hides the rows again: rows are visible through policies only
    // if every applicable restrictive SELECT/ALL policy also lets every row
    // through (issue #723).
    let pool = sqlx::PgPool::connect(&db.url).await.expect("connect");
    sqlx::raw_sql(&format!(
        "CREATE POLICY cratefield_inspect_deny ON auth.users AS RESTRICTIVE FOR SELECT TO {role} \
         USING (false);"
    ))
    .execute(&pool)
    .await
    .expect("a restrictive policy");
    pool.close().await;

    let report = inspect(&options)
        .await
        .expect("inspect with a restrictive policy");
    assert!(
        not_visible(&report, "auth"),
        "a restrictive policy hides the rows again: {:?}",
        report.coverage.sections
    );
    assert_eq!(report.auth.users, None);

    drop_roles(&db.url, &owner, &role).await;
    db.finish().await;
}

#[tokio::test]
async fn a_write_through_the_session_is_refused_and_nothing_changes() {
    let Some(db) = fixture_db("supabase_write").await else {
        return;
    };
    // Even as the superuser: the guards are the session's, not the role's.
    let mut session = ReadOnlySession::open(&Secret::new(db.url.clone()))
        .await
        .expect("open");
    let refused = session
        .execute_for_test("INSERT INTO public.audit_log (message) VALUES ('written')")
        .await
        .expect_err("a write is refused");
    assert!(
        refused.to_string().contains("read-only transaction"),
        "{refused}"
    );
    drop(session);

    let mut session = ReadOnlySession::open(&Secret::new(db.url.clone()))
        .await
        .expect("open");
    let refused = session
        .execute_for_test("CREATE TABLE public.created_by_inspect (id int)")
        .await
        .expect_err("DDL is refused");
    assert!(
        refused.to_string().contains("read-only transaction"),
        "{refused}"
    );
    drop(session);

    let pool = sqlx::PgPool::connect(&db.url).await.expect("connect");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM public.audit_log")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 2);
    let created: bool =
        sqlx::query_scalar("SELECT to_regclass('public.created_by_inspect') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("lookup");
    assert!(!created);
    pool.close().await;

    // And a full inspection leaves the evidence that it never wrote.
    let report = inspect(&InspectOptions::new(
        PROJECT_REF,
        Secret::new(db.url.clone()),
    ))
    .await
    .expect("inspect");
    assert!(report.read_only.no_transaction_id_assigned);
    assert!(report.read_only.transaction_read_only);
    // The superuser can write, and the report says so.
    assert!(report.read_only.role_can_write);
    assert!(report.warnings.iter().any(|w| w.contains("superuser")));
    db.finish().await;
}

/// The Management API, answering by path.
struct FakeManagement;

#[async_trait]
impl HttpClient for FakeManagement {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let authorized = request
            .headers()
            .get(http::header::AUTHORIZATION)
            .is_some_and(|value| value == format!("Bearer {MANAGEMENT_TOKEN}").as_str());
        let path = request.uri().path().to_owned();
        let (status, body) = if !authorized {
            (401, r#"{"message":"Unauthorized"}"#.to_owned())
        } else if path == format!("/v1/projects/{PROJECT_REF}/functions") {
            (
                200,
                r#"[{"id":"f2","slug":"stripe-webhook","name":"stripe-webhook","status":"ACTIVE","version":7,"verify_jwt":false},
                    {"id":"f1","slug":"send-welcome","name":"send-welcome","status":"ACTIVE","version":3,"verify_jwt":true}]"#
                    .to_owned(),
            )
        } else if path == format!("/v1/projects/{PROJECT_REF}/config/auth") {
            (
                200,
                format!(
                    r#"{{"external_email_enabled":true,"external_google_enabled":true,
                        "external_google_secret":"{AUTH_CONFIG_SECRET}","external_github_enabled":true,
                        "external_apple_enabled":false,"external_phone_enabled":false,
                        "mfa_totp_enroll_enabled":true,"smtp_pass":"{SMTP_PASSWORD}","jwt_exp":3600}}"#
                ),
            )
        } else {
            (404, "{}".to_owned())
        };
        Ok(http::Response::builder()
            .status(status)
            .body(Bytes::from(body))
            .expect("a response"))
    }
}

#[tokio::test]
async fn credentials_and_secrets_never_reach_the_report() {
    let Some(db) = fixture_db("supabase_secrets").await else {
        return;
    };
    let (role, password, url) = read_only_role(&db, "secrets").await;
    let mut options = InspectOptions::new(PROJECT_REF, Secret::new(url.clone()));
    options.management = Some(ManagementApi::new(
        Arc::new(FakeManagement),
        "https://api.supabase.test",
        Secret::new(MANAGEMENT_TOKEN),
    ));
    let report = inspect(&options).await.expect("inspect");

    assert_eq!(report.coverage.management_api, SourceStatus::Inspected);
    let slugs: Vec<&str> = report
        .edge_functions
        .functions
        .iter()
        .map(|function| function.slug.as_str())
        .collect();
    assert_eq!(slugs, ["send-welcome", "stripe-webhook"]);
    assert_eq!(
        report.auth.enabled_providers.as_deref(),
        Some(["email", "github", "google"].map(str::to_owned).as_slice())
    );
    assert_eq!(
        report.auth.enabled_mfa.as_deref(),
        Some(["totp".to_owned()].as_slice())
    );

    let out = format!("{}\n{}\n{report:?}", report.to_json(), report.to_markdown());
    for secret in [
        password.as_str(),
        url.as_str(),
        MANAGEMENT_TOKEN,
        AUTH_CONFIG_SECRET,
        SMTP_PASSWORD,
        // No email and no password hash, either.
        "@example.test",
        "$2a$10$",
    ] {
        assert!(!out.contains(secret), "the output contains {secret:?}");
    }
    // The connection appears as host and database only.
    assert_eq!(report.project.database, db.url.rsplit('/').next().unwrap());

    // A wrong token is an access error, and its message quotes no token.
    let mut options = InspectOptions::new(PROJECT_REF, Secret::new(url));
    options.management = Some(ManagementApi::new(
        Arc::new(FakeManagement),
        "https://api.supabase.test",
        Secret::new("sbp_wrong_token_also_never_printed"),
    ));
    let error = inspect(&options).await.expect_err("refused");
    assert!(error.is_access());
    assert!(!error.to_string().contains("sbp_"), "{error}");
    db.finish().await;
    drop_role(&role).await;
}

#[tokio::test]
async fn a_connection_failure_never_quotes_the_url() {
    let url = "postgres://inspect:hunter2-fixture-password@127.0.0.1:1/postgres";
    let error = inspect(&InspectOptions::new(PROJECT_REF, Secret::new(url)))
        .await
        .expect_err("nothing listens on port 1");
    assert!(matches!(error, InspectError::Connect(_)), "{error:?}");
    assert!(error.is_access());
    assert!(!error.to_string().contains("hunter2"), "{error}");
    assert!(!format!("{error:?}").contains("hunter2"));
}

/// A classifier with a fixed answer per expression, recording what it was
/// sent.
struct FakeJudge {
    seen: std::sync::Arc<tokio::sync::Mutex<Vec<String>>>,
}

#[async_trait]
impl Classifier for FakeJudge {
    fn profile(&self) -> ClassifierProfile {
        ClassifierProfile::new(Calibration::Classifier, 96_000)
    }

    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        cratefield_core::validate_questions(questions)?;
        self.seen.lock().await.push(state.to_owned());
        let (label, confidence) = if state.contains("interval") {
            ("custom_logic", 0.93)
        } else if state.contains("auth.uid()") {
            ("owner_only", 0.85)
        } else {
            ("public_read", 0.6)
        };
        let probabilities = BTreeMap::from([(label.to_owned(), confidence)]);
        Ok(questions
            .keys()
            .map(|id| (id.clone(), Answer::choice(label, probabilities.clone())))
            .collect())
    }
}

async fn classified(db: &TempDb, threshold: f32) -> (Report, Vec<String>) {
    let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let mut options = InspectOptions::new(PROJECT_REF, Secret::new(db.url.clone()));
    options.classifier = Some(Arc::new(FakeJudge { seen: seen.clone() }));
    options.classify_threshold = threshold;
    let report = inspect(&options).await.expect("inspect");
    let states = seen.lock().await.clone();
    (report, states)
}

#[tokio::test]
async fn the_classifier_places_only_what_the_rules_left_and_respects_the_threshold() {
    let Some(db) = fixture_db("supabase_judge").await else {
        return;
    };
    let (report, states) = classified(&db, 0.8).await;
    assert_eq!(report.coverage.policy_classifier, SourceStatus::Inspected);
    // Asked about exactly the policies no rule placed; the storage policies
    // belong to the storage phase, never the classifier.
    assert_eq!(states.len(), 3);
    let by_name = |name: &str| {
        report
            .policies
            .iter()
            .find(|policy| policy.name == name)
            .expect("the policy")
    };
    // At or above the 0.8 threshold: placed at the classifier's confidence.
    let grace = by_name("Archived projects stay visible for a grace period");
    assert_eq!(grace.pattern, PolicyPattern::CustomLogic);
    assert_eq!(grace.source, PolicySource::Classifier);
    assert!((grace.confidence - 0.93).abs() < 1e-6);
    let leave = by_name("Members can leave unless they own the team");
    assert_eq!(leave.pattern, PolicyPattern::OwnerOnly);
    assert!((leave.confidence - 0.85).abs() < 1e-6);
    // Below it: sent back to review with the classifier's label.
    let rows = by_name("Members can read their team's rows");
    assert_eq!(rows.pattern, PolicyPattern::NeedsReview);
    assert_eq!(rows.classifier_label.as_deref(), Some("public_read"));
    // A rule match is never sent and keeps confidence 1.0.
    let own = by_name("Users can update own profile.");
    assert_eq!(own.source, PolicySource::Rule);
    assert!((own.confidence - 1.0).abs() < f32::EPSILON);
    // Advisory only: every policy still needs its own disposition, and its
    // stub fails until someone writes the test.
    for policy in &report.policies {
        assert_eq!(policy.disposition, Disposition::Undecided);
        assert!(policy.test_stub.contains("todo!("), "{}", policy.test_stub);
        let finding = report
            .findings
            .iter()
            .find(|finding| {
                finding.id == format!("policy:{}.{}.{}", policy.schema, policy.table, policy.name)
            })
            .expect("a finding per policy");
        assert_eq!(finding.classification, Classification::NeedsWork);
    }
    // SQL and names only: no row value from the fixture reached it.
    for state in &states {
        for row_value in ["example.test", "Difference engine", "ada.png", "Analytical"] {
            assert!(!state.contains(row_value), "{state}");
        }
    }

    // A higher threshold (0.9) sends the 0.85 answer back to review; the
    // 0.93 answer stays placed.
    let (report, _) = classified(&db, 0.9).await;
    let leave = report
        .policies
        .iter()
        .find(|policy| policy.name == "Members can leave unless they own the team")
        .expect("the policy");
    assert_eq!(leave.pattern, PolicyPattern::NeedsReview);
    assert_eq!(leave.classifier_label.as_deref(), Some("owner_only"));
    let grace = report
        .policies
        .iter()
        .find(|policy| policy.name == "Archived projects stay visible for a grace period")
        .expect("the policy");
    assert_eq!(grace.pattern, PolicyPattern::CustomLogic);
    db.finish().await;
}

/// A cron-shaped schema for the managed-policy test, created in its own
/// database so the shared fixture and the read-only-role grants stay
/// untouched (sibling PR #723 owns those grants).
const MANAGED_FIXTURE: &str = "\
    CREATE SCHEMA cron; \
    CREATE TABLE cron.job (jobid bigint PRIMARY KEY, jobname text, schedule text NOT NULL, \
     command text NOT NULL, username text DEFAULT CURRENT_USER, active boolean NOT NULL DEFAULT \
     true); \
    ALTER TABLE cron.job ENABLE ROW LEVEL SECURITY; \
    CREATE POLICY \"cron jobs are visible to their owner\" ON cron.job \
     FOR SELECT USING (username = CURRENT_USER);";

/// Issue #726: a policy on a Supabase-managed schema is audited but is never
/// a policy, a finding, or needs work.
#[tokio::test]
async fn a_managed_schema_policy_is_audited_but_never_a_finding() {
    let Some(db) = fixture_db("supabase_managed").await else {
        return;
    };
    let pool = sqlx::PgPool::connect(&db.url).await.expect("connect");
    sqlx::raw_sql(MANAGED_FIXTURE)
        .execute(&pool)
        .await
        .expect("the cron fixture loads");
    pool.close().await;
    let report = inspect(&InspectOptions::new(
        PROJECT_REF,
        Secret::new(db.url.clone()),
    ))
    .await
    .expect("inspect succeeds");

    let managed: Vec<String> = report
        .managed_policies
        .iter()
        .map(|policy| format!("{}.{}.{}", policy.schema, policy.table, policy.name))
        .collect();
    assert_eq!(managed, ["cron.job.cron jobs are visible to their owner"]);
    assert!(!report.policies.iter().any(|policy| policy.schema == "cron"));
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.object.contains("cron."))
    );
    // Still consistent: needs work counts exactly the needs-work findings.
    assert_eq!(
        report.summary.needs_work,
        report
            .findings
            .iter()
            .filter(|finding| finding.classification == Classification::NeedsWork)
            .count()
    );
    db.finish().await;
}

/// Issue #726: a storage policy attaches to the one bucket it names, in the
/// storage phase — never in `policies`, never a phase-`code` finding — and a
/// table with RLS and no policy is one informational (automatic) fact.
#[tokio::test]
async fn storage_policies_and_rls_without_a_policy_are_reported() {
    let Some(db) = fixture_db("supabase_storage").await else {
        return;
    };
    let report = inspect(&InspectOptions::new(
        PROJECT_REF,
        Secret::new(db.url.clone()),
    ))
    .await
    .expect("inspect succeeds");

    let avatars = report
        .storage
        .buckets
        .iter()
        .flatten()
        .find(|bucket| bucket.id == "avatars")
        .expect("the avatars bucket");
    let documents = report
        .storage
        .buckets
        .iter()
        .flatten()
        .find(|bucket| bucket.id == "documents")
        .expect("the documents bucket");
    let names: Vec<&str> = avatars
        .policies
        .iter()
        .map(|policy| policy.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "Avatar images are publicly accessible",
            "Users upload their own avatar",
        ]
    );
    assert!(documents.policies.is_empty());
    for policy in &avatars.policies {
        assert!(!policy.all_buckets);
        assert_eq!(policy.disposition, Disposition::Undecided);
        assert_eq!(policy.table, "storage.objects");
    }
    assert!(
        !report
            .policies
            .iter()
            .any(|policy| policy.schema == "storage")
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.kind == "policy" && finding.object.starts_with("storage."))
    );
    let storage_findings: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.kind == "storage_policy")
        .map(|finding| finding.id.as_str())
        .collect();
    assert_eq!(
        storage_findings,
        [
            "storage_policy:storage.objects.Avatar images are publicly accessible",
            "storage_policy:storage.objects.Users upload their own avatar",
        ]
    );
    for id in &storage_findings {
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.id == *id)
            .expect("the finding");
        assert_eq!(finding.phase, "storage");
        assert_eq!(finding.classification, Classification::NeedsWork);
    }

    let no_policy: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.kind == "rls_no_policy")
        .map(|finding| finding.object.as_str())
        .collect();
    assert_eq!(no_policy, ["public.audit_log"]);
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "rls_no_policy")
        .expect("the finding");
    assert_eq!(finding.classification, Classification::Automatic);
    assert_eq!(finding.phase, "code");
    assert!(finding.cratefield_equivalent.contains("service_role_only"));
    db.finish().await;
}
