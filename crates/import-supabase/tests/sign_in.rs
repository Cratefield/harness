//! Issue #659's acceptance criterion, end to end: the fixture project's
//! users, read by [`read_users`] and sent to the harness admin import,
//! sign in with the passwords they already had, an unconfirmed user stays
//! unconfirmed, and a second run imports nothing twice.
//!
//! The source is a throwaway Postgres named by `FZ_TEST_POSTGRES_URL`; the
//! target is the kit's in-memory `TestHarness` over the real `auth-core`
//! and `auth-password` modules — the same pair `auth-password`'s own
//! `an_imported_bcrypt_user_signs_in_and_is_upgraded` drives. So this skips,
//! saying why, only when no Postgres server is set.

use std::sync::Arc;

use cratefield_adapter_postgres::testing::{TempDb, base_url, skip_reason};
use cratefield_auth_core::{AuthCore, user_by_primary_email};
use cratefield_auth_password::Password;
use cratefield_core::MapConfig;
use cratefield_import_supabase::{ImportRecord, Secret, UsersOptions, read_users};
use cratefield_testing::{TestHarness, request, request_as};
use http::{Method, StatusCode};
use serde_json::json;
use sqlx::PgPool;

const FIXTURE: &str = include_str!("fixtures/supabase-project.sql");

const ADA: &str = "00000000-0000-4000-8000-000000000001";
const LINUS: &str = "00000000-0000-4000-8000-000000000003";
const ADA_EMAIL: &str = "ada@example.test";
const LINUS_EMAIL: &str = "linus@example.test";

/// A deterministic cost-4 bcrypt hash of [`LEGACY_PASSWORD`] — the same
/// pair `auth-password`'s own suite signs in with, generated once offline.
const LEGACY_PASSWORD: &str = "legacy-password-1";
const LEGACY_BCRYPT: &str = "$2b$04$.OGB/.SE/ueHAeqKBO2NC.Idt9kRB2ygG15erMmtNyb.8scW/Kmw2";

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const IMPORT: &str = "/v1/auth-core/admin/users/import";
const LOGIN: &str = "/v1/auth-password/login";

/// The fixture in a throwaway database, with the known bcrypt hash on the
/// user the source confirms (ada) and on the one it does not (linus): both
/// hold a password, and only the source's `email_confirmed_at` separates
/// them.
async fn source_db() -> Option<TempDb> {
    let Some(base) = base_url() else {
        eprintln!("skipping: {}", skip_reason());
        return None;
    };
    let db = TempDb::create(&base, "import_supabase_sign_in").await?;
    db.assert_postgres_16().await;
    let pool = PgPool::connect(&db.url).await.expect("connect");
    sqlx::raw_sql(FIXTURE)
        .execute(&pool)
        .await
        .expect("the fixture loads");
    sqlx::raw_sql(&format!(
        "UPDATE auth.users SET encrypted_password = '{LEGACY_BCRYPT}' \
         WHERE id IN ('{ADA}', '{LINUS}')"
    ))
    .execute(&pool)
    .await
    .expect("the known hash lands");
    pool.close().await;
    Some(db)
}

/// The kit's harness over the import route and the password login route,
/// with the admin token and the bcrypt opt-in the source's hashes need.
fn harness() -> TestHarness {
    TestHarness::with_ports(
        vec![Box::new(AuthCore::new()), Box::new(Password::new())],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("ADMIN_TOKEN", ADMIN),
                // The source's hashes are bcrypt; the login path accepts one
                // only when the deployment opts in (issue #650).
                ("AUTH_LEGACY_HASHES", "bcrypt"),
            ]));
        },
    )
}

/// The admin import document for a plan's records, as the route reads it.
fn import_body(records: &[ImportRecord]) -> String {
    json!({
        "dry_run": false,
        "merge_by_email": false,
        "users": serde_json::to_value(records).expect("records serialize"),
    })
    .to_string()
}

#[tokio::test]
async fn imported_fixture_users_sign_in_and_a_re_run_changes_nothing() {
    let Some(db) = source_db().await else {
        return;
    };
    let plan = read_users(&UsersOptions::new(Secret::new(db.url.clone())))
        .await
        .expect("read_users succeeds");
    let ada = plan
        .records
        .iter()
        .find(|record| record.external_id == ADA)
        .expect("ada");
    assert!(ada.email_verified, "the fixture confirms ada's address");
    assert_eq!(
        ada.password_hash.as_ref().map(Secret::expose),
        Some(LEGACY_BCRYPT)
    );
    let linus = plan
        .records
        .iter()
        .find(|record| record.external_id == LINUS)
        .expect("linus");
    assert!(
        !linus.email_verified,
        "the fixture leaves linus unconfirmed"
    );

    let kit = harness();
    let first = request_as(
        &kit.router,
        Method::POST,
        IMPORT,
        ADMIN,
        Some(&import_body(&plan.records)),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body());
    let first_doc = first.json();
    let first_results = first_doc["results"].as_array().expect("results");
    assert_eq!(first_results.len(), plan.records.len());
    for row in first_results {
        assert_eq!(row["status"].as_str(), Some("created"), "{first_doc}");
    }
    let first_subs: Vec<&str> = first_results
        .iter()
        .map(|row| row["sub"].as_str().expect("a created user has a sub"))
        .collect();

    // The confirmed user signs in with the password the source already
    // held; the first sign-in upgrades the stored hash (issue #650).
    let login = json!({"email": ADA_EMAIL, "password": LEGACY_PASSWORD}).to_string();
    let sign_in = request(&kit.router, Method::POST, LOGIN, Some(&login)).await;
    assert_eq!(sign_in.status, StatusCode::OK, "{:?}", sign_in.body());

    // The unconfirmed user stays unconfirmed: the harness stored the
    // source's own claim, and arriving with a password does not verify it.
    let imported = user_by_primary_email(&*kit.db, LINUS_EMAIL)
        .await
        .expect("query")
        .expect("linus was imported");
    assert!(
        !imported.primary_email_verified,
        "an unconfirmed source user must stay unverified"
    );
    let confirmed = user_by_primary_email(&*kit.db, ADA_EMAIL)
        .await
        .expect("query")
        .expect("ada was imported");
    assert!(confirmed.primary_email_verified);

    // The same records a second time write nothing: every row is
    // `unchanged` and hands back the sub the first run created.
    let second = request_as(
        &kit.router,
        Method::POST,
        IMPORT,
        ADMIN,
        Some(&import_body(&plan.records)),
    )
    .await;
    assert_eq!(second.status, StatusCode::OK, "{:?}", second.body());
    let second_doc = second.json();
    let second_results = second_doc["results"].as_array().expect("results");
    assert_eq!(second_results.len(), first_subs.len());
    for (row, sub) in second_results.iter().zip(&first_subs) {
        assert_eq!(row["status"].as_str(), Some("unchanged"), "{second_doc}");
        assert_eq!(row["sub"].as_str(), Some(*sub), "{second_doc}");
    }

    db.finish().await;
}
