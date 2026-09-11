//! Acceptance for `fz migrations apply` (issue #18): the featureless
//! build refuses with a clear message and never dials; the
//! `postgres`-feature build applies the fixture's migrations to a real
//! Postgres 16 (gated on `FZ_TEST_POSTGRES_URL`).

use cratefield_cli::apply::apply;
use venture_fixture::harness_v1;

#[test]
fn apply_rejects_unsupported_dialects() {
    let err = apply(
        &harness_v1(),
        "sqlite",
        "postgres://x",
        false,
        false,
        None,
        false,
    )
    .expect_err("sqlite apply is refused");
    assert!(err.contains("not supported for apply"), "message: {err}");
}

/// `--url` means two different databases depending on the flags, and the
/// combination that shipped in an early cut of #30 — fleet reconciliation
/// as the *default* — exited zero having applied nothing. These refuse the
/// combinations that cannot mean one thing, before anything dials.
#[test]
fn contradictory_apply_flags_are_refused_before_dialling() {
    let err = apply(
        &harness_v1(),
        "postgres",
        "postgres://leak:supersecret@127.0.0.1:1/none",
        true,
        true,
        None,
        false,
    )
    .expect_err("--plan with --fleet is refused");
    assert!(err.contains("contradict"), "message: {err}");
    assert!(
        !err.contains("supersecret"),
        "and never echoes the url: {err}"
    );

    let err = apply(
        &harness_v1(),
        "postgres",
        "postgres://leak:supersecret@127.0.0.1:1/none",
        false,
        false,
        None,
        true,
    )
    .expect_err("--strict without --fleet is refused");
    assert!(err.contains("--fleet"), "message: {err}");
    assert!(
        !err.contains("supersecret"),
        "and never echoes the url: {err}"
    );
}

#[cfg(not(feature = "postgres"))]
#[test]
fn apply_without_the_feature_fails_with_build_instructions() {
    let err = apply(
        &harness_v1(),
        "postgres",
        "postgres://x",
        false,
        false,
        None,
        false,
    )
    .expect_err("featureless build refuses");
    assert!(err.contains("`postgres` feature"), "message: {err}");
    assert!(err.contains("wrangler"), "points at the D1 flow: {err}");
}

#[cfg(feature = "postgres")]
mod on_postgres {
    use cratefield_cli::apply::apply;
    use cratefield_cli::run;
    use sqlx::Executor as _;
    use std::process::ExitCode;
    use venture_fixture::{harness_v1, harness_v2};

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(ToString::to_string).collect()
    }

    fn base_url() -> Option<String> {
        std::env::var("FZ_TEST_POSTGRES_URL")
            .ok()
            .map(|url| url.trim().to_owned())
            .filter(|url| !url.is_empty())
    }

    struct TempDb {
        url: String,
        database: String,
    }

    /// sqlx (runtime-tokio) needs a runtime; the CLI under test starts its
    /// own, so every helper runs on a private one that is dropped before
    /// the synchronous `run()` calls.
    fn with_runtime<T>(fut: impl std::future::Future<Output = T>) -> T {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(fut)
    }

    async fn create_db(tag: &str) -> Option<TempDb> {
        let base = base_url()?;
        let admin = sqlx::PgPool::connect(&base).await.expect("connect admin");
        let database = format!("fz_accept_{tag}_{}", std::process::id());
        admin
            .execute(format!(r#"CREATE DATABASE "{database}""#).as_str())
            .await
            .expect("create throwaway db");
        admin.close().await;
        let path = base
            .rsplit_once('/')
            .map(|(path, _database)| path.to_owned())
            .expect("url names a database");
        Some(TempDb {
            url: format!("{path}/{database}"),
            database,
        })
    }

    async fn drop_db(temp: &TempDb) {
        let base = base_url().expect("set in create_db");
        let dropper = sqlx::PgPool::connect(&base).await.expect("reconnect admin");
        dropper
            .execute(
                format!(
                    r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
                    temp.database
                )
                .as_str(),
            )
            .await
            .expect("drop throwaway db");
        dropper.close().await;
    }

    async fn tracked_migrations(url: &str) -> i64 {
        let db = sqlx::PgPool::connect(url).await.expect("connect db");
        let count = sqlx::query_scalar("SELECT COUNT(*) FROM harness_migrations")
            .fetch_one(&db)
            .await
            .expect("tracking readable");
        db.close().await;
        count
    }

    /// Whether the tracking table exists at all — the question that tells
    /// "applied nothing" apart from "applied and recorded nothing".
    async fn has_tracking(url: &str) -> bool {
        let db = sqlx::PgPool::connect(url).await.expect("connect db");
        let present: bool =
            sqlx::query_scalar("SELECT to_regclass('harness_migrations') IS NOT NULL")
                .fetch_one(&db)
                .await
                .expect("regclass is readable");
        db.close().await;
        present
    }

    #[test]
    fn apply_reapply_and_extend_through_the_cli() {
        let Some(temp) = with_runtime(create_db("cli")) else {
            eprintln!(
                "SKIPPED: FZ_TEST_POSTGRES_URL is not set (CI provides a postgres:16 \
                 service container)"
            );
            return;
        };

        // v1 applies, v2 appends later migrations into the same database —
        // the venture lifecycle from the architecture's self-hosted path.
        for harness in [harness_v1, harness_v2] {
            let argv = args(&[
                "migrations",
                "apply",
                "--dialect",
                "postgres",
                "--url",
                &temp.url,
            ]);
            assert_eq!(
                run(harness, argv.clone()),
                ExitCode::SUCCESS,
                "apply succeeds"
            );
            assert_eq!(run(harness, argv), ExitCode::SUCCESS, "re-apply is a no-op");
        }

        assert_eq!(
            with_runtime(tracked_migrations(&temp.url)),
            4,
            "v1 (2 modules) + v2 (2 added migrations)"
        );
        with_runtime(drop_db(&temp));
    }

    /// The regression this pair exists for: `apply` without `--fleet` must
    /// migrate the database `--url` names, and `--fleet` must *not* — it
    /// reconciles the tenants that database registers, each against its
    /// own. An early cut of #30 wired the fleet path to the default, so
    /// `fz migrations apply --url <venture>` reconciled an empty registry
    /// and exited zero with the venture unmigrated. Asserting only one
    /// direction would not have caught it: the fleet path "worked".
    #[test]
    fn fleet_reconciles_the_registry_and_leaves_the_control_database_alone() {
        let Some(temp) = with_runtime(create_db("fleet")) else {
            eprintln!(
                "SKIPPED: FZ_TEST_POSTGRES_URL is not set (CI provides a postgres:16 \
                 service container)"
            );
            return;
        };

        let fleet = args(&[
            "migrations",
            "apply",
            "--dialect",
            "postgres",
            "--fleet",
            "--url",
            &temp.url,
        ]);
        assert_eq!(
            run(harness_v1, fleet),
            ExitCode::SUCCESS,
            "an empty registry is not an error"
        );
        assert!(
            !with_runtime(has_tracking(&temp.url)),
            "--fleet reconciles registered tenants, so the control database itself \
             has no harness_migrations"
        );

        let plain = args(&[
            "migrations",
            "apply",
            "--dialect",
            "postgres",
            "--url",
            &temp.url,
        ]);
        assert_eq!(run(harness_v1, plain), ExitCode::SUCCESS, "apply succeeds");
        assert!(
            with_runtime(has_tracking(&temp.url)),
            "and without --fleet it applies to the database --url names"
        );

        with_runtime(drop_db(&temp));
    }

    #[test]
    fn connection_failures_never_echo_the_url() {
        let err = apply(
            &harness_v1(),
            "postgres",
            "postgres://leak:supersecret@127.0.0.1:1/none",
            false,
            false,
            None,
            false,
        )
        .expect_err("port 1 refuses connections");
        assert!(
            !err.contains("supersecret"),
            "the connection string is never echoed: {err}"
        );
    }
}
