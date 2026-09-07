//! Acceptance for `fz data export` / `fz data import` (issue #21): a
//! seeded SQLite database (the D1 stand-in — no Cloudflare credentials
//! exist in CI, so the wrangler leg is the documented manual step in
//! `docs/DATA-MOVE.md`, not a faked call) exported to manifest + JSONL,
//! imported into a real Postgres 16, verified by row counts and a
//! per-table content checksum. The refusal, `--append`, tamper and
//! `--plan` paths are exercised on the same fixture.

use factory0_cli::run;
use factory0_core::{Database, Statement};
#[cfg(feature = "postgres")]
use sea_query::Value as Sea;
use std::path::PathBuf;
use std::process::ExitCode;
use venture_fixture::harness_v1;

use factory0_adapter_sqlite::SqliteDatabase;

/// A unique scratch directory per test; removed on drop (best effort —
/// a failure leaves it behind, which is fine under the system temp).
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fz_data_{tag}_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(ToString::to_string).collect()
}

/// The seeded D1 stand-in: subscribers with NULLs, quotes and unicode,
/// waitlist entries across every state. Statement binds, never string
/// interpolation.
#[allow(clippy::too_many_lines)]
fn seed_sqlite(db: &SqliteDatabase) {
    let subscriber = |id: &str,
                      email: &str,
                      status: &str,
                      source: Option<&str>,
                      locale: Option<&str>,
                      confirmed: Option<&str>| {
        Statement::with_values(
            "INSERT INTO subscribers (id, email, email_normalized, status, source, locale, \
             confirmed_at, unsubscribed_at, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, NULL, '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')",
            vec![
                id.into(),
                email.into(),
                email.into(),
                status.into(),
                source.into(),
                locale.into(),
                confirmed.into(),
            ],
        )
    };
    pollster::block_on(db.execute(&subscriber(
        "01SUBSCRIBER0000000000000001",
        "nick@example.com",
        "confirmed",
        Some("launch"),
        None,
        Some("2026-01-02T00:00:00Z"),
    )))
    .expect("seed 1");
    pollster::block_on(db.execute(&subscriber(
        "01SUBSCRIBER0000000000000002",
        "Üna-Ünexample@xn--Example.com",
        "unsubscribed",
        None,
        Some("de"),
        None,
    )))
    .expect("seed 2");
    pollster::block_on(db.execute(&subscriber(
        "01SUBSCRIBER0000000000000003",
        "o'brien@example.com",
        "pending",
        Some("it's \"quoted\""),
        None,
        None,
    )))
    .expect("seed 3");

    let entry = |id: &str,
                 email: &str,
                 product: &str,
                 status: &str,
                 position: Option<i64>,
                 code: Option<&str>,
                 referred_by: Option<&str>,
                 answers: Option<&str>,
                 confirmed: Option<&str>| {
        Statement::with_values(
            "INSERT INTO waitlist_entries (id, email, email_normalized, product, status, \
             position, referral_code, referred_by, referrals, answers, created_at, confirmed_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, '2026-01-01T00:00:00Z', ?)",
            vec![
                id.into(),
                email.into(),
                email.into(),
                product.into(),
                status.into(),
                position.into(),
                code.into(),
                referred_by.into(),
                answers.into(),
                confirmed.into(),
            ],
        )
    };
    pollster::block_on(db.execute(&entry(
        "01WAITLIST000000000000000001",
        "first@example.com",
        "kontinuum",
        "confirmed",
        Some(1),
        Some("KONTIN01"),
        None,
        None,
        Some("2026-01-01T01:00:00Z"),
    )))
    .expect("seed w1");
    pollster::block_on(db.execute(&entry(
        "01WAITLIST000000000000000002",
        "second@example.com",
        "kontinuum",
        "confirmed",
        Some(2),
        Some("KONTIN02"),
        Some("01WAITLIST000000000000000001"),
        Some(r#"{"size":"m"}"#),
        Some("2026-01-01T02:00:00Z"),
    )))
    .expect("seed w2");
    pollster::block_on(db.execute(&entry(
        "01WAITLIST000000000000000003",
        "third@example.com",
        "kontinuum",
        "pending",
        None,
        Some("PENDW003"),
        None,
        None,
        None,
    )))
    .expect("seed w3");
    pollster::block_on(db.execute(&entry(
        "01WAITLIST000000000000000004",
        "fourth@example.com",
        "undercover",
        "confirmed",
        Some(1),
        Some("UNDER01"),
        None,
        Some(r#"{"size":"l"}"#),
        Some("2026-01-01T04:00:00Z"),
    )))
    .expect("seed w4");
    pollster::block_on(db.execute(&entry(
        "01WAITLIST000000000000000005",
        "fünft@example.com",
        "undercover",
        "pending",
        None,
        Some("PENDW005"),
        None,
        None,
        None,
    )))
    .expect("seed w5");
}

/// Migrates and seeds a fresh SQLite file; returns its path.
fn seeded_sqlite(scratch: &Scratch, tag: &str) -> PathBuf {
    let path = scratch.path(&format!("{tag}.db"));
    let db = SqliteDatabase::open(path.to_string_lossy().as_ref()).expect("open sqlite");
    for module in harness_v1().modules() {
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .expect("fixture migrations apply");
    }
    seed_sqlite(&db);
    path
}

fn export(db: &std::path::Path, out: &std::path::Path, plan: bool) -> ExitCode {
    let mut argv = args(&["data", "export", "--db"]);
    argv.push(db.to_string_lossy().into_owned());
    argv.push("--out".to_owned());
    argv.push(out.to_string_lossy().into_owned());
    if plan {
        argv.push("--plan".to_owned());
    }
    run(harness_v1, argv)
}

fn manifest_of(bytes: &[u8]) -> serde_json::Value {
    let first = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    serde_json::from_slice(first).expect("manifest line")
}

#[test]
fn export_writes_manifest_and_records_and_is_deterministic() {
    let scratch = Scratch::new("export");
    let db_path = seeded_sqlite(&scratch, "venture");
    let out = scratch.path("data.jsonl");

    assert_eq!(export(&db_path, &out, false), ExitCode::SUCCESS, "export");
    let bytes = std::fs::read(&out).expect("export file");
    let manifest = manifest_of(&bytes);
    let tables: Vec<(String, u64)> = manifest["tables"]
        .as_array()
        .expect("tables")
        .iter()
        .map(|t| {
            (
                t["table"].as_str().expect("table").to_owned(),
                t["rows"].as_u64().expect("rows"),
            )
        })
        .collect();
    assert_eq!(
        tables,
        vec![
            ("subscribers".to_owned(), 3),
            ("waitlist_entries".to_owned(), 5)
        ],
        "lock order and counts"
    );
    for table in manifest["tables"].as_array().expect("tables") {
        let sha = table["sha256"].as_str().expect("sha256");
        assert_eq!(sha.len(), 64, "sha256 is hex: {sha}");
        assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!table["columns"].as_array().expect("columns").is_empty());
    }
    let lines: Vec<&[u8]> = bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), 1 + 3 + 5, "manifest + 8 records");
    let first_record: serde_json::Value = serde_json::from_slice(lines[1]).expect("record");
    assert_eq!(first_record["table"], "subscribers");
    assert!(first_record["row"]["id"].is_string());

    let again = scratch.path("data-again.jsonl");
    assert_eq!(export(&db_path, &again, false), ExitCode::SUCCESS);
    assert_eq!(
        std::fs::read(&again).expect("again"),
        bytes,
        "the same database exports byte-identically"
    );
}

#[test]
fn export_plan_writes_nothing() {
    let scratch = Scratch::new("plan");
    let db_path = seeded_sqlite(&scratch, "venture");
    let out = scratch.path("data.jsonl");
    assert_eq!(export(&db_path, &out, true), ExitCode::SUCCESS);
    assert!(!out.exists(), "--plan writes no file");
}

#[test]
fn export_refuses_a_database_without_the_tables() {
    let scratch = Scratch::new("empty");
    let empty = scratch.path("empty.db");
    SqliteDatabase::open(empty.to_string_lossy().as_ref()).expect("open");
    let err = export(&empty, &scratch.path("out.jsonl"), false);
    assert_eq!(err, ExitCode::FAILURE);
}

#[cfg(not(feature = "postgres"))]
#[test]
fn import_without_the_feature_fails_with_build_instructions() {
    let scratch = Scratch::new("featureless");
    let db_path = seeded_sqlite(&scratch, "venture");
    let out = scratch.path("data.jsonl");
    assert_eq!(export(&db_path, &out, false), ExitCode::SUCCESS);
    let mut argv = args(&["data", "import", "--url", "postgres://x/y"]);
    argv.push(out.to_string_lossy().into_owned());
    assert_eq!(run(harness_v1, argv), ExitCode::FAILURE);
}

#[cfg(feature = "postgres")]
fn sqlite_rows(db: &dyn Database, table: &str) -> factory0_core::Rows {
    pollster::block_on(db.query(&Statement::new(format!(
        "SELECT * FROM \"{table}\" ORDER BY id"
    ))))
    .expect("sqlite read back")
}

#[cfg(feature = "postgres")]
fn canonical_value(value: &Sea) -> String {
    match value {
        Sea::String(Some(v)) => format!("s:{v}"),
        Sea::Char(Some(v)) => format!("s:{v}"),
        Sea::Bool(Some(v)) => format!("i:{}", i64::from(*v)),
        Sea::TinyInt(Some(v)) => format!("i:{v}"),
        Sea::SmallInt(Some(v)) => format!("i:{v}"),
        Sea::Int(Some(v)) => format!("i:{v}"),
        Sea::BigInt(Some(v)) => format!("i:{v}"),
        Sea::TinyUnsigned(Some(v)) => format!("i:{v}"),
        Sea::SmallUnsigned(Some(v)) => format!("i:{v}"),
        Sea::Unsigned(Some(v)) => format!("i:{v}"),
        Sea::BigUnsigned(Some(v)) => format!("i:{v}"),
        _ => "null".to_owned(),
    }
}

#[cfg(feature = "postgres")]
fn table_checksum(rows: &factory0_core::Rows) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for row in &rows.rows {
        for name in row.column_names() {
            let value = row.get::<Sea>(name).unwrap_or(Sea::String(None));
            hasher.update(name.as_bytes());
            hasher.update([0x1f]);
            hasher.update(canonical_value(&value).as_bytes());
            hasher.update([0x1f]);
        }
        hasher.update([0x1e]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(feature = "postgres")]
mod on_postgres {
    use super::{Scratch, args, export, seeded_sqlite, sqlite_rows, table_checksum};
    use factory0_adapter_postgres::Postgres;
    use factory0_adapter_postgres::testing::TempDb;
    use factory0_cli::run;
    use factory0_core::{Database, Statement};
    use std::process::ExitCode;
    use venture_fixture::harness_v1;

    fn base_url() -> Option<String> {
        std::env::var("FZ_TEST_POSTGRES_URL")
            .ok()
            .map(|url| url.trim().to_owned())
            .filter(|url| !url.is_empty())
    }

    /// One runtime per test: a sqlx pool is bound to the reactor it was
    /// created on, so every async helper in the test runs here (the CLI
    /// under test still starts and drops its own).
    struct Rt(tokio::runtime::Runtime);

    impl Rt {
        fn new() -> Self {
            Self(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime builds"),
            )
        }

        fn block_on<T>(&self, fut: impl std::future::Future<Output = T>) -> T {
            self.0.block_on(fut)
        }
    }

    /// A migrated, empty Postgres target.
    fn migrated_target(rt: &Rt, tag: &str) -> Option<TempDb> {
        let temp = rt.block_on(async {
            let base = base_url()?;
            TempDb::create(&base, tag).await
        })?;
        let mut argv = args(&["migrations", "apply", "--dialect", "postgres", "--url"]);
        argv.push(temp.url.clone());
        assert_eq!(
            run(harness_v1, argv),
            ExitCode::SUCCESS,
            "fixture migrations apply to the target"
        );
        Some(temp)
    }

    fn import(url: &str, file: &std::path::Path, append: bool, plan: bool) -> ExitCode {
        let mut argv = args(&["data", "import", "--url", url]);
        if append {
            argv.push("--append".to_owned());
        }
        if plan {
            argv.push("--plan".to_owned());
        }
        argv.push(file.to_string_lossy().into_owned());
        run(harness_v1, argv)
    }

    fn count(rt: &Rt, db: &Postgres, table: &str) -> i64 {
        let rows = rt.block_on(async {
            db.query(&factory0_core::Statement::new(format!(
                "SELECT COUNT(*) AS n FROM \"{table}\""
            )))
            .await
            .expect("count")
        });
        rows.first()
            .and_then(|row| row.get::<i64>("n"))
            .expect("count row")
    }

    /// The full rehearsal: seed SQLite, export, import into a migrated
    /// Postgres, compare per-table counts AND a canonical content
    /// checksum of every row.
    #[test]
    fn round_trip_sqlite_to_postgres_matches_counts_and_checksum() {
        let rt = Rt::new();
        let Some(temp) = migrated_target(&rt, "roundtrip") else {
            eprintln!(
                "SKIPPED: FZ_TEST_POSTGRES_URL is not set (CI provides a postgres:16 \
                 service container)"
            );
            return;
        };
        let scratch = Scratch::new("roundtrip");
        let db_path = seeded_sqlite(&scratch, "venture");
        let out = scratch.path("data.jsonl");
        assert_eq!(export(&db_path, &out, false), ExitCode::SUCCESS);

        assert_eq!(import(&temp.url, &out, false, false), ExitCode::SUCCESS);

        let pg = rt.block_on(async { Postgres::connect(&temp.url).await.expect("connect") });
        let sqlite =
            factory0_adapter_sqlite::SqliteDatabase::open(db_path.to_string_lossy().as_ref())
                .expect("reopen sqlite");
        for table in ["subscribers", "waitlist_entries"] {
            assert_eq!(count(&rt, &pg, table), expected_rows(table), "{table}");
            let pg_rows = rt.block_on(async {
                pg.query(&Statement::new(format!(
                    "SELECT * FROM \"{table}\" ORDER BY id"
                )))
                .await
                .expect("pg read back")
            });
            assert_eq!(
                table_checksum(&pg_rows),
                table_checksum(&sqlite_rows(&sqlite, table)),
                "{table}: identical canonical content"
            );
        }
        rt.block_on(async { temp.finish().await });
    }

    fn expected_rows(table: &str) -> i64 {
        if table == "subscribers" { 3 } else { 5 }
    }

    async fn delta_source(db_path: &std::path::Path) {
        let db = factory0_adapter_sqlite::SqliteDatabase::open(db_path.to_string_lossy().as_ref())
            .expect("reopen sqlite");
        for id in [
            "01SUBSCRIBER0000000000000004",
            "01SUBSCRIBER0000000000000005",
        ] {
            db.execute(&Statement::with_values(
                "INSERT INTO subscribers (id, email, email_normalized, status, source, \
                 locale, confirmed_at, unsubscribed_at, created_at, updated_at) \
                 VALUES (?, ?, ?, 'pending', 'late', NULL, NULL, NULL, \
                 '2026-02-01T00:00:00Z', '2026-02-01T00:00:00Z')",
                vec![
                    id.into(),
                    format!("{id}@example.com").into(),
                    format!("{id}@example.com").into(),
                ],
            ))
            .await
            .expect("late insert");
        }
        db.execute(&Statement::new(
            "DELETE FROM subscribers WHERE id IN ('01SUBSCRIBER0000000000000001', \
             '01SUBSCRIBER0000000000000002', '01SUBSCRIBER0000000000000003')",
        ))
        .await
        .expect("drop the shipped rows");
        db.execute(&Statement::new("DELETE FROM waitlist_entries"))
            .await
            .expect("waitlist already shipped");
    }

    #[test]
    fn import_refuses_non_empty_tables_without_append_and_appends_with_it() {
        let rt = Rt::new();
        let Some(temp) = migrated_target(&rt, "append") else {
            eprintln!(
                "SKIPPED: FZ_TEST_POSTGRES_URL is not set (CI provides a postgres:16 \
                 service container)"
            );
            return;
        };
        let scratch = Scratch::new("append");
        let db_path = seeded_sqlite(&scratch, "venture");
        let out = scratch.path("data.jsonl");
        assert_eq!(export(&db_path, &out, false), ExitCode::SUCCESS);

        assert_eq!(import(&temp.url, &out, false, false), ExitCode::SUCCESS);
        let pg = rt.block_on(async { Postgres::connect(&temp.url).await.expect("connect") });
        assert_eq!(count(&rt, &pg, "subscribers"), 3);

        // Second import into the now non-empty tables: refused, and a
        // re-import of the SAME rows with --append must fail on the
        // primary keys rather than duplicate anything.
        assert_eq!(import(&temp.url, &out, false, false), ExitCode::FAILURE);
        assert_eq!(import(&temp.url, &out, true, false), ExitCode::FAILURE);
        assert_eq!(count(&rt, &pg, "subscribers"), 3, "nothing duplicated");

        // The real append: the source moved on — two fresh subscribers,
        // waitlist unchanged — and a delta export (fresh subscribers,
        // empty waitlist) appends without touching what the target
        // already holds. Full-table export re-shipping existing rows is
        // the PK violation above, by design.
        pollster::block_on(delta_source(&db_path));
        let out2 = scratch.path("data-2.jsonl");
        assert_eq!(export(&db_path, &out2, false), ExitCode::SUCCESS);
        assert_eq!(import(&temp.url, &out2, true, false), ExitCode::SUCCESS);
        assert_eq!(count(&rt, &pg, "subscribers"), 5);
        assert_eq!(count(&rt, &pg, "waitlist_entries"), 5);
        rt.block_on(async { temp.finish().await });
    }

    #[test]
    fn tampered_file_fails_the_sha256_check() {
        let rt = Rt::new();
        let Some(temp) = migrated_target(&rt, "tamper") else {
            eprintln!(
                "SKIPPED: FZ_TEST_POSTGRES_URL is not set (CI provides a postgres:16 \
                 service container)"
            );
            return;
        };
        let scratch = Scratch::new("tamper");
        let db_path = seeded_sqlite(&scratch, "venture");
        let out = scratch.path("data.jsonl");
        assert_eq!(export(&db_path, &out, false), ExitCode::SUCCESS);

        let mut bytes = std::fs::read(&out).expect("export");
        // Rewrite a data value without touching the manifest: the last
        // record line's email.
        let pos = bytes
            .windows(9)
            .rposition(|w| w == b"pending\"}")
            .expect("a pending status cell");
        bytes[pos] = b'Q';
        bytes[pos + 1] = b'Q';
        bytes[pos + 2] = b'Q';
        bytes[pos + 3] = b'Q';
        bytes[pos + 4] = b'Q';
        bytes[pos + 5] = b'Q';
        bytes[pos + 6] = b'Q';
        let tampered = scratch.path("tampered.jsonl");
        std::fs::write(&tampered, bytes).expect("write tampered");

        assert_eq!(
            import(&temp.url, &tampered, false, false),
            ExitCode::FAILURE
        );
        let pg = rt.block_on(async { Postgres::connect(&temp.url).await.expect("connect") });
        assert_eq!(count(&rt, &pg, "subscribers"), 0, "nothing was written");
        assert_eq!(
            count(&rt, &pg, "waitlist_entries"),
            0,
            "nothing was written"
        );
        rt.block_on(async { temp.finish().await });
    }

    #[test]
    fn plan_reports_the_target_state_and_writes_nothing() {
        let rt = Rt::new();
        let Some(temp) = migrated_target(&rt, "planpg") else {
            eprintln!(
                "SKIPPED: FZ_TEST_POSTGRES_URL is not set (CI provides a postgres:16 \
                 service container)"
            );
            return;
        };
        let scratch = Scratch::new("planpg");
        let db_path = seeded_sqlite(&scratch, "venture");
        let out = scratch.path("data.jsonl");
        assert_eq!(export(&db_path, &out, false), ExitCode::SUCCESS);

        assert_eq!(import(&temp.url, &out, false, true), ExitCode::SUCCESS);
        let pg = rt.block_on(async { Postgres::connect(&temp.url).await.expect("connect") });
        assert_eq!(count(&rt, &pg, "subscribers"), 0, "--plan wrote nothing");
        assert_eq!(
            count(&rt, &pg, "waitlist_entries"),
            0,
            "--plan wrote nothing"
        );

        // Import for real, then plan again: it must still write nothing.
        assert_eq!(import(&temp.url, &out, false, false), ExitCode::SUCCESS);
        assert_eq!(import(&temp.url, &out, false, true), ExitCode::SUCCESS);
        assert_eq!(count(&rt, &pg, "subscribers"), 3);
        rt.block_on(async { temp.finish().await });
    }

    #[test]
    fn a_foreign_export_file_is_refused_before_anything_touches_the_network() {
        let scratch = Scratch::new("foreign");
        let db_path = seeded_sqlite(&scratch, "venture");
        let out = scratch.path("data.jsonl");
        assert_eq!(export(&db_path, &out, false), ExitCode::SUCCESS);
        // Rewrite the manifest to claim a table this venture does not
        // have; import must refuse without connecting.
        let bytes = std::fs::read(&out).expect("export");
        let mut lines: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
        let mut manifest: serde_json::Value = serde_json::from_slice(lines[0]).expect("manifest");
        manifest["tables"][0]["table"] = serde_json::json!("not_a_venture_table");
        let serialized = serde_json::to_string(&manifest).expect("re-serialize");
        lines[0] = serialized.as_bytes();
        let foreign = scratch.path("foreign.jsonl");
        std::fs::write(&foreign, lines.join(&b"\n"[..])).expect("write foreign");

        assert_eq!(
            import("postgres://unreachable.invalid:1/x", &foreign, false, false),
            ExitCode::FAILURE
        );
        assert_eq!(
            import("postgres://unreachable.invalid:1/x", &out, false, false),
            ExitCode::FAILURE,
            "the unreachable server is still a failure, not a hang"
        );
    }
}

/// A venture with a sidecar has tables in its database that `fz` cannot
/// see (issue #66). Exporting them silently would hand someone an
/// artifact that looks complete, which is the one thing a data move must
/// never do.
#[test]
fn export_refuses_a_venture_with_sidecars_until_the_omission_is_acknowledged() {
    let scratch = Scratch::new("sidecar_export");
    let db_path = seeded_sqlite(&scratch, "venture");
    let out = scratch.path("data.jsonl");

    let mut argv = args(&[
        "--sidecars",
        r#"{"acme-pricing":"ACME"}"#,
        "data",
        "export",
        "--db",
    ]);
    argv.push(db_path.to_string_lossy().into_owned());
    argv.push("--out".to_owned());
    argv.push(out.to_string_lossy().into_owned());
    assert_eq!(
        run(harness_v1, argv.clone()),
        ExitCode::FAILURE,
        "an export that cannot see a sidecar's tables must not look complete"
    );
    assert!(!out.exists(), "nothing is written when the export refuses");

    // Acknowledged: it runs, and the artifact records what it left out.
    argv.push("--without-sidecar-tables".to_owned());
    assert_eq!(run(harness_v1, argv), ExitCode::SUCCESS);
    let manifest: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&out)
            .expect("export written")
            .lines()
            .next()
            .expect("manifest line"),
    )
    .expect("manifest is JSON");
    assert_eq!(
        manifest["omitted_sidecars"],
        serde_json::json!(["acme-pricing"]),
        "the export file is the audit record: it has to say what did not move"
    );
}

/// A mount naming a compiled-in module is a misconfiguration the runtime
/// papers over (it ignores the mount), so the doctor says it plainly.
#[test]
fn doctor_rejects_a_sidecar_mount_that_shadows_a_compiled_in_module() {
    let scratch = Scratch::new("sidecar_doctor");
    let migrations = scratch.path("migrations");
    let collect = args(&["migrations", "collect", "--out"])
        .into_iter()
        .chain([migrations.to_string_lossy().into_owned()])
        .collect::<Vec<_>>();
    assert_eq!(run(harness_v1, collect), ExitCode::SUCCESS);

    let doctor = |table: &str| {
        let mut argv = args(&["--sidecars", table, "doctor", "--out"]);
        argv.push(migrations.to_string_lossy().into_owned());
        run(harness_v1, argv)
    };
    // A sidecar the venture does not compile in: fine, warned about.
    assert_eq!(doctor(r#"{"acme-pricing":"ACME"}"#), ExitCode::SUCCESS);
    // One that shadows a compiled-in module: a failure, not a warning.
    assert_eq!(doctor(r#"{"email-signup":"ES"}"#), ExitCode::FAILURE);
    // A malformed table is a failure too, not a silent empty mount set.
    assert_eq!(doctor("not json"), ExitCode::FAILURE);
}
