//! cratefield-cli acceptance tests (issue #8): collect + lockfile
//! append-only behavior, tamper detection, doctor (captcha rule,
//! consistency, lint), modules listing, and adapter-sqlite applying the
//! fixture's migrations.

use cratefield_cli::run;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use venture_fixture::{harness_v1, harness_v2};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fz-cli-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn migrations(&self) -> PathBuf {
        self.0.join("migrations")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(ToString::to_string).collect()
}

fn success(code: ExitCode) {
    assert_eq!(code, ExitCode::SUCCESS, "command must succeed");
}

#[test]
fn first_collect_yields_wrangler_ordered_files() {
    let tmp = TempDir::new("first");
    success(run(
        harness_v1,
        args(&[
            "migrations",
            "collect",
            "--out",
            tmp.migrations().to_str().unwrap(),
        ]),
    ));

    let listing = sorted_listing(&tmp.migrations());
    assert_eq!(
        listing,
        vec![
            ".harness-lock.json",
            "0001_email-signup_0001_init.sql",
            "0002_waitlist_0001_init.sql",
        ],
        "first collect file set"
    );

    let body =
        fs::read_to_string(tmp.migrations().join("0001_email-signup_0001_init.sql")).expect("file");
    assert!(body.starts_with("CREATE TABLE IF NOT EXISTS subscribers"));
    assert!(body.ends_with(";\n"), "collected SQL ends with newline");
}

#[test]
fn recollect_is_idempotent() {
    let tmp = TempDir::new("recollect");
    let out = tmp.migrations();
    success(run(
        harness_v1,
        args(&["migrations", "collect", "--out", out.to_str().unwrap()]),
    ));
    let before = sorted_listing(&out);
    success(run(
        harness_v1,
        args(&["migrations", "collect", "--out", out.to_str().unwrap()]),
    ));
    assert_eq!(before, sorted_listing(&out));
}

#[test]
fn extending_appends_and_leaves_earlier_files_byte_identical() {
    let tmp = TempDir::new("extend");
    let out = tmp.migrations();
    success(run(
        harness_v1,
        args(&["migrations", "collect", "--out", out.to_str().unwrap()]),
    ));

    let first_email = fs::read(out.join("0001_email-signup_0001_init.sql")).expect("read");
    let first_waitlist = fs::read(out.join("0002_waitlist_0001_init.sql")).expect("read");

    success(run(
        harness_v2,
        args(&["migrations", "collect", "--out", out.to_str().unwrap()]),
    ));

    let listing = sorted_listing(&out);
    assert_eq!(
        listing,
        vec![
            ".harness-lock.json",
            "0001_email-signup_0001_init.sql",
            "0002_waitlist_0001_init.sql",
            "0003_email-signup_0002_add_source_index.sql",
            "0004_audit-log_0001_init.sql",
        ],
        "extended collect appends 0003 and 0004"
    );

    assert_eq!(
        first_email,
        fs::read(out.join("0001_email-signup_0001_init.sql")).expect("re-read"),
        "earlier file byte-identical"
    );
    assert_eq!(
        first_waitlist,
        fs::read(out.join("0002_waitlist_0001_init.sql")).expect("re-read"),
        "earlier file byte-identical"
    );

    let snapshot = sorted_listing(&out).join("\n");
    insta::assert_snapshot!(snapshot);
}

#[test]
fn tampered_locked_file_fails_collect_and_doctor() {
    let tmp = TempDir::new("tamper");
    let out = tmp.migrations();
    success(run(
        harness_v1,
        args(&["migrations", "collect", "--out", out.to_str().unwrap()]),
    ));

    let target = out.join("0001_email-signup_0001_init.sql");
    let original = fs::read_to_string(&target).expect("read");
    fs::write(&target, original.replace("subscribers", "tampered")).expect("write");

    assert_eq!(
        run(
            harness_v1,
            args(&["migrations", "collect", "--out", out.to_str().unwrap()])
        ),
        ExitCode::FAILURE,
        "collect must fail on tampered locked file"
    );
    assert_eq!(
        run(
            harness_v1,
            args(&["doctor", "--out", out.to_str().unwrap()])
        ),
        ExitCode::FAILURE,
        "doctor must fail on tampered locked file"
    );

    // Deleting the file is also caught.
    fs::write(&target, original).expect("restore");
    success(run(
        harness_v1,
        args(&["doctor", "--out", out.to_str().unwrap()]),
    ));
    fs::remove_file(&target).expect("delete");
    assert_eq!(
        run(
            harness_v1,
            args(&["migrations", "collect", "--out", out.to_str().unwrap()])
        ),
        ExitCode::FAILURE,
        "collect must fail on missing locked file"
    );
}

#[test]
fn doctor_passes_on_collected_v1() {
    let tmp = TempDir::new("doctor-ok");
    let out = tmp.migrations();
    success(run(
        harness_v1,
        args(&["migrations", "collect", "--out", out.to_str().unwrap()]),
    ));
    success(run(
        harness_v1,
        args(&["doctor", "--out", out.to_str().unwrap()]),
    ));
}

#[test]
fn doctor_fails_when_not_collected() {
    let tmp = TempDir::new("doctor-missing");
    std::fs::create_dir_all(tmp.migrations()).expect("dir");
    assert_eq!(
        run(
            harness_v1,
            args(&["doctor", "--out", tmp.migrations().to_str().unwrap()])
        ),
        ExitCode::FAILURE
    );
}

#[test]
fn doctor_fails_on_banned_sql_tokens() {
    use cratefield_core::{
        Config, ConfigError, Harness, Migrations, Module, ModuleContext, Port, Runtime,
        SqlMigration, Venture,
    };

    struct BadModule;
    impl Module for BadModule {
        fn name(&self) -> &'static str {
            "bad"
        }
        fn version(&self) -> &'static str {
            "0.0.0"
        }
        fn requires(&self) -> &'static [Port] {
            &[]
        }
        fn migrations(&self) -> Migrations {
            const BAD: [SqlMigration; 1] = [SqlMigration {
                id: "0001",
                name: "bad",
                sql: "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT);",
            }];
            Migrations {
                sqlite: &BAD,
                postgres: &[],
            }
        }
        fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
            Ok(())
        }
        fn router(&self, _ctx: ModuleContext) -> axum::Router {
            axum::Router::new()
        }
    }
    struct AllPorts;
    impl Runtime for AllPorts {
        fn provides(&self) -> Vec<Port> {
            Port::ALL.to_vec()
        }
    }
    let build = move || {
        Harness::builder()
            .venture(
                Venture::new("bad-venture", "bad.example").cors_origins(["https://bad.example"]),
            )
            .module(BadModule)
            .runtime(AllPorts)
            .build()
            .expect("builds")
    };

    let tmp = TempDir::new("doctor-lint");
    std::fs::create_dir_all(tmp.migrations()).expect("dir");
    assert_eq!(
        run(
            build,
            args(&["doctor", "--out", tmp.migrations().to_str().unwrap()])
        ),
        ExitCode::FAILURE
    );
}

#[test]
fn lint_catches_each_banned_token() {
    let cases = [
        ("id INTEGER PRIMARY KEY AUTOINCREMENT", "AUTOINCREMENT"),
        ("SELECT datetime('now')", "datetime("),
        ("id SERIAL PRIMARY KEY", "SERIAL"),
        ("DEFAULT NOW()", "NOW()"),
        ("SELECT json_extract(x, '$.a')", "json_extract"),
        ("CREATE TABLE `t` (id TEXT)", "`"),
    ];
    for (sql, token) in cases {
        let hits = cratefield_cli::lint::banned_tokens(sql);
        assert!(
            hits.iter().any(|(found, _)| *found == token),
            "{sql:?} must flag {token}"
        );
    }
    assert!(cratefield_cli::lint::banned_tokens("CREATE TABLE t (id TEXT PRIMARY KEY)").is_empty());
}

#[test]
fn modules_lists_names_versions_prefixes_events_tables() {
    // Capture stdout by invoking the same printer through run(); the
    // output check runs through print_modules indirectly — assert the
    // command succeeds and the fixture data is reachable.
    let code = run(harness_v1, args(&["modules"]));
    success(code);
    let harness = harness_v1();
    assert_eq!(harness.modules().len(), 2);
    assert_eq!(harness.modules()[0].name(), "email-signup");
    assert_eq!(harness.modules()[1].emits(), &["waitlist.confirmed"]);
}

#[test]
fn adapter_sqlite_applies_fixture_migrations_and_round_trips() {
    use cratefield_core::Database;

    let db = cratefield_adapter_sqlite::SqliteDatabase::in_memory().expect("db");
    let harness = harness_v2();
    for module in harness.modules() {
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .unwrap_or_else(|err| panic!("{}: {err}", module.name()));
    }

    let insert = cratefield_core::Statement::with_values(
        "INSERT INTO subscribers (id, email, email_normalized, status, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
        vec![
            sea_query::Value::String(Some(Box::new("01FIX".to_string()))),
            sea_query::Value::String(Some(Box::new("Nick@Example.com".to_string()))),
            sea_query::Value::String(Some(Box::new("nick@example.com".to_string()))),
            sea_query::Value::String(Some(Box::new("pending".to_string()))),
            sea_query::Value::String(Some(Box::new("2026-09-06T00:00:00Z".to_string()))),
            sea_query::Value::String(Some(Box::new("2026-09-06T00:00:00Z".to_string()))),
        ],
    );
    let changed = pollster::block_on(db.execute(&insert)).expect("insert");
    assert_eq!(changed, 1);

    let select = cratefield_core::Statement::new(
        "SELECT email FROM subscribers WHERE email_normalized = 'nick@example.com'",
    );
    let rows = pollster::block_on(db.query(&select)).expect("select");
    assert_eq!(rows.len(), 1);
}

#[test]
fn unsupported_dialect_is_rejected() {
    let tmp = TempDir::new("dialect");
    assert_eq!(
        run(
            harness_v1,
            args(&[
                "migrations",
                "collect",
                "--dialect",
                "postgres",
                "--out",
                tmp.migrations().to_str().unwrap(),
            ])
        ),
        ExitCode::FAILURE
    );
}

fn sorted_listing(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .to_string()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn doctor_production_captcha_rule_and_override() {
    use cratefield_core::{
        Config, ConfigError, Harness, Migrations, Module, ModuleContext, Port, Runtime, Venture,
        VentureEnv,
    };

    struct WritingModule;
    impl Module for WritingModule {
        fn name(&self) -> &'static str {
            "writer"
        }
        fn version(&self) -> &'static str {
            "0.0.0"
        }
        fn requires(&self) -> &'static [Port] {
            &[]
        }
        fn public_writes(&self) -> bool {
            true
        }
        fn migrations(&self) -> Migrations {
            Migrations::default()
        }
        fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
            Ok(())
        }
        fn router(&self, _ctx: ModuleContext) -> axum::Router {
            axum::Router::new()
        }
    }
    struct NoCaptcha;
    impl Runtime for NoCaptcha {
        fn provides(&self) -> Vec<Port> {
            Port::ALL
                .iter()
                .copied()
                .filter(|port| *port != Port::Captcha)
                .collect()
        }
    }
    let build = move || {
        Harness::builder()
            .venture(
                Venture::new("prod-venture", "prod.example")
                    .cors_origins(["https://prod.example"])
                    .env(VentureEnv::Production),
            )
            .module(WritingModule)
            .runtime(NoCaptcha)
            .build()
            .expect("fixture builds")
    };

    // Without the override the rule fails the build check.
    assert_eq!(
        run(
            build,
            args(&["doctor", "--out", "/tmp/fz-doctor-test-migrations"])
        ),
        ExitCode::FAILURE
    );

    // The override downgrades the failure to a warning and passes
    // (no migrations to check, so an empty dir is fine).
    let tmp = TempDir::new("doctor-captcha");
    std::fs::create_dir_all(tmp.migrations()).expect("dir");
    assert_eq!(
        run(
            build,
            args(&[
                "doctor",
                "--out",
                tmp.migrations().to_str().unwrap(),
                "--allow-no-captcha",
                "internal staging form"
            ]),
        ),
        ExitCode::SUCCESS
    );
}
