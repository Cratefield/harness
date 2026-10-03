//! `fz import supabase inspect` (issue #658, ADR 0026): connects read-only
//! to a Supabase project and writes the migration report.
//!
//! The engine is `cratefield-import-supabase`, which reads Postgres through
//! sqlx and so is native-only. It is behind the `import-supabase` feature
//! for the reason `postgres` and `push-send` are: a venture links this
//! crate beside a wasm build, and that graph must never see sqlx or tokio.
//! Without the feature the command exists and says what to install — loud
//! absence, not a silently smaller `fz`.
//!
//! **Credentials.** The database URL comes from `--db-url` or
//! `SUPABASE_DB_URL`, the Management API token from `--management-token`
//! or `SUPABASE_ACCESS_TOKEN`, and `--classify` reads `TYPESAFE_API_KEY`
//! through the `TypeSafe` adapter's own `from_env`. `fz` never prompts (ADR
//! 0026, Decision 6), so a missing URL is a refusal naming the variable.
//! The values are held cleared-on-drop, never printed, and the report names
//! the database by host and database alone.

use std::path::{Path, PathBuf};

use crate::EnvVars;
use cratefield_core::Config;

/// The environment variable the database URL is read from.
pub const DB_URL_VAR: &str = "SUPABASE_DB_URL";
/// The environment variable the Management API token is read from.
pub const ACCESS_TOKEN_VAR: &str = "SUPABASE_ACCESS_TOKEN";

/// The report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Markdown, for a person.
    Markdown,
    /// JSON, for the later steps and the dashboard.
    Json,
}

/// Everything `fz import supabase inspect` was given.
#[derive(Debug, Clone)]
pub struct InspectArgs {
    /// The project ref.
    pub project: String,
    /// `--db-url`, if given.
    pub db_url: Option<String>,
    /// `--management-token`, if given.
    pub management_token: Option<String>,
    /// The format.
    pub format: Format,
    /// `--out`, if given.
    pub out: Option<PathBuf>,
    /// `--transfer-mbps`.
    pub transfer_mbps: u32,
    /// `--classify`.
    pub classify: bool,
    /// `--classify-threshold`.
    pub classify_threshold: f32,
}

/// Where each credential came from — the flag or the environment — with
/// the value itself never leaving this struct.
#[derive(Debug)]
pub struct Credentials {
    /// The database URL.
    pub db_url: Secret,
    /// The Management API token, if any.
    pub management_token: Option<Secret>,
    /// Notes for stderr: a credential given as a flag is in the shell
    /// history and the process list.
    pub notes: Vec<String>,
}

/// A string that prints as `[redacted]`. The engine has its own; this one
/// exists so the argument handling compiles without the feature.
#[derive(Clone)]
pub struct Secret(zeroize::Zeroizing<String>);

impl Secret {
    /// The value. Named `expose` so a reader has to notice.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Resolves the credentials from the flags, then `config` (the
/// environment). Never prompts.
///
/// # Errors
///
/// A refusal naming `SUPABASE_DB_URL` when no URL was given either way.
pub fn credentials(args: &InspectArgs, config: &dyn Config) -> Result<Credentials, String> {
    let mut notes = Vec::new();
    let db_url = match &args.db_url {
        Some(url) => {
            notes.push(format!(
                "note: --db-url puts the password in your shell history and the process list; \
                 prefer {DB_URL_VAR}"
            ));
            url.clone()
        }
        None => config.get(DB_URL_VAR).ok_or_else(|| {
            format!(
                "no database URL: set {DB_URL_VAR} to the read-only role's connection string \
                 (docs/import/supabase.md), or pass --db-url. fz never prompts"
            )
        })?,
    };
    let management_token = match &args.management_token {
        Some(token) => {
            notes.push(format!(
                "note: --management-token puts the token in your shell history and the process \
                 list; prefer {ACCESS_TOKEN_VAR}"
            ));
            Some(token.clone())
        }
        None => config.get(ACCESS_TOKEN_VAR),
    };
    Ok(Credentials {
        db_url: Secret(zeroize::Zeroizing::new(db_url)),
        management_token: management_token.map(|token| Secret(zeroize::Zeroizing::new(token))),
        notes,
    })
}

/// Runs the command: inspects, then writes the report to `--out` or
/// stdout.
///
/// # Errors
///
/// A refusal or an access error (connection, permission, a refused token):
/// the exit code is non-zero for those alone. Blockers are in the report
/// and the exit code is zero.
pub fn inspect(args: &InspectArgs) -> Result<(), String> {
    let credentials = credentials(args, &EnvVars)?;
    for note in &credentials.notes {
        eprintln!("{note}");
    }
    let rendered = run(args, &credentials)?;
    if let Some(path) = &args.out {
        write_report(path, &rendered.text)?;
        eprintln!("wrote {}: {}", path.display(), rendered.summary);
    } else {
        print!("{}", rendered.text);
    }
    Ok(())
}

fn write_report(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|err| format!("cannot write {}: {err}", path.display()))
}

/// The rendered report and its one-line summary.
pub struct Rendered {
    /// The report in the requested format.
    pub text: String,
    /// `N automatic, N needs work, N blockers`.
    pub summary: String,
}

#[cfg(feature = "import-supabase")]
fn run(args: &InspectArgs, credentials: &Credentials) -> Result<Rendered, String> {
    use cratefield_import_supabase as engine;
    use std::sync::Arc;

    let clock: Arc<dyn cratefield_core::Clock> = Arc::new(cratefield_runtime_native::TokioClock);
    let http: Arc<dyn cratefield_core::HttpClient> =
        Arc::new(cratefield_core::BoundedHttpClient::new(
            Arc::new(cratefield_runtime_native::ReqwestClient::new()),
            Arc::clone(&clock),
        ));
    let mut options = engine::InspectOptions::new(
        args.project.clone(),
        engine::Secret::new(credentials.db_url.expose()),
    );
    options.transfer_mbps = args.transfer_mbps;
    options.classify_threshold = args.classify_threshold;
    options.management = credentials.management_token.as_ref().map(|token| {
        engine::ManagementApi::new(
            Arc::clone(&http),
            engine::DEFAULT_API_BASE,
            engine::Secret::new(token.expose()),
        )
    });
    if args.classify {
        // TypeSafe (its judge, Jev) through the adapter's own reader, so
        // the key's name is the adapter's, not ours.
        let classifier = cratefield_adapter_typesafe::TypeSafe::from_env(
            Arc::clone(&http),
            Arc::clone(&clock),
        )
        .ok_or_else(|| {
            "--classify needs TYPESAFE_API_KEY (the TypeSafe adapter reads it); without it, \
             drop --classify and unplaced policies stay needs_review"
                .to_owned()
        })?;
        options.classifier = Some(Arc::new(classifier));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("cannot start the async runtime inspect needs: {err}"))?;
    let report = runtime
        .block_on(engine::inspect(&options))
        .map_err(|error| error.to_string())?;
    let s = &report.summary;
    let summary = format!(
        "{} automatic, {} needs work, {} blocker(s){}",
        s.automatic,
        s.needs_work,
        s.blockers,
        if s.ready { "" } else { " — not ready" }
    );
    Ok(Rendered {
        text: match args.format {
            Format::Json => report.to_json(),
            Format::Markdown => report.to_markdown(),
        },
        summary,
    })
}

#[cfg(not(feature = "import-supabase"))]
fn run(_args: &InspectArgs, _credentials: &Credentials) -> Result<Rendered, String> {
    Err(
        // As with `push-send`: an installed binary, never a feature on the
        // venture's dependency, whose wasm build must not see sqlx.
        "this `fz` was built without the `import-supabase` feature, so it cannot reach Postgres. \
         Install one that has it — `cargo install cratefield-cli --features import-supabase` — \
         and run that binary (it needs no compiled-in harness)."
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Vars(BTreeMap<&'static str, &'static str>);

    impl Config for Vars {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).map(|value| (*value).to_owned())
        }
    }

    fn args() -> InspectArgs {
        InspectArgs {
            project: "abcdefghijklmnopqrst".to_owned(),
            db_url: None,
            management_token: None,
            format: Format::Markdown,
            out: None,
            transfer_mbps: 100,
            classify: false,
            classify_threshold: 0.8,
        }
    }

    #[test]
    fn a_missing_url_is_a_refusal_not_a_prompt() {
        let error = credentials(&args(), &Vars(BTreeMap::new())).unwrap_err();
        assert!(error.contains(DB_URL_VAR), "{error}");
        assert!(error.contains("never prompts"), "{error}");
    }

    #[test]
    fn the_environment_is_read_and_never_printed() {
        let vars = Vars(BTreeMap::from([
            (DB_URL_VAR, "postgres://ro:hunter2@db.example.test/postgres"),
            (ACCESS_TOKEN_VAR, "sbp_secret_token"),
        ]));
        let credentials = credentials(&args(), &vars).expect("resolved");
        assert!(credentials.notes.is_empty());
        assert!(credentials.management_token.is_some());
        let debug = format!("{credentials:?}");
        assert!(
            !debug.contains("hunter2") && !debug.contains("sbp_"),
            "{debug}"
        );
    }

    #[test]
    fn a_flag_wins_and_earns_a_note() {
        let mut given = args();
        given.db_url = Some("postgres://ro:hunter2@db.example.test/postgres".to_owned());
        let vars = Vars(BTreeMap::from([(DB_URL_VAR, "postgres://other")]));
        let credentials = credentials(&given, &vars).expect("resolved");
        assert_eq!(
            credentials.db_url.expose(),
            "postgres://ro:hunter2@db.example.test/postgres"
        );
        assert_eq!(credentials.notes.len(), 1);
        assert!(!credentials.notes[0].contains("hunter2"));
    }

    #[test]
    #[cfg(not(feature = "import-supabase"))]
    fn without_the_feature_the_refusal_names_the_install() {
        let mut given = args();
        given.db_url = Some("postgres://ro:hunter2@db.example.test/postgres".to_owned());
        let error = inspect(&given).unwrap_err();
        assert!(
            error.contains("cargo install cratefield-cli --features import-supabase"),
            "{error}"
        );
        assert!(!error.contains("hunter2"));
    }

    #[test]
    #[cfg(feature = "import-supabase")]
    fn an_unreachable_database_is_an_error_that_quotes_no_secret() {
        let mut given = args();
        given.db_url = Some("postgres://ro:hunter2@127.0.0.1:1/postgres".to_owned());
        let error = inspect(&given).unwrap_err();
        assert!(error.contains("could not connect"), "{error}");
        assert!(!error.contains("hunter2"), "{error}");
    }
}
