//! `fz import supabase inspect` (issue #658, ADR 0026): connects read-only
//! to a Supabase project and writes the migration report.
//!
//! `--dispositions <FILE>` decides the report's needs-work and blocker items
//! from a TOML file (ADR 0026, Decision 5);
//! `fz import supabase dispositions init` writes a skeleton of that file.
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
/// The environment variable the target Postgres URL is read from by
/// default: the harness's own app-database variable, the one a venture's
/// native runtime reads (`crates/runtime-native/README.md`).
pub const DEFAULT_TARGET_ENV: &str = "DATABASE_URL";

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
    /// `--dispositions`, if given: the file applied to the report.
    pub dispositions: Option<PathBuf>,
}

/// Everything `fz import supabase dispositions init` was given.
#[derive(Debug, Clone)]
pub struct DispositionsInitArgs {
    /// The project ref.
    pub project: String,
    /// `--db-url`, if given.
    pub db_url: Option<String>,
    /// `--management-token`, if given.
    pub management_token: Option<String>,
    /// `--out`: where the skeleton goes.
    pub out: PathBuf,
    /// `--force`: overwrite an existing file.
    pub force: bool,
    /// `--dispositions`: skip items this file already decides.
    pub dispositions: Option<PathBuf>,
}

impl DispositionsInitArgs {
    /// The inspect args that reach the same project, for the shared
    /// credential and report code. Only the engine build inspects.
    #[cfg(feature = "import-supabase")]
    fn as_inspect(&self) -> InspectArgs {
        InspectArgs {
            project: self.project.clone(),
            db_url: self.db_url.clone(),
            management_token: self.management_token.clone(),
            format: Format::Markdown,
            out: None,
            transfer_mbps: 100,
            classify: false,
            classify_threshold: 0.8,
            dispositions: None,
        }
    }
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
    resolve(
        args.db_url.as_deref(),
        args.management_token.as_deref(),
        config,
    )
}

/// [`credentials`] without an [`InspectArgs`], so the plan run reuses it.
fn resolve(
    db_url: Option<&str>,
    management_token: Option<&str>,
    config: &dyn Config,
) -> Result<Credentials, String> {
    let mut notes = Vec::new();
    let db_url = match db_url {
        Some(url) => {
            notes.push(format!(
                "note: --db-url puts the password in your shell history and the process list; \
                 prefer {DB_URL_VAR}"
            ));
            url.to_owned()
        }
        None => config.get(DB_URL_VAR).ok_or_else(|| {
            format!(
                "no database URL: set {DB_URL_VAR} to the read-only role's connection string \
                 (docs/import/supabase.md), or pass --db-url. fz never prompts"
            )
        })?,
    };
    let management_token = match management_token {
        Some(token) => {
            notes.push(format!(
                "note: --management-token puts the token in your shell history and the process \
                 list; prefer {ACCESS_TOKEN_VAR}"
            ));
            Some(token.to_owned())
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
    /// `N automatic, N needs work, N blockers, N undecided`.
    pub summary: String,
}

/// The refusal every command prints when `fz` was built without the engine.
#[cfg(not(feature = "import-supabase"))]
const WITHOUT_FEATURE: &str = "this `fz` was built without the `import-supabase` feature, so it \
     cannot reach Postgres. Install one that has it — `cargo install cratefield-cli --features \
     import-supabase` — and run that binary (it needs no compiled-in harness).";

/// Runs `dispositions init`: inspects, then writes the skeleton file.
///
/// # Errors
///
/// A refusal — an existing file without `--force`, a bad dispositions file, a
/// connection or permission error.
pub fn dispositions_init(args: &DispositionsInitArgs) -> Result<(), String> {
    // Without the engine there is nothing to inspect, so refuse before the
    // overwrite and credential checks (which would otherwise be reached).
    #[cfg(not(feature = "import-supabase"))]
    {
        let _ = args;
        Err(WITHOUT_FEATURE.to_owned())
    }

    #[cfg(feature = "import-supabase")]
    {
        if args.out.exists() && !args.force {
            return Err(format!(
                "{} exists; pass --force to overwrite it",
                args.out.display()
            ));
        }
        let inspect_args = args.as_inspect();
        let credentials = credentials(&inspect_args, &EnvVars)?;
        for note in &credentials.notes {
            eprintln!("{note}");
        }
        write_skeleton(&inspect_args, &credentials, args)
    }
}

#[cfg(feature = "import-supabase")]
fn write_skeleton(
    inspect_args: &InspectArgs,
    credentials: &Credentials,
    args: &DispositionsInitArgs,
) -> Result<(), String> {
    use cratefield_import_supabase as engine;

    let mut report = inspect_report(inspect_args, credentials)?;
    if let Some(path) = &args.dispositions {
        let file = engine::DispositionsFile::load(path).map_err(|error| error.to_string())?;
        engine::apply_dispositions(&mut report, &file);
    }
    let text = engine::skeleton(&report);
    if let Some(parent) = args
        .out
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    std::fs::write(&args.out, &text)
        .map_err(|error| format!("cannot write {}: {error}", args.out.display()))?;
    println!(
        "{} undecided item(s) written to {}",
        report.summary.undecided,
        args.out.display()
    );
    Ok(())
}

#[cfg(feature = "import-supabase")]
fn engine_options(
    project: &str,
    credentials: &Credentials,
    transfer_mbps: u32,
    classify: bool,
    classify_threshold: f32,
) -> Result<cratefield_import_supabase::InspectOptions, String> {
    use cratefield_import_supabase as engine;
    use std::sync::Arc;

    let clock: Arc<dyn cratefield_core::Clock> = Arc::new(cratefield_runtime_native::TokioClock);
    let http: Arc<dyn cratefield_core::HttpClient> =
        Arc::new(cratefield_core::BoundedHttpClient::new(
            Arc::new(cratefield_runtime_native::ReqwestClient::new()),
            Arc::clone(&clock),
        ));
    let mut options = engine::InspectOptions::new(
        project.to_owned(),
        engine::Secret::new(credentials.db_url.expose()),
    );
    options.transfer_mbps = transfer_mbps;
    options.classify_threshold = classify_threshold;
    options.management = credentials.management_token.as_ref().map(|token| {
        engine::ManagementApi::new(
            Arc::clone(&http),
            engine::DEFAULT_API_BASE,
            engine::Secret::new(token.expose()),
        )
    });
    if classify {
        // TypeSafe (its judge, Jev) through the adapter's own reader, so
        // the key's name is the adapter's, not ours.
        let classifier =
            cratefield_adapter_typesafe::TypeSafe::from_env(Arc::clone(&http), Arc::clone(&clock))
                .ok_or_else(|| {
                    "--classify needs TYPESAFE_API_KEY (the TypeSafe adapter reads it); without \
                     it, drop --classify and unplaced policies stay needs_review"
                        .to_owned()
                })?;
        options.classifier = Some(Arc::new(classifier));
    }
    Ok(options)
}

#[cfg(feature = "import-supabase")]
fn inspect_report(
    args: &InspectArgs,
    credentials: &Credentials,
) -> Result<cratefield_import_supabase::Report, String> {
    use cratefield_import_supabase as engine;

    let options = engine_options(
        &args.project,
        credentials,
        args.transfer_mbps,
        args.classify,
        args.classify_threshold,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("cannot start the async runtime inspect needs: {err}"))?;
    let mut report = runtime
        .block_on(engine::inspect(&options))
        .map_err(|error| error.to_string())?;
    if let Some(path) = &args.dispositions {
        let file = engine::DispositionsFile::load(path).map_err(|error| error.to_string())?;
        engine::apply_dispositions(&mut report, &file);
    }
    Ok(report)
}

#[cfg(feature = "import-supabase")]
fn run(args: &InspectArgs, credentials: &Credentials) -> Result<Rendered, String> {
    let report = inspect_report(args, credentials)?;
    let s = &report.summary;
    let summary = format!(
        "{} automatic, {} needs work, {} blocker(s), {} undecided{}",
        s.automatic,
        s.needs_work,
        s.blockers,
        s.undecided,
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
    // As with `push-send`: an installed binary, never a feature on the
    // venture's dependency, whose wasm build must not see sqlx.
    Err(WITHOUT_FEATURE.to_owned())
}

/// Everything the bare `fz import supabase` and `fz import supabase plan`
/// were given (issue #728).
#[derive(Debug, Clone)]
pub struct PlanArgs {
    /// The project ref.
    pub project: String,
    /// `--db-url`, if given.
    pub db_url: Option<String>,
    /// `--management-token`, if given.
    pub management_token: Option<String>,
    /// `--target-env`: the variable the target Postgres URL is read from.
    pub target_env: String,
    /// `--dir`: where `report.json`, `report.md` and `plan.json` go.
    pub dir: PathBuf,
    /// `--transfer-mbps`.
    pub transfer_mbps: u32,
    /// `--classify`.
    pub classify: bool,
    /// `--classify-threshold`.
    pub classify_threshold: f32,
    /// `--apply`: apply an approved plan instead of writing one.
    pub apply: bool,
    /// `--plan`: the plan file to apply.
    pub plan: Option<PathBuf>,
}

/// Runs the command: inspects the source read-only, reads the target
/// read-only, and either writes `report.json`, `report.md` and `plan.json`
/// to `--dir`, or re-checks an approved plan with `--apply --plan`.
///
/// # Errors
///
/// A refusal or an access error. Blockers are in the plan and the exit code
/// is zero; `--apply` fails (non-zero) on an unknown plan version, a
/// project mismatch, drift or a remaining blocker.
pub fn plan(args: &PlanArgs) -> Result<(), String> {
    let credentials = resolve(
        args.db_url.as_deref(),
        args.management_token.as_deref(),
        &EnvVars,
    )?;
    for note in &credentials.notes {
        eprintln!("{note}");
    }
    run_plan(args, &credentials)
}

#[cfg(feature = "import-supabase")]
fn run_plan(args: &PlanArgs, credentials: &Credentials) -> Result<(), String> {
    use cratefield_import_supabase as engine;

    let options = engine_options(
        &args.project,
        credentials,
        args.transfer_mbps,
        args.classify,
        args.classify_threshold,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("cannot start the async runtime the plan needs: {err}"))?;
    runtime.block_on(async {
        if args.apply {
            let path = args
                .plan
                .as_ref()
                .ok_or_else(|| "--apply needs --plan <FILE>".to_owned())?;
            return apply_plan(args, path, &options).await;
        }
        let report = engine::inspect(&options)
            .await
            .map_err(|error| error.to_string())?;
        let target = match EnvVars.get(&args.target_env) {
            Some(url) => Some(
                engine::read_target(&engine::Secret::new(url))
                    .await
                    .map_err(|error| format!("could not read the target database: {error}"))?,
            ),
            None => None,
        };
        let plan = engine::build_plan(&report, target.as_ref());
        std::fs::create_dir_all(&args.dir)
            .map_err(|err| format!("cannot create {}: {err}", args.dir.display()))?;
        write_report(&args.dir.join("report.json"), &report.to_json())?;
        write_report(&args.dir.join("report.md"), &report.to_markdown())?;
        write_report(&args.dir.join("plan.json"), &plan.to_json())?;
        eprintln!(
            "wrote {}/report.json, report.md and plan.json: {} blocker(s) in the plan",
            args.dir.display(),
            plan.blockers.len()
        );
        for blocker in &plan.blockers {
            eprintln!("  blocker {}: {}", blocker.code, blocker.message);
        }
        Ok(())
    })
}

/// `--apply --plan FILE`: re-inspects and refuses unless the plan still
/// matches. It writes nothing: the auth-users and data phases land with
/// #659/#660.
#[cfg(feature = "import-supabase")]
async fn apply_plan(
    args: &PlanArgs,
    path: &Path,
    options: &cratefield_import_supabase::InspectOptions,
) -> Result<(), String> {
    use cratefield_import_supabase as engine;

    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let plan: engine::Plan = serde_json::from_str(&text)
        .map_err(|err| format!("{} is not a plan file: {err}", path.display()))?;
    if plan.plan_version != engine::PLAN_VERSION {
        return Err(format!(
            "{} is a version {} plan, and this fz applies version {}; re-plan with `fz import \
             supabase plan`",
            path.display(),
            plan.plan_version,
            engine::PLAN_VERSION
        ));
    }
    if plan.project.project_ref != args.project {
        return Err(format!(
            "{} is a plan for project {}, not {}; re-plan with `fz import supabase plan --project \
             {}`",
            path.display(),
            plan.project.project_ref,
            args.project,
            args.project
        ));
    }
    let report = engine::inspect(options)
        .await
        .map_err(|error| error.to_string())?;
    engine::check_drift(&plan, &report).map_err(|drift| drift.to_string())?;
    if !plan.blockers.is_empty() {
        let codes: Vec<&str> = plan.blockers.iter().map(|b| b.code.as_str()).collect();
        return Err(format!(
            "the plan still has {} blocker(s) ({}); resolve them and re-plan",
            plan.blockers.len(),
            codes.join(", ")
        ));
    }
    eprintln!(
        "the plan matches the source ({}); the auth-users and data phases land with #659/#660 — \
         nothing was written to the target",
        plan.inspection_hash
    );
    Ok(())
}

#[cfg(not(feature = "import-supabase"))]
fn run_plan(_args: &PlanArgs, _credentials: &Credentials) -> Result<(), String> {
    Err(
        // The same refusal `inspect` gives without the engine.
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
            dispositions: None,
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
    fn dispositions_init_refuses_to_overwrite_without_force() {
        let dir = std::env::temp_dir().join(format!("fz-dispositions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let out = dir.join("supabase-dispositions.toml");
        std::fs::write(&out, "# mine\n").expect("write");
        let given = DispositionsInitArgs {
            project: "abcdefghijklmnopqrst".to_owned(),
            db_url: None,
            management_token: None,
            out: out.clone(),
            force: false,
            dispositions: None,
        };
        let error = dispositions_init(&given).unwrap_err();
        assert!(error.contains("--force"), "{error}");
        assert!(error.contains(&out.display().to_string()), "{error}");
        // It left the file alone.
        assert_eq!(std::fs::read_to_string(&out).expect("read"), "# mine\n");
        let _ = std::fs::remove_dir_all(&dir);
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
