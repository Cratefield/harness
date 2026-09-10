//! `fz` — the Factory Zero venture CLI (issue #8): `fz migrations
//! collect`, `fz migrations apply` (issue #18), `fz doctor`, `fz
//! modules`, `fz push` (issue #184), and the agent-safe workflow over
//! the venture manifest (harness #140): `fz plan`, `fz deploy --plan`,
//! `fz add`, `fz init`, `fz verify`.
//!
//! `fz` is linked into the venture as a bin target so it can see the
//! compiled-in harness. The documented pattern (venture template):
//!
//! ```text
//! // src/lib.rs
//! pub use harness::harness;
//! // Cargo.toml
//! [[bin]]
//! name = "fz"
//! path = "src/fz_main.rs"
//! // src/fz_main.rs
//! fn main() { cratefield_cli::main_for(venture::harness); }
//! ```
//!
//! Then `cargo run -p venture --bin fz -- migrations collect`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod apply;
pub mod build;
pub mod codes;
mod collect;
pub mod data;
pub mod doctor;
pub mod lint;
mod lock;
pub mod push;
pub mod sidecars;
pub mod workflow;

use clap::{Parser, Subcommand};
use cratefield_core::{Config, Harness};
use std::path::PathBuf;
use std::process::ExitCode;

/// The process environment as a [`Config`], so `fz` reads a variable the
/// same way a deployed runtime does (issue #143): the doctor for `ENV`, and
/// `fz push` for the push transports' secrets — which it reads only through
/// `cratefield_push_wiring`, never by name.
pub(crate) struct EnvVars;

impl Config for EnvVars {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|value| !value.is_empty())
    }
}

#[derive(Parser)]
#[command(name = "fz", about = "Factory Zero venture CLI")]
struct Cli {
    /// The sidecar mount table, as the runtime reads it from config:
    /// `{"module-name":"BINDING"}`. Defaults to the `HARNESS_SIDECARS`
    /// environment variable. Commands that walk the compiled-in modules
    /// use it to say what they cannot see (issue #66).
    #[arg(long, global = true, value_name = "JSON")]
    sidecars: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Writes wrangler-compatible migration files and maintains the
    /// `.harness-lock.json` pinning module migrations to file names.
    Migrations {
        #[command(subcommand)]
        command: MigrationsCommand,
    },
    /// Validates the harness, the production-captcha rule, the lockfile
    /// and the portable-SQL lint.
    Doctor {
        /// Migration directory (default `migrations`).
        #[arg(long, default_value = "migrations")]
        out: PathBuf,
        /// Accept a production venture without a Captcha port for the
        /// stated reason; prints a warning instead of failing.
        #[arg(long, value_name = "REASON")]
        allow_no_captcha: Option<String>,
        /// Prints exactly one JSON object to stdout — `schema`, `ok` and
        /// the failures with their stable codes (`cratefield_cli::codes`)
        /// — instead of prose. The exit code still reflects the verdict.
        #[arg(long)]
        json: bool,
    },
    /// Prints modules, versions, route prefixes, emitted events, tables.
    Modules,
    /// Generates a deterministic Cloudflare venture crate from a venture
    /// manifest (issue #138): resolve the module set, write `Cargo.toml`,
    /// `src/lib.rs`, `src/fz_main.rs`, `wrangler.toml`. Standalone — it
    /// needs no compiled-in harness because it produces one. The final
    /// `worker-build` + `wrangler deploy` are printed as the next steps.
    Build {
        /// The venture manifest (`.json` or `.toml`).
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
        /// Output directory for the generated venture crate.
        #[arg(long, default_value = "dist")]
        out: PathBuf,
        /// Point the generated crate at a local harness checkout (path
        /// deps) instead of published versions — for offline / in-repo
        /// builds, as the Docker image does.
        #[arg(long, value_name = "PATH")]
        harness_path: Option<String>,
        /// A stamped catalog JSON instead of the built-in one (issue
        /// #142): the build service points this at the release-stamped
        /// catalog whose digests are real content addresses.
        #[arg(long, value_name = "PATH")]
        catalog: Option<PathBuf>,
        /// RFC 3339 timestamp recorded in provenance (issue #142). The
        /// CLI owns no clock, so a build without this (or
        /// `FZ_BUILD_TIMESTAMP`) records `built-at: null` rather than
        /// inventing one.
        #[arg(long, value_name = "RFC3339")]
        built_at: Option<String>,
        /// Builder identity recorded in provenance (issue #142);
        /// `FZ_BUILDER` is the fallback, then `"local"`.
        #[arg(long, value_name = "WHO")]
        builder: Option<String>,
    },
    /// Moves venture data between engines (issue #21): export D1/SQLite
    /// data to JSONL with a manifest, import into Postgres.
    Data {
        #[command(subcommand)]
        command: DataCommand,
    },
    /// Describes what the manifest would change — modules added or
    /// removed, the capabilities they require, config changes and
    /// migrations not yet collected — and prints a `digest` that
    /// approves exactly that plan. Read-only (harness #140).
    Plan {
        /// The venture manifest (`.json` or `.toml`).
        #[arg(long, default_value = "venture.json", value_name = "MANIFEST")]
        manifest: PathBuf,
        /// Migration directory holding `.harness-lock.json`.
        #[arg(long, default_value = "migrations")]
        migrations: PathBuf,
        /// Prints exactly one JSON object to stdout — `schema`, `ok`,
        /// `failures`, the plan `digest` and its content — instead of
        /// prose. Nothing else reaches stdout or stderr.
        #[arg(long)]
        json: bool,
        /// Never prompts (the workflow commands never do; anything
        /// needing a human is a coded refusal) and suppresses the
        /// human `next:` steps from the prose output.
        #[arg(long)]
        non_interactive: bool,
    },
    /// Applies exactly the approved plan: recomputes it from the
    /// current inputs and refuses any other digest. Records the plan in
    /// `.harness-deploy.json` beside the manifest — compiling,
    /// standing up the Worker and applying migrations stay with the
    /// needs-human steps it prints. A production venture, and any plan
    /// that removes modules, needs `--i-am-deploying-to-production`
    /// as a second, separate consent (harness #140).
    Deploy {
        /// The digest `fz plan --json` printed — the approval token.
        #[arg(long, value_name = "DIGEST")]
        plan: Option<String>,
        /// The venture manifest (`.json` or `.toml`).
        #[arg(long, default_value = "venture.json", value_name = "MANIFEST")]
        manifest: PathBuf,
        /// Migration directory holding `.harness-lock.json`.
        #[arg(long, default_value = "migrations")]
        migrations: PathBuf,
        /// The second consent: required when the venture resolves to
        /// production, or when the plan removes modules.
        #[arg(long)]
        i_am_deploying_to_production: bool,
        /// Prints exactly one JSON object to stdout instead of prose.
        #[arg(long)]
        json: bool,
        /// Never prompts; suppresses the human `next:` steps.
        #[arg(long)]
        non_interactive: bool,
    },
    /// Adds a module to the manifest's desired composition and nothing
    /// else — never deploys, never touches a database (harness #140).
    /// Adding a module already present is a no-op that succeeds.
    Add {
        /// The module slug, as the catalog names it.
        #[arg(value_name = "MODULE")]
        module: String,
        /// The venture manifest (`.json` or `.toml`).
        #[arg(long, default_value = "venture.json", value_name = "MANIFEST")]
        manifest: PathBuf,
        /// Prints exactly one JSON object to stdout instead of prose.
        #[arg(long)]
        json: bool,
        /// Never prompts; suppresses the human `next:` steps.
        #[arg(long)]
        non_interactive: bool,
    },
    /// Writes a new venture manifest — name and host, no modules.
    /// Refuses to overwrite an existing one unless `--force`
    /// (harness #140).
    Init {
        /// The venture name (becomes the generated crate name).
        #[arg(long, value_name = "NAME")]
        name: String,
        /// The primary host the backend answers on.
        #[arg(long, value_name = "HOST")]
        host: String,
        /// Where to write the manifest.
        #[arg(long, default_value = "venture.json", value_name = "MANIFEST")]
        manifest: PathBuf,
        /// Replace an existing manifest instead of refusing.
        #[arg(long)]
        force: bool,
        /// Prints exactly one JSON object to stdout instead of prose.
        #[arg(long)]
        json: bool,
        /// Never prompts; suppresses the human `next:` steps.
        #[arg(long)]
        non_interactive: bool,
    },
    /// Checks the recorded deployment still matches the manifest,
    /// reporting drift as coded failures in the doctor's JSON shape
    /// (harness #140).
    Verify {
        /// The venture manifest (`.json` or `.toml`).
        #[arg(long, default_value = "venture.json", value_name = "MANIFEST")]
        manifest: PathBuf,
        /// Migration directory holding `.harness-lock.json`.
        #[arg(long, default_value = "migrations")]
        migrations: PathBuf,
        /// Prints exactly one JSON object — the doctor's
        /// `{schema, ok, failures}` — instead of prose.
        #[arg(long)]
        json: bool,
        /// Never prompts; verify never does anyway.
        #[arg(long)]
        non_interactive: bool,
    },
    /// The push transports (issue #184): generate the VAPID key pair,
    /// send one notification through the adapters this venture's
    /// environment configures, inspect a Web Push subscription.
    ///
    /// Needs no compiled-in harness: push is configured by the
    /// environment, so these run from the standalone `fz` too.
    Push {
        #[command(subcommand)]
        command: PushCommand,
    },
}

#[derive(Subcommand)]
enum PushCommand {
    /// VAPID: the P-256 key pair Web Push identifies this application
    /// server by.
    Vapid {
        #[command(subcommand)]
        command: VapidCommand,
    },
    /// Sends one notification through the adapters this venture's
    /// environment configures — the same construction `serve()` uses, so
    /// what this reaches is what the deployment reaches.
    Send {
        /// Which transport to send over; also how `--recipient` is read.
        #[arg(long, value_enum)]
        transport: push::Transport,
        /// An APNs device token, an FCM registration token, or a Web Push
        /// subscription JSON (the browser's own shape, or the flattened
        /// one). Credential material: it is in this shell's history.
        #[arg(long, value_name = "TOKEN-OR-JSON")]
        recipient: String,
        /// The notification's title.
        #[arg(long)]
        title: String,
        /// The notification's body.
        #[arg(long)]
        body: String,
        /// Custom JSON payload the app reads alongside the alert.
        #[arg(long, value_name = "JSON")]
        data: Option<String>,
        /// Where a tap should take the user.
        #[arg(long, value_name = "URL")]
        url: Option<String>,
        /// How long the push service may hold it while the device is
        /// offline, in seconds. `0` means deliver now or drop.
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
        /// Delivery priority.
        #[arg(long, value_enum, default_value_t = push::PriorityArg::Immediate)]
        priority: push::PriorityArg,
        /// A data-only notification: nothing is shown, the app is woken.
        #[arg(long)]
        silent: bool,
        /// Report which transport would carry this and why, without
        /// sending. Reaches no network at all — it builds no HTTP client.
        #[arg(long)]
        dry_run: bool,
    },
    /// Validates a Web Push subscription and prints the `aud` the adapter
    /// will sign for it — a wrong `aud` is the commonest VAPID `401`.
    InspectSubscription {
        /// The subscription JSON, as the browser hands it over.
        #[arg(value_name = "JSON")]
        json: String,
    },
}

#[derive(Subcommand)]
enum VapidCommand {
    /// Generates a P-256 key pair, printing the public half in the form a
    /// browser passes to `pushManager.subscribe()`.
    ///
    /// A venture generates one of these once and keeps it: rotating it
    /// invalidates every existing browser subscription, which no server
    /// can recreate.
    Keygen {
        /// Write the private key here (owner-readable only).
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
        /// Overwrite an existing `--file`. This is a rotation.
        #[arg(long)]
        force: bool,
        /// Print the private key to stdout as well.
        #[arg(long)]
        print_private: bool,
    },
}

#[derive(Subcommand)]
enum DataCommand {
    /// Exports the venture's tables from a SQLite database (the D1
    /// stand-in — `docs/DATA-MOVE.md`) to manifest + JSONL records.
    Export {
        /// The SQLite database file to read.
        #[arg(long, value_name = "PATH")]
        db: PathBuf,
        /// Export without the tables of any sidecar-mounted module,
        /// recording the omission in the manifest. Without this, an
        /// export refuses to run when `HARNESS_SIDECARS` is set, rather
        /// than producing an artifact that looks complete (issue #66).
        #[arg(long)]
        without_sidecar_tables: bool,
        /// The JSONL file to write (manifest line first).
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Prints the per-table summary without writing the file.
        #[arg(long)]
        plan: bool,
    },
    /// Loads an export file into a Postgres database in lock order,
    /// verifying sha256 and row counts against the manifest. Requires
    /// the `postgres` feature.
    Import {
        /// Connection string of the target Postgres database.
        #[arg(long, value_name = "URL")]
        url: String,
        /// The export file written by `fz data export`.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Adds to non-empty tables instead of refusing them.
        #[arg(long)]
        append: bool,
        /// Prints what would be imported and the target state, writing
        /// nothing.
        #[arg(long)]
        plan: bool,
    },
}

#[derive(Subcommand)]
enum MigrationsCommand {
    /// Collects module migrations into wrangler-ordered files.
    Collect {
        /// SQL dialect of the collected files (sqlite for wrangler/D1).
        #[arg(long, default_value = "sqlite")]
        dialect: String,
        /// Output directory for wrangler `migrations_dir`.
        #[arg(long, default_value = "migrations")]
        out: PathBuf,
    },
    /// Applies the harness's migrations directly to a database — the
    /// native counterpart of `wrangler d1 migrations apply` (issue #18).
    Apply {
        /// Target SQL dialect: postgres.
        #[arg(long, default_value = "postgres")]
        dialect: String,
        /// Connection string of the target database, e.g.
        /// `postgres://user:pass@host:5432/venture`.
        #[arg(long, value_name = "URL")]
        url: String,
    },
}

/// Runs `fz` with the venture's harness and the given arguments.
///
/// # Panics
///
/// Never; failures are reported on stderr with a non-zero exit code.
#[must_use = "call process::exit with the returned ExitCode"]
pub fn run(build: impl Fn() -> Harness, args: impl IntoIterator<Item = String>) -> ExitCode {
    let mut full_argv: Vec<String> = Vec::with_capacity(8);
    full_argv.push("fz".to_string());
    full_argv.extend(args);
    let cli = Cli::parse_from(full_argv);
    // The harness-free commands run before (and without) the venture's
    // compiled-in harness.
    if let Some(exit) = harness_free(&cli.command) {
        return exit;
    }
    let harness = build();
    let sidecars = crate::sidecars::from_cli_or_env(cli.sidecars.as_deref());
    let result = match cli.command {
        Command::Migrations {
            command: MigrationsCommand::Collect { dialect, out },
        } => collect::collect(&harness, &dialect, &out),
        Command::Migrations {
            command: MigrationsCommand::Apply { dialect, url },
        } => apply::apply(&harness, &dialect, &url),
        Command::Doctor {
            out,
            allow_no_captcha,
            json,
        } => {
            if json {
                return doctor::doctor_json(
                    &harness,
                    &out,
                    allow_no_captcha.as_deref(),
                    sidecars.as_deref(),
                );
            }
            doctor::doctor(
                &harness,
                &out,
                allow_no_captcha.as_deref(),
                sidecars.as_deref(),
            )
        }
        Command::Modules => {
            print_modules(&harness);
            Ok(())
        }
        Command::Data {
            command:
                DataCommand::Export {
                    db,
                    out,
                    plan,
                    without_sidecar_tables,
                },
        } => data::export(
            &harness,
            &db,
            &out,
            plan,
            without_sidecar_tables,
            sidecars.as_deref(),
        ),
        Command::Data {
            command:
                DataCommand::Import {
                    url,
                    file,
                    append,
                    plan,
                },
        } => data::import(&harness, &file, &url, append, plan),
        // Handled by `harness_free` before `build()` above: build needs
        // no harness, the workflow commands work on the manifest and its
        // records, and push reads the venture's environment.
        Command::Build { .. }
        | Command::Plan { .. }
        | Command::Deploy { .. }
        | Command::Add { .. }
        | Command::Init { .. }
        | Command::Verify { .. }
        | Command::Push { .. } => unreachable!("dispatched before the harness is built"),
    };
    finish(result)
}

/// The commands that need no compiled-in harness, run — the one seam
/// both entry points dispatch through, before [`run`] builds the harness
/// and instead of the harness [`run_standalone`] does not have.
///
/// `fz build` **generates** a harness, so it cannot have one; the manifest
/// workflow — `fz plan` / `deploy` / `add` / `init` / `verify`, routed by
/// [`workflow::dispatch`] — works on the manifest and its on-disk records
/// rather than the compiled-in modules; and `fz push` reads the venture's
/// *environment* rather than its modules. `None` for every other command,
/// which is what sends [`run_standalone`] to its refusal and [`run`] on to
/// `build()`.
fn harness_free(command: &Command) -> Option<ExitCode> {
    match command {
        Command::Build {
            manifest,
            out,
            harness_path,
            catalog,
            built_at,
            builder,
        } => Some(finish(build::run(
            manifest,
            out,
            harness_path.as_deref(),
            catalog.as_deref(),
            built_at.as_deref(),
            builder.as_deref(),
        ))),
        Command::Push { command } => Some(finish(run_push(command))),
        _ => workflow::dispatch(command),
    }
}

/// `fz push` (issue #184). Every path prints its report to stdout and
/// reports the verdict as the exit code.
fn run_push(command: &PushCommand) -> Result<(), String> {
    match command {
        PushCommand::Vapid {
            command:
                VapidCommand::Keygen {
                    file,
                    force,
                    print_private,
                },
        } => {
            let generated = push::vapid_keygen(&push::KeygenOptions {
                file: file.as_deref(),
                force: *force,
                print_private: *print_private,
            })?;
            // The rotation warning is a diagnostic, so it goes to stderr:
            // stdout is the stream the README's recipe reads the public
            // key off, and a warning in it ends up in somebody's
            // `applicationServerKey`.
            if let Some(warning) = generated.warning() {
                eprint!("{warning}");
            }
            print!("{}", generated.render());
            if *print_private {
                print!("\n{}", *generated.private_key_disclosure());
            }
            Ok(())
        }
        PushCommand::Send {
            transport,
            recipient,
            title,
            body,
            data,
            url,
            ttl,
            priority,
            silent,
            dry_run,
        } => {
            let request = push::SendRequest::from_args(&push::SendArgs {
                transport: *transport,
                recipient: recipient.clone(),
                title: title.clone(),
                body: body.clone(),
                data: data.clone(),
                url: url.clone(),
                ttl: *ttl,
                priority: *priority,
                silent: *silent,
            })?;
            let report = if *dry_run {
                push::plan(&EnvVars, &request)
            } else {
                push::send_now(&EnvVars, &request)?
            };
            print!("{}", report.render());
            if report.ok() {
                Ok(())
            } else {
                // The report already said what happened, in full; the exit
                // code is what a script reads, and `finish` prefixes this.
                Err("nothing was delivered — see the report above".to_owned())
            }
        }
        PushCommand::InspectSubscription { json } => {
            print!("{}", push::inspect_subscription(json)?.render());
            Ok(())
        }
    }
}

/// Runs the harness-free `fz` commands from a standalone binary (no
/// compiled-in venture): `fz build <manifest>`, which generates a harness;
/// the manifest workflow — `fz plan` / `deploy` / `add` / `init` /
/// `verify` — which works on the manifest and its records, not on
/// compiled-in modules; and `fz push`, which reads the venture's
/// environment. Every other command needs the venture's harness and says
/// so.
#[must_use = "call process::exit with the returned ExitCode"]
pub fn run_standalone(args: impl IntoIterator<Item = String>) -> ExitCode {
    let mut full_argv: Vec<String> = Vec::with_capacity(8);
    full_argv.push("fz".to_string());
    full_argv.extend(args);
    let cli = Cli::parse_from(full_argv);
    let Some(exit) = harness_free(&cli.command) else {
        eprintln!(
            "fz: this command must run inside a venture (it needs the compiled-in harness — see \
             the cratefield-cli README). Only `fz build <manifest>`, the manifest workflow (`fz \
             plan` / `deploy` / `add` / `init` / `verify`) and `fz push` run standalone."
        );
        return ExitCode::FAILURE;
    };
    exit
}

fn finish(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("fz: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Entry point for the venture-side `fz` bin (see the crate docs).
pub fn main_for(build: fn() -> Harness) -> ! {
    let code = run(build, std::env::args().skip(1));
    std::process::exit(match code {
        ExitCode::SUCCESS => 0,
        _ => 1,
    });
}

fn print_modules(harness: &Harness) {
    for module in harness.modules() {
        println!(
            "{} {} /v1/{} emits=[{}] tables=[{}]",
            module.name(),
            module.version(),
            module.name(),
            module.emits().join(", "),
            module.tables().join(", "),
        );
    }
}
