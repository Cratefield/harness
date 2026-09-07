//! `fz` — the Factory Zero venture CLI (issue #8): `fz migrations
//! collect`, `fz migrations apply` (issue #18), `fz doctor`, `fz
//! modules`.
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
mod collect;
pub mod data;
mod doctor;
pub mod lint;
mod lock;
pub mod sidecars;

use clap::{Parser, Subcommand};
use cratefield_core::Harness;
use std::path::PathBuf;
use std::process::ExitCode;

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
    },
    /// Prints modules, versions, route prefixes, emitted events, tables.
    Modules,
    /// Moves venture data between engines (issue #21): export D1/SQLite
    /// data to JSONL with a manifest, import into Postgres.
    Data {
        #[command(subcommand)]
        command: DataCommand,
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
        } => doctor::doctor(
            &harness,
            &out,
            allow_no_captcha.as_deref(),
            sidecars.as_deref(),
        ),
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
    };
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
