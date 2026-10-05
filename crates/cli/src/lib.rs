//! `fz` — the Factory Zero venture CLI (issue #8): `fz migrations
//! collect`, `fz migrations apply` (issue #18), `fz doctor`, `fz
//! modules`, `fz push` (issue #184), and the agent-safe workflow over
//! the venture manifest (harness #140): `fz plan`, `fz deploy --plan`,
//! `fz add`, `fz init`, `fz verify`.
//!
//! `fz` is linked into the venture as a bin target so it can see the
//! compiled-in harness. The pattern `fz build` generates:
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
pub mod auth_import;
pub mod build;
pub mod build_key;
pub mod client_ts;
pub mod codes;
mod collect;
pub mod data;
pub mod doctor;
pub mod import;
pub mod lint;
mod lock;
pub mod push;
pub mod sidecars;
pub mod tables;
pub mod workflow;

use clap::{Args, Parser, Subcommand};
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
    /// Computes the artifact's content address (issue #59): sha256 over
    /// the pinned module releases, the harness API, the rustc version
    /// and the build profile. Prints the key and the inputs that
    /// produced it; runs no cargo, writes nothing. The venture name,
    /// host, config and the sidecar mount table are deployment
    /// configuration, not artifact content, so they are not inputs —
    /// two customers on the same module set share the artifact and the
    /// same key. Standalone, like `fz build`.
    BuildKey {
        /// The venture manifest (`.json` or `.toml`).
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
        /// A stamped catalog JSON instead of the built-in one — the
        /// same catalog the matching `fz build --catalog` would use.
        #[arg(long, value_name = "PATH")]
        catalog: Option<PathBuf>,
    },
    /// Generates the typed TypeScript client for a venture (issue #155):
    /// a `/__surface` contract document in, the files of a deterministic
    /// `@cratefield/client` package out, written to `--out`. Standalone —
    /// it reads the contract the venture serves, not a compiled-in
    /// venture, so the standalone `fz` runs it too.
    ClientTs {
        /// The `/__surface` document to read: a path, or `-` for stdin
        /// (`curl -s https://venture.example/__surface | fz client-ts
        /// --surface - --out ./client`).
        #[arg(long, value_name = "PATH")]
        surface: String,
        /// Output directory for the generated client package.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Prints exactly one JSON object to stdout — `schema`, `ok`, the
        /// package, the composition hash and the files written — instead
        /// of prose. The exit code still reflects the verdict.
        #[arg(long)]
        json: bool,
    },
    /// Moves venture data between engines (issue #21): export D1/SQLite
    /// data to JSONL with a manifest, import into Postgres.
    Data {
        #[command(subcommand)]
        command: DataCommand,
    },
    /// Declared tables (issue #153).
    Tables {
        #[command(subcommand)]
        command: TablesCommand,
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
    /// needs-human steps it prints. A production venture needs
    /// `--i-am-deploying-to-production` as a second, separate consent
    /// (harness #140); a plan that removes modules needs
    /// `--i-am-removing-modules`, a consent separate from that one.
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
        /// production.
        #[arg(long)]
        i_am_deploying_to_production: bool,
        /// Required when the plan drops modules from the served
        /// composition. Separate from the production flag on purpose: a
        /// removal in development is not a production deploy, and one
        /// flag for both would teach an operator to pass the production
        /// one by habit.
        #[arg(long)]
        i_am_removing_modules: bool,
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
    /// Loads users into a running venture's `auth-core` module over its
    /// admin API (issue #650). Needs no compiled-in harness: it talks to
    /// a URL, so the standalone `fz` runs it.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Moves a project from another platform onto the harness (ADR 0026).
    /// Supabase first; step one is a read-only inspection and its report.
    ///
    /// Needs no compiled-in harness, so it runs from the standalone `fz`
    /// too. The network leg needs the `import-supabase` feature.
    Import {
        #[command(subcommand)]
        command: ImportCommand,
    },
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Imports a JSONL file of users into `auth-core` — one JSON object
    /// per line, blank lines skipped — through
    /// `POST <target>/v1/auth-core/admin/users/import`.
    ///
    /// A dry run by default: the server validates every user and reports
    /// a verdict without writing. `--apply` is the run that writes.
    Import {
        /// The venture's base URL, e.g. `https://venture.example`.
        #[arg(long, value_name = "URL")]
        target: String,
        /// The environment variable holding the `ADMIN_TOKEN` to present.
        /// Required; the value is never printed.
        #[arg(long, value_name = "VAR")]
        admin_token_env: String,
        /// Actually write. Without it the run is a dry run.
        #[arg(long)]
        apply: bool,
        /// Let the server merge a user into an existing account that
        /// shares the email, instead of reporting a conflict.
        #[arg(long)]
        merge_by_email: bool,
        /// Where the report JSONL goes (default `<file>.report.jsonl`).
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
        /// Users per request (default 500, max 1000).
        #[arg(long, default_value_t = auth_import::DEFAULT_BATCH_SIZE, value_name = "N")]
        batch_size: usize,
        /// The JSONL file of user objects.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum ImportCommand {
    /// A Supabase project (ADR 0026, issues #658, #728). With no
    /// subcommand it inspects the source, reads the target and writes the
    /// report and the plan; `inspect` writes the report alone.
    #[command(args_conflicts_with_subcommands = true)]
    Supabase {
        #[command(subcommand)]
        command: Option<SupabaseCommand>,
        #[command(flatten)]
        run: SupabaseRunArgs,
    },
}

/// The source and target the bare `fz import supabase` (and `plan`) runs
/// against, shared by both. `project` is `Option` so a subcommand can
/// replace the run; the run refuses without it.
#[derive(Args)]
struct SupabaseRunArgs {
    /// The Supabase project ref (the `<ref>` in
    /// `https://<ref>.supabase.co`).
    #[arg(long, value_name = "REF")]
    project: Option<String>,
    /// The source database URL of a read-only role. Prefer the
    /// `SUPABASE_DB_URL` environment variable: a flag lands in the shell
    /// history and the process list.
    #[arg(long, value_name = "URL")]
    db_url: Option<String>,
    /// A Supabase Management API personal access token. Prefer
    /// `SUPABASE_ACCESS_TOKEN`.
    #[arg(long, value_name = "TOKEN")]
    management_token: Option<String>,
    /// The name of the environment variable holding the target Postgres
    /// URL. Unset, the plan carries a `target_not_checked` blocker rather
    /// than failing.
    #[arg(long, value_name = "VAR", default_value = import::DEFAULT_TARGET_ENV)]
    target_env: String,
    /// The directory the run writes `report.json`, `report.md` and
    /// `plan.json` to.
    #[arg(long, value_name = "DIR", default_value = ".")]
    dir: PathBuf,
    /// The throughput the transfer estimate assumes, in Mbit/s.
    #[arg(long, default_value_t = 100, value_name = "MBPS")]
    transfer_mbps: u32,
    /// Ask the `TypeSafe` classifier (Jev; `TYPESAFE_API_KEY`) about the
    /// RLS policies no rule placed. Advisory only.
    #[arg(long)]
    classify: bool,
    /// The confidence a classifier label needs; below it the policy stays
    /// `needs_review`.
    #[arg(long, default_value_t = 0.8, value_name = "0..1")]
    classify_threshold: f32,
    /// Apply an approved plan instead of writing a new one. Needs `--plan`.
    #[arg(long, requires = "plan")]
    apply: bool,
    /// The plan file to apply. Needs `--apply`.
    #[arg(long, value_name = "FILE", requires = "apply")]
    plan: Option<PathBuf>,
}

#[derive(Subcommand)]
enum SupabaseCommand {
    /// Connects read-only to the project's Postgres (and, with a token,
    /// the Management API) and writes the migration report: every item
    /// automatic, needs work or a blocker, with size and transfer
    /// estimates. Never writes to the project. The exit code is non-zero
    /// for a refused input, a connection or a permission error — never
    /// for a blocker, which is part of the report.
    Inspect {
        #[command(flatten)]
        source: SourceArgs,
        /// Write the JSON report (the format later steps read).
        #[arg(long, conflicts_with = "md")]
        json: bool,
        /// Write the Markdown report (the default).
        #[arg(long)]
        md: bool,
        /// Write the report to this file instead of stdout.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// The throughput the transfer estimate assumes, in Mbit/s.
        #[arg(long, default_value_t = 100, value_name = "MBPS")]
        transfer_mbps: u32,
        /// Ask the `TypeSafe` classifier (Jev; `TYPESAFE_API_KEY`) about the
        /// RLS policies no rule placed. Advisory only: it labels a
        /// policy, it never writes a check. Sends policy SQL and table and
        /// column names, never a row.
        #[arg(long)]
        classify: bool,
        /// The confidence a classifier label needs; below it the policy
        /// stays `needs_review`. Per adapter: it is `TypeSafe`'s number.
        #[arg(long, default_value_t = 0.8, value_name = "0..1")]
        classify_threshold: f32,
        /// Apply this dispositions file: give each needs-work and blocker
        /// item its own `covered` or `waived` entry (ADR 0026, Decision
        /// 5). A refused file is a non-zero exit naming the entry.
        #[arg(long, value_name = "FILE")]
        dispositions: Option<PathBuf>,
    },
    /// The dispositions file (ADR 0026, Decision 5).
    Dispositions {
        #[command(subcommand)]
        command: DispositionsCommand,
    },
    /// Inspects the source, reads the target and writes the report and the
    /// plan — the same run as the bare `fz import supabase`.
    Plan {
        #[command(flatten)]
        args: SupabaseRunArgs,
    },
}

/// The source flags `inspect` and `dispositions init` share: one read-only
/// connection to the project.
#[derive(Args)]
struct SourceArgs {
    /// The Supabase project ref (the `<ref>` in
    /// `https://<ref>.supabase.co`).
    #[arg(long, value_name = "REF")]
    project: String,
    /// The database URL of a read-only role. Prefer the
    /// `SUPABASE_DB_URL` environment variable: a flag lands in the
    /// shell history and the process list.
    #[arg(long, value_name = "URL")]
    db_url: Option<String>,
    /// A Supabase Management API personal access token, for Edge
    /// Functions and the auth configuration. Prefer
    /// `SUPABASE_ACCESS_TOKEN`. Without one those are reported as not
    /// inspected (unknown, not none).
    #[arg(long, value_name = "TOKEN")]
    management_token: Option<String>,
}

#[derive(Subcommand)]
enum DispositionsCommand {
    /// Writes a skeleton dispositions file: one placeholder entry per item
    /// that needs a decision, to fill in. Refuses to overwrite an existing
    /// file without `--force`.
    Init {
        #[command(flatten)]
        source: SourceArgs,
        /// Where to write the skeleton.
        #[arg(
            long,
            value_name = "FILE",
            default_value = "import/supabase-dispositions.toml"
        )]
        out: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
        /// Skip items already decided in this file.
        #[arg(long, value_name = "FILE")]
        dispositions: Option<PathBuf>,
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

/// `fz tables`'s own dispatch, in its own function.
///
/// `run` is at clippy's line limit and a subcommand arm has now pushed it
/// over twice; a group that grows belongs in a function that can grow.
fn run_tables(command: TablesCommand) -> Result<(), String> {
    match command {
        TablesCommand::Diff { from, to } => tables::diff(&from, &to),
        TablesCommand::Drift {
            manifest,
            dialect,
            url,
        } => tables::drift(&manifest, &dialect, &url),
    }
}

#[derive(Subcommand)]
enum TablesCommand {
    /// Reports what changed between two versions of a manifest's
    /// `[tables]` declaration, and what each change costs. Read-only,
    /// and no database is involved.
    Diff {
        /// The manifest as it was — a checkout of `main`, say.
        #[arg(long, value_name = "MANIFEST")]
        from: PathBuf,
        /// The manifest as it is now.
        #[arg(long, default_value = "venture.json", value_name = "MANIFEST")]
        to: PathBuf,
    },
    /// Reports what a database differs from the manifest's `[tables]`
    /// declaration by, in expand/contract/rewrite terms. Read-only.
    Drift {
        /// The venture manifest (`.json` or `.toml`).
        #[arg(long, default_value = "venture.json", value_name = "MANIFEST")]
        manifest: PathBuf,
        /// Target SQL dialect: postgres.
        #[arg(long, default_value = "postgres")]
        dialect: String,
        /// Connection string of the database to read.
        #[arg(long, value_name = "URL")]
        url: String,
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
    /// Applies the harness's migrations directly to the database
    /// `--url` names — the native counterpart of
    /// `wrangler d1 migrations apply` (issue #18). With `--fleet` or
    /// `--plan` the URL names the **control database** instead and the
    /// tenants in its registry are reconciled (RECONCILIATION.md).
    Apply {
        /// Target SQL dialect: postgres.
        #[arg(long, default_value = "postgres")]
        dialect: String,
        /// Connection string of the target database (the control
        /// database when `--fleet`, `--plan` or `--tenant` is given),
        /// e.g. `postgres://user:pass@host:5432/venture`.
        #[arg(long, value_name = "URL")]
        url: String,
        /// Reconcile every tenant in the control database's registry,
        /// each against its own database, instead of applying to the
        /// database `--url` names.
        #[arg(long)]
        fleet: bool,
        /// Print what would be applied, per tenant and per module,
        /// without applying anything.
        #[arg(long)]
        plan: bool,
        /// Reconcile one tenant only (registry id, not a DSN).
        #[arg(long, value_name = "TENANT")]
        tenant: Option<String>,
        /// Abort with a non-zero exit when any tenant is degraded,
        /// instead of letting the others serve. Needs `--fleet`.
        #[arg(long)]
        strict: bool,
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
        Command::Tables { command } => run_tables(command),
        Command::Migrations {
            command: MigrationsCommand::Collect { dialect, out },
        } => collect::collect(&harness, &dialect, &out),
        Command::Migrations {
            command:
                MigrationsCommand::Apply {
                    dialect,
                    url,
                    fleet,
                    plan,
                    tenant,
                    strict,
                },
        } => apply::apply(
            &harness,
            &dialect,
            &url,
            plan,
            fleet,
            tenant.as_deref(),
            strict,
        ),
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
        // Handled by `harness_free` before `build()` above: build and
        // client-ts generate from a file or a served contract rather than
        // a compiled-in harness, the workflow commands work on the
        // manifest and its records, and push reads the venture's
        // environment.
        Command::Build { .. }
        | Command::BuildKey { .. }
        | Command::ClientTs { .. }
        | Command::Plan { .. }
        | Command::Deploy { .. }
        | Command::Add { .. }
        | Command::Init { .. }
        | Command::Verify { .. }
        | Command::Push { .. }
        | Command::Auth { .. }
        | Command::Import { .. } => unreachable!("dispatched before the harness is built"),
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
/// rather than the compiled-in modules; `fz push` reads the venture's
/// *environment* rather than its modules; and `fz auth import` talks to a
/// URL. `None` for every other command,
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
        Command::BuildKey { manifest, catalog } => {
            Some(finish(crate::build_key::run(manifest, catalog.as_deref())))
        }
        // Two output disciplines, exactly as `fz doctor` runs them: prose
        // failures go through `finish`, `--json` prints its own object
        // and owns the exit code.
        Command::ClientTs { surface, out, json } => Some(if *json {
            client_ts::run_json(surface, out)
        } else {
            finish(client_ts::run(surface, out))
        }),
        Command::Push { command } => Some(finish(run_push(command))),
        Command::Auth { command } => Some(finish(run_auth(command))),
        Command::Import { command } => Some(finish(run_import(command))),
        _ => workflow::dispatch(command),
    }
}

/// `fz import` (issues #658, #727, #728): the bare command and `plan` run
/// inspect + plan; `inspect` writes the report alone; `dispositions init`
/// writes a skeleton dispositions file.
fn run_import(command: &ImportCommand) -> Result<(), String> {
    let ImportCommand::Supabase { command, run } = command;
    match command {
        None => import::plan(&plan_args(run)?),
        Some(SupabaseCommand::Plan { args }) => import::plan(&plan_args(args)?),
        Some(SupabaseCommand::Inspect {
            source,
            json,
            md: _,
            out,
            transfer_mbps,
            classify,
            classify_threshold,
            dispositions,
        }) => import::inspect(&import::InspectArgs {
            project: source.project.clone(),
            db_url: source.db_url.clone(),
            management_token: source.management_token.clone(),
            format: if *json {
                import::Format::Json
            } else {
                import::Format::Markdown
            },
            out: out.clone(),
            transfer_mbps: *transfer_mbps,
            classify: *classify,
            classify_threshold: *classify_threshold,
            dispositions: dispositions.clone(),
        }),
        Some(SupabaseCommand::Dispositions {
            command:
                DispositionsCommand::Init {
                    source,
                    out,
                    force,
                    dispositions,
                },
        }) => import::dispositions_init(&import::DispositionsInitArgs {
            project: source.project.clone(),
            db_url: source.db_url.clone(),
            management_token: source.management_token.clone(),
            out: out.clone(),
            force: *force,
            dispositions: dispositions.clone(),
        }),
    }
}

fn plan_args(run: &SupabaseRunArgs) -> Result<import::PlanArgs, String> {
    let project = run.project.clone().ok_or_else(|| {
        "no project ref: pass --project <ref>, the `<ref>` in https://<ref>.supabase.co".to_owned()
    })?;
    Ok(import::PlanArgs {
        project,
        db_url: run.db_url.clone(),
        management_token: run.management_token.clone(),
        target_env: run.target_env.clone(),
        dir: run.dir.clone(),
        transfer_mbps: run.transfer_mbps,
        classify: run.classify,
        classify_threshold: run.classify_threshold,
        apply: run.apply,
        plan: run.plan.clone(),
    })
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

/// `fz auth` (issue #650). The admin token is read from the environment
/// here — by the name `--admin-token-env` gives, through the same
/// [`EnvVars`] the rest of `fz` reads config with — and handed to the
/// import as a value, so it never becomes a flag in a shell history.
fn run_auth(command: &AuthCommand) -> Result<(), String> {
    match command {
        AuthCommand::Import {
            target,
            admin_token_env,
            apply,
            merge_by_email,
            report,
            batch_size,
            file,
        } => {
            let Some(admin_token) = EnvVars.get(admin_token_env) else {
                return Err(format!(
                    "the environment variable `{admin_token_env}` is not set or is empty (it \
                     must hold the auth-core admin token — the value the venture has as \
                     `ADMIN_TOKEN`)"
                ));
            };
            auth_import::run(&auth_import::ImportOptions {
                file: file.clone(),
                target: target.clone(),
                admin_token,
                apply: *apply,
                merge_by_email: *merge_by_email,
                report: report.clone(),
                batch_size: *batch_size,
            })
        }
    }
}

/// Runs the harness-free `fz` commands from a standalone binary (no
/// compiled-in venture): `fz build <manifest>`, which generates a harness;
/// `fz client-ts`, which generates the typed TypeScript client from the
/// contract a venture serves; the manifest workflow — `fz plan` /
/// `deploy` / `add` / `init` / `verify` — which works on the manifest and
/// its records, not on compiled-in modules; `fz push`, which reads the
/// venture's environment; and `fz auth`, which talks to a URL. Every
/// other command needs the venture's harness and says so.
#[must_use = "call process::exit with the returned ExitCode"]
pub fn run_standalone(args: impl IntoIterator<Item = String>) -> ExitCode {
    let mut full_argv: Vec<String> = Vec::with_capacity(8);
    full_argv.push("fz".to_string());
    full_argv.extend(args);
    let cli = Cli::parse_from(full_argv);
    let Some(exit) = harness_free(&cli.command) else {
        eprintln!(
            "fz: this command must run inside a venture (it needs the compiled-in harness — see \
             the cratefield-cli README). Only `fz build <manifest>`, `fz client-ts`, the manifest \
             workflow (`fz plan` / `deploy` / `add` / `init` / `verify`), `fz push`, `fz auth` \
             and `fz import` run standalone."
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

#[cfg(test)]
mod tests {
    use super::{Cli, Command, ImportCommand, SupabaseCommand};
    use clap::Parser as _;
    use std::ffi::OsString;

    fn parse(parts: &[&str]) -> Result<Cli, clap::Error> {
        let mut argv = vec![OsString::from("fz")];
        argv.extend(parts.iter().map(OsString::from));
        Cli::try_parse_from(argv)
    }

    #[test]
    fn the_bare_supabase_command_parses_the_run() {
        let cli = parse(&["import", "supabase", "--project", "abcdefghijklmnopqrst"])
            .expect("the bare run parses");
        let Command::Import {
            command: ImportCommand::Supabase { command, run },
        } = cli.command
        else {
            panic!("expected `import supabase`");
        };
        assert!(command.is_none());
        assert_eq!(run.project.as_deref(), Some("abcdefghijklmnopqrst"));
        assert_eq!(run.target_env, "DATABASE_URL");
        assert_eq!(run.dir, std::path::PathBuf::from("."));
        assert!(!run.apply);
        assert!(run.plan.is_none());
    }

    #[test]
    fn supabase_inspect_still_parses_without_the_run_args() {
        let cli = parse(&[
            "import",
            "supabase",
            "inspect",
            "--project",
            "abcdefghijklmnopqrst",
            "--json",
        ])
        .expect("inspect parses as before");
        let Command::Import {
            command: ImportCommand::Supabase { command, .. },
        } = cli.command
        else {
            panic!("expected `import supabase`");
        };
        assert!(matches!(
            command,
            Some(SupabaseCommand::Inspect { json: true, .. })
        ));
    }

    #[test]
    fn supabase_plan_parses_its_run_args() {
        let cli = parse(&[
            "import",
            "supabase",
            "plan",
            "--project",
            "abcdefghijklmnopqrst",
            "--dir",
            "/tmp/plan",
        ])
        .expect("plan parses");
        let Command::Import {
            command: ImportCommand::Supabase { command, .. },
        } = cli.command
        else {
            panic!("expected `import supabase`");
        };
        let Some(SupabaseCommand::Plan { args }) = command else {
            panic!("expected `plan`");
        };
        assert_eq!(args.project.as_deref(), Some("abcdefghijklmnopqrst"));
        assert_eq!(args.dir, std::path::PathBuf::from("/tmp/plan"));
    }

    #[test]
    fn apply_without_a_plan_is_refused() {
        let Err(error) = parse(&[
            "import",
            "supabase",
            "--project",
            "abcdefghijklmnopqrst",
            "--apply",
        ]) else {
            panic!("--apply without --plan must be refused");
        };
        assert!(error.to_string().contains("--plan"), "{error}");
    }

    #[test]
    fn the_bare_command_needs_a_project_at_run_time() {
        let Ok(cli) = parse(&["import", "supabase"]) else {
            panic!("the bare command parses (a subcommand may replace the run)");
        };
        let Command::Import {
            command: ImportCommand::Supabase { run, .. },
        } = cli.command
        else {
            panic!("expected `import supabase`");
        };
        assert!(run.project.is_none());
        let error = super::plan_args(&run).expect_err("a project ref is required");
        assert!(error.contains("--project"), "{error}");
    }
}
