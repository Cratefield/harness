//! The agent-safe workflow commands (harness #140): `fz plan`, `fz
//! deploy --plan <digest>`, `fz add`, `fz init` and `fz verify`. They
//! work on the venture manifest — the desired composition — and two
//! on-disk records: the migration lockfile (`.harness-lock.json`) and
//! the deploy record (`.harness-deploy.json`) that `fz deploy` writes.
//! They never run wrangler, never touch a database and never prompt:
//! turning the recorded composition into a running Worker stays with
//! `worker-build` and `wrangler deploy`, and applying migrations stays
//! with `fz migrations collect` / `wrangler d1 migrations apply` — the
//! same needs-human boundary `fz build` draws.
//!
//! Every command speaks the two disciplines `fz doctor --json`
//! established (harness #140). With `--json` it prints exactly one JSON
//! object on stdout — `schema` 1, `ok`, the `failures` each carrying a
//! stable code from [`crate::codes`] — and nothing else. Without it the
//! output is prose for the operator. `--non-interactive` is accepted on
//! every command: the workflow never prompts by construction, so the
//! flag's one effect is suppressing the human `next:` steps from prose
//! output; anything that would need a human is a coded refusal, never a
//! blocked process.
//!
//! [`PlanContent`] is the whole normalised plan; its sha256 (`fz plan
//! --json`'s `digest`) is the approval token. `fz deploy` recomputes the
//! plan from the current inputs and refuses any other digest — a stale
//! approval cannot deploy — and records the plan it applied. `fz
//! verify` diffs that record against the manifest and reports the drift
//! as coded failures in the doctor's JSON shape.

use crate::codes::{CODES, DoctorCodeDef};
use crate::doctor::DoctorFailure;
use crate::doctor::DoctorReport;
use crate::lock::{Lock, read_lock, sha256_hex};
use cratefield_core::VentureEnv;
use cratefield_manifest::{Catalog, ModuleSet, VentureManifest, builtin};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The `schema` field of every workflow JSON object — the same wire
/// contract `fz doctor --json` carries ([`crate::doctor::REPORT_SCHEMA`]).
pub const SCHEMA: u32 = 1;

/// The deploy record `fz deploy` writes next to the manifest: the plan
/// it applied, bound to the digest that approved it.
pub const RECORD_FILE: &str = ".harness-deploy.json";

/// A recorded deployment. `plan` is the full [`PlanContent`] that was
/// applied, so `fz verify` can name precisely which part of the
/// manifest drifted, and a stale `fz deploy` can name what moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployRecord {
    /// [`SCHEMA`]; consumers branch on it.
    pub schema: u32,
    /// The digest that approved the recorded plan.
    pub digest: String,
    /// The normalised plan content as it was deployed.
    pub plan: PlanContent,
}

/// The destination a plan describes: what the venture will become,
/// independent of what it is now. The sha256 over this struct's JSON
/// is the plan digest — the approval token — because an approval is of
/// the destination, not of the journey: the baseline-dependent deltas
/// ([`PlanContent`]'s added/removed lists) describe the journey and
/// change the moment a deployment is recorded, so hashing them would
/// make every deploy stale by its own success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanState {
    /// The venture name from the manifest.
    pub venture: String,
    /// The primary host from the manifest.
    pub host: String,
    /// The canonical public URL, when the manifest sets one.
    pub public_url: Option<String>,
    /// Browser origins allowed to call the API, sorted.
    pub cors_origins: Vec<String>,
    /// The resolved deployment environment (the manifest config's
    /// `ENV` key; `development` when unset or unrecognised).
    pub env: String,
    /// The resolved module set — dependencies before dependants —
    /// sorted, so manifest order cannot move the digest.
    pub modules: Vec<String>,
    /// The author's selection normalised: slug plus per-module config,
    /// sorted by slug. Per-module config changes are digest-visible
    /// here even when the resolved set is unchanged.
    pub selected: Vec<SelectedModule>,
    /// The venture-wide config the manifest declares.
    pub config: BTreeMap<String, String>,
    /// The seed SQL the manifest declares, if any.
    pub seed_sql: Option<String>,
    /// Migration status per resolved module, from the lockfile.
    pub migrations: MigrationState,
}

/// The full plan: the destination ([`PlanState`], flattened on the
/// wire, the only part the digest hashes) plus the deltas against the
/// current baseline — the deploy record when one exists, else the
/// modules the migration lockfile knows. Every list is sorted and
/// every map ordered, so output is a pure function of the inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanContent {
    /// The hashed destination.
    #[serde(flatten)]
    pub state: PlanState,
    /// Slugs in the resolved set that the baseline does not have,
    /// sorted.
    pub modules_added: Vec<String>,
    /// Baseline slugs the resolved set no longer carries, sorted.
    /// Removing a module takes its data out of the served venture, so
    /// a plan with any of these is destructive and `fz deploy` demands
    /// the second consent for it.
    pub modules_removed: Vec<String>,
    /// What each added module needs, from the catalog: its tier, the
    /// modules it requires, and whether the author selected it or a
    /// dependency pulled it in. Sorted by slug.
    pub capabilities: Vec<Capability>,
    /// Config keys the baseline does not have, sorted.
    pub config_added: Vec<String>,
    /// Baseline config keys the manifest drops, sorted.
    pub config_removed: Vec<String>,
    /// Baseline config keys whose value changed, sorted.
    pub config_changed: Vec<String>,
}

/// One manifest module reference, normalised: the slug and its
/// per-module config (empty for the bare-slug form).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SelectedModule {
    /// The module slug.
    pub slug: String,
    /// Per-module config keys, ordered.
    pub config: BTreeMap<String, String>,
}

/// What one added module needs, as the catalog declares it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Capability {
    /// The module slug.
    pub slug: String,
    /// `core` or `optional`.
    pub tier: String,
    /// The slugs this module requires; the catalog pulls them in, and
    /// resolution orders them before it.
    pub requires: Vec<String>,
    /// `selected` when the author listed it; `dependency` when another
    /// module's requirement pulled it into the set.
    pub via: String,
}

/// Migration status, read from the lockfile. The manifest world cannot
/// know whether a module ships migrations at all — only what has been
/// collected — so `not_collected` means "no locked migration exists",
/// phrased exactly that way in output.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MigrationState {
    /// Resolved module -> number of locked migration files, ordered.
    pub collected: BTreeMap<String, usize>,
    /// Resolved modules with no locked migrations, sorted.
    pub not_collected: Vec<String>,
    /// Lockfile entries (`module/id`) whose module the resolved set no
    /// longer carries, sorted — the migration files a removal orphans.
    pub orphaned: Vec<String>,
}

/// What the plan diffed against, and the slugs it saw there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Baseline {
    /// `deploy-record`, `lockfile` or `nothing`.
    pub source: &'static str,
    /// The baseline module slugs, sorted.
    pub modules: Vec<String>,
}

/// The outcome of `fz plan`: the normalised content and its digest.
#[derive(Debug, Clone)]
pub struct PlanOutcome {
    /// The normalised plan.
    pub content: PlanContent,
    /// sha256 over the JSON of [`PlanContent`] — the approval token
    /// `fz deploy --plan` demands.
    pub digest: String,
    /// What the deltas were computed against.
    pub baseline: Baseline,
}

/// The outcome of `fz deploy`.
#[derive(Debug, Clone)]
pub struct DeployOutcome {
    /// The plan that was applied.
    pub content: PlanContent,
    /// The digest that approved it.
    pub digest: String,
    /// `false` when the exact plan was already recorded — the
    /// idempotent second run changes nothing and says so.
    pub changed: bool,
    /// Where the record lives (or would live).
    pub record_path: PathBuf,
}

/// The outcome of `fz add`.
#[derive(Debug, Clone)]
pub struct AddOutcome {
    /// `false` when the module was already in the manifest — the
    /// no-op second run changes nothing and says so.
    pub changed: bool,
    /// The module slug named on the command line.
    pub module: String,
    /// The manifest file.
    pub manifest: PathBuf,
}

/// The outcome of `fz verify`: the doctor-shaped report plus the
/// recomputed digest when the manifest resolved far enough to compute
/// one.
#[derive(Debug)]
pub struct VerifyOutcome {
    /// Coded failures in the doctor's shape.
    pub report: DoctorReport,
    /// The recomputed plan digest, when available.
    pub digest: Option<String>,
}

/// Builds one coded failure.
fn failure(code: &'static DoctorCodeDef, message: impl Into<String>) -> DoctorFailure {
    DoctorFailure {
        code,
        message: message.into(),
    }
}

/// The prose form of a failure list, byte-compatible with the doctor's.
fn joined(failures: &[DoctorFailure]) -> String {
    failures
        .iter()
        .map(|f| f.message.as_str())
        .collect::<Vec<_>>()
        .join("\n  - ")
}

/// The deployment environment the manifest declares: its `ENV` config
/// key, `development` when absent or unrecognised. Unlike the deployed
/// runtime (issue #143), the manifest world has no compiled environment
/// to take the stricter of — the manifest is the declaration, and the
/// deployment's own `ENV` binding is checked where the harness exists,
/// by `fz doctor`.
fn resolved_env(manifest: &VentureManifest) -> VentureEnv {
    manifest
        .config
        .get("ENV")
        .and_then(|value| VentureEnv::parse(value))
        .unwrap_or_default()
}

/// Where the deploy record for this manifest lives: beside it.
fn record_path(manifest_path: &Path) -> PathBuf {
    let mut path = manifest_path.parent().map_or_else(PathBuf::new, |parent| {
        if parent.as_os_str().is_empty() {
            PathBuf::new()
        } else {
            parent.to_path_buf()
        }
    });
    path.push(RECORD_FILE);
    path
}

/// Reads the deploy record. Absent means never deployed (`None`); a
/// record that cannot be read or parsed is a real error.
fn read_record(manifest_path: &Path) -> Result<Option<DeployRecord>, String> {
    let path = record_path(manifest_path);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("cannot read {}: {err}", path.display())),
    };
    let record: DeployRecord = serde_json::from_str(&raw)
        .map_err(|err| format!("cannot parse {}: {err}", path.display()))?;
    if record.schema != SCHEMA {
        return Err(format!(
            "{}: unsupported schema {} (this fz speaks {SCHEMA})",
            path.display(),
            record.schema
        ));
    }
    Ok(Some(record))
}

/// Writes the deploy record atomically — write a sibling temp file,
/// then rename — so an interrupted deploy leaves either the previous
/// record or the new one, never a torn file, and re-running `fz
/// deploy` reconciles.
fn write_record(manifest_path: &Path, record: &DeployRecord) -> Result<PathBuf, String> {
    let path = record_path(manifest_path);
    let body = serde_json::to_string_pretty(record)
        .map_err(|err| format!("cannot serialize the deploy record: {err}"))?;
    let mut tmp = path.clone();
    tmp.set_extension("tmp");
    std::fs::write(&tmp, body + "\n")
        .map_err(|err| format!("cannot write {}: {err}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|err| {
        format!(
            "cannot finalize {} (partial file left at {}): {err}",
            path.display(),
            tmp.display()
        )
    })?;
    Ok(path)
}

/// Writes a manifest back in the format its extension names — JSON by
/// default, TOML for `.toml`. Comments and formatting of the original
/// file are not preserved; the parsed document is.
fn write_manifest(path: &Path, manifest: &VentureManifest) -> Result<(), String> {
    let body = match path.extension().and_then(|ext| ext.to_str()) {
        Some("toml") => toml::to_string_pretty(manifest)
            .map_err(|err| format!("cannot serialize TOML manifest: {err}"))?,
        _ => serde_json::to_string_pretty(manifest)
            .map_err(|err| format!("cannot serialize manifest: {err}"))?,
    };
    std::fs::write(path, body + "\n")
        .map_err(|err| format!("cannot write {}: {err}", path.display()))
}

/// Everything the workflow commands read: the manifest (parsed and
/// resolved), the migration lockfile and the deploy record.
struct Inputs {
    manifest: VentureManifest,
    set: ModuleSet,
    lock: Lock,
    record: Option<DeployRecord>,
    catalog: Catalog,
}

/// Reads and resolves the inputs. The manifest is upstream of
/// everything, so it fails fast; lockfile and deploy-record problems
/// accumulate and surface together.
fn load(manifest_path: &Path, migrations_dir: &Path) -> Result<Inputs, Vec<DoctorFailure>> {
    let raw = std::fs::read_to_string(manifest_path).map_err(|err| {
        vec![failure(
            &CODES.manifest_unreadable,
            format!("cannot read {}: {err}", manifest_path.display()),
        )]
    })?;
    let manifest = crate::build::parse(manifest_path, &raw).map_err(|err| {
        vec![failure(
            &CODES.manifest_unreadable,
            format!("{}: {err}", manifest_path.display()),
        )]
    })?;
    let catalog = builtin();
    let set = manifest
        .resolve(&catalog)
        .map_err(|err| vec![failure(&CODES.manifest_invalid, err.to_string())])?;

    let mut failures: Vec<DoctorFailure> = Vec::new();
    let lock = match read_lock(migrations_dir) {
        Ok(lock) => lock,
        Err(err) => {
            failures.push(failure(&CODES.lockfile_unreadable, err));
            Lock::default()
        }
    };
    let record = match read_record(manifest_path) {
        Ok(record) => record,
        Err(err) => {
            failures.push(failure(&CODES.deploy_record_unreadable, err));
            None
        }
    };
    if failures.is_empty() {
        Ok(Inputs {
            manifest,
            set,
            lock,
            record,
            catalog,
        })
    } else {
        Err(failures)
    }
}

/// The module slugs the lockfile knows, sorted — the collected
/// composition, as close to "what deployment tooling last saw" as the
/// manifest world gets without a deploy record.
fn lockfile_modules(lock: &Lock) -> Vec<String> {
    let mut modules: Vec<String> = lock
        .keys()
        .filter_map(|key| key.split('/').next())
        .filter(|module| !module.is_empty())
        .map(str::to_owned)
        .collect();
    modules.sort_unstable();
    modules.dedup();
    modules
}

/// What the plan diffs against: the deploy record when one exists,
/// else the lockfile's modules, else nothing.
fn baseline_of(lock: &Lock, record: Option<&DeployRecord>) -> Baseline {
    if let Some(record) = record {
        let mut modules = record.plan.state.modules.clone();
        modules.sort_unstable();
        return Baseline {
            source: "deploy-record",
            modules,
        };
    }
    let modules = lockfile_modules(lock);
    if modules.is_empty() {
        Baseline {
            source: "nothing",
            modules: Vec::new(),
        }
    } else {
        Baseline {
            source: "lockfile",
            modules,
        }
    }
}

/// What each added module needs, as the catalog declares it: tier,
/// required modules, and whether the author selected it or a
/// dependency pulled it in.
fn capabilities_of(added: &[String], selected: &[&str], catalog: &Catalog) -> Vec<Capability> {
    added
        .iter()
        .filter_map(|slug| {
            let module = catalog.modules.iter().find(|m| &m.slug == slug)?;
            let tier = match module.tier {
                cratefield_manifest::Tier::Core => "core",
                cratefield_manifest::Tier::Optional => "optional",
            };
            let mut requires = module.depends_on.clone();
            requires.sort_unstable();
            Some(Capability {
                slug: slug.clone(),
                tier: tier.to_owned(),
                requires,
                via: if selected.contains(&slug.as_str()) {
                    "selected".to_owned()
                } else {
                    "dependency".to_owned()
                },
            })
        })
        .collect()
}

/// The venture-wide config deltas against the recorded config.
fn config_deltas(
    manifest: &VentureManifest,
    recorded: &BTreeMap<String, String>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let config_added: Vec<String> = manifest
        .config
        .keys()
        .filter(|key| !recorded.contains_key(*key))
        .cloned()
        .collect();
    let config_removed: Vec<String> = recorded
        .keys()
        .filter(|key| !manifest.config.contains_key(*key))
        .cloned()
        .collect();
    let config_changed: Vec<String> = manifest
        .config
        .iter()
        .filter(|(key, value)| {
            recorded
                .get(*key)
                .is_some_and(|recorded| recorded != *value)
        })
        .map(|(key, _)| key.clone())
        .collect();
    (config_added, config_removed, config_changed)
}

/// Migration status per resolved module, read from the lockfile.
fn migration_state(desired: &[String], lock: &Lock) -> MigrationState {
    let mut state = MigrationState::default();
    for key in lock.keys() {
        let Some(module) = key.split('/').next() else {
            continue;
        };
        if desired.iter().any(|slug| slug == module) {
            *state.collected.entry(module.to_owned()).or_insert(0) += 1;
        } else {
            state.orphaned.push(key.clone());
        }
    }
    state.not_collected = desired
        .iter()
        .filter(|slug| !state.collected.contains_key(*slug))
        .cloned()
        .collect();
    state.orphaned.sort_unstable();
    state
}

/// Computes the normalised plan and its baseline. Pure: the same
/// inputs always produce the same content, so the same digest.
#[must_use]
fn compute_plan(
    manifest: &VentureManifest,
    set: &ModuleSet,
    lock: &Lock,
    record: Option<&DeployRecord>,
    catalog: &Catalog,
) -> (PlanContent, Baseline) {
    let mut desired = set.slugs().to_vec();
    desired.sort_unstable();
    let baseline = baseline_of(lock, record);
    let modules_added: Vec<String> = desired
        .iter()
        .filter(|slug| !baseline.modules.contains(slug))
        .cloned()
        .collect();
    let modules_removed: Vec<String> = baseline
        .modules
        .iter()
        .filter(|slug| !desired.contains(slug))
        .cloned()
        .collect();

    let selected_slugs = manifest.module_slugs();
    let capabilities = capabilities_of(&modules_added, &selected_slugs, catalog);
    let recorded_config: &BTreeMap<String, String> = match record {
        Some(record) => &record.plan.state.config,
        None => &BTreeMap::new(),
    };
    let (config_added, config_removed, config_changed) = config_deltas(manifest, recorded_config);

    let mut selected: Vec<SelectedModule> = manifest
        .modules
        .iter()
        .map(|module| SelectedModule {
            slug: module.slug().to_owned(),
            config: module.config(),
        })
        .collect();
    selected.sort_unstable();

    let migrations = migration_state(&desired, lock);
    let mut cors_origins = manifest.cors_origins.clone();
    cors_origins.sort_unstable();

    let state = PlanState {
        venture: manifest.name.clone(),
        host: manifest.host.clone(),
        public_url: manifest.public_url.clone(),
        cors_origins,
        env: resolved_env(manifest).as_str().to_owned(),
        modules: desired,
        selected,
        config: manifest.config.clone(),
        seed_sql: manifest.seed_sql.clone(),
        migrations,
    };
    let content = PlanContent {
        state,
        modules_added,
        modules_removed,
        capabilities,
        config_added,
        config_removed,
        config_changed,
    };
    (content, baseline)
}

/// The digest of a plan: sha256 over the normalised destination
/// state's JSON — deliberately not over the baseline-dependent deltas,
/// so a deploy does not go stale by its own success.
///
/// # Errors
///
/// Only if `serde_json` cannot serialize the content — a struct of
/// strings, maps and lists cannot hit that, but the Result keeps every
/// caller total instead of panicking.
fn plan_digest(content: &PlanContent) -> Result<String, Vec<DoctorFailure>> {
    serde_json::to_vec(&content.state)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|err| {
            vec![failure(
                &CODES.manifest_invalid,
                format!("the plan content does not serialize: {err}"),
            )]
        })
}

/// `fz plan`: describes what the manifest would change, and nothing
/// else. Read-only by construction — nothing here touches the disk
/// beyond reading its inputs.
///
/// # Errors
///
/// Coded failures when the manifest cannot be read or resolved, or the
/// lockfile or deploy record cannot be parsed.
pub fn plan(
    manifest_path: &Path,
    migrations_dir: &Path,
) -> Result<PlanOutcome, Vec<DoctorFailure>> {
    let inputs = load(manifest_path, migrations_dir)?;
    let (content, baseline) = compute_plan(
        &inputs.manifest,
        &inputs.set,
        &inputs.lock,
        inputs.record.as_ref(),
        &inputs.catalog,
    );
    let digest = plan_digest(&content)?;
    Ok(PlanOutcome {
        content,
        digest,
        baseline,
    })
}

/// What moved between the recorded state and the one recomputed now —
/// the message a stale `fz deploy` shows. Every field is named; when
/// none differs the digests can disagree only by a plan-format
/// evolution, and the message says that too.
fn moved_since(current: &PlanState, recorded: &PlanState) -> Vec<String> {
    let mut moved: Vec<String> = Vec::new();
    if let Some(what) = diff_modules(&current.modules, &recorded.modules) {
        moved.push(format!("modules: {what}"));
    }
    if let Some(what) = diff_config(&current.config, &recorded.config) {
        moved.push(format!("config: {what}"));
    }
    if current.env != recorded.env {
        moved.push(format!("environment: {} -> {}", recorded.env, current.env));
    }
    if current.host != recorded.host {
        moved.push(format!("host: {} -> {}", recorded.host, current.host));
    }
    if current.public_url != recorded.public_url {
        moved.push("public URL changed".to_owned());
    }
    if current.cors_origins != recorded.cors_origins {
        moved.push("CORS origins changed".to_owned());
    }
    if current.seed_sql != recorded.seed_sql {
        moved.push("seed SQL changed".to_owned());
    }
    if current.selected != recorded.selected {
        moved.push("the module selection or its per-module config changed".to_owned());
    }
    moved
}

/// One line about a module-set difference, or `None` when equal.
fn diff_modules(current: &[String], recorded: &[String]) -> Option<String> {
    let added: Vec<&String> = current
        .iter()
        .filter(|slug| !recorded.contains(slug))
        .collect();
    let removed: Vec<&String> = recorded
        .iter()
        .filter(|slug| !current.contains(slug))
        .collect();
    if added.is_empty() && removed.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    if !added.is_empty() {
        parts.push(format!(
            "added {}",
            added
                .iter()
                .map(|slug| slug.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !removed.is_empty() {
        parts.push(format!(
            "removed {}",
            removed
                .iter()
                .map(|slug| slug.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Some(parts.join("; "))
}

/// One line about a config difference, or `None` when equal.
fn diff_config(
    current: &BTreeMap<String, String>,
    recorded: &BTreeMap<String, String>,
) -> Option<String> {
    let added: Vec<&String> = current
        .keys()
        .filter(|key| !recorded.contains_key(*key))
        .collect();
    let removed: Vec<&String> = recorded
        .keys()
        .filter(|key| !current.contains_key(*key))
        .collect();
    let changed: Vec<&String> = current
        .iter()
        .filter(|(key, value)| recorded.get(*key).is_some_and(|r| r != *value))
        .map(|(key, _)| key)
        .collect();
    if added.is_empty() && removed.is_empty() && changed.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    let list = |keys: &[&String]| {
        keys.iter()
            .map(|key| key.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if !added.is_empty() {
        parts.push(format!("added {}", list(&added)));
    }
    if !removed.is_empty() {
        parts.push(format!("removed {}", list(&removed)));
    }
    if !changed.is_empty() {
        parts.push(format!("changed {}", list(&changed)));
    }
    Some(parts.join("; "))
}

/// `fz deploy --plan <digest>`: applies exactly the approved plan — by
/// recording it, bound to its digest, in `.harness-deploy.json` beside
/// the manifest. It refuses:
///
/// - without `--plan` at all (approval is the point);
/// - a digest that does not match a plan recomputed now, naming what
///   moved since the recorded deployment;
/// - a production venture without `--i-am-deploying-to-production` —
///   the second consent, deliberately unlike the first;
/// - a plan that removes modules (their data leaves the venture)
///   without that same flag.
///
/// Writing the composition itself — compiling, standing up the Worker,
/// applying migrations — stays with the needs-human steps `fz build`
/// and the wrangler flow own. Running the same approved deploy twice
/// is safe: the second run records nothing and reports `changed:
/// false`.
///
/// # Errors
///
/// Coded failures for every refusal above, plus unreadable inputs and
/// a record that cannot be written.
pub fn deploy(
    approved: Option<&str>,
    manifest_path: &Path,
    migrations_dir: &Path,
    consent: bool,
) -> Result<DeployOutcome, Vec<DoctorFailure>> {
    let Some(approved) = approved else {
        return Err(vec![failure(
            &CODES.deploy_plan_required,
            "deploy requires an approved plan — run `fz plan --json` and pass its `digest` \
             as --plan; there is no default",
        )]);
    };
    let inputs = load(manifest_path, migrations_dir)?;
    let (planned, _) = compute_plan(
        &inputs.manifest,
        &inputs.set,
        &inputs.lock,
        inputs.record.as_ref(),
        &inputs.catalog,
    );
    let digest = plan_digest(&planned)?;

    let mut failures: Vec<DoctorFailure> = Vec::new();
    if approved != digest {
        failures.push(failure(
            &CODES.stale_plan,
            stale_plan_message(&planned, inputs.record.as_ref(), approved, &digest),
        ));
    }
    if resolved_env(&inputs.manifest) == VentureEnv::Production && !consent {
        failures.push(failure(
            &CODES.production_deploy_unauthorized,
            "this venture resolves to production (manifest config ENV=production) — deploying \
             needs a second, explicit consent: pass --i-am-deploying-to-production alongside \
             the approved digest",
        ));
    }
    if !planned.modules_removed.is_empty() && !consent {
        failures.push(failure(
            &CODES.destructive_change_unauthorized,
            format!(
                "this plan removes {} from the served composition — its data leaves the \
                 venture; pass --i-am-deploying-to-production to accept that",
                planned.modules_removed.join(", ")
            ),
        ));
    }
    if !failures.is_empty() {
        return Err(failures);
    }

    let record_path = record_path(manifest_path);
    if inputs
        .record
        .as_ref()
        .is_some_and(|record| record.digest == digest)
    {
        return Ok(DeployOutcome {
            content: planned,
            digest,
            changed: false,
            record_path,
        });
    }
    let record = DeployRecord {
        schema: SCHEMA,
        digest: digest.clone(),
        plan: planned.clone(),
    };
    let record_path = write_record(manifest_path, &record)
        .map_err(|err| vec![failure(&CODES.manifest_write_failed, err)])?;
    Ok(DeployOutcome {
        content: planned,
        digest,
        changed: true,
        record_path,
    })
}

/// Why the approved digest is stale, naming what moved: every field
/// that differs from the recorded deployment, or — when none does —
/// the honest answer that the digest came from a different fz or an
/// older plan format.
fn stale_plan_message(
    planned: &PlanContent,
    record: Option<&DeployRecord>,
    approved: &str,
    digest: &str,
) -> String {
    let mut message = format!(
        "the approved digest {approved} does not match a plan recomputed from the current \
         inputs (the current digest is {digest})"
    );
    let Some(record) = record else {
        let mut what: Vec<String> = Vec::new();
        if !planned.modules_added.is_empty() {
            what.push(format!("add {}", planned.modules_added.join(", ")));
        }
        if !planned.modules_removed.is_empty() {
            what.push(format!("remove {}", planned.modules_removed.join(", ")));
        }
        if what.is_empty() {
            message
                .push_str("; no deployment is recorded yet, so there is nothing to diff against");
        } else {
            message.push_str("; no deployment is recorded yet and the current plan would ");
            message.push_str(&what.join(" and "));
        }
        return message;
    };
    let moved = moved_since(&planned.state, &record.plan.state);
    if moved.is_empty() {
        message.push_str(
            "; the recorded deployment matches every plan field, so the approved digest was \
             computed by a different fz or an older plan format",
        );
    } else {
        message.push_str("; since the recorded deployment: ");
        message.push_str(&moved.join("; "));
    }
    message
}

/// `fz add <module>`: adds a module to the manifest's desired
/// composition and nothing else — it never deploys, never provisions
/// and never touches a database. Adding a module the manifest already
/// lists is a no-op that succeeds with `changed: false`.
///
/// # Errors
///
/// Coded failures when the manifest cannot be read or resolved, the
/// slug is not in the catalog, or the manifest cannot be written back.
pub fn add(module: &str, manifest_path: &Path) -> Result<AddOutcome, Vec<DoctorFailure>> {
    let raw = std::fs::read_to_string(manifest_path).map_err(|err| {
        vec![failure(
            &CODES.manifest_unreadable,
            format!("cannot read {}: {err}", manifest_path.display()),
        )]
    })?;
    let mut manifest = crate::build::parse(manifest_path, &raw).map_err(|err| {
        vec![failure(
            &CODES.manifest_unreadable,
            format!("{}: {err}", manifest_path.display()),
        )]
    })?;
    let catalog = builtin();
    manifest
        .resolve(&catalog)
        .map_err(|err| vec![failure(&CODES.manifest_invalid, err.to_string())])?;

    if manifest.module_slugs().contains(&module) {
        return Ok(AddOutcome {
            changed: false,
            module: module.to_owned(),
            manifest: manifest_path.to_path_buf(),
        });
    }

    let known: Vec<&str> = catalog.modules.iter().map(|m| m.slug.as_str()).collect();
    if !known.contains(&module) {
        return Err(vec![failure(
            &CODES.module_unknown,
            format!(
                "`{module}` is not a module in the catalog; available: {}",
                known.join(", ")
            ),
        )]);
    }
    manifest
        .modules
        .push(cratefield_manifest::ModuleRef::Slug(module.to_owned()));
    manifest
        .resolve(&catalog)
        .map_err(|err| vec![failure(&CODES.manifest_invalid, err.to_string())])?;
    write_manifest(manifest_path, &manifest)
        .map_err(|err| vec![failure(&CODES.manifest_write_failed, err)])?;
    Ok(AddOutcome {
        changed: true,
        module: module.to_owned(),
        manifest: manifest_path.to_path_buf(),
    })
}

/// `fz init`: writes a new venture manifest — name and host, no
/// modules yet. Refuses to overwrite an existing manifest unless
/// `--force`.
///
/// # Errors
///
/// Coded failures when the file exists without `--force`, the name or
/// host is empty, or the manifest cannot be written.
pub fn init(
    name: &str,
    host: &str,
    manifest_path: &Path,
    force: bool,
) -> Result<PathBuf, Vec<DoctorFailure>> {
    if manifest_path.exists() && !force {
        return Err(vec![failure(
            &CODES.manifest_exists,
            format!(
                "{} already exists — init refuses to overwrite a manifest; pass --force to \
                 replace it",
                manifest_path.display()
            ),
        )]);
    }
    let manifest = VentureManifest {
        name: name.to_owned(),
        host: host.to_owned(),
        public_url: None,
        cors_origins: Vec::new(),
        modules: Vec::new(),
        config: BTreeMap::new(),
        seed_sql: None,
    };
    manifest
        .validate()
        .map_err(|err| vec![failure(&CODES.manifest_invalid, err.to_string())])?;
    write_manifest(manifest_path, &manifest)
        .map_err(|err| vec![failure(&CODES.manifest_write_failed, err)])?;
    Ok(manifest_path.to_path_buf())
}

/// `fz verify`: diffs the recorded deployment against the manifest and
/// reports every drift as a coded failure in the doctor's shape —
/// composition, config, environment, and (when nothing narrower
/// explains it) the recorded digest no longer matching a recomputed
/// plan.
///
/// # Panics
///
/// Never; every problem is a coded failure in the report.
#[must_use]
pub fn verify(manifest_path: &Path, migrations_dir: &Path) -> VerifyOutcome {
    let inputs = match load(manifest_path, migrations_dir) {
        Ok(inputs) => inputs,
        Err(failures) => {
            return VerifyOutcome {
                report: DoctorReport { failures },
                digest: None,
            };
        }
    };
    let (content, _) = compute_plan(
        &inputs.manifest,
        &inputs.set,
        &inputs.lock,
        inputs.record.as_ref(),
        &inputs.catalog,
    );
    let mut failures: Vec<DoctorFailure> = Vec::new();
    let digest = match plan_digest(&content) {
        Ok(digest) => digest,
        Err(new_failures) => {
            return VerifyOutcome {
                report: DoctorReport {
                    failures: new_failures,
                },
                digest: None,
            };
        }
    };

    let Some(record) = &inputs.record else {
        failures.push(failure(
            &CODES.not_deployed,
            "no deployment is recorded for this manifest — run `fz plan --json`, approve the \
             digest, then `fz deploy --plan <digest>`",
        ));
        return VerifyOutcome {
            report: DoctorReport { failures },
            digest: Some(digest),
        };
    };

    if let Some(what) = diff_modules(&content.state.modules, &record.plan.state.modules) {
        failures.push(failure(
            &CODES.composition_drift,
            format!("the recorded deployment's module set drifted from the manifest: {what}"),
        ));
    }
    if let Some(what) = diff_config(&content.state.config, &record.plan.state.config) {
        failures.push(failure(
            &CODES.config_drift,
            format!("the recorded deployment's config drifted from the manifest: {what}"),
        ));
    }
    if content.state.env != record.plan.state.env {
        failures.push(failure(
            &CODES.env_drift,
            format!(
                "the deployment environment drifted: recorded {}, manifest resolves to {}",
                record.plan.state.env, content.state.env
            ),
        ));
    }
    let narrow = failures.len();
    if record.digest != digest {
        let moved = moved_since(&content.state, &record.plan.state);
        let message = if moved.is_empty() {
            format!(
                "the recorded digest does not match a plan recomputed from the manifest, and \
                 no module, config or environment drift explains it — the venture's host, \
                 public URL, CORS origins, seed SQL or per-module config changed since the \
                 deployment was recorded (recorded {}, current {digest})",
                record.digest
            )
        } else {
            format!(
                "the recorded digest does not match a plan recomputed from the manifest \
                 (recorded {}, current {digest}): {}",
                record.digest,
                moved.join("; ")
            )
        };
        if failures.len() == narrow {
            failures.push(failure(&CODES.manifest_drift, message));
        }
    }
    VerifyOutcome {
        report: DoctorReport { failures },
        digest: Some(digest),
    }
}

/// One failure as it travels on the wire: the catalogue slug plus the
/// message, in the doctor's shape.
#[derive(Serialize)]
struct FailRef<'a> {
    code: &'a str,
    message: &'a str,
}

/// Every workflow failure payload: the doctor's object, nothing more.
#[derive(Serialize)]
struct BarePayload<'a> {
    schema: u32,
    ok: bool,
    failures: Vec<FailRef<'a>>,
}

/// The `fz plan --json` object: the verdict plus the plan content and
/// its digest.
#[derive(Serialize)]
struct PlanPayload<'a> {
    schema: u32,
    ok: bool,
    failures: Vec<FailRef<'a>>,
    digest: &'a str,
    #[serde(flatten)]
    content: &'a PlanContent,
    baseline: &'a Baseline,
}

/// The `fz deploy --json` object.
#[derive(Serialize)]
struct DeployPayload<'a> {
    schema: u32,
    ok: bool,
    failures: Vec<FailRef<'a>>,
    changed: bool,
    digest: &'a str,
    venture: &'a str,
    env: &'a str,
    modules_added: &'a [String],
    modules_removed: &'a [String],
    record: String,
}

/// The `fz add --json` object.
#[derive(Serialize)]
struct AddPayload<'a> {
    schema: u32,
    ok: bool,
    failures: Vec<FailRef<'a>>,
    changed: bool,
    module: &'a str,
    manifest: String,
}

/// The `fz init --json` object.
#[derive(Serialize)]
struct InitPayload<'a> {
    schema: u32,
    ok: bool,
    failures: Vec<FailRef<'a>>,
    name: &'a str,
    host: &'a str,
    manifest: String,
}

fn refs(failures: &[DoctorFailure]) -> Vec<FailRef<'_>> {
    failures
        .iter()
        .map(|failure| FailRef {
            code: failure.code.code,
            message: &failure.message,
        })
        .collect()
}

/// Prints one JSON object — the payload plus the exit code it implies.
/// Serialization cannot fail for these structs; the stderr fallback
/// mirrors [`crate::doctor::doctor_json`].
fn emit(payload: &impl Serialize, exit: ExitCode) -> ExitCode {
    match serde_json::to_string(payload) {
        Ok(line) => {
            println!("{line}");
            exit
        }
        Err(err) => {
            eprintln!("fz: cannot serialize the report: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Prints a failure list under the active discipline: one JSON object
/// under `--json`, the joined prose on stderr otherwise.
fn fail(failures: &[DoctorFailure], json: bool) -> ExitCode {
    if json {
        let payload = BarePayload {
            schema: SCHEMA,
            ok: false,
            failures: refs(failures),
        };
        return emit(&payload, ExitCode::FAILURE);
    }
    eprintln!("fz: {}", joined(failures));
    ExitCode::FAILURE
}

/// The `fz plan` CLI entry: both output disciplines.
#[must_use = "call process::exit with the returned ExitCode"]
pub fn plan_cli(
    manifest_path: &Path,
    migrations_dir: &Path,
    json: bool,
    non_interactive: bool,
) -> ExitCode {
    match plan(manifest_path, migrations_dir) {
        Ok(outcome) => {
            if json {
                let payload = PlanPayload {
                    schema: SCHEMA,
                    ok: true,
                    failures: Vec::new(),
                    digest: &outcome.digest,
                    content: &outcome.content,
                    baseline: &outcome.baseline,
                };
                return emit(&payload, ExitCode::SUCCESS);
            }
            println!(
                "fz plan: {} (env: {})",
                outcome.content.state.venture, outcome.content.state.env
            );
            println!("  digest:     {}", outcome.digest);
            println!(
                "  baseline:   {} ({})",
                outcome.baseline.source,
                or_none(&outcome.baseline.modules)
            );
            println!("  added:      {}", or_none(&outcome.content.modules_added));
            println!(
                "  removed:    {}",
                or_none(&outcome.content.modules_removed)
            );
            let mut config = Vec::new();
            for key in &outcome.content.config_added {
                config.push(format!("+{key}"));
            }
            for key in &outcome.content.config_removed {
                config.push(format!("-{key}"));
            }
            for key in &outcome.content.config_changed {
                config.push(format!("~{key}"));
            }
            println!(
                "  config:     {}",
                if config.is_empty() {
                    "(unchanged)".to_owned()
                } else {
                    config.join(" ")
                }
            );
            println!(
                "  migrations: not collected for {} / orphaned {}",
                or_none(&outcome.content.state.migrations.not_collected),
                or_none(&outcome.content.state.migrations.orphaned)
            );
            for capability in &outcome.content.capabilities {
                println!(
                    "  needs:      {} ({} module, requires {}, {})",
                    capability.slug,
                    capability.tier,
                    or_none(&capability.requires),
                    capability.via
                );
            }
            if !non_interactive {
                println!();
                println!("next:");
                println!(
                    "  fz deploy --plan {}   # apply exactly this plan",
                    outcome.digest
                );
            }
            ExitCode::SUCCESS
        }
        Err(failures) => fail(&failures, json),
    }
}

/// `"(none)"` for an empty list, the comma-joined list otherwise.
fn or_none(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_owned()
    } else {
        items.join(", ")
    }
}

/// The `fz deploy` CLI entry: both output disciplines.
#[must_use = "call process::exit with the returned ExitCode"]
pub fn deploy_cli(
    approved: Option<&str>,
    manifest_path: &Path,
    migrations_dir: &Path,
    consent: bool,
    json: bool,
    non_interactive: bool,
) -> ExitCode {
    match deploy(approved, manifest_path, migrations_dir, consent) {
        Ok(outcome) => {
            if json {
                let payload = DeployPayload {
                    schema: SCHEMA,
                    ok: true,
                    failures: Vec::new(),
                    changed: outcome.changed,
                    digest: &outcome.digest,
                    venture: &outcome.content.state.venture,
                    env: &outcome.content.state.env,
                    modules_added: &outcome.content.modules_added,
                    modules_removed: &outcome.content.modules_removed,
                    record: outcome.record_path.display().to_string(),
                };
                return emit(&payload, ExitCode::SUCCESS);
            }
            if !outcome.changed {
                println!(
                    "fz deploy: nothing to do — plan {} is already the recorded deployment",
                    outcome.digest
                );
                return ExitCode::SUCCESS;
            }
            println!(
                "fz deploy: {} (env: {})",
                outcome.content.state.venture, outcome.content.state.env
            );
            println!("  digest:     {}", outcome.digest);
            println!("  added:      {}", or_none(&outcome.content.modules_added));
            println!(
                "  removed:    {}",
                or_none(&outcome.content.modules_removed)
            );
            println!("  record:     {}", outcome.record_path.display());
            if !non_interactive {
                println!();
                println!("next (needs a human or credentials fz does not hold):");
                println!(
                    "  fz migrations collect        # materialise the wrangler migration files"
                );
                println!("  fz doctor                    # harness validity, production rules");
                println!("  worker-build --release       # compile the venture to wasm");
                println!("  wrangler deploy              # stand up the Worker + D1");
            }
            ExitCode::SUCCESS
        }
        Err(failures) => fail(&failures, json),
    }
}

/// The `fz add` CLI entry: both output disciplines.
#[must_use = "call process::exit with the returned ExitCode"]
pub fn add_cli(module: &str, manifest_path: &Path, json: bool, non_interactive: bool) -> ExitCode {
    match add(module, manifest_path) {
        Ok(outcome) => {
            if json {
                let payload = AddPayload {
                    schema: SCHEMA,
                    ok: true,
                    failures: Vec::new(),
                    changed: outcome.changed,
                    module: &outcome.module,
                    manifest: outcome.manifest.display().to_string(),
                };
                return emit(&payload, ExitCode::SUCCESS);
            }
            if outcome.changed {
                println!(
                    "fz add: added `{}` to {} — the desired composition only; nothing was \
                     deployed, provisioned or migrated",
                    outcome.module,
                    outcome.manifest.display()
                );
                if !non_interactive {
                    println!();
                    println!("next:");
                    println!("  fz plan --json   # see what this would change and get its digest");
                }
            } else {
                println!(
                    "fz add: `{}` is already in {} — nothing changed",
                    outcome.module,
                    outcome.manifest.display()
                );
            }
            ExitCode::SUCCESS
        }
        Err(failures) => fail(&failures, json),
    }
}

/// The `fz init` CLI entry: both output disciplines.
#[must_use = "call process::exit with the returned ExitCode"]
pub fn init_cli(
    name: &str,
    host: &str,
    manifest_path: &Path,
    force: bool,
    json: bool,
    non_interactive: bool,
) -> ExitCode {
    match init(name, host, manifest_path, force) {
        Ok(path) => {
            if json {
                let payload = InitPayload {
                    schema: SCHEMA,
                    ok: true,
                    failures: Vec::new(),
                    name,
                    host,
                    manifest: path.display().to_string(),
                };
                return emit(&payload, ExitCode::SUCCESS);
            }
            println!(
                "fz init: wrote {} (venture {name}, host {host}, no modules yet)",
                path.display()
            );
            if !non_interactive {
                println!();
                println!("next:");
                println!(
                    "  fz add <module>   # grow the desired composition, one module at a time"
                );
            }
            ExitCode::SUCCESS
        }
        Err(failures) => fail(&failures, json),
    }
}

/// The `fz verify` CLI entry: both output disciplines. The JSON shape
/// is the doctor's, byte for byte.
#[must_use = "call process::exit with the returned ExitCode"]
pub fn verify_cli(manifest_path: &Path, migrations_dir: &Path, json: bool) -> ExitCode {
    let outcome = verify(manifest_path, migrations_dir);
    if json {
        match outcome.report.render_json() {
            Ok(payload) => {
                println!("{payload}");
                return if outcome.report.ok() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                };
            }
            Err(err) => {
                eprintln!("fz: cannot serialize the report: {err}");
                return ExitCode::FAILURE;
            }
        }
    }
    if outcome.report.ok() {
        match outcome.digest {
            Some(digest) => println!(
                "fz verify: the recorded deployment matches the manifest (digest {digest})"
            ),
            None => println!("fz verify: no problems found"),
        }
        ExitCode::SUCCESS
    } else {
        eprintln!("fz: {}", joined(&outcome.report.failures));
        ExitCode::FAILURE
    }
}

/// Routes the workflow commands — the ones that need no compiled-in
/// harness — or `None` for every other command.
pub(crate) fn dispatch(command: &crate::Command) -> Option<ExitCode> {
    match command {
        crate::Command::Plan {
            manifest,
            migrations,
            json,
            non_interactive,
        } => Some(plan_cli(manifest, migrations, *json, *non_interactive)),
        crate::Command::Deploy {
            plan,
            manifest,
            migrations,
            i_am_deploying_to_production,
            json,
            non_interactive,
        } => Some(deploy_cli(
            plan.as_deref(),
            manifest,
            migrations,
            *i_am_deploying_to_production,
            *json,
            *non_interactive,
        )),
        crate::Command::Add {
            module,
            manifest,
            json,
            non_interactive,
        } => Some(add_cli(module, manifest, *json, *non_interactive)),
        crate::Command::Init {
            name,
            host,
            manifest,
            force,
            json,
            non_interactive,
        } => Some(init_cli(
            name,
            host,
            manifest,
            *force,
            *json,
            *non_interactive,
        )),
        crate::Command::Verify {
            manifest,
            migrations,
            json,
            ..
        } => Some(verify_cli(manifest, migrations, *json)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_plan, plan_digest, resolved_env};
    use crate::lock::Lock;
    use cratefield_core::VentureEnv;
    use cratefield_manifest::{ModuleRef, VentureManifest, builtin};
    use std::collections::BTreeMap;

    fn manifest(modules: &[&str], config: &[(&str, &str)]) -> VentureManifest {
        VentureManifest {
            name: "acme".to_owned(),
            host: "acme.factory0.dev".to_owned(),
            public_url: None,
            cors_origins: Vec::new(),
            modules: modules
                .iter()
                .map(|slug| ModuleRef::Slug((*slug).to_owned()))
                .collect(),
            config: config
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
            seed_sql: None,
        }
    }

    #[test]
    fn env_reads_the_manifest_config_key() {
        assert_eq!(resolved_env(&manifest(&[], &[])), VentureEnv::Development);
        assert_eq!(
            resolved_env(&manifest(&[], &[("ENV", "production")])),
            VentureEnv::Production
        );
        assert_eq!(
            resolved_env(&manifest(&[], &[("ENV", "nonsense")])),
            VentureEnv::Development,
            "unrecognised values fall back to development"
        );
    }

    /// The digest is a pure function of the normalised content: the
    /// same inputs twice give the same digest, and any input change —
    /// here one config key — gives a different one.
    #[test]
    fn digest_is_stable_and_input_sensitive() {
        let catalog = builtin();
        let first = manifest(&["waitlist"], &[]);
        let set = first.resolve(&catalog).expect("resolves");
        let (content, _) = compute_plan(&first, &set, &Lock::default(), None, &catalog);
        let (again, _) = compute_plan(&first, &set, &Lock::default(), None, &catalog);
        let digest = plan_digest(&content).expect("digests");
        assert_eq!(digest, plan_digest(&again).expect("digests"));

        let changed = manifest(&["waitlist"], &[("ENV", "production")]);
        let changed_set = changed.resolve(&catalog).expect("resolves");
        let (changed_content, _) =
            compute_plan(&changed, &changed_set, &Lock::default(), None, &catalog);
        assert_ne!(
            digest,
            plan_digest(&changed_content).expect("digests"),
            "a config change must move the digest"
        );
        assert_eq!(changed_content.state.env, "production");
    }

    /// Manifest module order cannot move the digest: the content is
    /// normalised before it is hashed.
    #[test]
    fn digest_is_order_insensitive_over_the_selection() {
        let catalog = builtin();
        let a = manifest(&["waitlist", "email-signup"], &[]);
        let b = manifest(&["email-signup", "waitlist"], &[]);
        let set_a = a.resolve(&catalog).expect("resolves");
        let set_b = b.resolve(&catalog).expect("resolves");
        let (content_a, _) = compute_plan(&a, &set_a, &Lock::default(), None, &catalog);
        let (content_b, _) = compute_plan(&b, &set_b, &Lock::default(), None, &catalog);
        assert_eq!(
            plan_digest(&content_a).expect("digests"),
            plan_digest(&content_b).expect("digests")
        );
    }
}
