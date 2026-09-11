//! The agent-safe workflow commands (harness #140): `fz plan`, `fz
//! deploy --plan`, `fz add`, `fz init`, `fz verify`. Proves what an
//! agent needs: a plan's digest is stable across runs and moves when
//! any input moves; a stale digest and a deploy without a plan are
//! refused with their own codes; production needs the second consent
//! flag; `fz add` is idempotent and never deploys; and `fz verify`
//! names the drift with the doctor's coded-failure shape.
//!
//! No test here runs a real deploy or touches a real database: the
//! workflow's whole write surface is the manifest and the
//! `.harness-deploy.json` record beside it.

use cratefield_cli::doctor::DoctorFailure;
use cratefield_cli::run;
use cratefield_cli::workflow;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use venture_fixture::harness_v1;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fz-workflow-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn manifest(&self) -> PathBuf {
        self.0.join("venture.json")
    }

    fn migrations(&self) -> PathBuf {
        self.0.join("migrations")
    }

    fn record(&self) -> PathBuf {
        self.0.join(".harness-deploy.json")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(ToString::to_string).collect()
}

fn write_manifest(path: &Path, modules: &[&str], config: &[(&str, &str)]) {
    let module_list = modules
        .iter()
        .map(|slug| format!("\"{slug}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config_list = config
        .iter()
        .map(|(key, value)| format!("\"{key}\": \"{value}\""))
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(
        path,
        format!(
            "{{\n  \"name\": \"acme\",\n  \"host\": \"acme.factory0.dev\",\n  \
             \"modules\": [{module_list}],\n  \"config\": {{{config_list}}}\n}}\n"
        ),
    )
    .expect("write manifest");
}

fn code_of(failures: &[DoctorFailure]) -> &'static str {
    let only = failures.first().expect("exactly the failures we look at");
    only.code.code
}

/// A plan's digest is stable across runs and is a 64-hex sha256; the
/// JSON carries `schema` 1, `ok`, and no changes when nothing changed.
#[test]
fn plan_digest_is_stable_across_runs() {
    let tmp = TempDir::new("stable");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);

    let first = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");
    let again = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");
    assert_eq!(first.digest, again.digest, "same inputs, same digest");
    assert_eq!(first.digest.len(), 64, "sha256 hex");
    assert!(first.digest.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(first.content.state.modules.contains(&"waitlist".to_owned()));
    assert_eq!(first.content.state.env, "development");
}

/// Any input change — a config key here — moves the digest, and the
/// plan reports the delta against the recorded deployment.
#[test]
fn plan_digest_changes_when_an_input_changes() {
    let tmp = TempDir::new("moves");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);
    let before = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");

    write_manifest(&tmp.manifest(), &["waitlist"], &[("ENV", "production")]);
    let after = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");
    assert_ne!(
        before.digest, after.digest,
        "a config change moves the digest"
    );
    assert_eq!(after.content.state.env, "production");
    assert_eq!(after.content.config_changed, Vec::<String>::new());
    assert_eq!(after.content.config_added, vec!["ENV".to_owned()]);

    // And `fz add` moves it too, the way an agent would grow the
    // composition.
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);
    let middle = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");
    assert_eq!(middle.digest, before.digest, "back to the same inputs");
    let exit = run(
        harness_v1,
        args(&["add", "cms", "--manifest", tmp.manifest().to_str().unwrap()]),
    );
    assert_eq!(exit, ExitCode::SUCCESS);
    let grown = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");
    assert_ne!(middle.digest, grown.digest);
    // With nothing deployed yet the baseline is empty, so the whole
    // composition reads as added.
    assert_eq!(
        grown.content.modules_added,
        vec!["cms".to_owned(), "waitlist".to_owned()]
    );
}

/// `fz plan` is read-only: the manifest and everything beside it are
/// byte-identical afterwards.
#[test]
fn plan_changes_nothing_on_disk() {
    let tmp = TempDir::new("readonly");
    write_manifest(&tmp.manifest(), &["waitlist", "email-signup"], &[]);
    let before = fs::read(tmp.manifest()).expect("read");

    let exit = run(
        harness_v1,
        args(&[
            "plan",
            "--manifest",
            tmp.manifest().to_str().unwrap(),
            "--json",
        ]),
    );
    assert_eq!(exit, ExitCode::SUCCESS);
    assert_eq!(fs::read(tmp.manifest()).expect("read"), before);
    assert!(!tmp.record().exists(), "plan never writes a deploy record");
    assert!(
        !tmp.migrations().join(".harness-lock.json").exists(),
        "plan never writes a lockfile"
    );
}

/// Deploying without `--plan` at all is refused: approval is the point.
#[test]
fn deploy_without_a_plan_is_refused() {
    let tmp = TempDir::new("no-plan");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);

    let err = workflow::deploy(
        None,
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent::default(),
    )
    .expect_err("refused");
    assert_eq!(code_of(&err), "deploy-plan-required");
    assert!(!tmp.record().exists(), "a refused deploy records nothing");

    let exit = run(
        harness_v1,
        args(&[
            "deploy",
            "--manifest",
            tmp.manifest().to_str().unwrap(),
            "--json",
        ]),
    );
    assert_eq!(exit, ExitCode::FAILURE);
}

/// A digest computed before an input change is stale: refused with its
/// own code, and the message names what moved.
#[test]
fn a_stale_digest_is_refused_and_names_what_moved() {
    let tmp = TempDir::new("stale");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);
    let stale = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");

    let exit = run(
        harness_v1,
        args(&["add", "cms", "--manifest", tmp.manifest().to_str().unwrap()]),
    );
    assert_eq!(exit, ExitCode::SUCCESS);

    let err = workflow::deploy(
        Some(&stale.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent::default(),
    )
    .expect_err("refused");
    assert_eq!(code_of(&err), "stale-plan");
    assert!(
        err[0].message.contains("cms"),
        "the refusal names what moved: {}",
        err[0].message
    );
    assert!(!tmp.record().exists());

    let exit = run(
        harness_v1,
        args(&[
            "deploy",
            "--plan",
            &stale.digest,
            "--manifest",
            tmp.manifest().to_str().unwrap(),
            "--json",
        ]),
    );
    assert_eq!(exit, ExitCode::FAILURE);
}

/// The happy path: deploy with the current digest records the plan,
/// the second identical deploy changes nothing, and `fz verify` agrees.
#[test]
fn deploy_records_the_approved_plan_and_is_idempotent() {
    let tmp = TempDir::new("deploy");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);
    let plan = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");

    let first = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent::default(),
    )
    .expect("applied");
    assert!(first.changed);
    assert!(
        tmp.record().exists(),
        "the record is the applied deployment"
    );

    let second = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent::default(),
    )
    .expect("idempotent");
    assert!(!second.changed, "the second run says it changed nothing");

    let verify = workflow::verify(&tmp.manifest(), &tmp.migrations());
    assert!(
        verify.report.ok(),
        "a fresh deployment verifies clean: {:?}",
        verify.report.failures
    );

    let exit = run(
        harness_v1,
        args(&[
            "verify",
            "--manifest",
            tmp.manifest().to_str().unwrap(),
            "--json",
        ]),
    );
    assert_eq!(exit, ExitCode::SUCCESS);
}

/// A production venture needs the second, explicit consent — the flag
/// is not a rename of plan approval, and absent it the deploy refuses
/// with its own code even when the digest matches.
#[test]
fn production_needs_the_second_consent_flag() {
    let tmp = TempDir::new("production");
    write_manifest(&tmp.manifest(), &["waitlist"], &[("ENV", "production")]);
    let plan = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");

    let err = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent::default(),
    )
    .expect_err("refused");
    assert_eq!(code_of(&err), "production-deploy-unauthorized");
    assert!(!tmp.record().exists());

    let exit = run(
        harness_v1,
        args(&[
            "deploy",
            "--plan",
            &plan.digest,
            "--manifest",
            tmp.manifest().to_str().unwrap(),
            "--json",
        ]),
    );
    assert_eq!(exit, ExitCode::FAILURE);

    let consented = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent {
            production: true,
            removal: true,
        },
    )
    .expect("applied with the flag");
    assert!(consented.changed);
}

/// Removing a module takes its data out of the served venture, so the
/// plan is destructive and demands the same second consent.
#[test]
fn a_destructive_plan_needs_the_second_consent_flag() {
    let tmp = TempDir::new("destructive");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);
    write_locked_ghost(&tmp.migrations());

    let plan = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");
    assert_eq!(plan.content.modules_removed, vec!["ghost".to_owned()]);

    let err = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent::default(),
    )
    .expect_err("refused");
    assert_eq!(code_of(&err), "destructive-change-unauthorized");

    let consented = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent {
            production: true,
            removal: true,
        },
    )
    .expect("applied with the flag");
    assert!(consented.changed);
}

/// `fz add` mutates the manifest and nothing else; the second add of
/// the same module is a no-op that succeeds; an unknown slug is a
/// coded refusal.
#[test]
fn add_is_idempotent_and_never_deploys() {
    let tmp = TempDir::new("add");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);

    let first = workflow::add("cms", &tmp.manifest()).expect("added");
    assert!(first.changed);
    assert!(!tmp.record().exists(), "add never deploys");
    assert!(
        !tmp.migrations().join(".harness-lock.json").exists(),
        "add never touches migrations"
    );

    let grown = fs::read_to_string(tmp.manifest()).expect("read");
    assert!(grown.contains("cms"), "the manifest lists the module");

    let second = workflow::add("cms", &tmp.manifest()).expect("no-op");
    assert!(!second.changed, "the second run says it changed nothing");
    assert_eq!(
        fs::read_to_string(tmp.manifest()).expect("read"),
        grown,
        "the no-op rewrote nothing"
    );

    let exit = run(
        harness_v1,
        args(&["add", "cms", "--manifest", tmp.manifest().to_str().unwrap()]),
    );
    assert_eq!(exit, ExitCode::SUCCESS, "the no-op still succeeds");

    let err = workflow::add("not-a-module", &tmp.manifest()).expect_err("refused");
    assert_eq!(code_of(&err), "module-unknown");
}

/// `fz init` writes a fresh manifest, refuses to overwrite without
/// `--force`, and refuses an empty name.
#[test]
fn init_writes_a_manifest_and_refuses_to_overwrite() {
    let tmp = TempDir::new("init");
    let path = tmp.manifest();

    let exit = run(
        harness_v1,
        args(&[
            "init",
            "--name",
            "acme",
            "--host",
            "acme.factory0.dev",
            "--manifest",
            path.to_str().unwrap(),
            "--json",
        ]),
    );
    assert_eq!(exit, ExitCode::SUCCESS);
    let written = fs::read_to_string(&path).expect("read");
    let parsed: serde_json::Value = serde_json::from_str(&written).expect("valid JSON");
    assert_eq!(parsed["name"], "acme");
    assert_eq!(parsed["host"], "acme.factory0.dev");
    assert_eq!(parsed["modules"], serde_json::json!([]));

    let err = workflow::init("acme-2", "other.factory0.dev", &path, false).expect_err("refused");
    assert_eq!(code_of(&err), "manifest-exists");

    let exit = run(
        harness_v1,
        args(&[
            "init",
            "--name",
            "acme-2",
            "--host",
            "other.factory0.dev",
            "--manifest",
            path.to_str().unwrap(),
        ]),
    );
    assert_eq!(exit, ExitCode::FAILURE);

    workflow::init("acme-2", "other.factory0.dev", &path, true).expect("forced");
    let replaced = fs::read_to_string(&path).expect("read");
    assert!(replaced.contains("acme-2"), "force overwrites");

    let err = workflow::init("", "acme.factory0.dev", &tmp.0.join("empty.json"), false)
        .expect_err("refused");
    assert_eq!(code_of(&err), "manifest-invalid");
}

/// `fz verify` reports drift as coded failures in the doctor's shape —
/// composition drift after `fz add`, and never-deployed before the
/// first deploy.
#[test]
fn verify_reports_drift_as_coded_failures() {
    let tmp = TempDir::new("verify");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);

    let before = workflow::verify(&tmp.manifest(), &tmp.migrations());
    assert_eq!(before.report.failures[0].code.code, "not-deployed");

    let plan = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");
    workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent::default(),
    )
    .expect("applied");

    let clean = workflow::verify(&tmp.manifest(), &tmp.migrations());
    assert!(clean.report.ok());

    workflow::add("cms", &tmp.manifest()).expect("added");
    let drifted = workflow::verify(&tmp.manifest(), &tmp.migrations());
    assert!(!drifted.report.ok());
    let codes: Vec<&str> = drifted
        .report
        .failures
        .iter()
        .map(|failure| failure.code.code)
        .collect();
    assert!(
        codes.contains(&"composition-drift"),
        "composition drift is named: {codes:?}"
    );

    let exit = run(
        harness_v1,
        args(&[
            "verify",
            "--manifest",
            tmp.manifest().to_str().unwrap(),
            "--json",
        ]),
    );
    assert_eq!(exit, ExitCode::FAILURE, "drift fails the command");

    // And a config change alone is its own code.
    write_manifest(&tmp.manifest(), &["waitlist"], &[("brand", "Acme")]);
    let drifted = workflow::verify(&tmp.manifest(), &tmp.migrations());
    let codes: Vec<&str> = drifted
        .report
        .failures
        .iter()
        .map(|failure| failure.code.code)
        .collect();
    assert!(
        codes.contains(&"config-drift") && !codes.contains(&"composition-drift"),
        "config drift alone is named: {codes:?}"
    );
}

/// A removal in development is not a production deploy, and the two
/// flags must not stand in for one another.
///
/// One flag for both is how a production gate stops meaning anything: an
/// operator who has to pass `--i-am-deploying-to-production` to drop a
/// module from a dev venture learns to pass it everywhere.
#[test]
fn the_production_flag_does_not_authorise_a_removal() {
    let tmp = TempDir::new("consent-split");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);
    write_locked_ghost(&tmp.migrations());
    let plan = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");

    let err = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent {
            production: true,
            removal: false,
        },
    )
    .expect_err("the production flag is not a removal consent");
    assert_eq!(code_of(&err), "destructive-change-unauthorized");

    let applied = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent {
            production: false,
            removal: true,
        },
    )
    .expect("the removal flag alone is enough in development");
    assert!(applied.changed);
}

/// The refusal must not claim data is deleted, because none is.
#[test]
fn a_removal_says_what_it_actually_does_to_the_data() {
    let tmp = TempDir::new("removal-truth");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);
    write_locked_ghost(&tmp.migrations());
    let plan = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");

    let err = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent::default(),
    )
    .expect_err("refused");
    let message = err
        .iter()
        .map(|failure| failure.message.clone())
        .collect::<Vec<_>>()
        .join(" ");

    assert!(
        message.contains("no data is deleted"),
        "an operator who reads that data left reaches for a backup nobody \
         needs: {message}"
    );
    assert!(
        message.contains("ghost/0001"),
        "and it names the migration left applied: {message}"
    );
    assert!(
        !message.contains("data leaves the venture"),
        "the old claim was false — deploy never touches a database: {message}"
    );
}

/// A lockfile whose entry names a file that exists and hashes to what is
/// recorded — which is what a real `fz migrations collect` leaves behind.
///
/// Deploy verifies the lock, so a fixture with a dangling entry tests the
/// integrity check rather than the thing it meant to test.
fn write_locked_ghost(migrations: &std::path::Path) {
    fs::create_dir_all(migrations).expect("migrations dir");
    fs::write(migrations.join("0001_ghost_0001_init.sql"), "-- ghost\n").expect("migration");
    fs::write(
        migrations.join(".harness-lock.json"),
        format!(
            "{{\n  \"ghost/0001\": {{\"file\": \"0001_ghost_0001_init.sql\", \
             \"sha256\": \"5aed107e176cb0b90a7f11a30f68480312f656db2aec1b0ed7768cf676f1704f\"}}\n}}\n"
        ),
    )
    .expect("write lockfile");
}

/// An edited migration must not deploy.
///
/// `fz doctor` already checks this against a compiled harness, but deploy
/// does not require doctor to have been run. Without its own check, an
/// edited migration records a plan claiming a schema the files no longer
/// produce, and the next environment to apply them gets something
/// different from the one already running.
#[test]
fn deploy_refuses_a_migration_that_was_edited_after_it_was_locked() {
    let tmp = TempDir::new("edited-migration");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);
    write_locked_ghost(&tmp.migrations());
    let plan = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");

    // The file changes after the lock recorded it.
    fs::write(
        tmp.migrations().join("0001_ghost_0001_init.sql"),
        "-- ghost, but different\n",
    )
    .expect("edit");

    let err = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent {
            production: false,
            removal: true,
        },
    )
    .expect_err("an edited migration is not deployable");
    assert_eq!(code_of(&err), "locked-migration-edited");
}

/// A locked migration whose file is gone is the same class of problem.
#[test]
fn deploy_refuses_a_locked_migration_whose_file_is_missing() {
    let tmp = TempDir::new("missing-migration");
    write_manifest(&tmp.manifest(), &["waitlist"], &[]);
    write_locked_ghost(&tmp.migrations());
    let plan = workflow::plan(&tmp.manifest(), &tmp.migrations()).expect("plans");

    fs::remove_file(tmp.migrations().join("0001_ghost_0001_init.sql")).expect("remove");

    let err = workflow::deploy(
        Some(&plan.digest),
        &tmp.manifest(),
        &tmp.migrations(),
        workflow::Consent {
            production: false,
            removal: true,
        },
    )
    .expect_err("a dangling lock entry is not deployable");
    assert_eq!(code_of(&err), "locked-migration-missing");
}
