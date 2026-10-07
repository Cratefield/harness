//! The never-edit guard's *own* ability to run, as opposed to what it
//! checks: a base ref git cannot resolve a merge base for.
//!
//! `tools/migration-guard.sh` diffs against
//! `$(git merge-base "$BASE" HEAD)`. That substitution sits inside a
//! process substitution, and a process substitution's exit status is
//! discarded by the `while read` it feeds — so when `git merge-base`
//! failed, its empty output made the diff argument `...HEAD`, the diff
//! found nothing, and the script printed "no problems" and exited 0.
//! The `set -euo pipefail` at the top cannot see it: nothing in the
//! foreground command line failed.
//!
//! The result was a green check named "migrations are never edited"
//! that had checked nothing at all. The workflow calls the guard with
//! `origin/${{ ... base.ref }}`, so a renamed or removed base branch —
//! or a clone whose history does not reach the merge base — turned the
//! guard off without anyone being told.
//!
//! These run the real script against a throwaway git repository, the
//! same shape as `card_data_guard.rs`, because the guard reads
//! `git ls-files` and an uncommitted file is invisible to it.

mod common;

use common::repo_root;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn clear_git_env(cmd: &mut Command) {
    // A `GIT_DIR` / `GIT_WORK_TREE` / `GIT_INDEX_FILE` (or any other `GIT_*`
    // knob) inherited from the caller would redirect the fixture's `git`
    // invocations into the caller's repository instead of the throwaway
    // fixture (issues #474, #479).
    for (key, _) in std::env::vars() {
        if key.starts_with("GIT_") {
            cmd.env_remove(key);
        }
    }
}

fn git(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    clear_git_env(&mut cmd);
    let status = cmd.current_dir(dir).args(args).status().expect("git runs");
    assert!(status.success(), "git {args:?} failed");
}

/// A scratch directory, removed on drop. Hand-rolled rather than pulling
/// in `tempfile`, matched to `card_data_guard.rs`.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fz-migration-guard-base-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A repository whose HEAD **edits** a migration that was already
/// committed on `base` — the one thing rule 1 exists to catch, so a
/// guard that passes this fixture has checked nothing at all.
struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn edited_migration() -> Self {
        let dir = TempDir::new();
        let path = dir.path();
        git(path, &["init", "--quiet", "--initial-branch=main"]);
        git(path, &["config", "user.email", "test@example.invalid"]);
        git(path, &["config", "user.name", "guard test"]);

        let migrations = path.join("crates/module-demo/migrations/sqlite");
        std::fs::create_dir_all(&migrations).expect("mkdir");
        let migration = migrations.join("0001_init.sql");
        std::fs::write(&migration, "CREATE TABLE a (id TEXT);\n").expect("write");
        git(path, &["add", "."]);
        git(path, &["commit", "--quiet", "-m", "add migration"]);
        git(path, &["branch", "base"]);

        std::fs::write(&migration, "CREATE TABLE a (id TEXT, name TEXT);\n").expect("edit");
        git(path, &["add", "."]);
        git(
            path,
            &["commit", "--quiet", "-m", "edit an applied migration"],
        );

        Self { dir }
    }

    /// Runs the real guard against `base_ref`.
    fn run_guard(&self, base_ref: &str) -> (bool, String) {
        let script = repo_root().join("tools/migration-guard.sh");
        // Through `bash` rather than through the executable bit: a checkout
        // materialised by cp, an archive or a download does not carry mode
        // 755 the way a `git checkout` does, and the loss would fail every
        // test in this file at once with `PermissionDenied`.
        let mut cmd = Command::new("bash");
        clear_git_env(&mut cmd);
        let out = cmd
            .arg(&script)
            .current_dir(self.dir.path())
            .arg(base_ref)
            .output()
            .expect("guard runs");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

/// The control: with a base ref git can resolve, the guard catches the
/// edit. Everything below is this same fixture, this same commit, with
/// only the base ref changed — so a failure to fail cannot be blamed on
/// the fixture not containing what it should.
#[test]
fn a_resolvable_base_ref_catches_the_edit() {
    let fixture = Fixture::edited_migration();
    let (ok, stderr) = fixture.run_guard("base");
    assert!(!ok, "an edited applied migration must not pass the guard");
    assert!(
        stderr.contains("0001_init.sql"),
        "the refusal names the file: {stderr}"
    );
}

/// The defect: a base ref with no merge base — a renamed or removed base
/// branch, a typo in the workflow's `BASE`, a clone whose history does
/// not reach it. The guard used to print "no problems" and exit 0,
/// reporting success for a diff it never ran. It must refuse loudly
/// instead, and say which ref it could not resolve, so the check fails
/// rather than passing vacuously.
#[test]
fn an_unresolvable_base_ref_fails_the_guard_rather_than_passing_it() {
    for base_ref in ["no-such-branch", "origin/gone", "not-a-ref-at-all"] {
        let fixture = Fixture::edited_migration();
        let (ok, stderr) = fixture.run_guard(base_ref);
        assert!(
            !ok,
            "`{base_ref}` has no merge base, so the guard checked nothing; \
             it must not report success"
        );
        assert!(
            stderr.contains(base_ref),
            "the refusal names the base ref it could not resolve: {stderr}"
        );
        assert!(
            !stderr.contains("no problems"),
            "a run that diffed nothing must not claim it found none: {stderr}"
        );
    }
}
