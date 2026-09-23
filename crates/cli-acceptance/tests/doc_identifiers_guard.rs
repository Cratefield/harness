//! `tools/doc-identifiers.sh` reads the document being written (issue #445).
//!
//! The script listed documents with tracked-only `git ls-files`, so a new
//! doc citing a name nothing defines was green locally — it was untracked,
//! so it was never read — and red only once committed. These run the real
//! script against a throwaway git repository, as `card_data_guard.rs` does
//! for the migration guard, with the untracked doc left untracked.

mod common;

use common::repo_root;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

/// A command in `dir` that cannot reach the enclosing repository. A git
/// hook or a worktree harness exports these, and an inherited `GIT_DIR`
/// would point every fixture command at the real repository instead.
fn in_fixture(program: &Path, dir: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .current_dir(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE");
    command
}

fn git(dir: &Path, args: &[&str]) {
    let status = in_fixture(Path::new("git"), dir)
        .args(args)
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} failed");
}

/// A scratch directory, removed on drop, hand-rolled as elsewhere here.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A repository holding a copy of the script (it `cd`s to its own parent's
/// parent) and one committed source file and doc that agree.
struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn new() -> Self {
        // A counter as well as the clock, for the reason `card_data_guard.rs`
        // gives: the clock is not nanosecond-resolution on macOS, and
        // parallel tests can land in the same tick and share a directory.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = TempDir(std::env::temp_dir().join(format!(
            "fz-doc-identifiers-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let fixture = Self { dir };
        let path = fixture.dir.0.as_path();
        std::fs::create_dir_all(path.join("tools")).expect("mkdir");
        std::fs::copy(
            repo_root().join("tools/doc-identifiers.sh"),
            path.join("tools/doc-identifiers.sh"),
        )
        .expect("copy script");
        git(path, &["init", "--quiet", "--initial-branch=main"]);
        git(path, &["config", "user.email", "test@example.invalid"]);
        git(path, &["config", "user.name", "guard test"]);
        fixture.write("crates/demo/src/lib.rs", "pub fn alpha_beta_gamma() {}\n");
        fixture.write("docs/GUIDE.md", "Call `alpha_beta_gamma`.\n");
        git(path, &["add", "."]);
        git(path, &["commit", "--quiet", "-m", "base"]);
        fixture
    }

    fn write(&self, rel: &str, body: &str) {
        let file = self.dir.0.join(rel);
        std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
        std::fs::write(file, body).expect("write");
    }

    /// Runs the copied script. Returns (success, stderr).
    fn run(&self) -> (bool, String) {
        let path = self.dir.0.as_path();
        let Output { status, stderr, .. } =
            in_fixture(&path.join("tools/doc-identifiers.sh"), path)
                .output()
                .expect("script runs");
        (
            status.success(),
            String::from_utf8_lossy(&stderr).into_owned(),
        )
    }
}

#[test]
fn a_committed_doc_citing_a_defined_name_passes() {
    let (ok, stderr) = Fixture::new().run();
    assert!(ok, "every cited name is defined: {stderr}");
}

#[test]
fn an_untracked_doc_citing_an_undefined_name_fails() {
    // The #445 regression: tracked-only enumeration never read this file.
    let fixture = Fixture::new();
    fixture.write("docs/NEW.md", "See `zzz_never_defined_name`.\n");
    let (ok, stderr) = fixture.run();
    assert!(!ok, "an untracked doc is checked like a committed one");
    assert!(stderr.contains("docs/NEW.md"), "names the doc: {stderr}");
    assert!(
        stderr.contains("zzz_never_defined_name"),
        "names the name: {stderr}"
    );
}

#[test]
fn a_name_defined_only_in_an_untracked_source_counts() {
    // Otherwise a new doc and the new code it describes are red together
    // until the code is added, and green the moment it is.
    let fixture = Fixture::new();
    fixture.write("crates/demo/src/fresh.rs", "pub fn fresh_new_thing() {}\n");
    // The undefined name proves the doc was read at all.
    fixture.write(
        "docs/FRESH.md",
        "Call `fresh_new_thing`, not `zzz_never_defined_name`.\n",
    );
    let (ok, stderr) = fixture.run();
    assert!(!ok, "the undefined name still fails: {stderr}");
    assert!(stderr.contains("zzz_never_defined_name"), "{stderr}");
    assert!(
        !stderr.contains("fresh_new_thing"),
        "an untracked definition is a definition: {stderr}"
    );
}

#[test]
fn an_ignored_doc_is_not_read() {
    let fixture = Fixture::new();
    fixture.write(".gitignore", "docs/scratch/\n");
    fixture.write("docs/scratch/NOTES.md", "`zzz_never_defined_name`\n");
    // An unignored sibling proves untracked docs are read at all.
    fixture.write("docs/NEW.md", "`zzz_never_defined_name`\n");
    let (ok, stderr) = fixture.run();
    assert!(!ok, "the unignored doc still fails: {stderr}");
    assert!(stderr.contains("docs/NEW.md"), "{stderr}");
    assert!(
        !stderr.contains("docs/scratch"),
        "ignored files are not documents: {stderr}"
    );
}
