//! The card-data non-goal, enforced rather than asserted (issue #44).
//!
//! `docs/CARD-DATA.md` says card details never enter a Cratefield
//! database, and `tools/migration-guard.sh` greps every migration for the
//! column names that would mean they had. Nothing checked that the grep
//! fires, which is the same gap #39 had: a guard nobody tests is a guard
//! nobody knows is wired.
//!
//! These run the real script against a throwaway git repository, because
//! the guard reads `git ls-files` and an untracked file is invisible to
//! it — a test that forgot to commit would pass while proving nothing.

mod common;

use common::repo_root;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(dir)
        .args(args)
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} failed");
}

/// A scratch directory, removed on drop. The repo hand-rolls this rather
/// than depending on `tempfile`; matched here.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        // A counter as well as the clock: `as_nanos` is not
        // nanosecond-*resolution* on macOS, and these fixtures are built
        // in a tight loop across parallel tests, so two can land in the
        // same tick and share a directory. That reads as a mystifying
        // `git` failure only in the full workspace run.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fz-card-guard-{}-{}",
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

/// A git repository holding one migration with the given body, committed
/// on a branch off an empty base — the shape the guard expects.
struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn with_migration(name: &str, body: &str) -> Self {
        let dir = TempDir::new();
        let path = dir.path();
        git(path, &["init", "--quiet", "--initial-branch=main"]);
        git(path, &["config", "user.email", "test@example.invalid"]);
        git(path, &["config", "user.name", "guard test"]);

        // An empty base commit, so the guard has a merge base to diff.
        std::fs::write(path.join("README.md"), "fixture\n").expect("write");
        git(path, &["add", "."]);
        git(path, &["commit", "--quiet", "-m", "base"]);
        git(path, &["branch", "base"]);

        let migrations = path.join("crates/module-demo/migrations/sqlite");
        std::fs::create_dir_all(&migrations).expect("mkdir");
        std::fs::write(migrations.join(name), body).expect("write migration");
        git(path, &["add", "."]);
        git(path, &["commit", "--quiet", "-m", "add migration"]);

        Self { dir }
    }

    /// Runs the real guard against `base`. Returns (success, stderr).
    fn run_guard(&self) -> (bool, String) {
        let script = repo_root().join("tools/migration-guard.sh");
        let out = Command::new(&script)
            .current_dir(self.dir.path())
            .arg("base")
            .output()
            .expect("guard runs");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

#[test]
fn a_migration_adding_card_number_fails_the_guard() {
    let fixture = Fixture::with_migration(
        "0001_init.sql",
        "CREATE TABLE payments (\n  id TEXT PRIMARY KEY,\n  card_number TEXT NOT NULL\n);\n",
    );
    let (ok, stderr) = fixture.run_guard();
    assert!(!ok, "a migration storing a card number must not pass");
    assert!(
        stderr.contains("card data"),
        "the refusal names the rule: {stderr}"
    );
    assert!(
        stderr.contains("0001_init.sql"),
        "the refusal names the file: {stderr}"
    );
}

#[test]
fn every_card_data_column_name_is_refused() {
    // The whole pattern, so widening it later cannot silently narrow it.
    for column in [
        "pan",
        "cardholder",
        "card_number",
        "cardnumber",
        "cvv",
        "cvc",
        "card_cvv",
        "expiry_month",
        "expiry_year",
        "track2",
    ] {
        let fixture = Fixture::with_migration(
            "0001_init.sql",
            &format!("CREATE TABLE t (\n  {column} TEXT\n);\n"),
        );
        let (ok, stderr) = fixture.run_guard();
        assert!(!ok, "`{column}` must be refused");
        assert!(stderr.contains("card data"), "`{column}`: {stderr}");
    }
}

#[test]
fn the_stripe_identifiers_we_do_store_are_not_refused() {
    // `docs/CARD-DATA.md` lists these as ordinary data. A guard that
    // refused them would be one someone turns off.
    let fixture = Fixture::with_migration(
        "0001_init.sql",
        "CREATE TABLE customers (\n  \
           stripe_customer_id TEXT,\n  \
           stripe_payment_method_id TEXT,\n  \
           stripe_subscription_id TEXT,\n  \
           card_brand TEXT,\n  \
           card_last4 TEXT\n\
         );\n",
    );
    let (ok, stderr) = fixture.run_guard();
    assert!(
        ok,
        "the identifiers Stripe hands back are ordinary: {stderr}"
    );
}

#[test]
fn a_connection_string_with_credentials_fails_the_guard() {
    let fixture = Fixture::with_migration(
        "0001_init.sql",
        "-- seed\nINSERT INTO cfg VALUES ('dsn', 'postgres://app:hunter2@db.internal:5432/app');\n",
    );
    let (ok, stderr) = fixture.run_guard();
    assert!(!ok, "a DSN with credentials must not be committed");
    assert!(
        stderr.contains("connection string"),
        "the refusal names the rule: {stderr}"
    );
}
