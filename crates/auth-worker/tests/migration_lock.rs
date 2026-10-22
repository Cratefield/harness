//! Every migration a module of this Worker ships has a lock entry, and the
//! file the entry names exists and matches the entry's hash. `fz migrations
//! collect` numbers a file from this lock, so an entry that is missing is how
//! an applied migration gets renumbered (the auth-passkeys/0003 gap this test
//! was written for).

use std::path::PathBuf;

use auth_core::AuthCore;
use auth_magic_link::MagicLink;
use auth_meta::Meta;
use auth_oidc::Oidc;
use auth_passkeys::Passkeys;
use auth_password::Password;
use cratefield_core::Module;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

#[test]
fn every_module_migration_has_a_lock_entry_naming_its_file() {
    let dir = migrations_dir();
    let lock: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join(".harness-lock.json")).expect("lock file reads"),
    )
    .expect("lock is JSON");
    let lock = lock.as_object().expect("lock is an object");

    let modules: Vec<Box<dyn Module>> = vec![
        Box::new(AuthCore::new()),
        Box::new(Oidc::new()),
        Box::new(Passkeys::new()),
        Box::new(MagicLink::new()),
        Box::new(Password::new()),
        Box::new(Meta::new()),
    ];
    let mut checked = 0;
    for module in &modules {
        for migration in module.migrations().sqlite {
            let key = format!("{}/{}", module.name(), migration.id);
            let entry = lock
                .get(&key)
                .unwrap_or_else(|| panic!("{key} has no lock entry: collect would renumber it"));
            let file = entry["file"].as_str().expect("entry names a file");
            let bytes = std::fs::read(dir.join(file))
                .unwrap_or_else(|_| panic!("{key} names {file}, which is missing"));
            let digest = Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .concat();
            assert_eq!(
                entry["sha256"], digest,
                "{key}: lock hash does not match {file}"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 20,
        "the lock test is checking {checked} migrations"
    );
}
