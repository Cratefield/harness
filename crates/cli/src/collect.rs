//! `fz migrations collect` (issue #8): walks modules in config order,
//! writes `migrations/<GGGG>_<module>_<id>_<name>.sql` for wrangler, and
//! pins module migration -> global file in `.harness-lock.json`. Locked
//! entries are never renamed or renumbered; new ones append. Exits
//! non-zero when a locked file is missing or its content hash changed.

use crate::lock::{Lock, read_lock, sha256_hex, write_lock};
use cratefield_core::Harness;
use std::fmt;
use std::path::Path;

/// Collects the harness's module migrations into `out`.
///
/// # Errors
///
/// A human-readable message when the lockfile is unreadable, a locked
/// file is missing/edited, or files cannot be written.
pub fn collect(harness: &Harness, dialect: &str, out: &Path) -> Result<(), String> {
    if dialect != "sqlite" {
        return Err(format!(
            "dialect {dialect:?} is not available for collect (collect writes the \
             wrangler/D1 sqlite flow; postgres migrations apply directly with \
             `fz migrations apply --dialect postgres --url ...`)"
        ));
    }
    std::fs::create_dir_all(out)
        .map_err(|err| format!("cannot create {}: {err}", out.display()))?;
    let mut lock: Lock = read_lock(out)?;

    let mut next = next_global_number(&lock);
    for module in harness.modules() {
        for migration in module.migrations().sqlite {
            let key = format!("{}/{}", module.name(), migration.id);
            if let Some(entry) = lock.get(&key) {
                verify_locked(out, &key, entry).map_err(|err| err.to_string())?;
                continue;
            }
            let file = format!(
                "{next:04}_{}_{}_{}.sql",
                module.name(),
                migration.id,
                migration.name
            );
            let body = migration.sql.trim_end().to_owned() + "\n";
            std::fs::write(out.join(&file), &body)
                .map_err(|err| format!("cannot write {file}: {err}"))?;
            lock.insert(
                key,
                crate::lock::LockEntry {
                    file,
                    sha256: sha256_hex(body.as_bytes()),
                },
            );
            next += 1;
        }
    }

    write_lock(out, &lock)
}

/// Why a locked migration failed verification (harness #140): the doctor
/// needs the distinction to attach its stable error code. The `Display`
/// text is the exact prose `collect` and `doctor` have always printed.
#[derive(Debug)]
pub enum LockedMigrationError {
    /// The pinned file is not on disk.
    Missing { key: String, file: String },
    /// The pinned file's content hash no longer matches the lock entry.
    Edited { key: String, file: String },
}

impl fmt::Display for LockedMigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { key, file } => {
                write!(
                    formatter,
                    "locked migration {key:?} is missing its file {file}"
                )
            }
            Self::Edited { key, file } => write!(
                formatter,
                "locked migration {key:?} was edited after being applied ({file}) \
                 — restore the file or add a new migration instead"
            ),
        }
    }
}

pub fn verify_locked(
    out: &Path,
    key: &str,
    entry: &crate::lock::LockEntry,
) -> Result<(), LockedMigrationError> {
    let path = out.join(&entry.file);
    let body = std::fs::read_to_string(&path).map_err(|_| LockedMigrationError::Missing {
        key: key.to_owned(),
        file: entry.file.clone(),
    })?;
    let actual = sha256_hex(body.as_bytes());
    if actual != entry.sha256 {
        return Err(LockedMigrationError::Edited {
            key: key.to_owned(),
            file: entry.file.clone(),
        });
    }
    Ok(())
}

fn next_global_number(lock: &Lock) -> u64 {
    lock.values()
        .filter_map(|entry| entry.file.split('_').next())
        .filter_map(|prefix| prefix.parse::<u64>().ok())
        .max()
        .map_or(1, |max| max + 1)
}
