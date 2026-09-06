//! The `.harness-lock.json` format: `<module>/<id>` -> `{ file, sha256 }`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEntry {
    pub file: String,
    pub sha256: String,
}

pub type Lock = BTreeMap<String, LockEntry>;

pub const LOCK_FILE: &str = ".harness-lock.json";

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

pub fn read_lock(dir: &Path) -> Result<Lock, String> {
    let path = dir.join(LOCK_FILE);
    if !path.exists() {
        return Ok(Lock::new());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    serde_json::from_str(&raw).map_err(|err| format!("cannot parse {}: {err}", path.display()))
}

pub fn write_lock(dir: &Path, lock: &Lock) -> Result<(), String> {
    let path = dir.join(LOCK_FILE);
    let body = serde_json::to_string_pretty(lock)
        .map_err(|err| format!("cannot serialize lockfile: {err}"))?;
    std::fs::create_dir_all(dir)
        .map_err(|err| format!("cannot create {}: {err}", dir.display()))?;
    std::fs::write(&path, body + "\n")
        .map_err(|err| format!("cannot write {}: {err}", path.display()))
}
