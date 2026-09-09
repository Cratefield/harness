//! What the CLI can know about sidecar-mounted modules (issue #66).
//!
//! `fz` is linked into the venture, so it sees exactly the modules that
//! were compiled in. A sidecar is a separate deployment: its tables, its
//! migrations and its SQL live in someone else's repository, and no tool
//! here can read them. The mount table is the one thing the venture does
//! know, so every command that walks `harness.modules()` and would
//! otherwise quietly under-report says what it cannot see.
//!
//! The table comes from `--sidecars '<json>'` or, unset, from the
//! `HARNESS_SIDECARS` environment variable — the same table the runtime
//! reads from config. It is passed down from `run` rather than read
//! here, so nothing below the command line depends on process state.

use cratefield_core::{
    HARNESS_ONE_WORKER, HARNESS_SIDECARS, Harness, MapConfig, SidecarMount, SidecarMounts,
};

/// The mount table the command line gave, else the environment's.
#[must_use]
pub fn from_cli_or_env(flag: Option<&str>) -> Option<String> {
    flag.map(str::to_owned)
        .or_else(|| std::env::var(HARNESS_SIDECARS).ok())
        .filter(|table| !table.trim().is_empty())
}

/// Parses the table. `None` is `Ok(empty)`: most ventures mount no
/// sidecars.
///
/// The [`HARNESS_ONE_WORKER`] flag is read from the environment here, not
/// passed down, so every command sees exactly the table the runtime would
/// build — including the rejection of a sidecar in a one-Worker
/// deployment (issue #131).
///
/// # Errors
///
/// Every malformed entry, as `SidecarMounts::from_config` reports them.
pub fn parse(table: Option<&str>) -> Result<SidecarMounts, Vec<String>> {
    let Some(table) = table else {
        return Ok(SidecarMounts::default());
    };
    let mut pairs = vec![(HARNESS_SIDECARS.to_string(), table.to_string())];
    if let Some(flag) = std::env::var(HARNESS_ONE_WORKER)
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        pairs.push((HARNESS_ONE_WORKER.to_string(), flag));
    }
    SidecarMounts::from_config(&MapConfig::from_pairs(pairs))
}

/// Mounts that name a module compiled into this harness. The runtime
/// ignores these and keeps the compiled-in module, logging as it goes,
/// so nothing breaks — but the table is wrong and someone believes a
/// sidecar is serving that prefix.
#[must_use]
pub fn shadowing<'a>(harness: &Harness, mounts: &'a SidecarMounts) -> Vec<&'a SidecarMount> {
    let names: Vec<&str> = harness.modules().iter().map(|m| m.name()).collect();
    mounts
        .iter()
        .filter(|mount| names.contains(&mount.name.as_str()))
        .collect()
}

/// One line per sidecar, for a message that has to name what is missing.
#[must_use]
pub fn listed(mounts: &SidecarMounts) -> String {
    mounts
        .iter()
        .map(|mount| format!("`{}` (binding `{}`)", mount.name, mount.binding))
        .collect::<Vec<_>>()
        .join(", ")
}
