//! No tracing dispatcher reaches a Worker isolate (issues #132, #144).
//!
//! Installing any `tracing` dispatcher — `set_global_default` or
//! `set_default` — hangs the single-threaded workerd/miniflare isolate.
//! That was found empirically on wrangler 4.129 and is written down in
//! `runtime-cloudflare`'s module docs, but nothing enforced it: a change
//! that installed one under `wasm32` would compile, pass `cargo test`,
//! pass `worker-build`, and hang every request.
//!
//! This is the same shape as `push_env_guard.rs` and `card_data_guard.rs`:
//! the rule is a test, and the test proves the detector fires.
//!
//! It is a source scan rather than a type check because the thing being
//! forbidden is *reachable code*, not a signature — and because the
//! failure it prevents cannot be observed from a build at all.

mod common;

use std::path::{Path, PathBuf};

use common::repo_root;

/// What installs a dispatcher. `set_default` returns a guard, so it is as
/// fatal as `set_global_default` the moment the guard is leaked — which
/// the native path does deliberately.
const INSTALLERS: [&str; 2] = ["set_global_default", "set_default"];

/// Crates whose code can end up in a Worker. `runtime-native` cannot, and
/// the CLI is a host binary.
const WASM_REACHABLE: [&str; 3] = ["crates/runtime-cloudflare/", "crates/core/", "crates/ui/"];

/// Whether a line installing a dispatcher is inside a native-only region.
///
/// Deliberately crude: it looks for the `cfg` that gates the native half,
/// anywhere above the call in the same file. A file that gates its native
/// code some other way will trip this and have to say so — a guard that
/// tries to parse Rust to be clever is a guard that is wrong quietly.
fn native_only_above(source: &str, offset: usize) -> bool {
    source[..offset].contains(r#"#[cfg(not(target_arch = "wasm32"))]"#)
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if matches!(name.as_ref(), "target" | ".git" | "node_modules") {
                continue;
            }
            rust_sources(&path, out);
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every dispatcher install in a wasm-reachable source that is not gated
/// to the native target.
fn offenders_in(relative: &str, source: &str) -> Vec<String> {
    if !WASM_REACHABLE.iter().any(|dir| relative.starts_with(dir)) {
        return Vec::new();
    }
    let mut found = Vec::new();
    for installer in INSTALLERS {
        let needle = format!("{installer}(");
        let mut from = 0;
        while let Some(at) = source[from..].find(&needle) {
            let offset = from + at;
            if !native_only_above(source, offset) {
                found.push(format!("{relative} installs a dispatcher ({installer})"));
            }
            from = offset + needle.len();
        }
    }
    found
}

#[test]
fn no_wasm_reachable_crate_installs_a_tracing_dispatcher() {
    let root = repo_root();
    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);
    assert!(
        sources.len() > 100,
        "the walk found only {} Rust sources, so it is not walking the workspace",
        sources.len()
    );

    let mut violations = Vec::new();
    for path in sources {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        violations.extend(offenders_in(&relative, &source));
    }

    assert!(
        violations.is_empty(),
        "installing a tracing dispatcher hangs the workerd isolate — the Workers path \
         forwards to `console_error!` instead (see `runtime-cloudflare::tracing_setup`). \
         Gate it behind `#[cfg(not(target_arch = \"wasm32\"))]` if it is native-only:\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn the_guard_fires_on_an_ungated_install() {
    // A guard nobody tests is a guard nobody knows is wired.
    let source = "fn boot() { tracing::subscriber::set_global_default(s); }\n";
    assert_eq!(
        offenders_in("crates/runtime-cloudflare/src/boot.rs", source).len(),
        1
    );
}

#[test]
fn the_guard_does_not_fire_on_the_native_half() {
    // The shape `runtime-cloudflare` actually uses: the wasm arm forwards,
    // the native arm installs, and only the second is reachable off-wasm.
    let source = "#[cfg(target_arch = \"wasm32\")]\nfn a() {}\n\
                  #[cfg(not(target_arch = \"wasm32\"))]\n\
                  fn b() { let g = tracing::dispatcher::set_default(&d); }\n";
    assert!(offenders_in("crates/runtime-cloudflare/src/x.rs", source).is_empty());
}

#[test]
fn the_guard_ignores_crates_that_cannot_reach_a_worker() {
    // `runtime-native` installs one on purpose; it is never in a Worker.
    let source = "fn boot() { tracing::subscriber::set_global_default(s); }\n";
    assert!(offenders_in("crates/runtime-native/src/tracing_setup.rs", source).is_empty());
}
