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

/// Crates that cannot end up in a Worker: the native runtime, the `fz`
/// host binary, and this crate's own tests (which quote the installer
/// names by design).
///
/// Everything else under `crates/`, `examples/` and `ventures/` is
/// scanned. The list used to be the opposite shape — an explicit
/// wasm-reachable allowlist of three crates — and that was a guard that
/// only looked like it covered the invariant: forty crates link into a
/// Worker (every module and adapter, the facade), so a dispatcher
/// installed in, say, `adapter-resend` would hang every production Worker
/// while the scan shrugged. Scanning by default fails loud when a
/// native-only crate legitimately needs an installer: it either gates the
/// call behind `#[cfg(not(target_arch = "wasm32"))]` (which the detector
/// already honours, see [`native_only_above`]) or this list has to name
/// it, in the open.
const NATIVE_ONLY: [&str; 3] = ["crates/runtime-native/", "crates/cli/", "crates/cli-acceptance/"];

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

/// Whether the file is outside the native-only crates, i.e. scanned.
fn scanned(relative: &str) -> bool {
    let in_scope = relative.starts_with("crates/")
        || relative.starts_with("examples/")
        || relative.starts_with("ventures/");
    in_scope && !NATIVE_ONLY.iter().any(|dir| relative.starts_with(dir))
}

/// Every dispatcher install in a scanned source that is not gated to the
/// native target.
fn offenders_in(relative: &str, source: &str) -> Vec<String> {
    if !scanned(relative) {
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
fn no_worker_reachable_source_installs_a_tracing_dispatcher() {
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

#[test]
fn the_guard_covers_every_crate_that_links_into_a_worker() {
    // The reason the scan is deny-by-default: an installer in a module or
    // adapter crate hangs every Worker exactly as hard as one in
    // `runtime-cloudflare`, and the old three-crate allowlist would have
    // let it through.
    let source = "fn boot() { tracing::subscriber::set_global_default(s); }\n";
    for relative in [
        "crates/adapter-resend/src/lib.rs",
        "crates/module-waitlist/src/lib.rs",
        "crates/facade/src/lib.rs",
        "examples/venture/src/lib.rs",
        "ventures/cratefield-waitlist/src/lib.rs",
    ] {
        assert_eq!(
            offenders_in(relative, source).len(),
            1,
            "{relative} is scanned"
        );
    }
}
