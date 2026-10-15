//! `module_log!` from outside the defining crate (issue #846).
//!
//! The macro is how module code logs: modules are ordinary crates that
//! depend only on `cratefield-core`, and on Workers no tracing dispatcher
//! can be installed (it hangs the workerd isolate), so the macro routes its
//! line through the process-wide control-event forwarder to Workers Logs
//! and emits a normal `tracing` event natively. This file proves the
//! `#[macro_export]` expansion — `$crate` paths included — resolves from an
//! ordinary dependent crate, and that what the sink receives carries its
//! level prefix and no address.
//!
//! The unit tests in `src/logging.rs` cover the helper and the native
//! tracing arm in isolation.

// The capture sink below is a `std::sync::Mutex` on purpose (see the
// comment below); clippy.toml bans the type workspace-wide, so the allow is
// scoped to this file.
#![allow(clippy::disallowed_types)]

use cratefield_core::{ControlLevel, set_error_forwarder};

// ---------------------------------------------------------- the capture sink
//
// **Process-global on purpose.** The sink `set_error_forwarder` installs is
// global and first-install-wins, so a test binary installs exactly one and
// every test in this file shares one buffer. An assertion must therefore
// name a needle only its own test produces, and the buffer is never
// asserted empty: another test may have filled it first.

static CAPTURED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
static INSTALL: std::sync::Once = std::sync::Once::new();

fn record(_level: ControlLevel, line: &str) {
    CAPTURED.lock().expect("capture lock").push(line.to_owned());
}

/// Installs the sink once per test binary — `set_error_forwarder` keeps the
/// first installation and ignores later ones, so this must not race — and
/// returns the lookup.
fn capture() -> impl Fn(&str) -> Option<String> {
    INSTALL.call_once(|| set_error_forwarder(record));
    move |needle: &str| {
        CAPTURED
            .lock()
            .expect("capture lock")
            .iter()
            .find(|line| line.contains(needle))
            .cloned()
    }
}

// ---------------------------------------------------------------- the macro

#[test]
fn an_info_line_arrives_prefixed_and_scrubbed() {
    let capture = capture();
    cratefield_core::module_log!(info, "module-log-846-info row stored for ada@example.com");
    let line = capture("module-log-846-info").expect("the info line should reach the sink");
    assert!(
        line.starts_with("[info] "),
        "an info log is prefixed with its level: {line}"
    );
    assert!(!line.contains('@'), "email reached the sink: {line}");
}

#[test]
fn a_warn_line_arrives_prefixed() {
    let capture = capture();
    cratefield_core::module_log!(warn, "module-log-846-warn retrying the outbox sweep");
    let line = capture("module-log-846-warn").expect("the warn line should reach the sink");
    assert!(
        line.starts_with("[warn] "),
        "a warn log is prefixed with its level: {line}"
    );
}

#[test]
fn an_error_line_arrives_prefixed() {
    let capture = capture();
    cratefield_core::module_log!(error, "module-log-846-error outbox drain failed");
    let line = capture("module-log-846-error").expect("the error line should reach the sink");
    assert!(
        line.starts_with("[error] "),
        "an error log is prefixed with its level: {line}"
    );
}

#[test]
fn a_formatted_line_arrives_rendered_and_prefixed() {
    let capture = capture();
    let n = 3;
    cratefield_core::module_log!(warn, "module-log-846-args stored {n} rows", n = n);
    let line = capture("module-log-846-args").expect("the formatted line should reach the sink");
    assert!(
        line.starts_with("[warn] "),
        "a formatted warn log is prefixed with its level: {line}"
    );
    assert!(
        line.contains("stored 3 rows"),
        "the format args are rendered into the line: {line}"
    );
}
