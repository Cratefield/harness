//! `factory0-core` is the runtime-agnostic kernel of the Factory Zero harness.
//!
//! Placeholder crate for milestone M0 issue #1: the `Module` trait, `Harness`
//! builder, port traits, problem+json errors, request scope, event bus and
//! template registry land with issues #2-#4. See `docs/ARCHITECTURE.md`.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_smoke() {
        // Proves fmt + clippy + test run on a clean clone from day one.
        assert_eq!(2 + 2, 4);
    }
}


#[allow(dead_code)]
fn clippy_probe() -> u64 {
    // clippy::cast_possible_truncation (pedantic) — deliberately here to
    // verify CI fails on clippy warnings. Throwaway branch, deleted after.
    3.7_f64 as u64
}

#[cfg(test)]
mod failing_probe {
    #[test]
    fn deliberately_failing() {
        // Deliberately failing to verify CI fails on test failures.
        assert_eq!(1, 2, "throwaway CI verification probe");
    }
}
