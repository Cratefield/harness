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

