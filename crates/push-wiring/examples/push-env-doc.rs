//! Generates `docs/PUSH-ENV.md` from `cratefield-push-wiring`'s
//! `PUSH_ENV` table (issue #191). Run without arguments to write the file,
//! or with `--check` to verify the checked-in copy has no drift (CI fails
//! the run on drift).
//!
//! ```text
//! cargo run -p cratefield-push-wiring --example push-env-doc          # write
//! cargo run -p cratefield-push-wiring --example push-env-doc -- --check
//! ```
//!
//! Host-only tooling, the same shape as `cratefield-core`'s `errors-doc`:
//! the library itself never touches `std::fs`.

use cratefield_push_wiring::{PUSH_ENV, notifications_doc};

fn main() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/PUSH-ENV.md");
    let generated = notifications_doc();
    let check = std::env::args().any(|arg| arg == "--check");

    if check {
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current != generated {
            eprintln!(
                "docs/PUSH-ENV.md is stale; regenerate with `cargo run -p \
                 cratefield-push-wiring --example push-env-doc` and commit it"
            );
            std::process::exit(1);
        }
        println!(
            "docs/PUSH-ENV.md is up to date ({} variables)",
            PUSH_ENV.len()
        );
        return;
    }

    std::fs::write(&path, generated).expect("write docs/PUSH-ENV.md");
    println!("wrote {} ({} variables)", path.display(), PUSH_ENV.len());
}
