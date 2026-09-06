//! Generates `docs/ERRORS.md` from the problem registry in
//! `factory0-core::problems` (issue #14). Run without arguments to
//! write the file, or with `--check` to verify the checked-in copy has
//! no drift (CI fails the run on drift).
//!
//! ```text
//! cargo run -p factory0-core --example errors-doc          # write
//! cargo run -p factory0-core --example errors-doc -- --check
//! ```
//!
//! Host-only tooling: the core library itself never touches `std::fs`.

use factory0_core::problem_registry;

fn markdown() -> String {
    let mut defs = problem_registry();
    defs.sort_by_key(|def| def.slug);

    let mut out = String::new();
    out.push_str("# Error taxonomy\n\n");
    out.push_str(
        "Every problem slug the harness can emit, generated from\n\
         `factory0-core`'s registry by `cargo run -p factory0-core --example\n\
         errors-doc` and checked in CI for drift. Responses are RFC 9457\n\
         `application/problem+json` with `type` =\n\
         `https://factory0.ventures/problems/<slug>` and `instance` = the\n\
         request id.\n\n",
    );
    out.push_str("| Slug | Status | Title | Description |\n");
    out.push_str("|---|---|---|---|\n");
    for def in defs {
        use std::fmt::Write as _;
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            def.slug,
            def.status.as_u16(),
            def.title,
            def.description
        );
    }
    out
}

fn main() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ERRORS.md");
    let generated = markdown();
    let check = std::env::args().any(|arg| arg == "--check");

    if check {
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current != generated {
            eprintln!(
                "docs/ERRORS.md is stale; regenerate with `cargo run -p factory0-core \
                 --example errors-doc` and commit it"
            );
            std::process::exit(1);
        }
        println!(
            "docs/ERRORS.md is up to date ({} slugs)",
            problem_registry().len()
        );
        return;
    }

    std::fs::write(&path, generated).expect("write docs/ERRORS.md");
    println!(
        "wrote {} ({} slugs)",
        path.display(),
        problem_registry().len()
    );
}
