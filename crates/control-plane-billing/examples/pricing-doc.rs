//! Regenerates the two data tables in `docs/control-plane/PRICING.md`
//! from `cratefield-billing`'s pricing data. Run without arguments to
//! write the file, or with `--check` to verify the checked-in copy has
//! no drift (CI fails the run on drift).
//!
//! ```text
//! cargo run -p cratefield-billing --example pricing-doc          # write
//! cargo run -p cratefield-billing --example pricing-doc -- --check
//! ```
//!
//! Host-only tooling, the same shape as `errors-doc`,
//! `compatibility-doc` and `push-env-doc`: the library itself never
//! touches `std::fs`, and the document is where the decision lives —
//! this only keeps the two tables the screen renders from saying
//! something the document does not.

fn main() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/control-plane/PRICING.md");
    let check = std::env::args().any(|arg| arg == "--check");
    let current = std::fs::read_to_string(&path).unwrap_or_default();

    // The marginal-cost figure is hand-written arithmetic in the
    // document, not a generated table: the tool will not rewrite it, so
    // it refuses instead, naming the paragraph. This runs before either
    // mode so a write cannot "fix" drift the prose still carries.
    if !cratefield_billing::marginal_cost_appears_in(&current) {
        eprintln!(
            "docs/control-plane/PRICING.md no longer carries \
             `{}`: the free-venture marginal cost and the crate's constant have drifted. \
             Edit the document's arithmetic paragraph and \
             FREE_VENTURE_MARGINAL_COST together.",
            cratefield_billing::FREE_VENTURE_MARGINAL_COST
                .trim_start_matches('≈')
                .trim(),
        );
        std::process::exit(1);
    }

    let generated = match cratefield_billing::sync_pricing_doc(&current) {
        Ok(generated) => generated,
        Err(err) => {
            eprintln!("docs/control-plane/PRICING.md cannot be generated: {err}");
            std::process::exit(1);
        }
    };

    if check {
        if current != generated {
            eprintln!(
                "docs/control-plane/PRICING.md is stale; regenerate with `cargo run -p \
                 cratefield-billing --example pricing-doc` and commit it"
            );
            std::process::exit(1);
        }
        println!(
            "docs/control-plane/PRICING.md is up to date ({} cost lines, {} tier lines)",
            cratefield_billing::PLATFORM_COSTS.len(),
            cratefield_billing::TIERS.len(),
        );
        return;
    }

    std::fs::write(&path, generated).expect("write docs/control-plane/PRICING.md");
    println!(
        "wrote {} ({} cost lines, {} tier lines)",
        path.display(),
        cratefield_billing::PLATFORM_COSTS.len(),
        cratefield_billing::TIERS.len(),
    );
}
