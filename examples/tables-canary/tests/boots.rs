//! The generated venture composes.
//!
//! This is the gate that was missing. Nothing compiled a generated
//! venture — `examples/venture` is hand-written — so the generator could
//! emit source that does not build, and did emit source that builds and
//! then panics: #371 shipped a module requiring `Port::Auth` beside a
//! runtime that provided none, and `build().expect(...)` would have
//! panicked on the first request in production.
//!
//! Compiling is the crate being a workspace member. This is the other
//! half: the composition the generated `harness()` performs actually
//! succeeds.

#[test]
fn the_generated_venture_composes() {
    // `harness()` is the generated function `fz` and the Worker both
    // call. It ends in `build().expect("generated venture harness is
    // valid")`, so a composition the harness refuses is a panic here —
    // which is the point.
    let harness = tables_canary::harness();
    let modules: Vec<&str> = harness.modules().iter().map(|m| m.name()).collect();
    assert_eq!(modules, ["tables"], "the declared tables module is mounted");
}

#[test]
fn the_module_requires_a_verifier_and_the_runtime_provides_one() {
    // The pair #371 got wrong in opposite directions. Asserting both here
    // rather than trusting that composing proved it: a future change that
    // dropped both would compose fine and serve an `owner` table with no
    // way to identify a caller.
    use cratefield::{Port, Runtime as _};

    let harness = tables_canary::harness();
    let module = harness
        .modules()
        .iter()
        .find(|m| m.name() == "tables")
        .expect("mounted");
    assert!(
        module.requires().contains(&Port::Auth),
        "an owner table's module must know who is calling: {:?}",
        module.requires()
    );
    assert!(
        tables_canary::runtime().provides().contains(&Port::Auth),
        "and the runtime has to provide it"
    );
}

#[test]
fn the_venture_declares_both_of_its_tables() {
    let harness = tables_canary::harness();
    let module = harness
        .modules()
        .iter()
        .find(|m| m.name() == "tables")
        .expect("mounted");
    let mut tables = module.tables().to_vec();
    tables.sort_unstable();
    assert_eq!(tables, ["note", "tier"]);

    // And says what each holds, or they are outside `fz data export`,
    // outside subject access and outside erasure.
    let declared: Vec<&str> = module.personal_data().iter().map(|set| set.table).collect();
    assert_eq!(declared.len(), 2, "{declared:?}");
}
