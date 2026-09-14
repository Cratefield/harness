//! The manifest's vocabularies are the harness's.
//!
//! `cratefield-manifest` deliberately does not depend on the harness, so
//! it carries its own copy of the data-kind names. `fz build` then turns
//! an author's `kind` straight into `DataKind::<Kind>` in generated
//! source, which makes the copy load-bearing in both directions:
//!
//! - a string in `KINDS` that is not a variant here is a generated
//!   venture that does not compile, and the author meets a rustc error in
//!   a file whose first line says not to edit it;
//! - a variant here that `KINDS` does not list is a kind no author can
//!   declare, and the manifest's own error message offers a shorter menu
//!   than the harness understands.
//!
//! This crate is where the two are both visible.

use cratefield_core::DataKind;

#[test]
fn the_manifest_knows_every_data_kind() {
    let harness: Vec<&str> = DataKind::ALL.iter().map(|kind| kind.as_str()).collect();
    let mut manifest = cratefield_manifest::KINDS.to_vec();
    let mut harness_sorted = harness.clone();
    manifest.sort_unstable();
    harness_sorted.sort_unstable();
    assert_eq!(
        manifest, harness_sorted,
        "the manifest's `kind` vocabulary and `DataKind` have drifted"
    );
}

#[test]
fn every_kind_capitalises_into_its_variant_name() {
    // `generate_tables` writes `DataKind::{}` with the wire name simply
    // capitalised — `camel`, which uppercases the first character and
    // copies the rest. That works only while every wire name is a single
    // lowercase word. `DataKind`'s own doc says the names are kebab-case
    // "matching the harness's route convention", so the day a two-word
    // kind arrives the generator emits `DataKind::Phone-number` and the
    // venture does not build.
    //
    // Asserted here rather than left to be discovered there.
    for kind in DataKind::ALL {
        let wire = kind.as_str();
        assert!(
            wire.chars().all(|c| c.is_ascii_lowercase()),
            "`{wire}` is not a single lowercase word, so capitalising it does not \
             name a Rust variant"
        );
        let capitalised = {
            let mut chars = wire.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + chars.as_str()
            })
        };
        assert_eq!(
            format!("{kind:?}"),
            capitalised,
            "`{wire}` does not capitalise into its variant name"
        );
    }
}
