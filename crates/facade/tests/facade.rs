//! The facade adds no code, so there is exactly one thing to test: that it
//! still points at everything, and points at the same types.

/// Re-exporting the core at the root has to give the *same* types, not
/// lookalikes, or a venture that mixes `cratefield::Harness` with a crate
/// taking `cratefield_core::Harness` stops compiling for no visible reason.
/// These functions only compile if the two are one type.
#[test]
fn the_root_reexport_is_the_core_itself() {
    fn _harness(h: cratefield::Harness) -> cratefield_core::Harness {
        h
    }
    fn _venture(v: cratefield_core::Venture) -> cratefield::Venture {
        v
    }
    fn _port(p: cratefield::Port) -> cratefield_core::Port {
        p
    }
    fn _module(m: &dyn cratefield::Module) -> &dyn cratefield_core::Module {
        m
    }
}

/// Each feature alias must name the crate the feature enables. Wiring one
/// to the wrong crate is a copy-paste away and would compile.
#[test]
fn every_enabled_feature_aliases_its_own_crate() {
    #[cfg(feature = "cloudflare")]
    fn _cloudflare(
        c: cratefield::cloudflare::Cloudflare,
    ) -> cratefield_runtime_cloudflare::Cloudflare {
        c
    }
    #[cfg(feature = "sqlite")]
    fn _sqlite(d: cratefield::sqlite::SqliteDatabase) -> cratefield_adapter_sqlite::SqliteDatabase {
        d
    }
    #[cfg(feature = "waitlist")]
    fn _waitlist(w: cratefield::waitlist::Waitlist) -> cratefield_module_waitlist::Waitlist {
        w
    }
    #[cfg(feature = "ui")]
    fn _ui(u: cratefield::ui::Ui) -> cratefield_ui::Ui {
        u
    }
}

/// The drift this crate exists to cause, and therefore has to guard: a new
/// publishable crate lands in the workspace and nobody adds it here, so
/// `cargo add cratefield` quietly stops being the whole harness.
///
/// Reads the manifests rather than a hand-written list, because a
/// hand-written list is the thing that goes stale.
#[test]
fn every_publishable_library_is_reachable_from_the_facade() {
    // `cratefield-cli` is the `fz` binary: nothing `use`s it, so it is not
    // a facade dependency. `cratefield` is this crate.
    const NOT_LIBRARIES: &[&str] = &["cratefield-cli", "cratefield"];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crates/facade has a workspace root two levels up")
        .to_path_buf();

    let workspace = std::fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");
    let facade = std::fs::read_to_string(root.join("crates/facade/Cargo.toml")).expect("manifest");

    // Every internal crate the workspace declares, with the directory it
    // lives in, so the publish flag can be read from its own manifest.
    let declared: Vec<(String, String)> = workspace
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(" = {")?;
            let name = name.trim();
            if !name.starts_with("cratefield") {
                return None;
            }
            let path = rest.split_once("path = \"")?.1.split_once('"')?.0;
            Some((name.to_owned(), path.to_owned()))
        })
        .collect();
    assert!(
        declared.len() > 10,
        "parsed {} workspace crates, so the parser is broken, not the facade",
        declared.len()
    );

    let reachable: Vec<&str> = facade
        .lines()
        .filter_map(|line| line.split_once(" = {"))
        .map(|(name, _)| name.trim())
        .filter(|name| name.starts_with("cratefield-"))
        .collect();

    let mut missing = Vec::new();
    for (name, path) in &declared {
        if NOT_LIBRARIES.contains(&name.as_str()) {
            continue;
        }
        let manifest =
            std::fs::read_to_string(root.join(path).join("Cargo.toml")).expect("crate manifest");
        if manifest.contains("publish = false") {
            continue;
        }
        if !reachable.contains(&name.as_str()) {
            missing.push(name.clone());
        }
    }

    assert!(
        missing.is_empty(),
        "publishable crates that `cargo add cratefield` cannot reach: {missing:?}\n\
         add each one to crates/facade as an optional dependency behind its own feature"
    );
}
