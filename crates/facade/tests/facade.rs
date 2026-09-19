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
///
/// This used to be four `#[cfg(feature = "…")]` functions whose types only
/// line up if the alias is right. That shape has two problems, and the
/// second one is why it is gone: it covered four of the twenty-four
/// aliases, and with `default = []` — which is what `cargo test
/// --workspace` builds — every one of the four compiled to nothing. The
/// test had never checked an alias.
///
/// Reading the source instead covers all of them, and covers them with no
/// features enabled, which is the configuration the test actually runs in.
#[test]
fn every_feature_aliases_the_crate_it_enables() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = std::fs::read_to_string(root.join("src/lib.rs")).expect("the facade's own source");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("the facade's manifest");

    // `#[cfg(feature = "x")]` immediately above `pub use <crate> as <alias>;`
    let mut aliases: Vec<(String, String, String)> = Vec::new();
    let lines: Vec<&str> = lib.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let Some(feature) = line
            .split_once("cfg(feature = \"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(name, _)| name.to_owned())
        else {
            continue;
        };
        let Some(next) = lines.get(index + 1) else {
            continue;
        };
        let Some(rest) = next.trim().strip_prefix("pub use ") else {
            continue;
        };
        let Some((krate, alias)) = rest.trim_end_matches(';').split_once(" as ") else {
            continue;
        };
        aliases.push((feature, krate.trim().to_owned(), alias.trim().to_owned()));
    }

    // The absences below would all hold over an empty list, and an empty
    // list is exactly what a changed re-export style would produce.
    assert!(
        aliases.len() >= 20,
        "only {} aliases found in the facade — the scan is reading nothing: {aliases:?}",
        aliases.len()
    );

    for (feature, krate, alias) in &aliases {
        // The alias is named after the feature, with the hyphen a Rust
        // module name cannot have.
        assert_eq!(
            alias,
            &feature.replace('-', "_"),
            "feature `{feature}` is exposed as `{alias}`"
        );
        // And the feature enables exactly that crate. `notifications`
        // enables a second feature as well, so this is a containment
        // check rather than an equality one.
        let declared = feature_line(&manifest, feature)
            .unwrap_or_else(|| panic!("`{feature}` is aliased but not declared in [features]"));
        let wanted = format!("dep:{}", krate.replace('_', "-"));
        assert!(
            declared.contains(&wanted),
            "feature `{feature}` aliases `{krate}` but enables {declared}"
        );
    }
}

/// The `[features]` entry for `name`, flattened onto one line — the
/// declaration may wrap, as `push-wiring` does.
fn feature_line(manifest: &str, name: &str) -> Option<String> {
    let features = manifest.find("\n[features]")?;
    let rest = &manifest[features..];
    let end = rest[1..].find("\n[").map_or(rest.len(), |at| at + 1);
    let section = &rest[..end];
    let at = section.find(&format!("\n{name} ="))?;
    let from = &section[at + 1..];
    let close = from.find(']')?;
    Some(
        from[..=close]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
    )
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
    // a facade dependency. `cratefield` is this crate. workers-ai is the
    // classifier adapter that needs the Workers `env.AI` binding (and the
    // `worker` crate): a facade feature would be platform-blind, so a
    // venture on Workers depends on it directly and no native venture ever
    // pulls `worker` through here (issue #456).
    const NOT_LIBRARIES: &[&str] = &[
        "cratefield-cli",
        "cratefield",
        "cratefield-adapter-workers-ai",
    ];

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
