//! No app is baked into the Worker (issues #646, #777): auth runs as one
//! branded instance per app, and every app-specific value arrives through
//! configuration. A name or domain under `src/` would be one app's
//! deployment detail leaking into every other app's instance.

use std::fs;
use std::path::Path;

/// Literals that name a particular app, brand or domain. None may appear
/// anywhere under `src/`, compared case-insensitively. The old umbrella's
/// names are spelt in two halves so that this file does not itself match a
/// repository-wide search for them.
const APP_MARKERS: &[&str] = &[
    concat!("factory", "0"),
    concat!("factory", " zero"),
    "cratefield.com",
    "alphahunt",
    "yoginini",
    "earthos",
];

#[test]
fn no_app_literal_appears_in_the_worker_source() {
    let mut offenders = Vec::new();
    scan(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut offenders,
    );
    assert!(
        offenders.is_empty(),
        "an app-specific literal appears in src/; move it to the instance's config:\n{}",
        offenders.join("\n")
    );
}

/// Collects every line in a `.rs` file under `dir`, recursively, that
/// carries one of the markers.
fn scan(dir: &Path, offenders: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("src is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            scan(&path, offenders);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            let text = fs::read_to_string(&path).expect("a source file is readable");
            for (line_no, line) in text.lines().enumerate() {
                let lower = line.to_ascii_lowercase();
                if APP_MARKERS.iter().any(|marker| lower.contains(marker)) {
                    offenders.push(format!(
                        "{}:{}: {}",
                        path.display(),
                        line_no + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
}
