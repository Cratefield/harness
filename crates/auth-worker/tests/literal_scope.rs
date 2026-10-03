//! The venture name may appear in exactly one place (issue #646): the
//! `defaults` table. Anywhere else under `src` it is a deployment detail
//! leaking into code that a wrapper venture should be able to reuse unchanged.

use std::fs;
use std::path::Path;

/// The one literal the scan forbids outside `defaults.rs`.
const VENTURE_MARKER: &str = "factory0";

#[test]
fn the_venture_marker_lives_only_in_the_defaults_table() {
    let mut offenders = Vec::new();
    scan(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut offenders,
    );
    assert!(
        offenders.is_empty(),
        "the venture marker appears outside src/defaults.rs:\n{}",
        offenders.join("\n")
    );
}

/// Collects every `factory0` line in a `.rs` file under `dir`, recursively,
/// skipping the defaults table itself.
fn scan(dir: &Path, offenders: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("src is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            scan(&path, offenders);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs")
            && path.file_name().and_then(|name| name.to_str()) != Some("defaults.rs")
        {
            let text = fs::read_to_string(&path).expect("a source file is readable");
            for (line_no, line) in text.lines().enumerate() {
                if line.contains(VENTURE_MARKER) {
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
