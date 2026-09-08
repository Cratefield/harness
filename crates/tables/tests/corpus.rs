//! The conformance corpus: `corpus/rows.json` run through the Rust
//! validator.
//!
//! The file is data, not Rust, so a second implementation in another
//! language runs over the same cases. That is the whole point: this
//! validator and a generated client will otherwise drift on empty versus
//! absent, number coercion, null versus missing, Unicode length and
//! whitespace, and each of those has cases here.

use cratefield_tables::{ErrorCode, RowError, Schema, validate_row};
use serde::Deserialize;
use serde_json::Value;

const CORPUS: &str = include_str!("../corpus/rows.json");

#[derive(Debug, Deserialize)]
struct Corpus {
    version: u32,
    codes: Vec<String>,
    tables: Schema,
    cases: Vec<Case>,
    #[allow(dead_code)]
    #[serde(flatten)]
    rest: serde_json::Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    #[allow(dead_code)]
    #[serde(default)]
    why: Option<String>,
    table: String,
    input: Value,
    expect: Expect,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "verdict", rename_all = "lowercase")]
enum Expect {
    Accept,
    Reject { errors: Vec<ExpectedError> },
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ExpectedError {
    field: String,
    code: ErrorCode,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("corpus/rows.json parses")
}

#[test]
fn every_case_reaches_its_expected_verdict() {
    let corpus = corpus();
    assert_eq!(corpus.version, 1);
    for case in &corpus.cases {
        let table = corpus
            .tables
            .table(&case.table)
            .unwrap_or_else(|| panic!("{}: no table named `{}`", case.name, case.table));

        match (&case.expect, validate_row(table, &case.input)) {
            (Expect::Accept, Ok(())) => {}
            (Expect::Accept, Err(errors)) => {
                panic!("{}: expected accept, got {}", case.name, errors.detail())
            }
            (Expect::Reject { .. }, Ok(())) => {
                panic!("{}: expected reject, got accept", case.name)
            }
            (Expect::Reject { errors: expected }, Err(actual)) => {
                let got: Vec<ExpectedError> = actual
                    .errors()
                    .iter()
                    .map(|error: &RowError| ExpectedError {
                        field: error.field.clone(),
                        code: error.code,
                    })
                    .collect();
                assert_eq!(
                    &got,
                    expected,
                    "{}: wrong errors ({})",
                    case.name,
                    actual.detail()
                );
            }
        }
    }
}

#[test]
fn every_table_in_the_corpus_is_a_declarable_table() {
    // The corpus reuses the manifest's own deserializer, so a case cannot
    // describe a table a venture could not declare.
    corpus()
        .tables
        .validate()
        .expect("the corpus tables declare");
}

#[test]
fn the_corpus_covers_every_error_code() {
    let corpus = corpus();
    let mut seen: Vec<ErrorCode> = Vec::new();
    for case in &corpus.cases {
        if let Expect::Reject { errors } = &case.expect {
            for error in errors {
                if !seen.contains(&error.code) {
                    seen.push(error.code);
                }
            }
        }
    }
    let missing: Vec<&str> = ErrorCode::ALL
        .iter()
        .filter(|code| !seen.contains(code))
        .map(|code| code.as_str())
        .collect();
    assert!(missing.is_empty(), "codes with no case: {missing:?}");
}

#[test]
fn the_declared_code_list_matches_the_validator() {
    // The file lists its own vocabulary for a reader in another language.
    // If a code is added to the crate and not to the file, this fails.
    let declared = corpus().codes;
    let actual: Vec<String> = ErrorCode::ALL
        .iter()
        .map(|code| code.as_str().to_owned())
        .collect();
    assert_eq!(declared, actual);
}

#[test]
fn every_case_name_is_unique() {
    let corpus = corpus();
    let mut names: Vec<&str> = corpus.cases.iter().map(|case| case.name.as_str()).collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "a case name is repeated");
}

#[test]
fn the_corpus_has_a_case_for_each_named_drift_risk() {
    // The five the roadmap calls out. A prefix per group so a missing
    // group is visible rather than quietly absent.
    let corpus = corpus();
    for prefix in [
        "empty string:",
        "coercion:",
        "null:",
        "unicode:",
        "whitespace:",
    ] {
        let count = corpus
            .cases
            .iter()
            .filter(|case| case.name.starts_with(prefix))
            .count();
        assert!(count >= 3, "only {count} cases for `{prefix}`");
    }
}
