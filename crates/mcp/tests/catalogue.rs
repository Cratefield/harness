//! The anti-drift contract — the most important test in the crate:
//! `fz_error_codes` serves the CLI's registry, read live, in registry
//! order, plus exactly the wrapper codes `codes.rs` lists — four today
//! (`mcp-fz-timeout` was appended fourth), and the count here is read
//! from that list rather than hardcoded, so a fifth appends without
//! this test learning a new number. If the CLI grows a code this test
//! grows with it; if this crate ever copies the list instead of reading
//! it, the copies stop matching and this fails.

mod common;

use common::{call_tool, envelope_of, printing};

use cratefield_cli::codes::registry;
use cratefield_mcp::codes::wrapper_codes;
use cratefield_mcp::server::Server;
use serde_json::json;

#[test]
fn fz_error_codes_is_the_cli_registry_plus_exactly_the_wrapper_codes() {
    let registry = registry();
    let wrappers = wrapper_codes();
    let (runner, calls) = printing("");
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_error_codes", "{}");
    let envelope = envelope_of(&result);

    // The catalogue rides inside the envelope shape every other tool
    // returns, and serving it spawns nothing. The schema it claims is
    // the CLI's own constant, not this crate's idea of it.
    assert_eq!(envelope["schema"], json!(cratefield_cli::workflow::SCHEMA));
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["failures"], json!([]));
    assert_eq!(calls.count(), 0, "the catalogue runs no fz process");

    let codes = envelope["codes"].as_array().expect("the codes array");
    assert_eq!(
        codes.len(),
        registry.len() + wrappers.len(),
        "every fz code, then exactly the wrapper codes"
    );

    for (entry, definition) in codes.iter().zip(&registry) {
        assert_eq!(entry["source"], "fz", "{} is the CLI's", definition.code);
        assert_eq!(entry["code"], definition.code, "registry order, unedited");
        assert_eq!(entry["title"], definition.title);
        assert_eq!(entry["description"], definition.description);
    }

    for (entry, definition) in codes[registry.len()..].iter().zip(&wrappers) {
        assert_eq!(
            entry["source"], "mcp",
            "{} is the wrapper's",
            definition.code
        );
        assert_eq!(entry["code"], definition.code);
        assert_eq!(entry["title"], definition.title);
        assert_eq!(entry["description"], definition.description);
    }
}

#[test]
fn every_code_is_unique_and_no_wrapper_code_collides_with_a_cli_code() {
    let registry = registry();
    let (runner, _) = printing("");
    let mut server = Server::new(runner);
    let envelope = envelope_of(&call_tool(&mut server, "fz_error_codes", "{}"));
    let codes = envelope["codes"]
        .as_array()
        .expect("the codes array")
        .clone();

    let fz_codes: Vec<String> = codes[..registry.len()]
        .iter()
        .map(|entry| entry["code"].as_str().expect("a code").to_owned())
        .collect();
    let wrapper_codes: Vec<String> = codes[registry.len()..]
        .iter()
        .map(|entry| entry["code"].as_str().expect("a code").to_owned())
        .collect();

    let mut everything = fz_codes.clone();
    everything.extend(wrapper_codes.iter().cloned());
    let total = everything.len();
    everything.sort();
    everything.dedup();
    assert_eq!(everything.len(), total, "a code twice in the catalogue");

    for wrapper in &wrapper_codes {
        assert!(
            !fz_codes.contains(wrapper),
            "{wrapper} collides with a CLI code"
        );
    }
}
