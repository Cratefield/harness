//! Argument validation: every refusal is an envelope carrying
//! `mcp-argument-invalid` on a normal result — never a JSON-RPC error —
//! and every one of them fires before `fz` is spawned, because the
//! alternative is clap's prose where the agent expected JSON.

mod common;

use common::{call_tool, envelope_of, exiting, failure_code, printing};

use cratefield_mcp::server::Server;

const CLEAN: &str = r#"{"schema":1,"ok":true,"failures":[]}"#;

#[test]
fn a_missing_required_argument_is_an_envelope_not_a_protocol_error() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_init", r#"{"host":"example.com"}"#);
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(failure_code(&envelope), "mcp-argument-invalid");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("name"),
        "the refusal names the argument: {message}"
    );
    assert_eq!(calls.count(), 0, "the refusal happens before fz runs");
}

#[test]
fn a_null_required_argument_counts_as_missing() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = call_tool(
        &mut server,
        "fz_init",
        r#"{"name":null,"host":"example.com"}"#,
    );
    assert_eq!(result["isError"], true);
    assert_eq!(failure_code(&envelope_of(&result)), "mcp-argument-invalid");
    assert_eq!(calls.count(), 0);
}

#[test]
fn a_wrong_json_type_is_refused_naming_the_expected_type() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_init", r#"{"name":5,"host":"example.com"}"#);
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(failure_code(&envelope), "mcp-argument-invalid");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("name") && message.contains("a string"),
        "the refusal names the argument and the type wanted: {message}"
    );
    assert_eq!(calls.count(), 0);
}

#[test]
fn an_unknown_property_is_refused_naming_it() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_doctor", r#"{"bogus":"x"}"#);
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(failure_code(&envelope), "mcp-argument-invalid");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("bogus"),
        "a misspelled argument must not be silently dropped: {message}"
    );
    assert_eq!(
        calls.count(),
        0,
        "the tool never runs with defaults the agent did not ask for"
    );
}

#[test]
fn an_empty_required_string_is_refused() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = call_tool(
        &mut server,
        "fz_init",
        r#"{"name":"","host":"example.com"}"#,
    );
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(failure_code(&envelope), "mcp-argument-invalid");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("empty"),
        "an empty name would reach clap and fail there, as prose: {message}"
    );
    assert_eq!(calls.count(), 0);
}

#[test]
fn a_leading_dash_value_is_refused_before_clap_can_read_it_as_a_flag() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_add", r#"{"module":"-h"}"#);
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(failure_code(&envelope), "mcp-argument-invalid");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("flag"),
        "the refusal says why: `-h` would be re-read as a flag: {message}"
    );
    assert_eq!(
        calls.count(),
        0,
        "fz add -h is a usage error that prints no JSON at all"
    );
}

#[test]
fn a_null_optional_argument_is_absent_so_the_tool_runs_its_defaults() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_doctor", r#"{"out":null}"#);
    assert_eq!(result["isError"], false);
    assert_eq!(calls.single(), ["doctor", "--json"]);
}

#[test]
fn a_leading_dash_on_an_optional_argument_is_refused_too() {
    let (runner, calls) = exiting(0, CLEAN, "");
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_doctor", r#"{"out":"-o"}"#);
    assert_eq!(result["isError"], true);
    assert_eq!(failure_code(&envelope_of(&result)), "mcp-argument-invalid");
    assert_eq!(
        calls.count(),
        0,
        "fz doctor --out -o is the same trap: the value would be re-read as a flag"
    );
}

#[test]
fn fz_error_codes_refuses_an_unknown_property_like_every_other_tool() {
    // Its schema says `additionalProperties: false` just as the other
    // tools' do, so a misspelled argument cannot sail through as a
    // successful catalogue call.
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_error_codes", r#"{"bogus":true}"#);
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(failure_code(&envelope), "mcp-argument-invalid");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("bogus") && message.contains("fz_error_codes"),
        "the refusal names the argument and the tool: {message}"
    );
    assert!(
        envelope.get("codes").is_none(),
        "the refusal is the whole envelope, not a catalogue with a note"
    );
    assert_eq!(calls.count(), 0);
}
