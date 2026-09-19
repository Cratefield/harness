//! Envelope handling: `fz`'s stdout is the answer, byte for byte, when
//! its last non-empty line is a JSON object; everything else lands on
//! `mcp-fz-no-json` carrying the exit status and a stderr excerpt, and
//! a spawn failure on `mcp-fz-unavailable`.

mod common;

use common::{call_tool, envelope_of, exiting, failure_code, text_of, unspawnable};

use cratefield_mcp::server::Server;
use serde_json::json;

/// The text the agent reads is exactly the line `fz` printed, key order
/// included. A re-serialisation would alphabetise `digest` and `changed`
/// to the front — precisely what the pass-through exists to prevent.
#[test]
fn an_ok_envelope_passes_through_byte_for_byte() {
    let line = r#"{"schema":1,"ok":true,"failures":[],"digest":"abc123","changed":false}"#;
    let stdout = format!("{line}\n");
    let (runner, calls) = exiting(0, &stdout, "");
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_plan", "{}");
    assert_eq!(result["isError"], false);
    assert_eq!(text_of(&result), line, "the agent reads fz's own bytes");
    assert_eq!(calls.single()[0], "plan");
}

#[test]
fn a_failed_envelope_arrives_as_iserror_with_its_failures_preserved() {
    let (runner, _) = exiting(
        1,
        r#"{"schema":1,"ok":false,"failures":[{"code":"stale-plan","message":"modules: added cms"}]}"#,
        "",
    );
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_deploy", "{}");
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(envelope["failures"][0]["code"], "stale-plan");
    assert_eq!(envelope["failures"][0]["message"], "modules: added cms");
    assert_eq!(envelope["failures"].as_array().map(Vec::len), Some(1));
}

#[test]
fn a_spawn_failure_is_mcp_fz_unavailable_with_the_reason() {
    let (runner, _) = unspawnable("could not run `fz`: no such file or directory (os error 2)");
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_doctor", "{}");
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(failure_code(&envelope), "mcp-fz-unavailable");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("could not run `fz`"),
        "the OS reason travels: {message}"
    );
}

#[test]
fn a_clap_usage_error_is_mcp_fz_no_json_naming_the_exit_status_and_stderr() {
    let (runner, _) = exiting(
        2,
        "",
        "error: unexpected argument '--bogus' found\n\nUsage: fz add [OPTIONS] [MODULE]\n",
    );
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_add", r#"{"module":"cms"}"#);
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(failure_code(&envelope), "mcp-fz-no-json");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("exit code 2"),
        "the exit status travels: {message}"
    );
    assert!(
        message.contains("unexpected argument"),
        "the stderr excerpt travels: {message}"
    );
}

#[test]
fn a_trailing_newline_on_stdout_is_trimmed_off_the_text() {
    let (runner, _) = exiting(0, "{\"schema\":1,\"ok\":true,\"failures\":[]}\n\n", "");
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_verify", "{}");
    assert_eq!(
        text_of(&result),
        r#"{"schema":1,"ok":true,"failures":[]}"#,
        "trailing whitespace is not fz's bytes"
    );
    assert_eq!(result["isError"], false);
}

#[test]
fn the_last_non_empty_line_is_the_envelope_and_only_it() {
    let (runner, _) = exiting(
        0,
        "warning: deprecated flag\n{\"schema\":1,\"ok\":true,\"failures\":[]}\n",
        "",
    );
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_verify", "{}");
    assert_eq!(
        text_of(&result),
        r#"{"schema":1,"ok":true,"failures":[]}"#,
        "the prose before the object is not the answer"
    );
}

#[test]
fn an_array_on_stdout_is_not_an_envelope() {
    let (runner, _) = exiting(0, "[1,2]\n", "");
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_verify", "{}");
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(failure_code(&envelope), "mcp-fz-no-json");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("stdout excerpt") && message.contains("[1,2]"),
        "with stderr empty the excerpt comes from stdout: {message}"
    );
}

#[test]
fn a_bare_string_on_stdout_is_not_an_envelope() {
    let (runner, _) = exiting(0, "\"hi\"\n", "");
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_verify", "{}");
    assert_eq!(result["isError"], true);
    assert_eq!(failure_code(&envelope_of(&result)), "mcp-fz-no-json");
}

/// The `mcp-fz-no-json` description promises "a bounded stderr excerpt",
/// so the bound has to bite: a five-thousand-character traceback reaches
/// the agent only as its head, never in full. Pinned as an effect — the
/// reply carries a small fraction of what `fz` dumped, and says where it
/// stopped — rather than on the exact cap, so a deliberate change to the
/// cap does not fail here.
#[test]
fn a_huge_stderr_is_excerpted_not_carried_in_full() {
    let stderr = format!("error: the venture exploded\n{}\n", "x".repeat(5000));
    let (runner, _) = exiting(2, "", &stderr);
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_doctor", "{}");
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("error: the venture exploded"),
        "the head of the traceback travels: {message}"
    );
    let dumped = stderr.chars().count();
    let carried = message.chars().count();
    assert!(
        carried * 4 < dumped,
        "the excerpt is bounded: {carried} of {dumped} characters travelled"
    );
    assert!(
        message.ends_with('…'),
        "a cut excerpt says it was cut: {message}"
    );
}

#[test]
fn a_synthesised_envelope_claims_the_cli_schema_not_a_local_literal() {
    // The refusal envelopes are the one shape this crate builds itself,
    // and their `schema` is the CLI's constant by path — when the CLI
    // bumps its schema, these follow rather than keep saying 1.
    assert_eq!(
        cratefield_mcp::fz::SCHEMA,
        cratefield_cli::workflow::SCHEMA,
        "the wrapper's schema constant is the CLI's, by path"
    );
    let (runner, _) = unspawnable("could not run `fz`: no such file or directory (os error 2)");
    let mut server = Server::new(runner);
    let envelope = envelope_of(&call_tool(&mut server, "fz_doctor", "{}"));
    assert_eq!(
        envelope["schema"],
        json!(cratefield_cli::workflow::SCHEMA),
        "the synthesised refusal carries the CLI's schema value"
    );
}
