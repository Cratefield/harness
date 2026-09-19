//! Structured tool output is a protocol revision, not a given:
//! `structuredContent` on results and `outputSchema` on tools exist
//! from 2025-06-18 on. An older client gets the envelope as text and no
//! keys it could not know.

mod common;

use common::{call_tool, envelope_of, exiting, initialize, result_of};

use cratefield_mcp::server::Server;
use serde_json::json;

const CLEAN: &str = r#"{"schema":1,"ok":true,"failures":[]}"#;

#[test]
fn the_structured_protocols_carry_structured_content_and_output_schema() {
    for version in ["2025-06-18", "2025-11-25"] {
        let (runner, _) = exiting(0, CLEAN, "");
        let mut server = Server::new(runner);
        initialize(&mut server, version);

        let listed = result_of(
            &mut server,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        );
        for tool in listed["tools"].as_array().expect("the tools array") {
            let schema = &tool["outputSchema"];
            assert_eq!(schema["type"], "object", "{}", tool["name"]);
            assert_eq!(
                schema["required"],
                json!(["schema", "ok", "failures"]),
                "{} pins the envelope's first three keys",
                tool["name"]
            );
        }

        let result = call_tool(&mut server, "fz_plan", "{}");
        assert_eq!(
            result["structuredContent"],
            envelope_of(&result),
            "the structured content is the same envelope the text carries"
        );
    }
}

#[test]
fn a_structured_protocol_also_gates_a_failure_envelope() {
    let (runner, _) = exiting(
        1,
        r#"{"schema":1,"ok":false,"failures":[{"code":"not-deployed","message":"run fz deploy"}]}"#,
        "",
    );
    let mut server = Server::new(runner);
    initialize(&mut server, "2025-06-18");
    let result = call_tool(&mut server, "fz_verify", "{}");
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(result["structuredContent"], envelope);
    assert_eq!(envelope["failures"][0]["code"], "not-deployed");
}

#[test]
fn the_older_protocols_carry_neither_key() {
    for version in ["2025-03-26", "2024-11-05"] {
        let (runner, _) = exiting(0, CLEAN, "");
        let mut server = Server::new(runner);
        initialize(&mut server, version);

        let listed = result_of(
            &mut server,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        );
        for tool in listed["tools"].as_array().expect("the tools array") {
            assert!(
                tool.get("outputSchema").is_none(),
                "{}: no outputSchema at {version}",
                tool["name"]
            );
        }

        let result = call_tool(&mut server, "fz_plan", "{}");
        assert!(
            result.get("structuredContent").is_none(),
            "no structuredContent at {version}"
        );
        assert_eq!(
            result["content"][0]["type"], "text",
            "the envelope is the text"
        );
        assert_eq!(result["isError"], false);
    }
}

#[test]
fn before_any_handshake_nothing_structured_is_offered() {
    let (runner, _) = exiting(0, CLEAN, "");
    let mut server = Server::new(runner);
    let listed = result_of(
        &mut server,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    );
    for tool in listed["tools"].as_array().expect("the tools array") {
        assert!(tool.get("outputSchema").is_none());
    }
    let result = call_tool(&mut server, "fz_plan", "{}");
    assert!(result.get("structuredContent").is_none());
}
