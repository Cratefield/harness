//! The protocol layer: the handshake, the notification silence, ping,
//! the tool table, and the JSON-RPC errors the transport owes a client —
//! parse error, invalid request, method not found, invalid params —
//! each under the id it must be answered with.

mod common;

use common::{call_line, initialize, initialize_line, printing, reply, result_of};

use cratefield_mcp::server::{PREFERRED_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, Server};
use serde_json::{Value, json};

const CLEAN: &str = r#"{"schema":1,"ok":true,"failures":[]}"#;

#[test]
fn initialize_echoes_each_supported_protocol_version() {
    for version in SUPPORTED_PROTOCOL_VERSIONS {
        let (runner, _) = printing(CLEAN);
        let mut server = Server::new(runner);
        let result = initialize(&mut server, version);
        assert_eq!(result["protocolVersion"], version);
        assert_eq!(server.negotiated_version(), Some(version));
    }
}

#[test]
fn initialize_falls_back_to_the_preferred_version_for_an_unknown_ask() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = result_of(&mut server, &initialize_line("1999-01-01"));
    assert_eq!(result["protocolVersion"], PREFERRED_PROTOCOL_VERSION);
    assert_eq!(
        server.negotiated_version(),
        Some(PREFERRED_PROTOCOL_VERSION)
    );
}

#[test]
fn initialize_without_a_version_still_succeeds_at_the_preferred_one() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = result_of(
        &mut server,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
    );
    assert_eq!(result["protocolVersion"], PREFERRED_PROTOCOL_VERSION);
}

#[test]
fn notifications_are_answered_with_nothing_at_all() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    assert_eq!(
        server.handle(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
        None
    );
    assert_eq!(
        server.handle(
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#
        ),
        None
    );
    assert_eq!(
        server.handle(r#"{"jsonrpc":"2.0","method":"totally/unknown/notification"}"#),
        None,
        "an unknown notification is still a notification: its sender is not waiting"
    );
    assert_eq!(calls.count(), 0);
}

#[test]
fn ping_answers_an_empty_object() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = result_of(&mut server, r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#);
    assert_eq!(result, json!({}));
}

#[test]
fn tools_list_lists_all_seven_tools_with_object_schemas_and_all_four_hints() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = result_of(
        &mut server,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
    );
    let tools = result["tools"].as_array().expect("the tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("every tool names itself"))
        .collect();
    assert_eq!(
        names,
        [
            "fz_doctor",
            "fz_plan",
            "fz_verify",
            "fz_init",
            "fz_add",
            "fz_deploy",
            "fz_error_codes",
        ]
    );
    for tool in tools {
        assert!(
            !tool["description"]
                .as_str()
                .expect("a description")
                .is_empty(),
            "{} describes itself",
            tool["name"]
        );
        assert_eq!(tool["inputSchema"]["type"], "object", "{}", tool["name"]);
        assert_eq!(
            tool["inputSchema"]["additionalProperties"], false,
            "{}: the wrapper owns this surface",
            tool["name"]
        );
        let annotations = tool["annotations"]
            .as_object()
            .expect("an annotations object");
        assert_eq!(
            annotations.len(),
            4,
            "all four hints stated, none left to the spec's defaults: {annotations:?}"
        );
        for key in [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ] {
            assert!(
                annotations.contains_key(key),
                "{} misses {key}",
                tool["name"]
            );
            assert!(
                tool["annotations"][key].is_boolean(),
                "{} {key} is a boolean",
                tool["name"]
            );
        }
    }
}

#[test]
fn every_tools_annotations_say_what_the_verb_does() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = result_of(
        &mut server,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
    );
    let tools = result["tools"].as_array().expect("the tools array");
    // (name, read_only, destructive, idempotent, open_world).
    let expected: [(&str, [bool; 4]); 7] = [
        ("fz_doctor", [true, false, true, false]),
        ("fz_plan", [true, false, true, false]),
        ("fz_verify", [true, false, true, false]),
        ("fz_init", [false, false, false, false]),
        ("fz_add", [false, false, true, false]),
        ("fz_deploy", [false, true, false, true]),
        ("fz_error_codes", [true, false, true, false]),
    ];
    for (name, hints) in expected {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("{name} is listed"));
        let annotations = &tool["annotations"];
        assert_eq!(
            annotations["readOnlyHint"], hints[0],
            "{name} read_only_hint"
        );
        assert_eq!(
            annotations["destructiveHint"], hints[1],
            "{name} destructive_hint"
        );
        assert_eq!(
            annotations["idempotentHint"], hints[2],
            "{name} idempotent_hint"
        );
        assert_eq!(
            annotations["openWorldHint"], hints[3],
            "{name} open_world_hint"
        );
    }
}

#[test]
fn an_unknown_method_is_method_not_found() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let response = reply(
        &mut server,
        r#"{"jsonrpc":"2.0","id":9,"method":"fz/list"}"#,
    );
    assert_eq!(response["error"]["code"], -32601);
    assert!(response.get("result").is_none());
}

#[test]
fn an_unknown_tool_is_invalid_params_not_a_tool_error() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let response = reply(&mut server, &call_line("fz_manifest", "{}"));
    assert_eq!(response["error"]["code"], -32602);
    let message = response["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains("fz_manifest"),
        "the tool is named: {message}"
    );
}

#[test]
fn an_unparsable_line_is_a_parse_error_with_a_null_id() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let response = reply(&mut server, "this line is not json");
    assert_eq!(response["error"]["code"], -32700);
    assert_eq!(response["id"], Value::Null);
}

#[test]
fn a_batched_array_is_an_invalid_request_with_a_null_id() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let response = reply(&mut server, r#"[{"jsonrpc":"2.0","id":5,"method":"ping"}]"#);
    assert_eq!(response["error"]["code"], -32600);
    assert_eq!(response["id"], Value::Null);
    let data = response["error"]["data"].as_str().expect("the reason");
    assert!(data.contains("batching"), "the client is told why: {data}");
}

#[test]
fn a_scalar_request_is_an_invalid_request() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let response = reply(&mut server, "42");
    assert_eq!(response["error"]["code"], -32600);
    assert_eq!(response["id"], Value::Null);
}

#[test]
fn a_tool_call_without_a_params_object_is_invalid_params() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let response = reply(
        &mut server,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call"}"#,
    );
    assert_eq!(response["error"]["code"], -32602);
}

#[test]
fn tool_arguments_that_are_not_an_object_are_invalid_params() {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let response = reply(
        &mut server,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fz_doctor","arguments":5}}"#,
    );
    assert_eq!(response["error"]["code"], -32602);
}

/// The JSON-RPC `id` is echoed, not normalised: an agent correlating a
/// reply with its request must get back the id it chose, as the same
/// JSON type. Every other id in the suite is numeric, so a regression to
/// a coerced or nulled id would otherwise pass the whole file unnoticed.
#[test]
fn a_string_id_round_trips_as_a_string() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let response = reply(
        &mut server,
        r#"{"jsonrpc":"2.0","id":"abc-1","method":"tools/call","params":{"name":"fz_doctor","arguments":{}}}"#,
    );
    assert!(
        response["id"].is_string(),
        "the id keeps its JSON type: {response}"
    );
    assert_eq!(
        response["id"],
        json!("abc-1"),
        "the same string, byte for byte"
    );
    assert!(
        response.get("error").is_none(),
        "the call itself succeeds: {response}"
    );
    assert_eq!(calls.count(), 1, "the tool ran");
}

/// `arguments` absent from the params object is the same call as an
/// empty one: the params name a real tool whose arguments are all
/// optional, so it runs on its defaults — never a -32602, never a panic.
/// `a_tool_call_without_a_params_object_is_invalid_params` covers the
/// different case of `params` missing entirely; this is the key, not the
/// object, being absent.
#[test]
fn a_tool_call_with_no_arguments_key_counts_as_empty_arguments() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let response = reply(
        &mut server,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fz_doctor"}}"#,
    );
    assert!(
        response.get("error").is_none(),
        "absent `arguments` is not invalid params: {response}"
    );
    let result = response
        .get("result")
        .expect("a tool call answers with a result");
    assert_eq!(result["isError"], false);
    let envelope: Value = serde_json::from_str(
        result["content"][0]["text"]
            .as_str()
            .expect("the envelope as text"),
    )
    .expect("the text content is the envelope JSON");
    assert_eq!(envelope["ok"], true);
    assert_eq!(
        calls.single(),
        ["doctor", "--json"],
        "the tool ran on its defaults, as an empty `arguments` would"
    );
}
