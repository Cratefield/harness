//! Newline discipline: the transport is one message per line, so no
//! string `Server::handle` returns may carry an embedded `\n` — a
//! serialiser that reached for the pretty printer, or a payload copied
//! in raw, would desynchronise every client at once. The cases include
//! multi-line `fz` output on purpose: those are the ones that catch the
//! regression.

mod common;

use common::{call_line, exiting, initialize_line};

use cratefield_mcp::server::Server;

/// Asserts `reply` is one line, naming `what` it was if not.
fn assert_one_line(reply: Option<String>, what: &str) {
    let reply = reply.unwrap_or_else(|| panic!("{what} must be answered"));
    assert!(
        !reply.contains('\n'),
        "{what} replied with an embedded newline: {reply:?}"
    );
}

#[test]
fn every_kind_of_reply_is_one_line() {
    let multi_line_stdout = "trace: opening venture.json\ntrace: no deploy record\n";
    let multi_line_usage = "error: unexpected argument '-x' found\n\nUsage: fz verify [OPTIONS]\n";

    // The happy paths and the protocol paths.
    let (runner, _) = exiting(0, r#"{"schema":1,"ok":true,"failures":[]}"#, "");
    let mut server = Server::new(runner);
    assert_one_line(server.handle(&initialize_line("2025-06-18")), "initialize");
    assert_one_line(
        server.handle(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#),
        "ping",
    );
    assert_one_line(
        server.handle(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#),
        "tools/list",
    );
    assert_one_line(
        server.handle(&call_line("fz_plan", "{}")),
        "an ok tool call",
    );
    assert_one_line(
        server.handle(r#"{"jsonrpc":"2.0","id":4,"method":"no/such/method"}"#),
        "an unknown method",
    );
    assert_one_line(server.handle("this line is not json"), "a parse error");
    assert_one_line(
        server.handle(r#"[{"jsonrpc":"2.0","id":5,"method":"ping"}]"#),
        "a batched array",
    );
    assert_one_line(
        server.handle(&call_line("fz_nope", "{}")),
        "an unknown tool",
    );

    // A tool failure and the wrapper's argument refusal.
    let (runner, _) = exiting(
        1,
        r#"{"schema":1,"ok":false,"failures":[{"code":"stale-plan","message":"modules: added cms"}]}"#,
        "",
    );
    let mut server = Server::new(runner);
    assert_one_line(
        server.handle(&call_line("fz_deploy", "{}")),
        "a failed tool call",
    );
    assert_one_line(
        server.handle(&call_line("fz_add", r#"{"module":"-h"}"#)),
        "an argument refusal",
    );

    // fz dumped multi-line prose on both streams; every line of it may
    // reach the agent only escaped, inside one reply line.
    let (runner, _) = exiting(2, multi_line_stdout, multi_line_usage);
    let mut server = Server::new(runner);
    assert_one_line(
        server.handle(&call_line("fz_verify", "{}")),
        "a no-json tool call",
    );
}

#[test]
fn a_multi_line_stderr_really_flows_into_the_one_line_reply() {
    let (runner, _) = exiting(
        2,
        "no json on stdout\neither\n",
        "first stderr line\nsecond stderr line\n",
    );
    let mut server = Server::new(runner);
    let reply = server
        .handle(&call_line("fz_verify", "{}"))
        .expect("a tool call is answered");
    assert!(!reply.contains('\n'), "the reply is one line: {reply:?}");

    let parsed: serde_json::Value = serde_json::from_str(&reply).expect("a reply is JSON");
    let text = parsed["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert!(
        !text.contains('\n'),
        "the envelope text is one line of JSON"
    );

    let envelope: serde_json::Value = serde_json::from_str(text).expect("the text is the envelope");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("a message");
    // The guard above is only honest if the payload it carried really
    // had newlines in it: decoded back out of the envelope, the stderr
    // excerpt must still be multi-line, while the line it travelled on
    // — reply and envelope text alike — is not.
    assert!(
        message.contains("first stderr line") && message.contains('\n'),
        "the payload must be multi-line for this test to bite: {message:?}"
    );
}
