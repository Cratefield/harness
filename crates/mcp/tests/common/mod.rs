//! What more than one `fz-mcp` test needs, in one place: a fake
//! [`FzRunner`] that records the argv it was handed and answers with a
//! canned [`FzOutput`], and the helpers that drive the protocol as
//! strings through `Server::handle` and dig the envelope back out of a
//! reply.
//!
//! `tests/` is one binary per file, so this module compiles into every
//! test that includes it and a helper only some of them use reads as
//! dead in the rest. The two allows below are about how `tests/` is
//! built, not about anything here being unused or wrongly visible.
#![allow(dead_code)]
#![allow(unreachable_pub)]

use std::cell::RefCell;
use std::rc::Rc;

use serde_json::Value;

use cratefield_mcp::fz::{FzFailure, FzOutput, FzRunner};
use cratefield_mcp::server::Server;

/// The argv a [`FakeRunner`] recorded. Handed out beside the runner so
/// the test can read the calls while the [`Server`] owns the runner.
#[derive(Clone)]
pub struct Calls {
    recorded: Rc<RefCell<Vec<Vec<String>>>>,
}

impl Calls {
    /// The argv of the one `fz` run; panics when the tool ran `fz` any
    /// other number of times than once.
    pub fn single(&self) -> Vec<String> {
        let recorded = self.recorded.borrow();
        assert_eq!(
            recorded.len(),
            1,
            "expected exactly one fz run, saw {}",
            recorded.len()
        );
        recorded[0].clone()
    }

    /// Every argv, in call order.
    pub fn all(&self) -> Vec<Vec<String>> {
        self.recorded.borrow().clone()
    }

    /// How many times `fz` was run — zero for the refusals and the
    /// catalogue, which spawn nothing.
    pub fn count(&self) -> usize {
        self.recorded.borrow().len()
    }
}

/// A fake `fz`: records each argv and answers with one canned outcome.
pub struct FakeRunner {
    calls: Calls,
    outcome: Result<FzOutput, FzFailure>,
}

impl FzRunner for FakeRunner {
    fn run(&self, args: &[String]) -> Result<FzOutput, FzFailure> {
        self.calls.recorded.borrow_mut().push(args.to_vec());
        self.outcome.clone()
    }
}

/// A runner whose child exits 0 printing `stdout` — the clean run.
pub fn printing(stdout: &str) -> (FakeRunner, Calls) {
    exiting(0, stdout, "")
}

/// A runner whose child exits `status` printing `stdout` and `stderr`.
pub fn exiting(status: i32, stdout: &str, stderr: &str) -> (FakeRunner, Calls) {
    with_outcome(Ok(FzOutput {
        status: Some(status),
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
    }))
}

/// A runner whose child cannot be spawned at all; `reason` is what the
/// trait's `Err` carries.
pub fn unspawnable(reason: &str) -> (FakeRunner, Calls) {
    with_outcome(Err(FzFailure::Unavailable(reason.to_owned())))
}

/// One fake with its recording handle.
fn with_outcome(outcome: Result<FzOutput, FzFailure>) -> (FakeRunner, Calls) {
    let calls = Calls {
        recorded: Rc::new(RefCell::new(Vec::new())),
    };
    (
        FakeRunner {
            calls: calls.clone(),
            outcome,
        },
        calls,
    )
}

/// Handles one request line and parses the reply object; panics when
/// the message was a notification and drew no reply.
pub fn reply<R: FzRunner>(server: &mut Server<R>, line: &str) -> Value {
    let reply = server
        .handle(line)
        .unwrap_or_else(|| panic!("expected a reply to {line}"));
    serde_json::from_str(&reply).expect("a reply is one JSON object")
}

/// Handles one request and returns its `result`, asserting the reply
/// was a success — for the tests whose subject is not the error path.
pub fn result_of<R: FzRunner>(server: &mut Server<R>, line: &str) -> Value {
    let reply = reply(server, line);
    assert!(
        reply.get("error").is_none(),
        "expected a result, got a protocol error: {reply}"
    );
    reply
        .get("result")
        .cloned()
        .expect("a successful reply carries a result")
}

/// The `initialize` request line naming `version`.
pub fn initialize_line(version: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{version}","capabilities":{{}},"clientInfo":{{"name":"fz-mcp-test","version":"0"}}}}}}"#
    )
}

/// The `tools/call` request line for `tool` with `arguments`, a JSON
/// object literal (`"{}"` when the call has none).
pub fn call_line(tool: &str, arguments: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments}}}}}"#
    )
}

/// Handshakes at `version` and returns the initialize result — which
/// the helper asserts echoes `version`, so only for supported versions.
pub fn initialize<R: FzRunner>(server: &mut Server<R>, version: &str) -> Value {
    let result = result_of(server, &initialize_line(version));
    assert_eq!(
        result["protocolVersion"].as_str(),
        Some(version),
        "the handshake echoes the requested version"
    );
    result
}

/// Calls `tool` with `arguments` and returns the result object. A tool
/// that refused or failed answers here too — as a result carrying
/// `isError`, never as a protocol error, which this pins.
pub fn call_tool<R: FzRunner>(server: &mut Server<R>, tool: &str, arguments: &str) -> Value {
    let reply = reply(server, &call_line(tool, arguments));
    assert_eq!(reply["id"], 7, "the reply echoes the request id");
    assert!(
        reply.get("error").is_none(),
        "a tool call is answered with a result even when the tool failed: {reply}"
    );
    reply
        .get("result")
        .cloned()
        .expect("a tool call answers with a result")
}

/// The envelope as the agent reads it: `content[0].text`, verbatim.
pub fn text_of(result: &Value) -> &str {
    result["content"][0]["text"]
        .as_str()
        .expect("every result carries one text content")
}

/// The envelope parsed — the object the text is the pass-through of.
pub fn envelope_of(result: &Value) -> Value {
    serde_json::from_str(text_of(result)).expect("the text content is the envelope JSON")
}

/// The stable code of the one failure the envelope carries.
pub fn failure_code(envelope: &Value) -> &str {
    envelope["failures"][0]["code"]
        .as_str()
        .expect("one failure carrying a stable code")
}
