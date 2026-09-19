//! The stdio loop itself: `serve` is the half a real client talks to,
//! and the framing it owns lives nowhere else. Each reply is written
//! followed by exactly one `\n`; requests are answered in order; a
//! notification draws nothing and the loop carries on; EOF is a clean
//! shutdown. A forgotten newline or an answered notification corrupts
//! every real client while every `Server::handle` test still passes,
//! which is why these are pinned at the byte level, over a `Cursor` and
//! a `Vec<u8>`, rather than through `handle`.

mod common;

use std::io::Cursor;

use common::{initialize_line, printing};

use cratefield_mcp::server::{self, Server};
use serde_json::{Value, json};

/// The clean envelope the stubbed `fz` prints; what the tools answer is
/// not the subject here, only that the loop delivers it.
const CLEAN: &str = r#"{"schema":1,"ok":true,"failures":[]}"#;

/// Serves `input` to EOF over an in-memory transport and returns every
/// byte the loop wrote.
fn served(input: &str) -> Vec<u8> {
    let (runner, _) = printing(CLEAN);
    let mut server = Server::new(runner);
    let mut input = Cursor::new(input.as_bytes());
    let mut output = Vec::new();
    server::serve(&mut server, &mut input, &mut output)
        .expect("an in-memory transport cannot fail");
    output
}

/// The reply lines `output` carries, parsed. The parse is part of the
/// assertion: a reply with an embedded newline, or two replies run
/// together, fails here as not-one-object-per-line.
fn reply_lines(output: &[u8]) -> Vec<Value> {
    String::from_utf8(output.to_vec())
        .expect("the transport is UTF-8")
        .lines()
        .map(|line| {
            serde_json::from_str(line).expect("each reply is one JSON object on its own line")
        })
        .collect()
}

#[test]
fn every_reply_is_terminated_by_exactly_one_newline() {
    let output = served(&initialize_line("2025-11-25"));
    let printed = String::from_utf8_lossy(&output);
    assert!(
        output.ends_with(b"\n"),
        "the reply ends with a newline: {printed}"
    );
    assert_eq!(
        printed.matches('\n').count(),
        1,
        "one reply, one newline — no more, no fewer: {printed}"
    );
}

#[test]
fn two_requests_are_answered_with_two_reply_lines_in_order() {
    let input = format!(
        "{}\n{}\n",
        initialize_line("2025-11-25"),
        r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#
    );
    let replies = reply_lines(&served(&input));
    assert_eq!(replies.len(), 2, "one reply per request");
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(
        replies[0]["result"]["protocolVersion"], "2025-11-25",
        "the first reply is the handshake's"
    );
    assert_eq!(replies[1]["id"], 2);
    assert_eq!(
        replies[1]["result"],
        json!({}),
        "the second reply is the ping's"
    );
}

#[test]
fn a_notification_draws_no_reply_line_and_the_loop_continues() {
    let input = format!(
        "{}\n{}\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#
    );
    let output = served(&input);
    let replies = reply_lines(&output);
    assert_eq!(
        replies.len(),
        1,
        "the notification is answered with nothing; only the ping replies: {}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(replies[0]["id"], 3, "the one reply is the ping's");
}

#[test]
fn eof_is_a_clean_shutdown_that_writes_nothing_more() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let mut input = Cursor::new(b"" as &[u8]);
    let mut output = Vec::new();
    let outcome = server::serve(&mut server, &mut input, &mut output);
    assert!(
        outcome.is_ok(),
        "stdin ending is a clean shutdown, not an error: {outcome:?}"
    );
    assert!(
        output.is_empty(),
        "EOF writes nothing: {:?}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(calls.count(), 0);
}
