//! `fz-mcp` — a Model Context Protocol server over `fz --json` (issue
//! #160): a thin wrapper that puts the venture CLI in front of an agent
//! without giving it a second surface that can drift.
//!
//! The contract is the CLI's own, not this crate's. Six of the seven
//! tools spawn the real `fz` program and return the one JSON object
//! `fz --json` printed — `schema`, `ok`, `failures[]` with their stable
//! codes, plus whatever the verb adds — as both the result's text
//! content and, on protocols new enough to have it, its structured
//! content. `fz` must be a child process; it cannot be a library call
//! here, because in a venture it is a `[[bin]]` linked against that
//! venture's compiled-in harness, which this process does not have.
//!
//! The error-code catalogue is likewise read, never copied:
//! [`cratefield_cli::codes::registry`] runs in this server's own
//! process, never asked of the spawned `fz`, and this
//! server adds exactly four codes of its own, all prefixed `mcp-` so a
//! collision with the CLI's append-only catalogue is structurally
//! impossible — see [`crate::codes`]. When the CLI grows a verb or a
//! code, this server follows with no change here.
//!
//! A child is also not allowed to hold the session hostage: the serve
//! loop answers one call at a time, so a child that never exits would
//! stop even `ping` from being answered. A child that outlives
//! `FZ_MCP_TIMEOUT_SECS` seconds (default 600, generous because
//! `fz deploy` legitimately takes minutes; `0` disables) is killed, and
//! its call comes back as an `mcp-fz-timeout` envelope.
//!
//! Transport: newline-delimited JSON-RPC 2.0 over stdin/stdout, one
//! message per line, no Content-Length framing; nothing but MCP
//! messages is ever written to stdout, and diagnostics stay on stderr.
//! Point it at a venture with
//! `fz-mcp --cwd ./my-venture -- cargo run -q --bin fz --`; the default
//! command is plain `fz`.
//!
//! Two seams keep the crate testable without touching a process:
//! [`crate::server::Server::handle`] is the whole protocol as a pure
//! function of one line, and [`crate::fz::FzRunner`] is the process
//! boundary the tools run through.

#![forbid(unsafe_code)]

pub mod codes;
pub mod fz;
pub mod server;
pub mod tools;

pub use crate::fz::{Envelope, FzConfig, FzFailure, FzOutput, FzRunner, ProcessRunner};
pub use crate::server::Server;
