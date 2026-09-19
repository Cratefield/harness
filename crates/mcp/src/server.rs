//! The JSON-RPC 2.0 layer: dispatch one line, write at most one line.
//!
//! The transport is newline-delimited JSON on stdin/stdout — no
//! Content-Length framing — and what keeps it honest is that everything
//! written to stdout is serialised with `serde_json::to_string`, never
//! the pretty printer: a message is one line by construction, and an
//! embedded newline would desynchronise every client at once.
//! Diagnostics belong on stderr.
//!
//! The protocol layer is deliberately boring. A tool that ran and
//! reported a failure is a *tool execution error* — `isError: true` on a
//! normal result — because the envelope, not the transport, is the
//! contract. JSON-RPC errors are for requests that could not be
//! understood at all: unparsable lines ([`PARSE_ERROR`]), shapes the
//! protocol forbids such as the batched arrays 2025-06-18 removed
//! ([`INVALID_REQUEST`]), unknown methods ([`METHOD_NOT_FOUND`]), and
//! params that are missing or not objects — including a `tools/call`
//! naming no tool this server has ([`INVALID_PARAMS`]).

use serde::Serialize;
use serde_json::{Value, json};

use crate::fz::{self, FzRunner};
use crate::tools;

/// The protocol version this server prefers and falls back to.
pub const PREFERRED_PROTOCOL_VERSION: &str = "2025-11-25";

/// Every protocol version this server can speak, newest first. The
/// handshake echoes the client's request when it is on this list and
/// falls back to [`PREFERRED_PROTOCOL_VERSION`] otherwise — a successful
/// result either way, because an agent on an older protocol must still
/// be able to read the answer.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 4] =
    ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// The versions with structured tool output (`structuredContent` and
/// `outputSchema`), which did not exist before 2025-06-18. Everything
/// versioned behind this flag degrades gracefully: an older client gets
/// the envelope as text and no schema keys it could not know.
const STRUCTURED_OUTPUT_VERSIONS: [&str; 2] = ["2025-11-25", "2025-06-18"];

/// What `initialize` tells the agent about every tool's answer: the
/// envelope is the whole story, and `fz_error_codes` explains its codes.
const INSTRUCTIONS: &str = "Six of the seven tools run the real `fz` program with --json and return its envelope: one object with `schema`, `ok` and `failures[]`, each failure carrying a stable `code`; the seventh serves the error-code catalogue in-process. `ok: false` arrives as a tool execution error (isError true), not a protocol failure. Call `fz_error_codes` for every code — fz's catalogue plus the four `mcp-` codes this server itself can emit — and what each means.";

/// Unparsable JSON on a line.
pub const PARSE_ERROR: i64 = -32700;
/// A parseable line that is not a valid request — non-objects, and the
/// batched arrays the 2025-06-18 protocol removed.
pub const INVALID_REQUEST: i64 = -32600;
/// A method this server does not serve.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Params that are missing or not objects — including a `tools/call`
/// naming a tool this server does not have.
pub const INVALID_PARAMS: i64 = -32602;

/// One JSON-RPC error object; `data` only when there is something worth
/// adding to the message.
#[derive(Serialize)]
struct RpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// A response: exactly one of `result` and `error`. Serialised field
/// order is `jsonrpc`, `id`, then the outcome, matching the spec's own
/// examples.
#[derive(Serialize)]
struct Response {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

/// The `initialize` result.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InitializeResult {
    protocol_version: String,
    capabilities: Capabilities,
    server_info: ServerInfo,
    instructions: &'static str,
}

#[derive(Serialize)]
struct Capabilities {
    tools: ToolsCapability,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolsCapability {
    list_changed: bool,
}

#[derive(Serialize)]
struct ServerInfo {
    name: &'static str,
    title: &'static str,
    version: &'static str,
}

/// The MCP server state: the runner it delegates to, and the protocol
/// version the handshake settled on.
pub struct Server<R: FzRunner> {
    runner: R,
    negotiated: Option<String>,
}

impl<R: FzRunner> Server<R> {
    /// A server that has not yet been initialised: tools answer, but
    /// without `structuredContent`/`outputSchema` until a handshake
    /// negotiates a protocol new enough to have them.
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            negotiated: None,
        }
    }

    /// The protocol version the handshake settled on, if one happened.
    #[must_use]
    pub fn negotiated_version(&self) -> Option<&str> {
        self.negotiated.as_deref()
    }

    /// Whether tool results carry `structuredContent` (protocol
    /// 2025-06-18 and later). Before a handshake this is false: the
    /// oldest client that might still talk to us is the one to degrade
    /// for.
    #[must_use]
    pub fn structured(&self) -> bool {
        self.negotiated
            .as_deref()
            .is_some_and(|version| STRUCTURED_OUTPUT_VERSIONS.contains(&version))
    }

    /// Handles one line of the transport and returns the reply line,
    /// without its trailing newline — or `None` for a notification,
    /// which is answered with nothing at all. Pure with respect to the
    /// transport: the only state it touches is the negotiated version,
    /// so a test can drive the whole protocol as strings.
    pub fn handle(&mut self, line: &str) -> Option<String> {
        let message: Value = match serde_json::from_str(line) {
            Ok(message) => message,
            Err(_) => {
                // A line that cannot be parsed cannot name an id, so the
                // reply's id is null even when the client sent one.
                return Some(render(&Response {
                    jsonrpc: "2.0",
                    id: Value::Null,
                    result: None,
                    error: Some(rpc_error(PARSE_ERROR, "Parse error", None)),
                }));
            }
        };
        // Batching was removed in protocol 2025-06-18 and never comes
        // back: one line, one message. A top-level array — or any other
        // non-object — is an invalid request, with a null id because no
        // single request could be echoed.
        if !message.is_object() {
            let data = message.is_array().then(|| {
                json!("JSON-RPC batching was removed in protocol 2025-06-18; send one message per line")
            });
            return Some(render(&Response {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(rpc_error(INVALID_REQUEST, "Invalid Request", data)),
            }));
        }
        // A message with no `id` is a notification, answered with
        // nothing at all — no reply, not even an error, because its
        // sender is not waiting for one. This is where
        // `notifications/initialized` and every other notification, known
        // or unknown, disappear silently — the `?` is the whole rule.
        let id = message.get("id")?.clone();
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return Some(render(&Response {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(rpc_error(INVALID_REQUEST, "Invalid Request", None)),
            }));
        };
        let params = message.get("params");
        let result = match method {
            "initialize" => self.initialize(params),
            "ping" => json!({}),
            "tools/list" => self.tools_list(),
            "tools/call" => {
                return Some(match self.tools_call(params) {
                    Ok(result) => ok_response(&id, result),
                    Err(message) => error_response(&id, INVALID_PARAMS, &message, None),
                });
            }
            _ => {
                return Some(error_response(
                    &id,
                    METHOD_NOT_FOUND,
                    "Method not found",
                    None,
                ));
            }
        };
        Some(ok_response(&id, result))
    }

    /// The handshake: echo the client's requested version when this
    /// server speaks it, [`PREFERRED_PROTOCOL_VERSION`] otherwise — a
    /// successful result in every case, because an agent on an older
    /// protocol must still be able to read the answer.
    fn initialize(&mut self, params: Option<&Value>) -> Value {
        let requested = params
            .and_then(|params| params.get("protocolVersion"))
            .and_then(Value::as_str);
        let negotiated = requested
            .filter(|version| SUPPORTED_PROTOCOL_VERSIONS.contains(version))
            .unwrap_or(PREFERRED_PROTOCOL_VERSION)
            .to_owned();
        self.negotiated = Some(negotiated.clone());
        serde_json::to_value(InitializeResult {
            protocol_version: negotiated,
            capabilities: Capabilities {
                tools: ToolsCapability {
                    list_changed: false,
                },
            },
            server_info: ServerInfo {
                name: "cratefield-fz",
                title: "Cratefield fz",
                version: env!("CARGO_PKG_VERSION"),
            },
            instructions: INSTRUCTIONS,
        })
        .expect("the initialize result is plain JSON; serialisation cannot fail")
    }

    fn tools_list(&self) -> Value {
        let definitions = tools::tool_defs();
        let listed: Vec<Value> = definitions
            .iter()
            .map(|definition| definition.to_json(self.structured()))
            .collect();
        // A `cursor` in the request is ignored and no `nextCursor` is
        // emitted: seven tools fit one page, and paging surface nobody
        // needs is surface that can drift.
        json!({ "tools": listed })
    }

    /// A `tools/call`: `Err` is the -32602 the protocol owes the client
    /// (malformed params, or a tool this server does not have); `Ok` is
    /// a normal result wrapping the envelope.
    fn tools_call(&self, params: Option<&Value>) -> Result<Value, String> {
        let params = params
            .and_then(Value::as_object)
            .ok_or_else(|| "`tools/call` needs a params object with a tool `name`".to_owned())?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "`tools/call` needs a string `name`".to_owned())?;
        let arguments = match params.get("arguments") {
            None | Some(Value::Null) => None,
            Some(Value::Object(arguments)) => Some(arguments),
            Some(_) => return Err("`arguments` must be an object".to_owned()),
        };
        if !tools::exists(name) {
            // "Cannot find the tool" is the one tool-call failure that
            // is a protocol error rather than an envelope.
            return Err(format!("Unknown tool: {name}"));
        }
        let envelope = tools::call(&self.runner, name, arguments);
        Ok(self.tool_result(envelope))
    }

    /// Wraps an envelope in the one result shape every tool returns: the
    /// envelope as text content — for a spawn, exactly the line `fz`
    /// printed — the same object as `structuredContent` when the
    /// protocol has it, and `isError` exactly when the envelope's `ok`
    /// is `false`.
    fn tool_result(&self, envelope: fz::Envelope) -> Value {
        let is_error = fz::is_failure(&envelope.value);
        let mut result = json!({
            "content": [{ "type": "text", "text": envelope.text }],
        });
        let fields = result
            .as_object_mut()
            .expect("a freshly built json! object");
        if self.structured() {
            fields.insert("structuredContent".to_owned(), envelope.value);
        }
        fields.insert("isError".to_owned(), Value::Bool(is_error));
        result
    }
}

/// The stdio loop: one line in, at most one line out, until stdin ends.
/// EOF is a clean shutdown — a client that closed the pipe said
/// everything it had to say.
///
/// # Errors
///
/// Returns the I/O error when reading stdin or writing stdout fails;
/// `main` turns that into a non-zero exit. Each reply is flushed before
/// the next line is read, so a client sees every answer immediately.
pub fn serve<R, I, O>(server: &mut Server<R>, input: &mut I, output: &mut O) -> std::io::Result<()>
where
    R: FzRunner,
    I: std::io::BufRead,
    O: std::io::Write,
{
    loop {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let Some(reply) = server.handle(&line) else {
            continue;
        };
        output.write_all(reply.as_bytes())?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
}

fn ok_response(id: &Value, result: Value) -> String {
    render(&Response {
        jsonrpc: "2.0",
        id: id.clone(),
        result: Some(result),
        error: None,
    })
}

fn error_response(id: &Value, code: i64, message: &str, data: Option<Value>) -> String {
    render(&Response {
        jsonrpc: "2.0",
        id: id.clone(),
        result: None,
        error: Some(rpc_error(code, message, data)),
    })
}

fn rpc_error(code: i64, message: &str, data: Option<Value>) -> RpcError {
    RpcError {
        code,
        message: message.to_owned(),
        data,
    }
}

fn render(response: &Response) -> String {
    // `to_string`, never `to_string_pretty`: the transport is one
    // message per line, and an embedded newline would corrupt it. These
    // structs are plain JSON, so serialisation cannot fail.
    serde_json::to_string(response)
        .expect("JSON-RPC responses are plain JSON; serialisation cannot fail")
}
