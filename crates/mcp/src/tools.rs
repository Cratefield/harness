//! The tool table: the seven tools, the `fz` argv each one builds, and
//! the validation that runs before any process is spawned.
//!
//! The table is data, not code paths: each [`ToolDef`] carries its own
//! argv builder, so "which tools exist" and "what a call runs" cannot
//! drift apart. The definitions also state all four annotations
//! explicitly, because the MCP spec defaults the surprising ones —
//! `destructiveHint` and `openWorldHint` both default to *true* — and
//! silence would advertise a read-only tool as a hazard.
//!
//! Validation refuses, with `mcp-argument-invalid`, anything that would
//! not survive the trip to clap: a value starting with `-` would be
//! re-read as a flag (`module: "-h"` would turn `fz add` into a usage
//! error that prints no JSON at all — exactly the non-JSON stdout
//! [`crate::codes::FZ_NO_JSON`] exists for), an unknown property would
//! otherwise be silently ignored while the agent believes its argument
//! mattered, and a missing or empty required value would produce clap's
//! prose instead of an envelope. Refusing at this boundary keeps the
//! envelope the only thing an agent ever has to parse.

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::codes;
use crate::fz::{self, FzRunner, SCHEMA, failure_envelope};

/// The one tool that runs no `fz` process: it serves the error-code
/// catalogue straight from the CLI's registry.
pub const ERROR_CODES_TOOL: &str = "fz_error_codes";

/// Shared `manifest` argument description: same flag, same default on
/// every workflow verb, so it is written once.
const MANIFEST_DOC: &str = "Path of the venture manifest (`.json` or `.toml`; the CLI's `--manifest`, default `venture.json`).";

/// Shared `migrations` argument description.
const MIGRATIONS_DOC: &str = "Migration directory holding `.harness-lock.json` (the CLI's `--migrations`, default `migrations`).";

/// The four MCP tool annotations, stated on every tool: the spec
/// defaults the surprising ones (`destructiveHint` true,
/// `openWorldHint` true), so silence would mislabel a tool. The field
/// names are the spec's — `readOnlyHint`, `destructiveHint`,
/// `idempotentHint`, `openWorldHint` — because clients look for exactly
/// those keys. The four booleans are the spec's own shape; nothing here
/// could be an enum without lying about it.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the four MCP annotation hints are, by specification, four independent booleans"
)]
pub struct ToolAnnotations {
    /// Does the tool only read? The spec's `readOnlyHint`.
    pub read_only_hint: bool,
    /// Can the tool destroy data? The spec's `destructiveHint`; only
    /// `fz_deploy` may, by removing modules — their data leaves the
    /// venture.
    pub destructive_hint: bool,
    /// Is calling it twice the same as calling it once? The spec's
    /// `idempotentHint`.
    pub idempotent_hint: bool,
    /// Does the tool reach beyond its arguments and the venture's
    /// directory on disk? The spec's `openWorldHint`; only `fz_deploy`
    /// says yes: it is the step that leads to standing up a Worker in
    /// the world.
    pub open_world_hint: bool,
}

/// Builds the `fz` argv for one call, or the reason the arguments are
/// refused. A pure function: validation happens here, spawning happens
/// later.
pub type ArgvBuilder = fn(&Map<String, Value>) -> Result<Vec<String>, String>;

/// One tool as `tools/list` presents it: name and prose, the input
/// schema, the argv builder, and the annotations. The output schema is
/// shared by every tool (see [`output_schema`]) and only exists on
/// protocol 2025-06-18 and later, so it is attached at serialisation
/// time.
#[derive(Debug, Clone)]
pub struct ToolDef {
    /// The MCP tool name; `fz_`-prefixed and `[A-Za-z0-9._-]`-safe.
    pub name: &'static str,
    /// Human-readable title.
    pub title: &'static str,
    /// What the tool runs and what comes back.
    pub description: &'static str,
    /// The JSON Schema for a call's `arguments`.
    pub input_schema: Value,
    /// The four hints, all explicit.
    pub annotations: ToolAnnotations,
    /// Builds the `fz` argv for a call, or the refusal message; see
    /// [`ArgvBuilder`].
    pub build: ArgvBuilder,
}

impl ToolDef {
    /// Assembles one definition; the property/description pairs become
    /// the input schema in the order given, and `required` is omitted
    /// when empty.
    fn new(
        name: &'static str,
        title: &'static str,
        description: &'static str,
        properties: Vec<(&'static str, Value)>,
        required: &[&str],
        annotations: ToolAnnotations,
        build: ArgvBuilder,
    ) -> Self {
        Self {
            name,
            title,
            description,
            input_schema: input_schema(properties, required),
            annotations,
            build,
        }
    }

    /// The tool as it appears in `tools/list`. `structured` gates
    /// `outputSchema`, which did not exist before protocol 2025-06-18.
    ///
    /// # Panics
    ///
    /// Only if the freshly built `json!` object were not an object, or
    /// [`ToolAnnotations`] were not plain JSON; neither can happen, and
    /// both would be this file's own bug rather than a caller's.
    #[must_use]
    pub fn to_json(&self, structured: bool) -> Value {
        let mut tool = json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
        });
        let fields = tool.as_object_mut().expect("a freshly built json! object");
        if structured {
            fields.insert("outputSchema".to_owned(), output_schema());
        }
        fields.insert(
            "annotations".to_owned(),
            serde_json::to_value(self.annotations)
                .expect("ToolAnnotations is plain JSON; serialisation cannot fail"),
        );
        tool
    }
}

/// The seven tools, in `tools/list` order. Built per call: `tools/list`
/// is rare, and the crate keeps no cacheable statics.
#[must_use]
pub fn tool_defs() -> Vec<ToolDef> {
    vec![
        doctor(),
        plan(),
        verify(),
        init(),
        add(),
        deploy(),
        error_codes(),
    ]
}

/// Whether `name` names a tool this server serves — the check that
/// separates "protocol error" (-32602, no such tool) from "tool ran and
/// refused" (an envelope), so it must consult the same table
/// `tools/call` dispatches through.
#[must_use]
pub fn exists(name: &str) -> bool {
    tool_defs().iter().any(|definition| definition.name == name)
}

/// Executes a `tools/call` and returns the envelope the result carries:
/// either the catalogue (no process) or one run of the configured `fz`.
/// Argument failures, an unspawnable `fz` and a child that outlived its
/// limit are envelopes too — a tool execution error surfaces as
/// `isError` on a normal result, never as a JSON-RPC error, which is
/// reserved for "there is no such tool".
pub fn call<R: FzRunner>(
    runner: &R,
    tool: &str,
    arguments: Option<&Map<String, Value>>,
) -> fz::Envelope {
    let Some(definition) = tool_defs().into_iter().find(|def| def.name == tool) else {
        // `server` rejects unknown tools as -32602 before calling here;
        // this arm exists so the invariant cannot be silently broken.
        return failure_envelope(&codes::ARGUMENT_INVALID, format!("unknown tool: {tool}"));
    };
    let empty = Map::new();
    let arguments = arguments.unwrap_or(&empty);
    // Validation runs for every tool, the catalogue included: its schema
    // says `additionalProperties: false` like the others, so an unknown
    // property is refused the same way rather than waved through with
    // `ok: true`.
    let argv = match (definition.build)(arguments) {
        Ok(argv) => argv,
        Err(message) => return failure_envelope(&codes::ARGUMENT_INVALID, message),
    };
    if definition.name == ERROR_CODES_TOOL {
        return codes::error_codes_envelope();
    }
    match runner.run(&argv) {
        Ok(output) => fz::envelope_from_output(&output),
        Err(failure) => failure_envelope(failure.code(), failure.message()),
    }
}

/// The one output schema every tool shares: the envelope's first three
/// keys and nothing pinned beyond them. Deliberately **no**
/// `additionalProperties: false` — the `fz --json` envelope is
/// documented as grow-only (verbs add `digest`, `record`, `changed`,
/// and more), and a closed schema would make every such addition look
/// like a tool regression the moment the CLI exercises its own contract.
#[must_use]
pub fn output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "schema": {
                "type": "integer",
                "description": format!(
                    "The envelope schema version — the CLI's own ({SCHEMA}), moved only by the CLI."
                ),
            },
            "ok": {
                "type": "boolean",
                "description": "Whether the fz command succeeded.",
            },
            "failures": {
                "type": "array",
                "description": "Empty when ok; each failure carries a stable code (see fz_error_codes).",
                "items": {
                    "type": "object",
                    "properties": {
                        "code": { "type": "string" },
                        "message": { "type": "string" },
                    },
                    "required": ["code", "message"],
                },
            },
        },
        "required": ["schema", "ok", "failures"],
    })
}

/// Builds one `inputSchema`: an object with the given properties, the
/// given required names (omitted when none), and — unlike the output
/// schema — `additionalProperties: false`, because here the wrapper owns
/// the surface, and an undeclared property can only be a mistake that
/// would otherwise be dropped on the floor.
fn input_schema(properties: Vec<(&'static str, Value)>, required: &[&str]) -> Value {
    let mut object = Map::new();
    for (name, schema) in properties {
        object.insert(name.to_owned(), schema);
    }
    let mut schema = json!({ "type": "object", "properties": object });
    let fields = schema
        .as_object_mut()
        .expect("a freshly built json! object");
    if !required.is_empty() {
        fields.insert("required".to_owned(), json!(required));
    }
    fields.insert("additionalProperties".to_owned(), Value::Bool(false));
    schema
}

/// One string property with its description.
fn string_property(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

/// One boolean property with its description.
fn boolean_property(description: &str) -> Value {
    json!({ "type": "boolean", "description": description })
}

fn doctor() -> ToolDef {
    ToolDef::new(
        "fz_doctor",
        "fz doctor",
        "Runs `fz doctor --json` and returns its envelope: harness, production rules, migration lockfile and portable-SQL findings, each failure carrying a stable error code.",
        vec![
            (
                "out",
                string_property(
                    "Migration directory fz doctor reads (the CLI's `--out`, default `migrations`).",
                ),
            ),
            (
                "allow_no_captcha",
                string_property(
                    "Accept a production venture without an effective Captcha port for the stated reason (the CLI's `--allow-no-captcha`).",
                ),
            ),
        ],
        &[],
        ToolAnnotations {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        },
        build_doctor,
    )
}

fn plan() -> ToolDef {
    ToolDef::new(
        "fz_plan",
        "fz plan",
        "Runs `fz plan --json` and returns its envelope: what a deployment would change — modules, config, migrations — plus the `digest` that approves exactly that plan. Reads only; writes nothing.",
        vec![
            ("manifest", string_property(MANIFEST_DOC)),
            ("migrations", string_property(MIGRATIONS_DOC)),
        ],
        &[],
        ToolAnnotations {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        },
        build_plan,
    )
}

fn verify() -> ToolDef {
    ToolDef::new(
        "fz_verify",
        "fz verify",
        "Runs `fz verify --json` and returns its envelope: whether the recorded deployment still matches the manifest, with any drift reported as coded failures.",
        vec![
            ("manifest", string_property(MANIFEST_DOC)),
            ("migrations", string_property(MIGRATIONS_DOC)),
        ],
        &[],
        ToolAnnotations {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        },
        build_verify,
    )
}

fn init() -> ToolDef {
    ToolDef::new(
        "fz_init",
        "fz init",
        "Runs `fz init --json` to write a new venture manifest — name and host, no modules. Refuses to overwrite an existing manifest unless `force` is set.",
        vec![
            (
                "name",
                string_property(
                    "The venture name; becomes the generated crate name (the CLI's `--name`).",
                ),
            ),
            (
                "host",
                string_property("The primary host the backend answers on (the CLI's `--host`)."),
            ),
            ("manifest", string_property(MANIFEST_DOC)),
            (
                "force",
                boolean_property(
                    "Replace an existing manifest instead of refusing (the CLI's `--force`).",
                ),
            ),
        ],
        &["name", "host"],
        ToolAnnotations {
            read_only_hint: false,
            destructive_hint: false,
            idempotent_hint: false,
            open_world_hint: false,
        },
        build_init,
    )
}

fn add() -> ToolDef {
    ToolDef::new(
        "fz_add",
        "fz add",
        "Runs `fz add --json` to add one module to the manifest's desired composition — never deploys, never touches a database. Adding an already-present module is a successful no-op.",
        vec![
            (
                "module",
                string_property("The module slug, as the catalog names it."),
            ),
            ("manifest", string_property(MANIFEST_DOC)),
        ],
        &["module"],
        ToolAnnotations {
            read_only_hint: false,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        },
        build_add,
    )
}

fn deploy() -> ToolDef {
    ToolDef::new(
        "fz_deploy",
        "fz deploy",
        "Runs `fz deploy --json` to record the approved plan beside the manifest; the `digest` from `fz_plan` is the approval token it enforces. A production venture needs `i_am_deploying_to_production`; a plan that removes modules needs `i_am_removing_modules`.",
        vec![
            (
                "plan",
                string_property(
                    "The digest `fz_plan` printed — the approval token `fz deploy --plan` recomputes and enforces.",
                ),
            ),
            ("manifest", string_property(MANIFEST_DOC)),
            ("migrations", string_property(MIGRATIONS_DOC)),
            (
                "i_am_deploying_to_production",
                boolean_property(
                    "Required by fz when the venture resolves to production (the CLI's second consent).",
                ),
            ),
            (
                "i_am_removing_modules",
                boolean_property(
                    "Required by fz when the plan removes modules from the served composition — their data leaves the venture.",
                ),
            ),
        ],
        &[],
        ToolAnnotations {
            read_only_hint: false,
            destructive_hint: true,
            idempotent_hint: false,
            open_world_hint: true,
        },
        build_deploy,
    )
}

fn error_codes() -> ToolDef {
    ToolDef::new(
        ERROR_CODES_TOOL,
        "fz error codes",
        "Returns the stable error-code catalogue — every code an `fz` failure can carry, plus this server's four `mcp-` codes — each with title, description and source. Runs no fz process.",
        vec![],
        &[],
        ToolAnnotations {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        },
        build_error_codes,
    )
}

/// The verb plus its fixed flags.
fn argv(verb: &str, fixed: &[&str]) -> Vec<String> {
    let mut argv = Vec::with_capacity(fixed.len() + 4);
    argv.push(verb.to_owned());
    argv.extend(fixed.iter().map(|flag| (*flag).to_owned()));
    argv
}

/// Appends `--flag value` when the optional argument is present.
fn push_optional(argv: &mut Vec<String>, flag: &str, value: Option<String>) {
    if let Some(value) = value {
        argv.push(flag.to_owned());
        argv.push(value);
    }
}

fn build_doctor(arguments: &Map<String, Value>) -> Result<Vec<String>, String> {
    reject_unknown("fz_doctor", arguments, &["out", "allow_no_captcha"])?;
    let mut argv = argv("doctor", &["--json"]);
    push_optional(&mut argv, "--out", optional_string(arguments, "out")?);
    push_optional(
        &mut argv,
        "--allow-no-captcha",
        optional_string(arguments, "allow_no_captcha")?,
    );
    Ok(argv)
}

fn build_plan(arguments: &Map<String, Value>) -> Result<Vec<String>, String> {
    reject_unknown("fz_plan", arguments, &["manifest", "migrations"])?;
    let mut argv = argv("plan", &["--json", "--non-interactive"]);
    push_optional(
        &mut argv,
        "--manifest",
        optional_string(arguments, "manifest")?,
    );
    push_optional(
        &mut argv,
        "--migrations",
        optional_string(arguments, "migrations")?,
    );
    Ok(argv)
}

fn build_verify(arguments: &Map<String, Value>) -> Result<Vec<String>, String> {
    reject_unknown("fz_verify", arguments, &["manifest", "migrations"])?;
    let mut argv = argv("verify", &["--json", "--non-interactive"]);
    push_optional(
        &mut argv,
        "--manifest",
        optional_string(arguments, "manifest")?,
    );
    push_optional(
        &mut argv,
        "--migrations",
        optional_string(arguments, "migrations")?,
    );
    Ok(argv)
}

fn build_init(arguments: &Map<String, Value>) -> Result<Vec<String>, String> {
    reject_unknown("fz_init", arguments, &["name", "host", "manifest", "force"])?;
    let name = required_string(arguments, "name")?;
    let host = required_string(arguments, "host")?;
    let mut argv = argv(
        "init",
        &[
            "--json",
            "--non-interactive",
            "--name",
            &name,
            "--host",
            &host,
        ],
    );
    push_optional(
        &mut argv,
        "--manifest",
        optional_string(arguments, "manifest")?,
    );
    if boolean_flag(arguments, "force")? {
        argv.push("--force".to_owned());
    }
    Ok(argv)
}

fn build_add(arguments: &Map<String, Value>) -> Result<Vec<String>, String> {
    reject_unknown("fz_add", arguments, &["module", "manifest"])?;
    let module = required_string(arguments, "module")?;
    let mut argv = argv("add", &["--json", "--non-interactive"]);
    argv.push(module);
    push_optional(
        &mut argv,
        "--manifest",
        optional_string(arguments, "manifest")?,
    );
    Ok(argv)
}

fn build_deploy(arguments: &Map<String, Value>) -> Result<Vec<String>, String> {
    reject_unknown(
        "fz_deploy",
        arguments,
        &[
            "plan",
            "manifest",
            "migrations",
            "i_am_deploying_to_production",
            "i_am_removing_modules",
        ],
    )?;
    let mut argv = argv("deploy", &["--json", "--non-interactive"]);
    push_optional(&mut argv, "--plan", optional_string(arguments, "plan")?);
    push_optional(
        &mut argv,
        "--manifest",
        optional_string(arguments, "manifest")?,
    );
    push_optional(
        &mut argv,
        "--migrations",
        optional_string(arguments, "migrations")?,
    );
    if boolean_flag(arguments, "i_am_deploying_to_production")? {
        argv.push("--i-am-deploying-to-production".to_owned());
    }
    if boolean_flag(arguments, "i_am_removing_modules")? {
        argv.push("--i-am-removing-modules".to_owned());
    }
    Ok(argv)
}

fn build_error_codes(arguments: &Map<String, Value>) -> Result<Vec<String>, String> {
    // No subprocess: `call` serves the catalogue once this validation
    // has run, before any argv is used.
    reject_unknown(ERROR_CODES_TOOL, arguments, &[])?;
    Ok(Vec::new())
}

/// Rejects any property the tool does not declare. With
/// `additionalProperties: false` in the schema a conforming client never
/// sends one, but a spelling mistake from a non-conforming one would
/// otherwise be silently ignored — the tool would run with defaults
/// while the agent believed its argument mattered.
fn reject_unknown(
    tool: &str,
    arguments: &Map<String, Value>,
    known: &[&str],
) -> Result<(), String> {
    for name in arguments.keys() {
        if !known.contains(&name.as_str()) {
            return Err(format!("unknown argument `{name}` for tool `{tool}`"));
        }
    }
    Ok(())
}

/// An optional string argument. `null` counts as absent — some clients
/// send it for "not set" — and a `-`-leading value is refused before
/// clap can re-read it as a flag.
fn optional_string(arguments: &Map<String, Value>, name: &str) -> Result<Option<String>, String> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            check_no_leading_dash(name, value)?;
            Ok(Some(value.clone()))
        }
        Some(other) => Err(wrong_type(name, other, "a string")),
    }
}

/// A required string argument: absent, `null` and `""` are all
/// refusals, each naming the argument.
fn required_string(arguments: &Map<String, Value>, name: &str) -> Result<String, String> {
    match arguments.get(name) {
        None | Some(Value::Null) => Err(format!("missing required argument `{name}`")),
        Some(Value::String(value)) if value.is_empty() => {
            Err(format!("argument `{name}` must not be empty"))
        }
        Some(Value::String(value)) => {
            check_no_leading_dash(name, value)?;
            Ok(value.clone())
        }
        Some(other) => Err(wrong_type(name, other, "a string")),
    }
}

/// An optional boolean flag argument.
fn boolean_flag(arguments: &Map<String, Value>, name: &str) -> Result<bool, String> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(wrong_type(name, other, "a boolean")),
    }
}

fn check_no_leading_dash(name: &str, value: &str) -> Result<(), String> {
    if value.starts_with('-') {
        return Err(format!(
            "argument `{name}` must not start with `-`: the fz command line would read {value:?} as a flag"
        ));
    }
    Ok(())
}

fn wrong_type(name: &str, value: &Value, expected: &str) -> String {
    format!(
        "argument `{name}` must be {expected}, got {}",
        json_type(value)
    )
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}
