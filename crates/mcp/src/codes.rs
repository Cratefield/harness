//! The wrapper's own error codes, and the assembled catalogue the
//! `fz_error_codes` tool serves.
//!
//! The CLI's catalogue ([`cratefield_cli::codes`]) is the contract, so
//! it is compiled in from the linked `cratefield-cli` library —
//! [`cratefield_cli::codes::registry`] runs in this server's own
//! process, never asked of the spawned `fz` — in registry order,
//! unedited, and never copied into this crate. A code the CLI appends
//! is served here with no change on this side.
//!
//! The four codes below are everything this server may ever add. They
//! are prefixed `mcp-` so they can never collide with the CLI's
//! kebab-case namespace, and they carry the same append-only contract
//! the CLI's catalogue does: a code is never renamed, reworded or
//! removed. A failure *message* may change wording freely; a *code*
//! may not. New codes append.

pub use cratefield_cli::codes::DoctorCodeDef;
use serde::Serialize;

/// The `fz` program could not be spawned at all — a missing binary, a
/// configured `--cwd` that does not exist. The message names the program
/// and the OS error.
pub const FZ_UNAVAILABLE: DoctorCodeDef = DoctorCodeDef {
    code: "mcp-fz-unavailable",
    title: "fz unavailable",
    description: "The configured fz program could not be spawned; the message names the program and the OS error.",
};

/// `fz` ran but stdout was not a single JSON object: a clap usage error
/// (exit 2), a standalone-binary refusal, a crash. The message carries
/// the exit status and a bounded excerpt of stderr, else stdout.
pub const FZ_NO_JSON: DoctorCodeDef = DoctorCodeDef {
    code: "mcp-fz-no-json",
    title: "fz printed no JSON",
    description: "fz ran but stdout was not one JSON object — most often a clap usage error; the message carries the exit status and a bounded excerpt of stderr, else stdout.",
};

/// `fz` outlived the configured time limit (`FZ_MCP_TIMEOUT_SECS`,
/// default 600 seconds, `0` disables) and was killed. The message names
/// the configured program and the limit it outlived.
pub const FZ_TIMEOUT: DoctorCodeDef = DoctorCodeDef {
    code: "mcp-fz-timeout",
    title: "fz timed out",
    description: "fz outlived the configured time limit and was killed; the message names the program and the limit.",
};

/// An argument failed the wrapper's validation before `fz` was invoked:
/// a missing or empty required value, a wrong JSON type, an unknown
/// property, or a string starting with `-` — which clap would re-read
/// as a flag.
pub const ARGUMENT_INVALID: DoctorCodeDef = DoctorCodeDef {
    code: "mcp-argument-invalid",
    title: "Argument invalid",
    description: "A tool argument failed validation before fz ran: missing, empty, wrong type, unknown, or a `-`-leading string clap would read as a flag.",
};

/// The four wrapper codes, in catalogue order.
#[must_use]
pub fn wrapper_codes() -> Vec<&'static DoctorCodeDef> {
    vec![&FZ_UNAVAILABLE, &FZ_NO_JSON, &FZ_TIMEOUT, &ARGUMENT_INVALID]
}

/// One row of the `fz_error_codes` catalogue: a code definition plus
/// which half owns it.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogueEntry {
    /// The stable kebab-case code.
    pub code: &'static str,
    /// Short, stable human title.
    pub title: &'static str,
    /// One-line description of when the code appears.
    pub description: &'static str,
    /// `"fz"` for the CLI's own codes (`cratefield_cli::codes::registry`
    /// runs in this server's own process, not the spawned `fz`), `"mcp"`
    /// for the four wrapper codes.
    pub source: &'static str,
}

/// The full catalogue: every `fz` code in registry order, then the four
/// wrapper codes. This is the one place the two lists meet; nothing else
/// in the crate names an `fz` code.
#[must_use]
pub fn catalogue() -> Vec<CatalogueEntry> {
    let from = |def: &'static DoctorCodeDef, source: &'static str| CatalogueEntry {
        code: def.code,
        title: def.title,
        description: def.description,
        source,
    };
    let mut entries: Vec<CatalogueEntry> = cratefield_cli::codes::registry()
        .into_iter()
        .map(|def| from(def, "fz"))
        .collect();
    entries.extend(wrapper_codes().into_iter().map(|def| from(def, "mcp")));
    entries
}

/// The `fz_error_codes` payload: the catalogue inside the envelope shape
/// every other tool returns, so an agent parses exactly one object shape
/// forever.
#[derive(Serialize)]
struct CodesPayload {
    schema: u32,
    ok: bool,
    /// Always empty — serving the catalogue cannot fail.
    failures: Vec<crate::fz::FailRef>,
    codes: Vec<CatalogueEntry>,
}

/// The envelope `fz_error_codes` returns: no subprocess, just the
/// catalogue.
#[must_use]
pub fn error_codes_envelope() -> crate::fz::Envelope {
    let payload = CodesPayload {
        schema: crate::fz::SCHEMA,
        ok: true,
        failures: Vec::new(),
        codes: catalogue(),
    };
    crate::fz::Envelope::serialised(&payload)
}
