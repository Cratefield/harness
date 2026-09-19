//! `fz client-ts` (issue #155): a `/__surface` contract document in, the
//! files of a typed `@cratefield/client` package out, written to `--out`.
//!
//! The other harness-free commands work on what a venture *has* — a
//! manifest (`fz build`), a migration directory, its environment
//! (`fz push`). This one works on what a venture *serves*: `--surface`
//! names the JSON the running venture publishes at `/__surface`, or `-`
//! to read the body off stdin, so a client can be generated without
//! checking the venture out at all:
//!
//! ```text
//! curl -s https://venture.example/__surface | fz client-ts --surface - --out ./client
//! ```
//!
//! Generation itself is [`cratefield_client_ts::generate`] — pure,
//! deterministic, no I/O — so this module is only the I/O around it: read
//! the document, write the files, and say which of the two failed in the
//! doctor's coded shape (`--json` prints exactly one object on stdout,
//! every refusal carrying a stable code from [`crate::codes`]).

use crate::codes::{CODES, DoctorCodeDef};
use cratefield_client_ts::{GenerateError, GeneratedPackage};
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

/// The `schema` field of the `fz client-ts --json` object: consumers
/// branch on it, so it only ever grows. The same wire contract
/// `fz doctor --json` carries ([`crate::doctor::REPORT_SCHEMA`]).
pub const SCHEMA: u32 = 1;

/// A refused run: its stable code from the catalogue ([`crate::codes`])
/// plus the human message, which is exactly what the prose path prints
/// after `fz: `.
#[derive(Debug)]
pub struct Refusal {
    /// The catalogue definition this refusal is classified under.
    pub code: &'static DoctorCodeDef,
    /// The refusal message, exactly as the prose path prints it.
    pub message: String,
}

impl Refusal {
    /// The exact stdout payload of a refused `fz client-ts --json`: one
    /// object, one line, the doctor's failure shape.
    ///
    /// # Errors
    ///
    /// Only if `serde_json` cannot serialize the payload — a struct of
    /// strings and numbers cannot hit that, but the Result keeps every
    /// caller total instead of panicking.
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&BarePayload {
            schema: SCHEMA,
            ok: false,
            failures: vec![FailureRef {
                code: self.code.code,
                message: &self.message,
            }],
        })
    }
}

/// What a successful run did: the generated package's identity and the
/// files it wrote, in write order.
#[derive(Debug)]
pub struct Generated {
    /// The venture the client speaks for, from the document.
    pub venture: String,
    /// The npm package name the files implement: `@cratefield/client`.
    pub package_name: String,
    /// The sha256 composition hash over the generated files, for a
    /// reproducible-publish check.
    pub composition_hash: String,
    /// The directory the files went to, as `--out` spelled it.
    pub out: String,
    /// The package-relative paths written, in write order.
    pub files: Vec<String>,
}

impl Generated {
    /// The exact stdout payload of a successful `fz client-ts --json`:
    /// one object, one line.
    ///
    /// # Errors
    ///
    /// Only if `serde_json` cannot serialize the payload — a struct of
    /// strings and numbers cannot hit that, but the Result keeps every
    /// caller total instead of panicking.
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&WrittenPayload {
            schema: SCHEMA,
            ok: true,
            failures: Vec::new(),
            package: &self.package_name,
            venture: &self.venture,
            composition_hash: &self.composition_hash,
            out: self.out.clone(),
            files_written: self.files.len(),
            files: &self.files,
        })
    }
}

/// One failure as it travels on the wire: the catalogue slug plus the
/// message, in the doctor's shape.
#[derive(serde::Serialize)]
struct FailureRef<'a> {
    code: &'a str,
    message: &'a str,
}

/// The refused `fz client-ts --json` object: the doctor's bare payload.
#[derive(serde::Serialize)]
struct BarePayload<'a> {
    schema: u32,
    ok: bool,
    failures: Vec<FailureRef<'a>>,
}

/// The successful `fz client-ts --json` object.
#[derive(serde::Serialize)]
struct WrittenPayload<'a> {
    schema: u32,
    ok: bool,
    failures: Vec<FailureRef<'a>>,
    package: &'a str,
    venture: &'a str,
    composition_hash: &'a str,
    out: String,
    files_written: usize,
    files: &'a [String],
}

/// Runs `fz client-ts` in the prose discipline: the summary on stdout,
/// a refusal as the message `finish` prints after `fz: `. `source` is
/// the `--surface` value — a path, or `-` for stdin.
///
/// # Errors
///
/// A human-readable message naming what refused and what to do about it.
pub fn run(source: &str, out: &Path) -> Result<(), String> {
    match client_ts(source, out) {
        Ok(generated) => {
            print_summary(&generated);
            Ok(())
        }
        Err(refusal) => Err(refusal.message),
    }
}

/// Runs `fz client-ts --json`: exactly one JSON object on stdout, nothing
/// else on either stream, and the verdict as the exit code.
#[must_use = "call process::exit with the returned ExitCode"]
pub fn run_json(source: &str, out: &Path) -> ExitCode {
    let (payload, exit) = match client_ts(source, out) {
        Ok(generated) => (generated.render_json(), ExitCode::SUCCESS),
        Err(refusal) => (refusal.render_json(), ExitCode::FAILURE),
    };
    match payload {
        Ok(line) => {
            println!("{line}");
            exit
        }
        Err(err) => {
            eprintln!("fz: cannot serialize the report: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The whole command minus the argv plumbing: read the document, generate
/// the package, write it under `out`. Public so the acceptance tests can
/// pin the messages and the JSON payloads the two disciplines print
/// without driving argv.
///
/// # Errors
///
/// [`Refusal`] with the stable code for the step that refused: reading
/// the document, reading it as a `/__surface` contract, generating from
/// it, or writing the files out.
pub fn client_ts(source: &str, out: &Path) -> Result<Generated, Refusal> {
    let document = read_document(source)?;
    from_document(&document, &describe(source), out)
}

/// Generates and writes from a document **body** — the seam
/// [`client_ts`] reaches once it has read `--surface`. `described` is how
/// a refusal should name the document ("the document on stdin", or the
/// path it was read from).
///
/// # Errors
///
/// [`Refusal`], as [`client_ts`].
pub fn from_document(document: &str, described: &str, out: &Path) -> Result<Generated, Refusal> {
    // Two reads, on purpose: "not valid JSON" and "JSON, but not a
    // surface document" are different mistakes with different fixes, and
    // each gets its own stable code.
    let value: serde_json::Value = serde_json::from_str(document).map_err(|err| Refusal {
        code: &CODES.surface_unreadable,
        message: format!("{described} is not valid JSON: {err}"),
    })?;
    let parsed: cratefield_core::SurfaceDocument =
        serde_json::from_value(value).map_err(|err| Refusal {
            code: &CODES.surface_invalid,
            message: format!(
                "{described} is not a /__surface document: {err} — point --surface at the \
                 JSON the venture serves at /__surface"
            ),
        })?;
    let package = cratefield_client_ts::generate(&parsed).map_err(|error| classify(&error))?;
    write_package(&package, out)
}

/// Reads the `--surface` value: `-` is the document on stdin, anything
/// else a path.
fn read_document(source: &str) -> Result<String, Refusal> {
    if source == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|err| Refusal {
                code: &CODES.surface_unreadable,
                message: format!("cannot read the surface document from stdin: {err}"),
            })?;
        return Ok(buffer);
    }
    std::fs::read_to_string(source).map_err(|err| Refusal {
        code: &CODES.surface_unreadable,
        message: format!("cannot read {}: {err}", Path::new(source).display()),
    })
}

/// How a refusal should name the document, from the `--surface` value.
fn describe(source: &str) -> String {
    if source == "-" {
        "the document on stdin".to_owned()
    } else {
        format!("the document at {source}")
    }
}

/// The generator's refusals are contract refusals, and each variant is a
/// different thing an agent would branch on, so each gets its own stable
/// code; the message is the generator's own, which already names the fix.
fn classify(error: &GenerateError) -> Refusal {
    let code = match error {
        GenerateError::UnsupportedSurfaceApi { .. } => &CODES.surface_unsupported_contract,
        GenerateError::NoTablesModule { .. } => &CODES.surface_no_tables_module,
        GenerateError::UnknownAction { .. } | GenerateError::UnreadableAction { .. } => {
            &CODES.surface_action_unreadable
        }
        GenerateError::UnsupportedTableName { .. } => &CODES.surface_table_name_invalid,
    };
    Refusal {
        code,
        message: error.to_string(),
    }
}

/// Whether a generated file's package-relative path is safe to join onto
/// `--out`: relative, with no `..` component anywhere in it. Unreachable
/// for today's emitter — its six paths are hard-coded constants — and
/// cheap enough to keep as the guard for the day the file set grows
/// beyond them.
fn is_safe_relative(path: &str) -> bool {
    let path = Path::new(path);
    !path.is_absolute()
        && path.components().all(|component| {
            !matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
}

/// Writes the package to `out`, creating subdirectories, and reports what
/// landed where. Mirrors `fz build`'s file writing: the generated paths
/// are package-relative (`src/index.ts`).
fn write_package(package: &GeneratedPackage, out: &Path) -> Result<Generated, Refusal> {
    let mut written = Vec::with_capacity(package.files.len());
    for file in &package.files {
        if !is_safe_relative(&file.path) {
            return Err(Refusal {
                code: &CODES.client_write_failed,
                message: format!(
                    "the generated path `{}` is not package-relative, and the generator \
                     writes only below --out",
                    file.path
                ),
            });
        }
        let dest = out.join(&file.path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|err| Refusal {
                code: &CODES.client_write_failed,
                message: format!("cannot create {}: {err}", parent.display()),
            })?;
        }
        std::fs::write(&dest, &file.contents).map_err(|err| Refusal {
            code: &CODES.client_write_failed,
            message: format!("cannot write {}: {err}", dest.display()),
        })?;
        written.push(file.path.clone());
    }
    Ok(Generated {
        venture: package.venture.clone(),
        package_name: package.package_name.clone(),
        composition_hash: package.composition_hash.clone(),
        out: out.display().to_string(),
        files: written,
    })
}

/// The prose summary. A result, not a diagnostic — stdout, so a script
/// can read the file list off it.
fn print_summary(generated: &Generated) {
    println!(
        "fz client-ts: {} (venture: {})",
        generated.package_name, generated.venture
    );
    println!("  composition: sha256:{}", generated.composition_hash);
    println!(
        "  wrote {} files to {}:",
        generated.files.len(),
        generated.out
    );
    for file in &generated.files {
        println!("    {file}");
    }
}

#[cfg(test)]
mod tests {
    use super::is_safe_relative;

    /// The write guard: a generated path may travel below `--out` only.
    /// Unreachable through `emit()` today, so it is pinned here directly.
    #[test]
    fn a_generated_path_may_not_escape_out() {
        assert!(is_safe_relative("src/index.ts"));
        assert!(is_safe_relative("package.json"));
        assert!(!is_safe_relative(".."));
        assert!(!is_safe_relative("../evil.ts"), "a `..` escapes --out");
        assert!(
            !is_safe_relative("src/../../evil.ts"),
            "a buried `..` escapes --out too"
        );
        assert!(!is_safe_relative("/etc/cratefield"), "an absolute path");
    }
}
