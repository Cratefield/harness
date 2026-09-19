//! The TypeScript client generator (issue #155). See the crate README for
//! the pipeline this sits in; the short version: a `/__surface` document
//! in, the files of a typed `@cratefield/client` package out, with no I/O
//! anywhere in between — the caller writes what [`generate`] returns.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// The input side: the `/__surface` document read into the normalized
/// Tables model — [`contract::extract`], [`contract::Contract`],
/// [`contract::TableModel`], [`contract::ColumnModel`]. Public so a
/// pipeline (and the tests) can inspect the reading without running the
/// emitter behind it.
pub mod contract;
mod emitter;

/// A generated file: a package-relative path and its full contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFile {
    pub path: String,
    pub contents: String,
}

/// The generated client package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedPackage {
    /// The venture the client speaks for, from the document.
    pub venture: String,
    /// The npm package name the files implement: `@cratefield/client`.
    pub package_name: String,
    /// A sha256 over the generated files, for a reproducible-publish
    /// check: the same document always generates the same bytes, so the
    /// same hash.
    pub composition_hash: String,
    /// Every file to write, in a stable order. Paths are relative to the
    /// package root (`src/index.ts`, not `./src/index.ts`).
    pub files: Vec<GeneratedFile>,
}

/// Why generation refused. Every case is a contract this generator cannot
/// honour, and every `Display` says what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    /// The document's `surface_api` is not the contract this generator
    /// speaks: a newer (or corrupted) server than the generator.
    UnsupportedSurfaceApi {
        /// What the document declared.
        found: u32,
        /// What this generator reads.
        expected: u32,
    },
    /// The document declares no `tables` module, so there is no contract
    /// to generate a client from.
    NoTablesModule {
        /// The modules the document does declare.
        modules: Vec<String>,
    },
    /// An action in the Tables module whose name is not one of the five
    /// verbs the module publishes (`list-`/`read-`/`create-`/
    /// `replace-`/`delete-`, then the table name).
    UnknownAction {
        /// The action's name.
        action: String,
    },
    /// An action whose name parses but whose method or path is not what
    /// its verb promises — a contract drifted from its own vocabulary.
    UnreadableAction {
        /// The action's name.
        action: String,
        /// What is wrong with it.
        why: String,
    },
    /// A table whose name is not a safe identifier: lowercase snake-case
    /// (`[a-z][a-z0-9_]*`, no double or trailing underscore), the same
    /// rule `cratefield_tables::is_identifier` enforces on a declaration.
    /// The `/__surface` document is untrusted input — the documented usage
    /// is `curl -s https://venture/__surface | fz client-ts` — and the
    /// name is interpolated into the generated TypeScript, so anything it
    /// cannot spell is refused rather than renamed: a silently renamed
    /// table would produce a client that calls the wrong route.
    UnsupportedTableName {
        /// The offending table's name, as the document spelled it.
        table: String,
    },
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenerateError::UnsupportedSurfaceApi { found, expected } => write!(
                f,
                "the surface document speaks contract {found}, and this generator reads \
                 contract {expected}; generate the client with a generator built for it"
            ),
            GenerateError::NoTablesModule { modules } if modules.is_empty() => write!(
                f,
                "the surface document declares no modules at all; a venture that serves \
                 declared tables publishes them as the `tables` module — compose the \
                 tables module into the venture and regenerate"
            ),
            GenerateError::NoTablesModule { modules } => write!(
                f,
                "the surface document declares no `tables` module (it names [{}]); a \
                 client can only be generated from the tables the venture declares — \
                 compose the tables module into the venture and regenerate",
                modules.join(", ")
            ),
            GenerateError::UnknownAction { action } => write!(
                f,
                "the tables module publishes the action `{action}`, which is not one of \
                 the five verbs the generator reads (`list-`, `read-`, `create-`, \
                 `replace-`, `delete-`, each followed by the table name); regenerate \
                 with a generator that speaks this contract"
            ),
            GenerateError::UnreadableAction { action, why } => write!(
                f,
                "the tables module publishes the action `{action}`, and {why}; the \
                 contract has drifted from its own vocabulary — regenerate with a \
                 generator that speaks it",
            ),
            GenerateError::UnsupportedTableName { table } => write!(
                f,
                "the tables module publishes the table `{table}`, whose name is not a \
                 safe identifier — a table name must be lowercase `[a-z][a-z0-9_]*`, no \
                 double or trailing underscore — and it is interpolated into the \
                 generated TypeScript, so this generator refuses anything it cannot \
                 spell rather than renaming it; rename the table in the venture's \
                 declaration and regenerate",
            ),
        }
    }
}

impl std::error::Error for GenerateError {}

/// Generate the files of a typed `@cratefield/client` package from a
/// `/__surface` document.
///
/// Pure: the same document always generates byte-identical files, and
/// nothing here touches a disk — the caller writes
/// [`GeneratedPackage::files`] wherever the pipeline wants them.
///
/// # Errors
///
/// [`GenerateError::UnsupportedSurfaceApi`] when the document speaks a
/// contract version this generator does not read,
/// [`GenerateError::NoTablesModule`] when the document has no `tables`
/// module to generate from, [`GenerateError::UnknownAction`] /
/// [`GenerateError::UnreadableAction`] when the Tables module publishes
/// an action outside the verb vocabulary the generator reads, and
/// [`GenerateError::UnsupportedTableName`] when a table's name is not a
/// safe identifier the generated TypeScript can carry.
pub fn generate(
    document: &cratefield_core::SurfaceDocument,
) -> Result<GeneratedPackage, GenerateError> {
    let parsed = contract::extract(document)?;
    let files = emitter::emit(&parsed);
    let composition_hash = composition_hash_of(&files);
    Ok(GeneratedPackage {
        venture: parsed.venture,
        package_name: emitter::PACKAGE_NAME.to_owned(),
        composition_hash,
        files,
    })
}

/// The sha256 composition hash over a file set, in write order: each
/// file's path, a zero byte, its contents, a zero byte. Exported so a
/// publish pipeline can recompute it from the files it wrote and compare
/// it against what the generation recorded — the same construction
/// `cratefield_manifest::generate` uses for the venture crate.
#[must_use]
pub fn composition_hash_of(files: &[GeneratedFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.path.as_bytes());
        hasher.update([0]);
        hasher.update(file.contents.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    digest.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}
