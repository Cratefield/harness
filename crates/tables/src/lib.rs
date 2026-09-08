//! `cratefield-tables` is the schema a venture declares in its manifest,
//! and the artifacts derived from that one declaration.
//!
//! A venture edits `[tables]` in `venture.toml` and redeploys without a
//! rebuild, so the schema is a runtime value: rows are dynamic values
//! checked by an interpreter reading that value, not typed structs fixed
//! at compile time. Rust cannot infer a compile-time type from a runtime
//! value, so the two do not mix, and this is the representation for every
//! declared table.
//!
//! The schema type is a small purpose-built enum, not JSON Schema. JSON
//! Schema is sprawling and says nothing about the SQLite and Postgres DDL
//! mapping, so it is emitted as a derived view instead.
//!
//! # What one declaration produces
//!
//! - [`Schema::validate`] checks the declaration itself and reports every
//!   violation together.
//! - [`Schema::ddl`] renders forward-only, deterministic SQLite and
//!   Postgres DDL.
//! - [`validate_row`] checks a `serde_json` object against a table and
//!   answers with a [`cratefield_core::Problem`].
//! - [`json_schema`] renders a table as JSON Schema, for interop only.
//!
//! # The bound on a declaration
//!
//! A field can say required, length, range, format, enum, uniqueness,
//! foreign key, default and index. Anything that has to read another row
//! or another request is a function, not a field: overlap checks, state
//! machines and side effects belong in a module or a sidecar. Uniqueness
//! is on that list because the database enforces it, not the validator.
//!
//! # Where the rules are pinned
//!
//! `corpus/rows.json` holds triples of table, input and expected verdict,
//! run by `tests/corpus.rs`. It is a plain data file so a second
//! implementation in another language can be run over the same cases.
//! That is what keeps this validator and a generated client from
//! disagreeing about empty versus absent, number coercion, null versus
//! missing, Unicode length and whitespace.
//!
//! # Pure logic
//!
//! No I/O, no driver, no clock and no randomness. SQL is generated as
//! strings, so the crate builds for `wasm32-unknown-unknown` alongside
//! `cratefield-core`.
//!
//! # Not built here
//!
//! This crate is the schema definition and nothing downstream of it. The
//! following are deliberately absent, each its own follow-up:
//!
//! - CRUD route handlers, the access vocabulary and the batched read
//!   endpoint.
//! - The migration diff between two versions of a definition. Everything
//!   here only creates.
//! - The generated `@cratefield/client` TypeScript package, and the
//!   second run of `corpus/rows.json` against its Zod schemas.
//! - Publishing the declared tables on `/__surface`, and any control
//!   plane or manifest generator wiring.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod ddl;
mod json_schema;
mod manifest;
mod schema;
mod validate;
mod value;

pub use ddl::{SqlDialect, index_name};
pub use json_schema::{JSON_SCHEMA_DIALECT, json_schema};
pub use schema::{
    FieldDef, FieldKind, ForeignKey, MAX_IDENTIFIER_CHARS, RESERVED_PREFIXES, RESERVED_WORDS,
    Schema, TableDef, TextFormat, is_identifier,
};
pub use validate::{MAX_DETAIL_ERRORS, RowError, RowErrors, validate_row};
pub use value::{ErrorCode, ValueError, check_value, is_rfc3339, is_url, is_uuid};
