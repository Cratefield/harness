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
//! # The bound on a declaration
//!
//! A field can say required, length, range, format, enum, uniqueness,
//! foreign key, default and index. Anything that has to read another row
//! or another request is a function, not a field: overlap checks, state
//! machines and side effects belong in a module or a sidecar. Uniqueness
//! is on that list because the database enforces it, not the validator.
//!
//! # Pure logic
//!
//! No I/O, no driver, no clock and no randomness. SQL is generated as
//! strings, so the crate builds for `wasm32-unknown-unknown` alongside
//! `cratefield-core`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod ddl;
mod manifest;
mod schema;
mod value;

pub use ddl::{SqlDialect, index_name};
pub use schema::{
    FieldDef, FieldKind, ForeignKey, MAX_IDENTIFIER_CHARS, RESERVED_PREFIXES, RESERVED_WORDS,
    Schema, TableDef, TextFormat, is_identifier,
};
pub use value::{ErrorCode, ValueError, check_value, is_rfc3339, is_url, is_uuid};
