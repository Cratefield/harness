//! Serving the tables a venture declares (issue #153).
//!
//! A `[tables]` declaration already becomes DDL, a module, a privacy
//! declaration, an access level and the statements that read and write a
//! row. This is where a request meets them.
//!
//! Reading the access decision on its own is the point of splitting
//! [`access`] out: it decides who sees whose rows and it has no HTTP in
//! it, so every case is a value rather than a request.

pub mod access;

pub use access::{FORBIDDEN, MISDECLARED, Reach, TableApi, UNAUTHENTICATED, may_read};
