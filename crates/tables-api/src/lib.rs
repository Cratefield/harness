//! The HTTP API over a venture's declared tables (issue #153).
//!
//! Not a module crate, which is why it is not named like one. A
//! `crates/module-*` crate provides a [`Module`] and the conformance kit
//! runs against every one of them; this provides the decision and the
//! routes that a venture's **generated** tables module calls. That module
//! has to be generated source rather than a library because
//! `personal_data()` is `&'static` all the way down and cannot be
//! assembled from a manifest read at runtime.
//!
//! [`Module`]: cratefield_core::Module
//!
//! A `[tables]` declaration already becomes DDL, a module, a privacy
//! declaration, an access level and the statements that read and write a
//! row. This is where a request meets them.
//!
//! Reading the access decision on its own is the point of splitting
//! [`access`] out: it decides who sees whose rows and it has no HTTP in
//! it, so every case is a value rather than a request.

pub mod access;
pub mod batch;
pub mod declared;
pub mod read;
pub mod routes;
pub mod surface;
pub mod write;

pub use access::{
    FORBIDDEN, MISDECLARED, NO_MEMBERSHIP_FACT, NOT_YOURS_TO_GIVE, READ_ONLY, Reach, TableApi,
    UNAUTHENTICATED, may_read, may_write, settle_subject,
};
pub use batch::{Batch, MAX_READS, Read, run as run_batch};
pub use declared::{Declared, parse};
pub use read::{Asked, PAGE, Tables, one, page};
pub use routes::{
    BAD_CURSOR, BAD_KEY, COMPOSITE_KEY, Key, NOT_A_KEY_COLUMN, PARTIAL_KEY, cursor_from_query,
    key_from_path, router,
};
pub use surface::surface;
pub use write::{ALREADY_EXISTS, NOT_A_ROW, create, remove, replace};
