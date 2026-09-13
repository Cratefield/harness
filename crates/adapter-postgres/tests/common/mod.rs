//! Shared helpers for the Postgres integration tests: the crate's
//! exported `testing` module — per-test throwaway databases on the server
//! named by `FZ_TEST_POSTGRES_URL` (issue #18), reused by
//! `cratefield-testing`'s parity kit (issue #20).

// A test-support module, included with `mod support;` (or `mod common;`)
// into each test binary in this crate. `pub` is how a helper reads here,
// and the lint is right that nothing outside can reach it — the module is
// private to every binary that includes it. Saying so once beats
// `pub(crate)` on forty helpers.
#![allow(unreachable_pub)]
pub(crate) use cratefield_adapter_postgres::testing::{TempDb, base_url, skip_reason};
