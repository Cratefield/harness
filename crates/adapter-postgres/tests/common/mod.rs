//! Shared helpers for the Postgres integration tests: the crate's
//! exported `testing` module — per-test throwaway databases on the server
//! named by `FZ_TEST_POSTGRES_URL` (issue #18), reused by
//! `cratefield-testing`'s parity kit (issue #20).

pub(crate) use cratefield_adapter_postgres::testing::{TempDb, base_url, skip_reason};
