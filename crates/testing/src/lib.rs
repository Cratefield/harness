//! `cratefield-testing`: the conformance kit every Factory Zero module runs
//! against (issue #9) — fake ports, an in-memory SQLite `Database`, and
//! request helpers over the axum router with **no network**.
//!
//! ```no_run
//! use cratefield_testing::{conformance, TestHarness, request};
//!
//! #[test]
//! fn my_module_conforms() {
//!     conformance(Box::new(my_module::MyModule::new()));
//! }
//!
//! #[pollster::test]
//! async fn join_returns_202() {
//!     let kit = TestHarness::new(vec![Box::new(my_module::MyModule::new())]);
//!     let response = request(&kit.router, http::Method::POST,
//!         "/v1/my-module/join", Some(r#"{"email":"nick@example.com"}"#)).await;
//!     assert_eq!(response.status, http::StatusCode::ACCEPTED);
//! }
//! ```

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod conformance;
mod dialect;
mod fakes;
mod harness;
#[cfg(feature = "postgres")]
mod pg;
mod request;
mod sidecar;

pub use conformance::{
    assert_wasm_safe_deps, conformance, conformance_in_process_only, sidecar_parity,
};
pub use dialect::Dialect;
pub use fakes::{
    EmptyDatabase, FakeCaptcha, FakeDefer, FakeDispatcher, FakeHttpClient, FakeMailer,
    FakeRateLimiter, FixedClock, MailerMode, MemoryKeyValue,
};
pub use harness::TestHarness;
pub use request::{TestResponse, request};
pub use sidecar::{FakeSidecar, Fault, shared as shared_sidecar};

// The fixed test secret for the kit's Signer — an obvious dummy, never real.
pub const TEST_HARNESS_SECRET: &str = "cratefield-testing-dummy-secret-0123456789";

// Mirrors cratefield-adapter-postgres's integration-test skip reason.
const POSTGRES_SKIP_REASON: &str = "start a local postgres:16 \
     (docker run --rm -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:16) \
     and set FZ_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5433/postgres";
