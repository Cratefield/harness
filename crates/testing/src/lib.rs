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

// Needs only `cratefield-core`, so it is ungated like `vectors` and
// `tmp`: a light consumer can assert the batch contract without the
// harness graph (issues #126, #201).
mod batch;
#[cfg(feature = "harness")]
mod conformance;
#[cfg(feature = "harness")]
mod dialect;
#[cfg(feature = "harness")]
mod fakes;
#[cfg(feature = "harness")]
mod harness;
#[cfg(feature = "postgres")]
mod pg;
#[cfg(feature = "port-conformance")]
mod port;
#[cfg(feature = "harness")]
mod request;
#[cfg(feature = "harness")]
mod sidecar;
mod tmp;
pub mod vectors;

pub use batch::assert_batch_is_atomic;
#[cfg(feature = "harness")]
pub use conformance::{conformance, conformance_in_process_only, sidecar_parity};
#[cfg(feature = "harness")]
pub use dialect::Dialect;
#[cfg(feature = "harness")]
pub use fakes::{
    EmptyDatabase, FakeCaptcha, FakeDefer, FakeDispatcher, FakeHttpClient, FakeMailer,
    FakePayments, FakePush, FakeRateLimiter, FakeRealtime, FixedClock, MailerMode, MemoryBlob,
    MemoryKeyValue, PaymentsCall, PaymentsMode, PushMode,
};
#[cfg(feature = "harness")]
pub use harness::TestHarness;
#[cfg(feature = "port-conformance")]
pub use port::{assert_wasm_safe_deps, push_recipient_conformance};
#[cfg(feature = "harness")]
pub use request::{TestResponse, request};
#[cfg(feature = "harness")]
pub use sidecar::{FakeSidecar, Fault, shared as shared_sidecar};
pub use tmp::TempDir;

// The fixed test secret for the kit's Signer — an obvious dummy, never real.
pub const TEST_HARNESS_SECRET: &str = "cratefield-testing-dummy-secret-0123456789";

// Mirrors cratefield-adapter-postgres's integration-test skip reason.
// The dialect axis (behind `harness`) prints it when the Postgres leg is
// unavailable, so it exists whenever that axis or the leg itself does.
#[cfg(any(feature = "harness", feature = "postgres"))]
const POSTGRES_SKIP_REASON: &str = "start a local postgres:16 \
     (docker run --rm -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:16) \
     and set FZ_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5433/postgres";
