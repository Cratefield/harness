//! `factory0-testing`: the conformance kit every Factory Zero module runs
//! against (issue #9) — fake ports, an in-memory SQLite `Database`, and
//! request helpers over the axum router with **no network**.
//!
//! ```no_run
//! use factory0_testing::{conformance, TestHarness, request};
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
mod fakes;
mod harness;
mod request;

pub use conformance::{assert_wasm_safe_deps, conformance};
pub use fakes::{
    EmptyDatabase, FakeCaptcha, FakeDefer, FakeHttpClient, FakeMailer, FakeRateLimiter, FixedClock,
    MailerMode, MemoryKeyValue,
};
pub use harness::TestHarness;
pub use request::{TestResponse, request};

// The fixed test secret for the kit's Signer — an obvious dummy, never real.
pub const TEST_HARNESS_SECRET: &str = "factory0-testing-dummy-secret-0123456789";
