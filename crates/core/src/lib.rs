//! `factory0-core` is the runtime-agnostic kernel of the Factory Zero harness:
//! the [`Module`] contract, the [`Harness`] builder, port traits, RFC 9457
//! problem+json errors, the request [`Scope`], an in-process [`EventBus`] and
//! a [`TemplateRegistry`] (ADR 0001, 0002, 0007).
//!
//! Core depends only on `http`, `axum` (default features off), `serde`,
//! `tracing`, `sea-query` and pure-Rust crypto. It must never depend on
//! `worker`, `wasm-bindgen`, `tokio`, `reqwest`, `sqlx` or `rusqlite`, and
//! never touches `std::fs` or `std::net` — CI enforces this with a
//! `cargo tree` check and the wasm build of `examples/venture`.

#![forbid(unsafe_code)]

mod config;
mod events;
mod harness;
mod http;
mod module;
mod ports;
mod problem;
mod problems;
mod scope;
mod signer;
mod template;
mod venture;

pub use config::{Config, ConfigError, EmptyConfig, HarnessConfig, MapConfig, ModuleConfig};
pub use events::{AnyError, EventBus, EventHandler, EventName};
pub use harness::{Harness, HarnessBuilder, Runtime};
pub use http::{Json, MAX_BODY_BYTES, X_REQUEST_ID, request_id_is_valid};
pub use module::{BoxFuture, HARNESS_API, Migrations, Module, ModuleContext, SqlMigration};
pub use ports::{
    Captcha, CaptchaError, Clock, Database, DbError, Decision, Defer, HttpClient, HttpError, IdGen,
    KeyValue, Kid, KvError, MailError, Mailer, Message, NoopDefer, Payload, Port, Ports,
    RateLimitError, RateLimiter, Row, Rows, SendOutcome, SignatureError, Signer, Statement,
    SystemClock, TryFromValue, UlidIdGen, Verdict, timeout,
};
pub use problem::Problem;
pub use problems::{ProblemDef, SLUGS, registry as problem_registry};
pub use scope::Scope;
pub use signer::{HmacSigner, MIN_SECRET_BYTES, SignerError};
pub use template::{Rendered, Template, TemplateError, TemplateRegistry};
pub use venture::{Venture, VentureEnv};
