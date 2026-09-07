//! `cratefield-core` is the runtime-agnostic kernel of the Factory Zero harness:
//! the [`Module`] contract, the [`Harness`] builder, port traits, RFC 9457
//! problem+json errors, the request [`Scope`], an in-process [`EventBus`] and
//! a [`TemplateRegistry`] (ADR 0001, 0002, 0007).
//!
//! Core depends only on `http`, `axum` (default features off), `serde`,
//! `tracing`, `sea-query` and pure-Rust crypto. It must never depend on
//! `worker`, `wasm-bindgen`, `tokio`, `reqwest`, `sqlx` or `rusqlite`, and
//! never touches `std::fs` or `std::net` — CI enforces this with a
//! `cargo tree` check and the wasm build of `examples/venture`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod admin;
mod config;
mod csv;
mod email;
mod events;
mod harness;
mod http;
mod lint;
mod logging;
mod module;
mod ports;
mod problem;
mod problems;
mod rate_limit;
mod scope;
mod sidecar;
mod signer;
mod surface;
mod template;
mod venture;

pub use admin::{bearer_token, constant_time_eq, require_admin};
pub use config::{Config, ConfigError, EmptyConfig, HarnessConfig, MapConfig, ModuleConfig};
pub use csv::{FORMULA_PREFIXES, escape as csv_escape, row as csv_row};
pub use email::{
    MAX_EMAIL_BYTES, MAX_LOCAL_BYTES, invalid_email_problem, is_valid,
    normalize as normalize_email, validation_error,
};
pub use events::{AnyError, EventBus, EventHandler, EventName};
pub use harness::{Harness, HarnessBuilder, Runtime};
pub use http::{Form, Json, MAX_BODY_BYTES, X_REQUEST_ID, rate_limited, request_id_is_valid};
pub use lint::lint_portable_sql;
pub use logging::{
    RedactingVisitor, is_email_field, is_secret_field, redacted_value, subject_hash,
};
pub use module::{
    BoxFuture, HARNESS_API, Migrations, Module, ModuleContext, SqlMigration, harness_api_mismatch,
    migration_checksum, migration_edited,
};
pub use ports::{
    Captcha, CaptchaError, Clock, Database, DbError, Decision, Defer, DispatchError, Dispatcher,
    HttpClient, HttpError, IdGen, KeyValue, Kid, KvError, MailError, Mailer, Message, NoopDefer,
    Payload, Port, Ports, RateLimitError, RateLimiter, Row, Rows, SendOutcome, SignatureError,
    Signer, Statement, SystemClock, TryFromValue, UlidIdGen, Verdict, timeout,
};
pub use problem::Problem;
pub use problems::{ProblemDef, SLUGS, registry as problem_registry};
pub use rate_limit::{client_ip, rate_limit_keys};
pub use scope::Scope;
pub use sidecar::{HARNESS_SIDECARS, SidecarMount, SidecarMounts, X_HARNESS_API, X_HARNESS_MODULE};
pub use signer::{HmacSigner, MIN_SECRET_BYTES, SignerError};
pub use surface::{
    Action, Audience, Column, HINT_KEYWORDS, ModuleSurface, Outcome, RenderedSurface, SURFACE_API,
    Surface, SurfaceDocument, SurfaceSource, UiContext, UiMount, VentureSurface, View, hint_field,
    schema_for,
};
pub use template::{Rendered, Template, TemplateError, TemplateRegistry};
pub use venture::{Brand, Venture, VentureEnv};
